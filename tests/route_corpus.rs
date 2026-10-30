// SPDX-License-Identifier: BSD-3-Clause

//! The routes of this table by which a profile forges a macro chard reads are each withheld,
//! or named open.
//!
//! The withholding rules are tested by name elsewhere (`tests/fake_driver.rs` holds a shape
//! withheld under `compile-inputs-unmatched-by-arms`, another under `macro-supplied-by-profile`).
//! A test by name holds a rule, not the property the rules exist for: that an observable a
//! profile forged is never published as a measurement. A rule can lean on another's
//! over-withholding unseen, and narrowing the second then publishes the forgery. So this corpus
//! asserts the property itself over a table, and accepts any withholding that holds it.
//!
//! The table is built from lists so that it grows with them: the macros (every name in
//! `measure::COMPILER_DEFINED_MACROS` and `measure::COMPILER_IDENTITY_MACROS`, read from the
//! source, and every request macro a control arm sets by name), the spellings ([`SPELLINGS`]),
//! and the states of each macro and direction ([`state`]). The checks a macro reaches
//! ([`reached`]) are derived from the predicates that read it and the probe sources that branch
//! on it, rather than listed. The frame counts the routes fed against the routes the lists
//! make: for each driver, macro and spelling the driver takes, each state of the spelling's
//! direction, or one route counted as not constructible, with its reason.
//!
//! A route is one macro through one spelling, in one state, under one driver. A state is a
//! build without the protection a define claims, or with the one an undefine denies, one for
//! each flag the compiler defines the macro under: `__PIC__` is defined under `-fPIC` and
//! under `-fPIE`, and its twin reads the two differently. Before chard runs, the driver's own
//! `-dM -E` under the route's words shows whether the forgery reached the preprocessor at the
//! forged value ([`effect`]). A route whose forgery a C library header settles away is inert
//! and one whose preprocessing breaks is broken, each allowed only for the macros [`INERT`] and
//! [`BROKEN`] name with why; a spelling that reaches no macro under a driver fails.
//!
//! Beside each route the same build without the spelling is measured: the state's plain run,
//! whose own build is shown by the same `-dM -E` to carry the macro in the direction opposite
//! the forgery. A reached check the route leaves withheld (any verdict but `on`, `off` and
//! `partial`) passes, counted by what withheld it: a rule, the detector with no rule named, a
//! harness failure (`probe-invalid`, `build-failed`, `run-failed`), or the plain run's own
//! withholding with the same verdict and rule, which the route did not earn. A check the route
//! publishes with the plain run's verdict and level is a reading it did not move, counted
//! apart: the corpus sees a forgery only where the state makes the forged reading differ from
//! the honest one, which is what the states are chosen for. A check it publishes otherwise is
//! the forgery, and fails with the route, the check and the verdict, unless [`OPEN_ROUTES`]
//! names it, its forged verdict and why no rule holds it. A named combination that stops
//! publishing its forged verdict fails too, so the row is retired when the rule that holds it
//! lands. A driver and macro whose routes earn nothing (no reading withheld, named open or
//! forged) fail unless [`MEASURES_NOTHING`] names the macro with why.
//!
//! The plain runs are held to their states in a second way too: a define's state reads none of
//! the macro checks that read the name present, and an undefine's reads at least one present
//! where any reads it. A plain run whose reached check is a harness failure fails, since it
//! would hold no route to anything; a plain `indeterminate` is the honest reading of its state
//! (an optimisation-gated check at `-O0`), and a route that publishes over it is the forgery.
//!
//! A request macro defined before the C library's headers is the request itself, honest by
//! construction, so for the request macros only the shadow headers, read after the library's
//! headers have settled, are routes; the rest are counted as not constructible, as is a
//! direction the target cannot be put in (an undefine of `__FreeBSD__` off FreeBSD, of the
//! `__ARM_FEATURE_*` macros off `aarch64`), each reason one [`UNCONSTRUCTIBLE`] declares.
//!
//! Spellings left out: a header option handed to a tool without its file or directory in the
//! pair after it (`-Xpreprocessor -include FILE`), which chard refuses before any build as a
//! path option handed without its path (`compile::relative_path_readings`); response files
//! (refused); `-idirafter` and `-iquote`, which cannot shadow `<stdio.h>`, and so their handed
//! forms; the rest of the handed forms (`-Xclang -isystem`, `-Xclang -imacros`, `-Wp,-isystem`),
//! each the carrier and the option of a spelling here; joined and abbreviated forms of the long
//! options, `-isystem=`, `-I=`, `CPLUS_INCLUDE_PATH` and `-Xarch_`, which the readers' own unit
//! tests hold; and the sysroot, prefix and resource-directory words (`-Xclang -resource-dir`
//! among them) and a wrapper adding the define, a toolchain layout and a driver rather than a
//! spelling, which `THREAT_MODEL.md` names among its residuals. The
//! frame goes to stdout and the test ledger, and the cells (one line per reading, the plain
//! runs' among them) to `route-corpus/cells.tsv` under cargo's test scratch directory.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use chard::probe::{CORPUS, Channel};
use chard::report::Verdict;
use serde_json::Value;

mod common;

fn chard_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("chard")
}

/// The probe deadline every measurement here runs under, as `tests/fake_driver.rs`'s is: a
/// route's reading withheld because a busy host reached chard's own deadline would pass here
/// for a reason that is not the route's.
const PROBE_DEADLINE: [&str; 2] = ["--timeout", "60"];

/// How many measurements run at once. The host is shared; each measurement runs its probes'
/// arms one child at a time, so this bounds the corpus's share.
const WORKERS: usize = 8;

/// The macro a keyed file spelling tests, which the route's profile defines.
const GATE: &str = "CHARD_ROUTE_GATE";

/// The string entries of the array constant `name` declares in `src/measure.rs`: the lists are
/// private to the crate (one is compiled for its tests alone), and reading the declaration
/// keeps the corpus on the lists the rules read rather than on a copy.
fn measure_list(name: &str) -> Vec<String> {
    let source = include_str!("../src/measure.rs");
    let body = source
        .split_once(&format!("const {name}: &[&str] = &["))
        .unwrap_or_else(|| panic!("measure.rs declares {name}"))
        .1;
    let body = body.split_once("];").expect("the list closes").0;
    let names: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .flat_map(|l| l.split(','))
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            l.strip_prefix('"')
                .and_then(|l| l.strip_suffix('"'))
                .unwrap_or_else(|| panic!("an entry of {name} this reader cannot read: {l}"))
                .to_owned()
        })
        .collect();
    assert!(!names.is_empty(), "{name} read as empty");
    names
}

/// Every macro a control arm sets or unsets by name, read from the arms the way
/// `measure::macros_the_controls_set` reads them: the joined and split `-D` and `-U`, and each
/// piece of a `-Wp,` word. A copy of that derivation, since the function is private to the
/// crate, and not held to it: a copy that drifted would move a request macro in or out of the
/// table, which the frame's macro count shows and no assertion here catches.
fn request_macros() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for check in CORPUS.iter().flat_map(|p| p.checks) {
        for arm in [
            check.positive,
            check.negative,
            check.regime_arm().unwrap_or(&[]),
        ] {
            let flags: Vec<String> = arm.iter().map(|w| (*w).to_owned()).collect();
            let words = chard::compile_inputs::macro_words(&flags);
            let mut rest = words.iter();
            while let Some(word) = rest.next() {
                let joined;
                let word = if word == "-D" || word == "-U" {
                    let Some(name) = rest.next() else { break };
                    joined = format!("{word}{name}");
                    joined.as_str()
                } else {
                    word.as_str()
                };
                let pieces: Vec<&str> = match word.strip_prefix("-Wp,") {
                    Some(list) => list.split(',').collect(),
                    None => vec![word],
                };
                for piece in pieces {
                    if let Some(name) = chard::compile_inputs::macro_name(piece) {
                        names.insert(name.to_owned());
                    }
                }
            }
        }
    }
    names
}

/// What a macro is, which decides its states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacroClass {
    /// The compiler defines it to describe its code generation.
    CompilerDefined,
    /// The compiler defines it to name itself.
    Identity,
    /// The build defines it to ask a library for a protection.
    Request,
}

/// The macro list: the compiler-defined names, the identity names, the controls' requests.
fn macros() -> Vec<(String, MacroClass)> {
    let mut list: Vec<(String, MacroClass)> = Vec::new();
    let lists = [
        ("COMPILER_DEFINED_MACROS", MacroClass::CompilerDefined),
        ("COMPILER_IDENTITY_MACROS", MacroClass::Identity),
    ];
    for (constant, class) in lists {
        list.extend(measure_list(constant).into_iter().map(|m| (m, class)));
    }
    for m in request_macros() {
        assert!(
            !list.iter().any(|(n, _)| *n == m),
            "{m} is on two lists; the corpus reads it once"
        );
        list.push((m, MacroClass::Request));
    }
    list
}

/// Does any string in `value` equal `name`? A predicate names a macro only as a term's
/// string, so this finds every term that reads it.
fn mentions(value: &Value, name: &str) -> bool {
    match value {
        Value::String(s) => s == name,
        Value::Array(a) => a.iter().any(|v| mentions(v, name)),
        Value::Object(o) => o.values().any(|v| mentions(v, name)),
        _ => false,
    }
}

/// Does a `#if`, `#ifdef`, `#ifndef` or `#elif` line of `source` test `name`? The test
/// `measure::every_probe_declares_the_reserved_macros_its_source_branches_on` reads the
/// probes' branches the same way.
fn branches_on(source: &str, name: &str) -> bool {
    source.lines().any(|line| {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            return false;
        };
        let rest = rest.trim_start();
        let directive = ["ifdef", "ifndef", "elif", "if"].iter().any(|d| {
            rest.strip_prefix(d)
                .is_some_and(|r| r.starts_with([' ', '\t', '(']))
        });
        directive
            && rest
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|w| w == name)
    })
}

/// One check a macro reaches, with the probe that carries it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Reached {
    check: &'static str,
    probe: &'static str,
    /// The macro check reads the name; otherwise its probe's source branches on it.
    by_predicate: bool,
}

/// The checks `name` reaches: every macro-channel check whose predicate reads it, and every
/// check on another channel of a probe whose own source branches on it.
fn reached(name: &str) -> Vec<Reached> {
    let mut out = Vec::new();
    for probe in CORPUS {
        for check in probe.checks {
            let by_predicate = check.channel() == Channel::Macro;
            let reads = if by_predicate {
                let predicate = chard::predicate::for_check(check.id)
                    .unwrap_or_else(|| panic!("the macro check {} has no predicate", check.id));
                mentions(
                    &serde_json::to_value(predicate).expect("a predicate serializes"),
                    name,
                )
            } else {
                branches_on(probe.source, name)
            };
            if reads {
                out.push(Reached {
                    check: check.id,
                    probe: probe.id,
                    by_predicate,
                });
            }
        }
    }
    out
}

/// The probes a route measures: those of the reached checks, and those of the twins
/// `report::MACRO_TWINS` holds a reached macro check to, so the rule that compares a macro
/// with its artifact has what it compares.
fn probes_for(reached: &[Reached]) -> BTreeSet<&'static str> {
    let mut probes: BTreeSet<&'static str> = reached.iter().map(|r| r.probe).collect();
    for twin in chard::report::MACRO_TWINS {
        if reached.iter().any(|r| r.check == twin.macro_check) {
            for witness in twin.witnesses {
                let probe = CORPUS
                    .iter()
                    .find(|p| p.checks.iter().any(|c| c.id == witness.check))
                    .unwrap_or_else(|| panic!("no probe carries the twin {}", witness.check));
                probes.insert(probe.id);
            }
        }
    }
    probes
}

/// Which way a spelling moves the macro.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Direction {
    /// Defines it, claiming the protection; the route's build lacks it.
    Define,
    /// Undefines it, denying the protection; the route's build has it.
    Undefine,
}

/// The driver family a spelling exists under, where it is one family's alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Only {
    Any,
    Gcc,
    Clang,
}

/// A command-line form of the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cli {
    /// `-DNAME=v`, `-UNAME`.
    Joined,
    /// `-D NAME=v`, `-U NAME`.
    Split,
    /// `-Wp,-DNAME=v`.
    Wp,
    /// `-Wp,-D,NAME=v`, the operation split across the comma.
    WpComma,
    /// `-Xpreprocessor -DNAME=v`.
    Xpreprocessor,
    /// `-Xpreprocessor -D -Xpreprocessor NAME=v`.
    XpreprocessorPair,
    /// `-Xclang -DNAME=v`.
    Xclang,
    /// `--define-macro=NAME=v`, `--undefine-macro=NAME`.
    Long,
}

/// A form that names a file of the operation, which the preprocessor reads before the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Forced {
    /// `-include FILE`.
    Include,
    /// `-imacros FILE`.
    Imacros,
    /// `-Wp,-include,FILE`.
    WpInclude,
    /// `--include=FILE`.
    LongInclude,
    /// `--imacros=FILE`.
    LongImacros,
    /// `-Xpreprocessor -include -Xpreprocessor FILE`, the preprocessor's `-include`.
    XpreprocessorInclude,
    /// `-Xclang -include -Xclang FILE`, clang's `-cc1` `-include`.
    XclangInclude,
    /// `-Xpreprocessor -imacros -Xpreprocessor FILE`, the preprocessor.s `-imacros`.
    XpreprocessorImacros,
}

/// Where a shadow `stdio.h` is found ahead of the C library's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shadow {
    /// `-IDIR`.
    I,
    /// `-I DIR`.
    ISplit,
    /// `-isystem DIR`.
    Isystem,
    /// `CPATH=DIR`, through chard's `--env`.
    Cpath,
    /// `C_INCLUDE_PATH=DIR`, through chard's `--env`.
    CIncludePath,
    /// `-Xpreprocessor -I -Xpreprocessor DIR`, the preprocessor's `-I`.
    XpreprocessorI,
    /// `-Wp,-I,DIR`.
    WpI,
    /// `-Xpreprocessor -isystem -Xpreprocessor DIR`.
    XpreprocessorIsystem,
    /// `-Xclang -I -Xclang DIR`, clang.s `-cc1` `-I`.
    XclangI,
}

/// How the spelling reaches the preprocessor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carrier {
    Cli(Cli),
    /// The file, keyed on [`GATE`] or not.
    Forced(Forced, bool),
    /// A directory holding a `stdio.h` that includes the next one and then the operation,
    /// keyed on [`GATE`]. Every reached probe includes `<stdio.h>` (the C++ one through
    /// `<cstdio>`) before it branches, and the shadow is read after the C library's
    /// `features.h` has settled its own macros.
    Shadow(Shadow),
    /// A gcc specs file appending the operation to `cpp_unique_options`.
    Specs,
    /// A clang configuration file holding the operation.
    Config,
    /// `CCC_OVERRIDE_OPTIONS=+OPERATION` through chard's `--env`, which clang's driver applies
    /// to every command line it is given.
    CccOverride,
}

struct Spelling {
    id: &'static str,
    direction: Direction,
    only: Only,
    carrier: Carrier,
}

const fn spelling(
    id: &'static str,
    direction: Direction,
    only: Only,
    carrier: Carrier,
) -> Spelling {
    Spelling {
        id,
        direction,
        only,
        carrier,
    }
}

use Direction::{Define, Undefine};

/// The spellings an input reaches the preprocessor by, each in the directions it can take.
const SPELLINGS: &[Spelling] = &[
    spelling("-D", Define, Only::Any, Carrier::Cli(Cli::Joined)),
    spelling("-U", Undefine, Only::Any, Carrier::Cli(Cli::Joined)),
    spelling("-D split", Define, Only::Any, Carrier::Cli(Cli::Split)),
    spelling("-U split", Undefine, Only::Any, Carrier::Cli(Cli::Split)),
    spelling("-Wp,-D", Define, Only::Any, Carrier::Cli(Cli::Wp)),
    spelling("-Wp,-U", Undefine, Only::Any, Carrier::Cli(Cli::Wp)),
    spelling(
        "-Wp,-D, comma",
        Define,
        Only::Any,
        Carrier::Cli(Cli::WpComma),
    ),
    spelling(
        "-Wp,-U, comma",
        Undefine,
        Only::Any,
        Carrier::Cli(Cli::WpComma),
    ),
    spelling(
        "-Xpreprocessor pair -D",
        Define,
        Only::Any,
        Carrier::Cli(Cli::XpreprocessorPair),
    ),
    spelling(
        "-Xpreprocessor pair -U",
        Undefine,
        Only::Any,
        Carrier::Cli(Cli::XpreprocessorPair),
    ),
    spelling(
        "-Xpreprocessor -D",
        Define,
        Only::Any,
        Carrier::Cli(Cli::Xpreprocessor),
    ),
    spelling(
        "-Xpreprocessor -U",
        Undefine,
        Only::Any,
        Carrier::Cli(Cli::Xpreprocessor),
    ),
    spelling("-Xclang -D", Define, Only::Clang, Carrier::Cli(Cli::Xclang)),
    spelling(
        "-Xclang -U",
        Undefine,
        Only::Clang,
        Carrier::Cli(Cli::Xclang),
    ),
    spelling("--define-macro", Define, Only::Any, Carrier::Cli(Cli::Long)),
    spelling(
        "--undefine-macro",
        Undefine,
        Only::Any,
        Carrier::Cli(Cli::Long),
    ),
    spelling(
        "-include define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::Include, false),
    ),
    spelling(
        "-include undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::Include, false),
    ),
    spelling(
        "-include keyed define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::Include, true),
    ),
    spelling(
        "-include keyed undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::Include, true),
    ),
    spelling(
        "-imacros define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::Imacros, false),
    ),
    spelling(
        "-imacros undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::Imacros, false),
    ),
    spelling(
        "-imacros keyed define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::Imacros, true),
    ),
    spelling(
        "-imacros keyed undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::Imacros, true),
    ),
    spelling(
        "-Wp,-include keyed define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::WpInclude, true),
    ),
    spelling(
        "-Wp,-include keyed undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::WpInclude, true),
    ),
    spelling(
        "-I shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::I),
    ),
    spelling(
        "-I shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::I),
    ),
    spelling(
        "-isystem shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::Isystem),
    ),
    spelling(
        "-isystem shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::Isystem),
    ),
    spelling(
        "CPATH shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::Cpath),
    ),
    spelling(
        "CPATH shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::Cpath),
    ),
    spelling(
        "-I split shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::ISplit),
    ),
    spelling(
        "-I split shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::ISplit),
    ),
    spelling(
        "C_INCLUDE_PATH shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::CIncludePath),
    ),
    spelling(
        "C_INCLUDE_PATH shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::CIncludePath),
    ),
    spelling(
        "-Xpreprocessor -include keyed define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::XpreprocessorInclude, true),
    ),
    spelling(
        "-Xpreprocessor -include keyed undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::XpreprocessorInclude, true),
    ),
    spelling(
        "-Xclang -include keyed define",
        Define,
        Only::Clang,
        Carrier::Forced(Forced::XclangInclude, true),
    ),
    spelling(
        "-Xclang -include keyed undefine",
        Undefine,
        Only::Clang,
        Carrier::Forced(Forced::XclangInclude, true),
    ),
    spelling(
        "-Xpreprocessor -I shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::XpreprocessorI),
    ),
    spelling(
        "-Xpreprocessor -I shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::XpreprocessorI),
    ),
    spelling(
        "-Xpreprocessor -imacros keyed define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::XpreprocessorImacros, true),
    ),
    spelling(
        "-Xpreprocessor -imacros keyed undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::XpreprocessorImacros, true),
    ),
    spelling(
        "-Xpreprocessor -isystem shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::XpreprocessorIsystem),
    ),
    spelling(
        "-Xpreprocessor -isystem shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::XpreprocessorIsystem),
    ),
    spelling(
        "-Xclang -I shadow define",
        Define,
        Only::Clang,
        Carrier::Shadow(Shadow::XclangI),
    ),
    spelling(
        "-Xclang -I shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Shadow(Shadow::XclangI),
    ),
    spelling(
        "-Wp,-I shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::WpI),
    ),
    spelling(
        "-Wp,-I shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::WpI),
    ),
    spelling(
        "--include= keyed define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::LongInclude, true),
    ),
    spelling(
        "--include= keyed undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::LongInclude, true),
    ),
    spelling(
        "--imacros= keyed define",
        Define,
        Only::Any,
        Carrier::Forced(Forced::LongImacros, true),
    ),
    spelling(
        "--imacros= keyed undefine",
        Undefine,
        Only::Any,
        Carrier::Forced(Forced::LongImacros, true),
    ),
    spelling(
        "CCC_OVERRIDE_OPTIONS define",
        Define,
        Only::Clang,
        Carrier::CccOverride,
    ),
    spelling(
        "CCC_OVERRIDE_OPTIONS undefine",
        Undefine,
        Only::Clang,
        Carrier::CccOverride,
    ),
    spelling("-specs define", Define, Only::Gcc, Carrier::Specs),
    spelling("-specs undefine", Undefine, Only::Gcc, Carrier::Specs),
    spelling("--config define", Define, Only::Clang, Carrier::Config),
    spelling("--config undefine", Undefine, Only::Clang, Carrier::Config),
];

/// What a define writes: the value the compiler or library would give the macro.
fn value(name: &str) -> &'static str {
    match name {
        "__SSP_STRONG__"
        | "__USE_FORTIFY_LEVEL"
        | "_USE_FORTIFY_LEVEL"
        | "_FORTIFY_SOURCE"
        | "__CET__" => "3",
        "__SSP_ALL__" | "__SSP_FORTIFY_LEVEL" | "__PIE__" | "__PIC__" => "2",
        "__SSP_EXPLICIT__" | "_LIBCPP_HARDENING_MODE" => "4",
        "__FreeBSD__" => "14",
        _ => "1",
    }
}

/// The flag sets a direction's states are made by, one per state.
type States = &'static [&'static [&'static str]];

/// Why a request macro no check reads has no route.
const REQUEST_UNREAD: &str =
    "no check reads this request macro, so no route of it reaches a reading";

/// Every reason a route is not constructible. [`every_reason_a_route_is_not_built_is_declared`]
/// holds [`state`] and [`constructible`] to this list, so a state turned into a refusal fails
/// rather than shrinking the table.
const UNCONSTRUCTIBLE: &[&str] = &[
    REQUEST_UNREAD,
    REQUEST_HONEST,
    "clang has no -fstack-protector-explicit",
    "the macro is defined only by a C library or platform other than this one",
    "no AArch64 build this corpus has measured defines `__ARM_FEATURE_GCS_DEFAULT`",
    "the AArch64 feature macros are defined only on AArch64 targets",
    "`__CET__` is defined only on x86 targets",
    "clang defines `__clang__` itself",
    "only clang defines `__clang__`",
    "`_LIBCPP_HARDENING_MODE` is read as a request only beside libc++",
];

/// Why a request route through a spelling other than a shadow header is not constructible.
const REQUEST_HONEST: &str = "a request macro spelled before the C library's headers is the \
                              request itself, honest by construction";

/// The builds a route of `name` contradicts, each as the flags that make it: without the
/// protection for a define, with it for an undefine, on a target of `arch` under `family`.
/// Where the compiler defines the macro under more than one flag, each is a state of its own,
/// since a twin can read the protection differently under each (`pic-object-relocs` reads a
/// direct relocation under `-fPIE` by design and a GOT one under `-fPIC`). `Err` names why no
/// build here can be put in it. A macro with no row panics, so a name added to a list is given
/// its states before the corpus runs again.
fn state(
    name: &str,
    class: MacroClass,
    direction: Direction,
    arch: &str,
    family: Only,
) -> Result<States, &'static str> {
    if class == MacroClass::Request && reached(name).is_empty() {
        return Err(REQUEST_UNREAD);
    }
    match class {
        MacroClass::CompilerDefined => compiler_state(name, direction, arch, family),
        MacroClass::Identity => identity_state(name, direction, family),
        MacroClass::Request => request_state(name, direction),
    }
}

fn compiler_state(
    name: &str,
    direction: Direction,
    arch: &str,
    family: Only,
) -> Result<States, &'static str> {
    let x86 = arch == "x86_64";
    let aarch64 = arch == "aarch64";
    match (name, direction) {
        ("__SSP__" | "__SSP_STRONG__" | "__SSP_ALL__" | "__SSP_EXPLICIT__", Define) => {
            Ok(&[&["-fno-stack-protector"]])
        }
        ("__SSP__", Undefine) => Ok(&[&["-fstack-protector"]]),
        ("__SSP_STRONG__", Undefine) => Ok(&[&["-fstack-protector-strong"]]),
        ("__SSP_ALL__", Undefine) => Ok(&[&["-fstack-protector-all"]]),
        ("__SSP_EXPLICIT__", Undefine) if family == Only::Clang => {
            Err("clang has no -fstack-protector-explicit")
        }
        ("__SSP_EXPLICIT__", Undefine) => Ok(&[&["-fstack-protector-explicit"]]),
        ("__USE_FORTIFY_LEVEL" | "_USE_FORTIFY_LEVEL" | "__SSP_FORTIFY_LEVEL", Define) => {
            Ok(&[&["-U_FORTIFY_SOURCE"]])
        }
        ("__USE_FORTIFY_LEVEL", Undefine) => Ok(&[&["-D_FORTIFY_SOURCE=2"]]),
        ("_USE_FORTIFY_LEVEL" | "__SSP_FORTIFY_LEVEL" | "__FreeBSD__", Undefine) => {
            Err("the macro is defined only by a C library or platform other than this one")
        }
        (
            "__ARM_FEATURE_BTI_DEFAULT" | "__ARM_FEATURE_PAC_DEFAULT" | "__ARM_FEATURE_GCS_DEFAULT",
            Define,
        ) if aarch64 => Ok(&[&["-mbranch-protection=none"]]),
        ("__ARM_FEATURE_BTI_DEFAULT" | "__ARM_FEATURE_PAC_DEFAULT", Undefine) if aarch64 => {
            Ok(&[&["-mbranch-protection=standard"]])
        }
        ("__ARM_FEATURE_GCS_DEFAULT", Undefine) if aarch64 => {
            Err("no AArch64 build this corpus has measured defines `__ARM_FEATURE_GCS_DEFAULT`")
        }
        ("__CET__", Define) if x86 => Ok(&[&["-fcf-protection=none"]]),
        // Off the macro's own target nothing defines it, so the build is already without
        // what a define claims.
        (
            "__FreeBSD__"
            | "__ARM_FEATURE_BTI_DEFAULT"
            | "__ARM_FEATURE_PAC_DEFAULT"
            | "__ARM_FEATURE_GCS_DEFAULT"
            | "__CET__",
            Define,
        ) => Ok(&[&[]]),
        (
            "__ARM_FEATURE_BTI_DEFAULT" | "__ARM_FEATURE_PAC_DEFAULT" | "__ARM_FEATURE_GCS_DEFAULT",
            Undefine,
        ) => Err("the AArch64 feature macros are defined only on AArch64 targets"),
        ("__PIE__", Define) => Ok(&[&["-fno-pie", "-no-pie"]]),
        ("__PIE__", Undefine) => Ok(&[&["-fPIE", "-pie"]]),
        ("__PIC__", Define) => Ok(&[&["-fno-pic", "-fno-pie", "-no-pie"]]),
        ("__PIC__", Undefine) => Ok(&[&["-fPIC"], &["-fPIE", "-pie"]]),
        ("__CET__", Undefine) if x86 => Ok(&[
            &["-fcf-protection=full"],
            &["-fcf-protection=branch"],
            &["-fcf-protection=return"],
        ]),
        ("__CET__", Undefine) => Err("`__CET__` is defined only on x86 targets"),
        ("__OPTIMIZE__", Define) => Ok(&[&["-O0"]]),
        ("__OPTIMIZE__", Undefine) => Ok(&[&["-O2"]]),
        ("__EXCEPTIONS", Define) => Ok(&[&["-fno-exceptions"]]),
        ("__EXCEPTIONS", Undefine) => Ok(&[&["-fexceptions"]]),
        _ => panic!(
            "the route corpus has no state for {name} ({direction:?}): give it the flags that \
             build without the protection a define claims and with the one an undefine denies"
        ),
    }
}

fn identity_state(name: &str, direction: Direction, family: Only) -> Result<States, &'static str> {
    match (name, direction, family) {
        ("__clang__", Define, Only::Gcc) | ("__clang__", Undefine, Only::Clang) => Ok(&[&[]]),
        ("__clang__", Define, _) => Err("clang defines `__clang__` itself"),
        ("__clang__", Undefine, _) => Err("only clang defines `__clang__`"),
        _ => panic!("the route corpus has no state for the identity macro {name}"),
    }
}

fn request_state(name: &str, direction: Direction) -> Result<States, &'static str> {
    match (name, direction) {
        ("_FORTIFY_SOURCE", Define) => Ok(&[&["-U_FORTIFY_SOURCE"]]),
        ("_FORTIFY_SOURCE", Undefine) => Ok(&[&["-D_FORTIFY_SOURCE=2"]]),
        ("_GLIBCXX_ASSERTIONS", Define) => Ok(&[&["-U_GLIBCXX_ASSERTIONS"]]),
        ("_GLIBCXX_ASSERTIONS", Undefine) => Ok(&[&["-D_GLIBCXX_ASSERTIONS"]]),
        ("_LIBCPP_HARDENING_MODE", Define) => Ok(&[&[]]),
        ("_LIBCPP_HARDENING_MODE", Undefine) => {
            Err("`_LIBCPP_HARDENING_MODE` is read as a request only beside libc++")
        }
        _ => panic!("the route corpus has no state for the request macro {name} ({direction:?})"),
    }
}

/// A driver this corpus measures through, by the name chard resolves on `PATH`.
struct Driver {
    name: &'static str,
    family: Only,
    /// The target's architecture, from `-dumpmachine`, which decides the states.
    arch: String,
    /// The first line of `--version`, for the frame.
    version: String,
}

/// gcc and clang where each is on `PATH`. A missing one is announced as a gap, as a compiler
/// this host lacks is everywhere in the suite (`common::capability_gap`); one that is present
/// and fails to name its target fails the corpus.
fn drivers() -> Vec<Driver> {
    let mut found = Vec::new();
    for (name, family) in [("gcc", Only::Gcc), ("clang", Only::Clang)] {
        let machine = match Command::new(name).arg("-dumpmachine").output() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                common::capability_gap(
                    &format!("route_corpus under {name}"),
                    &format!(
                        "no `{name}` on PATH, so the routes through it, and its own spellings, \
                         are not measured"
                    ),
                );
                continue;
            }
            Err(e) => panic!("`{name} -dumpmachine` could not run: {e}"),
            Ok(o) if !o.status.success() => panic!("`{name} -dumpmachine` failed: {o:?}"),
            Ok(o) => o,
        };
        let triple = String::from_utf8_lossy(&machine.stdout).trim().to_owned();
        let arch = match triple.split('-').next().unwrap_or("") {
            "amd64" => "x86_64".to_owned(),
            "arm64" => "aarch64".to_owned(),
            other => other.to_owned(),
        };
        let version = version_line(Path::new(name));
        found.push(Driver {
            name,
            family,
            arch,
            version,
        });
    }
    found
}

fn applies(spelling: &Spelling, family: Only) -> bool {
    spelling.only == Only::Any || spelling.only == family
}

/// Is this spelling a route for a macro of `class`? `Err` names why it is not.
fn constructible(spelling: &Spelling, class: MacroClass) -> Result<(), &'static str> {
    if class == MacroClass::Request && !matches!(spelling.carrier, Carrier::Shadow(_)) {
        return Err(REQUEST_HONEST);
    }
    Ok(())
}

/// The words and environment pairs that carry `name` through `spelling`, writing any file they
/// name into `dir`.
struct Carried {
    words: Vec<String>,
    env: Vec<(String, String)>,
}

/// `option` and its `value` handed to a tool by `hand`, each in its own pair.
fn handed_pair(hand: &str, option: &str, value: String) -> Vec<String> {
    vec![hand.to_owned(), option.to_owned(), hand.to_owned(), value]
}

fn spelling_words(spelling: &Spelling, name: &str, dir: &Path) -> Carried {
    let (define, v) = (spelling.direction == Define, value(name));
    let op = if define {
        format!("-D{name}={v}")
    } else {
        format!("-U{name}")
    };
    let lines = if define {
        format!("#undef {name}\n#define {name} {v}\n")
    } else {
        format!("#undef {name}\n")
    };
    let keyed = |lines: &str| format!("#ifdef {GATE}\n{lines}#endif\n");
    let gate = format!("-D{GATE}");
    let file = |file: &str, contents: &str| {
        let path = dir.join(file);
        std::fs::write(&path, contents).expect("writing a route's file");
        path.display().to_string()
    };
    let mut env = Vec::new();
    let words = match spelling.carrier {
        Carrier::Cli(form) => cli_words(form, &op, name, define),
        Carrier::Forced(form, is_keyed) => {
            let body = if is_keyed { keyed(&lines) } else { lines };
            let path = file("route.h", &body);
            let mut words = if is_keyed { vec![gate] } else { Vec::new() };
            words.extend(match form {
                Forced::Include => vec!["-include".to_owned(), path],
                Forced::Imacros => vec!["-imacros".to_owned(), path],
                Forced::WpInclude => vec![format!("-Wp,-include,{path}")],
                Forced::LongInclude => vec![format!("--include={path}")],
                Forced::LongImacros => vec![format!("--imacros={path}")],
                Forced::XpreprocessorInclude => handed_pair("-Xpreprocessor", "-include", path),
                Forced::XclangInclude => handed_pair("-Xclang", "-include", path),
                Forced::XpreprocessorImacros => handed_pair("-Xpreprocessor", "-imacros", path),
            });
            words
        }
        Carrier::Shadow(form) => {
            let shadow = dir.join("shadow");
            std::fs::create_dir_all(&shadow).expect("the shadow directory");
            let header = format!("#include_next <stdio.h>\n{}", keyed(&lines));
            std::fs::write(shadow.join("stdio.h"), header).expect("writing the shadow header");
            let shadow = shadow.display().to_string();
            match form {
                Shadow::I => vec![gate, format!("-I{shadow}")],
                Shadow::ISplit => vec![gate, "-I".to_owned(), shadow],
                Shadow::Isystem => vec![gate, "-isystem".to_owned(), shadow],
                Shadow::Cpath => {
                    env.push(("CPATH".to_owned(), shadow));
                    vec![gate]
                }
                Shadow::XpreprocessorI => {
                    [vec![gate], handed_pair("-Xpreprocessor", "-I", shadow)].concat()
                }
                Shadow::WpI => vec![gate, format!("-Wp,-I,{shadow}")],
                Shadow::XpreprocessorIsystem => [
                    vec![gate],
                    handed_pair("-Xpreprocessor", "-isystem", shadow),
                ]
                .concat(),
                Shadow::XclangI => [vec![gate], handed_pair("-Xclang", "-I", shadow)].concat(),
                Shadow::CIncludePath => {
                    env.push(("C_INCLUDE_PATH".to_owned(), shadow));
                    vec![gate]
                }
            }
        }
        Carrier::Specs => vec![format!(
            "-specs={}",
            file("route.specs", &format!("*cpp_unique_options:\n+ {op}\n\n"))
        )],
        Carrier::Config => vec![format!(
            "--config={}",
            file("route.cfg", &format!("{op}\n"))
        )],
        Carrier::CccOverride => {
            env.push(("CCC_OVERRIDE_OPTIONS".to_owned(), format!("+{op}")));
            Vec::new()
        }
    };
    Carried { words, env }
}

fn cli_words(form: Cli, op: &str, name: &str, define: bool) -> Vec<String> {
    let (flag, rest) = op.split_at(2);
    match form {
        Cli::Joined => vec![op.to_owned()],
        Cli::Split => vec![flag.to_owned(), rest.to_owned()],
        Cli::Wp => vec![format!("-Wp,{op}")],
        Cli::WpComma => vec![format!("-Wp,{flag},{rest}")],
        Cli::Xpreprocessor => vec!["-Xpreprocessor".to_owned(), op.to_owned()],
        Cli::XpreprocessorPair => ["-Xpreprocessor", flag, "-Xpreprocessor", rest]
            .iter()
            .map(|w| (*w).to_owned())
            .collect(),
        Cli::Xclang => vec!["-Xclang".to_owned(), op.to_owned()],
        Cli::Long if define => vec![format!("--define-macro={rest}")],
        Cli::Long => vec![format!("--undefine-macro={name}")],
    }
}

/// One measurement the corpus runs: a route, or the plain run of a state (`spelling: None`).
struct Job {
    driver: usize,
    name: String,
    direction: Direction,
    spelling: Option<usize>,
    state: &'static [&'static str],
    reached: Vec<Reached>,
}

impl Job {
    fn label(&self, drivers: &[Driver]) -> String {
        let spelling = self.spelling.map_or("plain", |s| SPELLINGS[s].id);
        format!(
            "{} {} {spelling} ({:?}) [{}]",
            drivers[self.driver].name,
            self.name,
            self.direction,
            self.state.join(" ")
        )
    }
}

/// One reached check's reading in a job's report.
#[derive(Clone, Debug)]
struct Reading {
    check: &'static str,
    verdict: Verdict,
    /// The level, as the report serializes it (`null` where there is none).
    level: String,
    rule: String,
}

impl Reading {
    /// The rule that withheld it, or the verdict where no gating names one.
    fn named(&self) -> String {
        if self.rule.is_empty() {
            verdict_word(self.verdict)
        } else {
            self.rule.clone()
        }
    }

    fn present(&self) -> bool {
        matches!(self.verdict, Verdict::On | Verdict::Partial)
    }
}

fn verdict_word(verdict: Verdict) -> String {
    serde_json::to_value(verdict)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// A verdict that is a failure of the harness rather than a reading of the build.
fn harness_state(verdict: Verdict) -> bool {
    matches!(
        verdict,
        Verdict::ProbeInvalid | Verdict::BuildFailed | Verdict::RunFailed
    )
}

/// What a job came to.
enum Outcome {
    /// The reached checks' readings, in the order of the job's `reached`.
    Readings(Vec<Reading>),
    /// The forgery did not reach the preprocessor in the direction it claims.
    Inert,
    /// The preprocessor failed under the route's words, with its last line.
    Broken(String),
}

/// The words a job's build is measured under, and its environment pairs.
fn job_flags(job: &Job, work: &Path) -> (Vec<String>, Vec<(String, String)>) {
    let mut flags: Vec<String> = vec!["-O2".to_owned()];
    flags.extend(job.state.iter().map(|w| (*w).to_owned()));
    let mut env = Vec::new();
    if let Some(s) = job.spelling {
        let carried = spelling_words(&SPELLINGS[s], &job.name, work);
        flags.extend(carried.words);
        env = carried.env;
    }
    (flags, env)
}

/// The value the driver's preprocessor gives `name` under `flags` and `env`, in a unit
/// including `<stdio.h>`: `Ok(None)` where it is undefined, `Err` with the first error line
/// where preprocessing fails. The driver gets `PATH` and the route's pairs and nothing else of
/// the test's environment, as chard's driver gets `PATH`, the run's `--env` pairs and chard's
/// own pins. A C++ probe reaches the same C library headers through `<cstdio>`.
fn dumped_value(
    driver: &str,
    flags: &[String],
    env: &[(String, String)],
    name: &str,
    work: &Path,
) -> Result<Option<String>, String> {
    let unit = work.join("route-effect.c");
    std::fs::write(&unit, "#include <stdio.h>\nint chard_route;\n").expect("writing the unit");
    let done = Command::new(driver)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(env.iter().map(|(k, v)| (k, v)))
        .args(flags)
        .args(["-dM", "-E", "-x", "c"])
        .arg(&unit)
        .output()
        .expect("spawning the driver");
    if !done.status.success() {
        let stderr = String::from_utf8_lossy(&done.stderr);
        return Err(stderr
            .lines()
            .find(|l| l.contains("error"))
            .unwrap_or("")
            .to_owned());
    }
    let dump = String::from_utf8_lossy(&done.stdout);
    Ok(dump.lines().find_map(|l| {
        let rest = l.strip_prefix("#define ")?;
        let (macro_name, value) = rest.split_once(' ').unwrap_or((rest, ""));
        (macro_name == name).then(|| value.trim().to_owned())
    }))
}

/// Did the route's forgery reach the preprocessor? A define must leave the macro at the
/// forged value, an undefine must leave it undefined; a C library header that settles the
/// macro after the spelling makes the route inert, a preprocessor that fails under its words
/// makes it broken.
fn effect(
    driver: &str,
    flags: &[String],
    env: &[(String, String)],
    job: &Job,
    work: &Path,
) -> Option<Outcome> {
    let forged = match job.direction {
        Define => Some(value(&job.name).to_owned()),
        Undefine => None,
    };
    match dumped_value(driver, flags, env, &job.name, work) {
        Err(line) => Some(Outcome::Broken(line)),
        Ok(found) if found == forged => None,
        Ok(_) => Some(Outcome::Inert),
    }
}

/// Does the state's own build carry the macro the way its routes contradict: not at the forged
/// value where they define it (undefined, or at the value a C library gives it without the
/// protection, as glibc's `__USE_FORTIFY_LEVEL 0`), defined where they undefine it? A state that does not would pass every
/// route as unmoved, whatever its macro checks read.
fn state_holds(driver: &str, flags: &[String], job: &Job, work: &Path) -> Result<(), String> {
    match (
        dumped_value(driver, flags, &[], &job.name, work),
        job.direction,
    ) {
        (Err(line), _) => Err(format!("the state's own build does not preprocess: {line}")),
        (Ok(found), Define) if found.as_deref() != Some(value(&job.name)) => Ok(()),
        (Ok(Some(_)), Undefine) => Ok(()),
        (Ok(found), _) => Err(format!(
            "the state's own build has {} at {found:?}, the direction its routes forge, so they \
             contradict nothing",
            job.name
        )),
    }
}

/// Measure `job` in `work`: for a route, its effect first, for a plain run its state's own
/// build, then chard.
fn run(job: &Job, drivers: &[Driver], work: &Path, assert_host: bool) -> Result<Outcome, String> {
    std::fs::create_dir_all(work).expect("a job's directory");
    let driver = drivers[job.driver].name;
    let (flags, env) = job_flags(job, work);
    if job.spelling.is_some() {
        if let Some(outcome) = effect(driver, &flags, &env, job, work) {
            return Ok(outcome);
        }
    } else {
        state_holds(driver, &flags, job, work)?;
    }
    let output = work.join("report.json");
    let mut command = Command::new(chard_binary());
    command
        .arg("measure")
        .args(PROBE_DEADLINE)
        .arg("-o")
        .arg(&output)
        .args(["--cc", driver, "--profile", "explicit", "--flags"])
        .arg(flags.join(" "))
        .arg("--workdir")
        .arg(work.join("w"));
    for (k, v) in &env {
        command.arg("--env").arg(format!("{k}={v}"));
    }
    for probe in probes_for(&job.reached) {
        command.args(["--probe", probe]);
    }
    if assert_host {
        command.args(["--execution", "host"]);
    }
    let done = command.output().expect("spawning chard");
    if !done.status.success() {
        let stderr = String::from_utf8_lossy(&done.stderr);
        return Err(format!(
            "chard exited {:?} under {flags:?} {env:?}: {}",
            done.status.code(),
            stderr.lines().last().unwrap_or("")
        ));
    }
    let text = std::fs::read_to_string(&output).map_err(|e| format!("no report: {e}"))?;
    let report: Value = serde_json::from_str(&text).map_err(|e| format!("not JSON: {e}"))?;
    let observations = report["observations"].as_array().ok_or("no observations")?;
    job.reached
        .iter()
        .map(|r| reading(observations, r.check))
        .collect::<Result<Vec<_>, _>>()
        .map(Outcome::Readings)
}

/// The observation of `check`, read through the schema's verdict, or why it cannot be.
fn reading(observations: &[Value], check: &'static str) -> Result<Reading, String> {
    let mut of_check = observations
        .iter()
        .filter(|o| o["check"].as_str() == Some(check));
    let o = of_check
        .next()
        .ok_or_else(|| format!("no observation of {check}"))?;
    if of_check.next().is_some() {
        return Err(format!("{check} is observed more than once"));
    }
    let verdict: Verdict = serde_json::from_value(o["verdict"].clone()).map_err(|e| {
        format!(
            "{check}'s verdict {} is not the schema's: {e}",
            o["verdict"]
        )
    })?;
    Ok(Reading {
        check,
        verdict,
        level: o["level"].to_string(),
        rule: o["gating"]["rule"].as_str().unwrap_or("").to_owned(),
    })
}

/// A route that publishes on main today: under the driver family, the macro through each of
/// the spellings, in each of the states, read by each of the checks, publishes one of the
/// forged verdicts, and no rule withholds it. Each row says why. Every combination a row
/// names must publish one of its verdicts, moved from the plain run's, under every driver of
/// its family the corpus ran, or the corpus fails and names the row to retire; a row goes when
/// the rule that holds it lands.
struct OpenRoute {
    only: Only,
    name: &'static str,
    spellings: &'static [&'static str],
    checks: &'static [&'static str],
    /// The state the row holds for, or every state of the spelling's direction.
    states: Option<&'static [&'static str]>,
    /// The forged verdicts it publishes.
    reads: &'static [Verdict],
    why: &'static str,
}

const KEYED_DEFINES: &[&str] = &[
    "-include keyed define",
    "-imacros keyed define",
    "--include= keyed define",
    "--imacros= keyed define",
    "-I shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
];

/// [`SHADOW_DEFINES`] and the header directories handed to the preprocessor (`-Xpreprocessor`,
/// `-Wp,`, clang's `-Xclang`), which clang's runtime readings under a branching probe meet as
/// they meet the driver's.
const SHADOW_DEFINES_WITH_HANDED: &[&str] = &[
    "-I shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "-Xpreprocessor -I shadow define",
    "-Wp,-I shadow define",
    "-Xpreprocessor -isystem shadow define",
    "-Xclang -I shadow define",
];

const SHADOW_DEFINES: &[&str] = &[
    "-I shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
];

const SHADOW_UNDEFINES: &[&str] = &[
    "-I shadow undefine",
    "-I split shadow undefine",
    "-isystem shadow undefine",
    "CPATH shadow undefine",
    "C_INCLUDE_PATH shadow undefine",
];

/// The shadow carriers a C++ compile reads: `C_INCLUDE_PATH` is the C driver's alone.
const CXX_SHADOW_DEFINES: &[&str] = &[
    "-I shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
];
const CXX_SHADOW_UNDEFINES: &[&str] = &[
    "-I shadow undefine",
    "-I split shadow undefine",
    "-isystem shadow undefine",
    "CPATH shadow undefine",
];

/// The shadow carriers the environment passes, which no rule reads.
const ENV_DEFINES: &[&str] = &["CPATH shadow define", "C_INCLUDE_PATH shadow define"];
const ENV_UNDEFINES: &[&str] = &["CPATH shadow undefine", "C_INCLUDE_PATH shadow undefine"];

/// Why a `CPATH` or `C_INCLUDE_PATH` route publishes where its `-I` twin is withheld.
const CPATH_UNREAD: &str = "a `CPATH` or `C_INCLUDE_PATH` the operator passes through `--env` \
                            names a header search directory that no rule reads: `macro-supplied-by-profile` withholds \
                            the twinless macro checks under the profile's own `-I`, `-isystem`, \
                            `-idirafter` and `-iquote` words, and the environment carries none";

/// Why a `CCC_OVERRIDE_OPTIONS` route steers a branching probe.
const CCC_UNREAD: &str = "a `CCC_OVERRIDE_OPTIONS` the operator passes through `--env` edits every \
                          command line clang's driver is given, the control arms' and the \
                          listings' with the measured build's, so no listing differs and no rule \
                          reads the variable, and a probe that branches on the macro is steered \
                          in every build alike";

/// Why a request a shadow header forges publishes.
const REQUEST_LATE: &str = "a request macro a header defines or undefines after the C library's \
                            headers have settled reaches the self-report and not the library, \
                            and no rule compares the request the self-report shows with the one \
                            the library saw";

const OPEN_ROUTES: &[OpenRoute] = &[
    OpenRoute {
        only: Only::Any,
        name: "__PIC__",
        spellings: KEYED_DEFINES,
        checks: &["pic-macro"],
        states: None,
        reads: &[Verdict::On],
        why: "`pic-object-relocs` is consulted as `pic-macro`'s twin only where the macro reads \
              absent (`report::MACRO_TWINS`), so a present `__PIC__` that a header forges over \
              a build without position-independent code has no reading to contradict it",
    },
    OpenRoute {
        only: Only::Any,
        name: "__PIC__",
        spellings: &[
            "-include keyed undefine",
            "-imacros keyed undefine",
            "--include= keyed undefine",
            "--imacros= keyed undefine",
        ],
        checks: &["pic-macro"],
        states: Some(&["-fPIC"]),
        reads: &[Verdict::Off],
        why: "the twin `pic-object-relocs` is itself withheld under `macro-supplied-by-profile` \
              where the list carries a forced include, since its probe branches on \
              `__clang__`, so an absent `__PIC__` that a keyed header forges over `-fPIC` \
              meets no reading to contradict it",
    },
    OpenRoute {
        only: Only::Any,
        name: "__PIC__",
        spellings: &[
            "-include keyed undefine",
            "-imacros keyed undefine",
            "--include= keyed undefine",
            "--imacros= keyed undefine",
            "-I shadow undefine",
            "-I split shadow undefine",
            "-isystem shadow undefine",
            "CPATH shadow undefine",
            "C_INCLUDE_PATH shadow undefine",
        ],
        checks: &["pic-macro"],
        states: Some(&["-fPIE", "-pie"]),
        reads: &[Verdict::Off],
        why: "`pic-object-relocs` reads a direct relocation under `-fPIE` by design, so it \
              reads absent beside an absent `__PIC__` that a header forges over a \
              position-independent executable, where the compiler defined the macro",
    },
    OpenRoute {
        only: Only::Any,
        name: "__SSP_EXPLICIT__",
        spellings: KEYED_DEFINES,
        checks: &["ssp-level"],
        states: None,
        reads: &[Verdict::Partial],
        why: "no probe function carries the attribute `-fstack-protector-explicit` protects, so \
              `canary-emitted` and `ssp-level-emitted` read absent with the flag and without \
              it, and the twin rule cannot tell a forged `explicit` from a build with no stack \
              protector",
    },
    OpenRoute {
        only: Only::Gcc,
        name: "__SSP_EXPLICIT__",
        spellings: &[
            "-include undefine",
            "-include keyed undefine",
            "-imacros undefine",
            "-imacros keyed undefine",
            "--include= keyed undefine",
            "--imacros= keyed undefine",
            "-I shadow undefine",
            "-I split shadow undefine",
            "-isystem shadow undefine",
            "CPATH shadow undefine",
            "C_INCLUDE_PATH shadow undefine",
        ],
        checks: &["ssp-level"],
        states: None,
        reads: &[Verdict::Off],
        why: "under `-fstack-protector-explicit` the twins read absent, as they do without a \
              stack protector, since no probe function carries the attribute, so an undefined \
              `__SSP_EXPLICIT__` over an `explicit` build agrees with them",
    },
    OpenRoute {
        only: Only::Clang,
        name: "__OPTIMIZE__",
        spellings: SHADOW_DEFINES_WITH_HANDED,
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        why: "a shadow header under a header search directory, the driver's or one handed to the \
              preprocessor, steers the runtime readings of a probe that branches on a reserved \
              macro, which no rule withholds there; `THREAT_MODEL.md`'s row on forged levels and \
              steered probes names the shadow under `-I` or `-isystem`, the driver's or one handed to \
              the preprocessor, that steers such a probe's runtime and artifact readings unseen",
    },
    OpenRoute {
        only: Only::Clang,
        name: "__OPTIMIZE__",
        spellings: &["--config define"],
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        why: "the listing comparison withholds a branching probe's compile-input readings \
              under a configuration file's define, and not the runtime readings `no-strict-overflow` \
              and `no-strict-aliasing`, whose probes print `optimize=` from `__OPTIMIZE__`",
    },
    OpenRoute {
        only: Only::Any,
        name: "__OPTIMIZE__",
        spellings: ENV_DEFINES,
        checks: &["optimization-enabled"],
        states: None,
        reads: &[Verdict::On],
        why: CPATH_UNREAD,
    },
    OpenRoute {
        only: Only::Any,
        name: "__OPTIMIZE__",
        spellings: ENV_UNDEFINES,
        checks: &["optimization-enabled"],
        states: None,
        reads: &[Verdict::Off],
        why: CPATH_UNREAD,
    },
    OpenRoute {
        only: Only::Any,
        name: "__USE_FORTIFY_LEVEL",
        spellings: ENV_DEFINES,
        checks: &["fortify-effective"],
        states: None,
        reads: &[Verdict::On],
        why: CPATH_UNREAD,
    },
    OpenRoute {
        only: Only::Any,
        name: "_FORTIFY_SOURCE",
        spellings: SHADOW_DEFINES,
        checks: &["fortify-requested"],
        states: None,
        reads: &[Verdict::On],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        name: "_FORTIFY_SOURCE",
        spellings: SHADOW_UNDEFINES,
        checks: &["fortify-requested"],
        states: None,
        reads: &[Verdict::Off],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: CXX_SHADOW_DEFINES,
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::On],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: CXX_SHADOW_UNDEFINES,
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::Off],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Clang,
        name: "__OPTIMIZE__",
        spellings: &["CCC_OVERRIDE_OPTIONS define"],
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        why: CCC_UNREAD,
    },
    OpenRoute {
        only: Only::Clang,
        name: "__OPTIMIZE__",
        spellings: &["CCC_OVERRIDE_OPTIONS define"],
        checks: &["cxx-stdlib-assertions", "cxx-assertions-symbol"],
        states: None,
        reads: &[Verdict::Off],
        why: CCC_UNREAD,
    },
    OpenRoute {
        only: Only::Clang,
        name: "__OPTIMIZE__",
        spellings: &["CCC_OVERRIDE_OPTIONS undefine"],
        checks: &["cxx-stdlib-assertions", "cxx-assertions-symbol"],
        states: None,
        reads: &[Verdict::On],
        why: CCC_UNREAD,
    },
];

/// What the corpus fed and found, for the frame and the cells.
#[derive(Default)]
struct Tally {
    /// The routes the lists make, counted from the lists alone ([`expected_routes`]).
    expected: usize,
    fed: usize,
    /// Routes whose measurement gave no report to judge; each is also a failure.
    errored: usize,
    /// Routes whose forgery did not reach the preprocessor, by driver and macro.
    inert: BTreeMap<(String, String), usize>,
    /// The preprocessor's error lines for routes it could not preprocess, by driver and macro.
    broken: BTreeMap<(String, String), BTreeSet<String>>,
    unconstructible: BTreeMap<String, usize>,
    /// Routes each driver's spelling fed, every spelling the driver takes seeded at zero.
    fed_by_spelling: BTreeMap<String, usize>,
    /// Every driver and macro a route was built for, and those with a reading some rule or
    /// row earned (withheld by a rule, withheld with no rule named, open or forged).
    routed: BTreeSet<(String, String)>,
    earned: BTreeSet<(String, String)>,
    plain: usize,
    readings: usize,
    /// The reached checks of the routes fed, which the readings must number.
    reached_fed: usize,
    withheld_by: BTreeMap<String, usize>,
    /// Withheld with no gating rule named, by verdict: the detector's own withholding.
    unruled: BTreeMap<String, usize>,
    /// Withheld as a harness failure, by verdict.
    harness: BTreeMap<String, usize>,
    /// Withheld with the verdict and rule the plain run withheld it with.
    as_plain: usize,
    /// Published as the plain run published them.
    unmoved: usize,
    open: usize,
    forged: usize,
    /// The [`OPEN_ROUTES`] combinations not yet seen publishing their forged reading.
    open_unseen: BTreeSet<String>,
    cells: Vec<String>,
    failures: Vec<String>,
}

/// The routes the lists make, from the lists alone: for each driver, macro and spelling the
/// driver takes, the states of that direction, or one route counted as not constructible.
fn expected_routes(drivers: &[Driver]) -> usize {
    let mut n = 0_usize;
    for driver in drivers {
        for (name, class) in macros() {
            for spelling in SPELLINGS.iter().filter(|s| applies(s, driver.family)) {
                n += match state(
                    &name,
                    class,
                    spelling.direction,
                    &driver.arch,
                    driver.family,
                ) {
                    Ok(states) if constructible(spelling, class).is_ok() => states.len(),
                    _ => 1,
                };
            }
        }
    }
    n
}

/// The jobs for every driver: each constructible route under each of its states, and each
/// state's plain run, with the routes the target cannot be put in counted by reason.
fn jobs(drivers: &[Driver], tally: &mut Tally) -> Vec<Job> {
    let mut jobs = Vec::new();
    for (d, driver) in drivers.iter().enumerate() {
        for (name, class) in macros() {
            let reached = reached(&name);
            let mut plain: BTreeSet<(Direction, &'static [&'static str])> = BTreeSet::new();
            for (s, spelling) in SPELLINGS.iter().enumerate() {
                if !applies(spelling, driver.family) {
                    continue;
                }
                tally
                    .fed_by_spelling
                    .entry(format!("{} {}", driver.name, spelling.id))
                    .or_default();
                let direction = spelling.direction;
                let states = state(&name, class, direction, &driver.arch, driver.family)
                    .and_then(|states| constructible(spelling, class).map(|()| states));
                let states = match states {
                    Err(why) => {
                        *tally.unconstructible.entry(why.to_owned()).or_default() += 1;
                        continue;
                    }
                    Ok(states) => states,
                };
                assert!(
                    !reached.is_empty(),
                    "{name} is constructible and reaches no reading; the corpus would hold nothing"
                );
                for state in states {
                    plain.insert((direction, state));
                    jobs.push(Job {
                        driver: d,
                        name: name.clone(),
                        direction,
                        spelling: Some(s),
                        state,
                        reached: reached.clone(),
                    });
                }
            }
            for (direction, state) in plain {
                jobs.push(Job {
                    driver: d,
                    name: name.clone(),
                    direction,
                    spelling: None,
                    state,
                    reached: reached.clone(),
                });
            }
        }
    }
    jobs
}

/// The row of [`OPEN_ROUTES`] that names `job`'s reading of `check`, if any.
fn open_row(job: &Job, drivers: &[Driver], check: &str) -> Option<&'static OpenRoute> {
    let s = job.spelling?;
    OPEN_ROUTES.iter().find(|row| {
        (row.only == Only::Any || row.only == drivers[job.driver].family)
            && row.name == job.name
            && row.spellings.contains(&SPELLINGS[s].id)
            && row.checks.contains(&check)
            && row.states.is_none_or(|state| state == job.state)
    })
}

/// Every combination [`OPEN_ROUTES`] names under the drivers the corpus ran, as
/// [`combination`] labels; [`judge_route`] removes each one it sees publish its forged
/// verdict, and what is left is stale. A row whose spelling has no state under a driver of
/// its family names a combination that cannot be met, which is stale too.
fn open_combinations(drivers: &[Driver]) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    for row in OPEN_ROUTES {
        for driver in drivers
            .iter()
            .filter(|d| row.only == Only::Any || row.only == d.family)
        {
            for id in row.spellings {
                let spelling = SPELLINGS
                    .iter()
                    .find(|s| s.id == *id)
                    .expect("a listed spelling");
                let class = macros()
                    .into_iter()
                    .find(|(m, _)| m == row.name)
                    .map_or(MacroClass::CompilerDefined, |(_, c)| c);
                let Ok(states) = state(
                    row.name,
                    class,
                    spelling.direction,
                    &driver.arch,
                    driver.family,
                ) else {
                    all.insert(format!("{} {} {id}: no state", driver.name, row.name));
                    continue;
                };
                for state in states
                    .iter()
                    .filter(|s| row.states.is_none_or(|r| r == **s))
                {
                    for check in row.checks {
                        all.insert(combination(driver.name, row.name, id, state, check));
                    }
                }
            }
        }
    }
    all
}

/// The label of one open combination: driver, macro, spelling, state and check.
fn combination(driver: &str, name: &str, spelling: &str, state: &[&str], check: &str) -> String {
    format!("{driver} {name} {spelling} [{}]: {check}", state.join(" "))
}

/// The plain runs' readings, by driver, macro, direction and state.
type Plain = BTreeMap<(usize, String, Direction, &'static [&'static str]), Vec<Reading>>;

/// Judge the plain runs. A reached check that reads a harness failure holds no route of the state to
/// anything, and a state whose macro checks do not read the direction it was chosen for (a
/// define's state reading one present, an undefine's reading none present where any reads
/// the name) would pass its routes as unmoved; each fails here.
fn judge_plain(
    jobs: &[Job],
    results: &[Result<Outcome, String>],
    drivers: &[Driver],
    tally: &mut Tally,
) -> Plain {
    let mut plain = Plain::new();
    for (job, result) in jobs
        .iter()
        .zip(results)
        .filter(|(j, _)| j.spelling.is_none())
    {
        let label = job.label(drivers);
        let readings = match result {
            Ok(Outcome::Readings(r)) => r,
            Ok(_) => unreachable!("a plain run has no effect check"),
            Err(why) => {
                tally.failures.push(format!("{label}: {why}"));
                continue;
            }
        };
        tally.plain += 1;
        for r in readings {
            tally.cells.push(cell(&label, r));
            if harness_state(r.verdict) {
                tally.failures.push(format!(
                    "{label}: the plain run reads {} {} ({}), a harness failure, so no route in this state measures anything",
                    r.check,
                    verdict_word(r.verdict),
                    r.named()
                ));
            }
        }
        let own: Vec<&Reading> = readings
            .iter()
            .zip(&job.reached)
            .filter(|(_, reached)| reached.by_predicate)
            .map(|(r, _)| r)
            .collect();
        let held = match job.direction {
            Define => !own.iter().any(|r| r.present()),
            Undefine => own.is_empty() || own.iter().any(|r| r.present()),
        };
        if !held {
            tally.failures.push(format!(
                "{label}: no macro check that reads {} reads the state's direction ({}), so the \
                 state does not contradict the routes made in it",
                job.name,
                own.iter()
                    .map(|r| format!("{} {}", r.check, verdict_word(r.verdict)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        plain.insert(
            (job.driver, job.name.clone(), job.direction, job.state),
            readings.clone(),
        );
    }
    plain
}

fn cell(label: &str, r: &Reading) -> String {
    format!(
        "{label}\t{}\t{}\t{}\t{}",
        r.check,
        verdict_word(r.verdict),
        r.level,
        r.named()
    )
}

/// Judge one route against its state's plain run: every reading lands in exactly one part of
/// the tally, which [`reconcile`] sums against the reached checks of the routes fed.
fn judge_route(
    job: &Job,
    drivers: &[Driver],
    result: &Result<Outcome, String>,
    plain: &Plain,
    tally: &mut Tally,
) {
    let label = job.label(drivers);
    let spelling = SPELLINGS[job.spelling.expect("a route")].id;
    let driver = drivers[job.driver].name;
    let pair = (driver.to_owned(), job.name.clone());
    tally.routed.insert(pair.clone());
    let readings = match result {
        Ok(Outcome::Readings(r)) => r,
        Ok(Outcome::Inert) => {
            *tally.inert.entry(pair).or_default() += 1;
            return;
        }
        Ok(Outcome::Broken(why)) => {
            tally.broken.entry(pair).or_default().insert(why.clone());
            return;
        }
        Err(why) => {
            tally.errored += 1;
            tally.failures.push(format!("{label}: {why}"));
            return;
        }
    };
    tally.fed += 1;
    tally.reached_fed += job.reached.len();
    *tally
        .fed_by_spelling
        .entry(format!("{driver} {spelling}"))
        .or_default() += 1;
    let baseline = plain.get(&(job.driver, job.name.clone(), job.direction, job.state));
    for r in readings {
        tally.readings += 1;
        tally.cells.push(cell(&label, r));
        let before = baseline.and_then(|b| b.iter().find(|p| p.check == r.check));
        let published_alike = before.is_some_and(|p| p.verdict == r.verdict && p.level == r.level);
        let withheld_alike = before.is_some_and(|p| p.verdict == r.verdict && p.rule == r.rule);
        let word = verdict_word(r.verdict);
        let earned = match (r.verdict.is_measurement(), open_row(job, drivers, r.check)) {
            (false, _) if harness_state(r.verdict) => {
                *tally.harness.entry(word).or_default() += 1;
                false
            }
            (false, _) if withheld_alike => {
                tally.as_plain += 1;
                false
            }
            (false, _) if r.rule.is_empty() => {
                *tally.unruled.entry(word).or_default() += 1;
                true
            }
            (false, _) => {
                *tally.withheld_by.entry(r.rule.clone()).or_default() += 1;
                true
            }
            (true, _) if published_alike => {
                tally.unmoved += 1;
                false
            }
            (true, Some(row)) if row.reads.contains(&r.verdict) => {
                tally.open += 1;
                tally.open_unseen.remove(&combination(
                    driver, &job.name, spelling, job.state, r.check,
                ));
                true
            }
            (true, _) => {
                tally.forged += 1;
                tally.failures.push(format!(
                    "{label}: {} published {word} at {} over a build the route contradicts",
                    r.check, r.level
                ));
                true
            }
        };
        if earned {
            tally.earned.insert(pair.clone());
        }
    }
}

/// Run `jobs` on [`WORKERS`] threads, each in its own directory under `root`.
fn run_all(
    jobs: &[Job],
    drivers: &[Driver],
    root: &Path,
    assert_host: bool,
) -> Vec<Result<Outcome, String>> {
    let next = AtomicUsize::new(0);
    let results: Mutex<BTreeMap<usize, Result<Outcome, String>>> = Mutex::new(BTreeMap::new());
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(job) = jobs.get(i) else { break };
                    let result = run(job, drivers, &root.join(format!("job-{i}")), assert_host);
                    results.lock().expect("the results lock").insert(i, result);
                }
            });
        }
    });
    results
        .into_inner()
        .expect("the results lock")
        .into_values()
        .collect()
}

/// Does chard, unasked, take this host for one that runs its own kernel on an assumption?
/// Then the corpus asserts it, as `tests/fake_driver.rs` does, so a check that reads kernel
/// policy is measured rather than withheld under `execution-mode-assumed`, which would hold
/// a route for a reason that is not the route's. The basis is printed in the frame.
fn execution_basis(work: &Path) -> String {
    let output = work.join("execution.json");
    let done = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .arg("-o")
        .arg(&output)
        .args(["--cc", "cc", "--probe", "toolchain-macros", "--workdir"])
        .arg(work.join("execution"))
        .output()
        .expect("spawning chard");
    assert!(
        done.status.success(),
        "chard could not measure the macro probe: {done:?}"
    );
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&output).expect("the report")).expect("JSON");
    let basis = report["environment"]["execution"]["mode_evidence"]["basis"]
        .as_str()
        .unwrap_or("");
    assert!(
        !basis.is_empty(),
        "the report names no execution basis: {}",
        report["environment"]["execution"]
    );
    basis.to_owned()
}

/// The first line of `program --version`, which fails the corpus if it cannot be read: the
/// frame names what it measured or it is not a frame.
fn version_line(program: &Path) -> String {
    let done = Command::new(program)
        .arg("--version")
        .output()
        .unwrap_or_else(|e| panic!("{} --version could not run: {e}", program.display()));
    let line = String::from_utf8_lossy(&done.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    assert!(
        done.status.success() && !line.is_empty(),
        "{} --version named no version: {done:?}",
        program.display()
    );
    line
}

fn print_frame(tally: &Tally, drivers: &[Driver], basis: &str) {
    let names: Vec<String> = drivers
        .iter()
        .map(|d| {
            let n = SPELLINGS.iter().filter(|s| applies(s, d.family)).count();
            format!("{} ({}, {n} spellings, {})", d.name, d.arch, d.version)
        })
        .collect();
    let sum = |m: &BTreeMap<String, usize>| m.values().sum::<usize>();
    let broken: usize = tally.broken.values().map(BTreeSet::len).sum();
    let mut lines = vec![
        format!(
            "route_corpus: {}, execution basis {basis}; {} macros, {} spellings; under {}",
            version_line(&chard_binary()),
            macros().len(),
            SPELLINGS.len(),
            names.join("; ")
        ),
        format!(
            "route_corpus: {} routes expected: {} fed, {} inert, {} broken, {} errored, {} not \
             constructible; {} plain runs; {} readings: {} withheld by a rule, {} with no rule \
             named, {} as a harness failure, {} as the plain run withheld them, {} published as \
             the plain run, {} open, {} forged",
            tally.expected,
            tally.fed,
            tally.inert.values().sum::<usize>(),
            broken,
            tally.errored,
            sum(&tally.unconstructible),
            tally.plain,
            tally.readings,
            sum(&tally.withheld_by),
            sum(&tally.unruled),
            sum(&tally.harness),
            tally.as_plain,
            tally.unmoved,
            tally.open,
            tally.forged
        ),
    ];
    let detail = [
        ("withheld under", &tally.withheld_by),
        ("withheld with no rule, as", &tally.unruled),
        ("withheld as", &tally.harness),
        ("not constructible", &tally.unconstructible),
    ];
    for (what, map) in detail {
        lines.extend(map.iter().map(|(k, n)| format!("  {what} {k}: {n}")));
    }
    lines.extend(
        tally
            .inert
            .iter()
            .map(|((d, m), n)| format!("  inert {d} {m}: {n}")),
    );
    lines.extend(
        tally
            .broken
            .iter()
            .map(|((d, m), why)| format!("  broken {d} {m}: {why:?}")),
    );
    lines.extend(
        tally
            .routed
            .difference(&tally.earned)
            .map(|(d, m)| format!("  measures nothing {d} {m}")),
    );
    lines.extend(OPEN_ROUTES.iter().map(|row| {
        let reads: Vec<String> = row.reads.iter().map(|v| verdict_word(*v)).collect();
        format!(
            "  open: {} through {} reaching {} reads {}: {}",
            row.name,
            row.spellings.join(", "),
            row.checks.join(", "),
            reads.join(" or "),
            row.why
        )
    }));
    for line in &lines {
        println!("{line}");
    }
    common::record("count", &lines.join("; "));
}

fn write_cells(tally: &Tally) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("route-corpus");
    std::fs::create_dir_all(&dir).expect("the cells directory");
    let mut cells = tally.cells.clone();
    cells.sort();
    let header = "route\tcheck\tverdict\tlevel\trule\n";
    std::fs::write(
        dir.join("cells.tsv"),
        format!("{header}{}\n", cells.join("\n")),
    )
    .expect("writing the cells");
    println!("route_corpus: cells in {}", dir.join("cells.tsv").display());
}

/// The parts of the tally sum to what was fed: every route is fed, inert, broken, errored or
/// not constructible, and every reading lands in one part.
fn reconcile(tally: &mut Tally, jobs: &[Job]) {
    let sum = |m: &BTreeMap<String, usize>| m.values().sum::<usize>();
    let routes = jobs.iter().filter(|j| j.spelling.is_some()).count();
    let broken: usize = tally.broken.values().map(BTreeSet::len).sum();
    let broken_routes = routes - tally.fed - tally.inert.values().sum::<usize>() - tally.errored;
    if routes + sum(&tally.unconstructible) != tally.expected {
        tally.failures.push(format!(
            "the routes do not add up: {routes} built and {} not constructible, {} expected \
             from the lists",
            sum(&tally.unconstructible),
            tally.expected
        ));
    }
    if broken > broken_routes {
        tally.failures.push(format!(
            "{broken} distinct preprocessor failures over {broken_routes} broken routes"
        ));
    }
    let parts = sum(&tally.withheld_by)
        + sum(&tally.unruled)
        + sum(&tally.harness)
        + tally.as_plain
        + tally.unmoved
        + tally.open
        + tally.forged;
    if parts != tally.readings || tally.readings != tally.reached_fed {
        tally.failures.push(format!(
            "the readings do not add up: {} judged, {parts} in the parts, {} reached by the \
             routes fed",
            tally.readings, tally.reached_fed
        ));
    }
    let dead: Vec<&String> = tally
        .fed_by_spelling
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(s, _)| s)
        .collect();
    if !dead.is_empty() {
        tally.failures.push(format!(
            "spellings whose forgery reached the preprocessor for no macro: {dead:?}"
        ));
    }
    let allowed = |list: &[(&str, &str)], name: &str| list.iter().any(|(m, _)| *m == name);
    let unexpected: Vec<String> = tally
        .inert
        .keys()
        .filter(|(_, m)| !allowed(INERT, m))
        .map(|(d, m)| format!("{d} {m} inert"))
        .chain(
            tally
                .broken
                .keys()
                .filter(|(_, m)| !allowed(BROKEN, m))
                .map(|(d, m)| format!("{d} {m} broken")),
        )
        .chain(
            tally
                .routed
                .difference(&tally.earned)
                .filter(|(_, m)| !allowed(MEASURES_NOTHING, m))
                .map(|(d, m)| format!("{d} {m} measures nothing")),
        )
        .collect();
    if !unexpected.is_empty() {
        tally.failures.push(format!(
            "routes that hold nothing, for no reason INERT, BROKEN or MEASURES_NOTHING gives: \
             {unexpected:?}"
        ));
    }
    let stale: Vec<String> = tally
        .open_unseen
        .iter()
        .map(|c| {
            format!("{c} is named in OPEN_ROUTES and did not publish its forged reading; retire it")
        })
        .collect();
    tally.failures.extend(stale);
}

/// The macros whose forgery a C library's headers settle away after an earlier spelling, so
/// those routes are inert, with why. Inert routes of any other macro fail the corpus.
const INERT: &[(&str, &str)] = &[(
    "__USE_FORTIFY_LEVEL",
    "glibc's `features.h` defines it from `_FORTIFY_SOURCE` and `__OPTIMIZE__` after any \
     spelling that reaches the preprocessor before the source",
)];

/// The macros whose forgery breaks the preprocessing of `<stdio.h>` under some driver, with
/// why. Broken routes of any other macro fail the corpus.
const BROKEN: &[(&str, &str)] = &[(
    "__FreeBSD__",
    "gcc's `stddef.h` includes FreeBSD's `sys/_types.h` under it, which glibc has not",
)];

/// The macros some driver's routes measure nothing for on the targets the corpus has run on
/// (no reading withheld by a rule, withheld with no rule named, open or forged), with why. A
/// driver and macro outside this list whose routes hold nothing fail the corpus.
const MEASURES_NOTHING: &[(&str, &str)] = &[
    (
        "_LIBCPP_HARDENING_MODE",
        "beside libstdc++ `cxx-hardening-requested` does not read libc++'s request, so a \
         forged one reads as the plain run",
    ),
    (
        "__FreeBSD__",
        "off FreeBSD the C library's headers break under it (gcc) or the probes do not build \
         (clang)",
    ),
    (
        "__ARM_FEATURE_BTI_DEFAULT",
        "off `aarch64` its check is gated by the target, as in the plain run",
    ),
    (
        "__ARM_FEATURE_PAC_DEFAULT",
        "off `aarch64` its check is gated by the target, as in the plain run",
    ),
    (
        "__ARM_FEATURE_GCS_DEFAULT",
        "off `aarch64` its check is gated by the target, as in the plain run",
    ),
];

/// Every route of the table is withheld by some rule, or named open.
#[test]
fn every_route_of_the_table_is_withheld_or_named_open() {
    let verifies = "every forging route of the table is withheld";
    if !(common::require_binary(&chard_binary(), verifies) && common::require_cc(verifies)) {
        return;
    }
    let drivers = drivers();
    if drivers.is_empty() {
        common::refuse("neither gcc nor clang is on PATH", verifies);
        return;
    }
    let work = common::Work::new("route-corpus", "all");
    let basis = execution_basis(work.dir());
    let mut tally = Tally {
        expected: expected_routes(&drivers),
        open_unseen: open_combinations(&drivers),
        ..Tally::default()
    };
    let jobs = jobs(&drivers, &mut tally);
    let results = run_all(&jobs, &drivers, work.dir(), basis == "assumed-host");
    assert_eq!(results.len(), jobs.len(), "every job ran once");
    let plain = judge_plain(&jobs, &results, &drivers, &mut tally);
    for (job, result) in jobs
        .iter()
        .zip(&results)
        .filter(|(j, _)| j.spelling.is_some())
    {
        judge_route(job, &drivers, result, &plain, &mut tally);
    }
    reconcile(&mut tally, &jobs);
    print_frame(&tally, &drivers, &basis);
    write_cells(&tally);
    assert!(
        tally.failures.is_empty(),
        "{} failures:\n{}",
        tally.failures.len(),
        tally.failures.join("\n")
    );
}

/// Every macro of the lists has its two states under each family on each target the corpus
/// can meet, or a declared reason it has none; [`state`] panics on a macro it has no row for,
/// a state it gives is never an empty list, and every compiler-defined and identity macro has
/// a route on `x86_64` under some driver.
#[test]
fn every_reason_a_route_is_not_built_is_declared() {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (name, class) in macros() {
        let mut built_on_x86 = false;
        for direction in [Define, Undefine] {
            for arch in ["x86_64", "aarch64", "riscv64"] {
                for family in [Only::Gcc, Only::Clang] {
                    match state(&name, class, direction, arch, family) {
                        Ok(states) => {
                            assert!(!states.is_empty(), "{name} {direction:?} has no state");
                            built_on_x86 |= arch == "x86_64";
                        }
                        Err(why) => {
                            assert!(UNCONSTRUCTIBLE.contains(&why), "undeclared reason: {why}");
                            seen.insert(why);
                        }
                    }
                }
            }
        }
        assert!(
            built_on_x86 || class == MacroClass::Request,
            "{name} has no route on x86_64"
        );
    }
    seen.insert(REQUEST_HONEST);
    let unused: Vec<&&str> = UNCONSTRUCTIBLE
        .iter()
        .filter(|r| !seen.contains(**r))
        .collect();
    assert!(
        unused.is_empty(),
        "declared reasons no state gives: {unused:?}"
    );
}

/// A compiler-defined or identity macro reaching no reading would make every route of it pass
/// on nothing.
#[test]
fn every_compiler_macro_reaches_a_reading() {
    let unreached: Vec<String> = macros()
        .into_iter()
        .filter(|(m, class)| *class != MacroClass::Request && reached(m).is_empty())
        .map(|(m, _)| m)
        .collect();
    assert!(
        unreached.is_empty(),
        "no check reads or branches on {unreached:?}"
    );
}

/// The shadow spellings put their operation in a `stdio.h`, which reaches a probe only where
/// the probe includes `<stdio.h>` or `<cstdio>` itself; every probe a macro reaches does.
#[test]
fn every_reached_probe_includes_the_header_the_shadows_replace() {
    for (name, _) in macros() {
        for r in reached(&name) {
            let probe = CORPUS.iter().find(|p| p.id == r.probe).expect("a probe");
            assert!(
                probe.source.contains("#include <stdio.h>")
                    || probe.source.contains("#include <cstdio>"),
                "{} reaches {} and includes no <stdio.h>",
                name,
                r.probe
            );
        }
    }
}

/// Each open row names a listed macro, spellings of the table under its family that share one
/// direction, checks the macro reaches, a state the macro has on `x86_64` (where the rows were
/// measured), published verdicts, which for a macro check forge its direction (present for a
/// define, `off` for an undefine; a probe a forged macro steers reads either), and says why.
#[test]
fn every_open_route_names_what_the_table_holds() {
    let listed = macros();
    for row in OPEN_ROUTES {
        let (_, class) = listed
            .iter()
            .find(|(m, _)| m == row.name)
            .unwrap_or_else(|| panic!("{} is on no list", row.name));
        let mut directions = BTreeSet::new();
        for id in row.spellings {
            let spelling = SPELLINGS
                .iter()
                .find(|s| s.id == *id && (s.only == Only::Any || s.only == row.only))
                .unwrap_or_else(|| {
                    panic!("{id} is not a spelling of the table under {:?}", row.only)
                });
            directions.insert(spelling.direction);
            if let Some(want) = row.states {
                let family = if row.only == Only::Clang {
                    Only::Clang
                } else {
                    Only::Gcc
                };
                let states = state(row.name, *class, spelling.direction, "x86_64", family)
                    .unwrap_or_else(|why| panic!("{} {id} has no state: {why}", row.name));
                assert!(
                    states.contains(&want),
                    "{} {id} has no state {want:?}",
                    row.name
                );
            }
        }
        assert_eq!(directions.len(), 1, "{} mixes directions", row.name);
        let forges = |v: &Verdict| match directions.first() {
            Some(Define) => matches!(v, Verdict::On | Verdict::Partial),
            _ => *v == Verdict::Off,
        };
        let reached = reached(row.name);
        let macro_checks = row
            .checks
            .iter()
            .all(|c| reached.iter().any(|r| r.check == *c && r.by_predicate));
        assert!(
            !row.reads.is_empty() && (!macro_checks || row.reads.iter().all(forges)),
            "{}'s verdicts {:?} do not forge its direction",
            row.name,
            row.reads
        );
        for check in row.checks {
            assert!(
                reached.iter().any(|r| r.check == *check),
                "{} does not reach {check}",
                row.name
            );
        }
        assert!(!row.why.is_empty(), "the row for {} says why", row.name);
    }
    let ids: BTreeSet<&str> = SPELLINGS.iter().map(|s| s.id).collect();
    assert_eq!(ids.len(), SPELLINGS.len(), "each spelling is named once");
}

fn synthetic_driver() -> Vec<Driver> {
    vec![Driver {
        name: "gcc",
        family: Only::Gcc,
        arch: "x86_64".to_owned(),
        version: "synthetic".to_owned(),
    }]
}

fn synthetic_job(spelling: Option<usize>, direction: Direction) -> Job {
    Job {
        driver: 0,
        name: "__CET__".to_owned(),
        direction,
        spelling,
        state: &["-fcf-protection=none"],
        reached: reached("__CET__"),
    }
}

fn synthetic_reading(check: &'static str, verdict: Verdict) -> Reading {
    Reading {
        check,
        verdict,
        level: "null".to_owned(),
        rule: String::new(),
    }
}

/// The judges fail what they exist to fail: a route publishing a reading its plain run did
/// not, and a state whose macro check reads the direction its routes forge.
#[test]
fn the_judges_fail_a_forged_reading_and_a_state_that_contradicts_nothing() {
    let drivers = synthetic_driver();
    let route = synthetic_job(SPELLINGS.iter().position(|s| s.id == "-D"), Define);
    let plain_job = synthetic_job(None, Define);
    let checks: Vec<&'static str> = route.reached.iter().map(|r| r.check).collect();
    let honest: Vec<Reading> = checks
        .iter()
        .map(|c| synthetic_reading(c, Verdict::Off))
        .collect();
    let mut tally = Tally::default();
    let plain = judge_plain(
        &[plain_job],
        &[Ok(Outcome::Readings(honest.clone()))],
        &drivers,
        &mut tally,
    );
    assert!(tally.failures.is_empty(), "{:?}", tally.failures);
    let forged: Vec<Reading> = checks
        .iter()
        .map(|c| synthetic_reading(c, Verdict::On))
        .collect();
    judge_route(
        &route,
        &drivers,
        &Ok(Outcome::Readings(forged)),
        &plain,
        &mut tally,
    );
    assert_eq!(tally.forged, checks.len(), "{:?}", tally.failures);
    assert_eq!(tally.failures.len(), checks.len());
    let mut tally = Tally::default();
    let present: Vec<Reading> = checks
        .iter()
        .map(|c| synthetic_reading(c, Verdict::On))
        .collect();
    judge_plain(
        &[synthetic_job(None, Define)],
        &[Ok(Outcome::Readings(present))],
        &drivers,
        &mut tally,
    );
    assert_eq!(tally.failures.len(), 1, "{:?}", tally.failures);
}
