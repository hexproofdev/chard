// SPDX-License-Identifier: BSD-3-Clause

//! The routes of this table by which a profile forges a macro chard reads are each withheld,
//! or named open.

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

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use chard::probe::{CFI_COMPONENTS, CORPUS, Channel, Levels};
use chard::report::Verdict;
use serde_json::Value;

mod common;

use common::chard_binary;

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
    /// `CPLUS_INCLUDE_PATH=DIR`, through chard's `--env`, which only a C++ compile reads.
    CplusIncludePath,
    /// `-iprefix PARENT -iwithprefixbefore /DIR`, which puts `PARENT/DIR` where `-I` would: gcc
    /// 16.2.1 and clang 22.1.8 join the operand to the prefix as written (measured with `-v` on
    /// Fedora 44 x86_64).
    IwithprefixBefore,
    /// `-iprefix PARENT -iwithprefix /DIR`, which gcc 16.2.1 puts ahead of the system
    /// directories (measured with `-v` on Fedora 44 x86_64) and clang 22.1.8 after them.
    Iwithprefix,
    /// `--include-directory=DIR`, the long form of `-I`.
    IncludeDirectory,
    /// `--include-directory DIR`.
    IncludeDirectorySplit,
    /// `-iwithsysroot DIR`, clang's: `DIR` under the system root, which is empty unless one is
    /// named, so `DIR` itself.
    Iwithsysroot,
    /// `-Xclang -c-isystem -Xclang DIR`, clang's `-cc1` system directory for C (its driver
    /// refuses `-c-isystem`).
    XclangCIsystem,
    /// `-cxx-isystem DIR`, clang's system directory for C++ alone, searched ahead of the C++
    /// library's.
    CxxIsystem,
}

/// A directory of the toolchain's own layout that a path word names, holding a shadow where the
/// driver looks for a header. Each is built under the job's directory by [`layout_words`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// `--sysroot=ROOT`, ROOT a mirror of `/` whose `usr/include/stdio.h` is the shadow.
    Sysroot,
    /// `-isysroot ROOT`, the same mirror, for headers alone.
    Isysroot,
    /// `-BPREFIX/`, gcc reading `PREFIX/include` as a system header directory.
    B,
    /// `--prefix=PREFIX/`, gcc's long form of `-B`.
    Prefix,
    /// `--gcc-install-dir=DIR`, DIR a mirror of the GCC installation clang selected, under a
    /// mirror of its prefix whose `include/c++/VERSION/cstdio` is the shadow.
    GccInstallDir,
    /// `--gcc-toolchain=PREFIX`, the same mirror named by its prefix.
    GccToolchain,
    /// `-resource-dir DIR`, DIR a mirror of clang's resource directory with a `stdio.h` added
    /// to its `include`, which clang searches ahead of the C library's.
    ResourceDir,
    /// `-stdlib++-isystem DIR` for each directory of the C++ library's search list, the one
    /// holding `cstdio` replaced by the GCC installation's mirror. The option replaces the
    /// library's list rather than adding to it, so a shadow `cstdio` alone in a directory it
    /// names breaks the compile (clang 22.1.8 on Fedora 44 x86_64: `'cstdio' file not found`).
    StdlibIsystem,
    /// `-ccc-install-dir PREFIX/bin`, PREFIX the GCC installation's mirror: clang selects the
    /// installation under the directory it is told it is installed in, and searches that
    /// installation's C++ library (clang 22.1.8 on Fedora 44 x86_64: `Selected GCC
    /// installation:` the mirror's, and a C compile's search list unchanged).
    CccInstallDir,
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
    /// A shadow under a directory of the toolchain's layout, keyed on [`GATE`].
    Layout(Layout),
    /// A wrapper handed to chard as the driver, adding the operation to the job whose output
    /// name ends in `-measured` and to no other.
    Wrapper,
}

/// The language a spelling's effect is checked in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lang {
    C,
    Cxx,
}

impl Carrier {
    /// C++ for the carriers only a C++ compile reads: `CPLUS_INCLUDE_PATH`, and the GCC
    /// installation, whose headers clang searches for the C++ library alone (with clang 22.1.8
    /// on Fedora 44 x86_64, `--gcc-install-dir=` and `--gcc-toolchain=` left a C compile's
    /// header search list as it was and put the installation's `include/c++` ahead of it in a
    /// C++ one), and clang's `-cxx-isystem`, `-stdlib++-isystem` and `-ccc-install-dir`, the
    /// last two acting through the C++ library alone as the installation's words do.
    fn lang(self) -> Lang {
        match self {
            Carrier::Shadow(Shadow::CplusIncludePath | Shadow::CxxIsystem)
            | Carrier::Layout(
                Layout::GccInstallDir
                | Layout::GccToolchain
                | Layout::StdlibIsystem
                | Layout::CccInstallDir,
            ) => Lang::Cxx,
            _ => Lang::C,
        }
    }
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
    spelling(
        "CPLUS_INCLUDE_PATH shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::CplusIncludePath),
    ),
    spelling(
        "CPLUS_INCLUDE_PATH shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::CplusIncludePath),
    ),
    spelling(
        "--sysroot shadow define",
        Define,
        Only::Any,
        Carrier::Layout(Layout::Sysroot),
    ),
    spelling(
        "--sysroot shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Layout(Layout::Sysroot),
    ),
    spelling(
        "-isysroot shadow define",
        Define,
        Only::Gcc,
        Carrier::Layout(Layout::Isysroot),
    ),
    spelling(
        "-isysroot shadow undefine",
        Undefine,
        Only::Gcc,
        Carrier::Layout(Layout::Isysroot),
    ),
    spelling(
        "-B shadow define",
        Define,
        Only::Gcc,
        Carrier::Layout(Layout::B),
    ),
    spelling(
        "-B shadow undefine",
        Undefine,
        Only::Gcc,
        Carrier::Layout(Layout::B),
    ),
    spelling(
        "--prefix= shadow define",
        Define,
        Only::Gcc,
        Carrier::Layout(Layout::Prefix),
    ),
    spelling(
        "--prefix= shadow undefine",
        Undefine,
        Only::Gcc,
        Carrier::Layout(Layout::Prefix),
    ),
    spelling(
        "--gcc-install-dir= shadow define",
        Define,
        Only::Clang,
        Carrier::Layout(Layout::GccInstallDir),
    ),
    spelling(
        "--gcc-install-dir= shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Layout(Layout::GccInstallDir),
    ),
    spelling(
        "--gcc-toolchain= shadow define",
        Define,
        Only::Clang,
        Carrier::Layout(Layout::GccToolchain),
    ),
    spelling(
        "--gcc-toolchain= shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Layout(Layout::GccToolchain),
    ),
    spelling(
        "-resource-dir shadow define",
        Define,
        Only::Clang,
        Carrier::Layout(Layout::ResourceDir),
    ),
    spelling(
        "-resource-dir shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Layout(Layout::ResourceDir),
    ),
    spelling(
        "-iwithprefixbefore shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::IwithprefixBefore),
    ),
    spelling(
        "-iwithprefixbefore shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::IwithprefixBefore),
    ),
    spelling(
        "-iwithprefix shadow define",
        Define,
        Only::Gcc,
        Carrier::Shadow(Shadow::Iwithprefix),
    ),
    spelling(
        "-iwithprefix shadow undefine",
        Undefine,
        Only::Gcc,
        Carrier::Shadow(Shadow::Iwithprefix),
    ),
    spelling(
        "--include-directory= shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::IncludeDirectory),
    ),
    spelling(
        "--include-directory= shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::IncludeDirectory),
    ),
    spelling(
        "--include-directory split shadow define",
        Define,
        Only::Any,
        Carrier::Shadow(Shadow::IncludeDirectorySplit),
    ),
    spelling(
        "--include-directory split shadow undefine",
        Undefine,
        Only::Any,
        Carrier::Shadow(Shadow::IncludeDirectorySplit),
    ),
    spelling(
        "-iwithsysroot shadow define",
        Define,
        Only::Clang,
        Carrier::Shadow(Shadow::Iwithsysroot),
    ),
    spelling(
        "-iwithsysroot shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Shadow(Shadow::Iwithsysroot),
    ),
    spelling(
        "-Xclang -c-isystem shadow define",
        Define,
        Only::Clang,
        Carrier::Shadow(Shadow::XclangCIsystem),
    ),
    spelling(
        "-Xclang -c-isystem shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Shadow(Shadow::XclangCIsystem),
    ),
    spelling(
        "-cxx-isystem shadow define",
        Define,
        Only::Clang,
        Carrier::Shadow(Shadow::CxxIsystem),
    ),
    spelling(
        "-cxx-isystem shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Shadow(Shadow::CxxIsystem),
    ),
    spelling(
        "-stdlib++-isystem shadow define",
        Define,
        Only::Clang,
        Carrier::Layout(Layout::StdlibIsystem),
    ),
    spelling(
        "-stdlib++-isystem shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Layout(Layout::StdlibIsystem),
    ),
    spelling(
        "-ccc-install-dir shadow define",
        Define,
        Only::Clang,
        Carrier::Layout(Layout::CccInstallDir),
    ),
    spelling(
        "-ccc-install-dir shadow undefine",
        Undefine,
        Only::Clang,
        Carrier::Layout(Layout::CccInstallDir),
    ),
    spelling("wrapper define", Define, Only::Any, Carrier::Wrapper),
    spelling("wrapper undefine", Undefine, Only::Any, Carrier::Wrapper),
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
    CXX_UNREAD,
    "clang has no -fstack-protector-explicit",
    "the macro is defined only by a C library or platform other than this one",
    GCS_UNDEFINED,
    "the AArch64 feature macros are defined only on AArch64 targets",
    "`__CET__` is defined only on x86 targets",
    "clang defines `__clang__` itself",
    "only clang defines `__clang__`",
    "`_LIBCPP_HARDENING_MODE` is read as a request only beside libc++",
];

/// Why an undefine of `__ARM_FEATURE_GCS_DEFAULT` is not constructible under a driver
/// [`gcs_by_standard`] finds does not define it.
const GCS_UNDEFINED: &str = "this driver does not define `__ARM_FEATURE_GCS_DEFAULT` under \
                             `-mbranch-protection=standard`, the one GCS state the corpus builds";

/// Why a route through a spelling only a C++ compile reads is not constructible.
const CXX_UNREAD: &str = "only a C++ compile reads this spelling, and no C++ probe reads or \
                          branches on the macro";

/// Why a request route through a spelling other than a shadow header is not constructible.
const REQUEST_HONEST: &str = "a request macro spelled before the C library's headers is the \
                              request itself, honest by construction";

/// The builds a route of `name` contradicts, each as the flags that make it: without the
/// protection for a define, with it for an undefine, on a target of `arch` under `family`;
/// `gcs` is whether the driver defines `__ARM_FEATURE_GCS_DEFAULT` under
/// `-mbranch-protection=standard` ([`gcs_by_standard`]).
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
    gcs: bool,
    family: Only,
) -> Result<States, &'static str> {
    if class == MacroClass::Request && reached(name).is_empty() {
        return Err(REQUEST_UNREAD);
    }
    match class {
        MacroClass::CompilerDefined => compiler_state(name, direction, arch, gcs, family),
        MacroClass::Identity => identity_state(name, direction, family),
        MacroClass::Request => request_state(name, direction),
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "an Err is a declared reason a route is not constructible, which the corpus counts \
              as one route; a macro the table has no row for is a gap in this test, so it fails \
              the test rather than read as a reason"
)]
fn compiler_state(
    name: &str,
    direction: Direction,
    arch: &str,
    gcs: bool,
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
        ("__ARM_FEATURE_GCS_DEFAULT", Define) if aarch64 => Ok(&[&["-mbranch-protection=none"]]),
        // A component of `-mbranch-protection` alone is a state of its own beside `none` and
        // `standard`: the other component's define is built over it, and its own undefine.
        ("__ARM_FEATURE_BTI_DEFAULT", Define) if aarch64 => Ok(&[
            &["-mbranch-protection=none"],
            &["-mbranch-protection=pac-ret"],
        ]),
        ("__ARM_FEATURE_PAC_DEFAULT", Define) if aarch64 => {
            Ok(&[&["-mbranch-protection=none"], &["-mbranch-protection=bti"]])
        }
        ("__ARM_FEATURE_BTI_DEFAULT", Undefine) if aarch64 => Ok(&[
            &["-mbranch-protection=standard"],
            &["-mbranch-protection=bti"],
        ]),
        ("__ARM_FEATURE_PAC_DEFAULT", Undefine) if aarch64 => Ok(&[
            &["-mbranch-protection=standard"],
            &["-mbranch-protection=pac-ret"],
        ]),
        ("__ARM_FEATURE_GCS_DEFAULT", Undefine) if aarch64 && gcs => {
            Ok(&[&["-mbranch-protection=standard"]])
        }
        ("__ARM_FEATURE_GCS_DEFAULT", Undefine) if aarch64 => Err(GCS_UNDEFINED),
        ("__CET__", Define) if x86 => Ok(&[&["-fcf-protection=none"]]),
        // Off FreeBSD nothing defines it, and a define claims FreeBSD's fortified library.
        ("__FreeBSD__", Define) => Ok(&[&["-U_FORTIFY_SOURCE"]]),
        // Off the macro's own target nothing defines it, so the build is already without
        // what a define claims.
        (
            "__ARM_FEATURE_BTI_DEFAULT"
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
        // Unfortified, so a driver that fortifies an optimised build by default (Ubuntu's gcc)
        // builds the state other drivers do.
        ("__OPTIMIZE__", Undefine) => Ok(&[&["-O2", "-U_FORTIFY_SOURCE"]]),
        ("__EXCEPTIONS", Define) => Ok(&[&["-fno-exceptions"]]),
        ("__EXCEPTIONS", Undefine) => Ok(&[&["-fexceptions"]]),
        _ => panic!("the route corpus has no state for {name} ({direction:?})"),
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "an Err is a declared reason a route is not constructible; a macro with no row is a \
              gap in this test, as in compiler_state"
)]
fn identity_state(name: &str, direction: Direction, family: Only) -> Result<States, &'static str> {
    match (name, direction, family) {
        ("__clang__", Define, Only::Gcc) | ("__clang__", Undefine, Only::Clang) => Ok(&[&[]]),
        ("__clang__", Define, _) => Err("clang defines `__clang__` itself"),
        ("__clang__", Undefine, _) => Err("only clang defines `__clang__`"),
        _ => panic!("the route corpus has no state for the identity macro {name}"),
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "an Err is a declared reason a route is not constructible; a macro with no row is a \
              gap in this test, as in compiler_state"
)]
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
    /// The C++ driver beside it, by the name `compile::cxx_driver_for` maps `name` to.
    cxx: &'static str,
    family: Only,
    /// The target's architecture, from `-dumpmachine`, which decides the states.
    arch: String,
    /// Whether the driver defines `__ARM_FEATURE_GCS_DEFAULT` under
    /// `-mbranch-protection=standard`, which decides that macro's undefine state.
    gcs: bool,
    /// Whether the C++ driver's library defines `_GLIBCXX_ASSERTIONS` at `-O0` and not at
    /// `-O2`, which decides whether a forged `__OPTIMIZE__` reaches the C++ library's assertion
    /// checks ([`OpenRoute::holds_on`]); `None` where no C++ driver was there to measure.
    assertions_follow_optimize: Option<bool>,
    /// The first line of `--version`, for the frame.
    version: String,
}

/// The absolute path of `name` on `PATH`, read without running anything, for a wrapper to run.
fn on_path(name: &str) -> Result<std::path::PathBuf, String> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .ok_or_else(|| format!("no `{name}` on PATH for the wrapper to run"))
}

/// The GCC installation clang selected, from the `Selected GCC installation:` line of `-v`.
fn gcc_installation(driver: &str) -> Result<std::path::PathBuf, String> {
    let done = driver_command(driver, &[])
        .arg("-v")
        .output()
        .map_err(|e| format!("`{driver} -v` could not run: {e}"))?;
    let stderr = String::from_utf8_lossy(&done.stderr);
    let path = stderr
        .lines()
        .find_map(|l| l.strip_prefix("Selected GCC installation: "))
        .ok_or_else(|| format!("`{driver} -v` names no GCC installation"))?;
    std::fs::canonicalize(path.trim()).map_err(|e| format!("{path}: {e}"))
}

/// The C++ library's header directories in the order `driver`'s C++ driver searches them: the
/// entries of its `-v` search list with a `c++` component, resolved, wherever the distribution
/// puts them. On Fedora 44 x86_64 under clang 22.1.8 they are `include/c++/16`, its
/// `x86_64-redhat-linux` and its `backward`.
fn cxx_library_dirs(driver: &Driver) -> Result<Vec<std::path::PathBuf>, String> {
    let done = driver_command(driver.cxx, &[])
        .args(["-v", "-fsyntax-only", "-x", "c++", "/dev/null"])
        .output()
        .map_err(|e| format!("`{} -v` could not run: {e}", driver.cxx))?;
    let stderr = String::from_utf8_lossy(&done.stderr);
    let dirs: Vec<std::path::PathBuf> = stderr
        .lines()
        .skip_while(|l| !l.starts_with("#include <...> search starts here:"))
        .skip(1)
        .take_while(|l| !l.starts_with("End of search list."))
        .map(|l| Path::new(l.trim()))
        .filter(|p| p.components().any(|c| c.as_os_str() == "c++"))
        .map(|p| std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display())))
        .collect::<Result<_, _>>()?;
    if dirs.is_empty() {
        return Err(format!(
            "`{} -v` names no C++ library directory in its search list",
            driver.cxx
        ));
    }
    Ok(dirs)
}

/// clang's resource directory, from `-print-resource-dir`.
fn resource_dir(driver: &str) -> Result<std::path::PathBuf, String> {
    let done = driver_command(driver, &[])
        .arg("-print-resource-dir")
        .output()
        .map_err(|e| format!("`{driver} -print-resource-dir` could not run: {e}"))?;
    let path = String::from_utf8_lossy(&done.stdout).trim().to_owned();
    std::fs::canonicalize(&path).map_err(|e| format!("the resource directory {path:?}: {e}"))
}

/// The compilers the corpus must run under, from `CHARD_ROUTE_DRIVERS`: words from `gcc` and
/// `clang`. `make test` sets it from the Makefile's `ROUTE_DRIVERS`, both unless the command
/// line names others, so a host that lost one fails `make test`. The test
/// ledger does not fail on a gap, so without this the lost compiler's routes would pass unrun.
/// Unset or empty, as under a bare `cargo test`, none is required. Read by the tests alone;
/// chard reads nothing from the environment but `PATH`.
fn required_drivers() -> Vec<String> {
    let names: Vec<String> = std::env::var("CHARD_ROUTE_DRIVERS")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    for name in &names {
        assert!(
            name == "gcc" || name == "clang",
            "CHARD_ROUTE_DRIVERS names `{name}`; the corpus runs under gcc and clang"
        );
    }
    names
}

/// A driver this host lacks: announced as a gap, as a compiler this host lacks is everywhere in
/// the suite (`common::capability_gap`), or a failure where the gate requires it.
fn missing_driver(name: &str, arm: &str, why: &str) {
    assert!(
        !required_drivers().iter().any(|n| n == name),
        "{arm}: {why}; CHARD_ROUTE_DRIVERS requires `{name}`"
    );
    common::capability_gap(arm, why);
}

/// gcc and clang where each is on `PATH`. A missing one is a gap, or a failure where the gate
/// requires it ([`required_drivers`]); one that is present and fails to name its target fails
/// the corpus.
fn drivers() -> Vec<Driver> {
    let mut found = Vec::new();
    for (name, cxx, family) in [("gcc", "g++", Only::Gcc), ("clang", "clang++", Only::Clang)] {
        let machine = match driver_command(name, &[]).arg("-dumpmachine").output() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing_driver(
                    name,
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
        let gcs = arch == "aarch64" && gcs_by_standard(name);
        let assertions_follow_optimize = assertions_follow_optimize(name, cxx);
        found.push(Driver {
            name,
            cxx,
            family,
            arch,
            gcs,
            assertions_follow_optimize,
            version,
        });
    }
    found
}

/// Does `driver` define `__ARM_FEATURE_GCS_DEFAULT` under `-mbranch-protection=standard`? The
/// dump decides, not a version. A dump that does not define `__aarch64__` is no answer, so it
/// fails the test rather than reading as "does not define".
fn gcs_by_standard(driver: &str) -> bool {
    let done = driver_command(driver, &[])
        .args(["-mbranch-protection=standard", "-dM", "-E", "-x", "c", "-"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|e| {
            panic!("`{driver} -mbranch-protection=standard -dM -E` could not run: {e}")
        });
    assert!(
        done.status.success(),
        "`{driver} -mbranch-protection=standard -dM -E` failed: {done:?}"
    );
    let dump = String::from_utf8_lossy(&done.stdout);
    assert!(
        defines(&dump, "__aarch64__"),
        "`{driver} -mbranch-protection=standard -dM -E` is not an AArch64 dump: {dump:?}"
    );
    defines(&dump, "__ARM_FEATURE_GCS_DEFAULT")
}

/// Does the C++ library `cxx` compiles against tie `_GLIBCXX_ASSERTIONS` to `__OPTIMIZE__`:
/// defined at `-O0`, where `__OPTIMIZE__` is not, and not at `-O2`, where it is? Fedora 44
/// x86_64's gcc 16.2.1 and clang 22.1.8 read yes, and Ubuntu 24.04 x86_64's gcc 13.3.0 no
/// (2026-11-22). The dump of `<cstdio>` decides, not a version. A dump that does not define
/// `__cplusplus` is no answer, so it fails the test rather than reading as "does not tie". A
/// C++ driver missing from `PATH` is `None`: a gap beside its C driver `name`, or a failure
/// where the gate requires `name` ([`missing_driver`]), and its rows are then not expected.
fn assertions_follow_optimize(name: &str, cxx: &str) -> Option<bool> {
    let assertions_at = |level: &str| -> Option<bool> {
        let spawned = driver_command(cxx, &[])
            .args(["-x", "c++", level, "-dM", "-E", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match spawned {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => panic!("`{cxx} {level} -dM -E` could not run: {e}"),
            Ok(child) => child,
        };
        let written = child
            .stdin
            .take()
            .expect("the dump's stdin")
            .write_all(b"#include <cstdio>\n");
        let done = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("`{cxx} {level} -dM -E` did not finish: {e}"));
        assert!(
            written.is_ok() && done.status.success(),
            "`{cxx} {level} -dM -E` of <cstdio> failed (input {written:?}): {done:?}"
        );
        let dump = String::from_utf8_lossy(&done.stdout);
        assert!(
            defines(&dump, "__cplusplus"),
            "`{cxx} {level} -dM -E` is not a C++ dump: {dump:?}"
        );
        Some(defines(&dump, "_GLIBCXX_ASSERTIONS"))
    };
    if let (Some(unoptimized), Some(optimized)) = (assertions_at("-O0"), assertions_at("-O2")) {
        return Some(unoptimized && !optimized);
    }
    missing_driver(
        name,
        &format!("route_corpus's C++ library under {cxx}, beside {name}"),
        &format!(
            "no `{cxx}` on PATH, so whether its C++ library ties `_GLIBCXX_ASSERTIONS` to \
             `__OPTIMIZE__` is not measured, and the open rows that rest on it are not expected"
        ),
    );
    None
}

/// Does a `-dM` dump define `name`?
fn defines(dump: &str, name: &str) -> bool {
    dump.lines().any(|l| {
        let mut words = l.split_whitespace();
        words.next() == Some("#define") && words.next() == Some(name)
    })
}

#[test]
fn a_dump_defines_a_macro_by_its_whole_name() {
    let dump = "#define __aarch64__ 1\n#define __ARM_FEATURE_GCS_DEFAULT 1\n";
    assert!(defines(dump, "__ARM_FEATURE_GCS_DEFAULT"));
    assert!(defines(dump, "__aarch64__"));
    assert!(!defines(
        "#define __ARM_FEATURE_GCS 1\n",
        "__ARM_FEATURE_GCS_DEFAULT"
    ));
    assert!(!defines(
        "#undef __ARM_FEATURE_GCS_DEFAULT\n",
        "__ARM_FEATURE_GCS_DEFAULT"
    ));
    assert!(!defines("", "__ARM_FEATURE_GCS_DEFAULT"));
}

fn applies(spelling: &Spelling, family: Only) -> bool {
    spelling.only == Only::Any || spelling.only == family
}

/// Is this spelling a route for a macro of `class`? `Err` names why it is not.
fn constructible(spelling: &Spelling, class: MacroClass, name: &str) -> Result<(), &'static str> {
    // The wrapper's operation is on the measured build's command line alone, ahead of the C
    // library's headers: the library reads it, the arms do not, so it is measured rather than
    // argued honest.
    let late = matches!(
        spelling.carrier,
        Carrier::Shadow(_) | Carrier::Layout(_) | Carrier::Wrapper
    );
    if class == MacroClass::Request && !late {
        return Err(REQUEST_HONEST);
    }
    if spelling.carrier.lang() == Lang::Cxx && !reaches_cxx(name) {
        return Err(CXX_UNREAD);
    }
    Ok(())
}

/// Does `name` reach a check of a C++ probe? A spelling only a C++ compile reads moves no
/// other reading, so its route of a macro no C++ probe reads would count as fed and unmoved.
fn reaches_cxx(name: &str) -> bool {
    reached(name).iter().any(|r| {
        CORPUS
            .iter()
            .any(|p| p.id == r.probe && p.lang == chard::probe::Lang::Cxx)
    })
}

/// The words and environment pairs that carry `name` through `spelling`, writing any file they
/// name into `dir`, and the driver chard is handed where it is not the driver's own name.
struct Carried {
    words: Vec<String>,
    env: Vec<(String, String)>,
    driver: Option<String>,
}

/// Make `dest` a directory whose entries are links to `real`'s, unless it already is one: a path
/// under it then resolves as under `real`, except below an entry opened the same way in turn.
fn open_dir(dest: &Path, real: &Path) -> Result<(), String> {
    let io = |e: std::io::Error| format!("mirroring {} at {}: {e}", real.display(), dest.display());
    if dest.is_symlink() {
        std::fs::remove_file(dest).map_err(io)?;
    }
    if dest.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dest).map_err(io)?;
    for entry in std::fs::read_dir(real).map_err(io)? {
        let entry = entry.map_err(io)?;
        std::os::unix::fs::symlink(entry.path(), dest.join(entry.file_name())).map_err(io)?;
    }
    Ok(())
}

/// Mirror `real` at `dest` and write `contents` at `file` under it, each directory on the way
/// opened by [`open_dir`] so that `..` from within resolves inside the mirror.
fn mirror_with(dest: &Path, real: &Path, file: &str, contents: &str) -> Result<(), String> {
    let (mut d, mut r) = (dest.to_path_buf(), real.to_path_buf());
    open_dir(&d, &r)?;
    let parts: Vec<&str> = file.split('/').collect();
    let (leaf, dirs) = parts.split_last().expect("a file name");
    for part in dirs {
        d.push(part);
        r.push(part);
        open_dir(&d, &r)?;
    }
    let target = d.join(leaf);
    if target.is_symlink() {
        std::fs::remove_file(&target).map_err(|e| format!("{}: {e}", target.display()))?;
    }
    std::fs::write(&target, contents).map_err(|e| format!("{}: {e}", target.display()))
}

/// Build `layout` under `dir` with `body` (the keyed operation) in its shadow, and return the
/// words that name it. The shadows that replace a header the library ships include it by its
/// real path, since the mirror stands in place of the directory `#include_next` would search.
fn layout_words(
    layout: Layout,
    dir: &Path,
    driver: &Driver,
    body: &str,
) -> Result<Vec<String>, String> {
    let shown = |p: &Path| p.display().to_string();
    match layout {
        Layout::Sysroot | Layout::Isysroot => {
            let stdio = Path::new("/usr/include/stdio.h");
            if !stdio.is_file() {
                return Err(
                    "the C library's `stdio.h` is not at /usr/include, which the \
                            sysroot mirror replaces"
                        .to_owned(),
                );
            }
            let root = dir.join("sysroot");
            let header = format!("#include \"{}\"\n{body}", stdio.display());
            mirror_with(&root, Path::new("/"), "usr/include/stdio.h", &header)?;
            Ok(if layout == Layout::Sysroot {
                vec![format!("--sysroot={}", shown(&root))]
            } else {
                vec!["-isysroot".to_owned(), shown(&root)]
            })
        }
        Layout::B | Layout::Prefix => {
            let prefix = dir.join("prefix");
            std::fs::create_dir_all(prefix.join("include")).map_err(|e| e.to_string())?;
            let header = format!("#include_next <stdio.h>\n{body}");
            std::fs::write(prefix.join("include/stdio.h"), header).map_err(|e| e.to_string())?;
            Ok(vec![if layout == Layout::B {
                format!("-B{}/", shown(&prefix))
            } else {
                format!("--prefix={}/", shown(&prefix))
            }])
        }
        Layout::GccInstallDir
        | Layout::GccToolchain
        | Layout::StdlibIsystem
        | Layout::CccInstallDir => {
            let install = gcc_installation(driver.name)?;
            // PREFIX/lib/gcc/TRIPLE/VERSION, whatever PREFIX's own `lib` directory is named.
            let version = install
                .file_name()
                .ok_or("an installation with no version")?;
            let triple = install
                .parent()
                .and_then(Path::file_name)
                .ok_or("an installation with no triple")?;
            let real = install
                .ancestors()
                .nth(4)
                .ok_or("an installation with no prefix")?;
            let lib = install
                .ancestors()
                .nth(3)
                .and_then(Path::file_name)
                .ok_or("an installation with no lib directory")?;
            let (version, triple, lib) = (
                version.to_string_lossy(),
                triple.to_string_lossy(),
                lib.to_string_lossy(),
            );
            let cstdio = format!("include/c++/{version}/cstdio");
            if !real.join(&cstdio).is_file() {
                return Err(format!(
                    "the GCC installation {} has no C++ library `cstdio` at {}",
                    install.display(),
                    real.join(&cstdio).display()
                ));
            }
            let prefix = dir.join("gcc");
            let installed = format!("{lib}/gcc/{triple}/{version}");
            // The installation itself is opened so its `..` stays inside the mirror.
            mirror_with(&prefix, real, &format!("{installed}/.chard-route"), "")?;
            let header = format!("#include \"{}\"\n{body}", real.join(&cstdio).display());
            mirror_with(&prefix, real, &cstdio, &header)?;
            Ok(match layout {
                Layout::GccInstallDir => vec![format!(
                    "--gcc-install-dir={}",
                    shown(&prefix.join(installed))
                )],
                Layout::GccToolchain => vec![format!("--gcc-toolchain={}", shown(&prefix))],
                Layout::CccInstallDir => {
                    // `bin` opened, so the `..` clang takes from it stays inside the mirror.
                    mirror_with(&prefix, real, "bin/.chard-route", "")?;
                    vec!["-ccc-install-dir".to_owned(), shown(&prefix.join("bin"))]
                }
                _ => stdlib_words(driver, real, &prefix, &version)?,
            })
        }
        Layout::ResourceDir => {
            let real = resource_dir(driver.name)?;
            let root = dir.join("resource");
            let header = format!("#include_next <stdio.h>\n{body}");
            mirror_with(&root, &real, "include/stdio.h", &header)?;
            Ok(vec!["-resource-dir".to_owned(), shown(&root)])
        }
    }
}

/// `-stdlib++-isystem` for each directory of the C++ library's search list, in its order, the
/// library's own (`REAL/include/c++/VERSION`) replaced by the GCC installation's mirror under
/// `prefix`, whose `cstdio` is the shadow.
fn stdlib_words(
    driver: &Driver,
    real: &Path,
    prefix: &Path,
    version: &str,
) -> Result<Vec<String>, String> {
    let library = real.join(format!("include/c++/{version}"));
    let mirrored = prefix.join(format!("include/c++/{version}"));
    let dirs = cxx_library_dirs(driver)?;
    if !dirs.contains(&library) {
        return Err(format!(
            "the C++ library's search list {dirs:?} does not hold {}, whose `cstdio` the mirror \
             replaces",
            library.display()
        ));
    }
    Ok(dirs
        .into_iter()
        .flat_map(|d| {
            let d = if d == library { mirrored.clone() } else { d };
            ["-stdlib++-isystem".to_owned(), d.display().to_string()]
        })
        .collect())
}

/// The names chard gives the measured build's output: `<probe>-measured`, with the suffix of the
/// probe's link mode (`measure::Session::gather`), which
/// [`the_wrapper_adds_its_operation_to_the_measured_build_alone`] holds to that function's text.
const MEASURED_OUTPUTS: &[&str] = &["*-measured", "*-measured.o", "*-measured.so"];

/// A wrapper pair, the C driver and its C++ sibling, in `dir`, each running the real driver with
/// `op` added where an argument names the measured build's output ([`MEASURED_OUTPUTS`]), and
/// passing every other job through; the C one's path, which chard is handed.
fn wrapper(dir: &Path, driver: &Driver, op: &str) -> Result<String, String> {
    let wrappers = dir.join("wrapper");
    std::fs::create_dir_all(&wrappers).map_err(|e| e.to_string())?;
    for name in [driver.name, driver.cxx] {
        let real = on_path(name)?;
        common::executable(&wrappers.join(name), &wrapper_body(&real, op));
    }
    Ok(wrappers.join(driver.name).display().to_string())
}

/// The wrapper's script over the driver at `real`.
fn wrapper_body(real: &Path, op: &str) -> String {
    format!(
        "for a in \"$@\"; do case \"$a\" in {}) exec '{real}' \"$@\" '{op}' ;; esac; \
         done\nexec '{real}' \"$@\"",
        MEASURED_OUTPUTS.join("|"),
        real = real.display()
    )
}

/// `option` and its `value` handed to a tool by `hand`, each in its own pair.
fn handed_pair(hand: &str, option: &str, value: String) -> Vec<String> {
    vec![hand.to_owned(), option.to_owned(), hand.to_owned(), value]
}

/// The words, and the environment pair where the form is a variable, naming a shadow
/// `stdio.h` that holds `body` in a directory under `dir`, with `gate` defining [`GATE`].
fn shadow_words(
    form: Shadow,
    dir: &Path,
    gate: String,
    body: &str,
    env: &mut Vec<(String, String)>,
) -> Vec<String> {
    let shadow = dir.join("shadow");
    std::fs::create_dir_all(&shadow).expect("the shadow directory");
    let header = format!("#include_next <stdio.h>\n{body}");
    std::fs::write(shadow.join("stdio.h"), header).expect("writing the shadow header");
    let shadow = shadow.display().to_string();
    let variable = match form {
        Shadow::Cpath => "CPATH",
        Shadow::CIncludePath => "C_INCLUDE_PATH",
        Shadow::CplusIncludePath => "CPLUS_INCLUDE_PATH",
        Shadow::I => return vec![gate, format!("-I{shadow}")],
        Shadow::ISplit => return vec![gate, "-I".to_owned(), shadow],
        Shadow::Isystem => return vec![gate, "-isystem".to_owned(), shadow],
        Shadow::XpreprocessorI => {
            return [vec![gate], handed_pair("-Xpreprocessor", "-I", shadow)].concat();
        }
        Shadow::WpI => return vec![gate, format!("-Wp,-I,{shadow}")],
        Shadow::XpreprocessorIsystem => {
            return [
                vec![gate],
                handed_pair("-Xpreprocessor", "-isystem", shadow),
            ]
            .concat();
        }
        Shadow::XclangI => {
            return [vec![gate], handed_pair("-Xclang", "-I", shadow)].concat();
        }
        Shadow::IwithprefixBefore | Shadow::Iwithprefix => {
            let option = if form == Shadow::IwithprefixBefore {
                "-iwithprefixbefore"
            } else {
                "-iwithprefix"
            };
            // The compilers join the operand to the prefix as written, so `/shadow` names
            // `DIR/shadow`; chard refuses the operand without its slash as a relative path.
            return vec![
                gate,
                "-iprefix".to_owned(),
                dir.display().to_string(),
                option.to_owned(),
                "/shadow".to_owned(),
            ];
        }
        Shadow::IncludeDirectory => return vec![gate, format!("--include-directory={shadow}")],
        Shadow::IncludeDirectorySplit => {
            return vec![gate, "--include-directory".to_owned(), shadow];
        }
        Shadow::Iwithsysroot => return vec![gate, "-iwithsysroot".to_owned(), shadow],
        Shadow::XclangCIsystem => {
            return [vec![gate], handed_pair("-Xclang", "-c-isystem", shadow)].concat();
        }
        Shadow::CxxIsystem => return vec![gate, "-cxx-isystem".to_owned(), shadow],
    };
    env.push((variable.to_owned(), shadow));
    vec![gate]
}

fn spelling_words(
    spelling: &Spelling,
    name: &str,
    dir: &Path,
    driver: &Driver,
) -> Result<Carried, String> {
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
        Carrier::Shadow(form) => shadow_words(form, dir, gate, &keyed(&lines), &mut env),
        Carrier::Layout(layout) => {
            let mut words = vec![gate];
            words.extend(layout_words(layout, dir, driver, &keyed(&lines))?);
            words
        }
        Carrier::Wrapper => {
            return Ok(Carried {
                words: Vec::new(),
                env,
                driver: Some(wrapper(dir, driver, &op)?),
            });
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
    Ok(Carried {
        words,
        env,
        driver: None,
    })
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
    /// What the report states of the controls, where it states both outcomes.
    controls: Option<Controls>,
}

/// The two controls' `outcome` and the observation's `controls.withheld_because` (empty where
/// the report gives none).
#[derive(Clone, Debug)]
struct Controls {
    positive: String,
    negative: String,
    cause: String,
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

/// A plain run whose `probe-invalid` is the check's own reading under a driver family, not a
/// harness failure: the probe's controls do not discriminate there, as its header records, so
/// no state of a macro reaching it is measured through that check.
struct Undiscriminated {
    check: &'static str,
    only: Only,
    /// The `outcome` both controls read.
    outcome: &'static str,
    /// The observation's `controls.withheld_because`.
    cause: &'static str,
    /// The probe's measurement.
    why: &'static str,
}

/// The [`Undiscriminated`] rows. A row excuses a reading only where the report states its
/// outcome for both controls and its cause, so an arm that failed to build or run, a control
/// that read otherwise, or a `probe-invalid` for another cause is still a harness failure. The
/// frame prints each row with the plain readings it excused, and a row that excuses none
/// wherever a driver of its family ran fails as stale (`judge_triples`), so a compiler of that
/// family under which the controls discriminate retires the row.
const UNDISCRIMINATED: &[Undiscriminated] = &[Undiscriminated {
    check: "no-delete-null-pointer-checks",
    only: Only::Clang,
    outcome: "present",
    cause: "negative-also-shows",
    why: "under clang 22.1.8 both controls print null-check=kept, -fdelete-null-pointer-checks \
          and -fno-delete-null-pointer-checks alike (probes/ub_null_check.c), so the triple \
          reads probe-invalid",
}];

/// The [`UNDISCRIMINATED`] row that declares `reading`, a plain run's `probe-invalid` under
/// `family` whose controls read the row's outcome for the row's cause, if one does.
fn undiscriminated(reading: &Reading, family: Only) -> Option<usize> {
    if reading.verdict != Verdict::ProbeInvalid {
        return None;
    }
    let controls = reading.controls.as_ref()?;
    UNDISCRIMINATED.iter().position(|row| {
        row.check == reading.check
            && row.only == family
            && controls.positive == row.outcome
            && controls.negative == row.outcome
            && controls.cause == row.cause
    })
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

/// The words a job's build is measured under, its environment pairs, and the driver chard is
/// handed: the job's own by name, or the wrapper a spelling put in its place.
struct JobInputs {
    flags: Vec<String>,
    env: Vec<(String, String)>,
    driver: String,
}

fn job_flags(job: &Job, drivers: &[Driver], work: &Path) -> Result<JobInputs, String> {
    let driver = &drivers[job.driver];
    let mut inputs = JobInputs {
        flags: vec!["-O2".to_owned()],
        env: Vec::new(),
        driver: driver.name.to_owned(),
    };
    inputs
        .flags
        .extend(job.state.iter().map(|w| (*w).to_owned()));
    if let Some(s) = job.spelling {
        let carried = spelling_words(&SPELLINGS[s], &job.name, work, driver)?;
        inputs.flags.extend(carried.words);
        inputs.env = carried.env;
        if let Some(wrapper) = carried.driver {
            inputs.driver = wrapper;
        }
    }
    Ok(inputs)
}

/// Every call the corpus makes of a program itself (a driver's target, a version line, a
/// route's macro dump), under the route's pairs `env`. It gets `PATH`, the pairs and
/// `compile::COMPILER_ENV_PINNED` and nothing else of the test's environment, as chard's
/// driver gets `PATH`, the run's `--env` pairs and chard's own pins. ccache stores no
/// preprocess-only call, so `CCACHE_DISABLE` changes nothing about these calls today; the
/// pins are here so the corpus's calls and chard's differ in no variable.
fn driver_command(driver: impl AsRef<std::ffi::OsStr>, env: &[(String, String)]) -> Command {
    let mut command = Command::new(driver);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(env.iter().map(|(k, v)| (k, v)))
        .envs(chard::compile::COMPILER_ENV_PINNED.iter().copied());
    command
}

#[test]
fn the_corpus_driver_call_gets_chards_pins() {
    let pairs = [("CCC_OVERRIDE_OPTIONS".to_owned(), "+-DX".to_owned())];
    let command = driver_command("cc", &pairs);
    let envs: BTreeMap<String, Option<String>> = command
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    for (name, value) in chard::compile::COMPILER_ENV_PINNED {
        assert_eq!(
            envs.get(*name),
            Some(&Some((*value).to_owned())),
            "the corpus's driver call is not handed the pin {name}={value}: {envs:?}"
        );
    }
    let mut expected: BTreeSet<&str> = chard::compile::COMPILER_ENV_PINNED
        .iter()
        .map(|(name, _)| *name)
        .collect();
    expected.extend(["PATH", "CCC_OVERRIDE_OPTIONS"]);
    let names: BTreeSet<&str> = envs.keys().map(String::as_str).collect();
    assert_eq!(
        names, expected,
        "the corpus's driver call is handed {envs:?}"
    );
}

/// How the effect run is made: its language, and whether its output is named as the measured
/// build's is (`-o ...-measured`), so that a wrapper keyed on that name acts on it.
#[derive(Clone, Copy)]
struct Dump {
    lang: Lang,
    as_measured: bool,
}

const C_DUMP: Dump = Dump {
    lang: Lang::C,
    as_measured: false,
};

/// The value the driver's preprocessor gives `name` under `flags` and `env`, in a unit
/// including `<stdio.h>` (C) or `<cstdio>` (C++): `Ok(None)` where it is undefined, `Err` with
/// the first error line where preprocessing fails, run through [`driver_command`].
fn dumped_value(
    driver: &str,
    flags: &[String],
    env: &[(String, String)],
    name: &str,
    work: &Path,
    how: Dump,
) -> Result<Option<String>, String> {
    let (file, text, lang) = match how.lang {
        Lang::C => (
            "route-effect.c",
            "#include <stdio.h>\nint chard_route;\n",
            "c",
        ),
        Lang::Cxx => (
            "route-effect.cc",
            "#include <cstdio>\nint chard_route;\n",
            "c++",
        ),
    };
    let unit = work.join(file);
    std::fs::write(&unit, text).expect("writing the unit");
    let listing = work.join("route-effect-measured");
    let mut command = driver_command(driver, env);
    command
        .args(flags)
        .args(["-dM", "-E", "-x", lang])
        .arg(&unit);
    if how.as_measured {
        command.arg("-o").arg(&listing);
    }
    let done = command.output().expect("spawning the driver");
    if !done.status.success() {
        let stderr = String::from_utf8_lossy(&done.stderr);
        return Err(stderr
            .lines()
            .find(|l| l.contains("error"))
            .unwrap_or("")
            .to_owned());
    }
    let dump = if how.as_measured {
        std::fs::read_to_string(&listing).map_err(|e| format!("the effect listing: {e}"))?
    } else {
        String::from_utf8_lossy(&done.stdout).into_owned()
    };
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
fn effect(inputs: &JobInputs, job: &Job, drivers: &[Driver], work: &Path) -> Option<Outcome> {
    let forged = match job.direction {
        Define => Some(value(&job.name).to_owned()),
        Undefine => None,
    };
    let carrier = SPELLINGS[job.spelling.expect("a route")].carrier;
    let how = Dump {
        lang: carrier.lang(),
        as_measured: carrier == Carrier::Wrapper,
    };
    // A C++ effect runs the C++ driver beside the job's; no wrapper carrier reads C++ alone.
    let driver = match how.lang {
        Lang::C => inputs.driver.as_str(),
        Lang::Cxx => drivers[job.driver].cxx,
    };
    match dumped_value(driver, &inputs.flags, &inputs.env, &job.name, work, how) {
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
        dumped_value(driver, flags, &[], &job.name, work, C_DUMP),
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
    let inputs = job_flags(job, drivers, work)?;
    let (flags, env, driver) = (&inputs.flags, &inputs.env, inputs.driver.as_str());
    if job.spelling.is_some() {
        if let Some(outcome) = effect(&inputs, job, drivers, work) {
            return Ok(outcome);
        }
    } else {
        state_holds(driver, flags, job, work)?;
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
    for (k, v) in env {
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
        controls: o["controls"]["positive"]["outcome"]
            .as_str()
            .zip(o["controls"]["negative"]["outcome"].as_str())
            .map(|(p, n)| Controls {
                positive: p.to_owned(),
                negative: n.to_owned(),
                cause: o["controls"]["withheld_because"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
            }),
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
    /// The target architecture the row holds on, one of [`ARCHES`], or every one the corpus
    /// runs on. A row of a macro the target decides (the `__ARM_FEATURE_*` undefines, built on
    /// `aarch64` alone) names its architecture. A run elsewhere expects none of its
    /// combinations, so only a run on that architecture holds the row.
    arch: Option<&'static str>,
    name: &'static str,
    spellings: &'static [&'static str],
    checks: &'static [&'static str],
    /// The state the row holds for, or every state of the spelling's direction.
    states: Option<&'static [&'static str]>,
    /// The forged verdicts it publishes.
    reads: &'static [Verdict],
    /// The levels a forged `on` or `partial` publishes at, as the report spells them; empty
    /// where the row's forged readings carry no level.
    levels: &'static [&'static str],
    why: &'static str,
}

/// The C++ library's checks a forged `__OPTIMIZE__` reaches only through the library's own
/// tie of `_GLIBCXX_ASSERTIONS` to the macro.
const ASSERTIONS_FROM_OPTIMIZE: &[&str] = &["cxx-stdlib-assertions", "cxx-assertions-symbol"];

impl OpenRoute {
    /// Does the row hold under `driver`? Its family and its architecture, and for an
    /// `__OPTIMIZE__` row reaching [`ASSERTIONS_FROM_OPTIMIZE`], a C++ library that ties
    /// `_GLIBCXX_ASSERTIONS` to `__OPTIMIZE__` ([`Driver::assertions_follow_optimize`]). Under a
    /// library without the tie the forgery moves no such reading, which then reads as the plain
    /// run, and a forged one there fails as forged.
    fn holds_on(&self, driver: &Driver) -> bool {
        (self.only == Only::Any || self.only == driver.family)
            && self.arch.is_none_or(|arch| arch == driver.arch)
            && (self.name != "__OPTIMIZE__"
                || !self
                    .checks
                    .iter()
                    .any(|c| ASSERTIONS_FROM_OPTIMIZE.contains(c))
                || driver.assertions_follow_optimize == Some(true))
    }

    /// Is a reading at `level`, as the report serializes it, inside the row? A row with no
    /// levels admits a reading with none; a row with levels admits a reading at one of them
    /// alone. So a forged level, or a level dropped, inside an open combination fails as forged.
    fn at_level(&self, level: &str) -> bool {
        if self.levels.is_empty() {
            level == "null"
        } else {
            self.levels.iter().any(|l| level == format!("\"{l}\""))
        }
    }
}

/// The target architectures a driver's `-dumpmachine` names, as the corpus spells them.
const ARCHES: &[&str] = &["x86_64", "aarch64", "riscv64"];

/// The undefines of one `-mbranch-protection` default that publish a lowered grade on
/// `aarch64`: the forced includes, the shadows under a header search directory or a layout,
/// `CCC_OVERRIDE_OPTIONS` and the wrapper. Each family takes its own (`-isysroot`, `-B` and
/// `--prefix=` gcc's, `CCC_OVERRIDE_OPTIONS` and `-resource-dir` clang's).
const BRANCH_PROTECTION_UNDEFINES: &[&str] = &[
    "-include undefine",
    "-include keyed undefine",
    "-imacros undefine",
    "-imacros keyed undefine",
    "--include= keyed undefine",
    "--imacros= keyed undefine",
    "-I shadow undefine",
    "--include-directory= shadow undefine",
    "--include-directory split shadow undefine",
    "-I split shadow undefine",
    "-isystem shadow undefine",
    "CPATH shadow undefine",
    "C_INCLUDE_PATH shadow undefine",
    "--sysroot shadow undefine",
    "-isysroot shadow undefine",
    "-B shadow undefine",
    "--prefix= shadow undefine",
    "-resource-dir shadow undefine",
    "CCC_OVERRIDE_OPTIONS undefine",
    "wrapper undefine",
];

/// Why an undefine of one `-mbranch-protection` default publishes.
const BRANCH_PROTECTION_COMPONENT: &str = "`report::MACRO_TWINS` holds \
     `branch-protection-marked` to `branch-protection-macro` for presence alone. Undefining one \
     of the two defaults over `-mbranch-protection=standard` leaves `branch-protection-macro` \
     present at `partial`, and no rule withholds a component forged inside a present reading \
     (`THREAT_MODEL.md`'s row on forged levels)";

/// The defines of one `-mbranch-protection` default that publish a raised grade on `aarch64`
/// over a build of the other component alone: the keyed forced includes, the shadows under a
/// header search directory or a layout, and the wrapper. Each family takes its own
/// (`-isysroot`, `-B` and `--prefix=` gcc's, `-resource-dir` clang's). The unkeyed forced
/// includes and `CCC_OVERRIDE_OPTIONS` read `probe-invalid` there, so they are not listed.
const BRANCH_PROTECTION_DEFINES: &[&str] = &[
    "-include keyed define",
    "-imacros keyed define",
    "--include= keyed define",
    "--imacros= keyed define",
    "-I shadow define",
    "--include-directory= shadow define",
    "--include-directory split shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-resource-dir shadow define",
    "wrapper define",
];

/// Why a define of the missing `-mbranch-protection` default publishes.
const BRANCH_PROTECTION_ADDED: &str = "`report::MACRO_TWINS` holds \
     `branch-protection-marked` to `branch-protection-macro` for presence alone. Defining the \
     missing default over a build of one component (`-mbranch-protection=bti` or \
     `-mbranch-protection=pac-ret`) raises `branch-protection-macro` to `on` at `full`, and no \
     rule withholds a component forged inside a present reading (`THREAT_MODEL.md`'s row on \
     forged levels)";

/// [`SHADOW_DEFINES`] and the header directories handed to the preprocessor (`-Xpreprocessor`,
/// `-Wp,`, clang's `-Xclang`) or named by clang's `-iwithsysroot` and `-iwithprefixbefore`, which
/// clang's runtime readings under a branching probe meet as they meet the driver's (under gcc
/// `-iwithprefixbefore` is withheld under `compile-inputs-unmatched-by-arms`).
const SHADOW_DEFINES_WITH_HANDED: &[&str] = &[
    "-I shadow define",
    "--include-directory= shadow define",
    "--include-directory split shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "-Xpreprocessor -I shadow define",
    "-Wp,-I shadow define",
    "-Xpreprocessor -isystem shadow define",
    "-Xclang -I shadow define",
    "-iwithsysroot shadow define",
    "-Xclang -c-isystem shadow define",
    "-iwithprefixbefore shadow define",
];

const SHADOW_DEFINES: &[&str] = &[
    "-I shadow define",
    "--include-directory= shadow define",
    "--include-directory split shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
];

const SHADOW_UNDEFINES: &[&str] = &[
    "-I shadow undefine",
    "--include-directory= shadow undefine",
    "--include-directory split shadow undefine",
    "-I split shadow undefine",
    "-isystem shadow undefine",
    "CPATH shadow undefine",
    "C_INCLUDE_PATH shadow undefine",
];

/// The shadow carriers a C++ compile reads: `C_INCLUDE_PATH` is the C driver's alone.
const CXX_SHADOW_DEFINES: &[&str] = &[
    "-I shadow define",
    "--include-directory= shadow define",
    "--include-directory split shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
];
const CXX_SHADOW_UNDEFINES: &[&str] = &[
    "-I shadow undefine",
    "--include-directory= shadow undefine",
    "--include-directory split shadow undefine",
    "-I split shadow undefine",
    "-isystem shadow undefine",
    "CPATH shadow undefine",
];

/// The shadow carriers the environment passes, which no rule reads.
const ENV_DEFINES: &[&str] = &["CPATH shadow define", "C_INCLUDE_PATH shadow define"];

/// The shadows under a path word of the toolchain's layout that a C compile reads, gcc's and
/// clang's together (each family's own are its routes alone, [`open_combinations`]).
const LAYOUT_DEFINES: &[&str] = &[
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-resource-dir shadow define",
];
const LAYOUT_UNDEFINES: &[&str] = &[
    "--sysroot shadow undefine",
    "-isysroot shadow undefine",
    "-B shadow undefine",
    "--prefix= shadow undefine",
    "-resource-dir shadow undefine",
];

/// [`LAYOUT_DEFINES`] and the carriers a C++ compile alone reads.
const CXX_LATE_DEFINES: &[&str] = &[
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-resource-dir shadow define",
    "--gcc-install-dir= shadow define",
    "--gcc-toolchain= shadow define",
    "-stdlib++-isystem shadow define",
    "-ccc-install-dir shadow define",
    "CPLUS_INCLUDE_PATH shadow define",
];
const CXX_LATE_UNDEFINES: &[&str] = &[
    "--sysroot shadow undefine",
    "-isysroot shadow undefine",
    "-B shadow undefine",
    "--prefix= shadow undefine",
    "-resource-dir shadow undefine",
    "--gcc-install-dir= shadow undefine",
    "--gcc-toolchain= shadow undefine",
    "-stdlib++-isystem shadow undefine",
    "-ccc-install-dir shadow undefine",
    "CPLUS_INCLUDE_PATH shadow undefine",
];

/// Why a shadow under a path word of the layout publishes.
const LAYOUT_UNREAD: &str = "a shadow header under a path word of the target or runtime selection \
                             (`--sysroot`, `-isysroot`, `-B`, `--prefix=`, `--gcc-install-dir=`, \
                             `--gcc-toolchain=`, `-resource-dir`), which chard carries to every \
                             arm, is under no header search word `macro-supplied-by-profile` or the \
                             listing comparison reads, so only the twin rule holds a reading it \
                             forges, and a reading with no twin, or a probe the macro steers, \
                             publishes";

/// Why a wrapper's request publishes.
const WRAPPER_REQUEST: &str = "a wrapper that adds a request to the measured build alone puts it \
                               ahead of the library's headers there (the C library's for \
                               `_FORTIFY_SOURCE`, the C++ library's for `_GLIBCXX_ASSERTIONS`), so \
                               the library settles it and the measured build carries it: the \
                               reading is true of the measured build, whose control arms, passed \
                               through untouched, carry no such request; `THREAT_MODEL.md`'s \
                               redirected-toolchain row says such readings stand";

/// Why a wrapper's route publishes.
const WRAPPER_UNSEEN: &str = "a wrapper handed to chard as the driver that adds the operation to \
                              the measured build alone changes no flag, listing or macro dump chard \
                              compares (a dump carries no `-o` to key on), so only the twin rule \
                              holds a reading it forges, and a reading with no twin that \
                              disagrees, or a probe the macro steers in the measured build, \
                              publishes; a wrapper that rewrites the dump as well is \
                              `THREAT_MODEL.md`'s redirected-toolchain position, which no route \
                              here models";

/// Why a `CPATH` or `C_INCLUDE_PATH` route publishes where its `-I` twin is withheld.
const CPATH_UNREAD: &str = "a `CPATH` or `C_INCLUDE_PATH` the operator passes through `--env` \
                            names a header search directory that no rule reads: `macro-supplied-by-profile` withholds \
                            the twinless macro check, and `optimization-enabled` where its twin \
                            is not a measurement, under the profile's own `-I`, `-isystem`, \
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
        arch: None,
        name: "__PIC__",
        spellings: &[
            "-include keyed define",
            "-imacros keyed define",
            "--include= keyed define",
            "--imacros= keyed define",
            "-I shadow define",
            "--include-directory= shadow define",
            "--include-directory split shadow define",
            "-I split shadow define",
            "-isystem shadow define",
            "CPATH shadow define",
            "C_INCLUDE_PATH shadow define",
            "--sysroot shadow define",
            "-isysroot shadow define",
            "-B shadow define",
            "--prefix= shadow define",
            "-resource-dir shadow define",
        ],
        checks: &["pic-macro"],
        states: None,
        reads: &[Verdict::On],
        levels: &["2"],
        why: "`pic-object-relocs` is consulted as `pic-macro`'s twin only where the macro reads \
              absent (`report::MACRO_TWINS`), so a present `__PIC__` that a header forges over \
              a build without position-independent code has no reading to contradict it",
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
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
        levels: &[],
        why: "the twin `pic-object-relocs` is itself withheld under `macro-supplied-by-profile` \
              where the list carries a forced include, since its probe branches on \
              `__clang__`, so an absent `__PIC__` that a keyed header forges over `-fPIC` \
              meets no reading to contradict it",
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__PIC__",
        spellings: &[
            "-include keyed undefine",
            "-imacros keyed undefine",
            "--include= keyed undefine",
            "--imacros= keyed undefine",
            "-I shadow undefine",
            "--include-directory= shadow undefine",
            "--include-directory split shadow undefine",
            "-I split shadow undefine",
            "-isystem shadow undefine",
            "CPATH shadow undefine",
            "C_INCLUDE_PATH shadow undefine",
            "--sysroot shadow undefine",
            "-isysroot shadow undefine",
            "-B shadow undefine",
            "--prefix= shadow undefine",
            "-resource-dir shadow undefine",
        ],
        checks: &["pic-macro"],
        states: Some(&["-fPIE", "-pie"]),
        reads: &[Verdict::Off],
        levels: &[],
        why: "`pic-object-relocs` reads a direct relocation under `-fPIE` by design, so it \
              reads absent beside an absent `__PIC__` that a header forges over a \
              position-independent executable, where the compiler defined the macro",
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__SSP_EXPLICIT__",
        spellings: &[
            "-include keyed define",
            "-imacros keyed define",
            "--include= keyed define",
            "--imacros= keyed define",
            "-I shadow define",
            "--include-directory= shadow define",
            "--include-directory split shadow define",
            "-I split shadow define",
            "-isystem shadow define",
            "CPATH shadow define",
            "C_INCLUDE_PATH shadow define",
            "--sysroot shadow define",
            "-isysroot shadow define",
            "-B shadow define",
            "--prefix= shadow define",
            "-resource-dir shadow define",
        ],
        checks: &["ssp-level"],
        states: None,
        reads: &[Verdict::Partial],
        levels: &["explicit"],
        why: "no probe function carries the attribute `-fstack-protector-explicit` protects, so \
              `canary-emitted` and `ssp-level-emitted` read absent with the flag and without \
              it, and the twin rule cannot tell a forged `explicit` from a build with no stack \
              protector",
    },
    OpenRoute {
        only: Only::Gcc,
        arch: None,
        name: "__SSP_EXPLICIT__",
        spellings: &[
            "-include undefine",
            "-include keyed undefine",
            "-imacros undefine",
            "-imacros keyed undefine",
            "--include= keyed undefine",
            "--imacros= keyed undefine",
            "-I shadow undefine",
            "--include-directory= shadow undefine",
            "--include-directory split shadow undefine",
            "-I split shadow undefine",
            "-isystem shadow undefine",
            "CPATH shadow undefine",
            "C_INCLUDE_PATH shadow undefine",
            "--sysroot shadow undefine",
            "-isysroot shadow undefine",
            "-B shadow undefine",
            "--prefix= shadow undefine",
        ],
        checks: &["ssp-level"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: "under `-fstack-protector-explicit` the twins read absent, as they do without a \
              stack protector, since no probe function carries the attribute, so an undefined \
              `__SSP_EXPLICIT__` over an `explicit` build agrees with them",
    },
    OpenRoute {
        only: Only::Clang,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: SHADOW_DEFINES_WITH_HANDED,
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: "a shadow header under a header search directory, the driver's or one handed to the \
              preprocessor, steers the runtime readings of a probe that branches on a reserved \
              macro, which no rule withholds there; `THREAT_MODEL.md`'s row on forged levels and \
              steered probes names the shadow under `-I` or `-isystem`, the driver's or one handed to \
              the preprocessor, that steers such a probe's runtime and artifact readings unseen",
    },
    OpenRoute {
        only: Only::Clang,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["--config define"],
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: "the listing comparison withholds a branching probe's compile-input readings \
              under a configuration file's define, and not the runtime readings `no-strict-overflow` \
              and `no-strict-aliasing`, whose probes print `optimize=` from `__OPTIMIZE__`",
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__USE_FORTIFY_LEVEL",
        spellings: ENV_DEFINES,
        checks: &["fortify-effective"],
        states: None,
        reads: &[Verdict::On],
        levels: &["3"],
        why: CPATH_UNREAD,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_FORTIFY_SOURCE",
        spellings: SHADOW_DEFINES,
        checks: &["fortify-requested"],
        states: None,
        reads: &[Verdict::On],
        levels: &["3"],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_FORTIFY_SOURCE",
        spellings: SHADOW_UNDEFINES,
        checks: &["fortify-requested"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: CXX_SHADOW_DEFINES,
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: CXX_SHADOW_UNDEFINES,
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Clang,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["CCC_OVERRIDE_OPTIONS define"],
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: CCC_UNREAD,
    },
    OpenRoute {
        only: Only::Clang,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["CCC_OVERRIDE_OPTIONS define"],
        checks: &["cxx-stdlib-assertions", "cxx-assertions-symbol"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: CCC_UNREAD,
    },
    OpenRoute {
        only: Only::Clang,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["CCC_OVERRIDE_OPTIONS undefine"],
        checks: &["cxx-stdlib-assertions", "cxx-assertions-symbol"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: CCC_UNREAD,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__USE_FORTIFY_LEVEL",
        spellings: LAYOUT_DEFINES,
        checks: &["fortify-effective"],
        states: None,
        reads: &[Verdict::On],
        levels: &["3"],
        why: LAYOUT_UNREAD,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_FORTIFY_SOURCE",
        spellings: LAYOUT_DEFINES,
        checks: &["fortify-requested"],
        states: None,
        reads: &[Verdict::On],
        levels: &["3"],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_FORTIFY_SOURCE",
        spellings: LAYOUT_UNDEFINES,
        checks: &["fortify-requested"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: CXX_LATE_DEFINES,
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: CXX_LATE_UNDEFINES,
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: REQUEST_LATE,
    },
    OpenRoute {
        only: Only::Clang,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["--sysroot shadow define", "-resource-dir shadow define"],
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: LAYOUT_UNREAD,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__PIC__",
        spellings: &["wrapper define"],
        checks: &["pic-macro"],
        states: None,
        reads: &[Verdict::On],
        levels: &["2"],
        why: WRAPPER_UNSEEN,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__PIC__",
        spellings: &["wrapper undefine"],
        checks: &["pic-macro"],
        states: Some(&["-fPIE", "-pie"]),
        reads: &[Verdict::Off],
        levels: &[],
        why: WRAPPER_UNSEEN,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__SSP_EXPLICIT__",
        spellings: &["wrapper define"],
        checks: &["ssp-level"],
        states: None,
        reads: &[Verdict::Partial],
        levels: &["explicit"],
        why: WRAPPER_UNSEEN,
    },
    OpenRoute {
        only: Only::Gcc,
        arch: None,
        name: "__SSP_EXPLICIT__",
        spellings: &["wrapper undefine"],
        checks: &["ssp-level"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: WRAPPER_UNSEEN,
    },
    OpenRoute {
        only: Only::Clang,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["wrapper define"],
        checks: &["no-strict-overflow", "no-strict-aliasing"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: WRAPPER_UNSEEN,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["wrapper define"],
        checks: &["cxx-stdlib-assertions", "cxx-assertions-symbol"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: WRAPPER_UNSEEN,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "__OPTIMIZE__",
        spellings: &["wrapper undefine"],
        checks: &["cxx-stdlib-assertions", "cxx-assertions-symbol"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: WRAPPER_UNSEEN,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_FORTIFY_SOURCE",
        spellings: &["wrapper define"],
        checks: &["fortify-requested", "fortify-effective"],
        states: None,
        reads: &[Verdict::On],
        levels: &["3"],
        why: WRAPPER_REQUEST,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_FORTIFY_SOURCE",
        spellings: &["wrapper undefine"],
        checks: &["fortify-requested", "fortify-effective"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: WRAPPER_REQUEST,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: &["wrapper define"],
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::On],
        levels: &[],
        why: WRAPPER_REQUEST,
    },
    OpenRoute {
        only: Only::Any,
        arch: None,
        name: "_GLIBCXX_ASSERTIONS",
        spellings: &["wrapper undefine"],
        checks: &["cxx-hardening-requested"],
        states: None,
        reads: &[Verdict::Off],
        levels: &[],
        why: WRAPPER_REQUEST,
    },
    OpenRoute {
        only: Only::Any,
        arch: Some("aarch64"),
        name: "__ARM_FEATURE_BTI_DEFAULT",
        spellings: BRANCH_PROTECTION_UNDEFINES,
        checks: &["branch-protection-macro"],
        states: Some(&["-mbranch-protection=standard"]),
        reads: &[Verdict::Partial],
        levels: &["return"],
        why: BRANCH_PROTECTION_COMPONENT,
    },
    OpenRoute {
        only: Only::Any,
        arch: Some("aarch64"),
        name: "__ARM_FEATURE_PAC_DEFAULT",
        spellings: BRANCH_PROTECTION_UNDEFINES,
        checks: &["branch-protection-macro"],
        states: Some(&["-mbranch-protection=standard"]),
        reads: &[Verdict::Partial],
        levels: &["branch"],
        why: BRANCH_PROTECTION_COMPONENT,
    },
    OpenRoute {
        only: Only::Any,
        arch: Some("aarch64"),
        name: "__ARM_FEATURE_BTI_DEFAULT",
        spellings: BRANCH_PROTECTION_DEFINES,
        checks: &["branch-protection-macro"],
        states: Some(&["-mbranch-protection=pac-ret"]),
        reads: &[Verdict::On],
        levels: &["full"],
        why: BRANCH_PROTECTION_ADDED,
    },
    OpenRoute {
        only: Only::Any,
        arch: Some("aarch64"),
        name: "__ARM_FEATURE_PAC_DEFAULT",
        spellings: BRANCH_PROTECTION_DEFINES,
        checks: &["branch-protection-macro"],
        states: Some(&["-mbranch-protection=bti"]),
        reads: &[Verdict::On],
        levels: &["full"],
        why: BRANCH_PROTECTION_ADDED,
    },
];

/// The table name the frame's count line starts with, which `make test` requires of the test
/// ledger (`--require route_corpus`); [`the_frame_is_the_table_the_ledger_requires`] holds the
/// two together.
const FRAME_TABLE: &str = "route_corpus";

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
    /// Routes the preprocessor could not preprocess.
    broken_routes: usize,
    /// The preprocessor's error lines for those routes, by driver and macro.
    broken: BTreeMap<(String, String), BTreeSet<String>>,
    unconstructible: BTreeMap<String, usize>,
    /// Routes each driver's spelling fed, every spelling the driver takes seeded at zero.
    fed_by_spelling: BTreeMap<String, usize>,
    /// Every driver, macro and spelling a route was fed for, and whether a reading of it
    /// earned: withheld by a rule, withheld with no rule named, a harness failure a
    /// [`HARNESS_ROUTES`] row declares, open or forged.
    triples: BTreeMap<(usize, String, &'static str), bool>,
    /// Every driver and macro a route was built for, fed or not.
    routed: BTreeSet<(usize, String)>,
    /// The triples that earned by a reading other than a declared harness failure.
    earned_otherwise: BTreeSet<(usize, String, &'static str)>,
    /// The harness readings over a plain run that measured the check, each declared, and the
    /// [`HARNESS_ROUTES`] rows that declared one.
    harness_declared: usize,
    harness_met: BTreeMap<usize, usize>,
    /// The plain runs' `probe-invalid` readings each [`UNDISCRIMINATED`] row excused, by row.
    undiscriminated_met: BTreeMap<usize, usize>,
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
    /// The drivers a wrapper route was fed under, those whose wrapper routes earned a reading,
    /// and those whose earned one on an object probe, whose measured output is `-measured.o`.
    wrapper_fed: BTreeSet<String>,
    wrapper_earned: BTreeSet<String>,
    wrapper_object: BTreeSet<String>,
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
                    driver.gcs,
                    driver.family,
                ) {
                    Ok(states) if constructible(spelling, class, &name).is_ok() => states.len(),
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
                let states = state(
                    &name,
                    class,
                    direction,
                    &driver.arch,
                    driver.gcs,
                    driver.family,
                )
                .and_then(|states| constructible(spelling, class, &name).map(|()| states));
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
        row.holds_on(&drivers[job.driver])
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
    OPEN_ROUTES
        .iter()
        .flat_map(|row| row_combinations(row, drivers))
        .collect()
}

/// The combinations one row of [`OPEN_ROUTES`] names under `drivers`. A spelling of the row
/// that has no state, or is no route of the row's macro, under a driver it applies to names a
/// combination that cannot be met (it ends `: no state` or `: not constructible`), which the
/// corpus then reports as stale.
fn row_combinations(row: &OpenRoute, drivers: &[Driver]) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    let class = macros()
        .into_iter()
        .find(|(m, _)| m == row.name)
        .map_or(MacroClass::CompilerDefined, |(_, c)| c);
    for driver in drivers.iter().filter(|d| row.holds_on(d)) {
        for id in row.spellings {
            let spelling = SPELLINGS
                .iter()
                .find(|s| s.id == *id)
                .expect("a listed spelling");
            // A row of both families names each family's own spellings; under the other
            // driver such a spelling is no route at all, so it names no combination there.
            if !applies(spelling, driver.family) {
                continue;
            }
            if constructible(spelling, class, row.name).is_err() {
                all.insert(format!(
                    "{} {} {id}: not constructible",
                    driver.name, row.name
                ));
                continue;
            }
            let Ok(states) = state(
                row.name,
                class,
                spelling.direction,
                &driver.arch,
                driver.gcs,
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
    all
}

/// The label of one open combination: driver, macro, spelling, state and check.
fn combination(driver: &str, name: &str, spelling: &str, state: &[&str], check: &str) -> String {
    format!("{driver} {name} {spelling} [{}]: {check}", state.join(" "))
}

/// The plain runs' readings, by driver, macro, direction and state.
type Plain = BTreeMap<(usize, String, Direction, &'static [&'static str]), Vec<Reading>>;

/// Judge the plain runs. A reached check that reads a harness failure holds no route of the
/// state to anything (an [`UNDISCRIMINATED`] row's reading is counted under the row instead),
/// and a state whose macro checks do not read the direction it was chosen for (a define's state
/// reading one present, other than at a level without the macro's own component
/// ([`lacks_component`]), an undefine's reading none present where any reads the name) would
/// pass its routes as unmoved; each fails here.
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
            Ok(_) => panic!("{label}: a plain run has no effect check, and this one read one"),
            Err(why) => {
                tally.failures.push(format!("{label}: {why}"));
                continue;
            }
        };
        tally.plain += 1;
        for r in readings {
            tally.cells.push(cell(&label, r));
            if !harness_state(r.verdict) {
                continue;
            }
            match undiscriminated(r, drivers[job.driver].family) {
                Some(i) => *tally.undiscriminated_met.entry(i).or_default() += 1,
                None => tally.failures.push(format!(
                    "{label}: the plain run reads {} {} ({}), a harness failure, so no route in this state measures anything",
                    r.check,
                    verdict_word(r.verdict),
                    r.named()
                )),
            }
        }
        let own: Vec<&Reading> = readings
            .iter()
            .zip(&job.reached)
            .filter(|(_, reached)| reached.by_predicate)
            .map(|(r, _)| r)
            .collect();
        let held = match job.direction {
            Define => own
                .iter()
                .all(|r| !r.present() || lacks_component(&job.name, r)),
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

/// Each `-mbranch-protection` default and the level of [`CFI_COMPONENTS`] its component
/// alone reads at.
const BRANCH_PROTECTION_LEVELS: &[(&str, &str)] = &[
    ("__ARM_FEATURE_BTI_DEFAULT", "branch"),
    ("__ARM_FEATURE_PAC_DEFAULT", "return"),
];

/// Whether `r` reads a build graded by component as `partial` at a level without `name`'s own
/// component, so that a define of `name` claims what the build lacks: a define of
/// `__ARM_FEATURE_BTI_DEFAULT` over `-mbranch-protection=pac-ret`, which reads `return`. A
/// `partial` at the macro's own component, or any reading of another macro, is not.
fn lacks_component(name: &str, r: &Reading) -> bool {
    let graded = CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .any(|k| k.id == r.check && k.levels == CFI_COMPONENTS);
    r.verdict == Verdict::Partial
        && graded
        && BRANCH_PROTECTION_LEVELS
            .iter()
            .any(|(m, own)| *m == name && r.level != format!("\"{own}\""))
}

#[test]
fn a_define_state_lacks_only_the_other_component() {
    let read = |check, verdict, level: &str| Reading {
        check,
        verdict,
        level: level.to_owned(),
        rule: String::new(),
        controls: None,
    };
    let bti = "__ARM_FEATURE_BTI_DEFAULT";
    let pac = "__ARM_FEATURE_PAC_DEFAULT";
    let check = "branch-protection-macro";
    assert!(lacks_component(
        bti,
        &read(check, Verdict::Partial, "\"return\"")
    ));
    assert!(lacks_component(
        pac,
        &read(check, Verdict::Partial, "\"branch\"")
    ));
    assert!(!lacks_component(
        bti,
        &read(check, Verdict::Partial, "\"branch\"")
    ));
    assert!(!lacks_component(
        pac,
        &read(check, Verdict::Partial, "\"return\"")
    ));
    assert!(!lacks_component(bti, &read(check, Verdict::On, "\"full\"")));
    assert!(!lacks_component(
        "__CET__",
        &read(check, Verdict::Partial, "\"return\"")
    ));
    assert!(!lacks_component(
        bti,
        &read("pic-macro", Verdict::Partial, "\"return\"")
    ));
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
    let family = drivers[job.driver].family;
    let pair = (driver.to_owned(), job.name.clone());
    tally.routed.insert((job.driver, job.name.clone()));
    let readings = match result {
        Ok(Outcome::Readings(r)) => r,
        Ok(Outcome::Inert) => {
            *tally.inert.entry(pair).or_default() += 1;
            return;
        }
        Ok(Outcome::Broken(why)) => {
            tally.broken_routes += 1;
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
    if SPELLINGS[job.spelling.expect("a route")].carrier == Carrier::Wrapper {
        tally.wrapper_fed.insert(driver.to_owned());
    }
    *tally
        .fed_by_spelling
        .entry(format!("{driver} {spelling}"))
        .or_default() += 1;
    let baseline = plain.get(&(job.driver, job.name.clone(), job.direction, job.state));
    let triple = (job.driver, job.name.clone(), spelling);
    tally.triples.entry(triple.clone()).or_insert(false);
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
                let measured = before.is_some_and(|p| p.verdict.is_measurement());
                if measured {
                    declare_harness(&label, family, &job.name, spelling, r, tally);
                }
                measured
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
            (true, Some(row)) if row.reads.contains(&r.verdict) && row.at_level(&r.level) => {
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
            tally.triples.insert(triple.clone(), true);
            if !harness_state(r.verdict) {
                tally.earned_otherwise.insert(triple.clone());
            }
            if SPELLINGS[job.spelling.expect("a route")].carrier == Carrier::Wrapper {
                tally.wrapper_earned.insert(driver.to_owned());
                let object = CORPUS.iter().any(|p| {
                    p.link_mode == chard::probe::LinkMode::Object
                        && p.checks.iter().any(|c| c.id == r.check)
                });
                if object {
                    tally.wrapper_object.insert(driver.to_owned());
                }
            }
        }
    }
}

/// A harness failure where the plain run measured the check moved the reading to a withholding
/// no rule gave: counted under the [`HARNESS_ROUTES`] row that says why, or a failure. Over a
/// plain run that withheld the check it moved nothing, and is not brought here.
fn declare_harness(
    label: &str,
    family: Only,
    name: &str,
    spelling: &str,
    r: &Reading,
    tally: &mut Tally,
) {
    match HARNESS_ROUTES
        .iter()
        .position(|row| row.holds(family, name, spelling, r))
    {
        Some(i) => {
            tally.harness_declared += 1;
            *tally.harness_met.entry(i).or_default() += 1;
        }
        None => tally.failures.push(format!(
            "{label}: {} reads {} where the plain run measured it, and no HARNESS_ROUTES row says \
             why",
            r.check,
            verdict_word(r.verdict)
        )),
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
    let done = driver_command(program, &[])
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

/// The frame's words for [`Driver::assertions_follow_optimize`].
fn tie_words(fact: Option<bool>) -> &'static str {
    match fact {
        Some(true) => ", its C++ library ties `_GLIBCXX_ASSERTIONS` to `__OPTIMIZE__`",
        Some(false) => ", its C++ library does not tie `_GLIBCXX_ASSERTIONS` to `__OPTIMIZE__`",
        None => ", its C++ library not measured (no C++ driver)",
    }
}

fn print_frame(tally: &Tally, drivers: &[Driver], basis: &str) {
    let names: Vec<String> = drivers
        .iter()
        .map(|d| {
            let n = SPELLINGS.iter().filter(|s| applies(s, d.family)).count();
            let gcs = if d.arch != "aarch64" {
                ""
            } else if d.gcs {
                ", `-mbranch-protection=standard` defines `__ARM_FEATURE_GCS_DEFAULT`"
            } else {
                ", `-mbranch-protection=standard` does not define `__ARM_FEATURE_GCS_DEFAULT`"
            };
            let tie = tie_words(d.assertions_follow_optimize);
            format!(
                "{} ({}, {n} spellings, {}{gcs}{tie})",
                d.name, d.arch, d.version
            )
        })
        .collect();
    let sum = |m: &BTreeMap<String, usize>| m.values().sum::<usize>();
    let messages: usize = tally.broken.values().map(BTreeSet::len).sum();
    let mut lines = vec![
        format!(
            "{FRAME_TABLE}: {}, execution basis {basis}; {} macros, {} spellings; under {}",
            version_line(&chard_binary()),
            macros().len(),
            SPELLINGS.len(),
            names.join("; ")
        ),
        format!(
            "route_corpus: {} routes expected: {} fed, {} inert, {} broken ({messages} distinct \
             preprocessor messages), {} errored, {} not constructible; {} plain runs; {} \
             readings: {} withheld by a rule, {} with no rule named, {} as a harness failure ({} \
             of them over a plain run that measured the check, declared), {} as the plain run \
             withheld them, {} published as the plain run, {} open, {} forged",
            tally.expected,
            tally.fed,
            tally.inert.values().sum::<usize>(),
            tally.broken_routes,
            tally.errored,
            sum(&tally.unconstructible),
            tally.plain,
            tally.readings,
            sum(&tally.withheld_by),
            sum(&tally.unruled),
            sum(&tally.harness),
            tally.harness_declared,
            tally.as_plain,
            tally.unmoved,
            tally.open,
            tally.forged
        ),
        triple_line(tally),
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
    lines.extend(row_lines(tally, drivers));
    lines.extend(
        OPEN_ROUTES
            .iter()
            .filter(|row| drivers.iter().any(|d| row.holds_on(d)))
            .map(|row| {
                let reads: Vec<String> = row.reads.iter().map(|v| verdict_word(*v)).collect();
                format!(
                    "  open: {} through {} reaching {} reads {}: {}",
                    row.name,
                    row.spellings.join(", "),
                    row.checks.join(", "),
                    reads.join(" or "),
                    row.why
                )
            }),
    );
    for line in &lines {
        println!("{line}");
    }
    common::record("count", &lines.join("; "));
}

/// The frame's line of triples: those fed, those that earned and how, those that earned
/// nothing, the driver and macro pairs routed with none fed, and the compilers required.
fn triple_line(tally: &Tally) -> String {
    let earned = tally.triples.values().filter(|e| **e).count();
    format!(
        "route_corpus: {} driver, macro and spelling triples fed: {earned} earned a reading \
         ({} of them by a declared harness failure alone), {} read as the plain run \
         throughout; {} driver and macro pairs routed and none fed; compilers required: {}",
        tally.triples.len(),
        earned - tally.earned_otherwise.len(),
        tally.triples.len() - earned,
        tally
            .routed
            .iter()
            .filter(|(d, m)| !tally.triples.keys().any(|(td, tm, _)| td == d && tm == m))
            .count(),
        match required_drivers() {
            r if r.is_empty() => "none".to_owned(),
            r => r.join(" and "),
        }
    )
}

/// The frame's lines for the rows of [`MEASURES_NOTHING`], [`HARNESS_ROUTES`] and
/// [`UNDISCRIMINATED`] that hold under the drivers the corpus ran, each with the triples or
/// readings it named on this run.
fn row_lines(tally: &Tally, drivers: &[Driver]) -> Vec<String> {
    let mut lines = Vec::new();
    for row in MEASURES_NOTHING {
        let named = tally
            .triples
            .iter()
            .filter(|((d, m, s), earned)| !**earned && row.names_triple(&drivers[*d], m, s))
            .count();
        let unfed = tally
            .routed
            .iter()
            .filter(|(d, m)| {
                row.names_every_route(&drivers[*d], m)
                    && !tally.triples.keys().any(|(td, tm, _)| td == d && tm == m)
            })
            .count();
        if named + unfed > 0 {
            lines.push(format!(
                "  measures nothing: {} under {} on {}, {named} triples and {unfed} unfed pairs: \
                 {}",
                row.names.join(", "),
                family_word(row.only),
                row.arch.word(),
                row.why
            ));
        }
    }
    for (i, row) in HARNESS_ROUTES.iter().enumerate() {
        if let Some(n) = tally.harness_met.get(&i) {
            lines.push(format!(
                "  harness: {} under {} through {} reads {}, {n} readings: {}",
                row.names.map_or("every macro".to_owned(), |n| n.join(", ")),
                family_word(row.only),
                row.spellings
                    .map_or("every spelling".to_owned(), |s| s.join(", ")),
                verdict_word(row.reads),
                row.why
            ));
        }
    }
    for (i, row) in UNDISCRIMINATED.iter().enumerate() {
        if let Some(n) = tally.undiscriminated_met.get(&i) {
            lines.push(format!(
                "  undiscriminated: {} under {} reads probe-invalid in the plain run, both \
                 controls {} ({}), plain readings excused: {n}: {}",
                row.check,
                family_word(row.only),
                row.outcome,
                row.cause,
                row.why
            ));
        }
    }
    lines
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
fn reconcile(tally: &mut Tally, jobs: &[Job], drivers: &[Driver]) {
    let sum = |m: &BTreeMap<String, usize>| m.values().sum::<usize>();
    let routes = jobs.iter().filter(|j| j.spelling.is_some()).count();
    let messages: usize = tally.broken.values().map(BTreeSet::len).sum();
    if routes + sum(&tally.unconstructible) != tally.expected {
        tally.failures.push(format!(
            "the routes do not add up: {routes} built and {} not constructible, {} expected \
             from the lists",
            sum(&tally.unconstructible),
            tally.expected
        ));
    }
    // The frame's addends, each counted where its route was judged, sum to the routes the
    // lists make.
    let addends = [
        tally.fed,
        tally.inert.values().sum::<usize>(),
        tally.broken_routes,
        tally.errored,
        sum(&tally.unconstructible),
    ];
    if addends.iter().sum::<usize>() != tally.expected {
        tally.failures.push(format!(
            "the frame's addends (fed, inert, broken, errored, not constructible) {addends:?} do \
             not sum to the {} routes expected",
            tally.expected
        ));
    }
    if messages > tally.broken_routes {
        tally.failures.push(format!(
            "{messages} distinct preprocessor failures over {} broken routes",
            tally.broken_routes
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
        .collect();
    if !unexpected.is_empty() {
        tally.failures.push(format!(
            "routes that hold nothing, for no reason INERT or BROKEN gives: {unexpected:?}"
        ));
    }
    judge_triples(tally, drivers);
    // The wrapper keys on the measured build's output names: a driver whose wrapper routes
    // earned nothing, or nothing on an object probe, means the names no longer match what chard
    // builds, and every such route would read as the plain run.
    for driver in &tally.wrapper_fed {
        if !tally.wrapper_earned.contains(driver) {
            tally.failures.push(format!(
                "{driver}: no wrapper route earned a reading; the wrapper reached no measured build"
            ));
        } else if !tally.wrapper_object.contains(driver) {
            tally.failures.push(format!(
                "{driver}: no wrapper route earned a reading on an object probe; the wrapper \
                 reached no `-measured.o` build"
            ));
        }
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

/// Each fed triple that earned nothing is named by a [`MEASURES_NOTHING`] row, and each fed
/// triple a row names earned nothing. A driver and macro with routes and none fed (every one
/// inert, broken or errored) is named by a row of every spelling. Each row names something fed
/// or routed wherever a driver it holds for ran, each [`HARNESS_ROUTES`] row declared a reading
/// wherever a driver of its family ran, and each [`UNDISCRIMINATED`] row excused a plain run's
/// reading wherever a driver of its family ran.
fn judge_triples(tally: &mut Tally, drivers: &[Driver]) {
    let mut met = BTreeSet::new();
    let mut failures = Vec::new();
    for ((d, name, spelling), earned) in &tally.triples {
        let driver = &drivers[*d];
        let row = MEASURES_NOTHING
            .iter()
            .position(|row| row.names_triple(driver, name, spelling));
        match (earned, row) {
            (false, None) => failures.push(format!(
                "{} {name} {spelling}: every reading is its state's plain run, and no \
                 MEASURES_NOTHING row names it on {}{}",
                driver.name,
                driver.arch,
                if MEASURES_NOTHING.iter().any(|row| {
                    row.names.contains(&name.as_str())
                        && row.spellings.is_none_or(|sp| sp.contains(spelling))
                }) {
                    " (a row names it on another architecture)"
                } else {
                    ""
                }
            )),
            (true, Some(i)) => failures.push(format!(
                "{} {name} {spelling}: MEASURES_NOTHING's row for {} names this triple, and it \
                 earned a reading: narrow the row",
                driver.name,
                MEASURES_NOTHING[i].names.join(", ")
            )),
            (false, Some(i)) => {
                met.insert(i);
            }
            (true, None) => {}
        }
    }
    for (d, name) in &tally.routed {
        if tally
            .triples
            .keys()
            .any(|(td, tn, _)| td == d && tn == name)
        {
            continue;
        }
        let driver = &drivers[*d];
        match MEASURES_NOTHING
            .iter()
            .position(|row| row.names_every_route(driver, name))
        {
            Some(i) => {
                met.insert(i);
            }
            None => failures.push(format!(
                "{} {name}: no route was fed (each inert, broken or errored), and no \
                 MEASURES_NOTHING row of every spelling names it",
                driver.name
            )),
        }
    }
    for (i, row) in MEASURES_NOTHING.iter().enumerate() {
        let here = drivers
            .iter()
            .any(|d| (row.only == Only::Any || row.only == d.family) && row.arch.holds(&d.arch));
        if here && !met.contains(&i) {
            failures.push(format!(
                "MEASURES_NOTHING's row for {} under {} names nothing fed or routed here: retire \
                 it",
                row.names.join(", "),
                family_word(row.only)
            ));
        }
    }
    for (i, row) in HARNESS_ROUTES.iter().enumerate() {
        let here = drivers
            .iter()
            .any(|d| row.only == Only::Any || row.only == d.family);
        if here && !tally.harness_met.contains_key(&i) {
            failures.push(format!(
                "HARNESS_ROUTES' row for {} under {} declared no reading here: retire it",
                row.names.map_or("every macro".to_owned(), |n| n.join(", ")),
                family_word(row.only)
            ));
        }
    }
    for (i, row) in UNDISCRIMINATED.iter().enumerate() {
        let here = drivers.iter().any(|d| row.only == d.family);
        if here && !tally.undiscriminated_met.contains_key(&i) {
            failures.push(format!(
                "UNDISCRIMINATED's row for {} under {} excused no plain run here: retire it",
                row.check,
                family_word(row.only)
            ));
        }
    }
    tally.failures.extend(failures);
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

/// The architectures a row of [`MEASURES_NOTHING`] holds on.
#[derive(Clone, Copy, Debug)]
enum Arch {
    Every,
    /// These alone, each one a run measured. On any other the row's triples must earn, so a run
    /// on an architecture no run has measured fails until its own rows are written.
    On(&'static [&'static str]),
}

impl Arch {
    fn holds(self, arch: &str) -> bool {
        match self {
            Arch::Every => true,
            Arch::On(arches) => arches.contains(&arch),
        }
    }

    fn word(self) -> String {
        match self {
            Arch::Every => "every architecture".to_owned(),
            Arch::On(arches) => arches.join(" and "),
        }
    }
}

/// The word a frame or failure line gives a driver family.
fn family_word(only: Only) -> &'static str {
    match only {
        Only::Any => "gcc and clang",
        Only::Gcc => "gcc",
        Only::Clang => "clang",
    }
}

/// A row names macros, spellings (or every spelling the driver takes), a driver family and the
/// architectures it holds on. Each named macro through each named spelling reads every reached
/// check, in every state, as its plain run does; the row's `why` says why. A row of every
/// spelling also names a driver and macro whose routes are all inert, broken or errored, so
/// none is fed.
struct Unmoved {
    only: Only,
    arch: Arch,
    names: &'static [&'static str],
    spellings: Option<&'static [&'static str]>,
    why: &'static str,
}

impl Unmoved {
    fn names_triple(&self, driver: &Driver, name: &str, spelling: &str) -> bool {
        (self.only == Only::Any || self.only == driver.family)
            && self.arch.holds(&driver.arch)
            && self.names.contains(&name)
            && self.spellings.is_none_or(|s| s.contains(&spelling))
    }

    /// Does the row name every spelling of `name` under `driver`, so that a driver and macro
    /// whose routes none fed reads nothing for the reason it gives?
    fn names_every_route(&self, driver: &Driver, name: &str) -> bool {
        self.spellings.is_none()
            && (self.only == Only::Any || self.only == driver.family)
            && self.arch.holds(&driver.arch)
            && self.names.contains(&name)
    }
}

/// The spellings no rule reads that a C compile reads ahead of `<stdio.h>`: the environment's
/// directories and the shadows under a layout's path word, the configuration channels clang
/// and gcc read, and the wrapper.
const UNREAD_DEFINES: &[&str] = &[
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-resource-dir shadow define",
    "CCC_OVERRIDE_OPTIONS define",
    "wrapper define",
];

/// [`UNREAD_DEFINES`] and the defines on the command line.
const COMMAND_LINE_AND_UNREAD_DEFINES: &[&str] = &[
    "-D",
    "-D split",
    "-Wp,-D",
    "-Xpreprocessor -D",
    "--define-macro",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-resource-dir shadow define",
    "CCC_OVERRIDE_OPTIONS define",
    "wrapper define",
];

/// The defines a C++ compile reads after `<cstdio>` that no rule reads: the shadows under a
/// search directory and under a layout's path word, and the wrapper.
const CXX_UNREAD_DEFINES: &[&str] = &[
    "-I shadow define",
    "--include-directory= shadow define",
    "--include-directory split shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "CPLUS_INCLUDE_PATH shadow define",
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-resource-dir shadow define",
    "--gcc-install-dir= shadow define",
    "--gcc-toolchain= shadow define",
    "-stdlib++-isystem shadow define",
    "-ccc-install-dir shadow define",
    "wrapper define",
];

/// The spellings only a C++ compile reads, both directions.
const CXX_ONLY: &[&str] = &[
    "CPLUS_INCLUDE_PATH shadow define",
    "CPLUS_INCLUDE_PATH shadow undefine",
    "--gcc-install-dir= shadow define",
    "--gcc-install-dir= shadow undefine",
    "--gcc-toolchain= shadow define",
    "-stdlib++-isystem shadow define",
    "-ccc-install-dir shadow define",
    "--gcc-toolchain= shadow undefine",
    "-stdlib++-isystem shadow undefine",
    "-ccc-install-dir shadow undefine",
];

/// The defines a C compile reads that no rule reads where `__CET__` decides nothing, off
/// `x86_64`: the shadows under a search directory or a layout, gcc's specs, clang's
/// configuration file, `CCC_OVERRIDE_OPTIONS` and the wrapper.
const CET_OFF_X86_DEFINES: &[&str] = &[
    "-I shadow define",
    "--include-directory= shadow define",
    "--include-directory split shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "-Wp,-I shadow define",
    "-Xpreprocessor -I shadow define",
    "-Xpreprocessor -isystem shadow define",
    "-Xclang -I shadow define",
    "-iwithsysroot shadow define",
    "-Xclang -c-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-resource-dir shadow define",
    "-specs define",
    "--config define",
    "CCC_OVERRIDE_OPTIONS define",
    "wrapper define",
];

/// clang's undefines of its own `__clang__` that no rule reads.
const CLANG_UNREAD_UNDEFINES: &[&str] = &[
    "-I shadow undefine",
    "--include-directory= shadow undefine",
    "--include-directory split shadow undefine",
    "-I split shadow undefine",
    "-isystem shadow undefine",
    "CPATH shadow undefine",
    "C_INCLUDE_PATH shadow undefine",
    "--sysroot shadow undefine",
    "-resource-dir shadow undefine",
    "wrapper undefine",
];

/// Built from the corpus's runs on Fedora 44 x86_64 (gcc 16.2.1, clang 22.1.8), for the rows of
/// every architecture and of `x86_64`, and on Ubuntu 26.04 aarch64 (gcc 15.2.0, clang 21.1.8),
/// for the rows of every architecture and of `aarch64`.
const MEASURES_NOTHING: &[Unmoved] = &[
    Unmoved {
        only: Only::Any,
        arch: Arch::Every,
        names: &["_LIBCPP_HARDENING_MODE"],
        spellings: Some(CXX_UNREAD_DEFINES),
        why: "under libstdc++ `cxx-hardening-requested` does not read libc++'s request, so a \
              forged one through a spelling no rule reads reads as the plain run",
    },
    Unmoved {
        only: Only::Any,
        arch: Arch::Every,
        names: &["_GLIBCXX_ASSERTIONS"],
        spellings: Some(&[
            "C_INCLUDE_PATH shadow define",
            "C_INCLUDE_PATH shadow undefine",
        ]),
        why: "a C compile alone reads `C_INCLUDE_PATH`, and only the C++ probe reads \
              `_GLIBCXX_ASSERTIONS`",
    },
    Unmoved {
        only: Only::Any,
        arch: Arch::Every,
        names: &["_USE_FORTIFY_LEVEL"],
        spellings: Some(UNREAD_DEFINES),
        why: "`fortify-effective`'s macro clauses read glibc's `__USE_FORTIFY_LEVEL` before \
              Apple's `_USE_FORTIFY_LEVEL` (`src/predicate/macro_channel.rs`), and glibc's \
              `<features.h>` always defines the first, so beside glibc a forged \
              `_USE_FORTIFY_LEVEL` through a spelling no rule reads leaves `fortify-effective` \
              at the plain run's reading. `fortify-requested` reads the request, which the \
              state removes (`-U_FORTIFY_SOURCE`), so it reads `off` as the plain run does",
    },
    Unmoved {
        only: Only::Any,
        arch: Arch::Every,
        names: &["__SSP_FORTIFY_LEVEL"],
        spellings: Some(COMMAND_LINE_AND_UNREAD_DEFINES),
        why: "FreeBSD's `<ssp/ssp.h>` defines `__SSP_FORTIFY_LEVEL`, and \
              `fortify-effective`'s clauses that read it require `__FreeBSD__` \
              (`src/predicate/macro_channel.rs`, the `freebsd-` clauses), so off FreeBSD a \
              forged one, on the command line too, leaves `fortify-effective` at the plain \
              run's reading",
    },
    Unmoved {
        only: Only::Any,
        arch: Arch::Every,
        names: &["__OPTIMIZE__"],
        spellings: Some(CXX_ONLY),
        why: "the C++ library's `<bits/c++config.h>`, which `<cstdio>` includes, settles \
              libstdc++'s assertions before a C++ shadow's operation runs, from \
              `__OPTIMIZE__` where the library ties them to it and from nothing it reads \
              where it does not (`Driver::assertions_follow_optimize`). The C++ probe's \
              `chard-opt=` line on stderr (`probes/cxx_assertions.cpp`) moves no reading, so \
              its checks read as the plain run. The C probes read no C++ compile's headers",
    },
    Unmoved {
        only: Only::Clang,
        arch: Arch::Every,
        names: &["__clang__"],
        spellings: Some(CLANG_UNREAD_UNDEFINES),
        why: "with `__clang__` undefined after `<stdio.h>`, clang takes the probes' gcc arms \
              (an attribute it ignores, a diagnostic pragma, the frontend line). Over the \
              state's build without the protection, every check then reads as the plain run",
    },
    Unmoved {
        only: Only::Any,
        arch: Arch::On(&["aarch64"]),
        names: &["__CET__"],
        spellings: Some(CET_OFF_X86_DEFINES),
        why: "on `aarch64` the checks `__CET__` reaches read as in the plain run under a route \
              no rule reads: `cet-macro` `unsupported` under `arch-gated`, \
              `shadow-stack-enforced` `indeterminate` under `no-check-on-target`, and \
              `zero-call-used-regs`, whose probe reads `__CET__` in its `x86_64` arm alone",
    },
    Unmoved {
        only: Only::Any,
        arch: Arch::On(&["aarch64"]),
        names: &["__CET__"],
        spellings: Some(&[
            "-iwithprefixbefore shadow define",
            "-iwithprefix shadow define",
        ]),
        why: "clang reads `-iwithprefixbefore` as it reads `-Xclang -I`, which \
              `CET_OFF_X86_DEFINES` names in the row above. Under gcc both words withhold \
              `cet-macro` alone on `x86_64` (`compile-inputs-unmatched-by-arms`), and on \
              `aarch64` `cet-macro` is `unsupported` under `arch-gated` first",
    },
    Unmoved {
        only: Only::Any,
        arch: Arch::On(&["x86_64"]),
        names: &[
            "__ARM_FEATURE_BTI_DEFAULT",
            "__ARM_FEATURE_PAC_DEFAULT",
            "__ARM_FEATURE_GCS_DEFAULT",
        ],
        spellings: None,
        why: "on `x86_64` `branch-protection-macro` and `gcs-macro` read as the plain run under \
              every route: `unsupported` under `arch-gated`",
    },
];

/// The harness failures a route reads where its plain run measured the check, by driver
/// family, macro (or any), spelling (or any), check (or any) and verdict, with why. Such a
/// reading moved from the plain run's measurement to a withholding the harness gives, not a
/// rule: one no row names fails the corpus, a row no reading meets under a driver of its
/// family fails as stale, and a reading a row names counts as earned for its triple.
struct HarnessRoute {
    only: Only,
    names: Option<&'static [&'static str]>,
    spellings: Option<&'static [&'static str]>,
    checks: Option<&'static [&'static str]>,
    reads: Verdict,
    why: &'static str,
}

impl HarnessRoute {
    fn holds(&self, family: Only, name: &str, spelling: &str, r: &Reading) -> bool {
        (self.only == Only::Any || self.only == family)
            && self.names.is_none_or(|n| n.contains(&name))
            && self.spellings.is_none_or(|s| s.contains(&spelling))
            && self.checks.is_none_or(|c| c.contains(&r.check))
            && self.reads == r.verdict
    }
}

/// The spellings whose operation reaches the control arms: the forced files without the key
/// (the arms of a check that reads the measured build carry the profile's `-include` and
/// `-imacros`, `toolchain::header_selecting_flags`, and not its `-D`), and the variable clang's
/// driver applies to every command line it is given.
const REACHES_THE_ARMS: &[&str] = &[
    "-include define",
    "-include undefine",
    "-imacros define",
    "-imacros undefine",
    "CCC_OVERRIDE_OPTIONS define",
    "CCC_OVERRIDE_OPTIONS undefine",
];

/// Built from the corpus's runs on Fedora 44 x86_64 (gcc 16.2.1, clang 22.1.8) and Ubuntu 26.04
/// aarch64 (gcc 15.2.0, clang 21.1.8).
const HARNESS_ROUTES: &[HarnessRoute] = &[
    HarnessRoute {
        only: Only::Any,
        names: None,
        spellings: Some(REACHES_THE_ARMS),
        checks: None,
        reads: Verdict::ProbeInvalid,
        why: "the operation reaches the forced-on and forced-off arms as it reaches the \
              measured build, so the arms read the macro alike and the control triple does not \
              discriminate: the check is withheld by the triple, not read off the forgery",
    },
    HarnessRoute {
        only: Only::Gcc,
        names: Some(&["__clang__"]),
        spellings: None,
        checks: Some(&["ubsan-trap-mode"]),
        reads: Verdict::BuildFailed,
        why: "under a forged `__clang__` `probes/ubsan_trap.c` spells clang's `_Nonnull`, \
              which gcc does not compile",
    },
    HarnessRoute {
        only: Only::Clang,
        names: Some(&["__FreeBSD__"]),
        spellings: None,
        checks: Some(&["fortify-effective"]),
        reads: Verdict::BuildFailed,
        why: "under a forged `__FreeBSD__` `probes/chard_selfreport.h` stops the build \
              (`#error`) where FreeBSD's `<sys/cdefs.h>` guard `_SYS_CDEFS_H_` is undefined, \
              and glibc's guard is `_SYS_CDEFS_H` (gcc's command-line routes of the macro \
              break first, as `BROKEN` says, and its shadow headers have the row below)",
    },
    HarnessRoute {
        only: Only::Gcc,
        names: Some(&["__FreeBSD__"]),
        spellings: Some(GCC_FREEBSD_SHADOWS),
        checks: Some(&["fortify-effective"]),
        reads: Verdict::BuildFailed,
        why: "a shadow header forging `__FreeBSD__` stops the build at \
              `probes/chard_selfreport.h`'s `#error` as clang's forgery does, and the probe's \
              macro dump, the same unit, stops at it too; a failed build is the reading, \
              whatever the dump says (`report::Variant::sufficient_for`)",
    },
];

/// The shadow-header spellings through which gcc's forged `__FreeBSD__` reaches the build
/// (its command-line spellings break before it, `BROKEN`).
const GCC_FREEBSD_SHADOWS: &[&str] = &[
    "-I shadow define",
    "-I split shadow define",
    "-isystem shadow define",
    "CPATH shadow define",
    "C_INCLUDE_PATH shadow define",
    "-Xpreprocessor -I shadow define",
    "-Xpreprocessor -isystem shadow define",
    "-Wp,-I shadow define",
    "--sysroot shadow define",
    "-isysroot shadow define",
    "-B shadow define",
    "--prefix= shadow define",
    "-iwithprefixbefore shadow define",
    "-iwithprefix shadow define",
    "--include-directory= shadow define",
    "--include-directory split shadow define",
];

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
    reconcile(&mut tally, &jobs, &drivers);
    print_frame(&tally, &drivers, &basis);
    write_cells(&tally);
    assert!(
        tally.failures.is_empty(),
        "{} failures:\n{}",
        tally.failures.len(),
        tally.failures.join("\n")
    );
}

#[test]
fn every_reason_a_route_is_not_built_is_declared() {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (name, class) in macros() {
        let mut built_on_x86 = false;
        for direction in [Define, Undefine] {
            for (arch, gcs) in [
                ("x86_64", false),
                ("aarch64", false),
                ("aarch64", true),
                ("riscv64", false),
            ] {
                for family in [Only::Gcc, Only::Clang] {
                    match state(&name, class, direction, arch, gcs, family) {
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
    for (name, class) in macros() {
        for spelling in SPELLINGS {
            if let Err(why) = constructible(spelling, class, &name) {
                assert!(UNCONSTRUCTIBLE.contains(&why), "undeclared reason: {why}");
                seen.insert(why);
            }
        }
    }
    let unused: Vec<&&str> = UNCONSTRUCTIBLE
        .iter()
        .filter(|r| !seen.contains(**r))
        .collect();
    assert!(
        unused.is_empty(),
        "declared reasons no state gives: {unused:?}"
    );
}

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

#[test]
fn an_assertions_row_holds_only_where_the_library_ties_them_to_optimize() {
    let mut tied = 0;
    for row in OPEN_ROUTES {
        if row.name != "__OPTIMIZE__"
            || !row
                .checks
                .iter()
                .any(|c| ASSERTIONS_FROM_OPTIMIZE.contains(c))
        {
            continue;
        }
        tied += 1;
        assert!(
            row.checks
                .iter()
                .all(|c| ASSERTIONS_FROM_OPTIMIZE.contains(c)),
            "an __OPTIMIZE__ row mixes the assertion checks with others: {:?}",
            row.checks
        );
        for family in [Only::Gcc, Only::Clang] {
            if !(row.only == Only::Any || row.only == family) {
                continue;
            }
            let with = synthetic_driver_on(family, "x86_64");
            let without = Driver {
                assertions_follow_optimize: Some(false),
                ..synthetic_driver_on(family, "x86_64")
            };
            let unmeasured = Driver {
                assertions_follow_optimize: None,
                ..synthetic_driver_on(family, "x86_64")
            };
            assert!(
                !row.holds_on(&unmeasured),
                "{:?} under {family:?}",
                row.spellings
            );
            assert!(row.holds_on(&with), "{:?} under {family:?}", row.spellings);
            assert!(
                !row.holds_on(&without),
                "{:?} under {family:?}",
                row.spellings
            );
            assert!(
                row_combinations(row, std::slice::from_ref(&without)).is_empty(),
                "the row for {:?} expects a combination without the tie",
                row.spellings
            );
        }
    }
    assert!(
        tied > 0,
        "no open __OPTIMIZE__ row reaches the assertion checks"
    );
}

#[test]
fn an_arch_scoped_open_row_holds_on_its_architecture_alone() {
    let mut scoped = 0;
    for row in OPEN_ROUTES {
        let Some(arch) = row.arch else { continue };
        scoped += 1;
        let elsewhere = ARCHES
            .iter()
            .find(|a| **a != arch)
            .expect("another architecture");
        for family in [Only::Gcc, Only::Clang] {
            if !(row.only == Only::Any || row.only == family) {
                continue;
            }
            let here = synthetic_driver_on(family, arch);
            let there = synthetic_driver_on(family, elsewhere);
            assert!(
                !row_combinations(row, std::slice::from_ref(&here)).is_empty(),
                "the row for {} expects nothing on {arch} under {family:?}",
                row.name
            );
            assert!(
                row_combinations(row, std::slice::from_ref(&there)).is_empty(),
                "the row for {} expects combinations on {elsewhere} under {family:?}",
                row.name
            );
            let spelling = SPELLINGS
                .iter()
                .position(|s| row.spellings.contains(&s.id) && applies(s, family))
                .expect("a spelling of the row under the family");
            let class = macros()
                .into_iter()
                .find(|(m, _)| m == row.name)
                .map(|(_, c)| c)
                .expect("a listed macro");
            let states = state(
                row.name,
                class,
                SPELLINGS[spelling].direction,
                arch,
                here.gcs,
                family,
            )
            .expect("a state on the row's architecture");
            // The row's own state where it names one, else the first the macro has.
            let own = row.states.unwrap_or(states[0]);
            assert!(
                states.contains(&own),
                "the row for {} names a state its macro does not have on {arch}",
                row.name
            );
            let job = Job {
                driver: 0,
                name: row.name.to_owned(),
                direction: SPELLINGS[spelling].direction,
                spelling: Some(spelling),
                state: own,
                reached: Vec::new(),
            };
            for check in row.checks {
                assert!(
                    open_row(&job, std::slice::from_ref(&here), check).is_some(),
                    "the row for {} does not name its reading on {arch}",
                    row.name
                );
                assert!(
                    open_row(&job, std::slice::from_ref(&there), check).is_none(),
                    "the row for {} names a reading on {elsewhere}",
                    row.name
                );
            }
        }
    }
    assert!(scoped > 0, "no open row names an architecture");
}

/// Under each family the open row claims and some spelling of it is a route of, on the row's
/// architecture (`x86_64` for a row of every architecture): at least one combination, every
/// one of them a state the corpus builds, so no part of the row is expected nowhere.
fn row_combinations_are_met(row: &OpenRoute) {
    for family in [Only::Gcc, Only::Clang] {
        let claimed = row.only == Only::Any || row.only == family;
        let taken = row
            .spellings
            .iter()
            .any(|id| SPELLINGS.iter().any(|s| s.id == *id && applies(s, family)));
        if !(claimed && taken) {
            continue;
        }
        let combinations = row_combinations(
            row,
            &[synthetic_driver_on(family, row.arch.unwrap_or("x86_64"))],
        );
        for id in row.spellings {
            let applies_here = SPELLINGS.iter().any(|s| s.id == *id && applies(s, family));
            let named = format!(" {id} [");
            assert!(
                !applies_here || combinations.iter().any(|c| c.contains(&named)),
                "the row for {} names {id}, which has no combination under {family:?}",
                row.name
            );
        }
        assert!(
            !combinations.is_empty(),
            "the row for {} names no combination under {family:?}",
            row.name
        );
        let unmet: Vec<&String> = combinations
            .iter()
            .filter(|c| c.ends_with(": no state") || c.ends_with(": not constructible"))
            .collect();
        assert!(
            unmet.is_empty(),
            "the row for {} names combinations that cannot be met: {unmet:?}",
            row.name
        );
    }
}

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
                .find(|s| {
                    s.id == *id
                        && (s.only == Only::Any || row.only == Only::Any || s.only == row.only)
                })
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
                let arch = row.arch.unwrap_or("x86_64");
                let states = state(
                    row.name,
                    *class,
                    spelling.direction,
                    arch,
                    arch == "aarch64",
                    family,
                )
                .unwrap_or_else(|why| panic!("{} {id} has no state: {why}", row.name));
                assert!(
                    states.contains(&want),
                    "{} {id} has no state {want:?}",
                    row.name
                );
            }
        }
        assert_eq!(directions.len(), 1, "{} mixes directions", row.name);
        assert!(
            row.arch.is_none_or(|a| ARCHES.contains(&a)),
            "the row for {} names an architecture the corpus does not know",
            row.name
        );
        let components = row.checks.iter().all(|c| {
            CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .any(|k| k.id == *c && k.levels == CFI_COMPONENTS)
        });
        // A row names levels only for a forged `on` or `partial` of a check with levels.
        let leveled = row.checks.iter().any(|c| {
            CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .any(|k| k.id == *c && k.levels != Levels::None)
        });
        let present = row
            .reads
            .iter()
            .any(|v| matches!(v, Verdict::On | Verdict::Partial));
        assert!(
            row.levels.is_empty() || (leveled && present),
            "row {} names levels {:?} without a leveled check and an `on` or `partial` read",
            row.name,
            row.levels
        );
        let forges = |v: &Verdict| match directions.first() {
            Some(Define) => matches!(v, Verdict::On | Verdict::Partial),
            _ => *v == Verdict::Off || (components && *v == Verdict::Partial),
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
        row_combinations_are_met(row);
    }
    let ids: BTreeSet<&str> = SPELLINGS.iter().map(|s| s.id).collect();
    assert_eq!(ids.len(), SPELLINGS.len(), "each spelling is named once");
}

fn synthetic_driver() -> Vec<Driver> {
    vec![synthetic_driver_of(Only::Gcc)]
}

/// A driver of `family` on `x86_64` that names no program the test runs.
fn synthetic_driver_of(family: Only) -> Driver {
    synthetic_driver_on(family, "x86_64")
}

/// A driver of `family` on `arch` that names no program the test runs; on `aarch64` it defines
/// `__ARM_FEATURE_GCS_DEFAULT` under `-mbranch-protection=standard`, so every state the corpus
/// can build there is a state of it.
fn synthetic_driver_on(family: Only, arch: &str) -> Driver {
    let (name, cxx) = if family == Only::Clang {
        ("clang", "clang++")
    } else {
        ("gcc", "g++")
    };
    Driver {
        name,
        cxx,
        family,
        arch: arch.to_owned(),
        gcs: arch == "aarch64",
        assertions_follow_optimize: Some(true),
        version: "synthetic".to_owned(),
    }
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
        controls: None,
    }
}

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

#[test]
fn a_forged_assertions_reading_without_the_tie_fails_as_forged() {
    for (tie, open, forged) in [(true, 1, 0), (false, 0, 1)] {
        let drivers = vec![Driver {
            assertions_follow_optimize: Some(tie),
            ..synthetic_driver_of(Only::Gcc)
        }];
        let mut tally = Tally::default();
        let baseline = judge_plain(
            &[job_of("__OPTIMIZE__", None)],
            &[Ok(Outcome::Readings(vec![synthetic_reading(
                "cxx-stdlib-assertions",
                Verdict::On,
            )]))],
            &drivers,
            &mut tally,
        );
        // The plain run's own judgement (its macro check is not in this synthetic reading)
        // is not under test: only what judging the route adds.
        let before = tally.failures.len();
        judge_route(
            &job_of("__OPTIMIZE__", Some("wrapper define")),
            &drivers,
            &Ok(Outcome::Readings(vec![synthetic_reading(
                "cxx-stdlib-assertions",
                Verdict::Off,
            )])),
            &baseline,
            &mut tally,
        );
        assert_eq!(
            (tally.open, tally.forged),
            (open, forged),
            "with the tie {tie}: {:?}",
            tally.failures
        );
        let added = &tally.failures[before..];
        assert_eq!(
            added.len(),
            usize::from(!tie),
            "with the tie {tie}: {added:?}"
        );
        assert!(
            added.iter().all(|f| f.contains("cxx-stdlib-assertions")),
            "with the tie {tie}: {added:?}"
        );
    }
}

/// A job of `name` through the spelling with id `spelling` (a plain run where `None`), in the
/// first define state the synthetic gcc driver on `x86_64` has.
fn job_of(name: &str, spelling: Option<&str>) -> Job {
    job_under(Only::Gcc, name, spelling)
}

/// [`job_of`] under a synthetic driver of `family`.
fn job_under(family: Only, name: &str, spelling: Option<&str>) -> Job {
    let class = macros()
        .into_iter()
        .find(|(m, _)| m == name)
        .map(|(_, c)| c)
        .expect("a listed macro");
    let states = state(name, class, Define, "x86_64", false, family).expect("a define state");
    Job {
        driver: 0,
        name: name.to_owned(),
        direction: Define,
        spelling: spelling.map(|id| {
            SPELLINGS
                .iter()
                .position(|s| s.id == id)
                .expect("a spelling of the table")
        }),
        state: states[0],
        reached: reached(name),
    }
}

/// Judge one route of `name` through `spelling` reading `route` over a plain run reading
/// `plain`, then its triple, and return the failures the judges gave that name `name`.
fn judged(name: &str, spelling: &str, plain: Reading, route: Reading) -> (Tally, Vec<String>) {
    judged_under(Only::Gcc, name, spelling, plain, route)
}

/// [`judged`] under a synthetic driver of `family`.
fn judged_under(
    family: Only,
    name: &str,
    spelling: &str,
    plain: Reading,
    route: Reading,
) -> (Tally, Vec<String>) {
    let drivers = vec![synthetic_driver_of(family)];
    let mut tally = Tally::default();
    let baseline = judge_plain(
        &[job_under(family, name, None)],
        &[Ok(Outcome::Readings(vec![plain]))],
        &drivers,
        &mut tally,
    );
    judge_route(
        &job_under(family, name, Some(spelling)),
        &drivers,
        &Ok(Outcome::Readings(vec![route])),
        &baseline,
        &mut tally,
    );
    judge_triples(&mut tally, &drivers);
    let named = tally
        .failures
        .iter()
        .filter(|f| f.contains(name))
        .cloned()
        .collect();
    (tally, named)
}

#[test]
fn the_judges_hold_a_route_to_its_frame() {
    let read = |check, verdict, level: &str, rule: &str| Reading {
        check,
        verdict,
        level: level.to_owned(),
        rule: rule.to_owned(),
        controls: None,
    };
    let off = |check| read(check, Verdict::Off, "null", "");
    // `__PIC__` through a shadow is open at `on` level 2; at level 1, or at none, it is forged.
    let (tally, failures) = judged(
        "__PIC__",
        "-I shadow define",
        off("pic-macro"),
        read("pic-macro", Verdict::On, "\"2\"", ""),
    );
    assert_eq!((tally.open, tally.forged), (1, 0), "{failures:?}");
    assert!(failures.is_empty(), "{failures:?}");
    for level in ["\"1\"", "null"] {
        let (tally, failures) = judged(
            "__PIC__",
            "-I shadow define",
            off("pic-macro"),
            read("pic-macro", Verdict::On, level, ""),
        );
        assert_eq!((tally.open, tally.forged), (0, 1), "{level}: {failures:?}");
        assert!(
            failures
                .iter()
                .any(|f| f.contains("pic-macro published on")),
            "{failures:?}"
        );
    }
    // A harness reading over a measured plain run: undeclared through `-D`, declared through
    // an unkeyed `-include`, where it earns its triple; the row is held to its verdict too.
    let invalid = read("pie-macro", Verdict::ProbeInvalid, "null", "");
    let (tally, failures) = judged("__PIE__", "-D", off("pie-macro"), invalid.clone());
    assert!(
        failures.iter().any(|f| f.contains("no HARNESS_ROUTES row")),
        "{failures:?}"
    );
    assert_eq!(tally.harness_declared, 0);
    let (tally, failures) = judged("__PIE__", "-include define", off("pie-macro"), invalid);
    assert_eq!(tally.harness_declared, 1, "{failures:?}");
    assert!(failures.is_empty(), "{failures:?}");
    let failed = read("pie-macro", Verdict::BuildFailed, "null", "");
    let (tally, failures) = judged("__PIE__", "-include define", off("pie-macro"), failed);
    assert_eq!(tally.harness_declared, 0, "{failures:?}");
    assert!(
        failures.iter().any(|f| f.contains("no HARNESS_ROUTES row")),
        "{failures:?}"
    );
    // A row naming a macro and a check holds them alone: gcc's forged `__clang__` declares
    // `ubsan-trap-mode`, and no other check.
    let ubsan = read("ubsan-trap-mode", Verdict::BuildFailed, "null", "");
    let (tally, _) = judged("__clang__", "-D", off("ubsan-trap-mode"), ubsan);
    assert_eq!(tally.harness_declared, 1);
    let trapv = read("trapv-trapped", Verdict::BuildFailed, "null", "");
    let (tally, failures) = judged("__clang__", "-D", off("trapv-trapped"), trapv);
    assert_eq!(tally.harness_declared, 0, "{failures:?}");
    // A forged `__FreeBSD__` declares `fortify-effective` under clang through any spelling,
    // and under gcc through a shadow header alone.
    let fortify = || read("fortify-effective", Verdict::BuildFailed, "null", "");
    let plain = || off("fortify-effective");
    let (tally, _) = judged_under(Only::Clang, "__FreeBSD__", "-D", plain(), fortify());
    assert_eq!(tally.harness_declared, 1);
    let (tally, _) = judged_under(Only::Gcc, "__FreeBSD__", "-D", plain(), fortify());
    assert_eq!(tally.harness_declared, 0);
    let shadow = "-I shadow define";
    let (tally, _) = judged_under(Only::Gcc, "__FreeBSD__", shadow, plain(), fortify());
    assert_eq!(tally.harness_declared, 1);
}

#[test]
fn the_judges_compare_a_route_with_its_plain_run() {
    let read = |verdict, level: &str, rule: &str| Reading {
        check: "pic-macro",
        verdict,
        level: level.to_owned(),
        rule: rule.to_owned(),
        controls: None,
    };
    let on = |level| read(Verdict::On, level, "");
    let held = |rule| read(Verdict::Indeterminate, "null", rule);
    let spelling = "-I shadow define";
    let (tally, _) = judged("__PIC__", spelling, on("\"1\""), on("\"1\""));
    assert_eq!((tally.unmoved, tally.open + tally.forged), (1, 0));
    let (tally, _) = judged("__PIC__", spelling, on("\"1\""), on("\"2\""));
    assert_eq!((tally.unmoved, tally.open), (0, 1));
    let (tally, _) = judged("__PIC__", spelling, held("a-rule"), held("a-rule"));
    assert_eq!((tally.as_plain, tally.withheld_by.len()), (1, 0));
    let (tally, _) = judged("__PIC__", spelling, held("a-rule"), held("another-rule"));
    assert_eq!(
        (tally.as_plain, tally.withheld_by.get("another-rule")),
        (0, Some(&1))
    );
}

#[test]
fn the_judges_excuse_a_plain_run_only_under_its_undiscriminated_row() {
    let check = "no-delete-null-pointer-checks";
    let controls = |positive: &str, negative: &str, cause: &str| {
        Some(Controls {
            positive: positive.to_owned(),
            negative: negative.to_owned(),
            cause: cause.to_owned(),
        })
    };
    let kept = || controls("present", "present", "negative-also-shows");
    let judged_plain = |family: Only, verdict: Verdict, controls: Option<Controls>| {
        let drivers = vec![synthetic_driver_of(family)];
        let mut tally = Tally::default();
        let reading = Reading {
            controls,
            ..synthetic_reading(check, verdict)
        };
        judge_plain(
            &[job_under(family, "__OPTIMIZE__", None)],
            &[Ok(Outcome::Readings(vec![reading]))],
            &drivers,
            &mut tally,
        );
        judge_triples(&mut tally, &drivers);
        let failed = tally
            .failures
            .iter()
            .any(|f| f.contains(&format!("the plain run reads {check} ")));
        let stale = tally.failures.iter().any(|f| {
            f.starts_with(&format!(
                "UNDISCRIMINATED's row for {check} under clang excused no plain run here"
            ))
        });
        let frame = row_lines(&tally, &drivers);
        (tally, failed, stale, frame)
    };
    let (tally, failed, stale, frame) = judged_plain(Only::Clang, Verdict::ProbeInvalid, kept());
    assert!(!failed && !stale, "{:?}", tally.failures);
    assert_eq!(tally.undiscriminated_met.get(&0), Some(&1));
    assert!(
        frame.iter().any(|l| l.starts_with(&format!(
            "  undiscriminated: {check} under clang reads probe-invalid in the plain run, both \
             controls present (negative-also-shows), plain readings excused: 1: under clang \
             22.1.8"
        ))),
        "{frame:?}"
    );
    // Under gcc the same reading is a harness failure, and the clang row is not judged.
    let (tally, failed, stale, _) = judged_plain(Only::Gcc, Verdict::ProbeInvalid, kept());
    assert!(failed && !stale, "{:?}", tally.failures);
    assert!(tally.undiscriminated_met.is_empty());
    // Under clang, either control reading otherwise, another cause, controls the report does
    // not state, and a build failure are not the row's, and the row, excusing nothing, is stale.
    for (verdict, controls) in [
        (
            Verdict::ProbeInvalid,
            controls("present", "absent", "negative-also-shows"),
        ),
        (
            Verdict::ProbeInvalid,
            controls("absent", "present", "negative-also-shows"),
        ),
        (
            Verdict::ProbeInvalid,
            controls("present", "present", "regime-confounded"),
        ),
        (Verdict::ProbeInvalid, None),
        (Verdict::BuildFailed, kept()),
    ] {
        let (tally, failed, stale, _) = judged_plain(Only::Clang, verdict, controls.clone());
        assert!(
            failed && stale,
            "{verdict:?} {controls:?}: {:?}",
            tally.failures
        );
    }
    // Another check under clang, its controls reading as the row's do, is not the row's.
    let drivers = vec![synthetic_driver_of(Only::Clang)];
    let mut tally = Tally::default();
    let other = Reading {
        controls: kept(),
        ..synthetic_reading("no-strict-overflow", Verdict::ProbeInvalid)
    };
    judge_plain(
        &[job_under(Only::Clang, "__OPTIMIZE__", None)],
        &[Ok(Outcome::Readings(vec![other]))],
        &drivers,
        &mut tally,
    );
    assert!(
        tally
            .failures
            .iter()
            .any(|f| f.contains("the plain run reads no-strict-overflow ")),
        "{:?}",
        tally.failures
    );
    assert!(tally.undiscriminated_met.is_empty());
}

#[test]
fn the_judges_hold_a_triple_to_its_row() {
    let read = |check, verdict, level: &str, rule: &str| Reading {
        check,
        verdict,
        level: level.to_owned(),
        rule: rule.to_owned(),
        controls: None,
    };
    let off = |check| read(check, Verdict::Off, "null", "");
    // A triple read as its plain run: unnamed through `-D`, named through `CPATH`.
    let (tally, failures) = judged("__CET__", "-D", off("cet-macro"), off("cet-macro"));
    assert!(
        failures
            .iter()
            .any(|f| f.contains("__CET__ -D: every reading is its state's plain run")),
        "{failures:?}"
    );
    // Rows that meet nothing here are stale, a row of another architecture is not judged here,
    // and a row of the other family is not either.
    for stale in [
        "MEASURES_NOTHING's row for _GLIBCXX_ASSERTIONS under gcc and clang names nothing fed",
        "HARNESS_ROUTES' row for __clang__ under gcc declared no reading here",
    ] {
        assert!(
            tally.failures.iter().any(|f| f.starts_with(stale)),
            "{stale}: {:?}",
            tally.failures
        );
    }
    for absent in ["row for __CET__", "row for __FreeBSD__ under clang"] {
        assert!(
            !tally.failures.iter().any(|f| f.contains(absent)),
            "{absent}: {:?}",
            tally.failures
        );
    }
    let effective = off("fortify-effective");
    let (_, failures) = judged(
        "_USE_FORTIFY_LEVEL",
        "CPATH shadow define",
        effective.clone(),
        effective.clone(),
    );
    assert!(failures.is_empty(), "{failures:?}");
    // The same named triple earning a reading fails, so the row is narrowed.
    let withheld = read(
        "fortify-effective",
        Verdict::Indeterminate,
        "null",
        "macro-supplied-by-profile",
    );
    let (_, failures) = judged(
        "_USE_FORTIFY_LEVEL",
        "CPATH shadow define",
        effective,
        withheld,
    );
    assert!(
        failures.iter().any(|f| f.contains("narrow the row")),
        "{failures:?}"
    );
    // A driver and macro whose routes none fed: `__ARM_FEATURE_BTI_DEFAULT` on `x86_64` is named
    // by a row of every spelling; `__PIE__` is not, and fails.
    let arm = "__ARM_FEATURE_BTI_DEFAULT";
    for (name, outcome, fails) in [
        (arm, Outcome::Broken("error".to_owned()), false),
        ("__PIE__", Outcome::Inert, true),
    ] {
        let drivers = synthetic_driver();
        let mut tally = Tally::default();
        let route = job_of(name, Some("-D"));
        judge_route(&route, &drivers, &Ok(outcome), &Plain::new(), &mut tally);
        judge_triples(&mut tally, &drivers);
        let unfed = tally
            .failures
            .iter()
            .any(|f| f.starts_with(&format!("gcc {name}: no route was fed")));
        assert_eq!(unfed, fails, "{name}: {:?}", tally.failures);
        let stale = tally
            .failures
            .iter()
            .any(|f| f.contains(&format!("row for {arm},")));
        assert_eq!(stale, name != arm, "{name}: {:?}", tally.failures);
    }
}

#[test]
fn every_unmoved_and_harness_row_names_what_the_table_holds() {
    let listed: BTreeSet<String> = macros().into_iter().map(|(m, _)| m).collect();
    let spelled = |only: Only, id: &str| {
        SPELLINGS
            .iter()
            .any(|s| s.id == id && (only == Only::Any || applies(s, only)))
    };
    for row in MEASURES_NOTHING {
        for name in row.names {
            assert!(listed.contains(*name), "{name} is on no list");
        }
        for id in row.spellings.unwrap_or(&[]) {
            assert!(
                spelled(row.only, id),
                "{id} is no spelling under {:?}",
                row.only
            );
        }
        if let Arch::On(arches) = row.arch {
            assert!(!arches.is_empty(), "a row of no architecture");
            for a in arches {
                assert!(
                    ARCHES.contains(a),
                    "{a} is no architecture the corpus knows"
                );
            }
        }
        assert!(!row.names.is_empty() && !row.why.is_empty());
    }
    for row in HARNESS_ROUTES {
        for name in row.names.unwrap_or(&[]) {
            assert!(listed.contains(*name), "{name} is on no list");
            for check in row.checks.unwrap_or(&[]) {
                assert!(
                    reached(name).iter().any(|r| r.check == *check),
                    "{name} does not reach {check}"
                );
            }
        }
        for id in row.spellings.unwrap_or(&[]) {
            assert!(
                spelled(row.only, id),
                "{id} is no spelling under {:?}",
                row.only
            );
        }
        assert!(harness_state(row.reads) && !row.why.is_empty());
    }
    for row in UNDISCRIMINATED {
        let check = row.check;
        assert!(
            listed
                .iter()
                .any(|m| reached(m).iter().any(|r| r.check == check)),
            "no listed macro reaches {check}"
        );
        assert!(row.only != Only::Any, "{check}: a row of every family");
        assert!(!row.outcome.is_empty() && !row.cause.is_empty() && !row.why.is_empty());
    }
}

#[test]
fn the_wrapper_adds_its_operation_to_the_measured_build_alone() {
    let source = include_str!("../src/measure.rs");
    for needle in [
        "let qualified = format!(\"{}-{tag}\", probe.id);",
        "&variant_flags(ctx.profile, probe.lang, &[]),\n            \"measured\",\n",
        "probe::LinkMode::Executable => String::new(),",
        "\".so\".to_owned()",
        "probe::LinkMode::Object => \".o\".to_owned(),",
    ] {
        assert!(
            source.contains(needle),
            "measure.rs no longer names the measured output as the wrapper expects: {needle}"
        );
    }
    let work = common::Work::new("route-corpus", "wrapper-unit");
    let stub = common::executable(&work.dir().join("stub"), "printf '%s\\n' \"$@\"");
    let wrapper = common::executable(
        &work.dir().join("wrapped"),
        &wrapper_body(&stub, "-DCHARD_ROUTE_OP=1"),
    );
    for (output, adds) in [
        ("p-measured", true),
        ("p-measured.o", true),
        ("p-measured.so", true),
        ("p-clean", false),
        ("p-check-pos", false),
        ("p-measured-x", false),
    ] {
        let done = driver_command(&wrapper, &[])
            .args(["-c", "p.c", "-o", output])
            .output()
            .expect("running the wrapper");
        let args = String::from_utf8_lossy(&done.stdout);
        assert_eq!(
            args.lines().any(|l| l == "-DCHARD_ROUTE_OP=1"),
            adds,
            "the wrapper over -o {output} passed {args:?}"
        );
    }
}

#[test]
fn clang_reads_no_c_header_through_the_words_the_table_withholds_from_it() {
    let clang = match driver_command("clang", &[]).arg("--version").output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            missing_driver(
                "clang",
                "route_corpus clang words",
                "no `clang` on PATH, so the words withheld from it are not measured under it",
            );
            return;
        }
        Err(e) => panic!("`clang --version` could not run: {e}"),
        Ok(_) => synthetic_driver_of(Only::Clang),
    };
    let work = common::Work::new("route-corpus", "clang-words");
    let body = "#define CHARD_ROUTE_SHADOWED 1\n";
    let cxx = Dump {
        lang: Lang::Cxx,
        as_measured: false,
    };
    for (layout, reads_c, reads_cxx) in [
        (Layout::Sysroot, true, true),
        (Layout::Isysroot, false, false),
        (Layout::B, false, false),
        (Layout::Prefix, false, false),
        (Layout::GccInstallDir, false, true),
        (Layout::GccToolchain, false, true),
        (Layout::StdlibIsystem, false, true),
        (Layout::CccInstallDir, false, true),
    ] {
        let dir = work.dir().join(format!("{layout:?}"));
        std::fs::create_dir_all(&dir).expect("the layout directory");
        let built = layout_words(layout, &dir, &clang, body).and_then(|words| {
            if matches!(
                layout,
                Layout::GccInstallDir
                    | Layout::GccToolchain
                    | Layout::StdlibIsystem
                    | Layout::CccInstallDir
            ) {
                shadow_the_installation_for_c(&dir, body)?;
            }
            Ok(words)
        });
        let words = match built {
            Ok(words) => words,
            Err(why) => {
                assert!(
                    !required_drivers().iter().any(|d| d == "clang"),
                    "the {layout:?} layout cannot be built ({why}); CHARD_ROUTE_DRIVERS needs clang"
                );
                common::capability_gap(
                    "route_corpus clang words",
                    &format!("the {layout:?} layout cannot be built here: {why}"),
                );
                continue;
            }
        };
        let read = |driver: &str, how: Dump| {
            dumped_value(driver, &words, &[], "CHARD_ROUTE_SHADOWED", &dir, how)
                .unwrap_or_else(|e| panic!("clang under {layout:?} ({words:?}) failed: {e}"))
                .is_some()
        };
        assert_eq!(
            read("clang", C_DUMP),
            reads_c,
            "under {layout:?} ({words:?}) clang's C compile read the shadow: {reads_c} expected"
        );
        if reads_cxx {
            assert!(
                read("clang++", cxx),
                "under {layout:?} ({words:?}) clang's C++ compile did not read the shadow"
            );
        }
    }
}

/// What a driver does with a word the module comment leaves out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Takes {
    /// Accepts it and reads the shadow through it: the control.
    Reads,
    /// Accepts it and reads no shadow through it.
    Unread,
    /// Refuses it, so no compile reads anything through it.
    Refused,
}

/// A label, the words, the environment pairs, and what the driver does with them.
type LeftOut = (&'static str, Vec<String>, Vec<(String, String)>, Takes);

/// The words the module comment leaves out, each with what a driver of `family` does with it,
/// over a shadow at `at` (and `parent`, its directory).
fn left_out_cases(at: &str, parent: &str, family: Only) -> Vec<LeftOut> {
    let words = |w: &[&str]| w.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let pair = |k: &str, v: String| vec![(k.to_owned(), v)];
    let mut cases: Vec<LeftOut> = vec![
        (
            "-isystem (control)",
            words(&["-isystem", at]),
            vec![],
            Takes::Reads,
        ),
        // The environment channel reads a directory, so the variables below are judged by it.
        (
            "CPATH (control)",
            vec![],
            pair("CPATH", at.to_owned()),
            Takes::Reads,
        ),
        // The prefix and operand of clang's `-iwithprefix` below reach a shadow under its sibling.
        (
            "-iwithprefixbefore (control)",
            words(&["-iprefix", parent, "-iwithprefixbefore", "/shadow"]),
            vec![],
            Takes::Reads,
        ),
        (
            "-isystem-after",
            words(&["-isystem-after", at]),
            vec![],
            Takes::Unread,
        ),
        (
            "-c-isystem",
            words(&["-c-isystem", at]),
            vec![],
            Takes::Refused,
        ),
        (
            "SDKROOT",
            vec![],
            pair("SDKROOT", at.to_owned()),
            Takes::Unread,
        ),
        (
            "CCC_ADD_ARGS -I",
            vec![],
            pair("CCC_ADD_ARGS", format!("-I{at}")),
            Takes::Unread,
        ),
        (
            "CCC_ADD_ARGS -D",
            vec![],
            pair("CCC_ADD_ARGS", "-DCHARD_ROUTE_SHADOWED=1".into()),
            Takes::Unread,
        ),
    ];
    if family == Only::Clang {
        cases.push((
            "-iwithprefix",
            words(&["-iprefix", parent, "-iwithprefix", "/shadow"]),
            vec![],
            Takes::Unread,
        ));
    }
    cases
}

#[test]
fn the_words_the_table_leaves_out_reach_no_header() {
    let work = common::Work::new("route-corpus", "left-out");
    let dir = work.dir().to_path_buf();
    let shadow = dir.join("shadow");
    std::fs::create_dir_all(&shadow).expect("the shadow directory");
    let body = "#define CHARD_ROUTE_SHADOWED 1\n";
    std::fs::write(
        shadow.join("stdio.h"),
        format!("#include_next <stdio.h>\n{body}"),
    )
    .expect("the shadow header");
    let at = shadow.display().to_string();
    let parent = dir.display().to_string();
    let mut ran = 0;
    for (driver, cxx, family) in [("gcc", "g++", Only::Gcc), ("clang", "clang++", Only::Clang)] {
        if on_path(driver).is_err() {
            missing_driver(
                driver,
                "route_corpus left-out words",
                &format!("no `{driver}` on PATH, so the words left out are not measured under it"),
            );
            continue;
        }
        let cases = left_out_cases(&at, &parent, family);
        for (label, flags, env, want) in &cases {
            for (program, how) in [
                (driver, C_DUMP),
                (
                    cxx,
                    Dump {
                        lang: Lang::Cxx,
                        as_measured: false,
                    },
                ),
            ] {
                let took =
                    match dumped_value(program, flags, env, "CHARD_ROUTE_SHADOWED", &dir, how) {
                        Err(_) => Takes::Refused,
                        Ok(Some(_)) => Takes::Reads,
                        Ok(None) => Takes::Unread,
                    };
                assert_eq!(
                    took, *want,
                    "{program} under {label} ({flags:?} {env:?}) did not take the word as listed"
                );
                ran += 1;
            }
        }
    }
    if ran == 0 {
        common::refuse(
            "neither gcc nor clang is on PATH",
            "the words the table leaves out reach no header",
        );
    }
}

/// A shadow `stdio.h` in each directory of the GCC installation's mirror under `dir` that a C
/// compile could search: the prefix's `include` and the installation's own `include`.
fn shadow_the_installation_for_c(dir: &Path, body: &str) -> Result<(), String> {
    let install = gcc_installation("clang")?;
    let real = install
        .ancestors()
        .nth(4)
        .ok_or("an installation with no prefix")?;
    let installed = install
        .strip_prefix(real)
        .map_err(|e| e.to_string())?
        .display()
        .to_string();
    let prefix = dir.join("gcc");
    let stdio = real.join("include/stdio.h");
    mirror_with(
        &prefix,
        real,
        "include/stdio.h",
        &format!("#include \"{}\"\n{body}", stdio.display()),
    )?;
    mirror_with(
        &prefix,
        real,
        &format!("{installed}/include/stdio.h"),
        &format!("#include_next <stdio.h>\n{body}"),
    )
}

/// The frame's count line starts with the table name `make test` hands the ledger.
#[test]
fn the_frame_is_the_table_the_ledger_requires() {
    // The ledger keys each line by the test binary's name, this file's stem, and the count
    // line's table by its prefix; the two are one word.
    assert_eq!(
        Path::new(file!()).file_stem().and_then(|s| s.to_str()),
        Some(FRAME_TABLE),
        "the frame's table is not the test binary the ledger names"
    );
    let makefile = include_str!("../Makefile");
    assert!(
        makefile.contains(&format!("--require {FRAME_TABLE} ")),
        "make test does not require the corpus's table {FRAME_TABLE}"
    );
    // `make test` requires both compilers unless told otherwise.
    assert!(
        makefile.contains("\nROUTE_DRIVERS := gcc clang\n")
            && makefile.contains("CHARD_ROUTE_DRIVERS='$(ROUTE_DRIVERS)' $(CARGO) test --locked"),
        "make test does not hand the corpus the compilers it requires (ROUTE_DRIVERS)"
    );
}

/// A spelling only a C++ compile reads is a route of a macro a C++ probe reads, and of no
/// macro only C probes read.
#[test]
fn a_cxx_only_spelling_is_a_route_only_of_a_macro_a_cxx_probe_reads() {
    let cplus = SPELLINGS
        .iter()
        .find(|s| s.id == "CPLUS_INCLUDE_PATH shadow define")
        .expect("the spelling");
    let class = |name: &str| {
        macros()
            .into_iter()
            .find(|(m, _)| m == name)
            .map(|(_, c)| c)
            .expect("a listed macro")
    };
    assert_eq!(
        constructible(cplus, class("__PIE__"), "__PIE__"),
        Err(CXX_UNREAD)
    );
    assert_eq!(
        constructible(cplus, class("_GLIBCXX_ASSERTIONS"), "_GLIBCXX_ASSERTIONS"),
        Ok(())
    );
    assert!(reaches_cxx("_GLIBCXX_ASSERTIONS") && !reaches_cxx("__PIE__"));
}
