// SPDX-License-Identifier: BSD-3-Clause

//! The probe corpus: what chard measures and how it decides.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::compile::BuildRecord;
pub use crate::decode::common::{
    CUT_MARKER, carries_a_cut, cxx_stdlib, parse_self_report, self_report_account,
    self_report_fields, self_report_listing, self_report_malformed,
};
pub(crate) use crate::decode::diag::diag_severity_of;
pub use crate::decode::diag::{DIAG_NEEDLES, DIAG_NEEDLES_EXEMPT, diag_needles};
use crate::decode::diag::{
    detect_bidi_chars, detect_format_security, detect_hardened_warning,
    detect_implicit_fallthrough, detect_implicit_function_declaration, detect_implicit_int,
    detect_incompatible_pointer_types, detect_int_conversion, detect_no_copy_dt_needed,
    detect_pic_shared_link, detect_trampolines, detect_warn_all, detect_warn_conversion,
    detect_warn_extra, detect_warn_format, detect_warn_format_nonliteral,
    detect_warn_sign_conversion,
};
use crate::decode::runtime::{
    detect_auto_var_init, detect_auto_var_init_pattern, detect_bti_enforced, detect_cxx_assertions,
    detect_fortify_percent_n, detect_fortify_runtime, detect_no_delete_null_checks,
    detect_no_strict_aliasing, detect_no_strict_overflow, detect_pac_ret_enforced,
    detect_shadow_stack, detect_stack_clash, detect_stack_exec, detect_strict_flex_arrays,
    detect_strict_flex_arrays_enforced, detect_trapv, detect_zero_call_used_regs,
    detect_zero_init_padding,
};
use crate::digest;
use crate::elf::{ElfFacts, ElfTable};
use crate::predicate::{self, Evaluation, Incomplete, Live, Predicate, elf_static, macro_channel};
use crate::run::RunRecord;

/// Shared header, written into the work directory beside every probe source.
pub const SELFREPORT_HEADER: &str = include_str!("../probes/chard_selfreport.h");
pub const SELFREPORT_HEADER_NAME: &str = "chard_selfreport.h";

/// `chard_schema` in `chard probes --format json`: the major version of the listing's shape,
/// under the rule the CLI's contract states. The listing has no schema file; its shape is
/// `corpus_listing`'s in `main.rs`.
pub const LISTING_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Channel {
    Macro,
    ElfStatic,
    Runtime,
    CompilerDiag,
}

impl Channel {
    /// Every channel, for the tests that hold a property to each.
    pub const ALL: [Self; 4] = [
        Self::Macro,
        Self::ElfStatic,
        Self::Runtime,
        Self::CompilerDiag,
    ];

    /// The name a report carries for the channel, as `serde` spells it (`kebab-case`), for
    /// prose that names a channel beside the JSON that records it;
    /// `channel_names_match_the_report` holds the two spellings together.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Macro => "macro",
            Self::ElfStatic => "elf-static",
            Self::Runtime => "runtime",
            Self::CompilerDiag => "compiler-diag",
        }
    }

    /// Whether an artifact must be produced for this channel.
    pub fn needs_build(self) -> bool {
        !matches!(self, Self::Macro)
    }

    /// Whether the artifact must be executed.
    pub fn needs_run(self) -> bool {
        matches!(self, Self::Runtime)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Polarity {
    /// Presence is good: a hardening mechanism is active.
    Harden,
    /// Presence is bad: a `DT_RPATH` or `DT_RUNPATH` entry, a text relocation.
    Weaken,
}

impl Polarity {
    /// Every value, for a walk over the whole enumeration.
    pub const ALL: [Self; 2] = [Self::Harden, Self::Weaken];
}

/// What a check's `on` is evidence of, toward the defect classes it bears on: the protection
/// itself, a request for it, or a marking that asks an enforcer outside the artifact for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Observes {
    /// The mechanism itself, in the artifact or at run time, or its producer's own word for
    /// its state.
    Protection,
    /// A macro the build supplied to ask a library or the compiler for the mechanism.
    Request,
    /// A property note, landing pad or compiler macro for a control-flow mechanism a CPU
    /// enforces, whose enforcement this check does not observe.
    Marking,
}

impl Observes {
    /// Every value, for the schema's pin.
    pub const ALL: [Self; 3] = [Self::Protection, Self::Request, Self::Marking];

    /// The name a report carries, as `serde` spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protection => "protection",
            Self::Request => "request",
            Self::Marking => "marking",
        }
    }
}

/// How directly the check's observable establishes the protection, decided when the check
/// is written rather than per run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    C,
    #[serde(rename = "c++")]
    Cxx,
}

impl Lang {
    /// The suffix a source file chard writes in this language carries, without the dot:
    /// the drivers choose the language from it. `clang++` warns on a C++ source named `.c`
    /// (`-Wdeprecated`), which a profile's `-Werror` turns into a failed build, so a macro
    /// dump through the C++ driver is named by this. Every probe's own source carries its
    /// language's suffix, held by a test over the corpus.
    #[must_use]
    pub const fn source_suffix(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cxx => "cpp",
        }
    }
}

/// What the probe links to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkMode {
    Executable,
    SharedObject,
    /// Compiled and not linked, so the artifact is what the *compiler* produced.
    Object,
    /// A shared object linked from code compiled exactly as the flags ask: `-shared` is
    /// added and no position-independence choice is made or dropped.
    SharedObjectAsCompiled,
}

impl LinkMode {
    /// Flags the driver must add to produce this output kind, given what it was already
    /// asked to compile with: the output kind's word first, then [`Self::compile_flags`].
    pub fn extra_flags(self, already: &[String]) -> Vec<&'static str> {
        let mut out = match self {
            Self::Executable => Vec::new(),
            Self::Object => vec!["-c"],
            Self::SharedObjectAsCompiled | Self::SharedObject => vec!["-shared"],
        };
        out.extend(self.compile_flags(already));
        out
    }

    /// The words of [`Self::extra_flags`] the compile reads, which a probe's macro dump
    /// carries beside the build's flags (`measure::Driver::gather_with`): `-fPIC` where it
    /// is added, which defines `__PIC__`. The output kind's word (`-c`, `-shared`) is the
    /// link's and is left out of the dump: the preprocessor reads nothing from it, and
    /// clang under `-Werror` refuses a `-dM -E` job that carries it as an unused argument
    /// (clang 22.1.8 on Fedora 44 x86_64; gcc 16.2.1 takes either and defines the same
    /// macros).
    pub fn compile_flags(self, already: &[String]) -> Vec<&'static str> {
        match self {
            Self::SharedObject if !Self::states_a_pic_choice(already) => vec!["-fPIC"],
            _ => Vec::new(),
        }
    }

    /// Whether `flags` state a position-independence choice ([`Self::is_pic_choice`]),
    /// walked by the one classifier (`toolchain::read`), so a value another word takes
    /// (`-MF -fno-pie`, a dependency file) or a word handed to a tool (`-Xlinker -fPIC`) is
    /// no choice of the compile's.
    fn states_a_pic_choice(flags: &[String]) -> bool {
        use crate::toolchain::{Hand, read};
        let mut i = 0;
        while let Some(word) = flags.get(i) {
            let reading = read(word, flags.get(i.saturating_add(1)).map(String::as_str));
            if reading.hand == Hand::Driver
                && reading.span() == 1
                && Self::is_pic_choice(&reading.word)
            {
                return true;
            }
            i = i.saturating_add(reading.own_words_span());
        }
        false
    }

    /// Whether a flag states a position-independence choice for code generation, in any
    /// of its spellings: each means the caller has decided, so chard must not decide again.
    fn is_pic_choice(flag: &str) -> bool {
        // The flag as gcc reads it: `--no-pie` is `-fno-pie`, `--PIC` is `-fPIC`
        // (`toolchain::LONG_ALIASES`, its generic map).
        let flag = crate::toolchain::spelled_alone(flag);
        matches!(
            &*flag,
            "-fPIC"
                | "-fpic"
                | "-fno-pic"
                | "-fno-PIC"
                | "-fPIE"
                | "-fpie"
                | "-fno-pie"
                | "-fno-PIE"
        )
    }

    /// Whether an incoming profile flag has to be dropped for this output kind.
    pub fn conflicts_with(self, flag: &str) -> bool {
        match self {
            Self::Executable => false,
            // Nothing reaches a linker here, so a linker flag in the profile would be
            // passed to a compile-only invocation that has no use for it.
            Self::Object => {
                [
                    "-Wl,",
                    "-fuse-ld=",
                    "--ld-path=",
                    "--for-linker=",
                    "-L",
                    "-z",
                    "-l",
                    "-T",
                ]
                .iter()
                .any(|prefix| flag.starts_with(prefix))
                    || (flag.starts_with("-u") && flag != "-undef")
                    || matches!(
                        flag,
                        "-pie"
                            | "-no-pie"
                            | "-shared"
                            | "-static-pie"
                            | "-rdynamic"
                            | "-s"
                            | "-r"
                            | "-static-libgcc"
                            | "-static-libstdc++"
                            | "-shared-libgcc"
                            | "-nostartfiles"
                            | "-nolibc"
                            | "-Xlinker"
                            | "-e"
                            | "-rpath"
                    )
            }
            Self::SharedObject => {
                matches!(
                    flag,
                    "-pie" | "-no-pie" | "-fPIE" | "-fpie" | "-fno-PIE" | "-fno-pie"
                ) || self.joined_linker_arg_conflicts(flag)
            }
            // The code generation is the subject, so only the output kind is resolved.
            Self::SharedObjectAsCompiled => {
                matches!(flag, "-pie" | "-no-pie") || self.joined_linker_arg_conflicts(flag)
            }
        }
    }

    /// Whether a one-token linker pass-through, `-Wl,<arg>` or `--for-linker=<arg>`, hands
    /// the linker an output kind this mode contradicts ([`Self::linker_arg_conflicts`]).
    fn joined_linker_arg_conflicts(self, flag: &str) -> bool {
        flag.strip_prefix("-Wl,")
            .or_else(|| flag.strip_prefix("--for-linker="))
            .is_some_and(|arg| self.linker_arg_conflicts(arg))
    }

    /// Whether a token the driver passes straight to the linker contradicts this output
    /// kind. Only the shared-object modes have one: `-pie` and `-no-pie` cannot share a
    /// link with `-shared`, as their driver spellings cannot in [`Self::conflicts_with`].
    fn linker_arg_conflicts(self, arg: &str) -> bool {
        match self {
            Self::Executable | Self::Object => false,
            Self::SharedObject | Self::SharedObjectAsCompiled => {
                matches!(arg, "-pie" | "-no-pie")
            }
        }
    }

    /// Splits a profile's flags into the ones this output kind compiles with and the ones
    /// it drops, in order.
    pub fn partition_flags(self, flags: &[String]) -> (Vec<String>, Vec<String>) {
        use crate::toolchain::{Hand, read};
        let mut kept = Vec::new();
        let mut dropped = Vec::new();
        let mut i = 0;
        while let Some(flag) = flags.get(i) {
            let reading = read(flag, flags.get(i.saturating_add(1)).map(String::as_str));
            let end = i.saturating_add(reading.span());
            // The span reaches past the list only where no next word exists, which `read`
            // never says; the word alone is the whole unit either way.
            let Some(words) = flags
                .get(i..end)
                .or_else(|| flags.get(i..i.saturating_add(1)))
            else {
                break;
            };
            let argument = words.get(1).map(String::as_str);
            let side = if reading.hand == Hand::Tool && reading.word == "-Xlinker" {
                // `-Xlinker <arg>`, `--for-linker <arg>` and gcc's abbreviations of it: the
                // pair goes with the argument's verdict, under every output kind.
                if (self == Self::Object) || argument.is_some_and(|a| self.linker_arg_conflicts(a))
                {
                    &mut dropped
                } else {
                    &mut kept
                }
            } else if self.conflicts_with(&reading.word) {
                &mut dropped
            } else if reading.hand == Hand::Arch
                && argument
                    .is_some_and(|a| self.conflicts_with(&crate::toolchain::spelled_alone(a)))
            {
                // The word clang applies for one architecture goes with its carrier, as
                // the driver's own word would alone.
                &mut dropped
            } else {
                &mut kept
            };
            side.extend(words.iter().cloned());
            i = end;
        }
        (kept, dropped)
    }
}

/// Why a check may be inapplicable here. A gate's verdict is a different claim from
/// `off`: `-mbranch-protection` does not exist on x86_64, and reporting that as "off"
/// would read as a distro choice rather than a hard limitation.
#[derive(Clone, Copy, Debug)]
pub struct Gate {
    /// Architectures the check applies to; empty means portable.
    pub arch: &'static [&'static str],
    /// libc implementations that are not *known* to support the flag.
    pub libc_unsupported: &'static [&'static str],
    /// Compiler families that cannot support the flag, by [`crate::toolchain::Kind`]
    /// name, `"gcc"`, `"clang"`.
    pub compiler_unsupported: &'static [&'static str],
    /// C++ standard libraries whose runtime cannot express this check's observable.
    pub cxx_stdlib_unsupported: &'static [&'static str],
    /// Verdict depends on kernel policy, so it is read only where whose kernel the run's
    /// is was established, the operator's `--execution host` or `vm`: under a container
    /// the kernel is the host's, and `host` by default settles nothing
    /// ([`crate::env::KernelAttribution`]).
    pub needs_vm: bool,
}

pub const PORTABLE: Gate = Gate {
    arch: &[],
    libc_unsupported: &[],
    compiler_unsupported: &[],
    cxx_stdlib_unsupported: &[],
    needs_vm: false,
};

/// A positive control that differs by target architecture: the flags the positive arm is
/// built with on `arch`, in place of [`Check::positive`].
#[derive(Debug)]
pub struct ArchControl {
    pub check: &'static str,
    pub arch: &'static str,
    pub positive: &'static [&'static str],
}

/// Every per-architecture positive control. See [`ArchControl`].
pub const ARCH_CONTROLS: &[ArchControl] = &[ArchControl {
    check: "textrel-absent",
    // No code model: `-m32` has no `-mcmodel=large` to give, and none is needed, since
    // i386's absolute relocation (`R_386_32`) is what a non-PIC reference already emits.
    arch: "x86",
    positive: &["-fno-pic", "-Wl,-z,notext"],
}];

/// A source the positive arm of one check links after the probe's own, and that no other
/// build is handed: not the measured build, not the clean build, not the negative or regime
/// arm, not another check's arm.
#[derive(Debug)]
pub struct PositiveInput {
    pub check: &'static str,
    /// The input's file name in the work directory, distinct from every probe's and
    /// auxiliary library's source name, so writing it overwrites no other source.
    pub source_name: &'static str,
    pub source: &'static str,
}

/// Every positive arm's own input. See [`PositiveInput`].
pub const POSITIVE_INPUTS: &[PositiveInput] = &[PositiveInput {
    check: "rwx-segment-absent",
    source_name: "rwx_segment.c",
    source: include_str!("../probes/rwx_segment.c"),
}];

/// A defect class a flag bears on.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Defect {
    pub id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<&'static str>,
    pub summary: &'static str,
}

pub const DEFECTS: &[Defect] = &[
    Defect {
        id: "stack-buffer-overflow",
        cwe: Some("CWE-121"),
        summary: "A write past the end of a stack buffer.",
    },
    Defect {
        id: "heap-buffer-overflow",
        cwe: Some("CWE-122"),
        summary: "A write past the end of a heap allocation.",
    },
    Defect {
        id: "uninitialized-read",
        cwe: Some("CWE-457"),
        summary: "Reading an automatic variable that was never assigned.",
    },
    Defect {
        id: "format-string",
        cwe: Some("CWE-134"),
        summary: "An attacker-influenced format string.",
    },
    Defect {
        id: "integer-overflow",
        cwe: Some("CWE-190"),
        summary: "Arithmetic that wraps or is assumed not to, typically producing an \
                  undersized allocation or a bypassed bounds check.",
    },
    Defect {
        id: "null-deref",
        cwe: Some("CWE-476"),
        summary: "A null pointer dereference the optimizer created by deleting a check it was entitled to assume redundant.",
    },
    Defect {
        id: "library-injection",
        cwe: Some("CWE-427"),
        summary: "Loading code from a path an attacker can influence, via a search path \
                  baked into the binary or a dlopen that should not have been possible.",
    },
    Defect {
        id: "return-oriented-programming",
        cwe: None,
        summary: "Chaining existing return sequences to execute attacker-chosen behaviour without injecting code.",
    },
    Defect {
        id: "jump-oriented-programming",
        cwe: None,
        summary: "The indirect-branch equivalent of ROP.",
    },
    Defect {
        id: "got-overwrite",
        cwe: None,
        summary: "Overwriting a relocation table entry that stays writable after startup.",
    },
    Defect {
        id: "stack-code-execution",
        cwe: None,
        summary: "Executing data written to the stack.",
    },
    Defect {
        id: "stack-clash",
        cwe: None,
        summary: "Growing the stack past its guard region into an adjacent mapping by \
                  allocating a frame larger than one page without touching it.",
    },
    Defect {
        id: "address-layout-disclosure",
        cwe: None,
        summary: "Learning where the image is mapped.",
    },
    Defect {
        id: "optimizer-exploited-ub",
        cwe: Some("CWE-1038"),
        summary: "The compiler removed or altered code.",
    },
    Defect {
        id: "undeclared-call-mismatch",
        cwe: Some("CWE-628"),
        summary: "Calling a function with no declaration in scope.",
    },
];

/// Look a defect class up by id.
pub fn defect(id: &str) -> Option<&'static Defect> {
    DEFECTS.iter().find(|d| d.id == id)
}

/// Why a check exists, and where the argument about it happened.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Reference {
    pub kind: ReferenceKind,
    pub title: &'static str,
    pub url: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReferenceKind {
    /// The OpenSSF guide section recommending the flag.
    Guide,
    /// A distribution's own tracker: where the adoption was argued.
    Discussion,
    /// An incident the flag bears on.
    Incident,
    /// Neighbouring work.
    RelatedWork,
}

const GUIDE: Reference = Reference {
    kind: ReferenceKind::Guide,
    title: "OpenSSF Compiler Options Hardening Guide for C and C++",
    url: "https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html",
};

const ALPINE_TSC_64: Reference = Reference {
    kind: ReferenceKind::Discussion,
    title: "Alpine TSC #64: CET support and general compiler-based hardening",
    url: "https://gitlab.alpinelinux.org/alpine/tsc/-/work_items/64",
};

const MUSL_CET_PATCHSET: Reference = Reference {
    kind: ReferenceKind::Discussion,
    title: "musl: CET support patchset",
    url: "https://inbox.vuxu.org/musl/20201019224342.53303-1-joao.moreira@intel.com/T/",
};

const RSYNC_HARDENING: Reference = Reference {
    kind: ReferenceKind::Incident,
    title: "CVE-2024-12085 disclosure chained into CVE-2024-12084",
    url: "https://www.chainguard.dev/unchained/mitigating-a-rsync-vulnerability-a-lesson-in-compiler-hardening",
};

const FLAGS_DISTRO_TABLE: Reference = Reference {
    kind: ReferenceKind::RelatedWork,
    title: "jvoisin/compiler-flags-distro",
    url: "https://github.com/jvoisin/compiler-flags-distro",
};

/// What a detector concluded. Three outcomes, not two: an observable that is
/// neither clearly present nor clearly absent must stay `Indeterminate` rather
/// than defaulting to absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Present,
    Absent,
    Indeterminate,
}

impl Outcome {
    /// The one spelling: `report`, `fixture` and the schema's vocabulary list take the
    /// name from here rather than keeping a copy.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug)]
pub struct Detection {
    pub outcome: Outcome,
    /// Which level is active, for graded mechanisms.
    pub level: Option<String>,
    /// Compact statement of what was actually seen; lands in `evidence`.
    pub observed: String,
    /// The gating rule the detector withheld under, where it withheld for a reason the
    /// table names (`Self::withheld`): `measure::settle` publishes it as the observation's
    /// `gating` where the triple discriminated. `None` for every other reading; an
    /// `indeterminate` whose reason is `observed` alone is one of those, and
    /// `coverage.withholding` counts it under `no_named_cause`.
    pub rule: Option<crate::report::gating_rule::DetectorRule>,
}

impl Detection {
    pub(crate) fn present(level: Option<&str>, observed: String) -> Self {
        Self {
            outcome: Outcome::Present,
            level: level.map(ToOwned::to_owned),
            observed,
            rule: None,
        }
    }

    pub(crate) fn absent(observed: String) -> Self {
        Self {
            outcome: Outcome::Absent,
            level: None,
            observed,
            rule: None,
        }
    }

    pub(crate) fn indeterminate(observed: String) -> Self {
        Self {
            outcome: Outcome::Indeterminate,
            level: None,
            observed,
            rule: None,
        }
    }

    /// An `indeterminate` the detector withholds under `rule`, with `observed` as the
    /// reason the published gating carries. The rule is a
    /// [`crate::report::gating_rule::DetectorRule`], a row of the table at
    /// [`crate::report::gating_rule::Stage::Detector`] by construction, so a detector cannot
    /// hand `settle` a rule the ladder consults elsewhere.
    pub(crate) fn withheld(
        rule: crate::report::gating_rule::DetectorRule,
        observed: String,
    ) -> Self {
        Self {
            outcome: Outcome::Indeterminate,
            level: None,
            observed,
            rule: Some(rule),
        }
    }
}

/// Everything a detector may inspect. Which fields are populated follows from
/// the check's channel; the driver never invokes a detector whose required
/// evidence is missing; a failed build becomes `build-failed`, not `off`.
#[derive(Debug)]
pub struct Evidence<'a> {
    pub macros: &'a BTreeMap<String, String>,
    pub elf: Option<&'a ElfFacts>,
    pub build: Option<&'a BuildRecord>,
    pub run: Option<&'a RunRecord>,
    /// The work directory the records were captured under, which a quoted excerpt is made
    /// relative to before it is cut ([`Self::published`]). `None` where the records are
    /// already the published copies (a replay, a fixture) or carry no path.
    pub workdir: Option<&'a std::path::Path>,
}

impl Evidence<'_> {
    /// `text` as the report will publish it: the rewrite `measure::publish` applies to an
    /// observation's copies, applied here so that a detector cuts the text a reader sees.
    #[must_use]
    pub fn published(&self, text: &str) -> String {
        crate::measure::publish_text(text, self.workdir.unwrap_or(std::path::Path::new("")))
    }
}

/// A check's level vocabulary, declared on the check so that no two checks' words are ever
/// compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Levels {
    /// The detector never reports a level.
    None,
    /// The detector reports one of these words as information; nothing is graded against it.
    Informational(&'static [&'static str]),
    /// Graded against the guide's ask on this check's own scale.
    Graded(Grade),
}

/// A scale and the guide's ask on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grade {
    pub scale: Scale,
    /// The word the guide asks for; a word on `scale`, which
    /// `every_graded_check_recommends_a_word_on_its_own_scale` holds.
    pub recommended: &'static str,
    /// Words the detector may report that sit on no rung of `scale`: a selection the
    /// mechanism made, published as the level and earning `on`, that is not comparable with
    /// the ask. [`Grade::meets`] does not know them, so they grade `Grading::Ungraded` rather
    /// than `OffScale`; `Levels::admits` does. Empty on every scale but `SSP_LEVELS`. Never a
    /// word of `scale`, which `every_graded_check_recommends_a_word_on_its_own_scale` holds.
    pub ungraded: &'static [&'static str],
}

/// How the words on a scale relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scale {
    /// Rungs in ascending strength; a rung meets the ask when it sits at or above the
    /// ask's rung.
    Ordered(&'static [&'static str]),
    /// Named readings with no order among them: the components of a bitmask, a fill kind.
    /// Only the ask's own word meets it.
    Named(&'static [&'static str]),
    /// Whole numbers, compared as numbers: a reading meets the ask when it is at least the
    /// ask. The words are every spelling of a `u32`, so [`Scale::words`] is empty and a
    /// reading that does not parse as one (a negative number, a name) is off the scale.
    /// `_FORTIFY_SOURCE` is the case: glibc's `<features.h>` treats a request above 3 as
    /// 3, so a request of `4` meets an ask of `3`.
    Numeric,
}

impl Scale {
    /// The finite words of the scale; empty for [`Scale::Numeric`], whose words are
    /// numbers. [`Levels::admits`] is the question to ask about one word.
    #[must_use]
    pub const fn words(&self) -> &'static [&'static str] {
        match self {
            Self::Ordered(words) | Self::Named(words) => words,
            Self::Numeric => &[],
        }
    }

    /// `ordered`, `named` or `numeric`, for the fingerprint and the corpus listing.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Ordered(_) => "ordered",
            Self::Named(_) => "named",
            Self::Numeric => "numeric",
        }
    }

    /// The scale as a reader sees it in a reason: `1 < 2 < 3`, `branch, return, full`, or
    /// `a whole number`.
    #[must_use]
    pub fn spelled(&self) -> String {
        match self {
            Self::Ordered(words) => words.join(" < "),
            Self::Named(words) => words.join(", "),
            Self::Numeric => "a whole number".to_owned(),
        }
    }
}

impl Grade {
    /// Does `actual` meet the ask? `None` when `actual` is not a word on this scale,
    /// which is a reading the grade cannot take: neither `on` nor `partial` is earned by
    /// a word the scale does not know.
    #[must_use]
    pub fn meets(&self, actual: &str) -> Option<bool> {
        match self.scale {
            Scale::Ordered(words) => {
                let position = words.iter().position(|w| *w == actual)?;
                let ask = words.iter().position(|w| *w == self.recommended)?;
                Some(position >= ask)
            }
            Scale::Named(words) => words.contains(&actual).then(|| actual == self.recommended),
            Scale::Numeric => {
                let reading: u32 = actual.parse().ok()?;
                let ask: u32 = self.recommended.parse().ok()?;
                Some(reading >= ask)
            }
        }
    }
}

impl Levels {
    /// Every word the detector may report, in the order the scale declares them.
    #[must_use]
    pub const fn words(&self) -> &'static [&'static str] {
        match self {
            Self::None => &[],
            Self::Informational(words) => words,
            Self::Graded(grade) => grade.scale.words(),
        }
    }

    /// May the detector report `word`? The finite vocabularies answer by membership and a
    /// numeric scale by parsing, and a graded scale admits its ungraded words too, so this
    /// is the question to ask about an archived level rather than [`Levels::words`].
    #[must_use]
    pub fn admits(&self, word: &str) -> bool {
        match self {
            Self::None => false,
            Self::Informational(words) => words.contains(&word),
            Self::Graded(grade) => grade.meets(word).is_some() || grade.ungraded.contains(&word),
        }
    }

    /// The words a graded check may report that sit on no rung of its scale
    /// ([`Grade::ungraded`]); empty elsewhere.
    #[must_use]
    pub const fn ungraded(&self) -> &'static [&'static str] {
        match self {
            Self::Graded(grade) => grade.ungraded,
            Self::None | Self::Informational(_) => &[],
        }
    }

    #[must_use]
    pub const fn grade(&self) -> Option<&Grade> {
        match self {
            Self::Graded(grade) => Some(grade),
            Self::None | Self::Informational(_) => None,
        }
    }

    /// The guide's ask, where the check is graded. This is what
    /// `observations[].recommended_level` carries.
    #[must_use]
    pub const fn recommended(&self) -> Option<&'static str> {
        match self.grade() {
            Some(grade) => Some(grade.recommended),
            None => None,
        }
    }

    /// `none`, `informational` or `graded`, for the fingerprint and the corpus listing.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Informational(_) => "informational",
            Self::Graded(_) => "graded",
        }
    }
}

/// gcc's `-fstack-protector-explicit`, `-fstack-protector`, `-strong`, `-all`:
/// `__SSP_EXPLICIT__`, `__SSP__`, `__SSP_STRONG__`, `__SSP_ALL__`. Each rung's protected set
/// contains the one below it, `explicit`'s being the functions marked
/// `__attribute__((stack_protect))`, which gcc instruments at every level;
/// `predicate::macro_channel`'s `SSP_LEVEL` has the measurement.
pub const SSP_LEVELS: Levels = Levels::Graded(SSP_GRADE);

/// The grade of [`SSP_LEVELS`] on its own, for `composite::ssp_constituent` to hold the
/// level `ssp-level-emitted` published to the ask without unwrapping the enumeration.
pub const SSP_GRADE: Grade = Grade {
    scale: Scale::Ordered(&["explicit", "basic", "strong", "all"]),
    recommended: "strong",
    ungraded: &[SSP_UNSAFE_FRAME],
};

/// The one ungraded word of [`SSP_LEVELS`]; its doc comment says what it is.
pub const SSP_UNSAFE_FRAME: &str = "unsafe-frame";

/// `_FORTIFY_SOURCE` as a number: the request as asked and the level the C library
/// settled. A request of `4` meets the ask of `3` and publishes `on` at its own number,
/// which is what glibc's `<features.h>` makes of it; `fortify-effective` reports what was
/// settled beside it. A request that is not a whole number is off the scale.
pub const FORTIFY_LEVELS: Levels = Levels::Graded(Grade {
    scale: Scale::Numeric,
    recommended: "3",
    ungraded: &[],
});

/// RELRO as `elf.rs` classifies it: `partial` is the segment alone, `full` the segment
/// with `BIND_NOW`.
pub const RELRO_LEVELS: Levels = Levels::Graded(Grade {
    scale: Scale::Ordered(&["partial", "full"]),
    recommended: "full",
    ungraded: &[],
});

/// `-fstrict-flex-arrays=` levels, read from which trailing-array spellings the compiler
/// bounded; the detector reports `1`, `2` or `3`, and the flag's levels are numbers.
pub const FLEX_ARRAY_LEVELS: Levels = Levels::Graded(Grade {
    scale: Scale::Numeric,
    recommended: "3",
    ungraded: &[],
});

/// The two control-flow-integrity components and their union, as the CET and
/// branch-protection checks read them: `branch` is IBT or BTI alone, `return` the shadow
/// stack or PAC alone, `full` both. Named rather than ordered: the two components are
/// independent bits, and the guide asks for both.
pub const CFI_COMPONENTS: Levels = Levels::Graded(Grade {
    scale: Scale::Named(&["branch", "return", "full"]),
    recommended: "full",
    ungraded: &[],
});

/// `-ftrivial-auto-var-init=` fill kinds. Named: `pattern` is a different choice from
/// `zero`, and the guide asks for `zero`, so `pattern` is `partial` against it.
pub const AUTO_VAR_FILL: Levels = Levels::Graded(Grade {
    scale: Scale::Named(&["zero", "pattern"]),
    recommended: "zero",
    ungraded: &[],
});

/// What `-fzero-call-used-regs` cleared before a return: `arg` is the argument registers
/// alone, which the `-arg` forms clear, and `gpr` is every general-purpose register the
/// function used, which `=used-gpr` (the guide's ask), `=used`, `=all-gpr` and `=all` clear.
/// Ordered, since the second set contains the first. Nothing on the scale separates `=all`
/// from `=used-gpr`; `zero_call_used_regs.c` says why the register that would is not read.
pub const ZERO_CALL_USED_REGS: Levels = Levels::Graded(Grade {
    scale: Scale::Ordered(&["arg", "gpr"]),
    recommended: "gpr",
    ungraded: &[],
});

/// The `-Werror=` checks: their detectors report `error` or nothing, so the scale has one
/// word and `partial` is unreachable on it. A diagnosis at warning strength is `absent`,
/// which the detector's own comment explains.
pub const DIAG_ERROR: Levels = Levels::Graded(Grade {
    scale: Scale::Named(&["error"]),
    recommended: "error",
    ungraded: &[],
});

/// Where the x86 shadow stack was enforced for a program the toolchain built: `opt-in` only
/// under glibc's tunable, which chard pins for the run, and `default` without it as well,
/// what a deployment that sets nothing gets. Ordered, since enforcement without the opt-in
/// holds with it. The ask is `default`, so upstream glibc 2.39 and later, which leave the
/// shadow stack off without the tunable, read `partial` at `opt-in` and never `on`:
/// `shadow_stack.c` carries the second run that reads it.
pub const SHADOW_STACK_DEFAULT: Levels = Levels::Graded(Grade {
    scale: Scale::Ordered(&["opt-in", "default"]),
    recommended: "default",
    ungraded: &[],
});

/// `__PIE__` and `__PIC__` values: `1` for the small code model, `2` for the large. A code
/// model selector, published beside the verdict and graded against nothing; the test
/// `a_small_code_model_pie_is_on_and_its_value_is_information_only` records why.
pub const CODE_MODEL: Levels = Levels::Informational(&["1", "2"]);

/// The artifact's PIE reading. One word, naming the ELF flavour rather than a grade, so
/// nothing is graded against it and `partial` is unreachable on it.
pub const PIE_FLAVOUR: Levels = Levels::Informational(&["pie"]);

/// Which dynamic tag the `rpath-absent` predicate found.
pub const SEARCH_PATH_KIND: Levels = Levels::Informational(&["rpath", "runpath"]);

/// The `textrel-absent` predicate's one word.
pub const TEXTREL_WORD: Levels = Levels::Informational(&["textrel"]);

/// The severity a `diag_presence` check saw on the diagnostic's own line. Presence is what
/// those checks measure; the severity travels as information.
pub const DIAG_SEVERITY: Levels = Levels::Informational(&["warning", "error"]);

/// `detect_auto_var_init_pattern`'s one word.
pub const PATTERN_FILL: Levels = Levels::Informational(&["pattern"]);

/// libc++'s hardening modes, in ascending strength. Informational: libstdc++'s request is
/// a boolean and its detector reports no word, and the guide's ask for libc++ is `fast`,
/// the lowest mode, so a grade against it would have graded nothing. The check's `notes`
/// and `predicate::macro_channel::cxx_hardening_requested` carry the rest.
pub const LIBCPP_MODES: Levels = Levels::Informational(&["fast", "extensive", "debug"]);

/// The trap instruction `ubsan-trap-mode` found: gcc's `ud2` and clang's `ud1` on x86_64,
/// `brk` on aarch64. Which compiler's form appeared, published beside `on` and graded
/// against nothing.
pub const UBSAN_TRAP_INSN: Levels = Levels::Informational(&["ud2", "ud1", "brk"]);

/// Whether a measurement of a check under a profile owes a regime-matched negative arm,
/// and why not where it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime {
    /// The negative control re-run in the measured profile's regime: the profile's flags
    /// followed by these, so that they win. They are the arm's own, not [`Check::negative`]:
    /// the plain negative is profile-free and self-sufficient (a fortify control carries
    /// its own `-O2`), while this arm sits on a profile and needs only the countermand.
    /// So no arm carries an `-O`: one would override the profile's level and build the arm
    /// at another, outside the measured regime; `tests/regime_arms.rs` refuses an arm that
    /// carries an `-O`. Never empty: an arm with nothing appended would re-run the measured
    /// build as its own negative and withhold every `on`.
    Arm(&'static [&'static str]),
    /// No arm is owed: the observable is specific to the flag, by the stated argument.
    NotOwed(Specific),
}

/// Why a check's observable cannot be produced by a profile flag other than its own, and
/// the frame the argument was made in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Specific {
    /// The argument, or the measurement, naming what else the profiles carry and why none
    /// of it reaches the observable, and saying which of the two it is.
    pub reason: &'static str,
    /// The built-in profiles whose flag lists the argument covers, among those that add
    /// flags ([`PROFILES_WITH_FLAGS`]); `bare` is clean and owes no arm to any check.
    pub profiles: &'static [&'static str],
    /// The compiler families the argument was made, or the measurement taken, on
    /// (`toolchain::Kind`'s names).
    pub toolchains: &'static [&'static str],
}

/// The built-in profiles that add flags, and so are the regime a reason has to cover:
/// `bare` is clean and never owes an arm (`measure::Conditions::profile_is_clean`).
pub const PROFILES_WITH_FLAGS: &[&str] = &["bare-optimized", "openssf-tldr"];

/// Both compiler families chard measures, for a reason argued over each.
pub const GCC_AND_CLANG: &[&str] = &["gcc", "clang"];

#[derive(Debug)]
pub struct Check {
    pub id: &'static str,
    /// Canonical flag spelling, used as the matrix key.
    pub flag: &'static str,
    /// How this check's observation is read, and so which channel it is on. See
    /// [`Decoder`].
    pub decoder: Decoder,
    pub polarity: Polarity,
    pub observable: &'static str,
    /// The level vocabulary this check's detector reports in, and the guide's ask on it
    /// where the check is graded. See [`Levels`].
    pub levels: Levels,
    pub confidence: Confidence,
    pub positive: &'static [&'static str],
    pub negative: &'static [&'static str],
    /// Checks sharing this key measure the *same* protection through different
    /// channels and must therefore agree.
    pub corroborates: Option<&'static str>,
    /// Read this check's own observable from the *clean* build rather than the measured
    /// one.
    pub measures_toolchain_default: bool,
    /// Whether a measurement under a profile owes a regime-matched negative arm, with the
    /// arm's flags, or why not. No default: see [`Regime`].
    pub regime: Regime,
    /// Defect classes this check's flag bears on, as ids into [`DEFECTS`]. Empty is
    /// meaningful: it says the flag is not a mitigation (a precondition, a
    /// startup-cost optimization, or a diagnostic).
    pub defects: &'static [&'static str],
    /// What this check's `on` is evidence of toward those defects: the protection, a request
    /// for it, or a marking for an enforcer outside the artifact. See [`Observes`]: only a
    /// check observing protection moves a defect's status in `report::defect_coverage`.
    pub observes: Observes,
    /// **Universal** references only: the guide, a specification, an incident, or
    /// neighbouring work. Every entry is copied into every report unfiltered, so one tied to
    /// a distribution would read as evidence in reports about the others.
    pub references: &'static [Reference],
    pub gate: Gate,
    pub notes: &'static str,
}

/// What a runtime check's reading rests on: the program's own computation, or the
/// machine it ran on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunBasis {
    /// The probe's own output or its C library's diagnostic: an emulator that executes
    /// the instructions answers for it.
    Program,
    /// A fault, a mapping or an enforcement the kernel and the hardware produce: under
    /// user-mode emulation the emulator produces it instead.
    Machine,
}

impl RunBasis {
    /// The word `chard probes` and the corpus hash carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Program => "program",
            Self::Machine => "machine",
        }
    }
}

/// How a check's observation is read: a published predicate, or code.
#[derive(Clone, Copy, Debug)]
pub enum Decoder {
    /// A macro-channel predicate, evaluated over the macro map.
    Macro(fn() -> &'static Predicate),
    /// An elf-static predicate, evaluated over the artifact's facts and the macro map.
    ElfStatic(fn() -> &'static Predicate),
    /// A runtime detector, and the ELF tables it reads through the self-report.
    Runtime {
        detect: Detector,
        reads: &'static [ElfTable],
        basis: RunBasis,
    },
    /// A compiler-diag detector, and the ELF tables it reads from the artifact the build
    /// wrote.
    CompilerDiag {
        detect: Detector,
        reads: &'static [ElfTable],
    },
}

/// A code decoder: the function, and the name the corpus hash binds it by.
#[derive(Clone, Copy, Debug)]
pub struct Detector {
    /// The function's identifier, as `detector!` spelled it.
    pub name: &'static str,
    pub detect: fn(&Evidence<'_>) -> Detection,
}

/// A [`Detector`] for the function `f`, named by `f`'s own identifier.
macro_rules! detector {
    ($f:ident) => {
        Detector {
            name: stringify!($f),
            detect: $f,
        }
    };
}

impl Decoder {
    /// The channel the decoder reads.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        match self {
            Self::Macro(_) => Channel::Macro,
            Self::ElfStatic(_) => Channel::ElfStatic,
            Self::Runtime { .. } => Channel::Runtime,
            Self::CompilerDiag { .. } => Channel::CompilerDiag,
        }
    }

    /// The predicate, for a predicate decoder.
    #[must_use]
    pub fn predicate(&self) -> Option<&'static Predicate> {
        match self {
            Self::Macro(p) | Self::ElfStatic(p) => Some(p()),
            Self::Runtime { .. } | Self::CompilerDiag { .. } => None,
        }
    }

    /// `predicate` or `code`, as `chard probes` publishes it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Macro(_) | Self::ElfStatic(_) => "predicate",
            Self::Runtime { .. } | Self::CompilerDiag { .. } => "code",
        }
    }

    /// The digest `chard probes` publishes for this decoder: SHA-256 over the predicate's
    /// canonical form, or, for a code decoder, [`decoder_sources_sha256`], since a function
    /// pointer has no value of its own to digest.
    #[must_use]
    pub fn sha256(&self) -> String {
        match self.predicate() {
            Some(p) => digest::sha256_hex(predicate_canonical(p).as_bytes()),
            None => decoder_sources_sha256().to_owned(),
        }
    }
}

/// A detection, and the evaluation it came from where the decoder is a predicate.
#[derive(Debug)]
pub struct Decoding {
    pub detection: Detection,
    /// The predicate's evaluation over the facts the detection read: the clause that
    /// decided and every read it made. `None` for a code decoder, and for a predicate the
    /// facts could not answer, whose detection says which key it lacked.
    pub proof: Option<Evaluation>,
}

impl Check {
    /// The positive control on `arch`: its [`ArchControl`] row where one exists, and
    /// [`Check::positive`] otherwise. `arch` is the gate's architecture, as
    /// `measure::Conditions::target_arch` carries it.
    #[must_use]
    pub fn positive_for(&self, arch: &str) -> &'static [&'static str] {
        ARCH_CONTROLS
            .iter()
            .find(|row| row.check == self.id && row.arch == arch)
            .map_or(self.positive, |row| row.positive)
    }

    /// The inputs the positive arm links after the probe's source: its [`PositiveInput`] rows,
    /// none for every check but one.
    #[must_use]
    pub fn positive_inputs(&self) -> Vec<&'static PositiveInput> {
        POSITIVE_INPUTS
            .iter()
            .filter(|row| row.check == self.id)
            .collect()
    }

    /// The flags the regime arm appends to the profile, where the check declares one
    /// ([`Regime::Arm`]), and `None` where it states why none is owed.
    #[must_use]
    pub const fn regime_arm(&self) -> Option<&'static [&'static str]> {
        match self.regime {
            Regime::Arm(flags) => Some(flags),
            Regime::NotOwed(_) => None,
        }
    }

    /// Whether a measurement of this check under a profile owes a regime-matched negative
    /// arm: the check declares one, and the profile adds something to a bare build
    /// (`measure::Conditions::profile_is_clean`).
    #[must_use]
    pub const fn owes_regime_control(&self, profile_is_clean: bool) -> bool {
        self.regime_arm().is_some() && !profile_is_clean
    }

    /// The guide's ask on this check's scale, where the check is graded. The one reading
    /// of [`Levels`] the report publishes as `recommended_level`.
    #[must_use]
    pub const fn recommended_level(&self) -> Option<&'static str> {
        self.levels.recommended()
    }

    /// The channel this check's observation is read on, from its decoder.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        self.decoder.channel()
    }

    /// What this check's runtime reading rests on, and `None` off the runtime channel.
    #[must_use]
    pub const fn run_basis(&self) -> Option<RunBasis> {
        match self.decoder {
            Decoder::Runtime { basis, .. } => Some(basis),
            _ => None,
        }
    }

    /// The ELF tables this check's observable is read from, for the truncation gate.
    #[must_use]
    pub fn reads(&self) -> &'static [ElfTable] {
        match self.decoder {
            Decoder::Macro(p) | Decoder::ElfStatic(p) => &p().tables,
            Decoder::Runtime { reads, .. } | Decoder::CompilerDiag { reads, .. } => reads,
        }
    }

    /// The check's predicate, where its decoder is one.
    #[must_use]
    pub fn predicate(&self) -> Option<&'static Predicate> {
        self.decoder.predicate()
    }

    /// Read `evidence` through this check's decoder: the one entry point every reading
    /// goes through, the measured build, every control arm and every replayed fixture
    /// alike.
    #[must_use]
    pub fn decode(&self, evidence: &Evidence<'_>) -> Decoding {
        match self.decoder {
            Decoder::Macro(p) | Decoder::ElfStatic(p) => {
                let p = p();
                let view = Live {
                    macros: Some(evidence.macros),
                    elf: evidence.elf,
                };
                match predicate::evaluate(p, &view) {
                    Ok(eval) => Decoding {
                        detection: Detection {
                            outcome: eval.outcome,
                            level: eval.level.clone(),
                            observed: predicate::render_observed(p, &eval),
                            rule: None,
                        },
                        proof: Some(eval),
                    },
                    Err(Incomplete(key)) => Decoding {
                        detection: Detection::indeterminate(format!(
                            "the predicate read {key}, which the evidence does not hold"
                        )),
                        proof: None,
                    },
                }
            }
            Decoder::Runtime { detect, .. } | Decoder::CompilerDiag { detect, .. } => Decoding {
                detection: (detect.detect)(evidence),
                proof: None,
            },
        }
    }
}

/// What a verdict establishes, and what it deliberately does not.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Boundary {
    /// What the verdict does establish, in the artifact.
    pub establishes: &'static str,
    /// What must also hold where the binary runs. Each entry is something this report does
    /// not and cannot check, because chard reads a file.
    pub requires_at_runtime: &'static [&'static str],
}

/// The runtime preconditions per protection, keyed on the canonical flag spelling.
const BOUNDARIES: &[(&str, Boundary)] = &[
    (
        "-fPIE",
        Boundary {
            establishes: "the binary is ET_DYN with DF_1_PIE",
            requires_at_runtime: &["kernel address-space randomisation enabled"],
        },
    ),
    // The enforcement reading of CET, before the marking's entry, since the lookup is the
    // first prefix match and this flag also starts with `-fcf-protection`.
    (
        "-fcf-protection=full (shadow stack enforced)",
        Boundary {
            establishes: "a program this toolchain built, run with glibc's shadow-stack opt-in, faulted on an overwritten return address on this kernel, CPU and C library",
            requires_at_runtime: &[
                "at level `opt-in`, the same opt-in where the program runs",
                "every object the program loads marked for the shadow stack",
                "a kernel with user shadow stack and a CPU implementing CET shadow stack where the program runs",
            ],
        },
    ),
    // Ahead of `-fcf-protection`, because the lookup takes the first key the flag starts
    // with: `cet-endbr-emitted` reads code, not a note, under `=branch`, which declares no
    // shadow stack.
    (
        "-fcf-protection=branch",
        Boundary {
            establishes: "the compiled object's functions begin with IBT landing pads",
            requires_at_runtime: &[
                "a CPU implementing IBT",
                "a kernel that enables user-mode IBT",
                "every input to the link marked for IBT",
            ],
        },
    ),
    (
        "-fcf-protection",
        Boundary {
            establishes: "the binary carries a GNU property note declaring IBT and shadow-stack compatibility, a claim of compatibility and not evidence of enforcement",
            requires_at_runtime: &[
                "a CPU implementing CET",
                "kernel support for the shadow stack",
            ],
        },
    ),
    (
        "-Wl,-z,noexecstack",
        Boundary {
            establishes: "the binary requests a non-executable stack through PT_GNU_STACK",
            requires_at_runtime: &["a kernel that honours PT_GNU_STACK and hardware NX"],
        },
    ),
    // `noexecstack-enforced` observes the requirement above on the host that measured, by
    // running the program, and carries its own entry below.
    (
        "non-executable stack at runtime",
        Boundary {
            establishes: "bytes a program this toolchain linked copied onto its stack faulted when called",
            requires_at_runtime: &[
                "a kernel where the binary runs that treats PT_GNU_STACK as the measuring host's did",
            ],
        },
    ),
    // The artifact reading of PIE: its flag is `-pie`, which the `-fPIE` key above does not
    // prefix.
    (
        "-pie",
        Boundary {
            establishes: "the linked artifact is ET_DYN marked as executable output by DF_1_PIE, PT_INTERP or DT_DEBUG",
            requires_at_runtime: &["kernel address-space randomisation enabled"],
        },
    ),
    // The enforcement reading of BTI, before the marking's entry, since the lookup is the
    // first prefix match and this flag also starts with `-mbranch-protection`.
    (
        "-mbranch-protection=bti (BTI enforced)",
        Boundary {
            establishes: "a program this toolchain built",
            requires_at_runtime: &[
                "every input to the program's link marked for BTI",
                "every library the program loads marked for BTI",
                "a CPU implementing FEAT_BTI and a kernel built with `CONFIG_ARM64_BTI` where the program runs",
                "for a dynamically linked program, a C library whose dynamic loader maps it PROT_BTI",
            ],
        },
    ),
    // The enforcement reading of return-address signing, for the same reason.
    (
        "-mbranch-protection=pac-ret (return address authenticated)",
        Boundary {
            establishes: "a program this toolchain built faulted when a function's saved return address was overwritten with an unsigned one",
            requires_at_runtime: &[
                "every function on the path compiled with return-address signing",
                "a CPU implementing FEAT_PAuth and a kernel built with `CONFIG_ARM64_PTR_AUTH` that enables the process's keys",
            ],
        },
    ),
    // aarch64 branch protection, covering all four checks: both mechanisms and both
    // channels share this prefix, with the imprecision `-fcf-protection` has, since a macro
    // check establishes that the compiler was asked while an artifact check establishes
    // that the note survived the link.
    (
        "-mbranch-protection",
        Boundary {
            establishes: "the compiler was asked for branch protection",
            requires_at_runtime: &[
                "a CPU implementing the requested features",
                "on Linux, a kernel or dynamic loader that maps a marked object's executable pages `PROT_BTI`",
                "on Linux, a C library that enables GCS at startup where the loaded objects' marking and its own policy allow",
                "for PAC, key management the kernel provides",
                "on OpenBSD, no PT_OPENBSD_NOBTCFI program header",
            ],
        },
    ),
];

/// The boundary for a flag, if that protection has one.
#[must_use]
pub fn boundary_for(flag: &str) -> Option<Boundary> {
    BOUNDARIES
        .iter()
        .find(|(key, _)| flag.starts_with(key))
        .map(|(_, b)| *b)
}

#[derive(Debug)]
pub struct Probe {
    pub id: &'static str,
    pub title: &'static str,
    pub lang: Lang,
    pub link_mode: LinkMode,
    /// The file name the source is written under. A probe that needs a build has one
    /// ([`Probe::needs_build`]), a macro-only probe among them, since the macro channel
    /// reads a compiled translation unit.
    pub source_name: &'static str,
    pub source: &'static str,
    /// Libraries this probe must link against, in **every** arm: positive control,
    /// negative control, regime control and measured build alike.
    pub link_libs: &'static [&'static str],
    /// Shared libraries this probe needs built *before* its own link, in order.
    pub aux_libs: &'static [AuxLib],
    /// Variables this probe's runs receive beside [`crate::run::PROBE_ENVIRONMENT`], in
    /// every arm: positive, negative, regime and measured alike.
    pub run_environment: &'static [(&'static str, &'static str)],
    pub checks: &'static [Check],
}

/// A shared library built to stand behind a probe, not measured itself.
#[derive(Debug)]
pub struct AuxLib {
    /// Library stem: `chard_dt_b` becomes `libchard_dt_b.so`, linkable as
    /// `-lchard_dt_b`. Also its `-Wl,-soname`, so the dependent library records the
    /// name the loader would look for rather than the build path.
    pub stem: &'static str,
    pub source_name: &'static str,
    pub source: &'static str,
    /// `-l` arguments for *this* library's own link, letting one aux library depend on
    /// an earlier one. The order of [`Probe::aux_libs`] is the build order.
    pub link_libs: &'static [&'static str],
}

impl Probe {
    /// Whether an artifact must be produced.
    pub fn needs_build(&self) -> bool {
        !self.source.is_empty() || self.checks.iter().any(|c| c.channel().needs_build())
    }

    /// A shared object is never executed, whatever its checks declare.
    pub fn needs_run(&self) -> bool {
        self.link_mode == LinkMode::Executable
            && self.checks.iter().any(|c| c.channel().needs_run())
    }

    /// Whether the probe's source writes the `.chard.report` self-report into its
    /// artifact (`CHARD_EMIT_REPORT` from `probes/chard_selfreport.h`).
    #[must_use]
    pub fn embeds_self_report(&self) -> bool {
        without_c_comments(self.source).contains("CHARD_EMIT_REPORT")
    }
}

/// `source` with every `/* */` block and `//` line comment removed, so a mention in
/// prose does not count as a reference. The probes carry no string literal holding
/// either delimiter, which is what makes this scan enough.
pub(crate) fn without_c_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(at) = rest.find("/*").into_iter().chain(rest.find("//")).min() {
        // `at` is where `find` matched, so it is a character boundary.
        let (code, comment) = rest.split_at(at);
        out.push_str(code);
        if comment.starts_with("/*") {
            rest = comment.split_once("*/").map_or("", |(_, after)| after);
        } else {
            rest = comment.split_once('\n').map_or("", |(_, after)| after);
            out.push('\n');
        }
    }
    out.push_str(rest);
    out
}

/// The library the `as-needed` probe links and never calls.
const AS_NEEDED_LINK_ARG: &str = "-lm";

/// The spelling every fortify negative control carries to reach a genuine off.
const FORTIFY_OFF: &str = "-D_FORTIFY_SOURCE=0";

/// The negative control of `pie-macro`: position-independent code off, and the link that
/// matches it.
const PIE_MACRO_NEGATIVE: &[&str] = &["-fno-PIE", "-no-pie"];

/// The negative control of `pic-macro`, `-fno-pic` with the link that matches it:
/// [`PIE_MACRO_NEGATIVE`] gives the failure and the measurement, which are the same arm's.
/// `-fno-pic` turns position-independent executables off with the rest, so a PIE-default
/// driver fails its link identically.
const PIC_MACRO_NEGATIVE: &[&str] = &["-fno-pic", "-no-pie"];

// --- the corpus ---------------------------------------------------------------

const CHECK_FORTIFY_DYNAMIC: Check = Check {
    id: "fortify-enforced-dynamic",
    flag: "-D_FORTIFY_SOURCE=3",
    decoder: Decoder::Runtime {
        detect: detector!(detect_fortify_runtime),
        reads: &[ElfTable::SectionNames],
        basis: RunBasis::Program,
    },
    polarity: Polarity::Harden,
    observable: "glibc's \"buffer overflow detected\" on an abort, a bare trap from an implementation the self-report names",
    levels: Levels::None,
    confidence: Confidence::High,
    // Level 2 is the negative control rather than fortify-off: the claim is that level 3
    // specifically is active, so the control must show level 2 missing it.
    positive: &[
        "-O2",
        "-U_FORTIFY_SOURCE",
        "-D_FORTIFY_SOURCE=3",
        "-fno-lto",
    ],
    negative: &[
        "-O2",
        "-U_FORTIFY_SOURCE",
        "-D_FORTIFY_SOURCE=2",
        "-fno-lto",
    ],
    defects: &["heap-buffer-overflow"],
    observes: Observes::Protection,
    corroborates: None,
    regime: Regime::NotOwed(Specific {
        reason: "glibc's buffer-overflow diagnostic is written by its fortified wrappers and by nothing else.",
        profiles: PROFILES_WITH_FLAGS,
        toolchains: GCC_AND_CLANG,
    }),
    measures_toolchain_default: false,
    references: &[GUIDE],
    gate: Gate {
        arch: &[],
        // Apple's headers clamp any `_FORTIFY_SOURCE > 1` to `_USE_FORTIFY_LEVEL=2`, so
        // `__builtin_dynamic_object_size` never engages and there is no level-3 mechanism
        // here to measure.
        libc_unsupported: &["musl", "openbsd", "apple", "freebsd"],
        compiler_unsupported: &[],
        cxx_stdlib_unsupported: &[],
        needs_vm: false,
    },
    notes: "The only behavioral discriminator between _FORTIFY_SOURCE=2 and =3. Requires optimization.",
};

pub const CORPUS: &[Probe] = &[
    Probe {
        id: "toolchain-macros",
        title: "Predefined macros the toolchain sets by default",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        // A real translation unit, so the macro state is read from what the
        // *compiler* believed rather than from a separate preprocessor job.
        source_name: "macro_report.c",
        source: include_str!("../probes/macro_report.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[
            Check {
                id: "ssp-level",
                flag: "-fstack-protector-strong",
                decoder: Decoder::Macro(macro_channel::ssp_level),
                polarity: Polarity::Harden,
                observable: "__SSP__ / __SSP_STRONG__ / __SSP_ALL__ / __SSP_EXPLICIT__",
                levels: SSP_LEVELS,
                confidence: Confidence::High,
                positive: &["-fstack-protector-strong"],
                negative: &["-fno-stack-protector"],
                defects: &["stack-buffer-overflow", "return-oriented-programming"],
                observes: Observes::Protection,
                corroborates: Some("stack-protector"),
                regime: Regime::NotOwed(Specific {
                    reason: "__SSP__, __SSP_STRONG__, __SSP_ALL__ and __SSP_EXPLICIT__ are predefined by the compiler exactly when it compiles at that protector level, whichever spelling asked.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Reports which level the compiler defaults to.",
            },
            Check {
                id: "fortify-requested",
                flag: "-D_FORTIFY_SOURCE",
                decoder: Decoder::Macro(macro_channel::fortify_requested),
                polarity: Polarity::Harden,
                observable: "_FORTIFY_SOURCE as the preprocessor sees it",
                levels: FORTIFY_LEVELS,
                confidence: Confidence::High,
                positive: &["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-O2"],
                negative: &["-U_FORTIFY_SOURCE", FORTIFY_OFF, "-O2"],
                defects: &["stack-buffer-overflow", "heap-buffer-overflow"],
                observes: Observes::Request,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "the observable is the _FORTIFY_SOURCE macro itself.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &[],
                    libc_unsupported: &["musl", "openbsd"],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "What was asked for, which is not necessarily what is in force.",
            },
            Check {
                id: "fortify-effective",
                // The matrix key, so it names what the check measures rather than one
                // library that measures it.
                flag: "_FORTIFY_SOURCE (level in force)",
                decoder: Decoder::Macro(macro_channel::fortify_effective),
                polarity: Polarity::Harden,
                observable: "the level the C library settled on",
                levels: FORTIFY_LEVELS,
                confidence: Confidence::High,
                positive: &["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-O2"],
                negative: &["-U_FORTIFY_SOURCE", FORTIFY_OFF, "-O2"],
                defects: &["stack-buffer-overflow", "heap-buffer-overflow"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "the C library derives __USE_FORTIFY_LEVEL from _FORTIFY_SOURCE and __OPTIMIZE__ alone.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &[],
                    // FreeBSD below 15 has no implementation: the positive arm
                    // reads `freebsd-without-ssp`, absent, and this gate names the library.
                    libc_unsupported: &["musl", "openbsd", "freebsd"],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "glibc silently downgrades a requested level it cannot serve.",
            },
            Check {
                id: "pie-macro",
                flag: "-fPIE",
                decoder: Decoder::Macro(macro_channel::pie_macro),
                polarity: Polarity::Harden,
                observable: "__PIE__",
                // No recommendation, so the value is never graded.
                levels: CODE_MODEL,
                confidence: Confidence::High,
                positive: &["-fPIE"],
                negative: PIE_MACRO_NEGATIVE,
                defects: &["address-layout-disclosure"],
                observes: Observes::Protection,
                corroborates: Some("pie"),
                regime: Regime::NotOwed(Specific {
                    reason: "__PIE__ is predefined exactly when the compiler generates position-independent executable code.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "`on` whenever __PIE__ is defined with a decimal value above zero.",
            },
            Check {
                id: "pic-macro",
                flag: "-fPIC",
                decoder: Decoder::Macro(macro_channel::pic_macro),
                polarity: Polarity::Harden,
                observable: "__PIC__",
                // The same code-model selector as `__PIE__` and ungraded for the same
                // reason: `-fpic` and `-fPIC` both generate position-independent code.
                levels: CODE_MODEL,
                confidence: Confidence::High,
                positive: &["-fPIC"],
                negative: PIC_MACRO_NEGATIVE,
                defects: &["address-layout-disclosure"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "__PIC__ is predefined by -fPIC and -fpic and equally by -fPIE and -fpie.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "The guide recommends `-fPIE -pie` for executables and `-fPIC -shared` for libraries.",
            },
            Check {
                id: "cet-macro",
                flag: "-fcf-protection=full",
                decoder: Decoder::Macro(macro_channel::cet_macro),
                polarity: Polarity::Harden,
                observable: "__CET__ bitmask (1=IBT, 2=shadow stack)",
                levels: CFI_COMPONENTS,
                confidence: Confidence::High,
                positive: &["-fcf-protection=full"],
                negative: &["-fcf-protection=none"],
                defects: &["return-oriented-programming", "jump-oriented-programming"],
                observes: Observes::Marking,
                corroborates: Some("cet"),
                regime: Regime::NotOwed(Specific {
                    reason: "__CET__ is predefined by -fcf-protection.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &["x86_64", "x86"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "Compile-time intent. Whether the markings survive into the artifact is the cet-marked check.",
            },
            Check {
                id: "gcs-macro",
                flag: "-mbranch-protection=gcs",
                decoder: Decoder::Macro(macro_channel::gcs_macro),
                polarity: Polarity::Harden,
                observable: "__ARM_FEATURE_GCS_DEFAULT",
                levels: Levels::None,
                confidence: Confidence::High,
                positive: &["-mbranch-protection=gcs"],
                negative: &["-mbranch-protection=none"],
                defects: &["return-oriented-programming"],
                observes: Observes::Marking,
                corroborates: Some("gcs"),
                regime: Regime::NotOwed(Specific {
                    reason: "__ARM_FEATURE_GCS_DEFAULT is predefined by the -mbranch-protection values that request GCS.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &["aarch64"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "No level: GCS is on or it is not.",
            },
            Check {
                id: "branch-protection-macro",
                flag: "-mbranch-protection=standard",
                decoder: Decoder::Macro(macro_channel::branch_protection_macro),
                polarity: Polarity::Harden,
                observable: "__ARM_FEATURE_BTI_DEFAULT and __ARM_FEATURE_PAC_DEFAULT",
                levels: CFI_COMPONENTS,
                confidence: Confidence::High,
                positive: &["-mbranch-protection=standard"],
                negative: &["-mbranch-protection=none"],
                defects: &["return-oriented-programming", "jump-oriented-programming"],
                observes: Observes::Marking,
                corroborates: Some("branch-protection"),
                regime: Regime::NotOwed(Specific {
                    reason: "__ARM_FEATURE_BTI_DEFAULT and __ARM_FEATURE_PAC_DEFAULT are predefined by -mbranch-protection and by nothing else in either profile.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &["aarch64"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "The aarch64 counterpart to cet-macro.",
            },
            Check {
                id: "optimization-enabled",
                flag: "-O2",
                decoder: Decoder::Macro(macro_channel::optimization_enabled),
                polarity: Polarity::Harden,
                observable: "__OPTIMIZE__",
                levels: Levels::None,
                confidence: Confidence::High,
                positive: &["-O2"],
                negative: &["-O0"],
                defects: &[],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "__OPTIMIZE__ is the mechanism itself, defined by every -O above -O0.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Load-bearing for hardening.",
            },
        ],
    },
    Probe {
        id: "optimization-object",
        title: "Whether the compiler optimised, read from the object it produced",
        lang: Lang::C,
        // An object, because the probe's callees are undefined externals the link would
        // need defined; the references are what the compiler emitted.
        link_mode: LinkMode::Object,
        source_name: "optimization_applied.c",
        source: include_str!("../probes/optimization_applied.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "optimization-applied",
            flag: "-O2 (code generation)",
            decoder: Decoder::ElfStatic(elf_static::optimization_applied),
            polarity: Polarity::Harden,
            observable: "no reference to chard_opt_dead from chard_opt_probe",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2"],
            negative: &["-O0"],
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the branch is folded by every -O above -O0 and kept at -O0 in the compilers measured.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The artifact twin of optimization-enabled.",
        }],
    },
    Probe {
        id: "cet-object",
        title: "What the compiler marked, before the link had a say",
        lang: Lang::C,
        link_mode: LinkMode::Object,
        // The same translation unit the linked check reads, deliberately: the pair is only
        // a finding if the two artifacts differ in nothing but the link.
        source_name: "link_defaults.c",
        source: include_str!("../probes/link_defaults.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "cet-marked-object",
            flag: "-fcf-protection=full (compiler marking, before linking)",
            decoder: Decoder::ElfStatic(elf_static::cet_marked),
            polarity: Polarity::Harden,
            observable: "GNU_PROPERTY_X86_FEATURE_1_AND IBT and SHSTK bits in the object file",
            levels: CFI_COMPONENTS,
            confidence: Confidence::High,
            positive: &["-fcf-protection=full"],
            negative: &["-fcf-protection=none"],
            defects: &["return-oriented-programming", "jump-oriented-programming"],
            observes: Observes::Marking,
            // Deliberately not part of the `cet` corroboration group: an object is not the
            // linked binary the protection is about, and counting it would let a marked
            // object vouch for a linked binary that carries no IBT or SHSTK at all.
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "read from the compiled object before any link.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &["x86_64", "x86"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The compile side of `cet-marked`.",
        }],
    },
    Probe {
        id: "cet-endbr",
        title: "Whether the compiler put IBT landing pads in the code",
        lang: Lang::C,
        // An object, for the reason `cet-object` is one: a linked program holds landing
        // pads from startup files chard did not build, so only an object separates what
        // the compiler did with this source from what the C library brought in.
        link_mode: LinkMode::Object,
        source_name: "cet_endbr.c",
        source: include_str!("../probes/cet_endbr.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "cet-endbr-emitted",
            flag: "-fcf-protection=branch (landing pads compiled in)",
            decoder: Decoder::ElfStatic(elf_static::cet_endbr),
            polarity: Polarity::Harden,
            observable: "endbr64 (x86_64) or endbr32",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fcf-protection=branch"],
            negative: &["-fcf-protection=none"],
            // The forward edge alone: a landing pad constrains where an indirect call or
            // jump may land, and does nothing for a return.
            defects: &["jump-oriented-programming"],
            observes: Observes::Marking,
            // Not in the `cet` group, for the reason `cet-marked-object` is not: it reads an
            // object, and the group's members are about the linked program.
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "an endbr64 as a function's first instruction is emitted by -fcf-protection=branch or full.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            // x86 alone.
            gate: Gate {
                arch: &["x86_64", "x86"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The instrumentation beside the claim.",
        }],
    },
    Probe {
        id: "no-plt",
        title: "-fno-plt: whether the compiler routes an external call through the PLT",
        lang: Lang::C,
        // An object, because the call's relocation is the observable and a link resolves
        // it into a PLT entry or a GOT slot.
        link_mode: LinkMode::Object,
        source_name: "no_plt.c",
        source: include_str!("../probes/no_plt.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "plt-bypassed",
            flag: "-fno-plt",
            decoder: Decoder::ElfStatic(elf_static::plt_bypassed),
            polarity: Polarity::Harden,
            observable: "the relocation of the object's one call to an external function",
            levels: Levels::None,
            confidence: Confidence::High,
            // `-fPIE` beside the flag because gcc on aarch64 honours -fno-plt only in
            // position-independent code, and Fedora's gcc does not default to it: there
            // `-fno-plt` alone emits the same `R_AARCH64_CALL26` as `-fplt`, and the triple
            // would be `probe-invalid` on a toolchain whose flag works wherever it is used
            // in PIC.
            positive: &["-fPIE", "-fno-plt"],
            negative: &["-fplt"],
            // None, deliberately.
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a call relocation against the callee's GOT slot rather than its PLT is -fno-plt's own code generation.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            // The guide does not name the flag.
            references: &[],
            // Portable.
            gate: PORTABLE,
            notes: "Read on an object: the probe calls one external function.",
        }],
    },
    Probe {
        id: "link-defaults",
        title: "Link-editor and ELF-level defaults",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "link_defaults.c",
        source: include_str!("../probes/link_defaults.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[
            Check {
                id: "pie",
                flag: "-pie",
                decoder: Decoder::ElfStatic(elf_static::pie),
                polarity: Polarity::Harden,
                observable: "ET_DYN with DF_1_PIE, PT_INTERP or DT_DEBUG",
                levels: PIE_FLAVOUR,
                confidence: Confidence::High,
                positive: &["-fPIE", "-pie"],
                negative: &["-fno-PIE", "-no-pie"],
                defects: &["address-layout-disclosure"],
                observes: Observes::Protection,
                corroborates: Some("pie"),
                regime: Regime::NotOwed(Specific {
                    reason: "DF_1_PIE, PT_INTERP and DT_DEBUG are written by the linker for a -pie link, whichever spelling asked.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "ET_DYN alone would also match a shared library, hence the additional DF_1_PIE / PT_INTERP / DT_DEBUG requirement.",
            },
            Check {
                id: "relro",
                flag: "-Wl,-z,relro -Wl,-z,now",
                decoder: Decoder::ElfStatic(elf_static::relro),
                polarity: Polarity::Harden,
                observable: "PT_GNU_RELRO, plus DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW for full",
                levels: RELRO_LEVELS,
                confidence: Confidence::High,
                positive: &["-Wl,-z,relro", "-Wl,-z,now"],
                negative: &["-Wl,-z,norelro"],
                defects: &["got-overwrite"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "PT_GNU_RELRO and the now-binding tags are written by the linker under -z relro and -z now.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                // Where the lazy-binding table lies, measured by a program that writes its own
                // DT_PLTGOT slots back under a fault guard, before and after its first PLT
                // calls.
                notes: "With PT_GNU_RELRO and no BIND_NOW the level is `partial`.",
            },
            Check {
                id: "noexecstack",
                flag: "-Wl,-z,noexecstack",
                decoder: Decoder::ElfStatic(elf_static::noexecstack),
                polarity: Polarity::Harden,
                observable: "PT_GNU_STACK present without PF_X",
                levels: Levels::None,
                confidence: Confidence::High,
                positive: &["-Wl,-z,noexecstack"],
                negative: &["-Wl,-z,execstack"],
                defects: &["stack-code-execution"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "PT_GNU_STACK without PF_X is written by the linker from -z noexecstack.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "An absent PT_GNU_STACK defers to the kernel default and is \
                        reported indeterminate, not off.",
            },
            Check {
                id: "separate-code",
                flag: "-Wl,-z,separate-code",
                decoder: Decoder::ElfStatic(elf_static::separate_code),
                polarity: Polarity::Harden,
                observable: "no allocated non-code section",
                levels: Levels::None,
                confidence: Confidence::Medium,
                positive: &["-Wl,-z,separate-code"],
                negative: &["-Wl,-z,noseparate-code"],
                // None, deliberately.
                defects: &[],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "code and non-code sections kept in separate pages is the linker's -z separate-code.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                // Read from the measured build, not the clean one: no shipped profile passes
                // the flag, so under `bare` the measured build is the linker's default, and a
                // profile that passes either spelling is asking about its own link.
                measures_toolchain_default: false,
                // The guide does not name the flag, and no universal reference beyond the
                // linkers' own manuals does; `ret-protector-emitted` carries none either.
                references: &[],
                // Portable: GNU ld, lld and mold accept both spellings on every ELF target
                // measured, and a linker that took the flag and laid nothing out
                // differently reads absent in the positive arm, which is
                // `probe-invalid`, never `off`.
                gate: PORTABLE,
                notes: "A linker property, and the linkers differ.",
            },
            Check {
                id: "rwx-segment-absent",
                flag: "-Wl,-N",
                decoder: Decoder::ElfStatic(elf_static::rwx_segment),
                // `-N` is the adverse direction: where it is in force the linked program
                // maps a page writable and executable at once, and that reads `on`; `off` is
                // the protected state.
                polarity: Polarity::Weaken,
                observable: "a PT_LOAD or PT_TLS segment carrying both PF_W and PF_X",
                levels: Levels::None,
                confidence: Confidence::High,
                // Injects the adverse finding, as `rpath-absent` does, and the clean
                // build stands in as the negative where the profile carries no target,
                // runtime, header or linker selection (with one, the negative is the check's
                // own build, without the input).
                positive: &["-Wl,-u,chard_rwx_byte"],
                negative: &[],
                // None, deliberately, as `separate-code`: the boundary crosses every
                // memory-corruption class, and crediting one would misattribute it.
                defects: &[],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "an RWX load segment is written only from -Wl,-N, a linker script",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                // Read from the measured build, not the clean one, as `separate-code`:
                // under `bare` the measured build is the linker's default, and a
                // profile passing -N asks about its own link.
                measures_toolchain_default: false,
                // The guide names the concern, as a build option whose warning chard
                // does not read; the guide's two RWX rows name this check.
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "A PT_LOAD or PT_TLS segment both writable and executable in the measured build reads on where the controls stand, the adverse finding.",
            },
            Check {
                id: "rpath-absent",
                flag: "-Wl,-rpath",
                decoder: Decoder::ElfStatic(elf_static::rpath),
                polarity: Polarity::Weaken,
                observable: "DT_RPATH or DT_RUNPATH entries",
                levels: SEARCH_PATH_KIND,
                confidence: Confidence::High,
                positive: &["-Wl,-rpath,/tmp/chard-control"],
                negative: &[],
                defects: &["library-injection"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "DT_RPATH and DT_RUNPATH are written only from -rpath, -R or an LDFLAGS default naming a path.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Discouraged by the guide.",
            },
            Check {
                id: "relative-relocs",
                flag: "-Wl,-z,pack-relative-relocs",
                decoder: Decoder::ElfStatic(elf_static::relr),
                polarity: Polarity::Harden,
                observable: "DT_RELR",
                levels: Levels::None,
                confidence: Confidence::Medium,
                // DT_RELR only exists for position-independent output, so the positive
                // control has to establish PIE as well; without -pie the flag does nothing.
                positive: &["-fPIE", "-pie", "-Wl,-z,pack-relative-relocs"],
                negative: &[],
                defects: &[],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "DT_RELR is written only under -z pack-relative-relocs.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Startup-cost reduction for PIE rather than a hardening mechanism itself.",
            },
            Check {
                id: "cet-marked",
                flag: "-fcf-protection=full (artifact markings)",
                decoder: Decoder::ElfStatic(elf_static::cet_marked),
                polarity: Polarity::Harden,
                observable: ".note.gnu.property GNU_PROPERTY_X86_FEATURE_1_AND IBT and SHSTK bits",
                levels: CFI_COMPONENTS,
                confidence: Confidence::High,
                positive: &["-fcf-protection=full"],
                negative: &["-fcf-protection=none"],
                defects: &["return-oriented-programming", "jump-oriented-programming"],
                observes: Observes::Marking,
                corroborates: Some("cet"),
                // The property is the linker's AND over its inputs, and the linker can
                // force it: an object built `-fcf-protection=none`, with no `endbr64`,
                // linked `-z ibt -z shstk` carries both bits (measured 2026-10-05 on Fedora
                // 44 x86_64, gcc 16.1.1 and clang 22.1.8: `cet-marked` read `on` at `full`
                // beside `cet-endbr-emitted` `off`).
                regime: Regime::Arm(&["-fcf-protection=none"]),
                measures_toolchain_default: false,
                references: &[GUIDE, MUSL_CET_PATCHSET],
                gate: Gate {
                    arch: &["x86_64", "x86"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "Markings only. Enforcement needs CPU and kernel support.",
            },
            Check {
                id: "gcs-marked",
                flag: "-mbranch-protection=gcs (artifact markings)",
                decoder: Decoder::ElfStatic(elf_static::gcs_marked),
                polarity: Polarity::Harden,
                observable: ".note.gnu.property GNU_PROPERTY_AARCH64_FEATURE_1_AND GCS bit",
                levels: Levels::None,
                confidence: Confidence::High,
                positive: &["-mbranch-protection=gcs"],
                negative: &["-mbranch-protection=none"],
                defects: &["return-oriented-programming"],
                observes: Observes::Marking,
                corroborates: Some("gcs"),
                // The linker forces this bit as it forces BTI: an object built
                // `-mbranch-protection=none` linked `-z gcs=always` carries GCS, with GNU ld 2.46.1
                // and LLD 22.1.8 alike, each warning and exiting 0 (2026-10-05, Fedora 44 aarch64
                // under qemu-user, gcc 16.2.1 and clang 22.1.8: this check read `on`).
                regime: Regime::Arm(&["-mbranch-protection=none"]),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &["aarch64"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "Markings only, and High on the same grounds as branch-protection-marked.",
            },
            Check {
                id: "branch-protection-marked",
                flag: "-mbranch-protection=standard (artifact markings)",
                decoder: Decoder::ElfStatic(elf_static::branch_protection_marked),
                polarity: Polarity::Harden,
                observable: ".note.gnu.property GNU_PROPERTY_AARCH64_FEATURE_1_AND BTI \
                             and PAC bits",
                levels: CFI_COMPONENTS,
                confidence: Confidence::High,
                positive: &["-mbranch-protection=standard"],
                negative: &["-mbranch-protection=none"],
                defects: &["return-oriented-programming", "jump-oriented-programming"],
                observes: Observes::Marking,
                corroborates: Some("branch-protection"),
                // The aarch64 shape of `cet-marked`'s forged marking: the linker forces BTI over
                // code with no landing pad.
                regime: Regime::Arm(&["-mbranch-protection=none"]),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &["aarch64"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "Markings only, exactly as for cet-marked.",
            },
        ],
    },
    Probe {
        id: "hardened-downgrade",
        title: "Whether gcc reports that -fhardened did not enable -fstack-protector-strong",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "hardened_downgrade.c",
        source: include_str!("../probes/hardened_downgrade.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "hardened-downgrade-warned",
            flag: "-Whardened",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_hardened_warning),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "a diagnostic that `-fhardened` did not enable `-fstack-protector-strong`",
            levels: DIAG_SEVERITY,
            confidence: Confidence::High,
            // `-Wall` in both arms so the probe's canary can fire: an unused local is
            // only diagnosed under -Wunused-variable, and without it a silent negative
            // arm reads `indeterminate` and takes the check to probe-invalid on a
            // toolchain that is behaving correctly.
            positive: &["-O2", "-Wall", "-fhardened", "-fno-stack-protector"],
            negative: &["-O2", "-Wall", "-fhardened"],
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is gcc's own diagnostic that -fhardened did not enable -fstack-protector-strong.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // `-fhardened` is GCC 14 and later; clang has no equivalent.
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            // A toolchain can report another downgrade in every build under `-fhardened`
            // (Ubuntu 26.04's gcc 15.2.0 reports `_FORTIFY_SOURCE`, which it defines itself),
            // so only the downgrade the positive arm forces is read.
            notes: "This reads whether the build reported that `-fhardened` did not enable `-fstack-protector-strong`.",
        }],
    },
    Probe {
        id: "link-unused-library",
        title: "Whether the linker drops a library none of whose symbols are used",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "link_unused_library.c",
        source: include_str!("../probes/link_unused_library.c"),
        // `compile::build` places these after the source, which is what makes
        // `--as-needed` measurable at all (the probe source says why).
        link_libs: &[AS_NEEDED_LINK_ARG],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "as-needed",
            flag: "-Wl,--as-needed",
            decoder: Decoder::ElfStatic(elf_static::as_needed),
            polarity: Polarity::Harden,
            observable: "no DT_NEEDED entry for a linked library whose symbols are unused",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-Wl,--as-needed"],
            negative: &["-Wl,--no-as-needed"],
            defects: &["library-injection"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a dropped DT_NEEDED for a library whose symbols go unused is --as-needed in force, whichever asked.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE, FLAGS_DISTRO_TABLE],
            gate: PORTABLE,
            notes: "In the guide's unconditional TL;DR block.",
        }],
    },
    Probe {
        id: "copy-dt-needed",
        title: "Whether the linker resolves symbols through a library it was not given",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "copy_dt_needed.c",
        source: include_str!("../probes/copy_dt_needed.c"),
        // Only A is named.
        link_libs: &["-lchard_dt_a"],
        aux_libs: &[
            // Build order is dependency order: B first, then A against it.
            AuxLib {
                stem: "chard_dt_b",
                source_name: "copy_dt_needed_b.c",
                source: include_str!("../probes/copy_dt_needed_b.c"),
                link_libs: &[],
            },
            AuxLib {
                stem: "chard_dt_a",
                source_name: "copy_dt_needed_a.c",
                source: include_str!("../probes/copy_dt_needed_a.c"),
                link_libs: &["-lchard_dt_b"],
            },
        ],
        run_environment: &[],
        checks: &[Check {
            id: "no-copy-dt-needed",
            flag: "-Wl,--no-copy-dt-needed-entries",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_no_copy_dt_needed),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "the link refusing a symbol reachable only through another \
                         library's DT_NEEDED",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-Wl,--no-copy-dt-needed-entries"],
            negative: &["-Wl,--copy-dt-needed-entries"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the link refusing a symbol reachable only through another library's DT_NEEDED is --no-copy-dt-needed-entries in force, the default of every linker chard has met.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["library-injection"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The `openssf-tldr` profile passes the flag.",
        }],
    },
    Probe {
        id: "shared-object-defaults",
        title: "Linker defaults that only apply to shared objects",
        lang: Lang::C,
        link_mode: LinkMode::SharedObject,
        source_name: "shared_object.c",
        source: include_str!("../probes/shared_object.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[
            Check {
                id: "nodlopen",
                flag: "-Wl,-z,nodlopen",
                decoder: Decoder::ElfStatic(elf_static::nodlopen),
                polarity: Polarity::Harden,
                observable: "DF_1_NOOPEN (0x40) in DT_FLAGS_1",
                levels: Levels::None,
                confidence: Confidence::High,
                positive: &["-Wl,-z,nodlopen"],
                negative: &[],
                defects: &["library-injection"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "DF_1_NOOPEN is written only under -z nodlopen.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE, FLAGS_DISTRO_TABLE],
                gate: PORTABLE,
                notes: "Measured on a shared object.",
            },
            Check {
                id: "textrel-absent",
                flag: "-fPIC (no text relocations)",
                decoder: Decoder::ElfStatic(elf_static::textrel),
                polarity: Polarity::Weaken,
                observable: "DT_TEXTREL, or DF_TEXTREL in DT_FLAGS",
                levels: TEXTREL_WORD,
                confidence: Confidence::High,
                // Injects the adverse finding, as `rpath-absent` does.
                positive: &["-fno-pic", "-mcmodel=large", "-Wl,-z,notext"],
                negative: &[],
                defects: &["stack-code-execution"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "DT_TEXTREL or DF_TEXTREL is written by the linker exactly when it placed a dynamic relocation in a read-only segment.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    // The property is universal, but the way this control manufactures it is
                    // not, so the gate admits only the architectures where the control was
                    // measured to discriminate.
                    arch: &["x86_64", "x86", "aarch64"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "A text relocation forces the loader to make executable pages writable to apply it.",
            },
        ],
    },
    Probe {
        id: "pic-shared-link",
        title: "Whether code compiled under the flags links into a shared object",
        lang: Lang::C,
        link_mode: LinkMode::SharedObjectAsCompiled,
        source_name: "pic_shared_link.c",
        source: include_str!("../probes/pic_shared_link.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "pic-shared-link",
            flag: "-fPIC (shared link)",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_pic_shared_link),
                reads: &[ElfTable::Dynamic],
            },
            polarity: Polarity::Harden,
            observable: "a `-shared` link of the probe's own code",
            levels: Levels::None,
            // Medium, not High: `on` is a link that succeeded, which more than -fPIC can
            // produce.
            confidence: Confidence::Medium,
            positive: &["-fPIC"],
            // `-fPIE` rather than `-fno-pic`: both are refused, and `-fPIE` is the code a
            // build carrying the guide's executable flags hands a library, which is the
            // confusion the check separates.
            negative: &["-fPIE"],
            // With `pic-object-relocs`, which reads the relocation the compiler wrote for
            // the same kind of access before any link.
            corroborates: Some("pic"),
            // The observable is generic in the `on` direction: a link succeeds for any
            // reason the probe's reference stops being refused, not only -fPIC.
            regime: Regime::Arm(&["-fPIE"]),
            measures_toolchain_default: false,
            defects: &[],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            // `pie-macro` and `pic-macro` cannot tell the two code models apart, since -fPIE
            // defines `__PIC__` as well as `__PIE__`.
            notes: "The guide recommends `-fPIE -pie` for executables and `-fPIC -shared` for shared libraries.",
        }],
    },
    Probe {
        id: "pic-object",
        title: "Whether the compiler reaches an exported global through the GOT",
        lang: Lang::C,
        // An object, because the linker relaxes a GOT access to a direct one wherever it
        // can: a linked program no longer says how the code was generated.
        link_mode: LinkMode::Object,
        source_name: "pic_object_relocs.c",
        source: include_str!("../probes/pic_object_relocs.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "pic-object-relocs",
            flag: "-fPIC (object relocations)",
            decoder: Decoder::ElfStatic(elf_static::pic_object),
            polarity: Polarity::Harden,
            observable: "the relocation type in the object file's code against the probe's exported, defined global",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fPIC"],
            // `-fPIE`, as `pic-shared-link` uses: the code a build carrying the guide's
            // executable flags hands a library, and the confusion the check separates.
            negative: &["-fPIE"],
            corroborates: Some("pic"),
            // A regime arm, the profile followed by `-fPIE`.
            regime: Regime::Arm(&["-fPIE"]),
            measures_toolchain_default: false,
            defects: &[],
            observes: Observes::Protection,
            references: &[GUIDE],
            // The relocation types are per machine, and the predicate names those of the
            // three it was measured on.
            gate: Gate {
                arch: &["x86_64", "x86", "aarch64"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The compiler-side reading of `pic-shared-link`'s question.",
        }],
    },
    Probe {
        id: "stack-canary",
        title: "Stack protector instrumentation actually emitted",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "stack_canary.c",
        source: include_str!("../probes/stack_canary.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "canary-emitted",
            flag: "-fstack-protector-strong (emitted)",
            decoder: Decoder::ElfStatic(elf_static::canary),
            polarity: Polarity::Harden,
            observable: "a __stack_chk_fail, __stack_chk_fail_local or \
                         __stack_smash_handler reference",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fstack-protector-all"],
            negative: &["-fno-stack-protector"],
            defects: &["stack-buffer-overflow", "return-oriented-programming"],
            observes: Observes::Protection,
            corroborates: Some("stack-protector"),
            regime: Regime::NotOwed(Specific {
                reason: "a reference to __stack_chk_fail or its siblings is emitted only by the stack protector, whichever spelling turned it on.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "Cross-checks the macro-channel ssp-level claim against what the compiler emitted.",
        }],
    },
    Probe {
        id: "ret-protector",
        title: "OpenBSD's RETGUARD: a return-address cookie per function",
        lang: Lang::C,
        // An object, because a linked OpenBSD program carries the startup objects' cookies
        // in every arm; see `predicate::elf_static`'s RET_PROTECTOR.
        link_mode: LinkMode::Object,
        source_name: "ret_protector.c",
        source: include_str!("../probes/ret_protector.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "ret-protector-emitted",
            flag: "-fret-protector",
            decoder: Decoder::ElfStatic(elf_static::ret_protector),
            polarity: Polarity::Harden,
            observable: "a .openbsd.randomdata.retguard.<n> cookie section in the object file",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fret-protector"],
            negative: &["-fno-ret-protector"],
            defects: &["return-oriented-programming"],
            observes: Observes::Protection,
            // A guard on the return address alone, and on OpenBSD amd64 it replaces the
            // canary rather than agreeing with it, so it corroborates no canary reading.
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a .openbsd.randomdata.retguard section is written only by OpenBSD clang's -fret-protector.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["clang"],
            }),
            measures_toolchain_default: false,
            references: &[],
            // Portable: only OpenBSD's clang knows the flag, and every other driver says so
            // on stderr, which publishes `unsupported` under `flag-unknown-to-driver` from
            // the driver's own words rather than from a list here.
            gate: PORTABLE,
            notes: "OpenBSD's clang turns RETGUARD on by default on amd64 and with the stack protector.",
        }],
    },
    Probe {
        id: "exceptions",
        title: "-fexceptions in C: the macro and the landing-pad table",
        lang: Lang::C,
        // An object, because the landing pad's callee is declared and never defined: the
        // call has to stay opaque so it may unwind, and a link would fail on it.
        link_mode: LinkMode::Object,
        source_name: "exceptions.c",
        source: include_str!("../probes/exceptions.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[
            Check {
                id: "exceptions-macro",
                flag: "-fexceptions",
                decoder: Decoder::Macro(macro_channel::exceptions_macro),
                polarity: Polarity::Harden,
                observable: "__EXCEPTIONS in a C translation unit",
                levels: Levels::None,
                confidence: Confidence::High,
                // No -O in either arm: the macro and the table read the same at -O0 and
                // -O2 on every toolchain measured (`elf_static`'s EXCEPT_TABLE).
                positive: &["-fexceptions"],
                negative: &["-fno-exceptions"],
                // No defect class: the guide asks for the flag so that a cancelled thread
                // runs the cleanup handlers of C frames, not for a class `DEFECTS` lists.
                defects: &[],
                observes: Observes::Protection,
                corroborates: Some("exceptions"),
                regime: Regime::NotOwed(Specific {
                    reason: "__EXCEPTIONS is predefined in a C translation unit by -fexceptions alone.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                // The readings behind the notes.
                notes: "The guide's TL;DR addendum asks for -fexceptions only for multi-threaded C code using glibc's pthreads.",
            },
            Check {
                id: "except-table-emitted",
                flag: "-fexceptions (emitted)",
                decoder: Decoder::ElfStatic(elf_static::except_table),
                polarity: Polarity::Harden,
                observable: "a .gcc_except_table section in the object file",
                levels: Levels::None,
                confidence: Confidence::High,
                positive: &["-fexceptions"],
                negative: &["-fno-exceptions"],
                defects: &[],
                observes: Observes::Protection,
                // The same object as `exceptions-macro`, so the group's agreement checks
                // chard's two readers of one artifact against each other.
                corroborates: Some("exceptions"),
                regime: Regime::NotOwed(Specific {
                    reason: "a .gcc_except_table in a C object.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                // `.eh_frame` was present in every arm on every toolchain measured but 32-bit
                // ARM's, whose default exception model writes .ARM.exidx entries instead.
                notes: "Cross-checks exceptions-macro against what the compiler emitted.",
            },
        ],
    },
    Probe {
        id: "ubsan-trap",
        title: "UBSan in trap mode: a trap instruction where a handler call would be",
        lang: Lang::C,
        // An object, so every relocated field in the function holds zero and no address
        // can put the trap's bytes there (`elf::code`).
        link_mode: LinkMode::Object,
        source_name: "ubsan_trap.c",
        source: include_str!("../probes/ubsan_trap.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "ubsan-trap-mode",
            flag: "-fsanitize-trap=undefined",
            decoder: Decoder::ElfStatic(elf_static::ubsan_trap),
            polarity: Polarity::Harden,
            observable: "a trap instruction (ud2, ud1 or brk) in the code of the probe's four functions or gcc's .cold parts of them",
            levels: UBSAN_TRAP_INSN,
            confidence: Confidence::High,
            // No -O in either arm: the trap and the handler calls appear at -O0 and -O2
            // alike on every toolchain measured (`elf_static`'s UBSAN_TRAP).
            positive: &["-fsanitize=undefined", "-fsanitize-trap=undefined"],
            // Handler mode, rather than no sanitizer: the arm shows the instrumentation
            // itself puts no trap pattern in the function, so a trap in the measured build
            // is the mode and not the sanitizer's presence.
            negative: &["-fsanitize=undefined"],
            // No defect class: the check reads the mode the sanitizer runs in, not which
            // undefined behaviours it was asked to check.
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a trap instruction in the probe's four functions is emitted by -fsanitize-trap.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            // The patterns exist for these two machines, measured; another machine's
            // object is unsearched and reads `indeterminate`, so the gate names the
            // architectures rather than leaving that to the predicate.
            gate: Gate {
                arch: &["x86_64", "aarch64"],
                ..PORTABLE
            },
            // The readings behind the notes.
            notes: "The guide sanctions UBSan in production in trap mode, -fsanitize=undefined -fsanitize-trap=undefined.",
        }],
    },
    Probe {
        id: "fortify-printf-flag",
        title: "_FORTIFY_SOURCE's level from printf's flag argument in the object's code",
        lang: Lang::C,
        // An object: `escape` is declared and never defined, and in an object no relocated
        // field contributes bytes to the searched code (`elf::code`).
        link_mode: LinkMode::Object,
        source_name: "fortify_printf_flag.c",
        source: include_str!("../probes/fortify_printf_flag.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "fortify-printf-flag",
            flag: "_FORTIFY_SOURCE (printf's flag argument)",
            decoder: Decoder::ElfStatic(elf_static::fortify_printf_flag),
            polarity: Polarity::Harden,
            observable: "the flag argument (__USE_FORTIFY_LEVEL - 1) loaded before __printf_chk or __vprintf_chk in the object's code",
            levels: FORTIFY_LEVELS,
            confidence: Confidence::High,
            // The arms of `fortify-effective`, whose settled level this reads from the code
            // the level produced rather than from the macro.
            positive: &["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-O2"],
            negative: &["-U_FORTIFY_SOURCE", FORTIFY_OFF, "-O2"],
            // No defect class: `fortify-effective` and the runtime rungs carry fortify's,
            // and a third bearer would grade the same defects on one more reading of the
            // same level.
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the flag argument loaded before __printf_chk exists only where fortify rewrote printf to __printf_chk.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // The flag patterns exist for these two machines, measured.
                arch: &["x86_64", "aarch64"],
                // As `fortify-enforced-dynamic`: a C library with no checking `printf` and
                // no `__strcpy_chk` leaves the positive arm without the observable, and only
                // then is the library named.
                libc_unsupported: &["musl", "openbsd", "apple", "freebsd"],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The level the compiled code asks the C library for, read from the object rather than from __USE_FORTIFY_LEVEL. glibc passes a checking printf the flag __USE_FORTIFY_LEVEL - 1.",
        }],
    },
    Probe {
        id: "fortify-known-object",
        title: "_FORTIFY_SOURCE enforcement on a compile-time-known object",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "fortify_known_object.c",
        source: include_str!("../probes/fortify_known_object.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "fortify-enforced-known",
            flag: "-D_FORTIFY_SOURCE (enforced)",
            decoder: Decoder::Runtime {
                detect: detector!(detect_fortify_runtime),
                reads: &[ElfTable::SectionNames],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "glibc's \"buffer overflow detected\" on an abort, a bare trap from an implementation the self-report names",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"],
            negative: &["-O2", "-U_FORTIFY_SOURCE", FORTIFY_OFF],
            defects: &["stack-buffer-overflow", "heap-buffer-overflow"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "glibc's buffer-overflow diagnostic is written by its fortified wrappers and by nothing else.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &["musl", "openbsd", "freebsd"],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "Proves the checks are in force rather than merely requested.",
        }],
    },
    Probe {
        id: "fortify-dynamic-object",
        title: "_FORTIFY_SOURCE level 3 enforcement on a heap object",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "fortify_dynamic_object.c",
        source: include_str!("../probes/fortify_dynamic_object.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[CHECK_FORTIFY_DYNAMIC],
    },
    Probe {
        id: "fortify-subobject",
        title: "_FORTIFY_SOURCE level 2: subobject bounds",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "fortify_subobject.c",
        source: include_str!("../probes/fortify_subobject.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "fortify-level-ge-2-subobject",
            flag: "-D_FORTIFY_SOURCE>=2 (subobject bounds)",
            decoder: Decoder::Runtime {
                detect: detector!(detect_fortify_runtime),
                reads: &[ElfTable::SectionNames],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "\"buffer overflow detected\" on an abort, a bare trap from an implementation the self-report names",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"],
            negative: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=1"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "glibc's buffer-overflow diagnostic on a write within an enclosing object is level 2's subobject bound.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["stack-buffer-overflow", "heap-buffer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &["musl", "openbsd", "freebsd"],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "Rung 2 of the fortify ratchet.",
        }],
    },
    Probe {
        id: "fortify-percent-n",
        title: "_FORTIFY_SOURCE level 2: %n in a writable segment",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "fortify_percent_n.c",
        source: include_str!("../probes/fortify_percent_n.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "fortify-level-ge-2-percent-n",
            flag: "-D_FORTIFY_SOURCE>=2 (%n in a writable segment)",
            decoder: Decoder::Runtime {
                detect: detector!(detect_fortify_percent_n),
                reads: &[],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "SIGABRT with glibc's distinct \"%n in writable segment(s) detected\"",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"],
            negative: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=1"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "glibc's distinct `%n in writable segment(s) detected` abort is raised by the fortified printf family at level 2 and by nothing else.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["format-string"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &["musl", "openbsd", "freebsd"],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "Rung 2': the same level as the subobject rung, reached through an unrelated glibc code path and carrying its own diagnostic.",
        }],
    },
    Probe {
        id: "linker-default-execstack",
        title: "What the linker assumes when an object says nothing",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "linker_default_execstack.S",
        source: include_str!("../probes/linker_default_execstack.S"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "linker-default-noexecstack",
            flag: "--enable-default-execstack=no (linker default)",
            decoder: Decoder::ElfStatic(elf_static::noexecstack),
            polarity: Polarity::Harden,
            observable: "PT_GNU_STACK on a binary linked from an object carrying no \
                         .note.GNU-stack",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-Wl,-z,noexecstack"],
            negative: &["-Wl,-z,execstack"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "reads its observable from the clean build.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: true,
            defects: &["stack-code-execution"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: Gate {
                // The property is portable; this `main` is not, and a build failure
                // elsewhere would read as a measurement.
                arch: &["x86_64", "x86"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The sibling `noexecstack` check asks whether a flag was passed.",
        }],
    },
    Probe {
        id: "stack-exec-runtime",
        title: "Is the stack executable when the program runs?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "stack_exec_runtime.c",
        source: include_str!("../probes/stack_exec_runtime.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "noexecstack-enforced",
            // Not a flag spelling, deliberately: what is measured is the link's PT_GNU_STACK
            // and the kernel's handling of it together.
            flag: "non-executable stack at runtime",
            decoder: Decoder::Runtime {
                detect: detector!(detect_stack_exec),
                reads: &[],
                // A fault the kernel's mapping of the stack produces.
                basis: RunBasis::Machine,
            },
            polarity: Polarity::Harden,
            observable: "whether machine code copied to a buffer on main's stack runs and returns its marker",
            levels: Levels::None,
            confidence: Confidence::High,
            // No `-O`: the probe reads the same at -O0 through -O3 and -Os on both
            // compilers and both architectures (measured 2026-10-02).
            positive: &["-Wl,-z,noexecstack"],
            negative: &["-Wl,-z,execstack"],
            defects: &["stack-code-execution"],
            observes: Observes::Protection,
            corroborates: None,
            // A regime control: both arms of the triple are built without the profile, so
            // they say nothing about a profile flag that produces the fault by another
            // route.
            regime: Regime::Arm(&["-Wl,-z,execstack"]),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // The two architectures the payload is written for.
                arch: &["x86_64", "aarch64"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                // The reading is the kernel's, so under a container it describes the host
                // and not the distribution on the column.
                needs_vm: true,
            },
            notes: "The enforced half of `noexecstack`.",
        }],
    },
    Probe {
        id: "ssp-small-array",
        title: "Stack protector coverage of a below-threshold array",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "ssp_small_array.c",
        source: include_str!("../probes/ssp_small_array.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "ssp-covers-small-arrays",
            flag: "--param ssp-buffer-size",
            decoder: Decoder::ElfStatic(elf_static::canary),
            polarity: Polarity::Harden,
            observable: "a __stack_chk_fail or __stack_smash_handler reference from a \
                         function whose only array is four bytes, below the default \
                         eight-byte threshold",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fstack-protector-all"],
            // The threshold is set explicitly rather than left to the compiler's
            // default, because the default is exactly what this check is trying to
            // observe.
            negative: &["-fstack-protector", "--param", "ssp-buffer-size=8"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a __stack_chk_fail reference from a function whose only array is four bytes is the strong protector's rule in force, however it was spelled.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["stack-buffer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE, ALPINE_TSC_64],
            gate: PORTABLE,
            notes: "Coverage rather than presence.",
        }],
    },
    Probe {
        id: "ssp-function-map",
        title: "Stack protector level read from which functions got a canary",
        lang: Lang::C,
        // An object, because a link resolves the relocations that attribute each canary
        // reference to the function making it; see `elf::ElfFacts::function_references`.
        link_mode: LinkMode::Object,
        source_name: "ssp_function_map.c",
        source: include_str!("../probes/ssp_function_map.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "ssp-level-emitted",
            flag: "-fstack-protector-strong (level emitted)",
            decoder: Decoder::ElfStatic(elf_static::ssp_level_emitted),
            polarity: Polarity::Harden,
            observable: "which of four functions, one per protector rule",
            levels: SSP_LEVELS,
            confidence: Confidence::High,
            positive: &["-fstack-protector-all"],
            negative: &["-fno-stack-protector"],
            // The classes `ssp-level` and `canary-emitted` already carry; this check
            // corroborates their reading rather than adding a mitigation.
            defects: &[],
            observes: Observes::Protection,
            corroborates: Some("stack-protector"),
            regime: Regime::NotOwed(Specific {
                reason: "which of the four functions refer to __stack_chk_fail is the protector's level in force, however it was spelled.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            // The readings behind the notes.
            gate: PORTABLE,
            notes: "The artifact half of ssp-level.",
        }],
    },
    Probe {
        id: "strict-flex-arrays",
        title: "Trailing arrays are bounded rather than treated as flexible",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "strict_flex_arrays.c",
        source: include_str!("../probes/strict_flex_arrays.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "strict-flex-arrays",
            flag: "-fstrict-flex-arrays",
            decoder: Decoder::Runtime {
                detect: detector!(detect_strict_flex_arrays),
                reads: &[],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "__builtin_object_size of trailing arrays declared [2], [1] and [0]",
            levels: FLEX_ARRAY_LEVELS,
            confidence: Confidence::High,
            positive: &["-O2", "-fstrict-flex-arrays=3"],
            negative: &["-O2", "-fstrict-flex-arrays=0"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "__builtin_object_size over the trailing arrays is the front end's own answer under -fstrict-flex-arrays, printed by the probe.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["heap-buffer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The flag that decides whether fortify works on the trailing-array pattern at all.",
        }],
    },
    Probe {
        id: "strict-flex-arrays-enforced",
        title: "Trailing-array bounds are enforced by a fortified copy",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "strict_flex_arrays_enforced.c",
        source: include_str!("../probes/strict_flex_arrays_enforced.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "strict-flex-arrays-enforced",
            flag: "-fstrict-flex-arrays (enforced under _FORTIFY_SOURCE>=2)",
            decoder: Decoder::Runtime {
                detect: detector!(detect_strict_flex_arrays_enforced),
                // The trap path asks the self-report which implementation wrapped the
                // translation unit, as `fortify-level-ge-2-subobject` does.
                reads: &[ElfTable::SectionNames],
                // glibc's diagnostic before an abort, and the probe's own account of how
                // each child ended: what the instructions and the C library do, which an
                // emulator executing them reproduces.
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "SIGABRT with \"buffer overflow detected\" from a fortified strcpy past trailing arrays declared [2], [1] and [0]",
            levels: FLEX_ARRAY_LEVELS,
            confidence: Confidence::High,
            // Both arms pin fortify at 2, the lowest level that checks a subobject bound,
            // so the arms differ in the flag alone; `-U` first, so a toolchain that
            // defines the macro itself is not handed a redefinition.
            positive: &[
                "-O2",
                "-U_FORTIFY_SOURCE",
                "-D_FORTIFY_SOURCE=2",
                "-fstrict-flex-arrays=3",
            ],
            negative: &[
                "-O2",
                "-U_FORTIFY_SOURCE",
                "-D_FORTIFY_SOURCE=2",
                "-fstrict-flex-arrays=0",
            ],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "glibc's diagnostic is specific to fortify.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["heap-buffer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                // The fortify rungs' gate, for their reason: musl has no fortified
                // wrappers of its own, OpenBSD's libc has none, and FreeBSD's strcpy
                // wrapper asks for the whole object.
                libc_unsupported: &["musl", "openbsd", "freebsd"],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The enforcement half of `strict-flex-arrays`.",
        }],
    },
    Probe {
        id: "ub-signed-overflow",
        title: "Signed-overflow guards survive the optimizer",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "ub_signed_overflow.c",
        source: include_str!("../probes/ub_signed_overflow.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "no-strict-overflow",
            flag: "-fno-strict-overflow",
            decoder: Decoder::Runtime {
                detect: detector!(detect_no_strict_overflow),
                reads: &[],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "whether an `x + 1 < x` guard is still present to run",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-fno-strict-overflow"],
            negative: &["-O2", "-fstrict-overflow"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a surviving guard can be kept by a sanitizer's checked add as well as by the flag.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["optimizer-exploited-ub", "integer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "One of the guide's four `for production code` anti-UB flags.",
        }],
    },
    Probe {
        id: "trapv-helper",
        title: "-ftrapv under gcc: the libgcc trapping helpers an object calls",
        lang: Lang::C,
        // An object, because a link copies the helpers in from libgcc.a and defines them,
        // and a stripped link drops them from the symbol table; in the object they are the
        // references gcc emitted.
        link_mode: LinkMode::Object,
        source_name: "trapv_helper.c",
        source: include_str!("../probes/trapv_helper.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "trapv-helper-called",
            flag: "-ftrapv (libgcc helper)",
            decoder: Decoder::ElfStatic(elf_static::trapv_helper),
            polarity: Polarity::Harden,
            observable: "a reference to __addvsi3, __subvsi3 or __mulvsi3 in the object \
                         file, the libgcc helpers gcc calls for signed int arithmetic \
                         under -ftrapv",
            levels: Levels::None,
            confidence: Confidence::High,
            // No -O in the positive arm: the helpers were called at every level measured
            // (`elf_static`'s TRAPV_HELPER).
            positive: &["-ftrapv"],
            negative: &[],
            defects: &["integer-overflow"],
            observes: Observes::Protection,
            corroborates: Some("trapv"),
            regime: Regime::NotOwed(Specific {
                reason: "__addvsi3, __subvsi3 and __mulvsi3 are called only by gcc's -ftrapv.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            // clang implements -ftrapv inline and names no helper, so its positive arm
            // reads absent; the gate turns that into `unsupported` rather than letting a
            // clang build read `off`.
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "gcc's form of -ftrapv only. gcc replaces each signed int addition, subtraction and multiplication it cannot prove safe with a call to libgcc's __addvsi3, __subvsi3 or __mulvsi3.",
        }],
    },
    Probe {
        id: "trapv",
        title: "-ftrapv: a signed overflow kills the program",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "trapv.c",
        source: include_str!("../probes/trapv.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "trapv-trapped",
            flag: "-ftrapv",
            decoder: Decoder::Runtime {
                detect: detector!(detect_trapv),
                reads: &[],
                // The reading is how the program died: an `abort()` the C library raises,
                // or a trap instruction the compiler emitted and the emulator executes as
                // the hardware does.
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "whether adding 1 to INT_MAX kills the program",
            levels: Levels::None,
            confidence: Confidence::High,
            // No -O and no negative arm, for the reasons `trapv-helper-called` gives: the
            // overflow trapped at every level measured, and clang cannot spell the flag
            // off.
            positive: &["-ftrapv"],
            negative: &[],
            defects: &["integer-overflow"],
            observes: Observes::Protection,
            corroborates: Some("trapv"),
            regime: Regime::NotOwed(Specific {
                reason: "death on INT_MAX + 1 is -ftrapv's own.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The guide's alternative to -fno-strict-overflow.",
        }],
    },
    Probe {
        id: "ub-null-check",
        title: "Null checks survive a preceding dereference",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "ub_null_check.c",
        source: include_str!("../probes/ub_null_check.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "no-delete-null-pointer-checks",
            flag: "-fno-delete-null-pointer-checks",
            decoder: Decoder::Runtime {
                detect: detector!(detect_no_delete_null_checks),
                reads: &[],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "whether a null check following a dereference is still present",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-fno-delete-null-pointer-checks"],
            negative: &["-O2", "-fdelete-null-pointer-checks"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a null check that survives its preceding dereference survives when the optimizer did not run or was told to keep it.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["optimizer-exploited-ub", "null-deref"],
            observes: Observes::Protection,
            references: &[GUIDE],
            // Deliberately NOT gated off clang.
            gate: PORTABLE,
            notes: "CVE-2009-1897 in the tun driver is the worked example.",
        }],
    },
    Probe {
        id: "ub-strict-aliasing",
        title: "Stores through incompatible pointer types are observed",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "ub_strict_aliasing.c",
        source: include_str!("../probes/ub_strict_aliasing.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "no-strict-aliasing",
            flag: "-fno-strict-aliasing",
            decoder: Decoder::Runtime {
                detect: detector!(detect_no_strict_aliasing),
                reads: &[],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "whether a store through an incompatible pointer is seen by a \
                         later read",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-fno-strict-aliasing"],
            negative: &["-O2", "-fstrict-aliasing"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "detect_no_strict_aliasing re-reads the store from a copy compiled without sanitizer instrumentation and withholds where only the instrumented build kept it.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["optimizer-exploited-ub"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The flag the Linux kernel passes.",
        }],
    },
    Probe {
        id: "zero-init-padding",
        title: "Padding and inactive union bytes zeroed on initialization",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "zero_init_padding.c",
        source: include_str!("../probes/zero_init_padding.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "zero-init-padding-bits",
            flag: "-fzero-init-padding-bits=all",
            decoder: Decoder::Runtime {
                detect: detector!(detect_zero_init_padding),
                reads: &[],
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "the byte past the active member of an initialized union",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fzero-init-padding-bits=all"],
            // `=standard` rather than omitting the flag: a compiler's default may be
            // `all` (Ubuntu 26.04's gcc 15.2.0), so the negative arm names the setting it
            // measures rather than inheriting one.
            negative: &["-fzero-init-padding-bits=standard"],
            defects: &["uninitialized-read", "address-layout-disclosure"],
            observes: Observes::Protection,
            corroborates: None,
            // A build whose own store for the initializer reaches the byte read zeroes it
            // with no flag; the arm, the profile's flags with `=standard` last, reads that
            // zero and withholds.
            regime: Regime::Arm(&["-fzero-init-padding-bits=standard"]),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // clang 22.1.8 answers `-fzero-init-padding-bits=all` with "unknown
                // argument", so both control arms fail to build and there is nothing to
                // compare.
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            // gcc 16.1.1 reads `on` with `-fzero-init-padding-bits=all` at `-O0`, `-Og` and
            // `-O2`, and with `=unions` at `-O2` (Fedora 44 x86_64, measured 2026-11-11 UTC).
            notes: "A gcc whose default is `standard` reads `off` under `bare`, `bare-optimized` and `openssf-tldr`.",
        }],
    },
    Probe {
        id: "zero-call-used-regs",
        title: "Call-used registers cleared before a function returns",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "zero_call_used_regs.c",
        source: include_str!("../probes/zero_call_used_regs.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "zero-call-used-regs",
            flag: "-fzero-call-used-regs",
            decoder: Decoder::Runtime {
                detect: detector!(detect_zero_call_used_regs),
                reads: &[],
                // The probe prints the registers' values after instructions it executed, and
                // an emulator executing the zeroing sequence reproduces them: eight static
                // aarch64 builds printed identical lines natively and under qemu-user
                // (2026-10-01; `measure::tests` pins the list).
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "the argument registers, and one non-argument register the function \
                         used, read by an assembly trampoline immediately after the function \
                         returns",
            levels: ZERO_CALL_USED_REGS,
            confidence: Confidence::High,
            // No `-O`: the clearing is emitted at every level, measured at -O0 through -O3
            // and -Os on both compilers and both architectures (the probe's header).
            positive: &["-fzero-call-used-regs=used-gpr"],
            // `=skip` rather than omitting the flag, so the negative arm is a stated
            // choice; it is also the form `tests/inert_flags.rs` drives.
            negative: &["-fzero-call-used-regs=skip"],
            defects: &["return-oriented-programming"],
            observes: Observes::Protection,
            corroborates: None,
            // An arm although no profile flag is known to produce the observable: the profile
            // followed by `=skip`, which wins last on the line, withholds the day a toolchain or a
            // profile clears the registers by another route.
            regime: Regime::Arm(&["-fzero-call-used-regs=skip"]),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // The two architectures the guide recommends the flag for, and the two the
                // probe's trampoline is written for.
                arch: &["x86_64", "aarch64"],
                libc_unsupported: &[],
                // clang implements the flag on both architectures from clang 15; clang
                // 14.0.0 rejects it as an unknown argument, which
                // `measure::unknown_flag_limitation` publishes as `unsupported` in the
                // driver's words.
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "Read from the registers themselves.",
        }],
    },
    Probe {
        id: "shadow-stack",
        title: "x86 shadow stack enforced for a program the toolchain built",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "shadow_stack.c",
        source: include_str!("../probes/shadow_stack.c"),
        link_libs: &[],
        aux_libs: &[],
        // glibc's opt-in: glibc 2.39 and later enable the shadow stack for a marked program only
        // where the process sets this tunable, so without it the triple could never discriminate.
        run_environment: &[(
            "GLIBC_TUNABLES",
            "glibc.cpu.hwcaps=SHSTK:glibc.malloc.perturb=170",
        )],
        checks: &[Check {
            id: "shadow-stack-enforced",
            flag: "-fcf-protection=full (shadow stack enforced)",
            decoder: Decoder::Runtime {
                detect: detector!(detect_shadow_stack),
                reads: &[],
                // The fault is the CPU's and the shadow stack the kernel's: an emulator
                // answers from its own model.
                basis: RunBasis::Machine,
            },
            polarity: Polarity::Harden,
            observable: "the running program's shadow stack",
            levels: SHADOW_STACK_DEFAULT,
            confidence: Confidence::High,
            // `=full` rather than `=return`, the guide's ask and the positive control
            // `cet-marked` uses; both set the shadow-stack bit, and both read present under
            // gcc 16.1.1 and clang 22.1.8 at -O0 through -O3 and -Os (probe header).
            positive: &["-fcf-protection=full"],
            negative: &["-fcf-protection=none"],
            defects: &["return-oriented-programming"],
            observes: Observes::Protection,
            // Not the `cet` group, whose readers of the marking must agree: this reads the
            // running process, where an unmarked object loaded beside the program turns the
            // shadow stack off whatever the marking says.
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "SEGV_CPERR is raised by a control-protection fault and by nothing else.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // The probe reads x86 CET: `arch_prctl(ARCH_SHSTK_STATUS)`, `rdsspq` and
                // SEGV_CPERR, which Linux offers on x86_64 alone.
                arch: &["x86_64"],
                // musl has no shadow-stack support: in the Alpine edge image (musl 1.2.6,
                // gcc 15.2.0, clang 23.1.2) on the Fedora 44 kernel, a
                // `-fcf-protection=full` build read `features=0` with the pin set.
                libc_unsupported: &["musl"],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                // The kernel is part of the question: under a container it is the host's.
                needs_vm: true,
            },
            // The opt-in run is present only where the kernel reports the shadow stack
            // enabled, the shadow stack pointer is non-zero and an overwritten return address
            // faults with SEGV_CPERR.
            notes: "Enforcement rather than marking.",
        }],
    },
    Probe {
        id: "bti-enforced",
        title: "AArch64 BTI enforced for a program the toolchain built",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "bti_enforced.c",
        source: include_str!("../probes/bti_enforced.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "bti-enforced",
            flag: "-mbranch-protection=bti (BTI enforced)",
            decoder: Decoder::Runtime {
                detect: detector!(detect_bti_enforced),
                // The program's own property note: the detector says whether the build it ran
                // carried the BTI bit, which is what the kernel maps PROT_BTI from.
                reads: &[ElfTable::Notes],
                // The fault is the CPU's and the PROT_BTI mapping the kernel's: an emulator
                // answers from its own model, and qemu-user writes an ESR record for a BTI
                // fault that the hardware measured did not (`probes/chard_selfreport.h`).
                basis: RunBasis::Machine,
            },
            polarity: Polarity::Harden,
            observable: "whether an indirect branch to an instruction that is not a landing pad",
            levels: Levels::None,
            confidence: Confidence::High,
            // `=bti` rather than `=standard`: the landing pads and the BTI bit alone, so the
            // positive arm's program carries the marking this check needs and nothing else
            // from the flag.
            positive: &["-mbranch-protection=bti"],
            negative: &["-mbranch-protection=none"],
            defects: &["jump-oriented-programming"],
            observes: Observes::Protection,
            // Not the `branch-protection` group, whose readers of the marking must agree: this
            // reads the running process, which a kernel or CPU without BTI, or an unmarked
            // input, can set against a correct marking.
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a SIGILL ILL_ILLOPC at the probe's declared target.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // FEAT_BTI is aarch64's.
                arch: &["aarch64"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                // The kernel maps PROT_BTI: under a container it is the host's.
                needs_vm: true,
            },
            // Validated on an Oracle Cloud A2 (AmpereOne, Oracle Linux 10.2, gcc 14.3.1 and
            // clang 21.1.8, 2026-11-05): the triple discriminated in every cell, the build
            // passing `-mbranch-protection=standard` read `on` and the flagless one `off`.
            notes: "Enforcement rather than marking.",
        }],
    },
    Probe {
        id: "pac-ret-enforced",
        title: "AArch64 return-address authentication enforced for a program the toolchain built",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "pac_ret_enforced.c",
        source: include_str!("../probes/pac_ret_enforced.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "pac-ret-enforced",
            flag: "-mbranch-protection=pac-ret (return address authenticated)",
            decoder: Decoder::Runtime {
                detect: detector!(detect_pac_ret_enforced),
                reads: &[],
                // The fault is the CPU's and the keys the kernel's: an emulator answers from its
                // own model.
                basis: RunBasis::Machine,
            },
            polarity: Polarity::Harden,
            observable: "whether a function's return through its own overwritten saved return address dies by the fault reporter's PAC failure",
            levels: Levels::None,
            confidence: Confidence::High,
            // `=pac-ret` rather than `=standard`: the signing alone, so the positive arm carries
            // nothing else of the flag.
            positive: &["-mbranch-protection=pac-ret"],
            negative: &["-mbranch-protection=none"],
            defects: &["return-oriented-programming"],
            observes: Observes::Protection,
            // Not the `branch-protection` group, which holds readers of the marking that must
            // agree; this reads the running process.
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a SIGILL ILL_ILLOPN with an ESR record of exception class 0x1c is a pointer authentication failure and nothing else.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // FEAT_PAuth is aarch64's, and the probe's frame-record overwrite is AAPCS64's.
                arch: &["aarch64"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                // The kernel enables the keys: under a container it is the host's.
                needs_vm: true,
            },
            // Validated on an Oracle Cloud A2 (AmpereOne, Oracle Linux 10.2, gcc 14.3.1 and
            // clang 21.1.8, FEAT_FPAC present, 2026-11-05): the triple discriminated in every
            // cell, the build passing `-mbranch-protection=standard` read `on` and the flagless
            // one `off`.
            notes: "Enforcement rather than marking.",
        }],
    },
    Probe {
        id: "auto-var-init",
        title: "Automatic-variable initialization actually in force",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "auto_var_init.c",
        source: include_str!("../probes/auto_var_init.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[
            Check {
                id: "auto-var-init-active",
                flag: "-ftrivial-auto-var-init",
                decoder: Decoder::Runtime {
                    detect: detector!(detect_auto_var_init),
                    // The header's class: clang's pattern byte depends on pointer width.
                    reads: &[ElfTable::Header],
                    basis: RunBasis::Program,
                },
                polarity: Polarity::Harden,
                observable: "the byte read back from an uninitialized local in a \
                             deliberately pre-dirtied frame",
                levels: AUTO_VAR_FILL,
                confidence: Confidence::High,
                positive: &["-O1", "-ftrivial-auto-var-init=zero"],
                negative: &["-O1", "-ftrivial-auto-var-init=uninitialized"],
                defects: &["uninitialized-read"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::Arm(&["-ftrivial-auto-var-init=uninitialized"]),
                measures_toolchain_default: false,
                references: &[GUIDE, RSYNC_HARDENING, ALPINE_TSC_64],
                gate: PORTABLE,
                notes: "The flag that broke the rsync exploit chain.",
            },
            Check {
                id: "auto-var-init-pattern",
                flag: "-ftrivial-auto-var-init=pattern",
                decoder: Decoder::Runtime {
                    detect: detector!(detect_auto_var_init_pattern),
                    // The header's class: clang's pattern byte depends on pointer width.
                    reads: &[ElfTable::Header],
                    basis: RunBasis::Program,
                },
                polarity: Polarity::Harden,
                observable: "gcc's 0xFE pattern fill, or clang's",
                levels: PATTERN_FILL,
                confidence: Confidence::High,
                positive: &["-O1", "-ftrivial-auto-var-init=pattern"],
                negative: &["-O1", "-ftrivial-auto-var-init=uninitialized"],
                defects: &["uninitialized-read"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::Arm(&["-ftrivial-auto-var-init=uninitialized"]),
                measures_toolchain_default: false,
                references: &[GUIDE, RSYNC_HARDENING],
                gate: PORTABLE,
                notes: "Attributable on both compilers.",
            },
        ],
    },
    Probe {
        id: "implicit-function-declaration",
        title: "Is calling an undeclared function an error by default?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "implicit_function_declaration.c",
        source: include_str!("../probes/implicit_function_declaration.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "implicit-function-declaration-is-error",
            flag: "-Werror=implicit-function-declaration",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_implicit_function_declaration),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "compiler exit status and diagnostic text",
            levels: DIAG_ERROR,
            confidence: Confidence::High,
            positive: &["-Werror=implicit-function-declaration"],
            negative: &[
                "-Wno-implicit-function-declaration",
                "-Wno-error=implicit-function-declaration",
            ],
            defects: &["undeclared-call-mismatch"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is the compiler's own severity on the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "GCC 14 and Clang 16 made this an error by default.",
        }],
    },
    Probe {
        id: "cxx-stdlib-assertions",
        title: "C++ standard library precondition checks",
        lang: Lang::Cxx,
        link_mode: LinkMode::Executable,
        source_name: "cxx_assertions.cpp",
        source: include_str!("../probes/cxx_assertions.cpp"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[
            Check {
                id: "cxx-hardening-requested",
                flag: "-D_GLIBCXX_ASSERTIONS / -D_LIBCPP_HARDENING_MODE",
                decoder: Decoder::Macro(macro_channel::cxx_hardening_requested),
                polarity: Polarity::Harden,
                observable: "_GLIBCXX_ASSERTIONS or _LIBCPP_HARDENING_MODE",
                levels: LIBCPP_MODES,
                confidence: Confidence::High,
                // Both libraries' spellings in both arms, because a control has to work
                // on whichever library the guest ships and each ignores the other's
                // macro.
                positive: &[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
                ],
                negative: &[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ],
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "the observable is the _GLIBCXX_ASSERTIONS or _LIBCPP_HARDENING_MODE macro itself, set only by a -D of its name or by libstdc++'s own -O0 default.",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                defects: &["heap-buffer-overflow"],
                observes: Observes::Request,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "The macro half of the C++ pair.",
            },
            Check {
                id: "cxx-stdlib-assertions",
                flag: "-D_GLIBCXX_ASSERTIONS",
                decoder: Decoder::Runtime {
                    detect: detector!(detect_cxx_assertions),
                    reads: &[],
                    basis: RunBasis::Program,
                },
                polarity: Polarity::Harden,
                observable: "an out-of-range vector subscript reaching either the standard library's own failed-precondition message on an abort",
                levels: Levels::None,
                confidence: Confidence::High,
                // -U before -D so the measured profile cannot leave a stale definition
                // behind.
                positive: &[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
                ],
                // Both spellings in the negative arm, because the regime variant inherits
                // the measured profile's flags and every rpm distribution defines this
                // through `-Wp,`, which goes straight to the preprocessor.
                negative: &[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-Wp,-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    // libc++'s off switch.
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ],
                defects: &["heap-buffer-overflow"],
                observes: Observes::Protection,
                corroborates: None,
                // Mandatory.
                regime: Regime::Arm(&[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-Wp,-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ]),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "The probe uses the C++ driver.",
            },
            Check {
                id: "cxx-assertions-symbol",
                flag: "-D_GLIBCXX_ASSERTIONS (artifact symbol)",
                decoder: Decoder::ElfStatic(elf_static::cxx_assertions_symbol),
                polarity: Polarity::Harden,
                observable: "libstdc++'s assertion-failure symbol left in the artifact",
                levels: Levels::None,
                confidence: Confidence::High,
                // Both libraries' spellings, as each ignores the other's macro.
                positive: &[
                    "-O2",
                    "-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
                ],
                // The sibling's negative arm, spelling for spelling, for the same reasons.
                negative: &[
                    "-O2",
                    "-U_GLIBCXX_ASSERTIONS",
                    "-Wp,-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ],
                corroborates: Some("cxx-stdlib-assertions"),
                // libstdc++ 16 turns the assertions on whenever `__OPTIMIZE__` is undefined,
                // so an unoptimized profile over it publishes `on` for a library default.
                regime: Regime::Arm(&[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-Wp,-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ]),
                measures_toolchain_default: false,
                defects: &["heap-buffer-overflow"],
                observes: Observes::Protection,
                references: &[GUIDE],
                gate: Gate {
                    arch: &[],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    // libc++ has no `__glibcxx_assert_fail` to leave in an artifact, so
                    // neither control arm can move this observable.
                    cxx_stdlib_unsupported: &["libc++"],
                    needs_vm: false,
                },
                notes: "The artifact half of the pair `cxx-stdlib-assertions` trips at runtime.",
            },
        ],
    },
    Probe {
        id: "stack-clash",
        title: "Stack-clash protection: does a huge frame skip the guard page?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "stack_clash.c",
        source: include_str!("../probes/stack_clash.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "stack-clash-guard-page",
            flag: "-fstack-clash-protection",
            decoder: Decoder::Runtime {
                detect: detector!(detect_stack_clash),
                reads: &[],
                basis: RunBasis::Machine,
            },
            polarity: Polarity::Harden,
            observable: "how far below the frame the first touch lands when a frame far larger than the stack limit is allocated",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-fstack-clash-protection"],
            negative: &["-O2", "-fno-stack-clash-protection"],
            defects: &["stack-clash"],
            observes: Observes::Protection,
            corroborates: None,
            // `-fstack-check` produces the same observable by a different mechanism
            // and is *not* countermanded by `-fno-stack-clash-protection`, measured:
            // gcc -O2 -fstack-check -fno-stack-clash-protection still reports 12.
            regime: Regime::Arm(&["-fno-stack-clash-protection"]),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            // The measurements behind the notes.
            notes: "Measures where the fault lands rather than whether one happens.",
        }],
    },
    Probe {
        id: "format-security",
        title: "Does a non-literal format string stop the build?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "format_security.c",
        source: include_str!("../probes/format_security.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "format-security-is-error",
            flag: "-Werror=format-security",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_format_security),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "the compiler's severity on a printf-attributed call with a \
                         non-literal format and no format arguments",
            levels: DIAG_ERROR,
            confidence: Confidence::High,
            // -Wformat is mandatory in the positive arm: without it gcc discards
            // -Werror=format-security and fails at cc1 level with a message carrying
            // no source location, which is a build failure rather than a diagnostic.
            positive: &["-Wformat", "-Werror=format-security"],
            // The negative keeps the diagnostic and only lowers its severity, which is
            // what proves the detector reads severity rather than the presence of text.
            negative: &[
                "-Wformat",
                "-Wformat-security",
                "-Wno-error=format-security",
            ],
            defects: &["format-string"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is the compiler's own severity on the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "Reports whether a non-literal format stops this build.",
        }],
    },
    // ---- OpenSSF guide Table 1: strictly compile-time checks -------------------
    Probe {
        id: "warn-all",
        title: "Are the common-defect warnings enabled?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "warn_all.c",
        source: include_str!("../probes/warn_all.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "warn-all",
            flag: "-Wall",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_warn_all),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether an unused label draws a compiler diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wall"],
            negative: &["-Wno-all"],
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "-Wunused-label is the observable.",
        }],
    },
    Probe {
        id: "warn-extra",
        title: "Are the extra warnings beyond -Wall enabled?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "warn_extra.c",
        source: include_str!("../probes/warn_extra.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "warn-extra",
            flag: "-Wextra",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_warn_extra),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether comparing a signed with an unsigned operand draws a \
                         signedness-mismatch diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wextra"],
            negative: &["-Wno-extra"],
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "-Wsign-compare is in -Wextra for C on both compilers and in neither -Wall.",
        }],
    },
    Probe {
        id: "warn-format",
        title: "Are format-string arguments type-checked?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "warn_format.c",
        source: include_str!("../probes/warn_format.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "format-mismatch-warned",
            flag: "-Wformat",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_warn_format),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether an argument whose type does not match its conversion \
                         draws a diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wformat"],
            negative: &["-Wno-format"],
            defects: &["format-string"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "Weak evidence that the profile asked for -Wformat specifically.",
        }],
    },
    Probe {
        id: "warn-format-nonliteral",
        title: "Is a non-literal format string with arguments diagnosed?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "warn_format_nonliteral.c",
        source: include_str!("../probes/warn_format_nonliteral.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "format-nonliteral-warned",
            flag: "-Wformat=2",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_warn_format_nonliteral),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether a non-literal format string carrying format arguments \
                         draws a diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wformat", "-Wformat=2"],
            negative: &["-Wformat", "-Wno-format-nonliteral"],
            defects: &["format-string"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The construct carries an argument.",
        }],
    },
    Probe {
        id: "warn-conversion",
        title: "Are value-changing implicit conversions diagnosed?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "warn_conversion.c",
        source: include_str!("../probes/warn_conversion.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "conversion-warns-on-narrowing",
            flag: "-Wconversion",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_warn_conversion),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether narrowing an int to a char draws a value-change diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wconversion"],
            negative: &["-Wno-conversion"],
            defects: &["integer-overflow"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The source value is volatile so the compiler cannot prove the conversion safe and skip the warning.",
        }],
    },
    Probe {
        id: "warn-sign-conversion",
        title: "Are sign-changing implicit conversions diagnosed?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "warn_sign_conversion.c",
        source: include_str!("../probes/warn_sign_conversion.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "sign-conversion-warns-on-signedness-change",
            flag: "-Wsign-conversion",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_warn_sign_conversion),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether converting a negative int to unsigned draws a \
                         sign-change diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wsign-conversion"],
            negative: &["-Wno-sign-conversion"],
            defects: &["integer-overflow"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "NOT independent of conversion-warns-on-narrowing.",
        }],
    },
    Probe {
        id: "implicit-fallthrough",
        title: "Is an unannotated switch fall-through diagnosed?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "implicit_fallthrough.c",
        source: include_str!("../probes/implicit_fallthrough.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "implicit-fallthrough-warned",
            flag: "-Wimplicit-fallthrough",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_implicit_fallthrough),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether a switch case that falls through unannotated draws a \
                         diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wimplicit-fallthrough"],
            negative: &["-Wno-implicit-fallthrough"],
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The detector matches the message wording, never the option name. clang answers -Wimplicit-fallthrough=5, a spelling the Linux kernel and several distributions pass.",
        }],
    },
    Probe {
        id: "trampolines",
        title: "Is a stack trampoline diagnosed?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "trampolines.c",
        source: include_str!("../probes/trampolines.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "trampolines-warned",
            flag: "-Wtrampolines",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_trampolines),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether taking the address of a capturing nested function draws \
                         a trampoline diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wtrampolines"],
            negative: &["-Wno-trampolines"],
            defects: &["stack-code-execution"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // Nested functions are a GNU C extension clang does not implement, so
                // the probe cannot build there and there is no diagnostic to read.
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "A trampoline needs an executable stack.",
        }],
    },
    Probe {
        id: "bidi-chars",
        title: "Are misleading Unicode bidirectional controls diagnosed?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "bidi_chars.c",
        source: include_str!("../probes/bidi_chars.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "bidi-chars-any",
            flag: "-Wbidi-chars=any",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_bidi_chars),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "whether a balanced RLO/PDF override in a comment and a string \
                         literal draws a diagnostic",
            levels: DIAG_SEVERITY,
            confidence: Confidence::Medium,
            positive: &["-Wbidi-chars=any"],
            negative: &["-Wbidi-chars=none"],
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is whether the compiler diagnoses the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // clang has no equivalent option: it answers -Wbidi-chars=any with
                // "unknown warning option".
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The Trojan Source class: source that reads one way to a human and another to the compiler.",
        }],
    },
    Probe {
        id: "implicit-int",
        title: "Is a declaration with no type specifier an error?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "implicit_int.c",
        source: include_str!("../probes/implicit_int.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "implicit-int-is-error",
            flag: "-Werror=implicit-int",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_implicit_int),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "the compiler's severity on a declaration that specifies no type",
            levels: DIAG_ERROR,
            confidence: Confidence::High,
            positive: &["-Werror=implicit-int"],
            negative: &["-Wno-error=implicit-int"],
            defects: &["undeclared-call-mismatch"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is the compiler's own severity on the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The other half of the guide's -Werror=implicit umbrella.",
        }],
    },
    Probe {
        id: "incompatible-pointer-types",
        title: "Is an assignment between incompatible pointer types an error?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "incompatible_pointer_types.c",
        source: include_str!("../probes/incompatible_pointer_types.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "incompatible-pointer-types-is-error",
            flag: "-Werror=incompatible-pointer-types",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_incompatible_pointer_types),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "the compiler's severity on assigning between unrelated pointer \
                         types with no cast",
            levels: DIAG_ERROR,
            confidence: Confidence::High,
            positive: &["-Werror=incompatible-pointer-types"],
            negative: &["-Wno-error=incompatible-pointer-types"],
            defects: &["undeclared-call-mismatch"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is the compiler's own severity on the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "C only: gcc 8.4+ warns the option is not valid for C++.",
        }],
    },
    Probe {
        id: "int-conversion",
        title: "Is an implicit integer/pointer conversion an error?",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "int_conversion.c",
        source: include_str!("../probes/int_conversion.c"),
        link_libs: &[],
        aux_libs: &[],
        run_environment: &[],
        checks: &[Check {
            id: "int-conversion-is-error",
            flag: "-Werror=int-conversion",
            decoder: Decoder::CompilerDiag {
                detect: detector!(detect_int_conversion),
                reads: &[],
            },
            polarity: Polarity::Harden,
            observable: "the compiler's severity on initialising a pointer from an \
                         integer with no cast",
            levels: DIAG_ERROR,
            confidence: Confidence::High,
            positive: &["-Werror=int-conversion"],
            negative: &["-Wint-conversion", "-Wno-error=int-conversion"],
            defects: &["undeclared-call-mismatch"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is the compiler's own severity on the construct.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "C only, and a compiler floor on gcc 14 / clang 15 and later.",
        }],
    },
];

/// Refused at compile time ([`CORPUS`] is a `const`): a regime arm with no flags or with an
/// empty flag, or a reason for owing none that names no profile or toolchain.
/// `tests/regime_arms.rs` holds the profile ids, compiler names and checks owning an arm.
const _: () = {
    let mut probes = CORPUS;
    while let Some((probe, rest)) = probes.split_first() {
        let mut checks = probe.checks;
        while let Some((check, more)) = checks.split_first() {
            match check.regime {
                Regime::Arm(flags) => {
                    assert!(
                        !flags.is_empty(),
                        "a regime arm with no flags would re-run the measured build as its own negative"
                    );
                    let mut rest = flags;
                    while let Some((flag, more)) = rest.split_first() {
                        assert!(
                            !flag.is_empty(),
                            "a regime arm flag with no text countermands nothing"
                        );
                        rest = more;
                    }
                }
                Regime::NotOwed(specific) => {
                    assert!(
                        !specific.profiles.is_empty(),
                        "a reason for owing no regime arm names the profiles it was argued over"
                    );
                    assert!(
                        !specific.toolchains.is_empty(),
                        "a reason for owing no regime arm names the toolchains it was argued over"
                    );
                }
            }
            checks = more;
        }
        probes = rest;
    }
};

/// Number of checks across the corpus: the denominator for coverage accounting.
pub fn total_checks() -> usize {
    CORPUS.iter().map(|p| p.checks.len()).sum()
}

pub fn find(id: &str) -> Option<&'static Probe> {
    CORPUS.iter().find(|p| p.id == id)
}

/// The probe of this corpus that holds the check `check_id`, which fixes the language its
/// arms are built in.
#[must_use]
pub fn probe_of_check(check_id: &str) -> Option<&'static Probe> {
    CORPUS
        .iter()
        .find(|p| p.checks.iter().any(|c| c.id == check_id))
}

pub use crate::fingerprint::{DECODER_SOURCES, NOT_DECODER_SOURCES, decoder_code};

/// A predicate's canonical form, the one its digest and the corpus hash are taken over.
fn predicate_canonical(p: &Predicate) -> String {
    // `canonical` fails only on a map with a non-string key, which no predicate type has;
    // the error text is deterministic, so even that case hashes the same on every host.
    predicate::canonical(p).unwrap_or_else(|e| format!("unserializable predicate: {e}"))
}

/// The fingerprint over `language`, the predicates as `(check, predicate)` in corpus order,
/// and `sources_sha256`, the digest of the decoding source ([`decoder_sources_sha256`]). Each
/// part is framed by its length, so no two inputs share a canonical form.
#[must_use]
pub fn decoders_sha256_of(
    language: &str,
    predicates: &[(&str, &Predicate)],
    sources_sha256: &str,
) -> String {
    let mut canonical = String::new();
    let mut push = |s: &str| crate::fingerprint::frame(&mut canonical, s);
    push(language);
    for (check, p) in predicates {
        push(check);
        push(&predicate_canonical(p));
    }
    push(sources_sha256);
    digest::sha256_hex(canonical.as_bytes())
}

/// The fingerprint over the code that decides what a report says about a check: the
/// predicate language version, every check's predicate in corpus order, and the digest of
/// every file in [`DECODER_SOURCES`], comments and trailing unit tests stripped.
#[must_use]
pub fn decoders_sha256() -> String {
    static DIGEST: LazyLock<String> = LazyLock::new(|| {
        let predicates: Vec<(&str, &Predicate)> = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter_map(|c| c.predicate().map(|p| (c.id, p)))
            .collect();
        decoders_sha256_of(predicate::LANGUAGE, &predicates, decoder_sources_sha256())
    });
    DIGEST.clone()
}

/// The digest of [`crate::fingerprint::sources_canonical`] over every file of
/// [`DECODER_SOURCES`] as it was on disk when this binary was built: `build.rs` reads them
/// and stamps it, so the binary does not carry their text. `tests/decode_layout.rs` holds it
/// to the tree's files.
#[must_use]
pub const fn decoder_sources_sha256() -> &'static str {
    env!("CHARD_DECODER_SOURCES_SHA256")
}

/// Hash over the corpus so a report names the exact probe set that produced it, and the
/// decoders that read it: [`corpus_sha256_of`] over [`CORPUS`] and [`decoders_sha256`].
pub fn corpus_sha256() -> String {
    corpus_sha256_of(CORPUS, &decoders_sha256())
}

/// Hash over `corpus` and the decoder fingerprint `decoders_sha256`.
#[must_use]
pub fn corpus_sha256_of(corpus: &[Probe], decoders_sha256: &str) -> String {
    corpus_sha256_with(corpus, POSITIVE_INPUTS, decoders_sha256)
}

/// [`corpus_sha256_of`] with the positive arms' inputs given, so a test can move one.
#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive destructure per struct, read top to bottom"
)]
fn corpus_sha256_with(
    corpus: &[Probe],
    positive_inputs: &[PositiveInput],
    decoders_sha256: &str,
) -> String {
    let mut canonical = String::new();
    canonical.push_str(SELFREPORT_HEADER);
    let mut push = |s: &str| {
        canonical.push_str(s);
        canonical.push('\n');
    };
    // The decoders' code, once: the source every check's reading passes through.
    push(decoders_sha256);
    for probe in corpus {
        let Probe {
            id,
            // Prose, with `notes` below: neither reaches a compiler or a detector, so a
            // wording fix must not invalidate a sweep's comparability.
            title: _,
            // The driver and the linker invocation.
            lang,
            link_mode,
            source_name,
            source,
            link_libs,
            // Part of the invocation, not prose: the chain these build is what the final
            // link is asked to resolve through, so a change to one changes the question.
            aux_libs,
            // The environment the probe's runs receive beside the base list: a pin turns a
            // mechanism on or off under every arm, so a change to one changes the answer.
            run_environment,
            checks,
        } = probe;
        push(id);
        push(&format!("{lang:?}/{link_mode:?}"));
        push(source_name);
        push(source);
        push(&link_libs.join(" "));
        for (name, value) in *run_environment {
            push(&format!("env {name}={value}"));
        }
        for aux in *aux_libs {
            let AuxLib {
                stem,
                source_name,
                source,
                link_libs,
            } = aux;
            push(stem);
            push(source_name);
            push(source);
            push(&link_libs.join(" "));
        }
        for check in *checks {
            let Check {
                id,
                flag,
                // How the observation is read: the channel and the tables a cut withholds on.
                decoder,
                polarity,
                confidence,
                observable,
                // A rung added to a scale turns an `indeterminate` into a measurement, and a
                // moved ask turns `on` into `partial`.
                levels,
                positive,
                negative,
                corroborates,
                regime,
                measures_toolchain_default,
                gate,
                // Which `defect_coverage` entries the verdict is counted in: a change moves a
                // published status with no verdict moving.
                defects,
                // Moves every status `defect_coverage` derives from the verdict.
                observes,
                // Cited documents, not a verdict input; a report carries them verbatim, so a
                // difference shows without the corpus id moving.
                references: _,
                notes: _,
            } = check;
            push(id);
            push(flag);
            push(observes.as_str());
            push(&format!("defects {}", defects.join(" ")));
            push(&format!(
                "{:?}/{polarity:?}/{confidence:?}",
                decoder.channel()
            ));
            // Destructured to the last field so a member added to a variant fails to compile
            // here.
            push(decoder.kind());
            match decoder {
                Decoder::Macro(predicate) | Decoder::ElfStatic(predicate) => {
                    push(&predicate_canonical(predicate()));
                }
                Decoder::Runtime {
                    detect: Detector { name, detect: _ },
                    reads: _,
                    basis,
                } => {
                    push(name);
                    push(basis.as_str());
                }
                Decoder::CompilerDiag {
                    detect: Detector { name, detect: _ },
                    reads: _,
                } => push(name),
            }
            push(observable);
            push(levels.kind());
            push(&levels.words().join(" "));
            push(&levels.ungraded().join(" "));
            push(levels.grade().map_or("", |g| g.scale.kind()));
            push(levels.recommended().unwrap_or(""));
            push(corroborates.unwrap_or(""));
            push(&positive.join(" "));
            // Pushed only where a check has a row, so a check without one keeps its hash.
            for row in ARCH_CONTROLS.iter().filter(|row| row.check == *id) {
                push(&format!("{}: {}", row.arch, row.positive.join(" ")));
            }
            // The positive arm's own inputs, where a check has one.
            for input in positive_inputs.iter().filter(|row| row.check == *id) {
                let PositiveInput {
                    check: _,
                    source_name,
                    source,
                } = input;
                push(&format!("input {source_name}"));
                push(source);
            }
            push(&negative.join(" "));
            // A reason for owing no arm is prose: rewording it must not break comparability.
            match regime {
                Regime::Arm(flags) => push(&format!("regime {}", flags.join(" "))),
                Regime::NotOwed(_) => push(""),
            }
            push(if *measures_toolchain_default {
                "toolchain-default"
            } else {
                ""
            });
            // Gating decides `unsupported` versus a measurement.
            let Gate {
                arch,
                libc_unsupported,
                compiler_unsupported,
                cxx_stdlib_unsupported,
                needs_vm,
            } = gate;
            push(&arch.join(" "));
            push(&libc_unsupported.join(" "));
            push(&compiler_unsupported.join(" "));
            push(&cxx_stdlib_unsupported.join(" "));
            push(if *needs_vm { "vm" } else { "" });
            // Which tables can withhold the check; a predicate's are pushed again so every
            // check's line has the same shape.
            push(
                &check
                    .reads()
                    .iter()
                    .map(|t| t.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
    }
    digest::sha256_hex(canonical.as_bytes())
}

#[cfg(test)]
#[test]
fn the_shadow_stack_pins_witness_and_the_probes_fill_byte_agree() {
    let probe = CORPUS
        .iter()
        .find(|p| p.id == "shadow-stack")
        .expect("the shadow-stack probe is in the corpus");
    let pin = probe
        .run_environment
        .iter()
        .find(|(name, _)| *name == "GLIBC_TUNABLES")
        .map(|(_, value)| *value)
        .expect("the probe pins GLIBC_TUNABLES");
    let perturb: u8 = pin
        .split(':')
        .find_map(|t| t.strip_prefix("glibc.malloc.perturb="))
        .expect("the pin carries its witness tunable")
        .parse()
        .expect("a byte");
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/probes/shadow_stack.c"
    ))
    .expect("the probe's source");
    let fill = source
        .lines()
        .find_map(|l| l.strip_prefix("#define CHARD_PERTURB_FILL "))
        .expect("the probe names its fill byte");
    let fill = u8::from_str_radix(fill.trim().trim_start_matches("0x"), 16).expect("a hex byte");
    assert_eq!(perturb ^ 0xff, fill, "pin {pin}, fill {fill:#x}");
}

#[cfg(test)]
pub(crate) mod tests {
    #[test]
    fn every_macro_channel_probe_embeds_the_self_report() {
        let mut fed = 0_usize;
        for probe in CORPUS {
            if !probe.checks.iter().any(|c| c.channel() == Channel::Macro) {
                continue;
            }
            fed += 1;
            assert!(
                probe.embeds_self_report(),
                "{}: a macro-channel check with no `.chard.report` in {} would be withheld \
                 on every artifact",
                probe.id,
                probe.source_name
            );
            // `CHARD_EMIT_REPORT` defines the array; a mention of `chard_report` outside a
            // comment is a use of it, and `CHARD_PRINT_REPORT` expands to one.
            let code = without_c_comments(probe.source);
            let references =
                code.matches("chard_report").count() + code.matches("CHARD_PRINT_REPORT").count();
            assert!(
                references >= 1,
                "{}: {} embeds the section and never references `chard_report`, so a link \
                 under --gc-sections without `retain` drops it",
                probe.id,
                probe.source_name
            );
        }
        assert_eq!(fed, 3, "the macro-channel probes of the corpus");
    }

    #[test]
    fn no_probe_source_holds_a_comment_delimiter_in_a_string_literal() {
        let mut fed = 0_usize;
        for probe in CORPUS {
            if probe.source.is_empty() {
                continue;
            }
            fed += 1;
            for (number, line) in without_c_comments(probe.source).lines().enumerate() {
                let quotes = line
                    .replace("\\\"", "")
                    .replace("'\"'", "")
                    .matches('"')
                    .count();
                assert!(
                    quotes % 2 == 0,
                    "{}:{}: a string literal was cut by the comment scan, so the source \
                     holds `//` or `/*` inside a literal, which `Probe::embeds_self_report` \
                     and `every_macro_channel_probe_embeds_the_self_report` assume it does \
                     not: {line:?}",
                    probe.source_name,
                    number + 1
                );
            }
        }
        assert!(fed > 0, "no probe carries a source");
    }

    #[test]
    fn the_comment_scan_keeps_code_and_drops_prose() {
        use super::without_c_comments;

        let code = "/* chard_report in prose */\nputs(chard_report); // chard_report again\n";
        assert_eq!(without_c_comments(code), "\nputs(chard_report); \n");
        assert_eq!(
            without_c_comments("/* only prose: chard_report */")
                .matches("chard_report")
                .count(),
            0
        );
        assert_eq!(without_c_comments("int x; /* unterminated"), "int x; ");
        // `embeds_self_report` reads code the same way: a probe naming the macro in a
        // comment alone does not embed the section.
        let prose_only = Probe {
            source: "/* CHARD_EMIT_REPORT is not used here */\nint main(void) { return 0; }\n",
            ..CORPUS[0]
        };
        assert!(!prose_only.embeds_self_report());
        assert!(
            CORPUS
                .iter()
                .find(|p| p.id == "toolchain-macros")
                .expect("in the corpus")
                .embeds_self_report()
        );
    }

    #[test]
    fn every_probe_source_carries_its_languages_suffix() {
        let mut fed = 0_usize;
        for probe in CORPUS {
            if probe.source_name.is_empty() {
                continue;
            }
            fed += 1;
            let suffix = std::path::Path::new(probe.source_name)
                .extension()
                .and_then(|e| e.to_str());
            // `.S` is assembly the C driver preprocesses and assembles, so a C probe may
            // carry it (`linker-default-execstack` does); no C++ probe is assembly.
            let assembly = probe.lang == Lang::C && suffix == Some("S");
            assert!(
                assembly || suffix == Some(probe.lang.source_suffix()),
                "{}: {} for a {:?} probe",
                probe.id,
                probe.source_name,
                probe.lang
            );
        }
        assert!(
            CORPUS
                .iter()
                .any(|p| p.lang == Lang::Cxx && !p.source_name.is_empty()),
            "the corpus holds a C++ probe with a source, so the C++ suffix is read"
        );
        assert!(fed > 1, "the probes with a source were read: {fed}");
    }

    use std::collections::BTreeSet;

    use super::*;
    use crate::decode::diag::DIAG_CANARY;

    #[test]
    fn the_bearing_table_names_what_each_check_observes() {
        const REQUESTS: &[&str] = &["cxx-hardening-requested", "fortify-requested"];
        const MARKINGS: &[&str] = &[
            "branch-protection-macro",
            "branch-protection-marked",
            "cet-endbr-emitted",
            "cet-macro",
            "cet-marked",
            "cet-marked-object",
            "gcs-macro",
            "gcs-marked",
        ];
        let mut requests = Vec::new();
        let mut markings = Vec::new();
        for check in CORPUS.iter().flat_map(|p| p.checks) {
            match check.observes {
                Observes::Protection => continue,
                Observes::Request => requests.push(check.id),
                Observes::Marking => markings.push(check.id),
            }
            assert!(
                !check.defects.is_empty(),
                "{}: a request or marking that bears on no defect observes nothing a status reads",
                check.id
            );
            assert_eq!(
                check.polarity,
                Polarity::Harden,
                "{}: a request's or marking's word does not say which way a flag points, so \
                 its polarity is harden; the rollup keys it as written whatever the polarity (\
                 report::tests::the_recount_agrees_with_the_rollup_on_every_polarity_word_and_verdict\
                 ), and this holds the vocabulary",
                check.id
            );
        }
        requests.sort_unstable();
        markings.sort_unstable();
        assert_eq!(requests, REQUESTS);
        assert_eq!(markings, MARKINGS);
    }

    #[test]
    fn the_defects_no_check_observes_protection_against_are_named() {
        let protected = |defect: &str| {
            CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .any(|c| c.observes == Observes::Protection && c.defects.contains(&defect))
        };
        let none: Vec<&str> = DEFECTS
            .iter()
            .filter(|d| !protected(d.id))
            .map(|d| d.id)
            .collect();
        assert_eq!(none, Vec::<&str>::new());
        let jop = "jump-oriented-programming";
        let measured_on = |arch: &str| {
            CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .filter(|c| c.observes == Observes::Protection && c.defects.contains(&jop))
                .any(|c| {
                    crate::mechanism::decide(c.id, arch) == crate::mechanism::Decision::Measured
                })
        };
        assert_eq!(
            crate::mechanism::ARCHS
                .iter()
                .filter(|a| measured_on(a))
                .collect::<Vec<_>>(),
            [&"aarch64"],
            "the architectures {jop} has a measured protection check on"
        );
        // The class's own summary says so, beside the status in every report.
        for id in none {
            let summary = defect(id).expect("the class").summary;
            assert!(
                summary.contains("so this status is unknown in every report"),
                "{id}: the summary says why its status is unknown"
            );
        }
    }

    #[test]
    fn the_corpus_digest_moves_with_what_a_check_observes() {
        let decoders = decoders_sha256();
        let flipped = |o: Observes| match o {
            Observes::Protection => Observes::Request,
            Observes::Request | Observes::Marking => Observes::Protection,
        };
        let checks: Vec<Check> = CORPUS[0]
            .checks
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == 0 {
                    Check {
                        observes: flipped(c.observes),
                        ..*c
                    }
                } else {
                    Check { ..*c }
                }
            })
            .collect();
        let reclassed = Probe {
            checks: Box::leak(checks.into_boxed_slice()),
            ..CORPUS[0]
        };
        let corpus: Vec<Probe> = CORPUS
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if i == 0 {
                    Probe { ..reclassed }
                } else {
                    Probe { ..*p }
                }
            })
            .collect();
        assert_ne!(
            corpus_sha256_of(&corpus, &decoders),
            corpus_sha256_of(CORPUS, &decoders)
        );
    }

    #[test]
    fn the_null_deref_class_has_one_check() {
        let bearers: Vec<&str> = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.defects.contains(&"null-deref"))
            .map(|c| c.id)
            .collect();
        assert_eq!(bearers, ["no-delete-null-pointer-checks"]);
        assert!(defect("null-deref").is_some(), "the class");
    }

    #[test]
    fn channel_names_match_the_report() {
        let mut seen = BTreeSet::new();
        for channel in Channel::ALL {
            let json = serde_json::to_value(channel).expect("a channel serializes");
            assert_eq!(json.as_str(), Some(channel.as_str()), "{channel:?}");
            seen.insert(channel.as_str());
        }
        assert_eq!(seen.len(), Channel::ALL.len(), "four distinct names");
    }

    /// A check's reading of `ev` through its decoder, the check looked up by id.
    fn decode_as(id: &str, ev: &Evidence<'_>) -> Detection {
        CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("{id} is in the corpus"))
            .decode(ev)
            .detection
    }

    fn ssp_level(ev: &Evidence<'_>) -> Detection {
        decode_as("ssp-level", ev)
    }

    fn fortify_requested(ev: &Evidence<'_>) -> Detection {
        decode_as("fortify-requested", ev)
    }

    fn fortify_effective(ev: &Evidence<'_>) -> Detection {
        decode_as("fortify-effective", ev)
    }

    fn pie_macro(ev: &Evidence<'_>) -> Detection {
        decode_as("pie-macro", ev)
    }

    fn pic_macro(ev: &Evidence<'_>) -> Detection {
        decode_as("pic-macro", ev)
    }

    fn cet_macro(ev: &Evidence<'_>) -> Detection {
        decode_as("cet-macro", ev)
    }

    fn branch_protection_macro(ev: &Evidence<'_>) -> Detection {
        decode_as("branch-protection-macro", ev)
    }

    fn gcs_macro(ev: &Evidence<'_>) -> Detection {
        decode_as("gcs-macro", ev)
    }

    fn cxx_hardening_requested(ev: &Evidence<'_>) -> Detection {
        decode_as("cxx-hardening-requested", ev)
    }

    fn rpath_absent(ev: &Evidence<'_>) -> Detection {
        decode_as("rpath-absent", ev)
    }

    fn cxx_assertions_symbol(ev: &Evidence<'_>) -> Detection {
        decode_as("cxx-assertions-symbol", ev)
    }

    #[test]
    fn every_compiler_diag_check_is_in_the_needle_table_or_exempt_from_it() {
        let diag: BTreeSet<&str> = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.channel() == Channel::CompilerDiag)
            .map(|c| c.id)
            .collect();
        let tabled: BTreeSet<&str> = DIAG_NEEDLES.iter().map(|(id, _)| *id).collect();
        let exempt: BTreeSet<&str> = DIAG_NEEDLES_EXEMPT.iter().map(|(id, _)| *id).collect();
        assert_eq!(tabled.len(), DIAG_NEEDLES.len(), "a check is tabled twice");
        assert!(
            tabled.is_disjoint(&exempt),
            "a check is both tabled and exempt"
        );
        let covered: BTreeSet<&str> = tabled.union(&exempt).copied().collect();
        assert_eq!(covered, diag, "the needle table and the corpus disagree");
        assert!(DIAG_NEEDLES.iter().all(|(_, n)| !n.is_empty()));
    }

    /// The runtime detectors that read the ELF header's class, which picks clang's
    /// `=pattern` byte (`decode::runtime`'s `pattern_fill`).
    const CLASS_READERS: [&str; 2] = ["detect_auto_var_init", "detect_auto_var_init_pattern"];

    #[test]
    fn the_fill_detectors_declare_the_header_their_pattern_byte_reads() {
        let readers: Vec<&Check> = CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .filter(|c| {
                matches!(c.decoder, Decoder::Runtime { detect, .. } if CLASS_READERS.contains(&detect.name))
            })
            .collect();
        assert_eq!(readers.len(), 2, "both auto-var-init checks");
        for check in readers {
            assert_eq!(check.reads(), &[ElfTable::Header], "{}", check.id);
        }
    }

    #[test]
    fn the_ssp_function_map_probe_defines_every_function_its_predicate_reads() {
        let probe = CORPUS
            .iter()
            .find(|p| p.id == "ssp-function-map")
            .expect("the probe is in the corpus");
        // The four roll-called functions and the discriminator, each with the external it
        // calls: the five rows the predicate's table reads.
        let calls = elf_static::SSP_FUNCTIONS
            .iter()
            .zip(elf_static::SSP_CALLEES)
            .chain(std::iter::once((
                &elf_static::SSP_DISCRIMINATOR,
                elf_static::SSP_DISCRIMINATOR_CALLEE,
            )));
        for (name, callee) in calls {
            let head = format!(" int {name}(");
            let start = probe.source.find(&head).unwrap_or_else(|| {
                panic!(
                    "{name} is read by ssp-level-emitted's roll-call and not defined by {}",
                    probe.source_name
                )
            });
            let body = &probe.source[start..];
            let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
            assert!(
                body.contains(&format!("{callee}(")),
                "{name} does not call {callee}, which ssp-level-emitted's unread-calls clause \
                 requires it to refer to"
            );
            // Declared and never defined: a line naming the callee before its parameters
            // is a declaration, ending in `;`, so the object cannot resolve the call.
            let mentions: Vec<&str> = probe
                .source
                .lines()
                .filter(|l| !l.starts_with(' ') && l.contains(&format!(" {callee}(")))
                .collect();
            assert!(
                !mentions.is_empty() && mentions.iter().all(|l| l.trim_end().ends_with(");")),
                "{callee} is not declared without a definition in {}: {mentions:?}",
                probe.source_name
            );
        }
    }

    #[test]
    fn every_checks_tables_derive_from_its_decoder() {
        use std::collections::BTreeSet;

        let mut elf_static = 0usize;
        let mut self_report_readers = 0usize;
        let mut declared: BTreeSet<ElfTable> = BTreeSet::new();
        for check in CORPUS.iter().flat_map(|p| p.checks.iter()) {
            match check.decoder {
                Decoder::Macro(p) | Decoder::ElfStatic(p) => {
                    assert!(
                        std::ptr::eq(check.reads(), p().tables.as_slice()),
                        "{}: a predicate's tables are the check's",
                        check.id
                    );
                    if check.channel() == Channel::ElfStatic {
                        elf_static += 1;
                        assert!(
                            !check.reads().is_empty(),
                            "{}: an elf-static predicate with no table can never be \
                             withheld for a cut one",
                            check.id
                        );
                    } else {
                        assert!(
                            check.reads().is_empty(),
                            "{}: a macro reads no table",
                            check.id
                        );
                    }
                }
                Decoder::Runtime { detect, reads, .. } => {
                    assert!(std::ptr::eq(check.reads(), reads));
                    // A detector reading the self-report through `fortify_impl` reads the section
                    // names that reach it; the BTI detector reads the program's own property
                    // note; the class readers are held below; every other reads none.
                    let expected: &[ElfTable] = match detect.name {
                        "detect_fortify_runtime" | "detect_strict_flex_arrays_enforced" => {
                            self_report_readers += 1;
                            &[ElfTable::SectionNames]
                        }
                        "detect_bti_enforced" => &[ElfTable::Notes],
                        name if CLASS_READERS.contains(&name) => reads,
                        _ => &[],
                    };
                    assert_eq!(
                        reads, expected,
                        "{}: a runtime detector reads the tables its reading needs and no other",
                        check.id
                    );
                }
                Decoder::CompilerDiag { detect, reads } => {
                    // Only `detect_pic_shared_link` reads the artifact, through `DT_TEXTREL`.
                    let dynamic = usize::from(detect.name == "detect_pic_shared_link");
                    assert_eq!(reads, &[ElfTable::Dynamic][..dynamic], "{}", check.id);
                }
            }
            let distinct: BTreeSet<ElfTable> = check.reads().iter().copied().collect();
            assert_eq!(
                distinct.len(),
                check.reads().len(),
                "{}: a table is declared twice: {:?}",
                check.id,
                check.reads()
            );
            for table in check.reads() {
                assert!(
                    ElfTable::SOFT_SITES.contains(table) || ElfTable::HARD_FAILURES.contains(table),
                    "{}: {table:?} has neither a recording site nor a hard failure in parse, \
                     so declaring it is inert",
                    check.id
                );
                declared.insert(*table);
            }
        }
        assert!(
            elf_static > 0,
            "no elf-static check in the corpus, so this test held nothing"
        );
        assert_eq!(
            self_report_readers, 4,
            "the three runtime fortify checks and strict-flex-arrays-enforced read the \
             self-report through `fortify_impl`"
        );
        // The partition itself: the two lists cover the enum without overlap.
        let soft: BTreeSet<ElfTable> = ElfTable::SOFT_SITES.iter().copied().collect();
        let hard: BTreeSet<ElfTable> = ElfTable::HARD_FAILURES.iter().copied().collect();
        assert!(
            soft.is_disjoint(&hard),
            "a table cannot both record and refuse: {:?}",
            soft.intersection(&hard).collect::<Vec<_>>()
        );
        let all: BTreeSet<ElfTable> = ElfTable::ALL.iter().copied().collect();
        assert_eq!(&soft | &hard, all, "every table is on exactly one list");
        eprintln!(
            "{elf_static} elf-static checks declare {} distinct tables",
            declared.len()
        );
    }

    #[test]
    fn a_stated_pic_choice_is_not_overridden_by_the_shared_object_default() {
        let none: Vec<String> = Vec::new();
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&none),
            vec!["-shared", "-fPIC"],
            "a bare profile still needs -fPIC or the library will not link"
        );

        // Every spelling `conflicts_with` knows plus every spelling this knows, because a
        // partial match here is a silent override.
        for stated in [
            "-fno-pic", "-fno-PIC", "-fPIC", "-fpic", "-fPIE", "-fpie", "-fno-pie", "-fno-PIE",
        ] {
            let flags = vec![stated.to_owned()];
            assert_eq!(
                LinkMode::SharedObject.extra_flags(&flags),
                vec!["-shared"],
                "`{stated}` states a choice, so chard must not append its own -fPIC after it"
            );
        }

        // An unrelated flag is not a choice about position independence.
        let unrelated = vec!["-O2".to_owned()];
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&unrelated),
            vec!["-shared", "-fPIC"]
        );

        // Executables get nothing added in any case.
        assert!(
            LinkMode::Executable.extra_flags(&none).is_empty(),
            "an executable gets no flag added: {:?}",
            LinkMode::Executable.extra_flags(&none)
        );
    }

    #[test]
    fn every_boundary_matches_a_check_and_every_dependent_protection_has_one() {
        let flags: Vec<&str> = CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .map(|c| c.flag)
            .collect();

        for (key, boundary) in BOUNDARIES {
            assert!(
                flags.iter().any(|f| f.starts_with(key)),
                "`{key}` is in BOUNDARIES and no check's flag starts with it, so it can never \
                 attach to an observation"
            );
            assert!(
                !boundary.requires_at_runtime.is_empty(),
                "`{key}` declares a boundary with nothing required, which is what omitting it \
                 already means"
            );
            assert!(
                !boundary.establishes.is_empty(),
                "`{key}` says what it does not establish without saying what it does"
            );
        }

        // The other direction: these protections depend on something outside the file.
        for needs in ["-fPIE", "-fcf-protection", "-Wl,-z,noexecstack"] {
            assert!(
                boundary_for(needs).is_some(),
                "{needs} takes effect only with kernel, CPU or libc cooperation, and an \
                 observation with no boundary asserts that nothing outside the artifact matters"
            );
        }

        // The lookup is a prefix match and takes the first key that matches, so a check
        // whose flag extends another's key inherits that key's boundary unless a longer key
        // sits ahead of it.
        let pads = CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .find(|c| c.id == "cet-endbr-emitted")
            .expect("the cet-endbr-emitted check");
        let pads = boundary_for(pads.flag).expect("a landing-pad boundary");
        assert!(
            pads.establishes.contains("landing pads") && !pads.establishes.contains("note"),
            "cet-endbr-emitted publishes the note's boundary: {}",
            pads.establishes
        );
        assert!(
            boundary_for("-fcf-protection=full (artifact markings)")
                .is_some_and(|b| b.establishes.contains("note")),
            "the marking checks keep the note's boundary"
        );

        // And the negative case, which is the one that makes absence readable: a canary is
        // enforced by the artifact itself, so it must *not* acquire a boundary by accident.
        assert!(
            boundary_for("-fstack-protector-strong").is_none(),
            "a stack canary needs nothing outside the binary; giving it a boundary would make \
             the field's absence mean nothing at all"
        );
    }

    #[test]
    fn every_check_id_is_unique() {
        let mut seen = BTreeSet::new();
        for probe in CORPUS {
            for check in probe.checks {
                assert!(seen.insert(check.id), "duplicate check id: {}", check.id);
            }
        }
    }

    #[test]
    fn every_probe_needing_a_build_has_a_source() {
        for probe in CORPUS {
            if probe.needs_build() {
                assert!(
                    !probe.source.is_empty(),
                    "{} needs a build but has no source",
                    probe.id
                );
                assert!(
                    !probe.source_name.is_empty(),
                    "{} has no source name",
                    probe.id
                );
            }
        }
    }

    #[test]
    fn every_channel_states_whether_it_needs_a_build_and_a_run() {
        for (channel, needs_build, needs_run) in [
            (Channel::Macro, false, false),
            (Channel::ElfStatic, true, false),
            (Channel::Runtime, true, true),
            (Channel::CompilerDiag, true, false),
        ] {
            assert_eq!(
                channel.needs_build(),
                needs_build,
                "{channel:?} answered the wrong way about needing an artifact"
            );
            assert_eq!(
                channel.needs_run(),
                needs_run,
                "{channel:?} answered the wrong way about needing to be executed"
            );
        }
    }

    #[test]
    fn a_macro_only_probe_is_still_built_and_a_sourceless_one_is_not() {
        let macro_only = find("toolchain-macros").expect("the probe is in the corpus");
        assert!(
            macro_only
                .checks
                .iter()
                .all(|c| c.channel() == Channel::Macro),
            "this test is about the all-macro probe; its channels have changed"
        );
        assert!(
            macro_only.needs_build(),
            "a macro-only probe that is not built reads `cc -dM -E` instead of the \
             artifact, which is a different compiler job"
        );

        for probe in CORPUS {
            assert!(probe.needs_build(), "{} is never built", probe.id);
        }

        let sourceless = Probe {
            id: "sourceless-macro-probe",
            title: "not a corpus probe: the shape needs_build must answer false for",
            lang: Lang::C,
            link_mode: LinkMode::Executable,
            source_name: "",
            source: "",
            link_libs: &[],
            aux_libs: &[],
            run_environment: &[],
            checks: macro_only.checks,
        };
        assert!(
            !sourceless.needs_build(),
            "with no source and nothing but macro checks there is nothing to build"
        );
    }

    #[test]
    fn only_an_executable_with_a_runtime_check_is_executed() {
        let with_runtime = find("stack-clash").expect("the probe is in the corpus");
        assert!(
            with_runtime.needs_run(),
            "an executable with a runtime check has to be executed or the channel is blind"
        );

        let elf_only = find("link-defaults").expect("the probe is in the corpus");
        assert!(
            elf_only
                .checks
                .iter()
                .all(|c| c.channel() != Channel::Runtime),
            "this test is about a probe with no runtime check; its channels have changed"
        );
        assert!(
            !elf_only.needs_run(),
            "running an artifact no check reads costs a process and answers nothing"
        );

        // The claim the corpus cannot make: a shared object declaring a runtime check.
        let shared_with_runtime = Probe {
            id: "shared-object-with-a-runtime-check",
            title: "not a corpus probe: the shape needs_run must answer false for",
            lang: Lang::C,
            link_mode: LinkMode::SharedObject,
            source_name: with_runtime.source_name,
            source: with_runtime.source,
            link_libs: &[],
            aux_libs: &[],
            run_environment: &[],
            checks: with_runtime.checks,
        };
        assert!(
            !shared_with_runtime.needs_run(),
            "a shared object has no entry point; declaring a runtime check does not make \
             it executable"
        );
    }

    #[test]
    fn every_positive_input_is_a_linking_checks_own_root() {
        let mut names: BTreeSet<&str> = CORPUS
            .iter()
            .map(|p| p.source_name)
            .chain(
                CORPUS
                    .iter()
                    .flat_map(|p| p.aux_libs)
                    .map(|a| a.source_name),
            )
            .chain([SELFREPORT_HEADER_NAME])
            .collect();
        for row in POSITIVE_INPUTS {
            let (probe, check) = CORPUS
                .iter()
                .find_map(|p| p.checks.iter().find(|c| c.id == row.check).map(|c| (p, c)))
                .unwrap_or_else(|| panic!("{} is not a check in the corpus", row.check));
            assert!(
                matches!(
                    probe.link_mode,
                    LinkMode::Executable | LinkMode::SharedObject
                ),
                "{}: an input for a probe that does not link",
                row.check
            );
            assert!(
                names.insert(row.source_name),
                "{}: {} is another source's name",
                row.check,
                row.source_name
            );
            let code = without_c_comments(row.source);
            let roots: Vec<&str> = check
                .positive
                .iter()
                .filter_map(|word| word.strip_prefix("-Wl,-u,"))
                .collect();
            assert!(
                !roots.is_empty()
                    && roots
                        .iter()
                        .all(|sym| code.contains(&format!(".globl {sym}\\n"))),
                "{}: the positive list roots {roots:?}, which {} does not define",
                row.check,
                row.source_name
            );
            // A per-architecture positive list replaces the default one on its
            // architecture, so it carries the same roots, or that arm links the input
            // with nothing keeping its section.
            for arch_row in ARCH_CONTROLS.iter().filter(|r| r.check == row.check) {
                for sym in &roots {
                    let root = format!("-Wl,-u,{sym}");
                    assert!(
                        arch_row.positive.contains(&root.as_str()),
                        "{} on {}: the positive list drops {root}",
                        row.check,
                        arch_row.arch
                    );
                }
            }
            assert_eq!(check.positive_inputs().len(), 1, "{}", row.check);
        }
        assert!(
            !POSITIVE_INPUTS.is_empty(),
            "the table is empty, and this test holds nothing"
        );
        let without: usize = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.positive_inputs().is_empty())
            .count();
        assert_eq!(without, total_checks() - POSITIVE_INPUTS.len());
    }

    #[test]
    fn no_probe_source_tests_a_chard_macro_it_does_not_define() {
        // Directives with their backslash continuations joined, so a test split over lines
        // is read whole.
        let directives = |source: &str| -> Vec<String> {
            without_c_comments(source)
                .replace("\\\n", " ")
                .lines()
                .filter_map(|l| l.trim_start().strip_prefix('#'))
                .map(|d| d.trim_start().to_owned())
                .collect()
        };
        let defines = |source: &str| -> BTreeSet<String> {
            directives(source)
                .iter()
                .filter_map(|d| {
                    let name = d.strip_prefix("define")?.split_whitespace().next()?;
                    Some(name.split('(').next().unwrap_or(name).to_owned())
                })
                .collect()
        };
        let tested = |source: &str| -> Vec<String> {
            directives(source)
                .iter()
                .filter(|d| {
                    ["if", "ifdef", "ifndef", "elif"]
                        .iter()
                        .any(|kind| d.starts_with(kind))
                })
                .flat_map(|d| {
                    d.match_indices("CHARD_")
                        .map(|(at, _)| {
                            d[at..]
                                .chars()
                                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                                .collect::<String>()
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let sources: Vec<(&str, &str)> = CORPUS
            .iter()
            .map(|p| (p.source_name, p.source))
            .chain(
                CORPUS
                    .iter()
                    .flat_map(|p| p.aux_libs)
                    .map(|a| (a.source_name, a.source)),
            )
            .chain(POSITIVE_INPUTS.iter().map(|r| (r.source_name, r.source)))
            .collect();
        let mut read = 0usize;
        for (name, source) in &sources {
            let own = defines(source);
            for word in tested(source) {
                read += 1;
                assert!(
                    own.contains(&word),
                    "{name} tests {word} and does not define it, so only a command line does: \
                     a switch a profile can turn on in the measured build alone"
                );
            }
        }
        // The header's own guard, and its opt-ins: each one a probe defines before it
        // includes the header.
        let header_own = defines(SELFREPORT_HEADER);
        let opted: BTreeSet<String> = sources.iter().flat_map(|(_, s)| defines(s)).collect();
        for word in tested(SELFREPORT_HEADER) {
            read += 1;
            assert!(
                header_own.contains(&word)
                    || (word.starts_with("CHARD_WANT_") && opted.contains(&word)),
                "{SELFREPORT_HEADER_NAME} tests {word}, which is neither its own nor an opt-in \
                 a probe defines"
            );
        }
        assert!(
            read > 0,
            "the scan read no CHARD_ test, so it holds nothing"
        );
    }

    #[test]
    fn the_corpus_digest_moves_with_a_positive_input() {
        let decoders = decoders_sha256();
        let base = corpus_sha256_with(CORPUS, POSITIVE_INPUTS, &decoders);
        assert_eq!(base, corpus_sha256_of(CORPUS, &decoders));
        let row = &POSITIVE_INPUTS[0];
        let retexted = [PositiveInput {
            check: row.check,
            source_name: row.source_name,
            source: "/* moved */",
        }];
        let renamed = [PositiveInput {
            check: row.check,
            source_name: "other.c",
            source: row.source,
        }];
        assert_ne!(base, corpus_sha256_with(CORPUS, &retexted, &decoders));
        assert_ne!(base, corpus_sha256_with(CORPUS, &renamed, &decoders));
        assert_ne!(base, corpus_sha256_with(CORPUS, &[], &decoders));
    }

    #[test]
    fn the_corpus_digest_moves_with_a_checks_defects() {
        let decoders = decoders_sha256();
        let base = corpus_sha256_of(CORPUS, &decoders);
        let (at, probe) = CORPUS
            .iter()
            .enumerate()
            .find(|(_, p)| p.checks.iter().any(|c| c.defects.len() > 1))
            .expect("a check bearing two defects");
        let i = probe
            .checks
            .iter()
            .position(|c| c.defects.len() > 1)
            .expect("the check");
        let declared = probe.checks[i].defects;
        let mut reversed = declared.to_vec();
        reversed.reverse();
        let mut added = declared.to_vec();
        added.push("library-injection");
        for defects in [&declared[1..], &added[..], &reversed[..]] {
            let defects: &'static [&'static str] = Box::leak(defects.to_vec().into_boxed_slice());
            let checks: Vec<Check> = (0..probe.checks.len())
                .map(|k| {
                    let check = Check { ..probe.checks[k] };
                    if k == i {
                        Check { defects, ..check }
                    } else {
                        check
                    }
                })
                .collect();
            let checks: &'static [Check] = Box::leak(checks.into_boxed_slice());
            let corpus: Vec<Probe> = (0..CORPUS.len())
                .map(|k| {
                    if k == at {
                        Probe {
                            checks,
                            ..CORPUS[k]
                        }
                    } else {
                        Probe { ..CORPUS[k] }
                    }
                })
                .collect();
            assert_ne!(
                base,
                corpus_sha256_of(&corpus, &decoders),
                "{defects:?} in place of {declared:?}"
            );
        }
    }

    #[test]
    fn every_check_has_a_positive_control() {
        for probe in CORPUS {
            for check in probe.checks {
                assert!(
                    !check.positive.is_empty(),
                    "{} has no positive control and could never be validated",
                    check.id
                );
            }
        }
    }

    #[test]
    fn every_arch_control_names_an_architecture_its_gate_admits() {
        let mut seen = BTreeSet::new();
        for row in ARCH_CONTROLS {
            let check = CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .find(|c| c.id == row.check)
                .unwrap_or_else(|| panic!("{} is not a check in the corpus", row.check));
            assert!(
                check.gate.arch.contains(&row.arch),
                "{}: a control for {} under a gate of {:?}",
                row.check,
                row.arch,
                check.gate.arch
            );
            assert!(!row.positive.is_empty(), "{}: an empty control", row.check);
            assert_ne!(row.positive, check.positive, "{}: no override", row.check);
            assert!(
                seen.insert((row.check, row.arch)),
                "{} on {} twice",
                row.check,
                row.arch
            );
            assert_eq!(check.positive_for(row.arch), row.positive);
        }
        assert!(
            !seen.is_empty(),
            "the table is empty, and this test holds nothing"
        );
    }

    #[test]
    fn an_architecture_without_a_row_uses_the_default_control() {
        let mut arches: BTreeSet<&str> = [
            "x86_64",
            "x86",
            "aarch64",
            "riscv64",
            "powerpc64le",
            "s390x",
        ]
        .into_iter()
        .collect();
        arches.extend(
            CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .flat_map(|c| c.gate.arch),
        );
        let mut defaulted = 0usize;
        for check in CORPUS.iter().flat_map(|p| p.checks) {
            for arch in &arches {
                if ARCH_CONTROLS
                    .iter()
                    .any(|row| row.check == check.id && row.arch == *arch)
                {
                    continue;
                }
                assert_eq!(
                    check.positive_for(arch),
                    check.positive,
                    "{} on {arch}",
                    check.id
                );
                defaulted = defaulted.saturating_add(1);
            }
        }
        let textrel = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == "textrel-absent")
            .expect("textrel-absent is in the corpus");
        assert_eq!(textrel.positive_for("x86_64"), textrel.positive);
        assert_ne!(textrel.positive_for("x86"), textrel.positive);
        assert!(defaulted > 0);
    }

    /// `text`, a C source, with every comment and every string and character literal
    /// blanked to spaces and its newlines kept, so line `n` of the result is line `n` of
    /// `text` and a word left in it is code. A comment or literal still open at the end
    /// panics, which is how a lexer that lost its place shows.
    pub(crate) fn c_code_only(name: &str, text: &str) -> String {
        let s: Vec<char> = text.chars().collect();
        let mut out = s.clone();
        let mut i = 0;
        while i < s.len() {
            let start = i;
            let at = |k: usize| s.get(i + k).copied();
            if s[i] == '/' && at(1) == Some('/') {
                while i < s.len() && s[i] != '\n' {
                    i += 1;
                }
            } else if s[i] == '/' && at(1) == Some('*') {
                i += 2;
                loop {
                    match (s.get(i), s.get(i + 1)) {
                        (Some('*'), Some('/')) => break i += 2,
                        (Some(_), _) => i += 1,
                        (None, _) => panic!("{name}: a comment at char {start} is not closed"),
                    }
                }
            } else if s[i] == '"' || s[i] == '\'' {
                let quote = s[i];
                i += 1;
                loop {
                    match s.get(i) {
                        Some('\\') => i += 2,
                        Some(c) if *c == quote => break i += 1,
                        Some('\n') | None => {
                            panic!("{name}: a literal at char {start} is not closed")
                        }
                        Some(_) => i += 1,
                    }
                }
            } else {
                i += 1;
                continue;
            }
            for c in out.iter_mut().take(i.min(s.len())).skip(start) {
                if *c != '\n' {
                    *c = ' ';
                }
            }
        }
        out.into_iter().collect()
    }

    /// The canary's one working form: a local that nothing reads and no attribute excuses.
    const CANARY_DECLARATION: &str = "int chard_canary_unused = 0;";

    /// The in-source pragma that pins the canary to warning severity, so it fires with no
    /// `-Wall` and survives `-Werror` as a warning.
    const CANARY_PRAGMA: &str = "#pragma GCC diagnostic warning \"-Wunused-variable\"";

    /// Compiler-diag probes whose canary fires without [`CANARY_PRAGMA`], and why.
    const CANARY_WITHOUT_PRAGMA: &[(&str, &str)] = &[(
        "hardened-downgrade",
        "both control arms pass -Wall, which turns -Wunused-variable on, as the probe's \
         comment argues",
    )];

    /// The preprocessor directive a line of code (comments and literals blanked) opens, as
    /// its word (`pragma`, `if`, `define`), allowing the spaces C allows around the `#`.
    fn directive(code_line: &str) -> Option<&str> {
        let rest = code_line.trim_start().strip_prefix('#')?.trim_start();
        let end = rest
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }

    /// The directives in `source` (`code` its [`c_code_only`]) whose effect a line-by-line
    /// reading cannot see: a linemarker, which can mark the rest of the file a system
    /// header and silence its warnings, and a directive continued onto the next line.
    fn unreadable_directives(source: &str, code: &str) -> Vec<String> {
        let mut faults = Vec::new();
        for (raw, line) in source.lines().zip(code.lines()) {
            let after_hash = line.trim_start().strip_prefix('#').map(str::trim_start);
            if after_hash.is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit())) {
                faults.push(format!(
                    "`{}` is a linemarker, which can mark the rest of the file a system header \
                     and silence its warnings",
                    raw.trim()
                ));
            }
            if after_hash.is_some() && line.trim_end().ends_with('\\') {
                faults.push(format!(
                    "`{}` continues a directive onto the next line, where this reading cannot \
                     follow it",
                    raw.trim()
                ));
            }
        }
        faults
    }

    /// Each line of `code`'s depth in preprocessor conditionals and in braces, as it begins.
    fn line_depths(code: &str) -> Vec<(usize, usize)> {
        let mut depth = Vec::new();
        let (mut conditionals, mut braces) = (0usize, 0usize);
        for line in code.lines() {
            depth.push((conditionals, braces));
            match directive(line) {
                Some("if" | "ifdef" | "ifndef") => conditionals += 1,
                Some("endif") => conditionals = conditionals.saturating_sub(1),
                _ => {}
            }
            for c in line.chars() {
                match c {
                    '{' => braces += 1,
                    '}' => braces = braces.saturating_sub(1),
                    _ => {}
                }
            }
        }
        depth
    }

    /// Why `source` cannot carry a working canary, one line per fault; empty when it can.
    fn canary_faults(name: &str, source: &str, pragma_exempt: bool) -> Vec<String> {
        let code = c_code_only(name, source);
        let mut faults = Vec::new();
        let uses = code.matches(DIAG_CANARY).count();
        if uses != 1 {
            faults.push(format!(
                "the canary's name appears {uses} times in code, where only its declaration \
                 may: any other use (a cast to void, an assignment, a read) silences it"
            ));
        }
        let declared_at = code.lines().position(|l| l.trim() == CANARY_DECLARATION);
        if declared_at.is_none() {
            faults.push(format!("no line of code is exactly `{CANARY_DECLARATION}`"));
        }
        let words: Vec<&str> = code
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .collect();
        for excuse in ["unused", "__unused__", "maybe_unused", "__maybe_unused__"] {
            if words.contains(&excuse) {
                faults.push(format!(
                    "the attribute `{excuse}` appears in code, which excuses the canary"
                ));
            }
        }
        if words.contains(&"_Pragma") {
            faults.push(
                "`_Pragma` appears in code, which can change the canary's warning with no \
                 `#pragma` line to show it"
                    .to_owned(),
            );
        }
        let pragmas: Vec<(usize, &str)> = source
            .lines()
            .zip(code.lines())
            .enumerate()
            .filter(|(_, (_, c))| directive(c) == Some("pragma"))
            .map(|(n, (raw, _))| (n, raw.trim()))
            .collect();
        for (_, raw) in &pragmas {
            if (raw.contains("diagnostic") || raw.contains("unused")) && *raw != CANARY_PRAGMA {
                faults.push(format!(
                    "`{raw}` changes diagnostics other than to pin the canary"
                ));
            }
        }
        faults.extend(unreadable_directives(source, &code));
        let depth = line_depths(&code);
        if let Some(&(conditional, brace)) = declared_at.and_then(|d| depth.get(d)) {
            if conditional > 0 {
                faults.push(
                    "the declaration sits inside a preprocessor conditional, which can \
                     compile it out"
                        .to_owned(),
                );
            }
            if brace == 0 {
                faults.push(
                    "the declaration is at file scope, where an unused variable draws no \
                     warning"
                        .to_owned(),
                );
            }
        }
        if !pragma_exempt {
            let pinned_at = pragmas
                .iter()
                .find(|(_, raw)| *raw == CANARY_PRAGMA)
                .map(|(n, _)| *n);
            match (pinned_at, declared_at) {
                (Some(p), Some(d)) if p < d => {}
                (Some(_), Some(_)) => faults.push("the pin follows the declaration".to_owned()),
                (None, _) => faults.push(format!("no `{CANARY_PRAGMA}` line pins the canary")),
                (Some(_), None) => {}
            }
            if pinned_at
                .and_then(|p| depth.get(p))
                .is_some_and(|(c, _)| *c > 0)
            {
                faults.push(
                    "the pin sits inside a preprocessor conditional, which can compile it out"
                        .to_owned(),
                );
            }
        }
        faults
    }

    #[test]
    fn every_compiler_diag_probe_carries_the_canary() {
        let exempt: BTreeSet<&str> = CANARY_WITHOUT_PRAGMA.iter().map(|(id, _)| *id).collect();
        let mut held = 0usize;
        let mut problems = Vec::new();
        for probe in CORPUS {
            if probe
                .checks
                .iter()
                .any(|c| c.channel() == Channel::CompilerDiag)
            {
                held += 1;
                for fault in
                    canary_faults(probe.source_name, probe.source, exempt.contains(probe.id))
                {
                    problems.push(format!("{}: {fault}", probe.id));
                }
            } else if c_code_only(probe.source_name, probe.source).contains(DIAG_CANARY) {
                problems.push(format!(
                    "{}: declares the canary and has no compiler-diag check, so nothing here \
                     holds it",
                    probe.id
                ));
            }
        }
        for id in &exempt {
            let probe = CORPUS
                .iter()
                .find(|p| p.id == *id)
                .unwrap_or_else(|| panic!("{id} is exempted from the pin and is not a probe"));
            for check in probe.checks {
                for control in [check.positive, check.negative] {
                    assert!(
                        control.contains(&"-Wall")
                            && !control.contains(&"-w")
                            && !control.contains(&"-Wno-unused-variable")
                            && !control.contains(&"-Wno-unused")
                            && !control.contains(&"-Wno-all"),
                        "{id} is exempted from the pin because its controls pass -Wall and \
                         nothing that takes -Wunused-variable back, and {}'s {control:?} do not",
                        check.id
                    );
                }
            }
        }
        let header = c_code_only(SELFREPORT_HEADER_NAME, SELFREPORT_HEADER);
        if header.lines().any(|l| directive(l) == Some("pragma"))
            || header
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|w| w == "_Pragma")
        {
            problems.push(format!(
                "{SELFREPORT_HEADER_NAME}: a pragma in the header every probe includes could \
                 silence every canary at once"
            ));
        }
        assert!(
            problems.is_empty(),
            "a compiler-diag probe whose canary cannot fire: the rule is blanket, and on a \
             probe whose detector reads the canary a silenced stderr would read as the flag \
             being off:\n{}",
            problems.join("\n")
        );
        assert!(
            held > 0,
            "no compiler-diag probe, so this test holds over nothing"
        );
        eprintln!(
            "canary: {held} compiler-diag probes of {} in the corpus, {} without the pin",
            CORPUS.len(),
            exempt.len()
        );
    }

    #[test]
    fn a_silent_build_is_read_against_its_flags_exactly_where_the_canary_is_not_pinned() {
        let exempt: BTreeSet<&str> = CANARY_WITHOUT_PRAGMA.iter().map(|(id, _)| *id).collect();
        let silent = BuildRecord {
            argv: ["cc", "-O2", "-o", "probe", "probe.c"]
                .map(str::to_owned)
                .to_vec(),
            dropped_flags: Vec::new(),
            exit_status: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };
        let macros = BTreeMap::new();
        let ev = Evidence {
            macros: &macros,
            elf: None,
            build: Some(&silent),
            run: None,
            workdir: None,
        };
        let mut unpinned = BTreeSet::new();
        let mut pinned = 0usize;
        let mut problems = Vec::new();
        for probe in CORPUS {
            for check in probe.checks {
                let Decoder::CompilerDiag { detect, .. } = &check.decoder else {
                    continue;
                };
                let d = (detect.detect)(&ev);
                let says = d
                    .observed
                    .contains("no recorded flag of the build asked for the canary warning");
                if exempt.contains(probe.id) {
                    unpinned.insert(probe.id);
                    if !says {
                        problems.push(format!(
                            "{} (no pin): {} does not read the flags: {}",
                            check.id, detect.name, d.observed
                        ));
                    }
                } else {
                    pinned += 1;
                    if says {
                        problems.push(format!(
                            "{} (pinned): {} reads the flags: {}",
                            check.id, detect.name, d.observed
                        ));
                    }
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
        assert!(
            unpinned == exempt && pinned > 0,
            "every exempt probe has a compiler-diag check that was read ({unpinned:?} of \
             {exempt:?}), and {pinned} pinned checks were read"
        );
    }

    #[test]
    fn the_canary_test_refuses_every_shape_that_silences_the_canary() {
        let pin = format!("{CANARY_PRAGMA}\n");
        let body = |inner: &str| format!("{pin}int main(void)\n{{\n{inner}\n    return 0;\n}}\n");
        let good = body("    int chard_canary_unused = 0;");
        // `good` with lines put before and after its pin.
        let around_pin =
            |before: &str, after: &str| good.replacen(&pin, &format!("{before}{pin}{after}"), 1);
        let commented =
            body("    /* chard_canary_unused is the canary */\n    int chard_canary_unused = 0;");
        for working in [&good, &commented] {
            assert_eq!(canary_faults("ok.c", working, false), Vec::<String>::new());
        }
        let silenced = [
            (
                "cast",
                body("    int chard_canary_unused = 0;\n    (void) chard_canary_unused;"),
            ),
            (
                "cast-parens",
                body("    int chard_canary_unused = 0;\n    (void)(chard_canary_unused);"),
            ),
            (
                "self-assign",
                body(
                    "    int chard_canary_unused = 0;\n    chard_canary_unused = chard_canary_unused;",
                ),
            ),
            (
                "attribute",
                body("    __attribute__((unused)) int chard_canary_unused = 0;"),
            ),
            (
                "attribute-above",
                body("    __attribute__((unused))\n    int chard_canary_unused = 0;"),
            ),
            (
                "maybe-unused",
                body("    [[maybe_unused]] int chard_canary_unused = 0;"),
            ),
            (
                "ignored",
                format!("#pragma GCC diagnostic ignored \"-Wunused-variable\"\n{good}"),
            ),
            ("missing", body("    int other = 0;")),
            ("unpinned", good.replacen(&pin, "", 1)),
            ("pin-after", format!("{}{pin}", good.replacen(&pin, "", 1))),
            (
                "_Pragma",
                format!(
                    "{pin}_Pragma(\"GCC diagnostic ignored \\\"-Wunused-variable\\\"\")\n{}",
                    good.replacen(&pin, "", 1)
                ),
            ),
            (
                "if-0",
                body("#if 0\n    int chard_canary_unused = 0;\n#endif"),
            ),
            (
                "ignored-wall",
                around_pin("", "#pragma GCC diagnostic ignored \"-Wall\"\n"),
            ),
            (
                "clang-everything",
                around_pin("", "#pragma clang diagnostic ignored \"-Weverything\"\n"),
            ),
            (
                "push-pop",
                around_pin(
                    "#pragma GCC diagnostic push\n",
                    "#pragma GCC diagnostic pop\n",
                ),
            ),
            (
                "spaced-ignored",
                format!("#  pragma GCC diagnostic ignored \"-Wunused-variable\"\n{good}"),
            ),
            (
                "pin-in-conditional",
                format!(
                    "#ifdef __GNUC__\n{pin}#endif\n{}",
                    good.replacen(&pin, "", 1)
                ),
            ),
            (
                "file-scope",
                format!(
                    "{pin}int chard_canary_unused = 0;\nint main(void)\n{{\n    return 0;\n}}\n"
                ),
            ),
            ("linemarker", around_pin("", "# 2 \"x.h\" 3\n")),
            (
                "continued-pragma",
                format!("#pragma GCC \\\ndiagnostic ignored \"-Wunused-variable\"\n{good}"),
            ),
        ];
        for (shape, source) in &silenced {
            assert!(
                !canary_faults(shape, source, false).is_empty(),
                "the `{shape}` shape silences the canary and the test accepted it:\n{source}"
            );
        }
    }

    #[test]
    fn ssp_level_ordering_prefers_the_strongest_macro() {
        let all = BTreeMap::from([
            ("__SSP_ALL__".to_owned(), "2".to_owned()),
            ("__SSP_STRONG__".to_owned(), "3".to_owned()),
        ]);
        let ev = Evidence {
            macros: &all,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        };
        let detection = ssp_level(&ev);
        assert_eq!(detection.outcome, Outcome::Present);
        assert_eq!(detection.level.as_deref(), Some("all"));

        let none = BTreeMap::new();
        let ev = Evidence {
            macros: &none,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        };
        assert_eq!(ssp_level(&ev).outcome, Outcome::Absent);
    }

    #[test]
    fn a_dump_carrying_ssp_explicit_reads_its_level_rather_than_off() {
        let dump = crate::compile::parse_macros(
            "#define __GNUC__ 16\n\
             #define __SSP_EXPLICIT__ 4\n",
        );
        let report = parse_self_report(
            "CHARD-REPORT-V2\n\
             __SSP__ undefined\n\
             __SSP_STRONG__ undefined\n\
             __SSP_ALL__ undefined\n\
             __SSP_EXPLICIT__=4\n\
             CHARD-REPORT-END\n",
        )
        .expect("a report");
        for macros in [&dump, &report] {
            let ev = Evidence {
                macros,
                elf: None,
                build: None,
                run: None,
                workdir: None,
            };
            let detection = ssp_level(&ev);
            assert_eq!(detection.outcome, Outcome::Present, "{macros:?}");
            assert_eq!(detection.level.as_deref(), Some("explicit"), "{macros:?}");
        }
        let grade = SSP_LEVELS.grade().expect("graded");
        assert_eq!(
            grade.meets("explicit"),
            Some(false),
            "explicit sits below the ask of strong, and below basic"
        );
        assert_eq!(
            grade.scale.words().first(),
            Some(&"explicit"),
            "the bottom rung"
        );
        // A stronger macro beside it, which no compiler defines but a forged list could,
        // reads the stronger level, as the ladder reads every other pair.
        let both = macro_evidence(&[("__SSP_EXPLICIT__", "4"), ("__SSP__", "1")]);
        let ev = Evidence {
            macros: &both,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        };
        assert_eq!(ssp_level(&ev).level.as_deref(), Some("basic"));
    }

    #[test]
    fn a_requested_level_no_libc_confirms_is_indeterminate_not_off() {
        let macros = BTreeMap::from([
            ("_FORTIFY_SOURCE".to_owned(), "3".to_owned()),
            ("__OPTIMIZE__".to_owned(), "1".to_owned()),
        ]);
        let ev = Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        };
        assert_eq!(fortify_effective(&ev).outcome, Outcome::Indeterminate);
    }

    #[test]
    fn a_requested_fortify_level_without_optimization_is_not_reported_on() {
        let inert = BTreeMap::from([("_FORTIFY_SOURCE".to_owned(), "3".to_owned())]);
        let ev = Evidence {
            macros: &inert,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        };
        assert_eq!(
            fortify_requested(&ev).outcome,
            Outcome::Indeterminate,
            "a fortify request that cannot take effect must not read as on"
        );

        let effective = BTreeMap::from([
            ("_FORTIFY_SOURCE".to_owned(), "3".to_owned()),
            ("__OPTIMIZE__".to_owned(), "1".to_owned()),
        ]);
        let ev = Evidence {
            macros: &effective,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        };
        let detection = fortify_requested(&ev);
        assert_eq!(detection.outcome, Outcome::Present);
        assert_eq!(detection.level.as_deref(), Some("3"));
    }

    #[test]
    fn a_fortify_request_at_or_below_zero_is_absent() {
        for value in ["-1", "0", "-3"] {
            let detection = detect_over_macros(
                fortify_requested,
                &[("_FORTIFY_SOURCE", value), ("__OPTIMIZE__", "1")],
            );
            assert_eq!(
                detection.outcome,
                Outcome::Absent,
                "_FORTIFY_SOURCE={value} is no request"
            );
            assert_eq!(detection.level, None);
        }
        let four = detect_over_macros(
            fortify_requested,
            &[("_FORTIFY_SOURCE", "4"), ("__OPTIMIZE__", "1")],
        );
        assert_eq!(four.outcome, Outcome::Present);
        assert_eq!(
            four.level.as_deref(),
            Some("4"),
            "a request above 3 is reported as asked; the grade reads it as a number"
        );
    }

    #[test]
    fn zero_fortify_level_is_off() {
        let macros = BTreeMap::from([("__USE_FORTIFY_LEVEL".to_owned(), "0".to_owned())]);
        let ev = Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        };
        assert_eq!(fortify_effective(&ev).outcome, Outcome::Absent);
    }

    #[test]
    fn corpus_hash_is_stable_across_calls() {
        assert_eq!(corpus_sha256(), corpus_sha256());
        assert_eq!(corpus_sha256().len(), 64);
        assert_eq!(
            corpus_sha256(),
            corpus_sha256_of(CORPUS, &decoders_sha256()),
            "the published corpus hash carries the published decoder fingerprint"
        );
        assert_eq!(decoders_sha256().len(), 64);
    }

    #[test]
    fn a_scale_read_another_way_is_another_corpus() {
        let fingerprint = decoders_sha256();
        let ordered = |c: &Check| match c.levels {
            Levels::Graded(grade) => match grade.scale {
                Scale::Ordered(words) => Some((grade, words)),
                Scale::Named(_) | Scale::Numeric => None,
            },
            Levels::None | Levels::Informational(_) => None,
        };
        let (index, probe) = CORPUS
            .iter()
            .enumerate()
            .find(|(_, p)| p.checks.iter().any(|c| ordered(c).is_some()))
            .expect("a check graded on an ordered scale");
        let checks: Vec<Check> = probe
            .checks
            .iter()
            .map(|c| match ordered(c) {
                Some((grade, words)) => Check {
                    levels: Levels::Graded(Grade {
                        scale: Scale::Named(words),
                        ..grade
                    }),
                    ..*c
                },
                None => Check { ..*c },
            })
            .collect();
        let renamed = Probe {
            checks: Box::leak(checks.into_boxed_slice()),
            ..*probe
        };
        let corpus: Vec<Probe> = CORPUS
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if i == index {
                    Probe { ..renamed }
                } else {
                    Probe { ..*p }
                }
            })
            .collect();
        assert_ne!(
            corpus_sha256_of(&corpus, &fingerprint),
            corpus_sha256_of(CORPUS, &fingerprint)
        );
    }

    #[test]
    fn levels_and_scales_name_their_kind_and_spell_their_words() {
        assert_eq!(Levels::None.kind(), "none");
        assert_eq!(Levels::Informational(&["a"]).kind(), "informational");
        assert_eq!(SHADOW_STACK_DEFAULT.kind(), "graded");
        assert_eq!(
            (
                Scale::Ordered(&[]).kind(),
                Scale::Named(&[]).kind(),
                Scale::Numeric.kind()
            ),
            ("ordered", "named", "numeric")
        );
        assert_eq!(Scale::Ordered(&["1", "2", "3"]).spelled(), "1 < 2 < 3");
        assert_eq!(
            Scale::Named(&["branch", "return", "full"]).spelled(),
            "branch, return, full"
        );
        assert_eq!(Scale::Numeric.spelled(), "a whole number");
    }

    #[test]
    fn repointing_a_check_at_another_detector_moves_the_corpus_hash() {
        let fingerprint = decoders_sha256();
        let (index, probe) = CORPUS
            .iter()
            .enumerate()
            .find(|(_, p)| {
                p.checks
                    .iter()
                    .any(|c| matches!(c.decoder, Decoder::CompilerDiag { .. }))
            })
            .expect("a compiler-diag check");
        let checks: Vec<Check> = probe
            .checks
            .iter()
            .map(|c| match c.decoder {
                Decoder::CompilerDiag { detect, reads } => Check {
                    decoder: Decoder::CompilerDiag {
                        detect: if detect.name == "detect_warn_all" {
                            detector!(detect_warn_extra)
                        } else {
                            detector!(detect_warn_all)
                        },
                        reads,
                    },
                    ..*c
                },
                _ => Check { ..*c },
            })
            .collect();
        let repointed = Probe {
            checks: Box::leak(checks.into_boxed_slice()),
            ..*probe
        };
        let corpus: Vec<Probe> = CORPUS
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if i == index {
                    Probe { ..repointed }
                } else {
                    Probe { ..*p }
                }
            })
            .collect();
        assert_ne!(
            corpus_sha256_of(&corpus, &fingerprint),
            corpus_sha256_of(CORPUS, &fingerprint),
            "a check pointed at another detector is another corpus"
        );
    }

    #[test]
    fn the_decoder_fingerprint_moves_on_code_and_clauses_and_not_on_comments() {
        let ssp = macro_channel::ssp_level();
        let source = "fn level() -> u8 {\n    // the reason\n    1\n}\n";
        let sources = |text: &str| {
            digest::sha256_hex(
                crate::fingerprint::sources_canonical([("src/decode/x.rs", text)]).as_bytes(),
            )
        };
        let fingerprint = |p: &Predicate, text: &str| {
            decoders_sha256_of(predicate::LANGUAGE, &[("ssp-level", p)], &sources(text))
        };
        let corpus = |fingerprint: &str| corpus_sha256_of(CORPUS, fingerprint);
        let base = fingerprint(ssp, source);

        let commented = "//! A module doc.\n\n/// Why.\nfn level() -> u8 {\n    // another \
                         reason, reworded\n\n    1\n}\n#[cfg(test)]\nmod tests {\n    \
                         fn helper() {}\n}\n";
        assert_eq!(
            fingerprint(ssp, commented),
            base,
            "comments, blank lines and a trailing test module are not decoder code"
        );

        // A test-only item ahead of the test module is read as code, and the module itself,
        // opened by a gate on its own line with an attribute between, is not.
        let helper = "fn level() -> u8 {\n    // the reason\n    1\n}\n#[cfg(test)]\nfn \
                      helper() {}\n#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod tests;\n";
        assert_ne!(
            fingerprint(ssp, helper),
            base,
            "a test-only item outside the trailing module is read, so it cannot hide code"
        );
        assert_eq!(
            fingerprint(
                ssp,
                "fn level() -> u8 {\n    1\n}\n#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod tests;\n"
            ),
            base,
            "a gate declaring the test module by path cuts there"
        );

        let recoded = "fn level() -> u8 {\n    // the reason\n    2\n}\n";
        let code_edit = fingerprint(ssp, recoded);
        assert_ne!(
            code_edit, base,
            "a changed line of code is a changed decoder"
        );

        let mut swapped = ssp.clone();
        swapped.clauses.swap(0, 1);
        let clause_edit = fingerprint(&swapped, source);
        assert_ne!(clause_edit, base, "a reordered ladder is a changed decoder");
        let mut reworded = ssp.clone();
        reworded.clauses[0].then = predicate::Conclusion::Absent;
        assert_ne!(fingerprint(&reworded, source), base);

        assert_ne!(
            fingerprint(ssp, source),
            decoders_sha256_of("chard-predicate/1", &[("ssp-level", ssp)], &sources(source)),
            "the language version is part of what reads the predicates"
        );

        let base_corpus = corpus(&base);
        assert_eq!(base_corpus, corpus(&fingerprint(ssp, commented)));
        assert_ne!(base_corpus, corpus(&code_edit));
        assert_ne!(base_corpus, corpus(&clause_edit));
    }

    #[test]
    fn every_check_has_a_distinct_flag() {
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        let mut clashes = Vec::new();
        for check in CORPUS.iter().flat_map(|p| p.checks) {
            if let Some(first) = seen.insert(check.flag, check.id) {
                clashes.push(format!(
                    "{:?} used by both {first} and {}",
                    check.flag, check.id
                ));
            }
        }
        assert!(
            clashes.is_empty(),
            "two checks share a flag, so whichever is observed last wins in `table` and \
             `matrix` with no record that the other disagreed:\n  {}",
            clashes.join("\n  ")
        );
        assert_eq!(
            seen.len(),
            total_checks(),
            "the flag set and the corpus should be the same size"
        );
    }

    /// What is wrong with a grade's ungraded words: each is admitted and on no rung, so
    /// `meets` must not know it (or it would be a rung) and `grade_level` must read it as
    /// `Ungraded`, and none is empty.
    fn ungraded_word_problems(check: &Check, grade: &Grade) -> Vec<String> {
        let mut problems = Vec::new();
        for word in grade.ungraded {
            if grade.meets(word).is_some() || word.is_empty() {
                problems.push(format!(
                    "{}: `{word}` is listed as ungraded and is a word of the scale ({}), or \
                     empty",
                    check.id,
                    grade.scale.spelled()
                ));
            }
            if !check.levels.admits(word)
                || crate::report::grade_level(Some(grade), Some(word))
                    != Some(crate::report::Grading::Ungraded)
            {
                problems.push(format!(
                    "{}: `{word}` is listed as ungraded and the grade does not read it so",
                    check.id
                ));
            }
        }
        problems
    }

    #[test]
    fn every_graded_check_recommends_a_word_on_its_own_scale() {
        // The spellings two different vocabularies share, with how many may carry each:
        // RELRO's `full` and the CFI components' `full`; the `-Werror=` checks' `error`
        // and the severity the `diag_presence` checks publish as information; the fill
        // `auto-var-init-active` grades against `zero` and `auto-var-init-pattern`
        // publishes as its one word.
        const SHARED_BY_SPELLING: &[(&str, usize)] = &[("full", 2), ("error", 2), ("pattern", 2)];
        let mut graded = 0usize;
        let mut informational = 0usize;
        let mut vocabularies: BTreeMap<&str, Vec<(Levels, &str)>> = BTreeMap::new();
        let mut problems = Vec::new();
        for check in CORPUS.iter().flat_map(|p| p.checks) {
            let words = check.levels.words();
            let distinct: BTreeSet<&str> = words.iter().copied().collect();
            if distinct.len() != words.len() || words.iter().any(|w| w.is_empty()) {
                problems.push(format!(
                    "{}: scale {words:?} repeats a word or carries an empty one",
                    check.id
                ));
            }
            match check.levels {
                Levels::None => {}
                Levels::Informational(_) => {
                    informational = informational.saturating_add(1);
                    if words.is_empty() {
                        problems.push(format!(
                            "{}: informational with no words, which is `Levels::None` spelled \
                             confusingly",
                            check.id
                        ));
                    }
                }
                Levels::Graded(grade) => {
                    graded = graded.saturating_add(1);
                    if !check.levels.admits(grade.recommended) {
                        problems.push(format!(
                            "{}: asks for `{}`, which is not on its own scale ({})",
                            check.id,
                            grade.recommended,
                            grade.scale.spelled()
                        ));
                    }
                    if grade.meets(grade.recommended) != Some(true) {
                        problems.push(format!(
                            "{}: the ask `{}` does not meet itself",
                            check.id, grade.recommended
                        ));
                    }
                    problems.extend(ungraded_word_problems(check, &grade));
                }
            }
            // The ungraded words are words of the vocabulary too, and shared across checks
            // through one constant like the rest.
            for word in words.iter().chain(check.levels.ungraded()) {
                vocabularies
                    .entry(word)
                    .or_default()
                    .push((check.levels, check.id));
            }
        }
        for (word, users) in &vocabularies {
            let distinct: BTreeSet<Levels> = users.iter().map(|(l, _)| *l).collect();
            let accepted = SHARED_BY_SPELLING
                .iter()
                .find(|(w, _)| w == word)
                .map_or(1, |(_, n)| *n);
            if distinct.len() > accepted {
                problems.push(format!(
                    "`{word}` is a word on {} different vocabularies ({:?}); a word shared \
                     across checks is shared through one constant, or listed as a spelling \
                     collision in this test",
                    distinct.len(),
                    users.iter().map(|(_, id)| *id).collect::<Vec<_>>()
                ));
            }
        }
        let distinct_vocabularies = vocabularies
            .values()
            .flat_map(|u| u.iter().map(|(l, _)| *l))
            .collect::<BTreeSet<Levels>>()
            .len();
        eprintln!(
            "probe: {graded} graded checks, {informational} informational, {} words across \
             {distinct_vocabularies} vocabularies",
            vocabularies.len()
        );
        assert!(problems.is_empty(), "{}", problems.join("\n"));
        assert!(
            graded > 0 && informational > 0,
            "the invariant held over nothing: {graded} graded, {informational} informational"
        );
    }

    #[test]
    fn no_probe_pin_restates_the_base_environment() {
        let base: BTreeSet<&str> = crate::run::PROBE_ENVIRONMENT
            .iter()
            .map(|(n, _)| *n)
            .collect();
        let mut pinned = 0;
        for probe in CORPUS {
            let mut seen = BTreeSet::new();
            for (name, value) in probe.run_environment {
                assert!(
                    !base.contains(name),
                    "{} pins {name}, which every probe already receives",
                    probe.id
                );
                assert!(
                    !name.is_empty() && !value.is_empty(),
                    "{}: an empty pin",
                    probe.id
                );
                assert!(seen.insert(*name), "{} pins {name} twice", probe.id);
                pinned += 1;
            }
            assert!(
                probe.run_environment.is_empty() || probe.needs_run(),
                "{} pins a variable and is never run",
                probe.id
            );
        }
        assert_eq!(pinned, 1, "one probe pin: `shadow-stack`'s tunable");
    }

    #[test]
    fn the_corpus_is_the_size_it_is_published_as() {
        const PROBES: usize = 54;
        const CHECKS: usize = 76;

        let manual: usize = CORPUS.iter().map(|p| p.checks.len()).sum();
        assert_eq!(
            total_checks(),
            manual,
            "total_checks() miscounts the corpus"
        );
        assert_eq!(
            CORPUS.len(),
            PROBES,
            "the corpus holds {} probes, not the {PROBES} the docs publish",
            CORPUS.len()
        );
        assert_eq!(
            manual, CHECKS,
            "the corpus holds {manual} checks, not the {CHECKS} the docs publish. If \
             this is deliberate, update PROBES/CHECKS here and every count in \
             README.md, SECURITY.md, THREAT_MODEL.md and DESIGN.md."
        );
    }

    #[test]
    fn check_ids_are_unique_across_the_corpus() {
        use std::collections::BTreeSet;

        let ids: Vec<&str> = CORPUS.iter().flat_map(|p| p.checks).map(|c| c.id).collect();
        let distinct: BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(
            ids.len(),
            distinct.len(),
            "duplicate check ids in the corpus: {:?}",
            ids.iter()
                .filter(|id| ids.iter().filter(|o| o == id).count() > 1)
                .collect::<BTreeSet<_>>()
        );
    }

    fn macro_evidence(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn fortify_effective_reads_both_libcs_and_both_macro_provenances() {
        let level_of = |pairs: &[(&str, &str)]| {
            let macros = macro_evidence(pairs);
            let d = fortify_effective(&Evidence {
                macros: &macros,
                elf: None,
                build: None,
                run: None,
                workdir: None,
            });
            (d.outcome, d.level)
        };

        // glibc, unchanged: the level it settled on is the level reported.
        assert_eq!(
            level_of(&[("_FORTIFY_SOURCE", "3"), ("__USE_FORTIFY_LEVEL", "3")]),
            (Outcome::Present, Some("3".to_owned()))
        );
        assert_eq!(level_of(&[("__USE_FORTIFY_LEVEL", "0")]).0, Outcome::Absent);

        // fortify-headers via the compiled artifact, which is what a real run produces.
        for requested in ["1", "2", "3"] {
            assert_eq!(
                level_of(&[
                    ("_FORTIFY_SOURCE", requested),
                    ("_FORTIFY_IMPL", "fortify-headers"),
                    ("__OPTIMIZE__", "1"),
                ]),
                (Outcome::Present, Some("1".to_owned())),
                "requested level {requested} is still enforced at 1"
            );
        }

        // And via a preprocessor dump, where the raw include guard is what appears.
        assert_eq!(
            level_of(&[
                ("_FORTIFY_SOURCE", "2"),
                ("_FORTIFY_HEADERS_H", ""),
                ("__OPTIMIZE__", "1"),
            ]),
            (Outcome::Present, Some("1".to_owned()))
        );

        // A third libc leaving neither mark, with fortify genuinely requested, is not
        // evidence the level is zero.
        assert_eq!(
            level_of(&[("_FORTIFY_SOURCE", "2"), ("__OPTIMIZE__", "1")]).0,
            Outcome::Indeterminate
        );

        // FreeBSD via the compiled artifact: the level its <ssp/ssp.h> settled on, clamped
        // at 2, beside optimization, and withheld without optimization, which clang allows
        // and under which the wrappers check nothing.
        for (settled, level) in [("1", "1"), ("2", "2")] {
            assert_eq!(
                level_of(&[
                    ("_FORTIFY_SOURCE", "3"),
                    ("__SSP_FORTIFY_LEVEL", settled),
                    ("__FreeBSD__", "15"),
                    ("__OPTIMIZE__", "1"),
                ]),
                (Outcome::Present, Some(level.to_owned())),
                "FreeBSD settled {settled}"
            );
        }
        let freebsd = |pairs: &[(&str, &str)]| level_of(pairs).0;
        assert_eq!(
            freebsd(&[
                ("_FORTIFY_SOURCE", "2"),
                ("__SSP_FORTIFY_LEVEL", "0"),
                ("__FreeBSD__", "15"),
                ("__OPTIMIZE__", "1"),
            ]),
            Outcome::Absent,
            "settled at 0: the wrappers did not instantiate"
        );
        assert_eq!(
            freebsd(&[
                ("_FORTIFY_SOURCE", "2"),
                ("__SSP_FORTIFY_LEVEL", "2"),
                ("__FreeBSD__", "15"),
            ]),
            Outcome::Indeterminate,
            "instantiated without optimization: the settled level is not the level in force"
        );
        for optimized in [true, false] {
            let mut pairs = vec![("_FORTIFY_SOURCE", "2"), ("__FreeBSD__", "14")];
            if optimized {
                pairs.push(("__OPTIMIZE__", "1"));
            }
            assert_eq!(
                freebsd(&pairs),
                Outcome::Absent,
                "a FreeBSD with no <ssp/ssp.h> has no implementation, optimized {optimized}"
            );
        }
        // A 15 or later whose headers defined no level is not told it has none, and the level
        // macro without the platform macro is not FreeBSD's: both fall through withheld.
        assert_eq!(
            freebsd(&[
                ("_FORTIFY_SOURCE", "2"),
                ("__FreeBSD__", "15"),
                ("__OPTIMIZE__", "1")
            ]),
            Outcome::Indeterminate
        );
        assert_eq!(
            freebsd(&[
                ("_FORTIFY_SOURCE", "2"),
                ("__SSP_FORTIFY_LEVEL", "2"),
                ("__OPTIMIZE__", "1")
            ]),
            Outcome::Indeterminate
        );
    }

    /// `fortify-printf-flag`'s `freebsd-unoptimized` clause withholds exactly a referenced
    /// `__strcpy_chk` beside `__FreeBSD__` and no `__OPTIMIZE__`. Held here because the
    /// replay rows record no macros for an elf-static reading, so the corpus cannot reach
    /// the clause.
    #[test]
    fn the_printf_flag_withholds_freebsds_unoptimized_wrapper_only() {
        use crate::elf::SymbolFact;
        let check = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == "fortify-printf-flag")
            .expect("the check");
        let read = |pairs: &[(&str, &str)], referenced: bool| {
            let mut elf = elf_with_report("");
            elf.symbol_tables = vec![".symtab".to_owned()];
            // The probe's printf function searched and no flag found, as the FreeBSD
            // objects record it, so the search clauses are silent and the level ones read.
            elf.code_scanned = vec!["chard_fortify_printf_probe:x86-mov-edi-1=0".to_owned()];
            if referenced {
                elf.watched_symbols.insert(
                    "__strcpy_chk".to_owned(),
                    SymbolFact {
                        defined: false,
                        tables: vec![".symtab".to_owned()],
                        versioned: Vec::new(),
                    },
                );
            }
            let macros = macro_evidence(pairs);
            let d = check
                .decode(&Evidence {
                    macros: &macros,
                    elf: Some(&elf),
                    build: None,
                    run: None,
                    workdir: None,
                })
                .detection;
            (d.outcome, d.level)
        };
        let freebsd = ("__FreeBSD__", "15");
        assert_eq!(
            read(&[freebsd], true),
            (Outcome::Indeterminate, None),
            "referenced without optimization on FreeBSD is withheld"
        );
        assert_eq!(
            read(&[freebsd, ("__OPTIMIZE__", "1")], true),
            (Outcome::Present, Some("1".to_owned())),
            "optimized, the reference is level 1"
        );
        assert_eq!(
            read(&[], true),
            (Outcome::Present, Some("1".to_owned())),
            "no platform macro: not FreeBSD's clause"
        );
        assert_eq!(read(&[freebsd], false).0, Outcome::Absent, "no reference");
    }

    /// FreeBSD's libc is listed on the gates of the checks its wrappers do not serve and on
    /// no other: `fortify-requested` reads the request, which every release carries. Pinned
    /// here because the gates fire only on FreeBSD.
    #[test]
    fn freebsd_is_gated_where_its_wrappers_do_not_serve_the_check() {
        let gated = [
            "fortify-effective",
            "fortify-printf-flag",
            "fortify-enforced-known",
            "fortify-level-ge-2-subobject",
            "fortify-level-ge-2-percent-n",
            "fortify-enforced-dynamic",
            "strict-flex-arrays-enforced",
        ];
        for check in CORPUS.iter().flat_map(|p| p.checks) {
            let listed = check.gate.libc_unsupported.contains(&"freebsd");
            assert_eq!(listed, gated.contains(&check.id), "{}", check.id);
        }
    }

    /// The negative control has to be able to demonstrate absence, or nothing here can
    /// ever be reported `off`.
    ///
    /// Under fortify-headers the marker is absent when inactive (there is no
    /// `__USE_FORTIFY_LEVEL=0` to read), so a detector treating "no marker" as
    /// `indeterminate` would read `fortify-effective` `probe-invalid` on every musl system.
    #[test]
    fn fortify_effective_demonstrates_absence_without_a_libc_marker() {
        let outcome = |pairs: &[(&str, &str)]| {
            let macros = macro_evidence(pairs);
            fortify_effective(&Evidence {
                macros: &macros,
                elf: None,
                build: None,
                run: None,
                workdir: None,
            })
            .outcome
        };

        // The negative control's exact shape: -U_FORTIFY_SOURCE -O2 under fortify-headers.
        assert_eq!(
            outcome(&[("__OPTIMIZE__", "1"), ("_FORTIFY_IMPL", "?")]),
            Outcome::Absent,
            "no _FORTIFY_SOURCE means no implementation can be running"
        );
        // Requested but inert for want of optimization; an implementation that does not gate
        // on optimization identifies itself through its own level macro before this branch.
        assert_eq!(
            outcome(&[("_FORTIFY_SOURCE", "3")]),
            Outcome::Absent,
            "glibc and fortify-headers both gate on optimization"
        );
        assert_eq!(outcome(&[("_FORTIFY_SOURCE", "0")]), Outcome::Absent);
    }

    /// Real ELF facts from a Linux `bare` run with only `self_report` varied.
    ///
    /// Deserialized rather than constructed so a new `ElfFacts` field fails here loudly
    /// instead of defaulting to something these tests would silently assert against.
    /// `truncations` carries `#[serde(default)]`, so this fixture reads as a whole artifact.
    pub(crate) fn elf_with_report(self_report: &str) -> ElfFacts {
        serde_json::from_value(serde_json::json!({
            "aarch64_bti": false, "aarch64_pac": false, "bind_now": false,
            "df_1_noopen": false, "df_1_pie": false, "dt_debug": false,
            "dt_relr": false, "dt_soname": false,
            "dynamic_tags": [], "elf_class": 64, "elf_data": "little-endian", "elf_type": "ET_EXEC",
            "aarch64_gcs": false, "gnu_property_types": [], "gnu_relro": true,
            "gnu_stack_executable": false, "gnu_stack_present": true,
            "has_dynamic": true, "has_interp": true, "machine": "x86_64",
            "needed": [], "pie": false, "recorded_command_line": "",
            "relro": "partial", "rpath": [], "runpath": [], "sections": [],
            "self_report": self_report, "shared_object": false, "static_pie": false,
            "statically_linked": false, "symbol_count": 35, "textrel": false,
            "watched_symbols": {}, "x86_ibt": false, "x86_shstk": false,
        }))
        .expect("fixture matches ElfFacts")
    }

    /// A compile-only probe drops what only a linker could use, and keeps what generates
    /// code.
    ///
    /// `-fPIE` is the load-bearing negative: the executable arm of the same probe compiles
    /// with it, and dropping it would make the object a different build from the one whose
    /// link it is read beside.
    #[test]
    fn an_object_probe_drops_link_flags_and_keeps_code_generation() {
        let drops = |flag: &str| LinkMode::Object.conflicts_with(flag);

        for flag in [
            "-Wl,-z,now",
            "-Wl,-z,relro",
            "-Wl,--as-needed",
            "-pie",
            "-no-pie",
            "-shared",
            "-fuse-ld=lld",
            "-fuse-ld=mold",
            "--ld-path=/usr/bin/ld.lld",
            "-static-pie",
            "-rdynamic",
            "-s",
            "-static-libgcc",
            "-L/usr/lib",
            "-znow",
            "--for-linker=-znow",
            "-lm",
            "-r",
            "-nostartfiles",
            "-nolibc",
            "-shared-libgcc",
            "-usym",
            "-Ts.ld",
        ] {
            assert!(drops(flag), "{flag} has no meaning without a link");
        }
        for flag in [
            "-fPIE",
            "-fPIC",
            "-O2",
            "-D_FORTIFY_SOURCE=3",
            "-fcf-protection=full",
            "-static",
            "-pthread",
            "-Werror",
            "-fsanitize=address",
            "-flto",
            // A preprocessor flag that a bare `-u` prefix would take, and clang's
            // `-emit-llvm`, which a `-e` prefix would.
            "-undef",
            "-emit-llvm",
        ] {
            assert!(
                !drops(flag),
                "{flag} is code generation and the object must carry it"
            );
        }

        // And the other two modes are unchanged by this arm existing.
        assert!(!LinkMode::Executable.conflicts_with("-Wl,-z,now"));
        assert!(LinkMode::SharedObject.conflicts_with("-pie"));
        assert!(!LinkMode::SharedObject.conflicts_with("-Wl,-z,now"));
    }

    /// An option and the word the driver takes with it are one unit under an object build,
    /// dropped or kept together on the option's verdict as the one classifier spans them
    /// (`toolchain::read`): `-l m` is a library (clang refuses `-l` at `-c -Werror`) and
    /// is dropped whole, and gcc's long spellings are read as the short words.
    #[test]
    fn an_object_probe_drops_or_keeps_an_option_with_the_word_it_takes() {
        let split = |flags: &[&str]| {
            let owned: Vec<String> = flags.iter().map(|f| (*f).to_owned()).collect();
            LinkMode::Object.partition_flags(&owned)
        };
        let strings = |flags: &[&str]| flags.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        let rows: [(&[&str], &[&str], &[&str]); 10] = [
            (&["-l", "m", "-O2"], &["-O2"], &["-l", "m"]),
            (&["-MF", "-L/x", "-O2"], &["-MF", "-L/x", "-O2"], &[]),
            (
                &["--machine", "32", "-O2"],
                &["--machine", "32", "-O2"],
                &[],
            ),
            (&["--shared", "-O2"], &["-O2"], &["--shared"]),
            (&["--pie", "-O2"], &["-O2"], &["--pie"]),
            (&["--static-pie", "-O2"], &["-O2"], &["--static-pie"]),
            (&["--static", "-O2"], &["--static", "-O2"], &[]),
            (
                &["--for-l", "-znow", "-O2"],
                &["-O2"],
                &["--for-l", "-znow"],
            ),
            (&["--li", "/x", "-O2"], &["-O2"], &["--li", "/x"]),
            // gcc's generic map: `--no-pie` is `-fno-pie`, code generation, kept.
            (&["--no-pie", "-O2"], &["--no-pie", "-O2"], &[]),
        ];
        let mut fed = 0_usize;
        for (flags, kept, dropped) in rows {
            let (k, d) = split(flags);
            assert_eq!((&k, &d), (&strings(kept), &strings(dropped)), "{flags:?}");
            let mut whole = k.clone();
            whole.extend(d);
            whole.sort();
            let mut input = strings(flags);
            input.sort();
            assert_eq!(whole, input, "{flags:?}: kept and dropped are the input");
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, rows.len(), "every row was fed");
    }

    /// A shared-object build reads the position-independence choice, which decides chard's
    /// own `-fPIC`, through the classifier, read through the partition and `extra_flags` as
    /// the build path reads it.
    #[test]
    fn a_shared_object_build_reads_the_position_choice_through_the_classifier() {
        let strings = |flags: &[&str]| flags.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        // The shared-object kinds read the long spellings too: `--pie` contradicts a shared
        // link and `--shared` does not.
        assert!(LinkMode::SharedObject.conflicts_with(&crate::toolchain::spelled_alone("--pie")));
        assert!(
            !LinkMode::SharedObject.conflicts_with(&crate::toolchain::spelled_alone("--shared"))
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&strings(&["--no-pie"])),
            vec!["-shared"],
            "`--no-pie` is `-fno-pie`, a position choice this reader does not decide again"
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&strings(&["--pie"])),
            vec!["-shared", "-fPIC"],
            "`--pie` is the linkage form `-pie`, no code-generation choice"
        );
        // A value another word takes, or a word handed to the linker, states no choice.
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&strings(&["-MF", "-fno-pie"])),
            vec!["-shared", "-fPIC"],
            "`-MF -fno-pie` names a dependency file"
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&strings(&["-Xlinker", "-fPIC", "-O2"])),
            vec!["-shared", "-fPIC"],
            "`-Xlinker -fPIC` is the linker's word"
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&strings(&["-O2", "-fno-pie"])),
            vec!["-shared"],
            "`-fno-pie` as the driver's own word is the choice"
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&strings(&["-Xarch_x86_64", "-fno-pie"])),
            vec!["-shared"],
            "the word clang applies for one architecture is the driver's own"
        );
        let (kept, dropped) =
            LinkMode::SharedObject.partition_flags(&strings(&["--no-pie", "-O2"]));
        assert_eq!(
            (kept, dropped),
            (strings(&["-O2"]), strings(&["--no-pie"])),
            "`--no-pie` is dropped from a shared-object build as `-fno-pie` is"
        );
        let (kept, dropped) =
            LinkMode::SharedObject.partition_flags(&strings(&["--no-pic", "-O2"]));
        assert_eq!(
            dropped,
            Vec::<String>::new(),
            "`--no-pic` is kept as `-fno-pic` is"
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&kept),
            vec!["-shared"],
            "`--no-pic` is `-fno-pic`, the choice, so chard adds no `-fPIC` over it"
        );
        // The word clang applies for one architecture goes with its carrier: dropped where
        // the bare word is, kept and read as the choice where the bare word is.
        let (kept, dropped) =
            LinkMode::SharedObject.partition_flags(&strings(&["-Xarch_x86_64", "-fno-pie", "-O2"]));
        assert_eq!(
            (kept.clone(), dropped),
            (strings(&["-O2"]), strings(&["-Xarch_x86_64", "-fno-pie"])),
            "`-Xarch_x86_64 -fno-pie` is dropped from a shared-object build as `-fno-pie` is"
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&kept),
            vec!["-shared", "-fPIC"]
        );
        let (kept, dropped) =
            LinkMode::SharedObject.partition_flags(&strings(&["-Xarch_x86_64", "-fno-pic", "-O2"]));
        assert_eq!(dropped, Vec::<String>::new());
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&kept),
            vec!["-shared"],
            "`-Xarch_x86_64 -fno-pic` is the choice, as `-fno-pic` is"
        );
        // A pair whose applied word is neither is kept whole and states no choice, and
        // `-pie` applied for one architecture contradicts a shared link as `-pie` does.
        let (kept, dropped) =
            LinkMode::SharedObject.partition_flags(&strings(&["-Xarch_x86_64", "-O2"]));
        assert_eq!(
            (kept.clone(), dropped),
            (strings(&["-Xarch_x86_64", "-O2"]), Vec::new())
        );
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&kept),
            vec!["-shared", "-fPIC"]
        );
        let (kept, dropped) =
            LinkMode::SharedObject.partition_flags(&strings(&["-Xarch_x86_64", "-pie", "-O2"]));
        assert_eq!(
            (kept, dropped),
            (strings(&["-O2"]), strings(&["-Xarch_x86_64", "-pie"]))
        );
    }

    /// A two-token link flag is dropped with its argument, so the argument never reaches an
    /// object-mode compile as an input file.
    #[test]
    fn an_object_probe_drops_a_two_token_link_flag_with_its_argument() {
        let split = |flags: &[&str]| {
            let owned: Vec<String> = flags.iter().map(|f| (*f).to_owned()).collect();
            LinkMode::Object.partition_flags(&owned)
        };
        let strings = |flags: &[&str]| flags.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();

        for (flags, kept, dropped) in [
            (
                &["-O2", "-z", "now", "-fPIC"][..],
                &["-O2", "-fPIC"][..],
                &["-z", "now"][..],
            ),
            (&["-L", "/usr/lib", "-O2"], &["-O2"], &["-L", "/usr/lib"]),
            (
                &["-Xlinker", "-z", "-Xlinker", "now", "-O2"],
                &["-O2"],
                &["-Xlinker", "-z", "-Xlinker", "now"],
            ),
            (
                &["-Xlinker", "--as-needed", "-fPIE"],
                &["-fPIE"],
                &["-Xlinker", "--as-needed"],
            ),
            // The joined spellings stay one token each.
            (
                &["-znow", "-L/usr/lib", "-Wl,-z,now", "-O2"],
                &["-O2"],
                &["-znow", "-L/usr/lib", "-Wl,-z,now"],
            ),
            // A trailing pair flag with no argument drops alone.
            (&["-O2", "-z"], &["-O2"], &["-z"]),
            // `--for-linker` is `-Xlinker` under another name; its argument goes with it.
            (
                &["--for-linker", "-znow", "-O2"],
                &["-O2"],
                &["--for-linker", "-znow"],
            ),
            (
                &["--for-linker=-znow", "-O2"],
                &["-O2"],
                &["--for-linker=-znow"],
            ),
            (
                &[
                    "-u", "sym", "-T", "s.ld", "-e", "main", "-rpath", "/usr/lib", "-O2",
                ],
                &["-O2"],
                &[
                    "-u", "sym", "-T", "s.ld", "-e", "main", "-rpath", "/usr/lib",
                ],
            ),
        ] {
            assert_eq!(split(flags), (strings(kept), strings(dropped)), "{flags:?}");
        }

        // The other modes consume no `-z` pair: `-z now` reaches their link intact.
        let owned = strings(&["-z", "now", "-pie"]);
        assert_eq!(
            LinkMode::SharedObject.partition_flags(&owned),
            (strings(&["-z", "now"]), strings(&["-pie"]))
        );
        assert_eq!(
            LinkMode::Executable.partition_flags(&owned),
            (owned.clone(), Vec::new())
        );

        // But a linker pass-through stays paired in every mode: dropping only the `-pie` of
        // `-Xlinker -pie` would hand chard's `-shared` to the `-Xlinker`.
        for mode in [LinkMode::SharedObject, LinkMode::SharedObjectAsCompiled] {
            for pass in ["-Xlinker", "--for-linker"] {
                let owned = strings(&["-O2", pass, "-pie", pass, "-znow"]);
                assert_eq!(
                    mode.partition_flags(&owned),
                    (strings(&["-O2", pass, "-znow"]), strings(&[pass, "-pie"])),
                    "{pass}"
                );
            }
        }
        let owned = strings(&["-Xlinker", "-pie", "--for-linker", "-no-pie"]);
        assert_eq!(
            LinkMode::Executable.partition_flags(&owned),
            (owned.clone(), Vec::new())
        );

        // The one-token spellings go the same way, dropped for a shared object, where they
        // would hand the linker `-pie` beside `-shared`, and kept for an executable. A `-Wl,`
        // list with other words in it is kept.
        for mode in [LinkMode::SharedObject, LinkMode::SharedObjectAsCompiled] {
            let owned = strings(&[
                "-O2",
                "-Wl,-pie",
                "-Wl,-no-pie",
                "--for-linker=-pie",
                "-Wl,-z,now",
                "-Wl,-z,now,-pie",
            ]);
            assert_eq!(
                mode.partition_flags(&owned),
                (
                    strings(&["-O2", "-Wl,-z,now", "-Wl,-z,now,-pie"]),
                    strings(&["-Wl,-pie", "-Wl,-no-pie", "--for-linker=-pie"])
                ),
                "{mode:?}"
            );
        }
        let owned = strings(&["-Wl,-pie", "--for-linker=-no-pie"]);
        assert_eq!(
            LinkMode::Executable.partition_flags(&owned),
            (owned.clone(), Vec::new())
        );
    }

    /// `pic-shared-link` links the profile's code as compiled: `-shared` is added, the
    /// output-kind flags that cannot share its line are dropped, and no position-independence
    /// choice is supplied or removed.
    ///
    /// Under [`LinkMode::SharedObject`] the `openssf-tldr` profile's `-fPIE` is dropped and
    /// `-fPIC` appended, so the check would link `-fPIC` code under every profile and read
    /// `on` for code the profile never produced.
    #[test]
    fn a_shared_link_of_the_code_as_compiled_makes_no_pic_choice() {
        let mode = LinkMode::SharedObjectAsCompiled;
        for stated in [
            Vec::new(),
            vec!["-fPIE".to_owned()],
            vec!["-fno-pic".to_owned()],
            vec!["-O2".to_owned()],
        ] {
            assert_eq!(mode.extra_flags(&stated), vec!["-shared"], "{stated:?}");
        }
        for flag in ["-pie", "-no-pie"] {
            assert!(
                mode.conflicts_with(flag),
                "{flag} names another output kind"
            );
        }
        for flag in [
            "-fPIE",
            "-fpie",
            "-fno-PIE",
            "-fno-pie",
            "-fPIC",
            "-fno-pic",
            "-Wl,-z,now",
        ] {
            assert!(
                !mode.conflicts_with(flag),
                "{flag} is what the check measures, or harmless on a shared link"
            );
        }
        let pic = CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.id == "pic-shared-link"))
            .expect("pic-shared-link is in the corpus");
        assert_eq!(pic.link_mode, mode);
    }

    /// The two arms this detector has besides "the symbol is there", each stopping a wrong
    /// `off`: one where the observable belongs to the other standard library, one where the
    /// library substitutes a different mechanism for the same request.
    #[test]
    fn the_symbol_check_withholds_on_libcxx_and_credits_the_debug_mechanism() {
        let outcome = |stdlib: &str, symbol: Option<&str>| {
            let macros = BTreeMap::from([("_CXX_STDLIB".to_owned(), stdlib.to_owned())]);
            let mut elf = elf_with_report("");
            if let Some(sym) = symbol {
                elf.watched_symbols.insert(
                    sym.to_owned(),
                    crate::elf::SymbolFact {
                        defined: true,
                        tables: vec![".symtab".to_owned()],
                        versioned: Vec::new(),
                    },
                );
            }
            cxx_assertions_symbol(&Evidence {
                macros: &macros,
                elf: Some(&elf),
                build: None,
                run: None,
                workdir: None,
            })
            .outcome
        };

        // libc++ has no libstdc++ assertion symbol at all, so its absence says nothing.
        assert_eq!(outcome("libc++", None), Outcome::Indeterminate);

        // `-D_GLIBCXX_DEBUG` substitutes the debug-mode error formatter for the assertion
        // handler. Reading only the handler reports the request absent on a build that
        // asked for something stricter.
        assert_eq!(
            outcome(
                "libstdc++",
                Some("_ZNK11__gnu_debug16_Error_formatter8_M_errorEv")
            ),
            Outcome::Present,
            "debug mode is the same request through a different mechanism"
        );

        // And the plain case still reads absent, or the two arms above would be vacuous.
        assert_eq!(outcome("libstdc++", None), Outcome::Absent);
    }

    /// libstdc++ before GCC 12 has no out-of-line handler, and its inline one counts.
    #[test]
    fn the_pre_gcc12_assertion_handler_is_the_mechanism_under_its_own_name() {
        let macros = BTreeMap::from([("_CXX_STDLIB".to_owned(), "libstdc++".to_owned())]);
        let outcome = |symbol: &str| {
            let mut elf = elf_with_report("");
            if !symbol.is_empty() {
                elf.watched_symbols.insert(
                    symbol.to_owned(),
                    crate::elf::SymbolFact {
                        defined: true,
                        tables: vec![".symtab".to_owned()],
                        versioned: Vec::new(),
                    },
                );
            }
            cxx_assertions_symbol(&Evidence {
                macros: &macros,
                elf: Some(&elf),
                build: None,
                run: None,
                workdir: None,
            })
            .outcome
        };

        assert_eq!(
            outcome("_ZSt21__glibcxx_assert_failPKciS0_S0_"),
            Outcome::Present,
            "the out-of-line handler GCC 12 introduced"
        );
        assert_eq!(
            outcome("_ZSt20__replacement_assertPKciS0_S0_"),
            Outcome::Present,
            "the inline one it replaced, emitted as a comdat where it was not folded; \
             the same mechanism under the name the older library gives it"
        );
        assert_eq!(
            outcome(""),
            Outcome::Absent,
            "neither name present is the reading the check exists to make"
        );
    }

    /// A preprocessor dump prints replacement text, not the expansion, so a mode the
    /// headers set for themselves arrives as the name of the constant it was spelled
    /// with. Measured on Darwin: `_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEFAULT`.
    #[test]
    fn a_hardening_mode_named_by_another_macro_resolves_to_its_value() {
        let macros: BTreeMap<String, String> = [
            (
                "_LIBCPP_HARDENING_MODE_DEFAULT",
                "_LIBCPP_HARDENING_MODE_FAST",
            ),
            ("_LIBCPP_HARDENING_MODE_FAST", "(1 << 2)"),
            ("SELF", "SELF"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();

        let level_of = |mode: &str| {
            let mut map = macros.clone();
            map.insert("_CXX_STDLIB".to_owned(), "libc++".to_owned());
            map.insert("_LIBCPP_HARDENING_MODE".to_owned(), mode.to_owned());
            let detection = cxx_hardening_requested(&Evidence {
                macros: &map,
                elf: None,
                build: None,
                run: None,
                workdir: None,
            });
            (detection.outcome, detection.level)
        };
        let fast = (Outcome::Present, Some("fast".to_owned()));
        assert_eq!(level_of("(1 << 2)"), fast);
        assert_eq!(level_of("4"), fast);
        assert_eq!(
            level_of("_LIBCPP_HARDENING_MODE_DEFAULT"),
            fast,
            "two hops, which is the shape Apple's headers produce"
        );
        assert_eq!(
            level_of("SELF"),
            (Outcome::Indeterminate, None),
            "a cycle terminates"
        );
        assert_eq!(level_of("_NOT_A_MACRO"), (Outcome::Indeterminate, None));
    }

    /// aarch64 branch protection, one bit per mechanism, measured rather than assumed.
    ///
    /// Every row below is `clang -target aarch64-linux-gnu -dM -E` on this host:
    ///
    /// ```text
    /// -mbranch-protection=standard        BTI_DEFAULT 1   PAC_DEFAULT 1
    /// -mbranch-protection=none            (neither defined)
    /// -mbranch-protection=bti             BTI_DEFAULT 1
    /// -mbranch-protection=pac-ret         PAC_DEFAULT 1
    /// -mbranch-protection=pac-ret+b-key   PAC_DEFAULT 2
    /// ```
    ///
    /// That last row is the reason the detector tests `> 0` instead of `== 1`:
    /// `__ARM_FEATURE_PAC_DEFAULT` selects the signing key, so a boolean reading would
    /// report a `b-key` build as having no return-address signing, a false `off`.
    #[test]
    fn branch_protection_reads_each_mechanism_separately() {
        let outcome = |pairs: &[(&str, &str)]| {
            let macros: BTreeMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            let d = branch_protection_macro(&Evidence {
                macros: &macros,
                elf: None,
                build: None,
                run: None,
                workdir: None,
            });
            (d.outcome, d.level)
        };
        let bti = "__ARM_FEATURE_BTI_DEFAULT";
        let pac = "__ARM_FEATURE_PAC_DEFAULT";

        let (o, l) = outcome(&[(bti, "1"), (pac, "1")]);
        assert_eq!((o, l.as_deref()), (Outcome::Present, Some("full")));
        let (o, l) = outcome(&[(bti, "1")]);
        assert_eq!((o, l.as_deref()), (Outcome::Present, Some("branch")));
        let (o, l) = outcome(&[(pac, "1")]);
        assert_eq!((o, l.as_deref()), (Outcome::Present, Some("return")));
        assert_eq!(outcome(&[]).0, Outcome::Absent);

        // B-key PAC. `== 1` would call this absent.
        let (o, l) = outcome(&[(pac, "2")]);
        assert_eq!(
            (o, l.as_deref()),
            (Outcome::Present, Some("return")),
            "PAC_DEFAULT=2 is B-key signing, not the absence of signing"
        );
    }

    /// libc++'s mode constants are not in strength order, as its own header says: `debug`
    /// is the stronger mode and carries the smaller value (`1 << 3`, beside `extensive`'s
    /// `1 << 4`). Reading the shifts as ordered swaps the two names without moving the
    /// verdict, since both exceed the recommended `fast`.
    #[test]
    fn libcpp_mode_names_follow_libcpp_values_and_not_their_order() {
        let level_of = |value: &str| {
            let macros: BTreeMap<String, String> =
                [("_CXX_STDLIB", "libc++"), ("_LIBCPP_HARDENING_MODE", value)]
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect();
            cxx_hardening_requested(&Evidence {
                macros: &macros,
                elf: None,
                build: None,
                run: None,
                workdir: None,
            })
        };

        assert_eq!(level_of("(1 << 1)").outcome, Outcome::Absent, "NONE is off");
        assert_eq!(level_of("(1 << 2)").level.as_deref(), Some("fast"));
        assert_eq!(
            level_of("(1 << 3)").level.as_deref(),
            Some("debug"),
            "(1 << 3) is DEBUG in libc++, not EXTENSIVE"
        );
        assert_eq!(
            level_of("(1 << 4)").level.as_deref(),
            Some("extensive"),
            "(1 << 4) is EXTENSIVE in libc++, not DEBUG"
        );
    }

    /// The evidence string names every macro read, and says which of three states each
    /// was in, so a reader auditing `observed` can tell an explicit `-DFOO` from an absent
    /// macro. The sentence is `predicate::render_observed`'s.
    #[test]
    fn the_macro_sentence_distinguishes_defined_empty_from_undefined() {
        // `__SSP_ALL__` stands for a macro defined with no body, `__SSP_STRONG__` carries a
        // value, and `__SSP__` is simply not defined. The reads stop at the first clause
        // that holds, so each map shows the rungs read up to it.
        let over = |pairs: &[(&str, &str)]| {
            let macros = macro_evidence(pairs);
            ssp_level(&Evidence {
                macros: &macros,
                elf: None,
                build: None,
                run: None,
                workdir: None,
            })
            .observed
        };
        let all = over(&[("__SSP_ALL__", ""), ("__SSP_STRONG__", "3")]);
        assert!(all.starts_with("__SSP_ALL__= ("), "{all}");
        let strong = over(&[("__SSP_STRONG__", "3")]);
        assert!(
            strong.starts_with("__SSP_ALL__ undefined __SSP_STRONG__=3 ("),
            "{strong}"
        );
        assert_eq!(
            over(&[]),
            "__SSP_ALL__ undefined __SSP_STRONG__ undefined __SSP__ undefined \
             __SSP_EXPLICIT__ undefined"
        );
    }

    /// The same fixture `elf_with_report` deserializes, with the two search-path tags
    /// varied instead of the self-report.
    fn elf_with_search_paths(rpath: &[&str], runpath: &[&str]) -> ElfFacts {
        let mut facts = elf_with_report("");
        facts.rpath = rpath.iter().map(|s| (*s).to_owned()).collect();
        facts.runpath = runpath.iter().map(|s| (*s).to_owned()).collect();
        facts
    }

    fn detect_over_macros(
        detect: fn(&Evidence<'_>) -> Detection,
        pairs: &[(&str, &str)],
    ) -> Detection {
        let macros = macro_evidence(pairs);
        detect(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        })
    }

    /// A position-independence macro defined as zero is a compiler saying no.
    ///
    /// gcc and clang define `__PIE__`/`__PIC__` to a level rather than to `1`, and a
    /// build configured `-fno-pie` on a PIE-default toolchain can carry the macro with
    /// the value `0`, which `>= 0` would read as position independence.
    #[test]
    fn a_position_independence_macro_of_zero_is_absent_not_present() {
        for (detect, name, other) in [
            (
                pie_macro as fn(&Evidence<'_>) -> Detection,
                "__PIE__",
                "__PIC__",
            ),
            (pic_macro, "__PIC__", "__PIE__"),
        ] {
            let off = detect_over_macros(detect, &[(name, "0"), (other, "0")]);
            assert_eq!(off.outcome, Outcome::Absent, "{name}=0 read as present");

            let on = detect_over_macros(detect, &[(name, "2"), (other, "2")]);
            assert_eq!(on.outcome, Outcome::Present, "{name}=2 read as absent");
            assert_eq!(on.level.as_deref(), Some("2"), "{name}");

            let undefined = detect_over_macros(detect, &[]);
            assert_eq!(undefined.outcome, Outcome::Absent, "{name}");
        }
    }

    /// `__CET__` is a bitmask and each of its three states names a different protection.
    ///
    /// A toolchain can serve branch tracking without a shadow stack or the reverse, so
    /// collapsing the mask to on/off would report a half-protected build as protected.
    #[test]
    fn every_cet_bit_combination_names_what_survived() {
        for (value, level) in [("3", "full"), ("2", "return"), ("1", "branch")] {
            let d = detect_over_macros(cet_macro, &[("__CET__", value)]);
            assert_eq!(d.outcome, Outcome::Present, "__CET__={value}");
            assert_eq!(d.level.as_deref(), Some(level), "__CET__={value}");
        }
        assert_eq!(
            detect_over_macros(cet_macro, &[("__CET__", "0")]).outcome,
            Outcome::Absent
        );
        assert_eq!(detect_over_macros(cet_macro, &[]).outcome, Outcome::Absent);
        // A bit this chard does not know, or text the language cannot read as a number,
        // is a mask that is not absent and names no level.
        for value in ["4", "7", "(3)", "3U"] {
            let d = detect_over_macros(cet_macro, &[("__CET__", value)]);
            assert_eq!(d.outcome, Outcome::Indeterminate, "__CET__={value}");
            assert_eq!(d.level, None, "__CET__={value}");
        }
    }

    /// aarch64's BTI and PAC are independent, and PAC's macro is a key selector rather
    /// than a boolean.
    ///
    /// `__ARM_FEATURE_PAC_DEFAULT` is `1` for the A-key and `2` for the B-key, so testing
    /// it for `1` reads a `-mbranch-protection=pac-ret+b-key` build as unsigned.
    #[test]
    fn branch_protection_reports_which_of_bti_and_pac_survived() {
        let bti = "__ARM_FEATURE_BTI_DEFAULT";
        let pac = "__ARM_FEATURE_PAC_DEFAULT";
        for (bti_value, pac_value, outcome, level) in [
            ("1", "1", Outcome::Present, Some("full")),
            ("1", "0", Outcome::Present, Some("branch")),
            ("0", "1", Outcome::Present, Some("return")),
            ("0", "0", Outcome::Absent, None),
        ] {
            let d = detect_over_macros(
                branch_protection_macro,
                &[(bti, bti_value), (pac, pac_value)],
            );
            assert_eq!(d.outcome, outcome, "bti={bti_value} pac={pac_value}");
            assert_eq!(d.level.as_deref(), level, "bti={bti_value} pac={pac_value}");
        }

        // The B-key. Signed return addresses, and a detector testing for `1` misses it.
        let b_key = detect_over_macros(branch_protection_macro, &[(pac, "2")]);
        assert_eq!(b_key.outcome, Outcome::Present);
        assert_eq!(b_key.level.as_deref(), Some("return"));

        // One bit the language cannot read as a number withholds the pair: read as not
        // on, a BTI macro spelt `(1)` beside PAC would publish `return` for a build that
        // has both.
        let unreadable = detect_over_macros(branch_protection_macro, &[(bti, "(1)"), (pac, "1")]);
        assert_eq!(unreadable.outcome, Outcome::Indeterminate);
        assert_eq!(unreadable.level, None);
    }

    /// The Guarded Control Stack macro is read the same way and answers on the same
    /// boundary.
    #[test]
    fn a_guarded_control_stack_default_of_zero_is_absent() {
        let gcs = "__ARM_FEATURE_GCS_DEFAULT";
        assert_eq!(
            detect_over_macros(gcs_macro, &[(gcs, "1")]).outcome,
            Outcome::Present
        );
        assert_eq!(
            detect_over_macros(gcs_macro, &[(gcs, "0")]).outcome,
            Outcome::Absent,
            "a compiler that defined the macro to zero said no"
        );
        assert_eq!(detect_over_macros(gcs_macro, &[]).outcome, Outcome::Absent);
        assert_eq!(
            detect_over_macros(gcs_macro, &[(gcs, "(1)")]).outcome,
            Outcome::Indeterminate,
            "text the language cannot read as a number is neither yes nor no"
        );
    }

    /// A macro defined with text the language cannot read as a number withholds rather
    /// than reads as absent. `-D_FORTIFY_SOURCE=(3)` is a request the preprocessor
    /// evaluates, and reading it as none published `fortify-requested` `off` beside a
    /// `__USE_FORTIFY_LEVEL` of 3 (Fedora 44 x86_64, gcc 16.1.1, glibc 2.43; `3L` and
    /// `2UL` the same on Darwin arm64 under Apple clang 21).
    #[test]
    fn a_macro_the_language_cannot_read_as_a_number_withholds() {
        for value in ["(3)", "3L", "2UL", ""] {
            let requested = detect_over_macros(
                fortify_requested,
                &[("_FORTIFY_SOURCE", value), ("__USE_FORTIFY_LEVEL", "3")],
            );
            assert_eq!(
                requested.outcome,
                Outcome::Indeterminate,
                "_FORTIFY_SOURCE={value:?}"
            );
            assert_eq!(requested.level, None, "_FORTIFY_SOURCE={value:?}");

            // The library's own level is read whatever the request's spelling.
            let settled = detect_over_macros(
                fortify_effective,
                &[
                    ("_FORTIFY_SOURCE", value),
                    ("__USE_FORTIFY_LEVEL", "3"),
                    ("__OPTIMIZE__", "2"),
                ],
            );
            assert_eq!(
                settled.outcome,
                Outcome::Present,
                "_FORTIFY_SOURCE={value:?}"
            );
            assert_eq!(
                settled.level.as_deref(),
                Some("3"),
                "_FORTIFY_SOURCE={value:?}"
            );

            // Where no library identified itself, the request is not read as no request.
            let third = detect_over_macros(
                fortify_effective,
                &[("_FORTIFY_SOURCE", value), ("__OPTIMIZE__", "2")],
            );
            assert_eq!(
                third.outcome,
                Outcome::Indeterminate,
                "_FORTIFY_SOURCE={value:?}"
            );
        }
        let model = detect_over_macros(pie_macro, &[("__PIE__", "(2)"), ("__PIC__", "2")]);
        assert_eq!(model.outcome, Outcome::Indeterminate);
        assert_eq!(model.level, None);
        let model = detect_over_macros(pic_macro, &[("__PIC__", "2L")]);
        assert_eq!(model.outcome, Outcome::Indeterminate);
    }

    /// Apple's `_USE_FORTIFY_LEVEL` (one leading underscore, from `<secure/_common.h>`)
    /// answers on the same rule as glibc's, zero included.
    #[test]
    fn apples_fortify_level_of_zero_is_absent_and_a_level_is_present() {
        let apple = "_USE_FORTIFY_LEVEL";
        let off = detect_over_macros(fortify_effective, &[(apple, "0")]);
        assert_eq!(off.outcome, Outcome::Absent);

        let on = detect_over_macros(fortify_effective, &[(apple, "2")]);
        assert_eq!(on.outcome, Outcome::Present);
        assert_eq!(on.level.as_deref(), Some("2"));
    }

    /// The C++ standard library is identified from its own version macro when chard's
    /// summary is absent.
    ///
    /// `_CXX_STDLIB` is written into the self-report, so on a platform with no artifact
    /// reader only the dump's `_LIBCPP_VERSION` or `__GLIBCXX__` names the library. No Linux
    /// report reaches either arm, so the replay corpus does not cover them.
    #[test]
    fn the_cxx_standard_library_is_identified_without_chards_own_summary() {
        let libstdcxx = detect_over_macros(
            cxx_hardening_requested,
            &[("__GLIBCXX__", "20260101"), ("_GLIBCXX_ASSERTIONS", "1")],
        );
        assert_eq!(
            libstdcxx.outcome,
            Outcome::Present,
            "__GLIBCXX__ identifies libstdc++ when _CXX_STDLIB is absent"
        );

        // `(1 << 2)` is libc++'s `fast` mode, in the spelling the macro carries when the
        // named constant came from the command line rather than the header default.
        let libcxx = detect_over_macros(
            cxx_hardening_requested,
            &[
                ("_LIBCPP_VERSION", "210000"),
                ("_LIBCPP_HARDENING_MODE", "(1 << 2)"),
            ],
        );
        assert_eq!(
            libcxx.outcome,
            Outcome::Present,
            "_LIBCPP_VERSION identifies libc++ when _CXX_STDLIB is absent"
        );
        assert_eq!(libcxx.level.as_deref(), Some("fast"));

        // Neither macro, and no summary: nothing identified itself.
        let unknown = detect_over_macros(cxx_hardening_requested, &[]);
        assert_eq!(unknown.outcome, Outcome::Indeterminate);
    }

    /// `DT_RPATH` and `DT_RUNPATH` are two spellings of one hazard and either one is a
    /// finding: `||` in place of the conjunction that decides absence would report a binary
    /// carrying one of the two as clean, a false `absent` on a defect check.
    #[test]
    fn either_search_path_tag_is_reported_and_only_neither_is_absent() {
        for (rpath, runpath, outcome, level) in [
            (&[][..], &[][..], Outcome::Absent, None),
            (&["/opt/lib"][..], &[][..], Outcome::Present, Some("rpath")),
            (
                &[][..],
                &["/opt/lib"][..],
                Outcome::Present,
                Some("runpath"),
            ),
            (
                &["/opt/lib"][..],
                &["/opt/lib"][..],
                Outcome::Present,
                Some("rpath"),
            ),
        ] {
            let elf = elf_with_search_paths(rpath, runpath);
            let macros = BTreeMap::new();
            let d = rpath_absent(&Evidence {
                macros: &macros,
                elf: Some(&elf),
                build: None,
                run: None,
                workdir: None,
            });
            assert_eq!(d.outcome, outcome, "rpath={rpath:?} runpath={runpath:?}");
            assert_eq!(
                d.level.as_deref(),
                level,
                "rpath={rpath:?} runpath={runpath:?}"
            );
        }

        // No artifact is not an empty artifact.
        let macros = BTreeMap::new();
        let unread = rpath_absent(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: None,
            workdir: None,
        });
        assert_eq!(unread.outcome, Outcome::Indeterminate);
    }

    /// `-fpie` is `on`, and the code-model value is published as information only.
    ///
    /// `__PIE__` is 1 under `-fpie` and 2 under `-fPIE`, and both are fully position
    /// independent, so a recommendation of `2` would grade a PIE build `partial`. The check
    /// carries no recommendation, and `report::decide` reads `__PIE__=1` as `on`.
    #[test]
    fn a_small_code_model_pie_is_on_and_its_value_is_information_only() {
        use crate::report::{ArmInput, Verdict, decide};
        /// An evaluated arm with no flags: what is under test here is the detector.
        fn arm(d: &Detection) -> ArmInput<'_> {
            ArmInput {
                detection: Some(d),
                flags: Vec::new(),
                overridden: None,
            }
        }

        // A grade asking for `2` on the scale `1 < 2`, which the check does not carry.
        const GRADED: Grade = Grade {
            scale: Scale::Ordered(&["1", "2"]),
            recommended: "2",
            ungraded: &[],
        };

        let macros_probe = find("toolchain-macros").expect("the probe is in the corpus");
        for id in ["pie-macro", "pic-macro"] {
            let check = macros_probe
                .checks
                .iter()
                .find(|c| c.id == id)
                .expect("the check is in the corpus");
            assert!(
                check.levels.grade().is_none(),
                "{id} grades a code-model selector as a hardening level"
            );
            assert_eq!(
                check.levels, CODE_MODEL,
                "{id} publishes the code model as information"
            );
        }

        let small = detect_over_macros(pie_macro, &[("__PIE__", "1"), ("__PIC__", "1")]);
        assert_eq!(small.outcome, Outcome::Present);
        assert_eq!(
            small.level.as_deref(),
            Some("1"),
            "the value is still reported"
        );
        let forced_on = detect_over_macros(pie_macro, &[("__PIE__", "2"), ("__PIC__", "2")]);
        let forced_off = detect_over_macros(pie_macro, &[]);

        let (verdict, controls) = decide(&small, arm(&forced_on), arm(&forced_off), None, None);
        assert!(controls.discriminating());
        assert_eq!(
            verdict,
            Verdict::On,
            "-fpie is a position-independent executable"
        );

        let (graded, _) = decide(
            &small,
            arm(&forced_on),
            arm(&forced_off),
            None,
            Some(&GRADED),
        );
        assert_eq!(
            graded,
            Verdict::Partial,
            "this is the reading the recommendation produced, and why it is gone"
        );
    }
}
