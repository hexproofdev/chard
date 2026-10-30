// SPDX-License-Identifier: BSD-3-Clause

//! The probe corpus: what chard measures and how it decides.
//!
//! Probes are Rust data rather than a config file. The C sources are embedded with
//! `include_str!`, which is what lets chard ship as one static binary that needs nothing
//! in a guest image but the toolchain under test. Each check's [`Decoder`] is a
//! `chard-predicate/1` value on the macro and elf-static channels, one evaluator in
//! `crate::predicate` runs it, and a report can carry it beside the facts it read; on the
//! runtime and compiler-diag channels it is a function under `src/decode/`.
//!
//! ## Every check carries its own controls
//!
//! `positive` and `negative` are the flag sets that must and must not produce the
//! observable. The driver builds all three variants and only trusts the `bare`
//! measurement when the controls actually discriminated on *this* toolchain (see
//! `DESIGN.md`). A check whose controls do not discriminate is reported
//! `probe-invalid`, never `off`; that is the whole point, because an absent
//! observable is worthless evidence unless we have just watched the detector see
//! a present one.
//!
//! Note what the controls are for `CHECK_FORTIFY_DYNAMIC`: its negative control
//! is `-D_FORTIFY_SOURCE=2`, not fortify-off, because the claim under test is
//! "level 3 specifically", so the control has to prove level 2 misses it.
//!
//! ## Adding a check
//!
//! A check is a [`Check`] literal in a [`Probe`] of [`CORPUS`]. The pieces it needs besides the
//! literal are below, each with where it lives; `DESIGN.md` carries the arguments, and `chard
//! probes` lists the corpus as it stands. A test holds each piece unless its bullet says review
//! does, so a green suite says the pieces agree with each other. It does not say the controls
//! discriminate on a real toolchain: that is the measured run.
//!
//! Every check needs:
//! - **Its control triple.** `positive` must produce the observable and `negative` must not,
//!   on every toolchain the check is read on; a pair that does not discriminate publishes
//!   `probe-invalid` (`DESIGN.md`, "The control triple"); the measured run below holds this,
//!   not a test. A library every arm links goes in [`Probe::link_libs`], not in one arm's
//!   flags, which review holds.
//! - **Its regime.** [`Check::regime`] is [`Regime::Arm`], the flags that countermand the
//!   mechanism on top of the measured profile, or [`Regime::NotOwed`], the argument and its
//!   frame; there is no default (`DESIGN.md`, "The third control arm"). `tests/regime_arms.rs`
//!   lists the checks that own an arm in `OWNS_REGIME_ARM`.
//! - **Its decoder.** On the macro and elf-static channels, a predicate of its own in
//!   `src/predicate/macro_channel.rs` or `src/predicate/elf_static.rs`, listed in that file's
//!   `table()` (`tests/predicates.rs`). On the runtime and compiler-diag channels, a function
//!   under `src/decode/` named through `detector!`, with the ELF tables it reads and, on the
//!   runtime channel, its [`RunBasis`].
//! - **Its guide row.** A row of `guide::INVENTORY` that names it, or an entry in
//!   `guide::BEYOND_THE_GUIDE` where the guide does not name the flag.
//! - **Its replay fixture.** Evidence recorded from a real run in
//!   `tests/fixtures/detectors.json`, mined as `tests/detector_replay.rs` says under
//!   "Regenerating"; a check with none is named in that file's `UNCOVERED`, with the reason
//!   no reachable host can produce it.
//! - **Its recipe.** The detection recipe it rests on, or why it rests on none, in the
//!   project's recipe record outside this repository; review holds it, and the record's
//!   private cross-check runs before a merge that adds or renames a check.
//! - **The counts.** `PROBES` and `CHECKS` in `the_corpus_is_the_size_it_is_published_as`
//!   below, and every count a document states, which `tests/detector_replay.rs`'s
//!   `the_counts_in_the_docs_are_the_counts_in_the_corpus` reads.
//! - **A measured run.** The branch's binary and main's measure the same toolchains, gcc and
//!   clang under `bare`, `bare-optimized` and `openssf-tldr`, and the verdicts are compared
//!   (`scripts/cells.sh`). A triple that never discriminates there reads `probe-invalid`, which
//!   the comparison shows and the suite cannot.
//!
//! Where it applies:
//! - **An inert form.** A graded check, or one whose control arms both carry `-O2`, names the
//!   form in which its flag is present and does nothing, in `tests/inert_flags.rs`'s
//!   `INERT_FORMS`, or the reason it has none in `NO_INERT_FORM`.
//! - **A register entry.** What the check takes on trust is an entry in `report::ASSUMPTIONS`
//!   with its retirement condition, and a row of `THREAT_MODEL.md`'s register:
//!   `tests/register.rs` holds the entry and the row to each other, and review holds that the
//!   entry exists.
//! - **An input the driver decides.** A macro-channel check is listed in
//!   `report::COMPILE_INPUT_READINGS`, since a `-D` the driver adds decides it; a check whose
//!   reading a link input decides is in `report::LINK_INPUT_READINGS`, and one the exception
//!   model decides in `report::EXCEPTION_MODEL_READINGS`.
//! - **An architecture gate.** A check read on some architectures only has a row in the
//!   mechanism table (`src/mechanism.rs`), and its `Gate.arch` literal lists the architectures
//!   that row names, which `every_gate_list_is_the_tables` holds; `report`'s tests name the
//!   gated checks.
//! - **A kernel.** A check that sets [`Gate::needs_vm`] is named in `DESIGN.md`'s `needs_vm`
//!   sentence, in `--fail-on-missing`'s help and in README's paragraph on it.
//! - **The machine.** A runtime check on [`RunBasis::Machine`] is named in the lists of
//!   `measure`'s and `decode::runtime`'s tests and of `tests/detect_cli.rs`, and each `main` of
//!   its probe calls `chard_report_translation()` before its first output
//!   (`every_machine_probe_reports_its_translation_first`).
//! - **A corroboration group.** [`Check::corroborates`] joins checks that read the same
//!   protection through other channels; a report holds the group's members to agree, and
//!   review holds that a check joins the group it belongs in.
//!
//! A new probe adds its C source under `probes/`. A precondition the source checks is
//! exercised in `tests/probe_sources.rs`, which review holds, and a variable it pins in
//! [`Probe::run_environment`] has the sentence in `THREAT_MODEL.md` that `tests/register.rs`
//! holds.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::Serialize;

use crate::compile::BuildRecord;
pub use crate::decode::common::{
    CUT_MARKER, carries_a_cut, cxx_stdlib, parse_self_report, self_report_account,
    self_report_fields, self_report_malformed,
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
    detect_auto_var_init, detect_auto_var_init_pattern, detect_cxx_assertions,
    detect_fortify_percent_n, detect_fortify_runtime, detect_no_delete_null_checks,
    detect_no_strict_aliasing, detect_no_strict_overflow, detect_shadow_stack, detect_stack_clash,
    detect_stack_exec, detect_strict_flex_arrays, detect_strict_flex_arrays_enforced, detect_trapv,
    detect_zero_call_used_regs, detect_zero_init_padding,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
///
/// `report::defect_coverage` moves a defect's status on the checks that observe protection
/// alone. A request or a marking is tallied under its own key (`requested`, `marked`, and
/// `not-requested`, `not-marked` where it reads `off`) and moves the status in neither direction.
/// Its `on` is not protection observed: in a fleet sweep, `fortify-requested` read `on` on OpenBSD
/// under `openssf-tldr` with every fortify runtime rung `unsupported`, and `stack-buffer-overflow`
/// read `partial` from the request alone; the CET markings at `branch` (IBT, no shadow stack) read
/// `partial` there and `return-oriented-programming` read `partial` from them, against a defect the
/// forward edge does not address. Its `off` is not protection absent either: Apple's
/// `<secure/_common.h>` sets `_USE_FORTIFY_LEVEL` to 2 unless `_FORTIFY_SOURCE` is defined as 0,
/// and OpenBSD's arm64 kernel enforces BTI for every program not carrying `PT_OPENBSD_NOBTCFI`,
/// marked or not, so an absent request or marking does not show the mechanism absent.
///
/// A marking here is a property note or landing pad for a control-flow mechanism a CPU
/// enforces (CET, BTI, PAC, GCS), whose enforcement the check does not observe: no check
/// measures IBT, BTI or PAC enforcement, and `shadow-stack-enforced` measures the shadow stack
/// as a protection check of its own. The macro of a marking (`__CET__`, the
/// `__ARM_FEATURE_*` words) is the compiler's word that it marked, and is a marking too.
/// `pie`, `relro` and `noexecstack` are not markings in this sense: the layout the artifact
/// carries is the mechanism, `boundary` names what must hold where it runs, and
/// `noexecstack-enforced` measures the kernel's part. A compiler's predefined macro for a
/// protection (`__SSP_STRONG__`, `__PIE__`) and a C library's settled level
/// (`__USE_FORTIFY_LEVEL`) are the mechanism's own state as its producer reports it,
/// corroborated by the artifact readers, and count as protection; a macro the build supplies
/// to ask for one (`_FORTIFY_SOURCE`, `_GLIBCXX_ASSERTIONS`, `_LIBCPP_HARDENING_MODE`) is a
/// request, and stays one where a library's own default defines it (libstdc++ defines
/// `_GLIBCXX_ASSERTIONS` at -O0, which `cxx-hardening-requested`'s evidence attributes): the
/// macro asks, and `cxx-stdlib-assertions` and `cxx-assertions-symbol` observe the answer.
/// `tests::the_bearing_table_names_what_each_check_observes` pins which checks are which.
///
/// Published as each observation's `observes`, and folded into the corpus digest. On read, a
/// report without `observes` is refused whatever its corpus (`report::reread_observes`). A
/// report of this corpus is also held to the table:
/// `report::observes_agrees_with_bearing_table` refuses a word the table does not give. A
/// report of another corpus is read with the word it carries.
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
///
/// Not a probability and not a function of the outcome: `controls.discriminating` is what
/// varies with the run, and it is `true` for every observation carrying controls on this
/// host, so it cannot stand in for this. `channel` cannot either; `compiler-diag` splits
/// six `High` against nine `Medium`, and all fifteen render as the same `d`.
///
/// A check moves from `Medium` to `High` with the measurements that licensed it named
/// beside the rule it met; `predicate::elf_static::branch_protection_marked` carries the
/// rule and the measurements for the two aarch64 marking checks.
///
/// `Low` was declared and never constructed, and the schema described it as "expected for
/// asm-pattern heuristics and for runtime probes sensitive to optimization level", a
/// sentence false against the corpus, where all twelve runtime checks are `High`. A value
/// a producer cannot emit is a promise to a consumer that nothing keeps.
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
    /// the drivers choose the language from it. A C++ source named `.c` is C++ to `g++`
    /// and `clang++` alike, and `clang++` warns that it is treating C input as C++
    /// (`-Wdeprecated`), which a profile's `-Werror` turns into a failed build, so a macro
    /// dump through the C++ driver is named by this. Every probe's own source
    /// carries its language's suffix, held by a test over the corpus.
    #[must_use]
    pub const fn source_suffix(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cxx => "cpp",
        }
    }
}

/// What the probe links to.
///
/// Not cosmetic: several linker flags only take effect on one kind of output.
/// `-Wl,-z,nodlopen` sets `DF_1_NOOPEN` on a shared object but is silently
/// ignored for an executable; the linker still emits `DT_FLAGS_1`, just with the
/// bit clear. A probe that measured it on an executable would read "off" on every
/// distro forever, and be wrong on all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkMode {
    Executable,
    SharedObject,
    /// Compiled and not linked, so the artifact is what the *compiler* produced.
    ///
    /// Every other mode reads a linked artifact, which is the right subject for almost
    /// every question here; a property note in an executable is the AND of every input
    /// object, which is what a loader acts on. But that AND is also why a `cet-marked`
    /// reading cannot say *who* cleared the bit: one unmarked startup object chard did
    /// not build zeroes the word, and the compiler's own marking becomes invisible. An
    /// object file separates the two, and the pair is a finding a distribution can act
    /// on where a single withheld cell is not.
    Object,
    /// A shared object linked from code compiled exactly as the flags ask: `-shared` is
    /// added and no position-independence choice is made or dropped.
    ///
    /// [`Self::SharedObject`] supplies `-fPIC` where nothing chose and drops a profile's
    /// `-fPIE`, so that a profile written for executables can still link a library probe.
    /// Both are right for a check reading the library and wrong for one asking whether the
    /// profile's code can be linked into a library at all: under that mode `openssf-tldr`,
    /// which carries `-fPIE`, would link `-fPIC` code and read `on`. Only the output-kind
    /// flags `-pie` and `-no-pie`, which cannot share a link line with `-shared`, are
    /// dropped, and `pic-shared-link` is the check built this way.
    SharedObjectAsCompiled,
}

impl LinkMode {
    /// Flags the driver must add to produce this output kind, given what it was already
    /// asked to compile with.
    ///
    /// `-shared` is unconditional: it is what makes the output a library rather than a
    /// program, and nothing else can supply it.
    ///
    /// `-fPIC` is a **default, and it yields to an explicit choice**; the same way
    /// `-fhardened` yields to a `-fno-` on the command line. Without it a bare profile
    /// could not link the shared-object probe at all on most targets, so chard supplies
    /// it; but appending it unconditionally meant that an operator running
    /// `--profile explicit --flags "-fno-pic"` got `-fno-pic -shared -fPIC`, with
    /// `profile.cflags` recording `-fno-pic` and the build doing the opposite. A report
    /// that names a flag list it did not measure is the failure this whole tool exists
    /// to detect, in its own harness.
    ///
    /// It also has to yield for the corpus to measure text relocations at all: the
    /// positive control for `textrel-absent` is a deliberately non-PIC library, and an
    /// appended `-fPIC` would silently defeat it and leave the control undiscriminating.
    pub fn extra_flags(self, already: &[String]) -> Vec<&'static str> {
        match self {
            Self::Executable => Vec::new(),
            Self::Object => vec!["-c"],
            Self::SharedObjectAsCompiled => vec!["-shared"],
            Self::SharedObject => {
                let mut out = vec!["-shared"];
                if !Self::states_a_pic_choice(already) {
                    out.push("-fPIC");
                }
                out
            }
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
    /// of its spellings. `-fpic`/`-fPIC` differ only in GOT size and `-fno-pic` is the
    /// negation; all of them mean the caller has decided, so chard must not decide again.
    ///
    /// This list and [`Self::conflicts_with`]'s must stay in agreement. A spelling in one
    /// and missing from the other (`-fno-PIE`, say) would be unreachable here, because the
    /// conflict filter runs first and drops it before this is consulted, so nothing would
    /// misbehave, and a test that enumerates the spellings the code does would not catch
    /// it. Both lists carry every spelling because "unreachable today" is not a property
    /// either function states.
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
    ///
    /// `-pie` and `-shared` are mutually exclusive, so a profile aimed at
    /// executables (the OpenSSF TL;DR among them, which prescribes `-fPIE -pie`
    /// for executables and `-fPIC -shared` for libraries), would simply fail to
    /// link a shared-object probe. A build failure there says nothing about the
    /// flag under test, so the conflict is resolved rather than reported.
    pub fn conflicts_with(self, flag: &str) -> bool {
        match self {
            Self::Executable => false,
            // Nothing reaches a linker here, so a linker flag in the profile would be
            // passed to a compile-only invocation that has no use for it. `-fPIE` stays:
            // it is code generation, it is what the executable's own arm compiles with,
            // and dropping it would make the object a different build from the one whose
            // link is being compared against.
            //
            // The driver's link-only flags go too: clang reports each as "argument unused
            // during compilation" at `-c`, so beside a profile's `-Werror` the object did not
            // build and every object-mode check read `build-failed` for an LDFLAGS a real
            // build never hands a compile. Measured 2026-10-02 with `clang -Werror -c`,
            // clang 22.1.8 on Fedora 44 x86_64: refused for each of `-fuse-ld=lld`,
            // `--ld-path=`, `-static-pie`, `-rdynamic`, `-s`, `-static-libgcc`, `-L<dir>`
            // and `-znow`, as for `-Wl,` and the three output kinds; gcc 16.1.1 accepted
            // all but `--ld-path=`. `-static`, `-nostdlib` and `-pthread` were accepted by
            // both and stay. Being unused at `-c`, none changes the object.
            //
            // The same measurement found clang also refusing `-l<lib>`, `-r`,
            // `-nostartfiles`, `-nolibc`, `-shared-libgcc`, `--for-linker=<arg>`, `-T<script>`
            // and `-u<sym>`, which are dropped too; gcc 16.1.1 accepted all of them. `-u` is
            // matched as a prefix except for `-undef`, which is a
            // preprocessor flag. `-e` has no joined spelling to match: clang rejects `-emain`
            // as an unknown argument, and a prefix would take clang's `-emit-llvm`.
            //
            // The option word is decided here, and [`Self::partition_flags`] drops or keeps
            // its separate argument with it (`-z now`, `-L /dir`, `-Xlinker <arg>`, `-l m`),
            // as the one classifier spans them (`toolchain::read`), because a bare `-z`
            // dropped alone leaves `now` to reach the compiler as an input file. `-Xlinker`,
            // `-e` and `-rpath` are here for that pairing: each hands the linker its next
            // word, which clang refuses at `-c -Werror` as it refuses the joined spellings.
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
    ///
    /// The shared-object modes drop `-Wl,-pie` as they drop `-pie` and `-Xlinker -pie`.
    /// Passed through, it hands GNU ld `-pie` beside chard's `-shared`, and the linker
    /// writes a PIE. Measured on Fedora 44 x86_64 (gcc 16.1.1, clang 22.1.8) with only the
    /// other two dropped, `--ldflags -Wl,-pie` read `pic-shared-link` `probe-invalid` under
    /// `-fPIE` and `-fPIC` alike, with the link warning `cannot find entry symbol _start`,
    /// and `nodlopen` `not-applicable`, where `-Xlinker -pie` read `off`, `on` and `off`. A
    /// `-Wl,` list is dropped only when the conflicting word is the whole of it; a list
    /// carrying one beside other words (`-Wl,-z,now,-pie`) is kept as it is.
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
    ///
    /// The list is walked by the one classifier of what the driver does with the next word
    /// (`toolchain::read`): an option and the word it takes (a value-taking option's value,
    /// a selection's, a hand-on's handed word, a word joined to gcc's `--machine`) are one
    /// unit, kept or dropped together on the option's verdict ([`Self::conflicts_with`], of
    /// the word as gcc reads it, so `--shared` is `-shared` and `--for-linker` is
    /// `-Xlinker`), and never split: under [`Self::Object`] `-z now`, `-L /usr/lib`,
    /// `-Xlinker -z -Xlinker now`, `-Xlinker --as-needed`, `-u sym` and `-l m` are dropped
    /// whole (clang refuses each at `-c -Werror` as it refuses the joined spellings;
    /// measured 2026-10-02, clang 22.1.8 on Fedora 44 x86_64, for the first four, which gcc
    /// 16.1.1 accepted), and `-MF -L/x`, a dependency file named `-L/x`, is kept whole,
    /// where a rule over one token at a time dropped the `-L/x` and left `-MF` to take the
    /// next word, and `-l m` dropped the `-l` and left `m` to reach the compile as an input
    /// file. A pair flag at the end of the list, with no argument, drops alone. The word clang
    /// applies for one architecture (`-Xarch_<arch> <word>`) goes with its carrier on the
    /// applied word's verdict, as the bare word would: `-Xarch_x86_64 -fno-pie` and
    /// `-Xarch_x86_64 -pie` are dropped from a shared-object build, `-Xarch_x86_64 -fno-pic`
    /// is kept and read as the position choice ([`Self::states_a_pic_choice`]).
    ///
    /// In the other modes `-Xlinker` stays paired with its argument: both are kept, or both
    /// are dropped when the argument contradicts the output kind. A per-token rule would drop
    /// the `-pie` of `-Xlinker -pie` and keep the `-Xlinker`, which then takes chard's
    /// appended `-shared`; `pic-shared-link` would link an executable's crt files into a
    /// library and read `indeterminate`, as measured under gcc 16.1.1 and clang 22.1.8 on
    /// Fedora 44 x86_64.
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
                // the driver's own word would alone (`-Xarch_x86_64 -fno-pie` is dropped
                // from a shared-object build as `-fno-pie` is, so chard's own `-fPIC`
                // follows in both spellings; `Self::states_a_pic_choice` reads the kept
                // pair the same way).
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
///
/// The verdict a gate produces is fixed by the premise class of the gating rule it
/// reaches, [`crate::report::gating_rule::Premise`]. The architecture, libc and compiler
/// axes publish `unsupported` (a fact about the toolchain or target); the C++
/// standard-library axis publishes `not-applicable` (an observable owned by the other
/// library); `needs_vm` publishes `indeterminate` (a limit of the run, not of the
/// toolchain).
#[derive(Clone, Copy)]
pub struct Gate {
    /// Architectures the check applies to; empty means portable.
    ///
    /// The list is the mechanism table's ([`crate::mechanism`]): the
    /// architectures whose row for the check's question names it as a reader, and the gate
    /// decides from that table, not from this field, which `mechanism::tests` holds equal to
    /// it. The field stays a literal until the Check literals are next rewritten.
    pub arch: &'static [&'static str],
    /// libc implementations that are not *known* to support the flag.
    ///
    /// A weaker claim than the field name suggests, and deliberately so. It licenses
    /// nothing on its own: [`crate::report::libc_limitation`] consults it only after the
    /// flag has been forced on and produced no observable, so a libc listed here that
    /// does implement the mechanism is measured normally and never gated.
    ///
    /// That ordering is load-bearing rather than defensive. `musl` is listed against the
    /// fortify checks, and Alpine (which is musl) fortifies its entire archive through
    /// fortify-headers. A gate keyed on the name would have reported `unsupported` for a
    /// distribution whose packages are fortified throughout.
    pub libc_unsupported: &'static [&'static str],
    /// Compiler families that cannot support the flag, by [`crate::toolchain::Kind`]
    /// name, `"gcc"`, `"clang"`.
    ///
    /// Some of the guide's own recommendations are conditional on the compiler:
    /// its TL;DR lists `-Wtrampolines` under "when using GCC", and `-Wbidi-chars`
    /// has no clang equivalent at all. For those, clang's answer is not `off`
    /// (nothing was declined, the mechanism does not exist), and reporting `off`
    /// would read as a distribution's choice.
    ///
    /// Like `libc_unsupported`, this is *not* consulted before measuring. The
    /// claim is earned the same way `off` is: the flag is forced on, the
    /// observable fails to appear, and only then is the compiler's known
    /// limitation offered as the explanation. See
    /// [`crate::report::compiler_limitation`].
    pub compiler_unsupported: &'static [&'static str],
    /// C++ standard libraries whose runtime cannot express this check's observable.
    ///
    /// The same weak claim `libc_unsupported` makes, on the third axis a C++ probe has.
    /// `cxx-assertions-symbol` reads libstdc++'s `__glibcxx_assert_fail` out of the
    /// artifact; libc++ routes precondition failures through `__libcpp_verbose_abort` and
    /// has no such symbol, so on a libc++ toolchain both control arms are indeterminate
    /// and the triple has nothing to discriminate. Without the gate that publishes
    /// `probe-invalid` on OpenBSD and FreeBSD: chard's instrument accused of failing by a
    /// toolchain that simply keeps its assertions somewhere else, and whose hardening is
    /// measured by `cxx-stdlib-assertions` instead.
    ///
    /// Consulted only after the fact, like the two above it, and against the standard
    /// library the toolchain names in its own macros rather than one inferred from the
    /// platform. See [`crate::probe::cxx_stdlib`].
    ///
    /// The claim is of another class than `libc_unsupported`'s. The rule this axis
    /// reaches, `stdlib-lacks-observable`, has an `Inapplicable` premise and publishes
    /// `not-applicable`, while the libc axis stays a toolchain fact and publishes
    /// `unsupported`; see [`crate::report::gating_rule::Premise`]. It fires only when the
    /// profile-free build the controls share and the measured build name the same library.
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
///
/// The property a check measures can be universal while the way its control manufactures
/// it is not. `textrel-absent`'s control on x86_64 needs `-mcmodel=large`, which gcc
/// refuses in 32-bit mode; on i386 the non-PIC library needs no code model at all, and
/// the i386 list (`-fno-pic -Wl,-z,notext`) fails to link on x86_64. One list per check
/// held the gate at the architecture the list worked on. Measured 2026-09-30: the i386
/// list gives `DT_TEXTREL` under gcc 7.5.0, gcc 12.2.0 and clang 6.0.0 on i386.
///
/// Selected by the architecture [`crate::report::applicability`] compares the gate
/// against (`measure::Conditions::target_arch`), which the artifacts' `e_machine` and the
/// driver's architecture macros witness afterwards (`toolchain::target_agreement`), so
/// the list that built an arm and the gate that admitted the check read one value. A
/// wrong selection cannot publish `off`, and the reason is the triple, not the linker:
/// either the positive arm fails to build or reads absent, leaving the triple
/// undiscriminating (`probe-invalid`), or it produces `DT_TEXTREL` and is a valid
/// positive control. A wrong list does not reliably fail. Measured 2026-09-30: in a
/// Debian 12 i386 container gcc 12.2.0 refuses the x86_64 list in 32-bit mode, while
/// clang 14.0.6 accepts it and links an ELF32 object carrying `DT_TEXTREL`; on Fedora 44
/// x86_64 the i386 list fails to link under gcc 16.1.1 and clang 22.1.8. Each arm
/// publishes the flags it was built with (`controls.positive.flags`), and the consistency
/// rule that re-reads a quoted rejection reads it against this same selection.
///
/// A table beside the corpus rather than a field on [`Check`], and positive-only, because
/// that is all one check needs; [`corpus_sha256_of`] hashes the rows of the check it
/// hashes, and `probe::tests::every_arch_control_names_an_architecture_its_gate_admits`
/// holds each row to a check whose gate names the architecture.
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

/// A defect class a flag bears on.
///
/// **Authored by this project, not cited.** The OpenSSF guide describes what each
/// option counters in prose and cites no CWE anywhere, verified by grepping the
/// whole document, which contains zero `CWE-` references. So this mapping is our
/// claim and is labelled as such in the report; a reader who disagrees with an
/// assignment is disagreeing with us, not with the guide.
///
/// Names follow the guide's own vocabulary where it has one, since those are the
/// terms it uses consistently: buffer overflow, format string, return-oriented and
/// jump-oriented programming, stack clash, uninitialized, integer overflow. A CWE
/// id is attached only where one maps unambiguously; several of these mechanisms
/// have no clean CWE and inventing one would be worse than leaving it absent.
///
/// The point of this field is to let a report answer the question an incident
/// actually poses. The rsync chain of CVE-2024-12085 into CVE-2024-12084 was broken
/// by closing one *disclosure* primitive, not by hardening the overflow, so "which
/// primitives are closed in this build" is the useful query, and a flag list cannot
/// answer it.
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
        summary: "A write past the end of a stack buffer, overwriting saved registers, \
                  the return address, or an adjacent local.",
    },
    Defect {
        id: "heap-buffer-overflow",
        cwe: Some("CWE-122"),
        summary: "A write past the end of a heap allocation, corrupting adjacent chunk \
                  data or allocator metadata.",
    },
    Defect {
        id: "uninitialized-read",
        cwe: Some("CWE-457"),
        summary: "Reading an automatic variable that was never assigned, disclosing \
                  whatever the frame last held. The disclosure primitive in the rsync \
                  chain (CVE-2024-12085).",
    },
    Defect {
        id: "format-string",
        cwe: Some("CWE-134"),
        summary: "An attacker-influenced format string; with %n it becomes an arbitrary \
                  write.",
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
        summary: "A null pointer dereference the optimizer created by deleting a check it \
                  was entitled to assume redundant (CVE-2009-1897). That deletion is what the \
                  one check bearing on this class keeps from happening; a dereference the \
                  source itself performs is outside every check here, and this status says \
                  nothing about it.",
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
        summary: "Chaining existing return sequences to execute attacker-chosen \
                  behaviour without injecting code. No single CWE describes it.",
    },
    Defect {
        id: "jump-oriented-programming",
        cwe: None,
        summary: "The indirect-branch equivalent of ROP, chaining existing indirect \
                  jumps and calls. No check here observes enforcement of the forward \
                  edge (IBT, BTI), so this status is unknown in every report; the CET \
                  and BTI macros, markings and landing pads bearing on it are counted \
                  in verdict_counts as markings.",
    },
    Defect {
        id: "got-overwrite",
        cwe: None,
        summary: "Overwriting a relocation table entry that stays writable after \
                  startup, redirecting a later call.",
    },
    Defect {
        id: "stack-code-execution",
        cwe: None,
        summary: "Executing data written to the stack, which requires the stack to be \
                  mapped executable.",
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
        summary: "Learning where the image is mapped, which every code-reuse technique \
                  needs and which a fixed load address hands over for free.",
    },
    Defect {
        id: "optimizer-exploited-ub",
        cwe: Some("CWE-1038"),
        summary: "The compiler removed or altered code because it was entitled to assume \
                  an undefined behaviour could not occur, so the written source and the \
                  generated code disagree and nothing in the build says so. CVE-2009-1897 \
                  is the worked example: a null check the author wrote, deleted because an \
                  earlier dereference proved the pointer non-null.",
    },
    Defect {
        id: "undeclared-call-mismatch",
        cwe: Some("CWE-628"),
        summary: "Calling a function with no declaration in scope, so the compiler \
                  assumes a signature that may not match the definition.",
    },
];

/// Look a defect class up by id.
pub fn defect(id: &str) -> Option<&'static Defect> {
    DEFECTS.iter().find(|d| d.id == id)
}

/// Why a check exists, and where the argument about it happened.
///
/// This is the one thing a measurement cannot produce and a curated table can.
/// chard can tell you that Ubuntu's driver sets `_FORTIFY_SOURCE=3`; it cannot
/// tell you that the decision was argued in LP#2012440 and landed in gcc-13 rather
/// than in dpkg, and a reader who wants to know *why* a distribution chose
/// something needs the thread, not the number. So references are carried
/// alongside the verdict rather than left to a wiki that will drift away from it.
///
/// Every URL here was fetched or read during development. None is inferred from a
/// naming pattern, because a plausible-looking dead link is worse than no link.
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
    title: "musl: CET support patchset (Intel, October 2020), never merged",
    url: "https://inbox.vuxu.org/musl/20201019224342.53303-1-joao.moreira@intel.com/T/",
};

const RSYNC_HARDENING: Reference = Reference {
    kind: ReferenceKind::Incident,
    title: "CVE-2024-12085 disclosure chained into CVE-2024-12084; auto-var-init broke the chain",
    url: "https://www.chainguard.dev/unchained/mitigating-a-rsync-vulnerability-a-lesson-in-compiler-hardening",
};

const FLAGS_DISTRO_TABLE: Reference = Reference {
    kind: ReferenceKind::RelatedWork,
    title: "jvoisin/compiler-flags-distro: the same territory read off build systems",
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
    /// The one spelling. `report`, `fixture` and the schema's vocabulary list take the
    /// name from here rather than keeping a copy: a name a report is compared against is
    /// not the sort of thing to keep two of.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Indeterminate => "indeterminate",
        }
    }
}

pub struct Detection {
    pub outcome: Outcome,
    /// Which level is active, for graded mechanisms.
    pub level: Option<String>,
    /// Compact statement of what was actually seen; lands in `evidence`.
    pub observed: String,
    /// The gating rule the detector withheld under, where it withheld for a reason the
    /// table names ([`Self::withheld`]): `measure::settle` publishes it as the observation's
    /// `gating` where the triple discriminated, at
    /// [`crate::report::gating_rule::Stage::Detector`], the only stage a
    /// [`crate::report::gating_rule::DetectorRule`] can be of. `None` for every other
    /// reading. An `indeterminate` whose reason is `observed` alone is one of those, and
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
    ///
    /// A detector that cuts the captured text before `publish` relativises the excerpt
    /// moves the cut point with the length of `--workdir`, and its `[N chars omitted]`
    /// count includes path characters the published text never carries. A fleet sweep cut
    /// that way held 44 compiler-diag `observed` strings carrying a cut across its 247
    /// reports, 29 of them counting more than the published stream lost. On OpenBSD 7.9
    /// under `openssf-tldr`, `format-security-is-error` quoted one 669-character stderr with
    /// 109 characters omitted under a 21-character work directory and 68 under a
    /// 10-character one; re-cutting the stream with each prefix restored reproduces both
    /// counts. The excerpt helpers in
    /// `decode::common` take the evidence for this reason, so no cut can be made ahead of
    /// the rewrite. The detector still matches
    /// on the record as captured; only the quote is rewritten.
    #[must_use]
    pub fn published(&self, text: &str) -> String {
        crate::measure::publish_text(text, self.workdir.unwrap_or(std::path::Path::new("")))
    }
}

/// A check's level vocabulary, declared on the check so that no two checks' words are ever
/// compared.
///
/// One ranking table for every graded mechanism would put `basic`, `1`, `partial`,
/// `branch`, `return`, `pie` and `fast` on one rung, `strong`, `2` and `extensive` on the
/// next, `all`, `3`, `full`, `error` and `debug` on the top, with string equality for a word
/// the table lacks. Words from different mechanisms would then compare as rungs of one scale
/// (`return` meeting `branch`, a CET bitmask reading graded as a stack-protector strength),
/// and `_FORTIFY_SOURCE=4` would read `partial` for failing to equal `3`. Each scale lives
/// on its check: [`Grade::meets`] answers only for a word on that
/// check's own scale, `report::decide` withholds the verdict where it cannot answer, and
/// `report::level_gating` names why.
///
/// The three variants are the three things a detector's level can be. `None` is a detector
/// that never reports one. `Informational` is a word published beside `on` and graded
/// against nothing: `__PIE__`'s code model, a diagnostic's severity, which of `DT_RPATH`
/// and `DT_RUNPATH` was found. `Graded` is a scale and the guide's ask on it, and is the
/// only source of `partial`. A graded check whose detector reports `present` with no level
/// is withheld by construction, `indeterminate` with a reason, because `detect` is a
/// function pointer and nothing static stops a detector from publishing `on` through a
/// fallthrough; `cxx-hardening-requested`'s libstdc++ arm publishes `on` because the check
/// is informational.
///
/// `tests/inert_flags.rs` derives its graded set from this, `corpus_sha256` hashes it
/// because a change here moves verdicts, and `chard probes` publishes it so a consumer can
/// read which words `observations[].level` may carry.
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
    /// mechanism really made, published as the level and earning `on` as presence, that
    /// neither meets nor falls below the ask because it is not comparable with it.
    /// [`Grade::meets`] does not know them, so they grade `Grading::Ungraded` rather than
    /// `OffScale`; `Levels::admits` does. Empty on every scale but `SSP_LEVELS`, whose
    /// `unsafe-frame` is the case and says why. Never a word of `scale`, which
    /// `every_graded_check_recommends_a_word_on_its_own_scale` holds.
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
    /// 3, the check that reads the request measures what was asked, and `composite`
    /// already compares the level numerically, so a request of `4` meets an ask of `3`.
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
    ///
    /// The ask is parsed by the same arm that parses the reading, so on a numeric scale
    /// an ask that is not a number puts every reading off the scale, and the corpus test
    /// `every_graded_check_recommends_a_word_on_its_own_scale` holds every ask to meeting
    /// itself.
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
/// `predicate::macro_channel`'s `SSP_LEVEL` has the measurement. `report::corroboration`
/// names `explicit` as the level no probe function opts in to.
///
/// `unsafe-frame` ([`SSP_UNSAFE_FRAME`]) is on no rung. It is what `ssp-level-emitted` reads
/// from an object clang's `SafeStack` built: a canary in exactly the functions `SafeStack` gave an
/// unsafe frame, at whatever level was requested, a set that contains neither `strong`'s nor
/// `basic`'s and is contained by neither (it widens `basic` and narrows `all`, and leaves an
/// array `strong` admits bare where `SafeStack` proves it safe), so no position on the scale
/// is true of it. Published as the level because canaries are present and `on` is earned;
/// ungraded because the ask of `strong` is not a question it answers. The macro reader
/// never reports it: the preprocessor sees the request and `SafeStack` defines no macro. Both
/// stack-protector readers share this one constant so the group compares their words on one
/// scale (`report::corroboration`), and the macro's `all` or `basic` beside the artifact's
/// `unsafe-frame` reads as a level requested and not realised rather than as agreement.
/// `predicate::elf_static`'s `SSP_LEVEL_EMITTED` carries the measurement, 2026-10-08.
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
/// stack or PAC alone, `full` both. Named rather than ordered because the two components
/// are independent bits: a build with only `return` is neither above nor below one with
/// only `branch`, and the guide asks for both.
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
/// nothing is graded against it and `partial` is unreachable on it; `DESIGN.md`'s
/// "Verdict vocabulary" gives the rule: a word on a check that grades nothing is
/// information beside `on`, and `partial` is earned only on a graded check.
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
///
/// The control triple's two plain arms are profile-free, so they show the detector can see
/// the flag at all, not that the signal in the *measured* build came from it: something
/// else the profile carries can produce a **generic** observable (`-fstack-protector-strong`
/// zeroes the uninitialized locals `-ftrivial-auto-var-init=zero` zeroes; `-z ibt -z shstk`
/// forces the property bits `-fcf-protection` earns). The regime arm is the negative control
/// re-run on top of the profile, and an observable that survives it is withheld as
/// `regime-confounded`. `DESIGN.md` ("The third control arm") carries the argument.
///
/// A check either spells its arm or states why none is owed, and the field has no default,
/// so neither can be omitted. A bare `bool` with no reason stated would let a confounder
/// pass unexamined: a diagnostics format that hides the text, a sanitizer's checked add, and
/// clang's link-time optimization are three such. A reason is a hazard log, not a
/// detector: it names the profiles and toolchains it was argued or measured over, and
/// `tests/regime_arms.rs` pins the flag lists of those profiles (the guide revision and its
/// composed list for `openssf-tldr`, `-O2` for `bare-optimized`), so a change to either fails
/// there with the instruction to re-read every reason. The same file holds the declarations'
/// content and the list of checks owning an arm; a compile-time check below [`CORPUS`]
/// refuses an empty arm, an empty arm flag and an unframed reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime {
    /// The negative control re-run in the measured profile's regime: the profile's flags
    /// followed by these, so that they win. They are the arm's own, not [`Check::negative`]:
    /// the plain negative is profile-free and self-sufficient (a fortify control carries
    /// its own `-O2`), while this arm sits on a profile and needs only the countermand.
    /// So no arm carries an `-O`: one would override the profile's level and build the arm
    /// at another, outside the measured regime. An arm that copied its negative list's `-O`
    /// (`auto-var-init-active` and `-pattern` `-O1`, `cxx-assertions-symbol` and
    /// `stack-clash-guard-page` `-O2`) would, under an explicit profile at `-O0`, at `-O3`
    /// or with no `-O`, be built at its own level. Dropping it moves no verdict there or
    /// in the six cells, on Fedora 44 x86_64 under gcc 16.1.1 and clang 22.1.8; the built-in
    /// profiles that add flags both carry `-O2`, so the six cells cannot show it.
    /// `tests/regime_arms.rs` names those four as the arms differing from their negative and
    /// refuses an arm that carries an `-O`. Never empty: an arm with nothing appended would
    /// re-run the measured build as its own negative and withhold every `on`.
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
    ///
    /// Deliberately not "same protection family". The fortify rungs all concern
    /// fortify and are *expected* to differ (rung 1 firing while rung 3 does not
    /// is how level 2 is recognised), and `fortify-requested` legitimately exceeds
    /// `fortify-effective`, which is the inert-flag finding. Grouping those would
    /// report a permanent contradiction and train a reader to ignore the signal.
    ///
    /// What belongs here is redundant measurement: `__CET__` against the artifact's
    /// property note, `__SSP_STRONG__` against an emitted canary, `__PIE__` against
    /// `DF_1_PIE`. When those disagree something is wrong with the toolchain or with
    /// chard, and either is worth surfacing.
    pub corroborates: Option<&'static str>,
    /// Read this check's own observable from the *clean* build rather than the measured
    /// one.
    ///
    /// A check that asks what the toolchain does when nothing was passed cannot be
    /// answered from a build that passed something. `linker-default-noexecstack` asks
    /// exactly that, and its observable (`PT_GNU_STACK` without `PF_X`) is produced
    /// just as well by a profile carrying `-Wl,-z,noexecstack`, which is in the guide's
    /// own TL;DR block and in most distributions' LDFLAGS. Under any such profile the
    /// check credited the linker's compiled-in default with what the command line had
    /// just done, publishing `on` for a binutils whose `bare` column in the same sweep
    /// shows it defaults to an executable stack. The control triple cannot see it: both
    /// arms are profile-free, so they discriminate perfectly over a measured cell the
    /// profile produced.
    ///
    /// `false` for every other check, where the profile's flags are precisely what is
    /// being measured.
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
    /// neighbouring work. There is no per-distribution reference table, every entry here
    /// is copied into the report unfiltered, so anything tied to one distribution would
    /// travel to reports about all the others. A Fedora report citing a Launchpad bug
    /// about Ubuntu is worse than citing nothing, because it reads as evidence.
    pub references: &'static [Reference],
    pub gate: Gate,
    pub notes: &'static str,
}

/// What a runtime check's reading rests on: the program's own computation, or the
/// machine it ran on.
///
/// A runtime probe built for another architecture runs on Linux through `binfmt_misc`,
/// which hands it to a user-mode emulator such as `qemu-aarch64`. Where the reading is something
/// the program computes and prints, or a C library's diagnostic before an abort, an
/// emulator executing the same instructions produces the same reading. Where it is a fault
/// the memory map produces, an enforcement the CPU performs, or a mapping the kernel lays
/// out, the emulator produces it from its own model, and a reading taken there describes
/// the emulator. `report::emulation_limitation` withholds a `Machine` reading taken over an
/// artifact the kernel does not execute natively; a `Program` reading stands.
///
/// Declared on [`Decoder::Runtime`], so a runtime check cannot be written without saying
/// which it is. The measurement behind the classification (2026-10-01): the twelve
/// `Program` checks gave the same reading on every arm natively and under qemu-user 10.2.2,
/// and so did `stack-clash-guard-page`, which is `Machine` by its mechanism rather than by
/// a difference that run observed.
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
///
/// The macro and elf-static channels read published facts (a macro map, an artifact's
/// `ElfFacts`), and their decoder is a `chard-predicate/1` value the report can carry beside
/// those facts; a code decoder on either channel is unrepresentable here, which is the
/// point of the type. The runtime and compiler-diag channels read a run's output and a
/// build's diagnostics, and their decoders are functions under `src/decode/`, identified
/// in a report by the fingerprint [`decoders_sha256`] takes over their source. A check
/// carrying a `channel`, a `reads` list and a `detect` function pointer side by side would
/// hold three fields that have to agree and that nothing makes agree.
#[derive(Clone, Copy)]
pub enum Decoder {
    /// A macro-channel predicate, evaluated over the macro map.
    Macro(fn() -> &'static Predicate),
    /// An elf-static predicate, evaluated over the artifact's facts and the macro map.
    ElfStatic(fn() -> &'static Predicate),
    /// A runtime detector, and the ELF tables it reads through the self-report.
    ///
    /// `reads` is what `report::truncation_limitation` intersects with the tables the
    /// reader could not finish. The runtime fortify detectors read `self_report` through
    /// [`Evidence::fortify_impl`] and declare `SectionNames`: the self-report is the
    /// `.chard.report` section, reached by name, and a cut section-name table or an
    /// unreadable section empties it. Declared, that cut is named on the cell under
    /// `artifact-unreadable` rather than surfacing as an unexplained `indeterminate`.
    /// The two auto-var-init detectors declare `Header`: clang's pattern byte depends on
    /// the target's pointer width, read from the ELF class (`decode::runtime`'s
    /// `pattern_fill`), and declaring it is also what keeps their arms' artifacts in
    /// the store a replay reads. Every other runtime detector reads no ELF table and
    /// declares none.
    ///
    /// `basis` is what the reading rests on, which decides whether a run under user-mode
    /// emulation can answer for it; see [`RunBasis`].
    Runtime {
        detect: Detector,
        reads: &'static [ElfTable],
        basis: RunBasis,
    },
    /// A compiler-diag detector, and the ELF tables it reads from the artifact the build
    /// wrote.
    ///
    /// `reads` is the runtime variant's: what `report::truncation_limitation` intersects
    /// with the tables the reader could not finish, and what keeps the arms' artifacts in
    /// the store a replay reads (`report::stores_arm_artifacts`). `detect_pic_shared_link`
    /// declares `Dynamic`, since a link that succeeded is read through the shared object's
    /// `DT_TEXTREL`; every other compiler-diag detector reads the build record alone and
    /// declares none.
    CompilerDiag {
        detect: Detector,
        reads: &'static [ElfTable],
    },
}

/// A code decoder: the function, and the name the corpus hash binds it by.
///
/// A function pointer has no stable value to hash. A corpus hash binding only a code
/// decoder's kind and, through `decoders_sha256`, the source of every detector, and not
/// which detector a check names, would let a check pointed at another function under
/// `src/decode/` move its verdicts under an unchanged `probe_corpus_sha256`. `detector!`
/// writes the name from the function's own identifier, so the two cannot name different
/// functions.
#[derive(Clone, Copy)]
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
            None => decoder_sources_sha256(),
        }
    }
}

/// A detection, and the evaluation it came from where the decoder is a predicate.
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
    ///
    /// One function because three readers need the same answer: `measure` builds the arm
    /// under it, and the report's rule `verdict-unearned-by-controls` and `chard detect`
    /// hold a published triple to it. A reader taking a published arm as the only sign one
    /// was owed would read a triple with its regime arm deleted as one that never needed it,
    /// and a regime-confounded `on` would pass. The arm carries its own flags, which cannot
    /// be empty, so no check asks for the arm and is silently owed none.
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
    ///
    /// `report::truncation_limitation` intersects this with the tables the reader could
    /// not finish on the artifact (`ElfFacts::truncations`), and withholds the reading
    /// where they meet. For a predicate it is the predicate's `tables`, the same list its
    /// `@truncated` preamble reads, so the gate on the measured build and the evaluation
    /// cannot name different tables; `tests/predicates.rs` holds every table a predicate's
    /// terms read to be on it, and `tests/elf_truncations.rs` holds every cut that moves a
    /// reading to a table on it. For a code decoder it is the list the runtime variant
    /// declares, and for a compiler-diag decoder the list it declares.
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
    ///
    /// A predicate is evaluated over the Live view of the evidence's macro map and facts,
    /// and its detection is the evaluation's outcome and level with the sentence
    /// [`predicate::render_observed`] writes. The Live view answers every key a validated
    /// predicate reads, so an `Incomplete` is a predicate naming something the view cannot
    /// hold; it reads `indeterminate`, naming the key, never `absent`.
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
///
/// A verdict in a chard report is a property of the **artifact**: what the binary opts
/// into. Several of those protections only take effect if something outside the binary
/// also holds (the kernel, the CPU, or the C library), and no measurement of a file can
/// establish any of it. Without the boundary in the JSON that drives automation, a policy
/// engine reading `pie: on` has no way to learn that the claim is about `ET_DYN` and not
/// about address randomisation.
///
/// The runtime checks that run a program on the measuring host are the exception to the
/// first sentence: `noexecstack-enforced` reads whether that host's kernel executed the
/// stack of a program the toolchain linked, and `shadow-stack-enforced` whether a program
/// ran with the shadow stack enabled there, and each one's boundary names that host as the
/// scope.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Boundary {
    /// What the verdict does establish, in the artifact.
    pub establishes: &'static str,
    /// What must also hold where the binary runs. Each entry is something this report does
    /// not and cannot check, because chard reads a file.
    pub requires_at_runtime: &'static [&'static str],
}

/// The runtime preconditions per protection, keyed on the canonical flag spelling.
///
/// Keyed on flag rather than carried on every [`Check`] because the boundary is a property of
/// the protection, and several checks measure one protection through different channels,
/// `__PIE__` and `DF_1_PIE` are two readings of the same claim and share one boundary. One
/// table, for the reason `env::FAMILIES` is one table.
///
/// Absence is meaningful and is the common case: a stack canary, a fortified call and full
/// RELRO are enforced by the artifact and the loader with nothing further required, so those
/// checks carry no boundary rather than an empty one. Only protections with a genuine external
/// dependency appear here.
const BOUNDARIES: &[(&str, Boundary)] = &[
    (
        "-fPIE",
        Boundary {
            establishes: "the binary is ET_DYN with DF_1_PIE, so the loader may place it at a randomised base",
            requires_at_runtime: &[
                "kernel address-space randomisation enabled (`kernel.randomize_va_space` non-zero); PIE is worth little where ASLR is off",
            ],
        },
    ),
    // The enforcement reading of CET, before the marking's entry, since the lookup is the
    // first prefix match and this flag also starts with `-fcf-protection`.
    (
        "-fcf-protection=full (shadow stack enforced)",
        Boundary {
            establishes: "with glibc's opt-in set, a program this toolchain built ran with the shadow stack enabled, and an overwritten return address faulted, on this kernel, CPU and C library; the level says whether the same program run without the opt-in was enforced too (`default`, `on`) or not (`opt-in`, `partial`)",
            requires_at_runtime: &[
                "at level `opt-in`, the same opt-in where the program runs: glibc 2.39 and later leave the shadow stack off unless `GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK` is set, and chard set it, with a witness tunable beside it, for the run that decides the outcome",
                "every object the program loads marked for the shadow stack: one unmarked shared object turns it off for the whole process at startup, and a later `dlopen` of one is refused while it is on",
                "a kernel with user shadow stack and a CPU implementing CET shadow stack where the program runs, as this run's machine had",
            ],
        },
    ),
    // Ahead of `-fcf-protection`, because the lookup takes the first key the flag starts
    // with: `cet-endbr-emitted` reads code, not a note, and reads `on` under `=branch`,
    // which declares no shadow stack, so the entry below misdescribed it.
    (
        "-fcf-protection=branch",
        Boundary {
            establishes: "the compiled object's functions begin with IBT landing pads (endbr64 on x86_64, endbr32 on i386)",
            requires_at_runtime: &[
                "a CPU implementing IBT",
                "a kernel that enables user-mode IBT, which mainline Linux does not as of 2026-10-02",
                "a link that keeps the IBT bit of the GNU property note, which `cet-marked` reads; one input without it clears the bit for the program",
            ],
        },
    ),
    (
        "-fcf-protection",
        Boundary {
            establishes: "the binary carries a GNU property note declaring IBT and shadow-stack compatibility",
            requires_at_runtime: &[
                "a CPU implementing CET; the note is a claim of compatibility, not evidence of enforcement",
                "kernel support for the shadow stack, and a glibc that opts into it",
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
    // running the program, and carries its own entry below. This entry is `noexecstack`'s,
    // whose verdict is a reading of the file.
    (
        "non-executable stack at runtime",
        Boundary {
            establishes: "on the kernel and CPU this run used, bytes a program this toolchain linked copied onto its stack faulted when called, or ran",
            requires_at_runtime: &[
                "a kernel where the binary runs that treats PT_GNU_STACK as the measuring host's did; the reading is of that host, and is withheld under a container (`needs_vm`), where nothing established whose kernel it is (`execution-mode-assumed`), under user-mode emulation and over an artifact the reader could not read",
            ],
        },
    ),
    // The artifact reading of PIE, which is the one the README uses as its worked
    // example: "a policy engine reading `pie: on` can see that the claim is about
    // `ET_DYN` and not about address randomisation". It carried no boundary, because
    // the key above is `-fPIE` and this check's flag is `-pie`: the lookup is a prefix
    // match on the flag string, so the macro reading of a protection got the note and
    // the artifact reading of the same protection did not.
    (
        "-pie",
        Boundary {
            establishes: "the linked artifact is ET_DYN marked as executable output by DF_1_PIE, PT_INTERP or DT_DEBUG, so the loader may place it at a randomised base",
            requires_at_runtime: &[
                "kernel address-space randomisation enabled (`kernel.randomize_va_space` non-zero); PIE is worth little where ASLR is off",
            ],
        },
    ),
    // aarch64 branch protection, covering all four checks: both mechanisms and both
    // channels share this prefix. One entry rather than four, the way `-fcf-protection`
    // already serves both the macro and the artifact reading of CET, and with the same
    // imprecision, since a macro check establishes that the compiler was asked while an
    // artifact check establishes that the note survived the link.
    //
    // These need the note more than most: `environment.cpu.relevant_features` records
    // `bti`, `paca`, `pacg` and `gcs` precisely so a reader can tell marked from
    // enforceable, and without a boundary nothing in the observation points at it.
    //
    // The second line differs by kernel. On OpenBSD 7.9 arm64, measured, BTI is enforced
    // on a program whose note is missing and turned off by the program's
    // `PT_OPENBSD_NOBTCFI` header (`composite::cfi_constituent` records the run). The
    // first line's feature list is read from `/proc/cpuinfo`, which OpenBSD does not have,
    // and was empty in every report from that guest although its CPU implements BTI. On
    // Linux, BTI is opt-in per mapping: `PROT_BTI` on a marked object's executable pages,
    // which the kernel sets for the interpreter or a static program
    // (`arch_elf_adjust_prot`) and the dynamic loader for the rest. GCS is per thread:
    // `PR_SET_SHADOW_STACK_STATUS` enables it for the calling thread only, new threads
    // inherit it and exec disables it (`Documentation/arch/arm64/gcs.rst`, Linux 7.3-rc3),
    // and the kernel does not read the GCS marking. glibc's loader makes the call at
    // startup under its `glibc.cpu.aarch64_gcs` policy: the tunable and its "not GCS
    // compatible" errors are in Fedora 44's aarch64 glibc 2.43 `ld-linux-aarch64.so.1`, and
    // how the policy weighs the marking is inferred from those strings and is not
    // measured on aarch64 hardware.
    (
        "-mbranch-protection",
        Boundary {
            establishes: "the compiler was asked for branch protection, and where the check reads the artifact, that GNU_PROPERTY_AARCH64_FEATURE_1_AND survived the link",
            requires_at_runtime: &[
                "a CPU implementing the requested features; `environment.cpu.relevant_features` reports `bti`, `paca`, `pacg` and `gcs` where the host advertises them in `/proc/cpuinfo`, so it is empty on a system without one, OpenBSD among them",
                "a kernel that enables them for userspace. On Linux, BTI is opt-in per mapping, the kernel or the dynamic loader mapping a marked object's executable pages `PROT_BTI`; GCS is enabled per thread by `prctl(PR_SET_SHADOW_STACK_STATUS)`, which the C library makes at startup where the marking of the loaded objects and its own policy allow (glibc's `glibc.cpu.aarch64_gcs` tunable), and new threads inherit; and PAC needs key management the kernel provides. On OpenBSD, BTI is enforced whether or not the program is marked, and a PT_OPENBSD_NOBTCFI program header (`-Wl,-z,nobtcfi`) turns it off for the whole program, which `cfi-effective` reads",
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

pub struct Probe {
    pub id: &'static str,
    pub title: &'static str,
    pub lang: Lang,
    pub link_mode: LinkMode,
    /// Empty for a probe whose checks are all `macro`-channel: those need only a
    /// preprocessor run, which [`crate::compile::macro_dump`] supplies itself.
    pub source_name: &'static str,
    pub source: &'static str,
    /// Libraries this probe must link against, in **every** arm: positive control,
    /// negative control, regime control and measured build alike.
    ///
    /// Distinct from a check's `positive`/`negative` flags, which differ between arms
    /// by design. These are part of the probe's own shape: `-Wl,--as-needed` cannot be
    /// measured at all unless there is a library on the command line for the linker to
    /// consider dropping, so `-lm` has to be present in the arm that drops it *and*
    /// the arm that keeps it. Putting it in the controls instead would make the two
    /// arms differ in two ways at once and the check would measure their sum.
    ///
    /// Appended **after** the source file rather than with the other flags, because GNU
    /// ld resolves libraries in command-line order: a `-l` preceding the object that
    /// references it contributes nothing, and with `--as-needed` in effect is dropped
    /// even when the symbol is used. So the position is load-bearing, not cosmetic,
    /// which is why this is its own field rather than more entries in `cflags`.
    pub link_libs: &'static [&'static str],
    /// Shared libraries this probe needs built *before* its own link, in order.
    ///
    /// Empty for every probe but one. `-Wl,--no-copy-dt-needed-entries` governs whether
    /// the linker will resolve a symbol through a library it was never told about: one
    /// named in another library's `DT_NEEDED` rather than on the command line. That
    /// cannot be posed with a system library the way `--as-needed` poses its question
    /// with `-lm`: it needs a two-deep chain the harness builds itself, so the transitive
    /// dependency is one nothing else on the link line already satisfies.
    ///
    /// Built with a fixed, minimal flag set rather than the arm's flags, and deliberately.
    /// These are scaffolding, not the measured artifact: the flag under test applies to
    /// the *final* link, and letting it reach the scaffolding would change what the chain
    /// is rather than how the last link treats it. See `copy_dt_needed.c`.
    pub aux_libs: &'static [AuxLib],
    /// Variables this probe's runs receive beside [`crate::run::PROBE_ENVIRONMENT`], in
    /// every arm: positive, negative, regime and measured alike, as `link_libs` reaches
    /// every arm's link.
    ///
    /// Empty for every probe but `shadow-stack`. A probe runs with no ambient variable, and
    /// a pin on the base list would reach every probe; a variable that is part of one
    /// probe's question belongs to that probe. `shadow-stack` asks whether the shadow stack
    /// is enforced for a program the toolchain built, and glibc 2.39 and later answer only
    /// for a process that opted in through `GLIBC_TUNABLES`, so the opt-in is the probe's
    /// to set and its arms differ in the flag alone. Each run record's `environment`
    /// carries the pin, so the condition is published with the reading; `THREAT_MODEL.md`
    /// names it, which `tests/register.rs` holds, and [`corpus_sha256_of`] hashes it, since
    /// a changed pin changes the question.
    pub run_environment: &'static [(&'static str, &'static str)],
    pub checks: &'static [Check],
}

/// A shared library built to stand behind a probe, not measured itself.
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
    ///
    /// True when any check's channel requires one, and *also* whenever the probe
    /// carries a source at all. The second condition exists because the macro
    /// channel reads its state from a compiled translation unit rather than
    /// from `cc -dM -E`: a macro-only probe still has to be built, or it silently
    /// falls back to the preprocessor and measures the wrong job.
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
    ///
    /// Every probe with a macro-channel check does, and
    /// `tests::every_macro_channel_probe_embeds_the_self_report` holds it: the macro
    /// channel's witness is that section, and a macro check over an artifact without one
    /// is withheld under `artifact-lacks-self-report`. The other probes that embed it
    /// carry it as provenance, and `measure::evidence_faults` warns when their artifact
    /// lacks it. Those need not reference it from code, and most do not, so a
    /// `--gc-sections` link on a compiler without `retain` can drop it; the warning is then
    /// the only mark, since the section reaches such a probe's readings only in the
    /// fortify runtime detectors, which credit a trap to fortify-headers or Apple's
    /// implementation (`decode::runtime`'s `fortify_impl`) or name a library without
    /// subobject bounds (`library_without_subobject_bounds`) from it and withhold without
    /// it, and in the choice among the reasons for a `probe-invalid`.
    /// `tests/fake_driver.rs`'s
    /// `a_probe_without_a_macro_check_reads_no_verdict_from_its_self_report` measures each
    /// such probe with the section and without, and the register entry
    /// `self-report-absent-withholds-the-macro-channel` names the residual.
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
///
/// The predicate's `DT_NEEDED` prefix is derived from this argument
/// (`predicate::elf_static`'s `as_needed_soname_prefix` reads the probe's `link_libs`), so
/// the argument and the prefix cannot disagree. Written as separate literals they would be a
/// silent coupling: changing the library would leave the decoder looking for a name no
/// build could produce, it would read the entry as absent, and report the flag `on`, a
/// false `on`, the outcome `THREAT_MODEL.md` defends against first.
///
/// libm and not something smaller because it has to be linkable everywhere chard runs and
/// separable from libc: glibc 2.34 merged libdl, libpthread and librt into libc, so those
/// produce one `DT_NEEDED` in both control arms and cannot show the difference. Where a
/// libc merges libm too, neither arm carries the entry, the controls agree, and the check
/// reports `probe-invalid`, which is the honest answer rather than a gap.
const AS_NEEDED_LINK_ARG: &str = "-lm";

/// The spelling every fortify negative control carries to reach a genuine off.
///
/// `-U_FORTIFY_SOURCE` alone assumes nothing else defines the macro, and it is not the
/// compiler that breaks the assumption. Apple's SDK does, from a header:
///
/// ```c
/// /* usr/include/_types.h, reached transitively from <string.h> */
/// #ifndef _FORTIFY_SOURCE
/// #  define _FORTIFY_SOURCE 2    /* on by default */
/// #endif
/// ```
///
/// `-U` only removes an *earlier command-line* definition, so by the time that guard is
/// reached the macro looks unset, `#ifndef` fires, and the header defines it anyway.
/// `-D_FORTIFY_SOURCE=0` leaves a real value in place that the guard cannot overwrite.
/// Measured on arm64: a probe built with `-O2 -U_FORTIFY_SOURCE` still self-reports
/// `_FORTIFY_SOURCE=2` and still trips the same trap as its positive control, and
/// `cc -### `/`cc -dM -E` over an empty file show the driver injecting nothing and the
/// compiler predefining nothing. A negative arm that fires identically to the positive
/// one cannot discriminate, so the check would report `probe-invalid` for a mitigation that
/// is plainly in force.
///
/// The `cxx-stdlib-assertions` negative arm meets the same defect on Fedora, one layer
/// lower down. That the fortify arms are built profile-free is true and not enough:
/// profile-free is not compiler-free. `-D_FORTIFY_SOURCE=0` is the term the header
/// condition actually tests, so it suppresses the definition however it arrived.
const FORTIFY_OFF: &str = "-D_FORTIFY_SOURCE=0";

/// The negative control of `pie-macro`: position-independent code off, and the link that
/// matches it.
///
/// The arm is linked, like every macro arm, and its macros are read from the artifact's
/// `.chard.report` where the link produced one. `-fno-PIE` alone is half a request on a
/// driver that links PIE by default: the code is built position-dependent and the driver
/// still links it `-pie`, and the link fails on the probe's own absolute reference to its
/// self-report. In a fleet sweep of 2026-10-06 that link failed in 76 cells, on GNU ld as
/// `R_X86_64_32 against .chard.report` and on lld as `R_X86_64_64` against a local symbol,
/// across gcc 7.5.0 to 16.2.1 and the PIE-default clangs (Chimera, OpenBSD amd64). A macro
/// arm whose build failed is unevaluable, so with that arm both checks would read
/// `probe-invalid` there over a dump that shows `__PIE__` absent correctly.
///
/// The remedy is in the arm rather than the rule. The rule's reason is that a dump answers for
/// flags while the cell asks about the build those flags make; a negative arm that cannot
/// be linked is not a build with PIE off, and `-fno-PIE -no-pie` is. It is the `pie`
/// check's negative control too, and in the same sweep that arm linked in each of the
/// 224 published reports that built it (gcc 7.5.0 to 16.2.1, clang 6.0.0 to 23.1.2, GNU
/// ld and lld, glibc and musl, Linux and both BSDs); none failed. A driver that does not
/// know `-no-pie` refuses the arm, and the check is withheld there as `pie` is, under
/// `unhardened-state-unbuildable`. In a fleet sweep, gcc 4.8.4, clang
/// 3.4.0 and clang 3.8.0 (Ubuntu 14.04 and 16.04) reject `-no-pie` (`unrecognized command
/// line option`, `unknown argument`), and in their `bare` and `bare-optimized` cells `pie`,
/// `pie-macro` and `pic-macro` are withheld under `unhardened-state-unbuildable`; Ubuntu
/// 16.04's gcc 5.4.0 accepts it.
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
    observable: "glibc's \"buffer overflow detected\" on an abort, a bare trap from an \
                 implementation the self-report names, or a bare abort where it names \
                 FreeBSD's and the artifact calls a checking function, on a heap object \
                 whose size only __builtin_dynamic_object_size can determine",
    levels: Levels::None,
    confidence: Confidence::High,
    // Level 2 is the negative control rather than fortify-off: the claim is that level 3
    // specifically is active, so the control must show level 2 missing it.
    //
    // `-fno-lto` last in both arms. The probe's discrimination rests on the compiler not
    // knowing the destination's size, and link-time optimisation is one way a size can
    // become visible; the research recipe behind this probe measured gcc false-firing at
    // level 2 under `-flto` with a separately compiled size function. chard's probe keeps
    // the size opaque with a `volatile` instead, which LTO cannot fold, but a compiled-in
    // LTO default is a toolchain property the profile-free arms would otherwise inherit,
    // and last on the line the flag wins. The measured build does not get it: that arm
    // carries the profile's flags and nothing appended that changes code generation, the
    // same rule `LinkMode::extra_flags` keeps for `-fPIC`, and the probe's own
    // `__builtin_object_size` self-check is what protects it there.
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
        reason: "glibc's buffer-overflow diagnostic is written by its fortified wrappers and by \
                 nothing else, and a bare trap is read only where the probe's self-report names an \
                 implementation that traps; of the flags of bare-optimized and openssf-tldr only \
                 _FORTIFY_SOURCE reaches those wrappers, with -O as its precondition rather than a \
                 confound (argued).",
        profiles: PROFILES_WITH_FLAGS,
        toolchains: GCC_AND_CLANG,
    }),
    measures_toolchain_default: false,
    references: &[GUIDE],
    gate: Gate {
        arch: &[],
        // Apple joins the list on measurement, not on reputation. Its headers clamp any
        // `_FORTIFY_SOURCE > 1` to `_USE_FORTIFY_LEVEL=2`, as the header reads, as a live
        // control triple confirms, and as building this probe at level 3 on arm64 confirms,
        // where it exits 0 having caught nothing.
        // `__builtin_dynamic_object_size` never engages, so there is no level-3 mechanism
        // here to measure.
        //
        // FreeBSD the same way: `<ssp/ssp.h>` clamps every request above 1 to
        // `__SSP_FORTIFY_LEVEL=2` and its wrappers ask `__builtin_object_size` only.
        // Measured on 15.1 amd64 (clang 19.1.7): this probe exits 0 having caught
        // nothing at every level at -O2 and at level 2 at -O0; and on 14.5, which has no
        // implementation at all.
        //
        // The gate still cannot fabricate: `report::libc_limitation` fires only when the
        // positive control was forced on and produced no observable, so an Apple release
        // that does implement level 3 shows the observable and is measured normally.
        libc_unsupported: &["musl", "openbsd", "apple", "freebsd"],
        compiler_unsupported: &[],
        cxx_stdlib_unsupported: &[],
        needs_vm: false,
    },
    notes: "The only behavioral discriminator between _FORTIFY_SOURCE=2 and =3. \
            Requires optimization: glibc's checks live in inline wrappers that do \
            not exist at -O0, so a bare profile with no -O reports off. The probe \
            checks its own precondition: if the compiler knew the destination's \
            size, level 2 would fire like level 3, so the probe exits distinctly and \
            the verdict is withheld rather than published as either.",
};

pub const CORPUS: &[Probe] = &[
    Probe {
        id: "toolchain-macros",
        title: "Predefined macros the toolchain sets by default",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        // A real translation unit, so the macro state is read from what the
        // *compiler* believed rather than from a separate preprocessor job. The two
        // can differ (see `probes/macro_report.c`) and the difference is reported
        // rather than silently resolved in favour of whichever was consulted.
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
                    reason: "__SSP__, __SSP_STRONG__, __SSP_ALL__ and __SSP_EXPLICIT__ are \
                             predefined by the compiler exactly when it compiles at that protector \
                             level, whichever spelling asked (the flag, -fhardened, a configured \
                             default), so the macro is the mechanism's own state; no flag of \
                             bare-optimized or openssf-tldr defines one by -D (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Reports which level the compiler defaults to. Cross-checked \
                        against an actual canary by the stack-canary probe. gcc's \
                        -fstack-protector-explicit reads partial at explicit, the bottom \
                        rung, since it instruments only functions marked \
                        __attribute__((stack_protect)); the artifact readers read off \
                        there, as no probe function is marked, and the group counts that \
                        as neither a disagreement nor a corroboration. clang rejects the \
                        flag.",
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
                    reason: "the observable is the _FORTIFY_SOURCE macro itself, which only a -D \
                             or -U of that name sets, on the line or from a specs or configuration \
                             file; the profile's -D_FORTIFY_SOURCE=3 is the flag under test, and \
                             no other flag of either profile defines or undefines _FORTIFY_SOURCE \
                             (openssf-tldr's other -D words name the C++ library's macros) \
                             (argued).",
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
                notes: "What was asked for, which is not necessarily what is in \
                        force; see fortify-effective and the two runtime probes.",
            },
            Check {
                id: "fortify-effective",
                // The matrix key, so it names what the check measures rather than one
                // library that measures it. Three implementations answer here now, and
                // "glibc settled on" was a label a Darwin or Alpine report carried while
                // reporting a level glibc had nothing to do with. Safe to change while
                // 0.1.0 is unreleased: `table` groups rows by `report::family`, which maps
                // this to `fortify` either way, so only a `matrix` key moves.
                flag: "_FORTIFY_SOURCE (level in force)",
                decoder: Decoder::Macro(macro_channel::fortify_effective),
                polarity: Polarity::Harden,
                observable: "the level the C library settled on: __USE_FORTIFY_LEVEL \
                             from glibc's <features.h>, _USE_FORTIFY_LEVEL from Apple's \
                             <secure/_common.h>, __SSP_FORTIFY_LEVEL from FreeBSD's \
                             <ssp/ssp.h>, or _FORTIFY_HEADERS_H where fortify-headers is \
                             the implementation",
                levels: FORTIFY_LEVELS,
                confidence: Confidence::High,
                positive: &["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-O2"],
                negative: &["-U_FORTIFY_SOURCE", FORTIFY_OFF, "-O2"],
                defects: &["stack-buffer-overflow", "heap-buffer-overflow"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "the C library derives __USE_FORTIFY_LEVEL from _FORTIFY_SOURCE and \
                             __OPTIMIZE__ alone, so the only other flag that moves it is -O, the \
                             precondition this check's levels publish rather than a confound \
                             (argued over bare-optimized and openssf-tldr).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    arch: &[],
                    // FreeBSD below 15 has no implementation: the positive arm
                    // reads `freebsd-without-ssp`, absent, and this gate names the library.
                    // A FreeBSD whose headers settle a level is measured normally.
                    libc_unsupported: &["musl", "openbsd", "freebsd"],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "glibc silently downgrades a requested level it cannot serve, \
                        so this can be lower than fortify-requested. Divergence \
                        between the two is a finding in itself. Under fortify-headers \
                        the two diverge by construction: it has no subobject bounds at \
                        any level, so a level-2 or level-3 request is enforced at 1.",
            },
            Check {
                id: "pie-macro",
                flag: "-fPIE",
                decoder: Decoder::Macro(macro_channel::pie_macro),
                polarity: Polarity::Harden,
                observable: "__PIE__",
                // No recommendation, so the value is never graded. `__PIE__` is a code
                // model selector rather than a hardening level: 1 is `-fpie` and 2 is
                // `-fPIE`, and both produce a fully position-independent executable with
                // identical address-space randomisation on every architecture chard
                // measures; the difference is a GOT-size limit on targets that have one.
                // Graded against `2`, a `-fpie -pie -O2` build read `partial` here while
                // the artifact check beside it read `pie: on` for the same binary, and the
                // two never met because their rollup keys differ. The numeric value is
                // still published as `level`, as information about which spelling was
                // used, which is the only thing it ever said.
                levels: CODE_MODEL,
                confidence: Confidence::High,
                positive: &["-fPIE"],
                negative: PIE_MACRO_NEGATIVE,
                defects: &["address-layout-disclosure"],
                observes: Observes::Protection,
                corroborates: Some("pie"),
                regime: Regime::NotOwed(Specific {
                    reason: "__PIE__ is predefined exactly when the compiler generates \
                             position-independent executable code, by -fPIE, -fpie, -fhardened or \
                             a configured default, each of which is the mechanism in force; no \
                             other flag of either profile defines it (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "`on` whenever __PIE__ is set and non-zero. The level carries the \
                        macro's value as information: 2 is -fPIE, 1 is -fpie, and the two \
                        differ only in GOT addressing on targets with a small code model, \
                        never in position independence, so neither is a weaker form of the \
                        other and no level is recommended.",
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
                    reason: "__PIC__ is predefined by -fPIC and -fpic and equally by -fPIE and \
                             -fpie: both pairs give the same value (2 for the upper-case forms, 1 \
                             for the lower-case, measured on gcc 16.1.1 and clang 22.1.8), so the \
                             level does not tell code built for a shared object from code built \
                             for an executable, and openssf-tldr, which carries -fPIE and no \
                             -fPIC, reads this check on at 2. The check reads position-independent \
                             code generation in force, by whichever spelling, and not readiness \
                             for a shared library, which is pic-shared-link's and \
                             pic-object-relocs' question (their arm is -fPIE). No appended \
                             countermand would separate the two (-fno-pic removes both, -fPIE \
                             after the profile defines the macro itself), so no arm is owed \
                             (argued, with the -fPIE value measured).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "The guide recommends `-fPIE -pie` for executables and `-fPIC \
                        -shared` for libraries, and `pie`/`pie-macro` only answer the \
                        first. This is the other half: whether the toolchain generates \
                        position-independent code by default, which is what decides \
                        whether an ordinary object can go into a shared library without \
                        being rebuilt. Measured on an executable-mode probe deliberately: \
                        the shared-object probe is compiled `-fPIC` by chard itself, so \
                        reading the macro there would measure the harness. \
                        Expect it to track `pie-macro` on a distribution configured \
                        `--enable-default-pie`, since -fPIE implies position independence \
                        and defines both macros; the case it separates is a toolchain \
                        defaulting to PIC without defaulting to PIE. The level carries \
                        __PIC__'s value as information: 2 is -fPIC, 1 is -fpic, a \
                        code-model choice rather than a grade, so no level is recommended.",
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
                    reason: "__CET__ is predefined by -fcf-protection, and by -fhardened which \
                             implies it, and by nothing else in either profile; the linker's -z \
                             ibt -z shstk, which forges the property note cet-marked owes its arm \
                             for, never reaches a predefined macro (argued).",
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
                notes: "Compile-time intent. Whether the markings survive into the \
                        artifact is the cet-marked check; whether hardware enforces \
                        them is a separate question again.",
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
                    reason: "__ARM_FEATURE_GCS_DEFAULT is predefined by -mbranch-protection=gcs \
                             and by nothing else in either profile; -z gcs=always forges the \
                             property note gcs-marked owes its arm for and never reaches a \
                             predefined macro (argued, aarch64).",
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
                notes: "No level: GCS is on or it is not, unlike the BTI/PAC pair whose \
                        two mechanisms are separately requestable. A compiler that does \
                        not know the flag fails its own positive control, so this reports \
                        probe-invalid there rather than crediting the absence to the \
                        distribution.",
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
                    reason: "__ARM_FEATURE_BTI_DEFAULT and __ARM_FEATURE_PAC_DEFAULT are \
                             predefined by -mbranch-protection and by nothing else in either \
                             profile; -z force-bti forges the property note \
                             branch-protection-marked owes its arm for and never reaches a \
                             predefined macro (argued, aarch64).",
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
                notes: "The aarch64 counterpart to cet-macro, and the reason the CET pair \
                        is gated to x86 rather than reporting `off` everywhere else: the \
                        protection exists on this architecture under a different flag, so \
                        silence about it was a gap rather than an absence. \
                        `-fhardened` does not enable it, which is why composite.rs marks \
                        the CET constituent inapplicable here instead of unsatisfied, and \
                        why the `cfi-effective` composite exists to ask the \
                        cross-architecture question separately.",
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
                    reason: "__OPTIMIZE__ is the mechanism itself, defined by every -O above -O0; \
                             under bare-optimized the profile's -O2 is the flag under test, which \
                             flags_source states, and no flag of openssf-tldr other than its -O2 \
                             defines or undefines it (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Load-bearing for hardening, not just performance: \
                        _FORTIFY_SOURCE is inert without it. A toolchain that \
                        defaults to -O0 cannot have fortify active by default.",
            },
        ],
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
            // Deliberately not part of the `cet` corroboration group. Corroboration means
            // two channels agreeing about one artifact; this is one channel reading a
            // different artifact, and counting it as a second channel would let a marked
            // object vouch for a linked binary that carries no IBT or SHSTK at all, the
            // false corroboration `corroboration` already records fixing once, in this
            // very protection.
            //
            // The `cet` group's members do not read one artifact either:
            // `corroboration.*.sources` on Fedora 44 (gcc 16.1.1, clang 22.1.8, all three
            // profiles) shows `cet-macro` reading the `toolchain-macros` probe's artifact
            // and `cet-marked` the `link-defaults` probe's. The exclusion stands on the
            // other half of the sentence: an object is not the linked binary the protection
            // is about. (The `exceptions` group's two members do read one object, the
            // `exceptions` probe's, and that group's `independent_witnesses` is 1 where both
            // measure.)
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "read from the compiled object before any link, so the -z ibt -z shstk \
                         forcing that confounds cet-marked cannot reach it; a compiler writes the \
                         object's property bits only when it emitted CET code, under \
                         -fcf-protection or -fhardened, and no other flag of either profile does \
                         (argued).",
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
            notes: "The compile side of `cet-marked`, and only useful beside it. The \
                    property word in a linked binary is the AND across every input \
                    object, so one unmarked startup file chard did not build zeroes it \
                    and the compiler's own marking becomes invisible, which reads as \
                    the toolchain not marking at all. Read as a pair: this `on` beside \
                    that `off` says the compiler did its part and the link cleared it, \
                    which names an input rather than withholding a cell. That is a bug \
                    report a distribution can act on, and it is why this is a separate \
                    check rather than a second channel on the same one.",
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
            observable: "endbr64 (x86_64) or endbr32 (i386) as the first instruction of each \
                         of the probe's address-taken functions in the object file",
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
                reason: "an endbr64 as a function's first instruction is emitted by \
                         -fcf-protection=branch or full, and by -fhardened, and by no other flag \
                         of either profile; a linker cannot insert an instruction into compiled \
                         code (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            // x86 alone. aarch64's landing pad is `bti c`, and the bytes at a function's
            // entry do not separate it from return signing there: clang 22.1.8 on Fedora 44
            // aarch64 began a leaf function with `paciasp` and no `bti c` under
            // `-mbranch-protection=pac-ret+leaf+bti` and under `pac-ret+leaf` alike (2026-10-02,
            // `objdump -d` over this probe at -O2), so reading `bti c` would be a false `off`
            // and reading either as a pad a false `on`. `branch-protection-marked` reads the
            // BTI bit from the note.
            gate: Gate {
                arch: &["x86_64", "x86"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The instrumentation beside the claim. `cet-marked-object` reads the \
                    property note the compiler writes into the same kind of object; this \
                    reads the landing pads the note says are there, at the entry of three \
                    functions the probe stores in a table of function pointers. A marked \
                    object without landing pads (assembly, or a tool that sets the note \
                    without compiling the code) reads `on` there and `off` here. Only the \
                    branch half: `-fcf-protection=return` compiles no landing pad and reads \
                    `off`, and the shadow-stack half is the note's. gcc from 15 combines \
                    `-fcf-protection` values, so `=full` followed by `=return` keeps the \
                    landing pads there; older gcc and clang take the last value. Ubuntu's \
                    gcc enables the flag by default on x86_64, so `bare` reads `on` there.",
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
            observable: "the relocation of the object's one call to an external function: \
                         through the callee's GOT slot (R_X86_64_GOTPCRELX, R_386_GOT32X, \
                         R_AARCH64_ADR_GOT_PAGE with LD64_GOT_LO12_NC, gcc's small-model \
                         R_AARCH64_LD64_GOTPAGE_LO15, or R_RISCV_GOT_HI20) rather than a \
                         direct call a PLT entry serves (R_X86_64_PLT32, R_386_PLT32 or \
                         PC32, R_AARCH64_CALL26, R_RISCV_CALL_PLT)",
            levels: Levels::None,
            confidence: Confidence::High,
            // `-fPIE` beside the flag because gcc on aarch64 honours -fno-plt only in
            // position-independent code, and Fedora's gcc does not default to it: there
            // `-fno-plt` alone emits the same `R_AARCH64_CALL26` as `-fplt`, and the triple
            // would be `probe-invalid` on a toolchain whose flag works wherever it is used
            // in PIC. Fedora 44's riscv64 cross gcc 16.1.1 has the same shape, with
            // `R_RISCV_CALL_PLT` for both (2026-10-05). Everywhere else measured `-fPIE`
            // changes nothing about the call
            // (`predicate::elf_static`'s PLT_BYPASSED carries the hosts), and it is not the
            // observable: under `-fPIE` alone the call is still a PLT call on every
            // toolchain measured. One list for every architecture rather than an
            // `ARCH_CONTROLS` row, since that table admits only the architectures a gate
            // names, and this check is not gated.
            positive: &["-fPIE", "-fno-plt"],
            negative: &["-fplt"],
            // None, deliberately. -fno-plt makes each such call load its target from a GOT
            // slot the dynamic linker fills at load time (`GLOB_DAT`, never lazy), and
            // with `PT_GNU_RELRO` that slot is read-only before `main` even without
            // BIND_NOW; that is the GOT overwrite `relro` at level `full` closes for every
            // call at once. Counted toward `got-overwrite`, a build with full RELRO and no
            // -fno-plt would read `partial` on a defect it has mitigated.
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a call relocation against the callee's GOT slot rather than its PLT is \
                         -fno-plt's own code generation; of the profiles' flags only -fPIE touches \
                         the call's relocation model, and under -fPIE alone the call is still a \
                         PLT call on every toolchain measured (the comment above and PLT_BYPASSED \
                         in predicate::elf_static), which is why the openssf-tldr cells, carrying \
                         -fPIE, read off. -mcmodel=large would bypass the PLT as well and is in \
                         neither profile: that residual is argued, not measured.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            // The guide does not name the flag.
            references: &[],
            // Portable. The reader names relocation types on x86_64, i386 and aarch64,
            // where the triple was measured to discriminate, and on RISC-V, where gcc
            // 16.1.1's objects were measured to carry both forms (2026-10-05, cross-compiled
            // on Fedora 44 x86_64; no native riscv64 triple has run). On any other machine
            // the types render as numbers no clause matches, both arms read
            // `indeterminate`, and the check is `probe-invalid`: chard's reader cannot see
            // the flag there, which is not a statement that the architecture has no such
            // mechanism, the sentence `arch-gated` publishes.
            gate: PORTABLE,
            notes: "Read on an object: the probe calls one external function, and the check \
                    reads how that call is relocated. -fno-plt compiles it as an indirect call \
                    through the callee's GOT slot, so the program needs no PLT entry for it, \
                    and the slot is bound when the program loads rather than lazily. That is \
                    also what -Wl,-z,now does for every call at link time, so with full RELRO \
                    (`relro` at level `full`) the GOT is read-only either way; with partial \
                    RELRO, -fno-plt's slots are in the read-only part, while the PLT's \
                    function slots stay writable where the linker leaves them outside it, as \
                    every Linux linker measured on x86_64 does (the `relro` check's note says \
                    where they are read-only). gcc on aarch64 and RISC-V honours the flag only \
                    in position-independent code, so on a gcc that does not default to PIE a \
                    build without -fPIE reads off with the flag passed, which is what the \
                    object does. An object with no call to read (the caller deleted, or LTO's \
                    IR in place of code) reads indeterminate, never off. One object says \
                    nothing about the rest of a program.",
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
                    reason: "DF_1_PIE, PT_INTERP and DT_DEBUG are written by the linker for a -pie \
                             link, whichever spelling asked (-pie, -fhardened, a configured \
                             default), and a -shared link, the other ET_DYN producer, writes none \
                             of them; no other flag of either profile changes the link's output \
                             type (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "ET_DYN alone would also match a shared library, hence the \
                        additional DF_1_PIE / PT_INTERP / DT_DEBUG requirement. DT_DEBUG \
                        is what lld 10.0.0 leaves on a plain static PIE it does not mark \
                        DF_1_PIE; under -z rodynamic it leaves neither, the artifact \
                        classifies as a shared object, and the reading is withheld.",
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
                    reason: "PT_GNU_RELRO and the now-binding tags are written by the linker under \
                             -z relro and -z now, or a configured default, each the mechanism in \
                             force; no other flag of either profile changes segment layout or \
                             binding (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                // Where the lazy-binding table lies, measured by a program that writes its own
                // DT_PLTGOT slots back under a fault guard, before and after its first PLT
                // calls. Fedora 44 x86_64, glibc, gcc 16.2.1 and clang 22.1.8, each through GNU
                // ld 2.46.1, gold 1.16, lld 22.1.8 and mold 2.40.4: with no `-z` flag and under
                // `-z relro -z lazy` 8 (GNU ld, gold) or 13 (lld, mold) of 13 writes succeed,
                // under `-z relro -z now` none, under `-z norelro` all 13. GNU ld and gold put
                // only the table's three reserved slots inside PT_GNU_RELRO, so DT_PLTGOT's own
                // address lies inside it there; lld and mold put none of it inside. OpenBSD 7.9
                // amd64 and arm64 (clang and lld 19.1.7) and 8.0 amd64 and arm64 (clang 22.1.6,
                // lld): none with no `-z` flag, under `-z relro -z lazy` or under `-z now`, all
                // 13 under `-z norelro`, with the whole of `.got.plt` inside PT_GNU_RELRO and
                // no DF_BIND_NOW in the first two. Under ktrace on OpenBSD 7.9 and 8.0 amd64
                // the default build makes 10 kbind(2) calls and the `-z now` build none. Other
                // OpenBSD architectures, and other systems, were not measured. `got-overwrite`
                // keeps the one reading of `partial` everywhere: `report::defect_coverage`
                // reads verdicts, and no check reads whether the table's function slots lie
                // inside PT_GNU_RELRO.
                notes: "With PT_GNU_RELRO and no BIND_NOW the level is `partial`, and the \
                        program's lazy-binding table (DT_PLTGOT, the PLT's GOT) is filled \
                        after startup. On Linux (measured on x86_64 with glibc) GNU ld, gold, \
                        lld and mold leave that table's function slots outside PT_GNU_RELRO, \
                        so they stay writable; that is why the level is reported rather than \
                        collapsed. On OpenBSD 7.9 and 8.0, amd64 and arm64, lld places the \
                        whole table inside PT_GNU_RELRO and ld.so binds lazily through the \
                        kbind(2) system call (traced on amd64), so a partial build leaves none \
                        of it writable to the program. Other systems were not measured. \
                        `got-overwrite` reads partial RELRO as `partial` on every system, so \
                        on OpenBSD it understates the protection.",
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
                    reason: "PT_GNU_STACK without PF_X is written by the linker from -z \
                             noexecstack, or from every input object carrying .note.GNU-stack, \
                             which is a toolchain default in force and what \
                             linker-default-noexecstack tells apart; no other flag of either \
                             profile reaches the stack segment's flags (argued).",
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
                observable: "no allocated non-code section (SHF_EXECINSTR clear, \
                             .note.gnu.build-id aside) in a page an executable PT_LOAD \
                             maps, the page being the segment's p_align and at least \
                             4096 bytes",
                levels: Levels::None,
                confidence: Confidence::Medium,
                positive: &["-Wl,-z,separate-code"],
                negative: &["-Wl,-z,noseparate-code"],
                // None, deliberately. The bytes the flag keeps out of executable pages are
                // gadget sources, so `return-oriented-programming` is the nearest class, but
                // the flag shrinks the surface a chain is built from rather than mitigating
                // the chain, and counted there it lifted that defect from `not-mitigated` to
                // `partial` under `bare` on Fedora 44 x86_64 with gcc 16.1.1 and clang
                // 22.1.8 (2026-10-02), where no stack protector, CET marking or other
                // bearing check reads `on`: a linker's default layout read as a mitigation.
                defects: &[],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "code and non-code sections kept in separate pages is the linker's -z \
                             separate-code, or a configured default, in force; no other flag of \
                             either profile changes section-to-segment placement (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                // Read from the measured build, not the clean one. The guide does not name
                // the flag, so no shipped profile passes it, and under `bare` the measured
                // build is the linker's default; a profile that passes either spelling is
                // asking about its own link, and the clean build would answer a different
                // question. `linker-default-noexecstack` reads the clean build because its
                // observable is produced by a flag in the guide's own TL;DR block.
                measures_toolchain_default: false,
                // The guide does not name the flag, and no universal reference beyond the
                // linkers' own manuals does; `ret-protector-emitted` carries none either.
                references: &[],
                // Portable: GNU ld, lld and mold accept both spellings on every ELF target
                // measured, and a linker that took the flag and laid nothing out
                // differently reads absent in the positive arm, which is
                // `probe-invalid`, never `off`. gold (binutils 2.38 and 2.46.1) rejects
                // both spellings as an unknown `-z` option, so under `-fuse-ld=gold` neither
                // control links and the check reads `probe-invalid` (2026-10-02).
                gate: PORTABLE,
                notes: "A linker property, and the linkers differ: GNU ld defaults to \
                        separate-code on x86_64 Linux (binutils 2.31 onward) and not on \
                        aarch64, and lld and mold default to noseparate-code everywhere, \
                        letting the first and last pages of the code segment share bytes \
                        with the segments beside it. Under `bare` this reads the default \
                        of whichever linker the driver chose. Read by page, not by which \
                        sections a segment lists, since lld and mold keep `.text` in a \
                        segment of its own either way. Fedora's GNU ld keeps the ELF \
                        header and `.note.gnu.build-id` in the code segment on x86_64 \
                        even under separate-code; header bytes are not sections and the \
                        note is not counted, so that layout reads `on`. gold rejects \
                        both spellings, so under -fuse-ld=gold the controls do not \
                        link and the check reads probe-invalid. Not in the guide.",
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
                    reason: "DT_RPATH and DT_RUNPATH are written only from -rpath, -R or an \
                             LDFLAGS default naming a path, and no flag of either profile names \
                             one; the clean build stands in as the negative, so there is no \
                             countermand to append (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Discouraged by the guide, so polarity is `weaken`: presence \
                        is the adverse finding.",
            },
            Check {
                id: "relative-relocs",
                flag: "-Wl,-z,pack-relative-relocs",
                decoder: Decoder::ElfStatic(elf_static::relr),
                polarity: Polarity::Harden,
                observable: "DT_RELR",
                levels: Levels::None,
                confidence: Confidence::Medium,
                // DT_RELR only exists for position-independent output, so the
                // positive control has to establish PIE as well; without -pie the
                // flag is accepted and does nothing, and the control would fail
                // for a reason that has nothing to do with the distro's default.
                positive: &["-fPIE", "-pie", "-Wl,-z,pack-relative-relocs"],
                negative: &[],
                defects: &[],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "DT_RELR is written only under -z pack-relative-relocs, or a \
                             configured linker default, which is the mechanism in force; no other \
                             flag of either profile changes relocation packing, and the clean \
                             build stands in as the negative (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Startup-cost reduction for PIE rather than a hardening \
                        mechanism itself, but a visible distro-default difference \
                        worth tracking alongside them. Necessarily off wherever PIE \
                        is off, since relative relocations presuppose it.",
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
                // beside `cet-endbr-emitted` `off`). The plain arms carry no profile flag, so
                // only an arm built in the profile's regime with `-fcf-protection=none`
                // appended sees a marking the code did not earn. A toolchain that forces it
                // by default shows it in the plain negative arm already.
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
                notes: "Markings only. Enforcement needs CPU and kernel support, \
                        which is why this is not evidence that CET is active at \
                        runtime.",
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
                // under qemu-user, gcc 16.2.1 and clang 22.1.8: this check read `on`). The
                // regime arm, the profile followed by `-mbranch-protection=none`, sees it, as
                // for `branch-protection-marked`.
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
                notes: "Markings only, and High on the same two measurements as \
                        branch-protection-marked (2026-09-28): the feature word is an AND \
                        across input objects, and the check reads `on` under Fedora 44 \
                        glibc 2.43, whose startup objects carry the note, and withholds as \
                        probe-invalid under Alpine edge musl 1.2.6, whose startup objects \
                        carry none. Enforcement needs a CPU and kernel with GCS support; \
                        environment.cpu records `gcs` alongside bti, paca and pacg, so a \
                        reader can tell a marked binary from an enforcing host.",
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
                // code with no landing pad. An object built `-mbranch-protection=pac-ret` linked
                // `-z force-bti` carries BTI and PAC, with GNU ld 2.46.1 and LLD 22.1.8 alike, each
                // warning and exiting 0 (2026-10-05, Fedora 44 aarch64 under qemu-user, gcc 16.2.1
                // and clang 22.1.8: this check read `on` at `full` beside
                // `cfi-effective` `on`, and `partial` at `branch` over `-mbranch-protection=none`).
                // The plain arms carry no profile flag, so only an arm built in the profile's
                // regime with `-mbranch-protection=none` appended sees a marking the code did not
                // earn. A toolchain that forces it by default shows it in the plain negative arm
                // already.
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
                notes: "Markings only, exactly as for cet-marked: enforcement needs a CPU \
                        and kernel that honour BTI and PAC, and `environment.cpu` records \
                        the `bti`, `paca` and `pacg` features so a reader can tell marked \
                        from enforceable. `Confidence::High`, on two \
                        aarch64 libcs from two distributions: Fedora 44 glibc 2.43, whose \
                        startup objects carry the note, reads `on` at `full` under \
                        openssf-tldr, and Alpine edge musl 1.2.6, whose startup objects \
                        carry none, withholds as probe-invalid rather than reading off.",
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
            // toolchain that is behaving correctly. Measured, not supposed.
            //
            // `-O2` in both arms so that the forced downgrade is the arms' only one: at
            // -O0 `-fhardened` alone also warns that it cannot enable _FORTIFY_SOURCE
            // without optimization. The needle does not read that line, so the controls
            // would still discriminate; the arms keep it out all the same.
            positive: &["-O2", "-Wall", "-fhardened", "-fno-stack-protector"],
            negative: &["-O2", "-Wall", "-fhardened"],
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the observable is gcc's own diagnostic that -fhardened did not enable \
                         -fstack-protector-strong, which only -fhardened emits; neither profile carries \
                         -fhardened, and no other flag can make the compiler mention it (argued; \
                         clang lacks the flag and is gated).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // `-fhardened` is GCC 14 and later; clang has no equivalent. Neither
                // fact is a version number here, and neither reaches the report through
                // this list first. Both arms carry `-fhardened`, so a driver that does not
                // know it fails them in its own words and `measure::unknown_flag_limitation`
                // publishes `unsupported` under `flag-unknown-to-driver`, quoting the
                // driver. Measured on Apple clang 21.0.0 under `--profile bare`: both arms
                // exit 1 with `clang: error: unknown argument: '-fhardened'`, the verdict
                // is `unsupported`, and `gating.rule` is `flag-unknown-to-driver`. This
                // entry is the fallback for a clang that accepts `-fhardened` with a
                // warning and exits 0, where the positive arm reads `absent` and
                // `report::compiler_limitation` earns the same verdict under
                // `compiler-declared`; a clang that implements it shows the observable
                // and is measured normally. An older gcc rejects the flag and takes the
                // first path.
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "This does not measure whether `-fhardened` is on. It measures whether \
                    this build reported that `-fhardened` did not enable \
                    `-fstack-protector-strong`, one option `-fhardened` wanted and did not \
                    get. The README names that as one of three ways a flag can be set and \
                    do nothing, because `-fhardened` yields to any explicit `-fno-` by \
                    design. The downgrade read is the one the positive arm forces: \
                    `-fstack-protector-strong`, not enabled because `-fno-stack-protector` \
                    was given. A toolchain can report another downgrade in every build \
                    under `-fhardened` (Ubuntu 26.04's gcc 15.2.0 reports \
                    `_FORTIFY_SOURCE`, which it defines itself), so that one cannot tell \
                    an arm from its control and is not read. `on` therefore means the \
                    build dropped `-fstack-protector-strong` under `-fhardened` *and said \
                    so*; `off` means it reported no such downgrade, whatever it reported \
                    about other options: a downgrade of another option it did report is \
                    named in the evidence, and is not read. \
                    Read `off` with the controls beside it, because on its own it cannot \
                    separate \"nothing was downgraded\" from \"a downgrade went \
                    unreported\", which is the hazard, since a spec file can add \
                    `-Wno-hardened` to suppress the complaint. The control triple is what \
                    separates them: the positive arm forces a downgrade, so a driver with \
                    the warning suppressed makes that arm silent, the controls stop \
                    discriminating, and the check reports `probe-invalid` rather than a \
                    clean `off`. A tampered toolchain shows up there, not in the verdict. \
                    A profile that never passes `-fhardened` asks nothing of it: without \
                    `-Wall` the build is silent and the check reads `indeterminate`; with \
                    it, as under `openssf-tldr`, the canary is heard and the check reads \
                    `off`, which says only that `-fstack-protector-strong` was not \
                    downgraded.",
        }],
    },
    Probe {
        id: "link-unused-library",
        title: "Whether the linker drops a library none of whose symbols are used",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "link_unused_library.c",
        source: include_str!("../probes/link_unused_library.c"),
        // The first user of `link_libs`, and the reason it exists. `compile::build`
        // places these after the source, which is also what makes `--as-needed`
        // measurable at all, see the probe source for why the ordering is not
        // incidental.
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
                reason: "a dropped DT_NEEDED for a library whose symbols go unused is --as-needed \
                         in force, whichever asked (the flag, a configured default); no other flag \
                         of either profile drops a needed entry (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE, FLAGS_DISTRO_TABLE],
            gate: PORTABLE,
            notes: "In the guide's unconditional TL;DR block, and chard passed it in the \
                    `openssf-tldr` profile for some time without being able to tell \
                    whether it took effect. Every unused DT_NEEDED is a library the \
                    loader opens and a name resolution can reach, so dropping them \
                    narrows what an injected object could satisfy. \
                    The observable is an absence, which makes the negative control the \
                    load-bearing arm: it must show the entry present, or the probe has \
                    not established that this linker records unused libraries at all.",
        }],
    },
    Probe {
        id: "copy-dt-needed",
        title: "Whether the linker resolves symbols through a library it was not given",
        lang: Lang::C,
        link_mode: LinkMode::Executable,
        source_name: "copy_dt_needed.c",
        source: include_str!("../probes/copy_dt_needed.c"),
        // Only A is named. B is reachable solely through A's DT_NEEDED, which is the
        // route under test -- putting B here would answer a different question.
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
                reason: "the link refusing a symbol reachable only through another library's \
                         DT_NEEDED is --no-copy-dt-needed-entries in force, the default of every \
                         linker chard has met; no other flag of either profile changes how the \
                         linker resolves through DT_NEEDED (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["library-injection"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The last flag in the guide's recommended set to be measured: the \
                    `openssf-tldr` profile has always passed it, so every report on that \
                    profile requested a hardening measure chard could not confirm took \
                    effect. Its observable is a link that fails, which is why the probe \
                    builds its own two-deep library chain -- a system library cannot pose \
                    the question, because the transitive dependency has to be one nothing \
                    else on the line already satisfies. gcc's driver hard-codes \
                    `--no-add-needed` and clang's does not, while GNU ld's own default on \
                    binutils 2.46 is already the hardened one, so reading the command \
                    line and reading the behaviour disagree here.",
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
                    reason: "DF_1_NOOPEN is written only under -z nodlopen; no other flag of \
                             either profile sets that bit (openssf-tldr's -z now and -pie set \
                             DF_1_NOW and DF_1_PIE, which the decoder does not read), and the \
                             clean build stands in as the negative, so there is no countermand to \
                             append (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE, FLAGS_DISTRO_TABLE],
                gate: PORTABLE,
                notes: "Measured on a shared object because the flag does nothing to an \
                    executable; the linker still writes DT_FLAGS_1, just without \
                    the bit. No distro is expected to default this on, which makes \
                    it a useful check that the corpus can distinguish a genuine \
                    `off` from an undetectable one.",
            },
            Check {
                id: "textrel-absent",
                flag: "-fPIC (no text relocations)",
                decoder: Decoder::ElfStatic(elf_static::textrel),
                polarity: Polarity::Weaken,
                observable: "DT_TEXTREL, or DF_TEXTREL in DT_FLAGS",
                levels: TEXTREL_WORD,
                confidence: Confidence::High,
                // Injects the adverse finding, as `rpath-absent` does. Getting a text
                // relocation past a modern linker on x86_64 takes all three: `-fno-pic` to
                // stop the compiler routing through the GOT, `-mcmodel=large` so the
                // relocations are absolute (`R_X86_64_64`) and therefore resolvable at load
                // time, and `-z notext` to stop the linker refusing. Without the middle one
                // the link fails outright with `R_X86_64_PC32 ... can not be used when
                // making a shared object`, which is a build failure rather than an
                // observable and would leave this control undiscriminating. That is the
                // x86_64 list; i386's has no code model, and is its `ARCH_CONTROLS` row.
                positive: &["-fno-pic", "-mcmodel=large", "-Wl,-z,notext"],
                negative: &[],
                defects: &["stack-code-execution"],
                observes: Observes::Protection,
                corroborates: None,
                regime: Regime::NotOwed(Specific {
                    reason: "DT_TEXTREL or DF_TEXTREL is written by the linker exactly when it \
                             placed a dynamic relocation in a read-only segment, so a profile that \
                             produces one has the defect reported, and -fPIE removes them by the \
                             very mechanism measured; the clean build stands in as the negative \
                             (argued over both profiles).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: Gate {
                    // `-mcmodel=large` is an x86 code model. The property is universal, but
                    // the way this control manufactures it is not, so the check reports
                    // `unsupported` elsewhere rather than a verdict its control never
                    // established. x86 has its own control list (`ARCH_CONTROLS`), measured
                    // to discriminate on i386.
                    arch: &["x86_64", "x86"],
                    libc_unsupported: &[],
                    compiler_unsupported: &[],
                    cxx_stdlib_unsupported: &[],
                    needs_vm: false,
                },
                notes: "A text relocation forces the loader to make executable pages \
                    writable to apply it, so the mapping is W^X-violating for the life \
                    of the process and the pages stay dirty and unshareable. Polarity is \
                    `weaken`: presence is the adverse finding. \
                    Read what this establishes narrowly. chard compiles its own probe \
                    `-fPIC`, so the measured arm answers \"did this toolchain and these \
                    flags produce a clean library\", not \"are the libraries on your \
                    system clean\"; that would mean reading binaries chard did not \
                    build, which it does not do. It earns its place by catching a \
                    profile or a toolchain that produces text relocations anyway.",
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
            observable: "a `-shared` link of the probe's own code, which the linker refuses \
                         with `recompile with -fPIC` naming the probe's exported global \
                         when the code addresses it directly",
            levels: Levels::None,
            // Medium, not High: `on` is a link that succeeded, which more than -fPIC can
            // produce (`-Wl,-Bsymbolic`, gcc's LTO under lld; the probe source has the
            // measurements). The regime-matched arm is what keeps either from reading `on`.
            // clang's LTO is the one it does not reach, and `lto-codegen-at-link` is what
            // keeps that from reading `on`.
            confidence: Confidence::Medium,
            positive: &["-fPIC"],
            // `-fPIE` rather than `-fno-pic`: both are refused, and `-fPIE` is the code a
            // build carrying the guide's executable flags hands a library, which is the
            // confusion the check separates. It is also what the regime arm appends to the
            // profile, so a profile that keeps a `-fPIE` object linkable is caught.
            negative: &["-fPIE"],
            // With `pic-object-relocs`, which reads the relocation the compiler wrote for
            // the same kind of access before any link. The two read different artifacts,
            // so where both measure the group counts two witnesses.
            corroborates: Some("pic"),
            // The observable is generic in the `on` direction: a link succeeds for any
            // reason the probe's reference stops being refused, not only -fPIC. Measured
            // 2026-10-02, each linking with no -fPIC:
            //   - `-O2 -fPIE -Wl,-Bsymbolic` under GNU ld 2.46.1, lld 22.1.8 and mold with
            //     gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64, and under GNU ld on
            //     Fedora 44 aarch64, Ubuntu 22.04 and 24.04 and Alpine;
            //   - gcc 16.1.1 `-O2 -fPIE -flto` under lld 22.1.8, exporting neither of the
            //     probe's symbols;
            //   - `-mcmodel=large -fPIE` under GNU ld 2.46.1 and mold on x86_64, and
            //     `-fno-pic -mcmodel=large` under mold, with DT_TEXTREL.
            // The regime arm is the profile followed by `-fPIE`, and links under each of
            // those profiles, which withholds the verdict. A link line carrying `-z notext`
            // is withheld by the detector instead, since lld refuses the regime arm's
            // large-model `-fPIE` there, and so is a link whose shared object carries
            // `DT_TEXTREL`, which is how a `-z notext` from a specs or configuration file
            // shows: the line does not carry it, and lld links the code in silence. That
            // is why the check declares the dynamic table.
            //
            // Measured 2026-10-09 on Fedora 44 x86_64 (clang 22.1.8, GNU ld 2.46.1), also
            // with no -fPIC: `-O2 -flto`, `-flto=thin` and a `--config=` file holding
            // `-flto` link, where `-O2` is refused, because the link generates the code from
            // bitcode and picks the position-independence itself. The regime arm's `-fPIE` is
            // refused under `-flto`, so it does not withhold that cell, and no arm can
            // reproduce the link's choice without carrying the flag the check asks after. The
            // verdict is withheld from the driver's `-###` words instead.
            regime: Regime::Arm(&["-fPIE"]),
            measures_toolchain_default: false,
            defects: &[],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The guide recommends `-fPIE -pie` for executables and `-fPIC -shared` \
                    for shared libraries. `pie-macro` and `pic-macro` cannot tell the two \
                    code models apart, since -fPIE defines `__PIC__` as well as `__PIE__`; \
                    this check can, because the linker refuses a shared object whose code \
                    assumes its exported data cannot be interposed. It reads the profile's \
                    own code generation: chard adds `-shared`, drops only `-pie` and \
                    `-no-pie`, and does not supply the `-fPIC` the `shared-object-defaults` \
                    probe gets. `off` under `bare`, `bare-optimized` and `openssf-tldr` is \
                    the measurement that the toolchain's default code, and the TL;DR's \
                    `-fPIE`, cannot go into a library, which is right for an executable; a \
                    library build needs -fPIC on its own command line. The verdict \
                    describes the code the measured command line compiled and linked as \
                    one build; under clang's -flto the link generates the code, and a \
                    link that succeeded is withheld as `lto-codegen-at-link`, while one \
                    that was refused stands as `off`. A link whose shared object carries \
                    `DT_TEXTREL` is withheld whatever its line said: a linker sets the tag \
                    where it linked code by text relocation into read-only code. LLD also \
                    sets it on every `-z \
                    notext` link, so position-independent code linked under one is withheld \
                    there too. Where `-z notext` is the toolchain's own default under LLD, \
                    the `-fPIC` control arm carries the tag as well, and every profile reads \
                    probe-invalid, `off` included. No defect is named: \
                    the flag decides whether a shared library can be built, not what it \
                    mitigates. On i386 GNU ld links both control arms, the `-fPIE` one \
                    with no text relocation (gcc 12.2.0 and binutils 2.40 on Debian 12), so \
                    the check reads probe-invalid there.",
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
            observable: "the relocation type in the object file's code against the probe's \
                         exported, defined global: a GOT type under -fPIC, a direct one \
                         under -fPIE or without PIC",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fPIC"],
            // `-fPIE`, as `pic-shared-link` uses: the code a build carrying the guide's
            // executable flags hands a library, and the confusion the check separates.
            negative: &["-fPIE"],
            corroborates: Some("pic"),
            // A regime arm, the profile followed by `-fPIE`. The link-side reasons
            // `pic-shared-link` withholds for (`-Wl,-Bsymbolic`, the linker under LTO,
            // text relocations) do not reach an object that is never linked, but a
            // compiler-side one does: clang's `-fsanitize=hwaddress` reaches the anchor
            // through the GOT under -fPIE and -fno-pic as well (measured 2026-10-02:
            // `R_X86_64_GOTPCREL` with clang 14.0.0, 18.1.3, 22.1.8 and 23.1.2 on x86_64,
            // `R_AARCH64_ADR_GOT_PAGE` with clang 22.1.8 on aarch64; gcc's hwasan stays
            // direct). Both controls are profile-free, so without this arm that profile
            // read `on` with a discriminating triple. The arm reads present there and the
            // cell withholds as regime-confounded; under every other measured profile it
            // reads absent (`predicate::elf_static`'s PIC_OBJECT lists the forms).
            regime: Regime::Arm(&["-fPIE"]),
            measures_toolchain_default: false,
            defects: &[],
            observes: Observes::Protection,
            references: &[GUIDE],
            // The relocation types are per machine, and the predicate names those of the
            // three it was measured on. On any other machine the positive arm names no
            // listed type and reads indeterminate; the gate says so first.
            gate: Gate {
                arch: &["x86_64", "x86", "aarch64"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The compiler-side reading of `pic-shared-link`'s question, whether the \
                    profile's code can go into a shared library. Under -fPIC an exported \
                    global may be preempted by another module, so the compiler reaches it \
                    through the GOT; under -fPIE, or without PIC, it reaches it directly, \
                    and a `-shared` link of that object is refused. Read on the object \
                    before any link, so `-Wl,-Bsymbolic`, LTO under lld and a linker \
                    that takes text relocations, which make `pic-shared-link` withhold, \
                    do not reach it, and i386, where GNU ld links both arms, is read too. \
                    Under clang's -fsanitize=hwaddress the code reaches the global through \
                    the GOT under -fPIE as well; the regime arm, the profile followed by \
                    -fPIE, reads that, and the cell withholds as regime-confounded. \
                    The last of -fPIC, -fpic, -fPIE, -fpie and -fno-pic wins: -fPIC -fPIE \
                    reads off. The probe's global is declared with default visibility, so \
                    -fvisibility=hidden does not turn -fPIC's GOT access into a direct one \
                    and read off; where a flag overrides the attribute (clang's \
                    -fvisibility-from-dllstorageclass with \
                    -fvisibility-nodllstorageclass=hidden), the object records the global \
                    as hidden and the cell reads indeterminate. A slim -flto object carries no code relocation and the \
                    cell withholds, `indeterminate` or, under gcc, whose regime arm is \
                    slim too, `probe-invalid`; -ffat-lto-objects is read. One object compiled -fPIC \
                    says nothing about the rest of a program, and no defect is named, as \
                    for `pic-shared-link`.",
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
                reason: "a reference to __stack_chk_fail or its siblings is emitted only by the \
                         stack protector, whichever spelling turned it on (-fstack-protector*, \
                         -fhardened, a configured default), so a profile producing it has the \
                         mechanism in force; no other flag of either profile emits a canary \
                         (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "Cross-checks the macro-channel ssp-level claim against what the \
                    compiler emitted. The two disagreeing means the macro is lying \
                    or no function was eligible at this level. The probe carries \
                    three constructs admitted by three rules: a 64-byte char array \
                    (plain -fstack-protector at the default threshold), an alloca \
                    call (plain -fstack-protector at any threshold) and an \
                    address-taken scalar (-fstack-protector-strong), so raising \
                    --param=ssp-buffer-size alone does not remove the observable. \
                    Eligibility-changing flags a reader of `off` should look for: \
                    --param=ssp-buffer-size (moves the array threshold only), \
                    gcc's -fstack-protector-explicit (instruments only functions \
                    marked __attribute__((stack_protect)), none here, so `off` by \
                    design; clang rejects the flag), \
                    __attribute__((no_stack_protector)) on a function, and -flto, \
                    which defers the decision to the link. Presence only: which rule \
                    admitted the reference is not readable from the artifact, so this \
                    check publishes no level and the ssp-level macro claim has no \
                    artifact-side level to be corroborated by. OpenBSD's clang calls \
                    __stack_smash_handler instead, and on amd64 emits RETGUARD in place \
                    of the canary under every protector mode, so the positive control \
                    carries no canary there and the check withholds rather than reading \
                    RETGUARD as one; `predicate::elf_static`'s CANARY holds the \
                    measurement.",
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
                reason: "a .openbsd.randomdata.retguard section is written only by OpenBSD clang's \
                         -fret-protector; gcc has no such flag and no flag of either profile \
                         writes a section of that name, so the frame names clang alone (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["clang"],
            }),
            measures_toolchain_default: false,
            references: &[],
            // Portable: only OpenBSD's clang knows the flag, and every other driver says so
            // on stderr, which publishes `unsupported` under `flag-unknown-to-driver` from
            // the driver's own words rather than from a list here.
            gate: PORTABLE,
            notes: "OpenBSD's clang turns RETGUARD on by default on amd64 and with the \
                    stack protector, so `-fno-stack-protector` also removes it, even \
                    when `-fret-protector` is given explicitly. The \
                    check reads an object rather than the linked program: the startup \
                    objects carry cookies of their own into every link, so a linked \
                    program cannot separate the arms, and an object holds only what the \
                    compiler made of chard's source. Presence only: one cookie per \
                    protected function, and which functions RETGUARD skipped is not \
                    graded. gcc and other clangs do not know the flag and read \
                    `unsupported`.",
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
                // unwinds through C frames and runs their cleanup handlers, which is
                // correctness of resource release rather than one of the memory-safety
                // classes `DEFECTS` lists.
                defects: &[],
                observes: Observes::Protection,
                corroborates: Some("exceptions"),
                regime: Regime::NotOwed(Specific {
                    reason: "__EXCEPTIONS is predefined in a C translation unit by -fexceptions \
                             alone; no other flag of either profile defines it (argued over \
                             bare-optimized and openssf-tldr).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "The guide's TL;DR addendum asks for -fexceptions only for \
                        multi-threaded C code using glibc's pthreads, where thread \
                        cancellation unwinds through C frames. On another C library the \
                        check still publishes what the compiler did, `off` included, \
                        because the macro is the compiler's and discriminates the same \
                        way there (measured on Alpine with musl); that `off` says the \
                        toolchain does not default to -fexceptions, not that the guide's \
                        ask is unmet. Whether musl's or a BSD's cancellation benefits \
                        from the flag is unmeasured. C polarity: in C++ the macro is on \
                        by default and -fno-exceptions removes it, so this reading holds \
                        for C only. The openssf-tldr profile does not pass the flag, by \
                        that profile's design (the TL;DR block it carries); the explicit \
                        profile measures it. Two other spellings reach the macro. On gcc \
                        13 and later -fnon-call-exceptions implies -fexceptions, and both \
                        checks read it as such; on gcc 11 and on clang it does nothing \
                        in C. clang's -fexceptions -fignore-exceptions defines the macro \
                        and emits no table, so this check reads `on` where the flag's \
                        cleanup tables are gone: that form is one the macro cannot see \
                        and except-table-emitted can, and the macro reading is withheld \
                        beside it under macro-contradicted-by-artifact, the reason naming \
                        both. clang's -fexceptions -fsjlj-exceptions is a \
                        form this check cannot tell apart: the macro is defined, but the \
                        frames register with the SjLj unwinder, which the forced unwind \
                        of glibc's cancellation does not run. On x86_64 the table is \
                        emitted and except-table-emitted reads `on` too; on 32-bit ARM \
                        clang 19.1.7 puts the table in .text, as it does under \
                        -fdwarf-exceptions, no .ARM.extab is written, and since the \
                        selector reaches the control arms, which then carry no mark either, \
                        except-table-emitted reads `probe-invalid` (Raspbian 13 armv6, \
                        measured 2026-10-21). On glibc x86_64 a \
                        cancellation program built that way fails to link (no \
                        __gcc_personality_sj0 or _Unwind_SjLj_Register; clang 22.1.8, \
                        Fedora 44, measured 2026-10-01), so the misbuild shows itself at \
                        link rather than here.",
            },
            Check {
                id: "except-table-emitted",
                flag: "-fexceptions (emitted)",
                decoder: Decoder::ElfStatic(elf_static::except_table),
                polarity: Polarity::Harden,
                observable: "a .gcc_except_table section in the object file, or on 32-bit \
                             ARM a .rel.ARM.extab, for a cleanup region spanning a call that \
                             may unwind",
                levels: Levels::None,
                confidence: Confidence::High,
                positive: &["-fexceptions"],
                negative: &["-fno-exceptions"],
                defects: &[],
                observes: Observes::Protection,
                // The same object as `exceptions-macro`, so the group's agreement checks
                // chard's two readers of one artifact against each other; the group note
                // says so through `independent_witnesses`.
                corroborates: Some("exceptions"),
                regime: Regime::NotOwed(Specific {
                    reason: "a .gcc_except_table in a C object, or on 32-bit ARM a \
                             .rel.ARM.extab, is written only where -fexceptions makes a cleanup \
                             region reach a call that may unwind; -fasynchronous-unwind-tables \
                             writes .eh_frame, or on 32-bit ARM .ARM.exidx entries and, under \
                             gcc, an .ARM.extab none of whose entries is relocated, not the \
                             except table, and no flag of either profile asks for exceptions in \
                             C (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "Cross-checks exceptions-macro against what the compiler emitted: \
                        the table that lists the landing pad running a `cleanup` \
                        attribute's handler when an exception unwinds the frame. The \
                        probe source is load-bearing, since a translation unit with no \
                        cleanup region gets no table under the flag; the positive \
                        control arm turns a probe that lost its landing pad into \
                        probe-invalid. `.eh_frame` is not the observable: it was present \
                        in every arm on every toolchain measured but 32-bit ARM's, which \
                        under its default exception model writes none, its unwind tables \
                        being .ARM.exidx entries, and where the table's mark is a \
                        .rel.ARM.extab. Read on the object, \
                        since a linked program carries whatever tables its startup \
                        objects and libraries bring. The non-glibc reading is \
                        exceptions-macro's: published as measured, with the guide's \
                        glibc condition in that check's notes. Under gcc's -flto the \
                        object is slim, GIMPLE with no generated code and so no table \
                        whatever the flag, and the reading is withheld under \
                        artifact-holds-lto-ir; clang's -flto object is bitcode, which \
                        the ELF reader does not read, and the reading is indeterminate. \
                        clang's -fexceptions -fsjlj-exceptions registers SjLj frames \
                        glibc's cancellation cannot unwind: on x86_64 it emits the table \
                        and reads `on`, and on 32-bit ARM the table is in .text and it \
                        reads `probe-invalid`, as under clang's -fdwarf-exceptions there, \
                        the model selector reaching the control arms; exceptions-macro's \
                        notes give the measurements.",
            },
        ],
    },
    Probe {
        id: "ubsan-trap",
        title: "UBSan in trap mode: a trap instruction where a handler call would be",
        lang: Lang::C,
        // An object, so every relocated field in the function holds zero and no address
        // can put the trap's bytes there; `elf::code` checks each field and carries the
        // argument. gcc's handler-mode
        // arm also needs no libubsan to build that way.
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
            observable: "a trap instruction (ud2, ud1 or brk) in the code of the probe's four \
                         functions or gcc's .cold parts of them, and no __ubsan_handle_* \
                         reference in the object",
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
            // undefined behaviours it was asked to check, and the probe's constructs stand in
            // for the groups. Bearing `null-deref` here would grade that defect on
            // a sanitizer no profile chard measures enables.
            defects: &[],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a trap instruction in the probe's four functions is emitted by \
                         -fsanitize-trap, and by clang's -ftrapv, which neither profile carries; a \
                         sanitizer group left in handler mode beside trapped ones, or trapped \
                         with no trap found, is withheld separately by \
                         report::sanitizer_group_limitation. The profiles' other flags emit calls, \
                         canaries, probes, endbr and register clears, never a trap (argued).",
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
            notes: "The guide sanctions UBSan in production in trap mode, \
                    -fsanitize=undefined -fsanitize-trap=undefined (gcc's spelling of \
                    the same is also -fsanitize-undefined-trap-on-error), since a trap \
                    needs no runtime library. The probe's function loads an array \
                    element through a pointer, shifts it and adds to it, so the \
                    sanitizer's null, alignment, bounds, pointer-overflow, shift and \
                    signed-integer-overflow checks each have something to trap on, and a \
                    trap configuration narrower than the whole sanitizer that covers any \
                    of them reads `on` too, but for clang's signed-overflow trap alone: \
                    clang's -ftrapv, with no sanitizer, emits the same trap with the same \
                    check number, so a function whose only traps are that one is \
                    `indeterminate` under clang, and so is \
                    -fsanitize-trap=signed-integer-overflow alone there. A \
                    second function holds a construct for every other group gcc and clang \
                    instrument in C without a call (integer-divide-by-zero, vla-bound, \
                    unreachable, builtin, bool, the float, nonnull and nullability groups, \
                    clang's implicit-conversion and unsigned groups), a third indexes a \
                    global array of known size through a pointer to its element type \
                    (gcc's object-size and clang's local-bounds, which size the object; \
                    not bounds, which reads the array type the cast hides and has its \
                    construct in the first function, so a local-bounds handler beside a \
                    bounds trap is seen rather than folded) and a fourth calls through a \
                    function pointer \
                    (clang's function), and the probe records whether the compiler reports \
                    an undefined-behavior group enabled, where the compiler answers \
                    __has_feature (clang, and gcc 16.1.1; gcc 13.3.0 answers nothing). \
                    `off` says no check traps in any of the four functions or gcc's .cold \
                    parts of them, no group the probe has no construct for is reported \
                    enabled, and the compile's own sanitizer words, read from the driver's \
                    -### command, name no group in trap mode: UBSan is in handler mode, or \
                    not enabled, and the default profiles enable it nowhere. The groups \
                    with no construct are enum and return, which neither compiler checks \
                    in C, and clang's object-size, which clang keeps only for a provable \
                    fault; any of them enabled in trap mode with no trap and no handler is \
                    `indeterminate`, under the compiler's report where it gives one and \
                    under the words everywhere (so gcc 13's -fsanitize=enum in handler \
                    mode reads `off`, its words naming no trapped group, where gcc 16 \
                    reports the group and reads `indeterminate`); so is an object without \
                    the construct functions; and one of them left in handler mode beside \
                    trapped groups is `indeterminate` under the same \
                    words, since the artifact's traps say nothing of \
                    that group. Under clang, -fsanitize=object-size at -O0 \
                    reads `off` because clang drops the group with a warning, which the \
                    observation's build.stderr carries: no check exists to run in either \
                    mode. clang's local-bounds traps by default and reads `on` with or \
                    without -fsanitize-trap naming it, beside -fsanitize-trap=undefined \
                    too, which leaves that default in place; -fno-sanitize-trap=local-bounds \
                    puts it in handler mode and reads `off` alone and `indeterminate` \
                    beside trapped groups, and clang's -fsanitize=bounds with no trap \
                    flag reads `indeterminate` the same way, since the bounds group \
                    includes local-bounds trapping beside array-bounds calling its \
                    handler. \
                    -fsanitize-trap=undefined without \
                    -fsanitize=undefined does nothing and reads `off`. A trap beside a \
                    runtime handler, which -fsanitize-trap=shift alone gives and which a \
                    construct-bearing group left in handler mode by -fno-sanitize-trap= \
                    gives, is `indeterminate`, and so is a trap beside any call in the \
                    first two functions, whatever the handler's name. Read from the code \
                    bytes of four functions in an object file, by a fixed-pattern search \
                    rather than a disassembler; `elf::code` says why that is sound for \
                    these functions and not for an arbitrary one, and why the third and \
                    fourth are searched for traps alone. A call in the function with neither a \
                    trap nor a handler is `indeterminate`, since the source calls \
                    nothing: clang's -ftrap-function=NAME, which turns each trap into a \
                    call to NAME (through a register under -mcmodel=large), reads so, and \
                    so do -fstack-protector-all, gcc's \
                    -ftrapv, -pg and -fsanitize=address, among others, which put a call \
                    there for their own reasons; the same calls beside a trap withhold \
                    an `on`.",
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
            observable: "the flag argument (__USE_FORTIFY_LEVEL - 1) loaded before \
                         __printf_chk or __vprintf_chk in the object's code, or a \
                         __strcpy_chk call where printf is not wrapped",
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
                reason: "the flag argument loaded before __printf_chk exists only where fortify \
                         rewrote printf to __printf_chk, which _FORTIFY_SOURCE alone does, with -O \
                         as its precondition; no other flag of either profile rewrites a libc call \
                         (argued).",
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
            notes: "The level the compiled code asks the C library for, read from the \
                    object rather than from __USE_FORTIFY_LEVEL: glibc passes a checking \
                    printf the flag __USE_FORTIFY_LEVEL - 1, so 1 is level 2 and 2 is \
                    level 3, and a __strcpy_chk call with printf unwrapped is level 1. A \
                    fixed-pattern search over the probe's printf function and, under \
                    clang, over glibc's out-of-line printf wrapper, whose mangled name is \
                    glibc's; `elf::code` says why that search is sound for these \
                    functions. Requires optimization, as every fortify reading does: \
                    without -O the wrappers are not used and the check reads off. A \
                    checking printf whose flag is not found is withheld as indeterminate, \
                    never read as a level.",
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
            observable: "glibc's \"buffer overflow detected\" on an abort, a bare trap from \
                         an implementation the self-report names, or a bare abort where it \
                         names FreeBSD's and the artifact calls a checking function",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"],
            negative: &["-O2", "-U_FORTIFY_SOURCE", FORTIFY_OFF],
            defects: &["stack-buffer-overflow", "heap-buffer-overflow"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "glibc's buffer-overflow diagnostic is written by its fortified wrappers \
                         and by nothing else, and a bare trap is read only where the probe's \
                         self-report names an implementation that traps; only _FORTIFY_SOURCE \
                         among the profiles' flags reaches those wrappers (argued).",
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
            notes: "Proves the checks are in force rather than merely requested. \
                    Destination is at file scope so a stack canary cannot fire \
                    first and be miscredited to fortify, and it is flanked by guard \
                    arrays the uncaught overflow lands in; the probe checks that a \
                    guard follows the destination and exits distinctly when none does, \
                    so the verdict is withheld rather than measured over memory the \
                    probe does not declare.",
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
            observable: "\"buffer overflow detected\" on an abort, a bare trap from an \
                         implementation the self-report names, or a bare abort where it \
                         names FreeBSD's and the artifact calls a checking function, on a \
                         write that leaves a struct member but stays inside the enclosing \
                         struct",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"],
            negative: &["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=1"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "glibc's buffer-overflow diagnostic on a write within an enclosing object \
                         is level 2's subobject bound, which only _FORTIFY_SOURCE sets; \
                         -fstrict-flex-arrays changes which trailing arrays count as bounded, not \
                         whether fortify checks, and no other flag of either profile reaches the \
                         wrappers (argued).",
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
            notes: "Rung 2 of the fortify ratchet, and the only rung that separates level 1 \
                    from level 2: level 1 asks __builtin_object_size for the whole object \
                    and the write fits, level 2 asks for the subobject and it does not. \
                    Must use the strcpy family: the same overflow via memset does not fire \
                    at any level on either compiler, because glibc's memset wrapper asks \
                    for the whole-object size even at level 2. On FreeBSD the strcpy \
                    wrapper asks for the whole object at every level too (<ssp/string.h>'s \
                    __ssp_bos0, as for the memcpy family), so the rung reads unsupported \
                    there under the libc gate; its strlcpy, strlcat and stdio wrappers ask \
                    the subobject bound at level 2, which this rung does not exercise.",
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
                reason: "glibc's distinct `%n in writable segment(s) detected` abort is raised by \
                         the fortified printf family at level 2 and by nothing else; no other flag \
                         of either profile reaches it (argued).",
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
            notes: "Rung 2': the same level as the subobject rung, reached through an \
                    unrelated glibc code path and carrying its own diagnostic, so neither \
                    can be mistaken for the other. Also worth measuring in its own right: \
                    %n is the primitive that turns a format-string bug into an arbitrary \
                    write.",
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
                reason: "reads its observable from the clean build (measures_toolchain_default), \
                         where there is no profile regime to re-run the negative in; the profile's \
                         own -z noexecstack is what the sibling check noexecstack measures (argued \
                         over both profiles).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: true,
            defects: &["stack-code-execution"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: Gate {
                // The property is portable; this `main` is not. A probe that assembles
                // on one architecture and fails elsewhere would report a build failure
                // as a measurement. Its two instructions are also valid i386 (AT&T,
                // 32-bit operands only), and both control arms discriminate there,
                // measured by hand on 2026-09-30: `-Wl,-z,noexecstack` gave `PT_GNU_STACK`
                // RW and `-Wl,-z,execstack` RWE, every output `EM_386`, under gcc 7.5.0
                // and clang 6.0.0 with binutils 2.30 (Ubuntu 18.04 i386, its own i686
                // kernel) and gcc 12.2.0 with binutils 2.40 (Debian 12 i386 userspace on
                // an x86_64 kernel). So `x86` is admitted beside `x86_64`; aarch64 has no
                // `main` here.
                arch: &["x86_64", "x86"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The sibling `noexecstack` check asks whether a *flag* was passed; \
                    this asks what the linker does when nothing was. The distinction \
                    matters because the stack is executable if any input requires it, and \
                    an object carrying no `.note.GNU-stack` has historically been read as \
                    requiring it, so one unmarked object silently makes a whole binary's \
                    stack executable. binutils built with `--enable-default-execstack=no` \
                    reverses that assumption. This is the only compiler-visible effect of \
                    Gentoo's `sys-devel/binutils[hardened]`, and the reason the probe is \
                    assembly: gcc emits the note into every object it produces, so a C \
                    source can only measure what gcc asked for, never what the linker \
                    assumes in its absence.",
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
            // Not a flag spelling, deliberately: what is measured is the outcome of the
            // link's PT_GNU_STACK and the kernel's handling of it together. A spelling that
            // began `-Wl,-z,noexecstack` would take that flag's artifact boundary, whose
            // runtime requirement is exactly what this check observes, and would key with
            // `noexecstack` as a second examiner of the same profile flag.
            flag: "non-executable stack at runtime",
            decoder: Decoder::Runtime {
                detect: detector!(detect_stack_exec),
                reads: &[],
                // A fault the kernel's mapping of the stack produces. Under user-mode
                // emulation the emulator decides whether the bytes run, so the reading
                // would describe it rather than the kernel.
                basis: RunBasis::Machine,
            },
            polarity: Polarity::Harden,
            observable: "whether machine code copied to a buffer on main's stack runs and \
                         returns its marker, or faults on the instruction fetch at the \
                         buffer's address",
            levels: Levels::None,
            confidence: Confidence::High,
            // No `-O`: the probe reads the same at -O0 through -O3 and -Os on both
            // compilers and both architectures (measured 2026-10-02). The
            // `noexecstack` check's controls, because the kernel maps the stack from the
            // PT_GNU_STACK they write.
            positive: &["-Wl,-z,noexecstack"],
            negative: &["-Wl,-z,execstack"],
            defects: &["stack-code-execution"],
            observes: Observes::Protection,
            corroborates: None,
            // A regime control: both arms of the triple are built without the profile, so
            // they say nothing about a profile flag that produces the fault by another
            // route. clang's `-fsanitize=safe-stack` is one: it moves the buffer onto a
            // separately mapped read-write stack, and the probe faulted at the payload
            // under it with `-z execstack` as well as `-z noexecstack` (Fedora 44 x86_64,
            // clang 22.1.8, measured 2026-10-02), so `--flags="-Wl,-z,execstack
            // -fsanitize=safe-stack"` published `on` over an RWE PT_GNU_STACK. The regime
            // arm is the profile's flags followed by `-Wl,-z,execstack`; it must read the
            // marker for an `on` to stand. A profile ending in `-Wl,-z,noexecstack` loses
            // nothing, because the arm's `-z` comes last and the last spelling wins. The
            // probe also declines when the buffer is not within 1 MiB below `argv`, which
            // is how it reads the safe-stack build now; the regime arm is the general
            // mechanism and that check the specific one.
            regime: Regime::Arm(&["-Wl,-z,execstack"]),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // The two architectures the payload is written for. i386 is out for a
                // second reason the recipe names: an absent PT_GNU_STACK there has set
                // READ_IMPLIES_EXEC, which this probe has not been run against.
                arch: &["x86_64", "aarch64"],
                libc_unsupported: &[],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                // The reading is the kernel's, so under a container it describes the host
                // and not the distribution on the column.
                needs_vm: true,
            },
            notes: "The enforced half of `noexecstack`, which reads the request in the \
                    artifact's PT_GNU_STACK: this check runs the program and reads whether \
                    the kernel honoured it. `on` is a SIGSEGV at the address of bytes the \
                    probe copied onto its stack and called; `off` is those bytes returning \
                    their marker. Any other fault, or a crash before the call, is withheld. \
                    The probe is written so the optimizer cannot remove the copy or turn \
                    the call into a tail jump, which is how the recipe it rests on read an \
                    executable stack as non-executable at -O2. A reading of this host's \
                    kernel, so it is withheld under a container (`needs_vm`), where nothing \
                    established whose kernel it is (`execution-mode-assumed`), under \
                    user-mode emulation and over an artifact the reader could not read \
                    (`run_basis` machine). It reads the main thread's \
                    stack only; thread stacks are mapped by the C library. A profile that \
                    moves the buffer off that stack, as clang's -fsanitize=safe-stack \
                    does, is withheld: the probe declines when the buffer is not just \
                    below `argv`, and the regime arm, the profile followed by \
                    -Wl,-z,execstack, must return the marker for an `on` to stand.",
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
            // observe. Measured on Alpine, whose gcc is patched to 4: plain
            // `-fstack-protector` still canaried the four-byte array, so both arms
            // showed the observable and the check reported `probe-invalid` on the one
            // system it was written for. Naming `=8` restores upstream's threshold for
            // the control alone and leaves the measured build's own default intact.
            negative: &["-fstack-protector", "--param", "ssp-buffer-size=8"],
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "a __stack_chk_fail reference from a function whose only array is four \
                         bytes is the strong protector's rule in force, however it was spelled; no \
                         other flag of either profile emits a canary (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["stack-buffer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE, ALPINE_TSC_64],
            gate: PORTABLE,
            notes: "Coverage rather than presence, and the two can differ. \
                    `-fstack-protector` instruments a function only when it holds an \
                    array of at least `ssp-buffer-size` bytes (eight upstream), so a \
                    four-byte array is unprotected there and protected under either \
                    `-fstack-protector-strong` or a lowered threshold. A distribution can \
                    lower it without changing the mode, which Alpine does, and a report \
                    saying `ssp-level: strong` is then true and understates what the \
                    archive gets. The negative control is plain `-fstack-protector` \
                    rather than `-fno-stack-protector`: the question is whether this \
                    function is covered, not whether the protector exists, and a control \
                    that switched it off entirely would answer the sibling check's \
                    question instead of this one. On OpenBSD amd64 neither arm carries a \
                    canary, since RETGUARD replaces it in every function it covers, and \
                    the check withholds for the reason `canary-emitted` records.",
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
            observable: "which of four functions, one per protector rule (two for basic), refer to \
                         __stack_chk_fail, __stack_chk_guard or __stack_smash_handler \
                         through a relocation inside their own range in the object file, \
                         whether a fifth, an array every access to which is in range, does, \
                         and which refer to SafeStack's __safestack_unsafe_stack_ptr",
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
                reason: "which of the four functions refer to __stack_chk_fail is the protector's \
                         level in force, however it was spelled; no other flag of either profile \
                         emits a canary or removes one (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The artifact half of ssp-level: the level the compiler applied, read \
                    from which functions it instrumented, beside the level its \
                    preprocessor announced. canary-emitted reads that some function got a \
                    canary and cannot say which rule admitted it; here one function per \
                    rule says which rules were in force. Read on the object, since a link \
                    keeps no per-function relocations. A probe function missing from the \
                    object withholds the reading rather than counting as unprotected, so \
                    gcc's slim -flto object, which holds no code, is indeterminate, and \
                    clang's -flto bitcode is not ELF and is indeterminate too. A raised \
                    --param=ssp-buffer-size still reads basic, since plain \
                    -fstack-protector admits the alloca function at any threshold; how \
                    large the threshold is, is ssp-covers-small-arrays' question. gcc's \
                    -fstack-protector-explicit instruments only functions marked \
                    stack_protect, none here, and reads absent, where ssp-level reads \
                    partial at explicit from the macro, except \
                    on Ubuntu 22.04, whose gcc 11.4.0 adds -fstack-protector-strong after it \
                    and reads strong; clang rejects that flag. Alpine's clang reads strong \
                    under plain -fstack-protector, as its preprocessor does. On OpenBSD \
                    amd64 RETGUARD replaces the canary, so the positive arm carries none \
                    and the check withholds for the reason canary-emitted records. Under \
                    clang's -fsanitize=safe-stack the reading is on at unsafe-frame, a word \
                    on no rung: SafeStack places a canary in exactly the functions it gave \
                    an unsafe frame, at whatever level was requested, so the object refers \
                    to __safestack_unsafe_stack_ptr, ssp_any stays bare under -all and the \
                    in-range array stays bare at -O1 and above where -strong would admit \
                    it; -fstack-protector-all is then present and inert on every frame with \
                    no unsafe local. The macro reader still reads the level requested, and \
                    the stack-protector group compares the two words and reports the split \
                    rather than agreement. Measured 2026-10-08 with clang 22.1.8 on Fedora \
                    44 x86_64 only; report::ASSUMPTIONS carries \
                    safestack-canaries-follow-the-unsafe-frame.",
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
                reason: "__builtin_object_size over the trailing arrays is the front end's own \
                         answer under -fstrict-flex-arrays, printed by the probe; of the profiles' \
                         other flags only _FORTIFY_SOURCE reads object sizes and it does not \
                         change them (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["heap-buffer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The flag that decides whether fortify works on the trailing-array \
                    pattern at all. A `char tail[1]` at the end of a struct is how C code \
                    has always faked a variable-length member, and a compiler that plays \
                    along cannot bound it, so a fortified memcpy into one is unfortified \
                    in practice, because the size it would check against is unknown. \
                    Graded, and the grading is the point: each level exempts one fewer \
                    spelling, so three declarations pin which level is in force and a \
                    distribution at `=1` or `=2` reports `partial` rather than off. \
                    Measured identically on gcc 16 and clang 22.",
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
                // emulator executing them reproduces. Nothing is read from a fault the
                // memory map or the CPU produces.
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "SIGABRT with \"buffer overflow detected\" from a fortified strcpy \
                         past trailing arrays declared [2], [1] and [0], each in its own \
                         child, beside a copy past a member that is not last as the witness",
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
                reason: "glibc's diagnostic is specific to fortify, and the ctrl row in the same \
                         run shows fortify is checking subobject bounds, so a caught trailing row \
                         is the bound the flag set and nothing a co-enabled flag adds (argued over \
                         both profiles).",
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
            notes: "The enforcement half of `strict-flex-arrays`, which reads the bound the \
                    compiler computes; this reads whether a fortified copy acts on it. \
                    Separate rather than a second reading of that check because it \
                    answers a conjunction: the flag's level and a fortify level of 2 or \
                    more, through the C library's wrapper. Where the `ctrl` copy is not \
                    caught (fortify below 2, -O0, or a wrapper that loses the subobject \
                    bound, as clang 18 with glibc 2.39 does) the check is withheld rather \
                    than off, and `strict-flex-arrays` still reads the compiler's level; \
                    on a C library the probe identifies as having no subobject bound for \
                    its copy (musl, alone or with fortify-headers, OpenBSD's libc, or \
                    FreeBSD's, whose strcpy wrapper asks for the whole object), it reads \
                    `unsupported`. `off` is earned only where the ctrl copy is \
                    caught and no trailing copy is. Not a corroboration group with \
                    `strict-flex-arrays`: both are runtime readings, and a group counts \
                    channels.",
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
                reason: "a surviving guard can be kept by a sanitizer's checked add as well as by \
                         the flag, which is how a check read on under -fsanitize=undefined (clang \
                         22.1.8, Fedora 44 x86_64, 2026-10-09); detect_no_strict_overflow \
                         withholds where the run carries a sanitizer report, and no flag of either \
                         profile instruments arithmetic or changes folding, -O2 being what both \
                         control arms carry (measured for the sanitizer, argued for the rest).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["optimizer-exploited-ub", "integer-overflow"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "One of the guide's four `for production code` anti-UB flags, and the \
                    first check in this corpus whose observable is neither a macro, an ELF \
                    bit, a manner of death nor a diagnostic. These flags leave no trace: \
                    they change what the optimizer is permitted to delete, so the only way \
                    to see one is to write code it would otherwise remove and ask the \
                    program whether the code is still there. Decidable at every \
                    optimization level on gcc 8 and later, unlike the aliasing check: \
                    gcc 8 and later fold the guard even at -O0, and the flag restores \
                    it there too. clang, and the gcc 4.8, 5.4 and 7.5 measured, keep \
                    the guard at -O0 without the flag, so an unoptimized build of clang \
                    or of a gcc before 8 that ran it is withheld. Those gccs also keep \
                    it at -O, -O1 and -Og, which the probe cannot tell from -O2, so an \
                    optimized build of theirs that ran it is read by the last -O word of \
                    its own compile line: on at -O2, -O3, -Os and -Ofast, where they fold \
                    it without the flag (-Ofast measured on 7.5 alone), and withheld at \
                    -O, -O1 and -Og, at a level not measured, and where no word, a specs \
                    file, a prefix directory, a forced include, a plugin or a wrapper leaves the \
                    level unreadable. No built-in profile compiles at those levels. A \
                    guard that ran and cannot be credited to the flag is withheld under \
                    `guard-kept-without-the-flag`.",
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
            // (`elf_static`'s TRAPV_HELPER). No negative arm: -ftrapv is off by default on
            // every toolchain measured, so the selection-only build is the flag off, and
            // clang has no -fno-trapv to spell it (an unknown argument on clang 14.0.0,
            // 18.1.3, 22.1.8 and 23.1.2, measured 2026-10-02).
            positive: &["-ftrapv"],
            negative: &[],
            defects: &["integer-overflow"],
            observes: Observes::Protection,
            corroborates: Some("trapv"),
            regime: Regime::NotOwed(Specific {
                reason: "__addvsi3, __subvsi3 and __mulvsi3 are called only by gcc's -ftrapv; no \
                         flag of either profile routes arithmetic through libgcc, and the clean \
                         build stands in as the negative (argued; clang is gated).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            // clang implements -ftrapv inline and names no helper, so its positive arm
            // reads absent; the gate turns that into `unsupported` rather than letting a
            // clang build read `off`. The `trapv` check reads clang.
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "gcc's form of -ftrapv only. gcc replaces each signed int addition, \
                    subtraction and multiplication it cannot prove safe with a call to \
                    libgcc's __addvsi3, __subvsi3 or __mulvsi3, which abort on overflow; \
                    the probe's three functions take their operands as parameters, so \
                    every one is called. clang inlines the check as a branch to a trap \
                    instruction and calls nothing, so on clang this check reads \
                    unsupported and trapv-trapped carries the reading. On gcc the last of \
                    -ftrapv, -fno-trapv, -fwrapv and -fno-strict-overflow wins: -ftrapv \
                    -fwrapv calls no helper and reads off, which is what the build does. \
                    UBSan's signed-integer-overflow check takes the arithmetic from \
                    -ftrapv when both are passed, so such a build reads off here while \
                    its overflow is still caught, by the sanitizer; trapv-trapped \
                    withholds that case. Read on the object; one object compiled with \
                    -ftrapv says nothing about the rest of a program.",
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
                // the hardware does. Measured under qemu-user against a native run (2026-10-02).
                basis: RunBasis::Program,
            },
            polarity: Polarity::Harden,
            observable: "whether adding 1 to INT_MAX kills the program, by the manner of \
                         death each compiler's -ftrapv has: SIGABRT from libgcc under \
                         gcc, a trap instruction under clang",
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
                reason: "death on INT_MAX + 1 is -ftrapv's own, by the manner each compiler gives \
                         it; a trapping sanitizer kills the program too, and detect_trapv \
                         withholds beside a sanitizer's report or trap, which neither profile \
                         carries anyway; the clean build stands in as the negative (argued over \
                         both profiles).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The guide's alternative to -fno-strict-overflow: overflow aborts rather \
                    than wrapping. Each compiler's -ftrapv dies one way with nothing on \
                    stderr: gcc through libgcc's abort (SIGABRT), clang through an inline \
                    trap (SIGILL on x86, SIGTRAP on aarch64), and only that way is \
                    credited. A trap is withheld from gcc, whose -ftrapv never traps, and \
                    from clang wherever a UBSan check was compiled in or could not be \
                    ruled out, because clang's trap-mode signed-overflow check is \
                    indistinguishable from its -ftrapv; an abort that printed anything, or \
                    a UBSan report, is withheld too. -fwrapv does not countermand clang's \
                    -ftrapv, so -ftrapv -fwrapv reads on under clang and off under gcc, \
                    each what the build does. Under -fsanitize=signed-integer-overflow \
                    -fsanitize-trap a clang build reads indeterminate with or without \
                    -ftrapv, which is that sanitizer's own check and not this flag's. \
                    Measured identically at every -O level.",
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
                reason: "a null check that survives its preceding dereference survives when the \
                         optimizer did not run or was told to keep it; both arms carry -O2, so the \
                         unoptimized form is the inert direction tests/inert_flags.rs holds, and \
                         no flag of either profile other than -O touches that optimization. \
                         Whether a sanitizer keeps the check is not measured (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["optimizer-exploited-ub", "null-deref"],
            observes: Observes::Protection,
            references: &[GUIDE],
            // Deliberately NOT gated off clang, though the obvious reading says it should
            // be. `compiler_limitation` upgrades `probe-invalid` to `unsupported` only when
            // the positive control shows the observable ABSENT -- the flag forced on and
            // nothing appearing. Here both arms show it present: clang keeps the null check
            // either way, so the mechanism is not missing, the discrimination is. The gate
            // refuses that case on purpose, since a non-discriminating negative is a harness
            // problem and must not be relabelled a property of the compiler. A gate here
            // would never fire, and a rule that cannot fire is worse than no rule.
            gate: PORTABLE,
            notes: "CVE-2009-1897 in the tun driver is the worked example: a dereference, \
                    then `if (!tun)`, and the compiler deleted the check because the \
                    dereference proved the pointer non-null. On a kernel with a mappable \
                    zero page that is privilege escalation rather than a crash. The probe \
                    needs optimization to run at all: without it the dead load is not \
                    eliminated and the null dereference executes, so an unoptimized \
                    profile reports `run-failed`, which is the honest answer rather than a \
                    verdict. The pointer is kept opaque to the optimizer so the observable \
                    is the flag rather than the caller's visible null literal. clang \
                    reports `probe-invalid`: it keeps the check under both arms, so the \
                    controls do not discriminate and there is no verdict to be had.",
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
                reason: "detect_no_strict_aliasing re-reads the store from a copy compiled without \
                         sanitizer instrumentation and withholds where only the instrumented build \
                         kept it, so a sanitizer cannot be credited to the flag; -O2 is in both \
                         arms, and no other flag of either profile changes type-based alias \
                         analysis (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            defects: &["optimizer-exploited-ub"],
            observes: Observes::Protection,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The flag the Linux kernel passes, and it is passed because the \
                    type-based aliasing assumption is wrong for a great deal of real code \
                    that punts types through pointers. Genuinely inert without \
                    optimization: measured on gcc, at -O0 the store is observed whether \
                    or not the flag is passed, so the detector requires __OPTIMIZE__ \
                    before crediting the reading, the same way the fortify detectors do. \
                    The three anti-UB flags do not share one relationship to the \
                    optimizer, and assuming they did would have produced a false positive \
                    here and a false negative on the overflow check. __OPTIMIZE__ is not \
                    enough on gcc either, which applies the rule by default only from -O2 \
                    and -Os: at -O1 and -Og the store is observed with no flag passed, \
                    and the flag there is present and inert. On gcc the probe carries two \
                    witness copies of the shape under the optimize attribute and a \
                    sibling-call witness, a tail call that becomes a jump at the levels \
                    that apply the rule; an observed store is credited only where a copy \
                    shows the flag rather than the level, or, on gcc 12 and later, where \
                    the -O2 copy also observed it beside that jump. Otherwise the reading \
                    is withheld as indeterminate: every gcc build at -O1 or -Og, with or \
                    without the flag, and a build whose flags suppress the jump. The probe \
                    source carries the witnesses, what moves them and their measurements.",
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
            observable: "the byte past the active member of an initialized union, in a \
                         deliberately pre-dirtied frame",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-fzero-init-padding-bits=all"],
            // `=standard` rather than omitting the flag: it is the other value gcc
            // accepts and it behaves as the default does, which makes the negative arm a
            // stated choice rather than an absence.
            negative: &["-fzero-init-padding-bits=standard"],
            defects: &["uninitialized-read", "address-layout-disclosure"],
            observes: Observes::Protection,
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "the obvious confounder would be -ftrivial-auto-var-init=zero, and it is \
                         measured not to be one: that flag covers variables with no initializer, \
                         and this probe's union has one, so it reads pad=0x5a with tavi=zero alone \
                         and pad=0x00 only when this flag is also passed; neither profile carries \
                         another flag that writes padding (measured on gcc; clang is gated).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // clang 22.1.8 answers `-fzero-init-padding-bits=all` with "unknown
                // argument", so both control arms fail to build and there is nothing to
                // compare. The triple reads `probe-invalid`, and the driver's own "unknown
                // argument" on the positive arm's stderr turns that reading into
                // `unsupported` under `flag-unknown-to-driver`
                // (`report::gating_rule::FLAG_UNKNOWN`), which does not consult this
                // declaration (`measure::unknown_flag_limitation` says why). clang 22.1.8
                // reads so in its three cells on Fedora 44 x86_64, as
                // `trampolines-warned` and `hardened-downgrade-warned` did.
                //
                // The declaration is the other path: a clang that accepted the option and
                // left the observable absent would read `unsupported` under
                // `compiler-declared`.
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "Answers under `bare` on gcc and withholds everywhere else, which is \
                    narrower than \
                    the guide's recommendation: the guide asks for this on production \
                    builds, and from -O1 upward the frame-reuse premise the probe depends \
                    on stops holding, so the observation is refused rather than read. The \
                    construct matters as much as the flag: gcc already zeroes struct \
                    padding, so a partially-initialized struct is identical with and \
                    without this option at every optimization level. A union with a short \
                    active member is the case that discriminates, so a test over \
                    structs and bitfields alone reads the flag as unobservable.",
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
            // This check gets an arm although no profile flag is known to produce the
            // observable. The measurement (gcc 16.1.1, clang 22.1.8, Fedora 44 x86_64, 2026-10-09):
            // openssf-tldr minus this flag reads `off` and `-O2` alone reads `off`, so no profile
            // flag is known to produce the observable, and the one co-enabled flag measured to zero
            // any argument register, `-fstack-protector-all` under gcc 16.2.1 on aarch64, zeroes
            // two and leaves the others, which reads `absent` (`detect_zero_call_used_regs`). The
            // arm is the profile followed by `=skip`, which wins last on the line, so it is expected
            // to read `absent` under every profile measured and to withhold the day a toolchain or a
            // profile clears the registers by another route.
            regime: Regime::Arm(&["-fzero-call-used-regs=skip"]),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // The two architectures the guide recommends the flag for, and the two the
                // probe's trampoline is written for. gcc implements the flag on i386 too.
                arch: &["x86_64", "aarch64"],
                libc_unsupported: &[],
                // clang implements the flag on both architectures from clang 15; clang
                // 14.0.0 rejects it as an unknown argument, which
                // `measure::unknown_flag_limitation` publishes as `unsupported` in the
                // driver's words. Not a family fact, so nothing is declared here.
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "Read from the registers themselves: an assembly trampoline loads a \
                    marker into every argument register and one non-argument register, \
                    calls a compiled function that uses all of them, and stores them \
                    straight after the return, with no compiled code in between. The same \
                    trampoline around a function that only returns must give every marker \
                    back, which is the witness. `gpr` is the guide's `=used-gpr` (and \
                    `=used`, `=all-gpr`, `=all`); `arg` is the `-arg` forms, which leave \
                    the non-argument register and read `partial`. `=skip`, and \
                    `=used-gpr` followed by `=skip`, read `off`. The guide's 2026-08-20 \
                    revision added the flag to its TL;DR addendum rows for x86_64 and \
                    aarch64, and the `openssf-tldr` profile carries it on both.",
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
        // glibc's opt-in. glibc 2.39 and later enable the shadow stack for a marked program only
        // where the process sets this tunable; without it the positive control reads `features=0`
        // and the triple could never discriminate, which is a question chard did not pose rather
        // than a toolchain that declined. The pin decides the outcome only: the probe runs itself a
        // second time without it, and that run is the level (`SHADOW_STACK_DEFAULT`), so an `on` is
        // never the opt-in's alone. `glibc.cpu.x86_shstk=on` and `=permissive` alone enable
        // nothing, and a spelling glibc does not recognise is ignored silently, so the spelling is
        // the one measured to arm it: on 2026-10-02 on Fedora 44 x86_64 (glibc 2.43, kernel
        // 7.3.0-rc3) and in the `ubuntu:24.04` image (glibc 2.39), a `-fcf-protection=full` build
        // read `features=0x1` under this pin and `features=0` under no tunable,
        // `glibc.cpu.x86_shstk=on`, `=permissive`, `=off` and `=ON`. A misspelled pin would silence
        // the positive control, which reads `probe-invalid`, never `off`. musl and Apple libc
        // ignore the variable. `glibc.malloc.perturb=170` rides with it as the pin's own
        // witness: the probe's first line says whether its effect showed, so a C library that
        // ignores `GLIBC_TUNABLES` (a Wolfi-derived rootfs's glibc) is named as one rather than read as a
        // program the opt-in reached (`report::opt_in_not_honoured`).
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
                // answers from its own model. qemu-x86_64 10.2.2 on the Fedora 44 x86_64
                // host (2026-10-02) answered `kernel=errno:22 cpu=no-ss` for a build the host
                // itself enforced.
                basis: RunBasis::Machine,
            },
            polarity: Polarity::Harden,
            observable: "the running program's shadow stack: ARCH_SHSTK_STATUS bit 0, a \
                         non-zero shadow stack pointer, and SIGSEGV with si_code SEGV_CPERR \
                         when an assembly function overwrites its own return address",
            levels: SHADOW_STACK_DEFAULT,
            confidence: Confidence::High,
            // `=full` rather than `=return`, the guide's ask and the positive control
            // `cet-marked` uses; both set the shadow-stack bit, and both read present under
            // gcc 16.1.1 and clang 22.1.8 at -O0 through -O3 and -Os (probe header).
            positive: &["-fcf-protection=full"],
            negative: &["-fcf-protection=none"],
            defects: &["return-oriented-programming"],
            observes: Observes::Protection,
            // Not the `cet` group. That group holds readers of the marking, which must
            // agree; this reads the running process, which can disagree with a correct
            // marking for reasons that are findings rather than faults: an unmarked object
            // loaded beside the program turns the shadow stack off for the whole process.
            corroborates: None,
            regime: Regime::NotOwed(Specific {
                reason: "SEGV_CPERR is raised by a control-protection fault and by nothing else, \
                         and bit 0 of the kernel's ARCH_SHSTK_STATUS is the shadow stack itself; \
                         no co-enabled flag of either profile produces either (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                // The probe reads x86 CET: `arch_prctl(ARCH_SHSTK_STATUS)`, `rdsspq` and
                // SEGV_CPERR, which Linux offers on x86_64 alone (`X86_USER_SHADOW_STACK`
                // depends on `X86_64`, so i386 has none). Linux also has a user shadow stack on
                // aarch64 (GCS) and riscv64 (Zicfiss), enabled through
                // `prctl(PR_SET_SHADOW_STACK_STATUS)`, which no probe reads, so the gate
                // stays x86_64 alone.
                arch: &["x86_64"],
                // musl has no shadow-stack support: in the Alpine edge image (musl 1.2.6,
                // gcc 15.2.0, clang 23.1.2) on the Fedora 44 kernel, a
                // `-fcf-protection=full` build read `features=0` with the pin set. Consulted
                // only after the positive control read absent (`report::libc_limitation`).
                libc_unsupported: &["musl"],
                compiler_unsupported: &[],
                cxx_stdlib_unsupported: &[],
                // The kernel is part of the question: under a container it is the host's.
                needs_vm: true,
            },
            notes: "Enforcement rather than marking. The program is run with glibc's opt-in \
                    (`GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK`, pinned for this probe alone, \
                    beside `glibc.malloc.perturb=170`, whose effect the probe reads to show \
                    the pin reached the C library), and that run is present only where the kernel reports the shadow stack \
                    enabled, the shadow stack pointer is non-zero and an overwritten return \
                    address faults with SEGV_CPERR; that run is what the control triple \
                    discriminates on. The probe then reads the same program run without the \
                    tunable, as a deployment that sets nothing runs it, and grades on that: \
                    `on` at `default` where the shadow stack was enforced there too, \
                    `partial` at `opt-in` where it was enforced only under the opt-in, which \
                    is upstream glibc 2.39 and later. It answers for the toolchain's output, \
                    the C library and every object loaded with the program, and the kernel \
                    and CPU it ran on. An unmarked object every arm loads (the C library, the \
                    startup files) silences the positive control and leaves the cell \
                    `probe-invalid`; one the profile adds, a library on the measured link \
                    line alone, turns the shadow stack off for the measured program only and \
                    reads `off`, the true state of enforcement for that build, while \
                    `cet-marked` may read `on`. Where the positive control read `absent` on \
                    glibc and its witness tunable showed no effect (`SHSTK tunables=ignored`), \
                    the opt-in is not shown to have reached the C library and the cell is \
                    `indeterminate` under `opt-in-not-honoured`. Where the kernel has no user \
                    shadow stack the cell is `unsupported` under `kernel-lacks-shadow-stack`; where the CPU the \
                    run was handed does not enumerate CET_SS, `indeterminate` under \
                    `cpu-lacks-shadow-stack`; under a container, `indeterminate` under \
                    `needs-vm`, and where nothing established whose kernel it is, under \
                    `execution-mode-assumed`.",
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
                notes: "The flag that broke the rsync exploit chain: CVE-2024-12085 was \
                        an uninitialized-stack disclosure chained into CVE-2024-12084's \
                        overflow for RCE, and zero-init removes the disclosure. \
                        Decidable on both compilers at every optimization level, because \
                        the probe reuses one frame and reads through volatile lvalues. \
                        Without that, clang appears to zero automatic variables \
                        incidentally from -O1 upward, and does not: it folds a read of a \
                        never-stored automatic to a constant and emits no load at all. \
                        gcc looks healthy for an equally bad reason, discriminating on \
                        loader residue that varies with the size of the environment \
                        rather than on anything the flag does.",
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
                observable: "gcc's 0xFE pattern fill, or clang's: 0xAA with 64-bit pointers, \
                             0xFF on an ELFCLASS32 artifact",
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
                notes: "Attributable on both compilers, unlike zero: gcc's 0xFE and \
                        clang's 64-bit 0xAA are values nothing produces by accident, and \
                        clang's 32-bit 0xFF is held to the ctrl witness and three shapes \
                        agreeing. Not the setting the \
                        guide recommends for production, but it is the setting that \
                        proves the detection mechanism works on a toolchain where the \
                        zero check cannot discriminate.",
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
                reason: "the observable is the compiler's own severity on the construct; a -Werror \
                         or a configured default that makes it an error is the mechanism in force, \
                         and a diagnostics format that hides the text is withheld under \
                         diag-stream-is-text-unless-recognised. No other flag of either \
                         profile changes this diagnostic (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "GCC 14 and Clang 16 made this an error by default. It leaves no \
                    trace in a binary, so no amount of artifact inspection can \
                    recover it; this is why the compiler-diag channel exists.",
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
                observable: "_GLIBCXX_ASSERTIONS or _LIBCPP_HARDENING_MODE, against the \
                             standard library that identified itself",
                levels: LIBCPP_MODES,
                confidence: Confidence::High,
                // Both libraries' spellings in both arms, because a control has to work
                // on whichever library the guest ships and each ignores the other's
                // macro. Measured: on Chimera, which is libc++, the libstdc++-only arms
                // changed nothing, so the controls could not discriminate and a build
                // running libc++ at hardening mode `debug` reported `probe-invalid`.
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
                    reason: "the observable is the _GLIBCXX_ASSERTIONS or _LIBCPP_HARDENING_MODE \
                             macro itself, set only by a -D of its name or by libstdc++'s own -O0 \
                             default, which cxx-stdlib-assertions attributes in \
                             evidence.cxx_assertions_source; no other flag of either profile \
                             defines one (argued).",
                    profiles: PROFILES_WITH_FLAGS,
                    toolchains: GCC_AND_CLANG,
                }),
                measures_toolchain_default: false,
                defects: &["heap-buffer-overflow"],
                observes: Observes::Request,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "The macro half of the C++ pair, and it exists for the reason \
                        `fortify-requested` does: a request is not enforcement, and \
                        divergence from `cxx-stdlib-assertions` beside it is a finding \
                        rather than noise. The two standard libraries spell the request \
                        differently: libstdc++ takes a boolean, libc++ a graded mode of \
                        none/fast/extensive/debug, so the library has to identify itself \
                        before either answer means anything, which is what `_CXX_STDLIB` \
                        in the self-report is for. Without it a build with neither macro \
                        defined is ambiguous: libstdc++ with assertions off and libc++, \
                        which does not use that macro at all, are indistinguishable. The \
                        same ambiguity `_FORTIFY_IMPL` was added to resolve for the C \
                        library. The mode is published as information and graded \
                        against nothing: the guide asks for `fast`, the lowest mode, so \
                        every mode short of `none` met it, and libstdc++'s boolean \
                        request carries no mode to grade.",
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
                observable: "an out-of-range vector subscript reaching either the standard \
                         library's own failed-precondition message on an abort, or a bare \
                         trap where the library identified itself as libc++",
                levels: Levels::None,
                confidence: Confidence::High,
                // -U before -D so the measured profile cannot leave a stale definition
                // behind. No -O2: the check is answerable without optimization (see the
                // negative arm), and leaving it out lets the regime arm run at the profile's
                // own optimization level instead of silently overriding it.
                positive: &[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
                ],
                // Both spellings in the negative arm, because the regime variant inherits
                // the measured profile's flags and every rpm distribution defines this
                // through `-Wp,`, which goes straight to the preprocessor. Measured: a
                // plain `-U_GLIBCXX_ASSERTIONS` does *not* counter
                // `-Wp,-D_GLIBCXX_ASSERTIONS`, so on Fedora the regime negative still
                // aborted and the check reported probe-invalid for a flag the
                // distribution plainly sets. A negative control has to counter the
                // spelling the distribution uses, not the canonical one.
                //
                // The plain arms are unaffected either way: they are built profile-free,
                // which is why the existing fortify checks do not have this problem
                // despite Fedora defining `-Wp,-D_FORTIFY_SOURCE=3`.
                //
                // `-D_GLIBCXX_NO_ASSERTIONS` is the load-bearing addition, and its absence
                // was a wrong-knob bug rather than a limitation of the mechanism.
                // `-U_GLIBCXX_ASSERTIONS` alone cannot switch this off at any optimization
                // level, because `c++config.h` re-defines the macro *after* the command
                // line is applied:
                //
                //     #ifndef _GLIBCXX_ASSERTIONS
                //     # if defined(_GLIBCXX_DEBUG)
                //     #  define _GLIBCXX_ASSERTIONS 1
                //     # elif ! defined(__OPTIMIZE__) && ! defined(_GLIBCXX_NO_ASSERTIONS)
                //     #  define _GLIBCXX_ASSERTIONS 1
                //     # endif
                //     #endif
                //
                // `_GLIBCXX_NO_ASSERTIONS` is a term of that same condition, so it is the
                // only thing that can suppress the unoptimized default. Measured on g++ and
                // clang++ at -O0: `-U_GLIBCXX_ASSERTIONS` still aborts, and adding
                // `-D_GLIBCXX_NO_ASSERTIONS` does not. That is what makes this check
                // answerable in an unoptimized build, which the `bare` profile is.
                negative: &[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-Wp,-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    // libc++'s off switch. Without it this arm cannot turn hardening off
                    // on a libc++ system, measured on Chimera, whose default is `fast`:
                    // both arms trapped, so the controls could not discriminate and a
                    // library that was plainly working reported `probe-invalid`.
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ],
                defects: &["heap-buffer-overflow"],
                observes: Observes::Protection,
                corroborates: None,
                // Mandatory. libstdc++ enables this precondition check whenever
                // `__OPTIMIZE__` is undefined, so an unoptimized build has it on without
                // anyone asking.
                //
                // The verdict is not withheld at -O0. The question is answerable there:
                // `-D_GLIBCXX_NO_ASSERTIONS` suppresses the default, measured, and
                // withholding a mitigation that is in force is the mirror image of the error
                // this project exists to prevent. At -O0 the abort does fire and the
                // precondition is checked, so the verdict is `on`.
                //
                // The regime arm does not say whether the library or the packager is why.
                // Under `--profile explicit --flags -U_GLIBCXX_ASSERTIONS` with no -O this
                // check reads `on` and its regime arm `absent`, because the negative list's
                // `-D_GLIBCXX_NO_ASSERTIONS` switches the library default off in that arm
                // too; gcc and clang on Fedora 44 x86_64 and aarch64. The
                // attribution is the observation's `evidence.cxx_assertions_source`
                // (`measure::cxx_assertions_source`), which names
                // `library-unoptimized-default` in that cell and `profile` under
                // `-D_GLIBCXX_ASSERTIONS`.
                regime: Regime::Arm(&[
                    "-U_GLIBCXX_ASSERTIONS",
                    "-Wp,-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ]),
                measures_toolchain_default: false,
                references: &[GUIDE],
                gate: PORTABLE,
                notes: "The first probe in the corpus to use the C++ driver. Verified to \
                    discriminate on both g++ and clang++, which on a glibc system both \
                    use libstdc++, so the message is the same. On libc++ a bare trap is \
                    credited where the build names libc++ as its library; of the \
                    measurements in chard's test corpus, a build under the `bare` profile \
                    on Chimera Linux (clang 22.1.7, musl, x86_64) alone reached `on` that \
                    way. libc++'s own failed-precondition message is matched too, but no \
                    recorded measurement holds it, only a hand-written test case. `operator[]` \
                    deliberately, not `at()`: `at()` throws whatever the flags say and \
                    would report identically in both control arms.",
            },
            Check {
                id: "cxx-assertions-symbol",
                flag: "-D_GLIBCXX_ASSERTIONS (artifact symbol)",
                decoder: Decoder::ElfStatic(elf_static::cxx_assertions_symbol),
                polarity: Polarity::Harden,
                observable: "libstdc++'s assertion-failure symbol left in the artifact",
                levels: Levels::None,
                confidence: Confidence::High,
                // Both libraries' spellings in the positive arm, for the reason
                // `cxx-hardening-requested` gives: a control has to do something on
                // whichever library the guest ships, and each ignores the other's macro.
                // `-O2` in both arms because libstdc++ auto-enables the assertions when
                // `__OPTIMIZE__` is undefined -- at -O0 the symbol is present in *both*
                // arms and the triple cannot discriminate, which is a property of the
                // library rather than of the build under test.
                positive: &[
                    "-O2",
                    "-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
                ],
                // The sibling's negative arm, spelling for spelling, because the same
                // library ignores the same macros here: `-U` and `-Wp,-U` because a
                // profile may have defined it on the command line, `_GLIBCXX_NO_ASSERTIONS`
                // because that is libstdc++'s off switch rather than merely not asking.
                negative: &[
                    "-O2",
                    "-U_GLIBCXX_ASSERTIONS",
                    "-Wp,-U_GLIBCXX_ASSERTIONS",
                    "-D_GLIBCXX_NO_ASSERTIONS",
                    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
                ],
                corroborates: Some("cxx-stdlib-assertions"),
                // For the confound the sibling carries it for, which reaches this channel
                // the same way: libstdc++ turns the assertions on whenever `__OPTIMIZE__`
                // is undefined, so at -O0 the symbol is in the artifact whether or not the
                // flag was asked for. The controls pin -O2 and therefore discriminate, but
                // the *measured* build is whatever the profile says, and an unoptimized
                // profile publishes `on` for a library default rather than for a
                // configuration. Re-running the negative under the profile's own flags does
                // not withhold it: the regime arm is the profile's flags followed by the
                // arm's list, whose `-D_GLIBCXX_NO_ASSERTIONS` removes the -O0 default, so
                // under `--profile explicit --flags -U_GLIBCXX_ASSERTIONS` with no -O the
                // arm reads `absent` and the check publishes `on`. Measured for gcc and
                // clang on Fedora 44 x86_64 and aarch64 (libstdc++ 16.1.1 and 16.2.1), with
                // -O2 in the arm list as well;
                // `tests/inert_flags.rs` carries the full set of cells. The observation
                // names the cause beside the `on` in `evidence.cxx_assertions_source`, as
                // `cxx-stdlib-assertions` does.
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
                    // neither control arm can move this observable and the triple has
                    // nothing to discriminate. Its hardening is real and is measured by
                    // `cxx-stdlib-assertions`; what is absent here is this mechanism, not
                    // the protection.
                    cxx_stdlib_unsupported: &["libc++"],
                    needs_vm: false,
                },
                notes: "The artifact half of the pair `cxx-stdlib-assertions` trips at \
                        runtime. Worth its own channel because the two fail differently: \
                        the runtime check needs the probe to execute, so a cross-built or \
                        unrunnable target withholds it, while the symbol survives in \
                        anything that linked. Measured on gcc 16.2.1 and clang 22.1.8 \
                        over libstdc++ 16, identical symbol counts for both compilers. \
                        `-D_GLIBCXX_DEBUG` removes the symbol this watches and \
                        substitutes __gnu_debug::_Error_formatter, so the detector reads \
                        both and reports `present` for the stronger mode rather than the \
                        `off` a one-symbol grep would publish.",
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
            observable: "how far below the frame the first touch lands when a frame far \
                         larger than the stack limit is allocated: one page (guard hit) \
                         versus the whole allocation (guard skipped)",
            levels: Levels::None,
            confidence: Confidence::High,
            positive: &["-O2", "-fstack-clash-protection"],
            negative: &["-O2", "-fno-stack-clash-protection"],
            defects: &["stack-clash"],
            observes: Observes::Protection,
            corroborates: None,
            // `-fstack-check` produces the same observable by a different mechanism
            // and is *not* countermanded by `-fno-stack-clash-protection`, measured:
            // gcc -O2 -fstack-check -fno-stack-clash-protection still reports 12. A
            // profile enabling stack-check would otherwise be credited to this flag.
            // gcc's -fhardened does the same to the countermand, the notes below say
            // how and what the check publishes then.
            regime: Regime::Arm(&["-fno-stack-clash-protection"]),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "Measures where the fault lands rather than whether one happens, so \
                    both directions are affirmative and absence is sound. Verified at 12% \
                    with the flag and 100% without, on gcc and clang. Needs a bounded \
                    RLIMIT_STACK to size the allocation from; an unbounded or very small \
                    stack yields a declined probe rather than a guess, and so does a \
                    limit whose allocation does not fit below the frame (16 TiB and up \
                    on 4-level x86_64, about 256 MiB and up for i386 in compat mode, measured \
                    2026-10-05). Needs no kernel-ownership gate (`needs_vm`): the verdict is \
                    the compiler's probing, and the kernel only supplies the fault, the same \
                    kernel for all three arms of a run. Linux (as above), FreeBSD and macOS \
                    fault at the stack limit, so an arm that probes reads about 12% and one \
                    that does not 100% (FreeBSD 15.1 clang 19.1.7, quoted from the fleet's \
                    reports; macOS 27.0.1 Homebrew gcc 16.2.0). Where \
                    the arms do not discriminate the check is `probe-invalid`: on OpenBSD 7.9 \
                    the driver ignores the flag, so the arms are one program, and a fault \
                    outside `MAP_STACK` memory arrives at the faulting instruction, which is \
                    no distance below the frame. So a kernel can leave this check without a \
                    verdict, but cannot make it read another one. gcc's `-fhardened` turns \
                    stack-clash protection on beside an explicit \
                    `-fno-stack-clash-protection`, in either order and with no `-Whardened` \
                    warning, where the stack protector, `_FORTIFY_SOURCE`, `-fcf-protection`, \
                    `-ftrivial-auto-var-init` and the linker's PIE, RELRO and `-z now` each \
                    yield to an explicit countermand and draw a `-Whardened` warning (checked \
                    on Fedora 44 gcc 16.1.1): an arm built with both reads about \
                    12%. That `-fhardened` keeps stack-clash protection on over the \
                    countermand was reported as GCC PR 127949 (2026-10-16, \
                    https://gcc.gnu.org/bugzilla/show_bug.cgi?id=127949). The check \
                    withholds in both shapes that behaviour makes, and reads neither \
                    `on` nor `off`: \
                    a driver that adds `-fhardened` to every build reads `probe-invalid` \
                    with `negative-also-shows` (the negative arm reads 12% too), and a \
                    profile that passes `-fhardened` reads `probe-invalid` with \
                    `regime-confounded` (the regime arm reads 12%, the plain negative \
                    100%). The 12% reading was measured on x86_64 by building the probe by \
                    hand with Fedora 44 gcc 16.1.1 and Wolfi gcc 14.4.0 and 16.2.0 \
                    (2026-10-15), where a Wolfi gcc 14 wrapper adding `-fhardened` \
                    also read `negative-also-shows`; both withheld shapes were measured \
                    through chard with Fedora 44 gcc 16.1.1.",
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
                reason: "the observable is the compiler's own severity on the construct, so a \
                         -Werror that makes it an error is the mechanism in force and not a \
                         confound, and no other flag of either profile touches this diagnostic (argued). \
                         Measured 2026-10-12 on Fedora 44 x86_64 (gcc 16.1.1, clang 22.1.8): the \
                         negative list appended after -Werror=format-security downgrades it to a \
                         warning on both, so an arm could be built; a plain -Wformat-security \
                         alone does not downgrade it, which is why the list carries -Wno-error.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "Reports whether a non-literal format stops this build, not whether a \
                    token was passed: -Wall -Werror and, on clang, a bare -Werror produce \
                    it too, since clang defaults -Wformat-security on. The probe declares \
                    and defines its own printf-attributed function and includes no libc \
                    header, because glibc's fortify headers redeclare printf under clang \
                    without a format attribute and silently disable -Wformat checking \
                    whenever _FORTIFY_SOURCE >= 2.",
        }],
    },
    // ---- OpenSSF guide Table 1: strictly compile-time checks -------------------
    //
    // Every check below carries exactly one observable in its own translation unit.
    // Pairing two into one file was measured to be wrong on precisely the profiles
    // that harden hardest: under `-Wall -Werror` gcc raises the first diagnostic as
    // an error and never reaches the second, so the second cell saw no observable, a
    // live canary and a failed build, and reported indeterminate where the truth was
    // plainly absent.
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wall, -Wextra which implies it, a \
                         configured default) is the mechanism in force and not a confound; a \
                         structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "-Wunused-label is the observable because it is in -Wall on both \
                    compilers, in neither default set, and in neither -Wextra. Three \
                    likelier candidates were measured and rejected: -Wreturn-type, \
                    -Wparentheses and -Wempty-body are on by default in clang 22, so the \
                    negative control cannot discriminate; and -Wunused-function is emitted \
                    by clang only while finishing the translation unit, a pass it skips \
                    once any error has been raised, so it vanishes under -Wall -Werror.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wextra, -Wall which does not imply \
                         it, a configured default) is the mechanism in force and not a confound; a \
                         structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "-Wsign-compare is in -Wextra for C on both compilers and in neither \
                    -Wall, so the cell is answerable with -Wall absent. In C++ it moves \
                    into -Wall, which is one reason this probe is C. One member of a group \
                    of roughly fifteen: a `present` says the group is on, not that every \
                    warning in it fired.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wformat, -Wall and -Wformat=2 \
                         which imply it, a configured default) is the mechanism in force and not a \
                         confound; a structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "Weak evidence that the profile asked for -Wformat specifically: clang \
                    enables it by default and gcc's -Wall implies it, so on gcc this cell \
                    largely restates warn-all and on clang it is close to constant. It is \
                    still worth reading, because -Werror=format-security is inert without \
                    it: a profile passing that flag alone gets nothing.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wformat=2, -Wformat-nonliteral, a \
                         configured default) is the mechanism in force and not a confound; a \
                         structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The construct carries an argument, which keeps it out of the \
                    -Wformat-security shape (non-literal, no arguments) that \
                    format-security-is-error already measures; verified that \
                    -Wformat-security raises nothing on this call. Reads -Wformat-nonliteral \
                    only, so `-Wformat -Wformat-nonliteral` is indistinguishable from \
                    -Wformat=2 here, and -Wformat-y2k is not read at all. The guide's \
                    divergence is the point: clang's -Wformat already covers what gcc calls \
                    -Wformat=2, while clang's -Wformat=2 does not include -Wformat.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wconversion, a configured default) \
                         is the mechanism in force and not a confound; a structured diagnostics \
                         format is withheld under diag-stream-is-text-unless-recognised, \
                         and no flag of either profile suppresses or fakes this diagnostic's text \
                         (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The source value is volatile so the compiler cannot prove the \
                    conversion safe and skip the warning. On both compilers -Wconversion \
                    also enables -Wsign-conversion for C, so this cell being on implies the \
                    sign-conversion cell is on; the two are not independent evidence.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wsign-conversion, -Wconversion \
                         which implies it in C, a configured default) is the mechanism in force \
                         and not a confound; a structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "NOT independent of conversion-warns-on-narrowing: -Wconversion enables \
                    -Wsign-conversion for C on both compilers, so this cell adds signal \
                    only for a profile passing -Wsign-conversion without -Wconversion. The \
                    containment differs again in C++, which is one reason this probe is C.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wimplicit-fallthrough, -Wextra \
                         which implies it, a configured default) is the mechanism in force and not \
                         a confound; a structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The detector matches the message wording, never the option name, and \
                    that is load-bearing: clang answers -Wimplicit-fallthrough=5 (a \
                    spelling the Linux kernel and several distributions really pass) with \
                    \"unknown warning option '-Wimplicit-fallthrough=5'; did you mean \
                    '-Wimplicit-fallthrough'?\" and no fall-through diagnostic at all, so a \
                    name match would score an ignored flag as present. Confound: gcc's \
                    -Wextra implies -Wimplicit-fallthrough=3, so a -Wextra-only profile \
                    lights this cell on gcc but not on clang.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wtrampolines, a configured \
                         default) is the mechanism in force and not a confound; a structured \
                         diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued). clang lacks \
                         the warning and is gated.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // Nested functions are a GNU C extension clang does not implement, so
                // the probe cannot build there and there is no diagnostic to read. The
                // guide lists this option under "when using GCC" for the same reason.
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "A trampoline needs an executable stack, which is why the guide warns \
                    about it: it defeats -Wl,-z,noexecstack. Two bounds on the cell: the \
                    linker emits \"requires executable stack\" in every arm, so a profile \
                    carrying -Wl,--fatal-warnings turns that into a link failure and the \
                    cell goes indeterminate for reasons unrelated to this flag; and gcc's \
                    -ftrampoline-impl=heap moves the trampoline off the stack, correctly \
                    silencing the diagnostic. So this measures \"a stack trampoline here is \
                    diagnosed\", not \"the token was passed\". \
                    \
                    On clang this reports probe-invalid rather than unsupported, and the \
                    difference from bidi-chars-any is deliberate. clang builds that probe \
                    and stays silent, which is a measured absence the compiler gate can \
                    convert into `unsupported`; here clang cannot compile nested functions \
                    at all, so both control arms are indeterminate and nothing was \
                    measured. Promoting a build failure to a claim about the compiler is \
                    exactly what the gate refuses to do, since a probe broken for any other \
                    reason would then masquerade as a compiler limitation.",
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
                reason: "the observable is whether the compiler diagnoses the construct, so any \
                         spelling that enables the diagnostic (-Wbidi-chars=any, over gcc's \
                         default of unpaired, a configured default) is the mechanism in force and \
                         not a confound; a structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile suppresses or fakes this diagnostic's text (argued). clang lacks \
                         the warning and is gated.",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: &["gcc"],
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: Gate {
                arch: &[],
                libc_unsupported: &[],
                // clang has no equivalent option: it answers -Wbidi-chars=any with
                // "unknown warning option". Reporting that as `off` would read as a
                // distribution's choice rather than a missing mechanism.
                compiler_unsupported: &["clang"],
                cxx_stdlib_unsupported: &[],
                needs_vm: false,
            },
            notes: "The Trojan Source class: source that reads one way to a human and \
                    another to the compiler. The override is *balanced* (RLO then PDF), so \
                    only -Wbidi-chars=any diagnoses it; gcc's default, =unpaired, does \
                    not, which is what makes the negative control meaningful. Only the \
                    `any` spelling is covered; =unpaired and the ,ucn variants are not \
                    reported, so a codebase legitimately using RTL text shows this absent. \
                    The detector matches the message, not the option name, because clang \
                    prints the option name while rejecting it.",
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
                reason: "the observable is the compiler's own severity on the construct, so a \
                         -Werror, a -Werror=implicit-int or a compiler that makes it an error by \
                         default (gcc 14 and clang do) is the mechanism in force and not a \
                         confound; a structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile changes this diagnostic (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "The other half of the guide's -Werror=implicit umbrella, whose \
                    function-declaration half is implicit-function-declaration-is-error. \
                    They are separately controllable warnings and gcc 14 / clang 15 moved \
                    their defaults independently, which is why both are measured. Expect \
                    `present` almost everywhere on modern toolchains: this is a compiler \
                    floor, already an error with no flags at all on gcc 16 and clang 22. It \
                    can still be downgraded, so the negative control is real and the cell's \
                    value is catching the profiles that do downgrade it.",
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
                reason: "the observable is the compiler's own severity on the construct, so a \
                         -Werror, a -Werror=incompatible-pointer-types or a compiler that makes it \
                         an error by default (gcc 14 and clang do) is the mechanism in force and \
                         not a confound; a structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile changes this diagnostic (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "C only: gcc 8.4+ warns the option is not valid for C++, where the \
                    construct is already illegal. A compiler floor on gcc 14 / clang 15 and \
                    later, same as its two siblings; all four cells of the guide's \
                    \"obsolete C constructs\" row will co-move on a modern toolchain, so \
                    they should not be counted as four independent pieces of evidence.",
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
                reason: "the observable is the compiler's own severity on the construct, so a \
                         -Werror, a -Werror=int-conversion or a compiler that makes it an error by \
                         default (gcc 14 and clang do) is the mechanism in force and not a \
                         confound; a structured diagnostics format is withheld under \
                         diag-stream-is-text-unless-recognised, and no flag of either \
                         profile changes this diagnostic (argued).",
                profiles: PROFILES_WITH_FLAGS,
                toolchains: GCC_AND_CLANG,
            }),
            measures_toolchain_default: false,
            references: &[GUIDE],
            gate: PORTABLE,
            notes: "C only, and a compiler floor on gcc 14 / clang 15 and later. Measured \
                    trap for the detector: clang's own -Wint-conversion wording is \
                    \"incompatible integer to pointer conversion\", so matching the bare \
                    word \"incompatible\" would collide with the sibling \
                    incompatible-pointer-types check. Also measured: a bare -Wno-error does \
                    NOT downgrade this on gcc, because the default-error is a permerror \
                    rather than a -Werror escalation.",
        }],
    },
];

/// Refused when the crate is built: a regime arm with no flags or with an empty flag, or a
/// reason for owing none that states no argument or no frame. [`CORPUS`] is a `const`, so this runs at compile
/// time and a check that violates it does not compile; `tests/regime_arms.rs` holds what a
/// type cannot, the profile ids, the compiler names and the list of checks owning an arm.
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
                        specific.reason.len() >= 60,
                        "a reason for owing no regime arm states the argument"
                    );
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

/// The files whose code the decoders are, by path, as [`decoders_sha256`] reads them.
///
/// The predicate language and its evaluator, the two predicate tables, the runtime and
/// compiler-diag detectors under `src/decode/` and their shared helpers, and the ELF reader
/// whose facts the elf-static predicates read, `src/elf.rs` and its modules under `src/elf/`. The `*_tests.rs` files beside them are unit
/// tests and are left out, as a file's own `#[cfg(test)]` module is ([`decoder_code`]).
/// `tests/decode_layout.rs` holds this list to
/// the module files of the two directories, so a file added there is read here or fails
/// that test, and holds each file to a layout [`decoder_code`] reads as code alone.
pub const DECODER_SOURCES: &[(&str, &str)] = &[
    ("src/predicate/mod.rs", include_str!("predicate/mod.rs")),
    (
        "src/predicate/elf_static.rs",
        include_str!("predicate/elf_static.rs"),
    ),
    (
        "src/predicate/macro_channel.rs",
        include_str!("predicate/macro_channel.rs"),
    ),
    ("src/decode/mod.rs", include_str!("decode/mod.rs")),
    ("src/decode/common.rs", include_str!("decode/common.rs")),
    ("src/decode/diag.rs", include_str!("decode/diag.rs")),
    ("src/decode/runtime.rs", include_str!("decode/runtime.rs")),
    ("src/elf.rs", include_str!("elf.rs")),
    ("src/elf/code.rs", include_str!("elf/code.rs")),
    ("src/elf/entry.rs", include_str!("elf/entry.rs")),
    ("src/elf/reloc_names.rs", include_str!("elf/reloc_names.rs")),
];

/// A source file as the fingerprint reads it: the text before its first top-level
/// `#[cfg(test)]` line, less every line whose first non-blank characters are `//` and
/// every blank line.
///
/// A comment or doc edit, and a unit test, therefore leave the fingerprint where it was,
/// and a change to any line of code moves it. A trailing comment on a line of code is part
/// of that line. The layout the strip relies on (no block comment, the test gate last) is
/// `tests/decode_layout.rs`'s to hold.
#[must_use]
pub fn decoder_code(text: &str) -> String {
    let mut code = String::new();
    for line in text.lines().take_while(|l| *l != "#[cfg(test)]") {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        code.push_str(line);
        code.push('\n');
    }
    code
}

/// A predicate's canonical form, the one its digest and the corpus hash are taken over.
fn predicate_canonical(p: &Predicate) -> String {
    // `canonical` fails only on a map with a non-string key, which no predicate type has;
    // the error text is deterministic, so even that case hashes the same on every host.
    predicate::canonical(p).unwrap_or_else(|e| format!("unserializable predicate: {e}"))
}

/// The fingerprint over `language`, the predicates as `(check, predicate)` in corpus order,
/// and `sources` as `(path, text)` read through [`decoder_code`]. Each part is framed by
/// its length, so no two inputs share a canonical form.
#[must_use]
pub fn decoders_sha256_of(
    language: &str,
    predicates: &[(&str, &Predicate)],
    sources: &[(&str, &str)],
) -> String {
    let mut canonical = String::new();
    let mut push = |s: &str| {
        canonical.push_str(&s.len().to_string());
        canonical.push(':');
        canonical.push_str(s);
        canonical.push('\n');
    };
    push(language);
    for (check, p) in predicates {
        push(check);
        push(&predicate_canonical(p));
    }
    for (path, text) in sources {
        push(path);
        push(&decoder_code(text));
    }
    digest::sha256_hex(canonical.as_bytes())
}

/// The fingerprint over the code that turns evidence into readings: the predicate language
/// version, every check's predicate in corpus order, and the source of every decoder file
/// in [`DECODER_SOURCES`], comments and unit tests stripped.
///
/// A corpus hash binding every declarative field of a check and leaving the detector out,
/// as a function pointer with no stable value, would let a reverted decoder fix flip a
/// verdict under a byte-identical `probe_corpus_sha256`. This closes that for the
/// decoders' code; the report publishes it as `run.decoders_sha256`, and
/// [`corpus_sha256`] folds it in, so a report joins only reports whose decoders read alike.
#[must_use]
pub fn decoders_sha256() -> String {
    static DIGEST: LazyLock<String> = LazyLock::new(|| {
        let predicates: Vec<(&str, &Predicate)> = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter_map(|c| c.predicate().map(|p| (c.id, p)))
            .collect();
        decoders_sha256_of(predicate::LANGUAGE, &predicates, DECODER_SOURCES)
    });
    DIGEST.clone()
}

/// [`decoders_sha256_of`] over [`DECODER_SOURCES`] alone: the source every code decoder is
/// compiled from, with no language and no predicate.
#[must_use]
pub fn decoder_sources_sha256() -> String {
    static DIGEST: LazyLock<String> =
        LazyLock::new(|| decoders_sha256_of("", &[], DECODER_SOURCES));
    DIGEST.clone()
}

/// Hash over the corpus so a report names the exact probe set that produced it, and the
/// decoders that read it: [`corpus_sha256_of`] over [`CORPUS`] and [`decoders_sha256`].
pub fn corpus_sha256() -> String {
    corpus_sha256_of(CORPUS, &decoders_sha256())
}

/// Hash over `corpus` and the decoder fingerprint `decoders_sha256`.
///
/// Every field is bound by an exhaustive destructure rather than reached through the
/// struct, and that is the whole design of this function. A hand-picked field list is a
/// second site that must agree with the struct definition, and a list that omitted fields
/// would leave the hash blind to them: with the control flags absent, adding
/// `-D_GLIBCXX_NO_ASSERTIONS` to the cxx-assertions negative arm would turn that check
/// from `probe-invalid` into a real verdict on every profile and both compilers without
/// moving the hash by one bit; with `lang`, `link_mode`, `channel`, `polarity` and
/// `confidence` absent, flipping a probe from `Executable` to `SharedObject` (which
/// changes the linker invocation and every verdict under it) would leave the hash
/// byte-identical. Nothing that runs would notice either omission.
///
/// With `let Probe { .. }` written out in full and no `..` rest pattern, a field added to
/// `Probe`, `Check` or `Gate` **fails to compile here** until somebody decides whether it
/// changes a verdict. The fields that do not are bound and discarded in the open, with the
/// reason beside them, so the exclusion is a decision on the record instead of an omission
/// nobody can see.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "one exhaustive destructure per struct, read top to bottom; split, the field \
              list would live in two places, which is the defect this function removes"
)]
pub fn corpus_sha256_of(corpus: &[Probe], decoders_sha256: &str) -> String {
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
            // Prose. `title` names the probe for a reader and `notes` below explain a
            // check; neither reaches a compiler or a detector, so a wording fix must not
            // invalidate a sweep's comparability.
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
                // How the observation is read, which fixes the channel and the tables a
                // cut withholds on.
                decoder,
                polarity,
                confidence,
                observable,
                // The scale a level is graded on, its kind and the ask on it. All three
                // move verdicts: a rung added to a scale turns an `indeterminate` into a
                // measurement, and a moved ask turns `on` into `partial`.
                levels,
                positive,
                negative,
                corroborates,
                regime,
                measures_toolchain_default,
                gate,
                // Prose and cross-references. `defects` and `references` change which
                // claims a report *cites*, not which verdict it reaches; a report carries
                // them verbatim, so a reader comparing two reports sees the difference
                // without needing the corpus id to have moved.
                defects: _,
                // What the check observes moves every status `defect_coverage` derives
                // from its verdict, so two corpora that class one check differently are
                // two corpora; a report of this corpus is held to it on read.
                observes,
                references: _,
                notes: _,
            } = check;
            push(id);
            push(flag);
            push(observes.as_str());
            push(&format!(
                "{:?}/{polarity:?}/{confidence:?}",
                decoder.channel()
            ));
            // The decoder itself, destructured to the last field so a member added to a
            // variant fails to compile here. A predicate is a value, pushed in its
            // canonical form, so a clause edit moves this hash through the check it
            // decodes. A code decoder is a function pointer, which has no stable value to
            // hash; the name `detector!` spelled from its identifier is pushed, so
            // repointing a check at another detector moves this hash, and the detectors'
            // source is in `decoders_sha256`, pushed once at the top.
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
            // The per-architecture rows, pushed only where a check has one, so a check
            // without any hashes as it did before the table existed.
            for row in ARCH_CONTROLS.iter().filter(|row| row.check == *id) {
                push(&format!("{}: {}", row.arch, row.positive.join(" ")));
            }
            push(&negative.join(" "));
            // The arm's flags build an arm and so move verdicts; a reason for owing none
            // is prose, and a reworded one must not invalidate a sweep's comparability.
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
            // Which tables can withhold the check: a declaration that moves verdicts. A
            // predicate's are its `tables`, already in its canonical form above, and are
            // pushed again here so every check's line has the same shape.
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

/// The shadow-stack pin's witness tunable and the byte the probe reads for it agree:
/// glibc's perturb fills a fresh chunk with the tunable's value XOR 0xff, which
/// `probes/shadow_stack.c` names `CHARD_PERTURB_FILL`. A changed or dropped value on either
/// side would read `ignored` on every glibc, a witness that could never say `honoured`.
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
    /// Every probe with a macro-channel check embeds the `.chard.report` self-report, and
    /// references it from code the linker keeps.
    ///
    /// The macro channel's witness is the section (`DESIGN.md`, "The binary
    /// testifies about itself"), so a macro check over an artifact without one is withheld
    /// under `artifact-lacks-self-report` (`report::self_report_limitation`), and that gate
    /// reads the channel and the artifact alone: this is the invariant that lets it,
    /// since a macro-channel probe that embedded no section would withhold every verdict.
    /// The reference is what keeps the section through `--gc-sections` on a toolchain
    /// without the `retain` attribute (gcc before 11, clang before 13): `used` keeps it
    /// through the compiler and not through the linker, and
    /// `tests/probe_sources.rs` links each of these probes that way and reads the section
    /// back. A probe with the section and no reference loses it to such a link on both
    /// compiler families.
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
            let code = super::without_c_comments(probe.source);
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

    /// The comment scan's premise, held over every probe source: no string literal holds
    /// `//` or `/*`. A literal that did would be cut by the scan, and the cut shows as a
    /// line with an odd number of unescaped quotes, so that is what is counted.
    #[test]
    fn no_probe_source_holds_a_comment_delimiter_in_a_string_literal() {
        let mut fed = 0_usize;
        for probe in CORPUS {
            if probe.source.is_empty() {
                continue;
            }
            fed += 1;
            for (number, line) in super::without_c_comments(probe.source).lines().enumerate() {
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

    /// The comment scan above drops prose and keeps code, and a probe whose only mention
    /// of the array is in a comment reads as unreferenced.
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

    /// Every probe's source file carries its language's suffix, so the driver chooses the
    /// language the probe declares, as a macro dump's does ([`Lang::source_suffix`]).
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

    /// The bearing table says per check what it observes ([`Observes`]), and the two lists a
    /// defect's status is deaf to are these. Every request or marking bears a defect (an
    /// `observes` on a check that bears none would say nothing) and hardens: its word does
    /// not say which way a flag points, so a weakening request or marking is outside the
    /// vocabulary, and this holds it out. The rollup keys such a word as written whatever the
    /// polarity, as the reread's recount does (`report::rollup_key`).
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

    /// A defect class no check observes protection against reads `unknown` in every report,
    /// with its requests and markings tallied beside it: the forward edge, which no check
    /// measures the enforcement of. Pinned so that the first enforcement check moves this
    /// list. The "Defect status" paragraph under DESIGN.md's "Verdict vocabulary" names the
    /// same class and no test reads it, so it is edited beside this list.
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
        assert_eq!(none, ["jump-oriented-programming"]);
        // The class's own summary says so, beside the status in every report.
        for id in none {
            let summary = defect(id).expect("the class").summary;
            assert!(
                summary.contains("so this status is unknown in every report"),
                "{id}: the summary says why its status is unknown"
            );
        }
    }

    /// The corpus digest moves when a check's `observes` moves: what a check observes
    /// decides every status the rollup derives from it, so two corpora that class one
    /// check differently must not share a digest.
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

    /// `null-deref` is borne by one check, which keeps the null check the optimizer would
    /// delete, and the class's summary says so and says what is outside it: the summary is
    /// what a reader of `mitigated` sees beside the status.
    #[test]
    fn the_null_deref_class_says_what_its_one_check_covers() {
        let bearers: Vec<&str> = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.defects.contains(&"null-deref"))
            .map(|c| c.id)
            .collect();
        assert_eq!(bearers, ["no-delete-null-pointer-checks"]);
        let summary = defect("null-deref").expect("the class").summary;
        assert!(summary.contains("the one check bearing on this class keeps from happening"));
        assert!(
            summary
                .contains("a dereference the source itself performs is outside every check here")
        );
    }

    /// `Channel::as_str` spells every channel as the report's JSON does, so prose that
    /// names a channel names the one the reader finds in `observations[].channel`.
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

    /// Every compiler-diag check is either in the structured decoder's needle table or
    /// exempt from it with a reason, never both, and nothing else is in either.
    ///
    /// A compiler-diag check added without an entry would be silently absent from every
    /// `--structured-diagnostics` comparison, with `checks_eligible` shrinking to match, so
    /// the gate's count would read as complete over a set that lost a member.
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

    /// The two fill detectors declare the header and nothing else, so an arm's artifact is
    /// stored for a replay and a cut header withholds them rather than reading as 64-bit.
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
        let calls = crate::predicate::elf_static::SSP_FUNCTIONS
            .iter()
            .zip(crate::predicate::elf_static::SSP_CALLEES)
            .chain(std::iter::once((
                &crate::predicate::elf_static::SSP_DISCRIMINATOR,
                crate::predicate::elf_static::SSP_DISCRIMINATOR_CALLEE,
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

    /// Every check's tables are derived from its decoder, and only the checks that read an
    /// artifact have any.
    ///
    /// The list is what the truncation gate intersects. A predicate's is its `tables`, the
    /// one list its `@truncated` preamble and `report::truncation_limitation` both read, so
    /// the two cannot name different tables. An
    /// elf-static predicate with no table is one no cut can withhold, and a macro predicate
    /// reads none. Off those channels, `section-names` is declared by exactly the runtime
    /// detectors that read the self-report through `Evidence::fortify_impl`, `header` by
    /// exactly the two auto-var-init detectors, whose clang pattern byte depends on the
    /// ELF class, and nothing else is declared. Each table is one with a
    /// recording site in `elf.rs` or one of the two `Elf::parse` refuses outright, so no
    /// list names a table nothing records.
    /// `tests/elf_truncations.rs` holds the lists to what the readings move on.
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
                    // `detect_strict_flex_arrays_enforced` credits a trap through
                    // `fortify_impl` as `detect_fortify_runtime` does.
                    if matches!(
                        detect.name,
                        "detect_fortify_runtime" | "detect_strict_flex_arrays_enforced"
                    ) {
                        self_report_readers += 1;
                        assert_eq!(
                            reads,
                            &[ElfTable::SectionNames],
                            "{}: a detector reading the self-report through `fortify_impl` \
                             reads the section names that reach it, and nothing else",
                            check.id
                        );
                    } else if !CLASS_READERS.contains(&detect.name) {
                        assert!(
                            reads.is_empty(),
                            "{}: a runtime detector off the self-report reads no ELF table, \
                             got {reads:?}",
                            check.id
                        );
                    }
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
        // The partition itself: the two lists cover the enum without overlap. The
        // disagreeing PT_GNU_STACK pair is `gnu-stack`'s (`elf::Elf::gnu_stack`), so the
        // program-header table is on one list only.
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

    /// A shared-object build gets `-fPIC` by default and **not** when the caller stated a
    /// position-independence choice of their own.
    ///
    /// The hazard this exists for. `measure` appends `extra_flags` after the profile, so an
    /// unconditional `["-shared", "-fPIC"]` would compile `--profile explicit --flags
    /// "-fno-pic"` as `-fno-pic -shared -fPIC`, with `profile.cflags` recording `-fno-pic`.
    /// The report would name a flag list it had not measured, the exact failure chard exists
    /// to detect, in chard.
    ///
    /// It also has to hold for `textrel-absent` to be measurable at all: that check's
    /// positive control is a deliberately non-PIC library, and an appended `-fPIC` would
    /// defeat it and leave the control undiscriminating, which reads as `probe-invalid` on
    /// a toolchain that is working correctly.
    #[test]
    fn a_stated_pic_choice_is_not_overridden_by_the_shared_object_default() {
        let none: Vec<String> = Vec::new();
        assert_eq!(
            LinkMode::SharedObject.extra_flags(&none),
            vec!["-shared", "-fPIC"],
            "a bare profile still needs -fPIC or the library will not link"
        );

        // Every spelling, because a partial match here is a silent override.
        // Every spelling `conflicts_with` knows plus every spelling this knows: the two
        // lists must agree, and a test that enumerated only one of them would let them
        // disagree.
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
        assert!(LinkMode::Executable.extra_flags(&none).is_empty());
    }

    /// Every boundary keys onto a flag the corpus actually measures, and the protections
    /// known to have a runtime dependency all have one.
    ///
    /// Absence carries meaning in this field (it says nothing outside the artifact is
    /// required), so an entry that matches no check would be a silent no-op, and a missing
    /// entry would read as "self-contained" for a protection that is not. Both directions are
    /// checked, because only one of them is visible from the output.
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

        // The other direction: these three protections depend on something outside the file,
        // and an observation of one that carried no boundary would read as self-contained.
        for needs in ["-fPIE", "-fcf-protection", "-Wl,-z,noexecstack"] {
            assert!(
                boundary_for(needs).is_some(),
                "{needs} takes effect only with kernel, CPU or libc cooperation, and an \
                 observation with no boundary asserts that nothing outside the artifact matters"
            );
        }

        // The lookup is a prefix match and takes the first key that matches, so a check
        // whose flag extends another's key inherits that key's boundary unless a longer key
        // sits ahead of it. The landing-pad reading is about code, not the note.
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
        let mut seen = std::collections::BTreeSet::new();
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

    /// Each channel answers for itself, in both directions.
    ///
    /// The two predicates are `matches!` over one variant, so a test that only ever asks
    /// about the variant it expects to be true leaves the other three unasserted, and a
    /// body replaced wholesale by `true`, or with its `!` removed, still passes. The
    /// enumeration is exhaustive on purpose: a fifth channel added later has to be given
    /// an answer here rather than inheriting one.
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

    /// Every probe in the corpus is built, and the disjunction that makes that true is
    /// load-bearing rather than incidental.
    ///
    /// The macro channel reads its state from a compiled translation unit, so a
    /// macro-only probe that was not built would silently fall back to the preprocessor
    /// and measure a different job, which is why `needs_build` is true whenever a source
    /// exists at all, not only when a check demands an artifact. `toolchain-macros` is the
    /// one probe whose checks are all macro-channel, so it is the only place in the corpus
    /// where the first half of that disjunction is the half doing the work.
    ///
    /// The sourceless probe is not a corpus shape and is not meant to become one. It is
    /// here because the corpus cannot distinguish `needs_build` from a function that
    /// returns `true`: every probe has a source, so every probe is built, and the test
    /// above this one asserts nothing about the false case. This one supplies it.
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

    /// Only an executable with a runtime check is executed.
    ///
    /// Both halves matter and the corpus exercises only one of them. Thirty-three probes
    /// are executables, so `link_mode == Executable` is nearly always true and a test over
    /// the corpus alone cannot tell the conjunction from its first operand; and the one
    /// shared object, `shared-object-defaults`, has no runtime check, so the documented
    /// claim ("a shared object is never executed, whatever its checks declare") is
    /// exactly the case the corpus does not contain. The synthetic probe supplies it.
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

    /// A check with no positive control can never be validated, so its verdict
    /// could only ever be `probe-invalid`. An empty *negative* control is fine,
    /// for a flag that is off by default, the bare build is itself the negative.
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

    /// Each [`ARCH_CONTROLS`] row names a corpus check, an architecture that check's gate
    /// names, a non-empty list that differs from the default, and no pair twice.
    ///
    /// A row for an architecture the gate does not admit would never be selected, since
    /// the check is `arch-gated` there before any arm is built, and a row on a portable
    /// check could name a spelling no target normalizes to (`i386` for `x86`) and be
    /// silently unreachable. So the gate names the architecture explicitly.
    #[test]
    fn every_arch_control_names_an_architecture_its_gate_admits() {
        let mut seen = std::collections::BTreeSet::new();
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

    /// An architecture with no row builds the check's default positive control, for every
    /// check and every architecture a gate names or a target normalizes to.
    #[test]
    fn an_architecture_without_a_row_uses_the_default_control() {
        let mut arches: std::collections::BTreeSet<&str> = [
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
    ///
    /// The canary fires only while nothing in the translation unit uses, excuses, hides or
    /// silences it, so containing its name is not enough: a `(void)` cast, an assignment or
    /// any other read silences `-Wunused-variable` while the text stays, as two probes'
    /// casts once did. So the name must appear in code exactly once, as
    /// [`CANARY_DECLARATION`], inside a function body (an unused variable at file scope
    /// draws no warning) and outside every preprocessor conditional (which can compile it
    /// out); no `unused` or `maybe_unused` attribute may appear; no diagnostic pragma other
    /// than the pin and no `_Pragma` at all, since a pop, an `ignored "-Wall"` or a clang
    /// `-Weverything` silences the canary as surely as naming its warning does; and the
    /// pin, unless `pragma_exempt`, precedes the declaration outside every conditional.
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

    /// Every compiler-diag probe carries a canary that can fire, or, where a detector reads
    /// the canary, a suppressed stderr would read as the flag being off on that probe alone.
    /// Containing the name was once all this held, and two probes cast the canary away and
    /// passed. This reads the source on every host; `tests/probe_sources.rs` compiles each
    /// probe and reads the warning on the host's compiler.
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

    /// A probe without the pin is read against its build's flags when it is silent, and a
    /// pinned one is not: fed one build that succeeded silently with no flag that enables
    /// `-Wunused-variable`, every compiler-diag check of a [`CANARY_WITHOUT_PRAGMA`] probe says
    /// the canary's warning was never asked for, and every other one says nothing of the
    /// kind. So the exemption list and `decode::diag::Canary` cannot drift apart: a probe
    /// that drops its pragma without its detector passing `Canary::AskedByFlags` would
    /// publish "suppressed or redirected" for a build that never asked for the warning.
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
                let says = d.observed.contains("never asked for the canary's warning");
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

    /// The canary test refuses each shape that keeps the name and silences the warning,
    /// and accepts the one that works, so it cannot pass on the text alone again.
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

    /// A macro dump carrying `__SSP_EXPLICIT__` gives `ssp-level` its level, `explicit`,
    /// which grades `partial` below the ask, rather than `off`.
    ///
    /// The dump is gcc 16.1.1's `-dM -E` under `-fstack-protector-explicit` on Fedora 44
    /// x86_64 (2026-10-05), trimmed to its stack-protector line and a neighbour, and the
    /// self-report is the same build's line as `chard_selfreport.h` renders it. With no
    /// clause reading the macro, both readings are `absent`, and the cell publishes `off` for
    /// a protector enabled for every function that opts in.
    #[test]
    fn a_dump_carrying_ssp_explicit_reads_its_level_rather_than_off() {
        let dump = crate::compile::parse_macros(
            "#define __GNUC__ 16\n\
             #define __SSP_EXPLICIT__ 4\n",
        );
        let report = crate::decode::common::parse_self_report(
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

    /// A level was requested and no C library said what it settled on. That is a gap in
    /// evidence, not proof of absence, and must not be reported `off`.
    ///
    /// The case is narrow, deliberately. `_FORTIFY_SOURCE=3` with no `__OPTIMIZE__` is not
    /// it, though a missing `__USE_FORTIFY_LEVEL` might seem to tell us nothing.
    /// `__OPTIMIZE__` is a *compiler* builtin rather than a libc macro: it is in the map
    /// whenever optimization is on, whether or not any libc header was ever reached. Its
    /// absence therefore does prove that no fortify implementation is running, since
    /// glibc and fortify-headers both gate on it. So that shape is `absent`, and what
    /// remains indeterminate is the case where fortify really could be running and
    /// nothing identified itself; a libc chard does not know.
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

    /// A requested fortify level with no optimization is inert: glibc sets
    /// `__USE_FORTIFY_LEVEL` to 0 and instantiates no checks. Verified on gcc
    /// 16.1.1 / glibc 2.43, where `-D_FORTIFY_SOURCE=3 -O0` yields
    /// `_FORTIFY_SOURCE 3` alongside `__USE_FORTIFY_LEVEL 0`. Publishing `on`
    /// there would claim hardening that does not exist.
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

    /// A `_FORTIFY_SOURCE` at or below zero is no request, which is how glibc reads it.
    ///
    /// `<features.h>` tests `_FORTIFY_SOURCE > 0`; without the guard `-D_FORTIFY_SOURCE=-1`
    /// reads `present` at level `-1`, a word the numeric scale would withhold on, and the
    /// guard reads it as glibc does instead. The pie and pic macro detectors
    /// carry the same guard.
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

    /// A grade's scale kind is part of the corpus hash: the same words read as named rather
    /// than ordered are another corpus.
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

    /// The words a level declaration and a scale publish themselves by.
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

    /// Repointing a code-decoded check at another detector moves the corpus hash with the
    /// decoder fingerprint held still: the detector's name is bound per check.
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

    /// The decoder fingerprint moves on a clause edit and on an edit to a line of code, and
    /// stays where it was on an edit to comments, blank lines or unit tests alone; the
    /// corpus hash moves with it.
    ///
    /// Fixture strings stand in for the source files and a copy of a real predicate for
    /// the corpus's, so each edit is one change and nothing else.
    #[test]
    fn the_decoder_fingerprint_moves_on_code_and_clauses_and_not_on_comments() {
        let ssp = macro_channel::ssp_level();
        let source = "fn level() -> u8 {\n    // the reason\n    1\n}\n";
        let fingerprint = |p: &Predicate, text: &str| {
            decoders_sha256_of(
                predicate::LANGUAGE,
                &[("ssp-level", p)],
                &[("src/decode/x.rs", text)],
            )
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
            decoders_sha256_of(
                "chard-predicate/2",
                &[("ssp-level", ssp)],
                &[("src/decode/x.rs", source)]
            ),
            "the language version is part of what reads the predicates"
        );

        let base_corpus = corpus(&base);
        assert_eq!(base_corpus, corpus(&fingerprint(ssp, commented)));
        assert_ne!(base_corpus, corpus(&code_edit));
        assert_ne!(base_corpus, corpus(&clause_edit));
    }

    /// The corpus is the denominator of every coverage claim chard publishes, so its
    /// size is committed rather than derived.
    ///
    /// `all_checks_attempted` compares the observations produced against
    /// `total_checks()`, and both come from `CORPUS`. Delete four probes and the
    /// numerator and denominator move together: the suite stays green *and* the report
    /// says `all_checks_attempted: true, 39/39`. A run that measured nine checks fewer
    /// than the last one describes itself as complete, which is the clean-looking zero
    /// wearing a percentage.
    ///
    /// The previous floor here was `>= 15` against a 43-check corpus, so a 65% shrink
    /// passed. An exact number cannot express a range and so cannot be satisfied by a
    /// smaller corpus; changing it is a deliberate edit that shows up in review next to
    /// the probe being added or removed, and next to any count a document states that has
    /// to move with it.
    /// Every check's `flag` is distinct, an invariant rather than an accident.
    ///
    /// The consumers fold over observations keyed on `flag`, where a duplicate is silently
    /// last-writer-wins rather than loudly `indeterminate`. So the property has to be
    /// asserted somewhere. It is three lines here instead of runtime machinery handling one
    /// instance of it, and it names the offender rather than resolving it.
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

    /// Every graded check asks for a word on its own scale, every scale is well formed, and
    /// no word belongs to two checks' vocabularies except through one shared constant.
    ///
    /// Each level word is a `&'static str` compared by string, so a typo in a scale
    /// (`stong`) would put the ask off its own scale and `Grade::meets` would answer `None`
    /// for every reading: the check would withhold every verdict and nothing else would
    /// notice. The third clause is what keeps the vocabularies per check rather than per
    /// coincidence: two checks with equal `Levels` are declaring one vocabulary on purpose,
    /// and a word two different `Levels` spell alike is listed below as an accepted
    /// collision, with the count of vocabularies that may carry it.
    #[test]
    fn every_graded_check_recommends_a_word_on_its_own_scale() {
        // The spellings two different vocabularies share, with how many may carry each:
        // RELRO's `full` and the CFI components' `full`; the `-Werror=` checks' `error`
        // and the severity the `diag_presence` checks publish as information; the fill
        // `auto-var-init-active` grades against `zero` and `auto-var-init-pattern`
        // publishes as its one word. Each pair is two distinct `Levels` with a distinct
        // disposition, and never compared.
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

    /// A probe's own pins add to the base list and never restate one of its names.
    ///
    /// `run::probe_environment` merges the two lists into one map, so a pin naming
    /// `LC_ALL` would silently replace the wording every runtime detector matches on for one
    /// probe. Refused here, so the merge never has to choose. Every pin is also a non-empty
    /// name and value, and no probe pins one name twice.
    #[test]
    fn no_probe_pin_restates_the_base_environment() {
        let base: std::collections::BTreeSet<&str> = crate::run::PROBE_ENVIRONMENT
            .iter()
            .map(|(n, _)| *n)
            .collect();
        let mut pinned = 0;
        for probe in CORPUS {
            let mut seen = std::collections::BTreeSet::new();
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

    /// A quoted path's extension, as written.
    fn extension_of(quote: &str) -> Option<&str> {
        std::path::Path::new(quote)
            .extension()
            .and_then(|e| e.to_str())
    }

    /// Every Rust file at `path`, or under it where it is a directory.
    fn rust_files(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).expect("a source directory") {
                rust_files(&entry.expect("a directory entry").path(), out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path.to_path_buf());
        }
    }
    /// The walkthrough's quote of a module path, as files: `report::ASSUMPTIONS` names
    /// `src/report.rs` and `src/report/`, and
    /// `decode::runtime` names `src/decode/runtime.rs` and its `runtime_tests.rs`.
    fn module_files(root: &std::path::Path, quote: &str) -> Vec<std::path::PathBuf> {
        let path: Vec<&str> = quote
            .trim_start_matches("crate::")
            .split("::")
            .take_while(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
            .collect();
        let mut files = Vec::new();
        if let Some(last) = path.last() {
            let base = root.join("src").join(path.join("/"));
            let file = base.with_extension("rs");
            if file.is_file() {
                files.push(file);
                let tests = base.with_file_name(format!("{last}_tests.rs"));
                if tests.is_file() {
                    files.push(tests);
                }
                rust_files(&base, &mut files);
            }
        }
        files
    }

    /// The walkthrough at the head of this module is a map, so what it names has to be there.
    /// Every file or directory it quotes exists. A constant it quotes as `module::NAME` is
    /// declared in that module's files, and any other constant or test it quotes in a file the
    /// walkthrough names, by path or by module, so a namesake elsewhere in the tree does not
    /// stand in for it. A `Type::member` it quotes is a field or variant in this file. Its
    /// backticks pair, so no quote is read as prose.
    #[test]
    fn the_walkthrough_names_files_lists_and_tests_that_exist() {
        use std::path::{Path, PathBuf};
        let read = |files: &[PathBuf]| -> String {
            files
                .iter()
                .map(|f| std::fs::read_to_string(f).expect("a named source file"))
                .collect()
        };
        let declares = |code: &str, name: &str| {
            code.contains(&format!("const {name}:")) || code.contains(&format!("static {name}:"))
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let this = include_str!("probe.rs");
        let doc = this
            .lines()
            .skip_while(|l| *l != "//! ## Adding a check")
            .take_while(|l| l.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(doc.len() > 1000, "the walkthrough is not being read");
        assert_eq!(
            doc.matches('`').count() % 2,
            0,
            "the walkthrough's backticks pair"
        );
        let quotes: Vec<&str> = doc.split('`').skip(1).step_by(2).collect();
        let pathlike = |q: &str| {
            q.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
        };
        let mut named = vec![root.join("src/probe.rs")];
        for q in &quotes {
            if pathlike(q) && extension_of(q) == Some("rs") {
                named.push(root.join(q));
            }
            named.extend(module_files(root, q));
        }
        let named = read(&named);
        let (mut paths, mut constants, mut tests, mut members) = (0, 0, 0, 0);
        for quoted in &quotes {
            let name = quoted.rsplit("::").next().unwrap_or(quoted);
            let upper =
                |n: &str| n.len() > 2 && n.chars().all(|c| c.is_ascii_uppercase() || c == '_');
            if pathlike(quoted)
                && (quoted.ends_with('/')
                    || extension_of(quoted)
                        .is_some_and(|e| ["rs", "json", "md", "sh"].contains(&e)))
            {
                assert!(
                    root.join(quoted).exists(),
                    "the walkthrough quotes {quoted}"
                );
                paths += 1;
            } else if upper(name) {
                let module = module_files(root, quoted);
                let code = if module.is_empty() {
                    named.clone()
                } else {
                    read(&module)
                };
                assert!(
                    declares(&code, name),
                    "the walkthrough quotes {quoted}, which {} does not declare",
                    if module.is_empty() {
                        "no file it names"
                    } else {
                        "that module"
                    }
                );
                constants += 1;
            } else if name.matches('_').count() >= 3
                && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            {
                assert!(
                    named.contains(&format!("fn {name}(")),
                    "the walkthrough quotes {quoted}, which is no function in a file it names"
                );
                tests += 1;
            } else if let Some((ty, member)) = quoted.split_once("::")
                && ty.starts_with(|c: char| c.is_ascii_uppercase())
                && !member.contains("::")
            {
                assert!(
                    [
                        format!("pub {member}:"),
                        format!("    {member}("),
                        format!("    {member},")
                    ]
                    .iter()
                    .any(|form| this.contains(form.as_str())),
                    "the walkthrough quotes {quoted}, which is no field or variant here"
                );
                members += 1;
            }
        }
        assert!(
            paths >= 14 && constants >= 13 && tests >= 4 && members >= 8,
            "the walkthrough's quotes were not all read: {paths} paths, {constants} constants, \
             {tests} tests, {members} members"
        );
    }

    #[test]
    fn the_corpus_is_the_size_it_is_published_as() {
        const PROBES: usize = 51;
        const CHECKS: usize = 72;

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

    /// Every check id is distinct, because coverage counts them and a report keys on them.
    ///
    /// Two probes sharing an id would make `total_checks()` and the number of *distinct*
    /// things measured disagree, and the coverage block reports the former.
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

    /// The libc-side fortify level has to be readable on both implementations, and from
    /// whichever map `gather` handed over.
    ///
    /// The hazard is specific. `gather` replaces the `-dM -E` dump with the compiled
    /// artifact's `.chard.report` wherever one exists, and that report condenses
    /// fortify-headers' include guard into `_FORTIFY_IMPL`. A detector reading only the
    /// raw guard therefore finds nothing on a real Alpine measurement: `probe-invalid`
    /// on a system whose own artifact says `fortify-headers` in the next field over.
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
        // Level 1 whatever was requested: it has no subobject bounds at any level, and
        // rung 2 is defined by that distinction.
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

        // FreeBSD via the compiled artifact: the level its <ssp/ssp.h> settled on,
        // clamped at 2, beside optimization; absent where the wrappers did not instantiate
        // (settled 0); withheld where they instantiated without optimization, which clang
        // allows and under which they check nothing; and a FreeBSD whose headers reached the
        // request and defined no level is a release with no implementation, absent at any
        // optimization, since no implementation precedes the optimization clause.
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
    /// `__strcpy_chk` beside `__FreeBSD__` and no `__OPTIMIZE__`: with optimization it reads
    /// level 1 as everywhere, without the platform macro it reads level 1 as everywhere, and
    /// without the reference it reads absent. Held here because the replay rows record no
    /// macros for an elf-static reading, so the corpus cannot reach the clause.
    #[test]
    fn the_printf_flag_withholds_freebsds_unoptimized_wrapper_only() {
        use crate::elf::SymbolFact;
        let check = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == "fortify-printf-flag")
            .expect("the check");
        let read = |pairs: &[(&str, &str)], referenced: bool| {
            let mut elf = tests::elf_with_report("");
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
    /// because the gates fire only in the guests; the lists are the claim this tree makes.
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
    /// This is the fragile arm under fortify-headers. Its marker is absent when it is
    /// inactive (there is no `__USE_FORTIFY_LEVEL=0` to read), so a detector treating
    /// "no marker" as `indeterminate` withholds the negative arm on every musl system,
    /// and `fortify-effective` comes back `probe-invalid` on Alpine with a positive arm
    /// that reads `present` perfectly well.
    ///
    /// Neither replacement condition asks what the C library is. Both implementations
    /// gate on `_FORTIFY_SOURCE > 0` and on optimization, so with either unmet nothing
    /// instantiates whoever ships the headers.
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
        // Requested but inert for want of optimization. True of the implementations that
        // reach this branch; an implementation that does not gate on optimization has to
        // identify itself through its own level macro before getting here.
        assert_eq!(
            outcome(&[("_FORTIFY_SOURCE", "3")]),
            Outcome::Absent,
            "glibc and fortify-headers both gate on optimization"
        );
        assert_eq!(outcome(&[("_FORTIFY_SOURCE", "0")]), Outcome::Absent);
    }

    /// Real ELF facts from a Linux `bare` run (then `evidence.elf`) with only `self_report`
    /// varied.
    ///
    /// Deserialized rather than constructed so thirty-odd fields irrelevant to these
    /// tests stay out of them, and so a new `ElfFacts` field fails here loudly instead
    /// of defaulting to something these tests would silently assert against.
    /// `truncations` is the exception: it carries `#[serde(default)]`, so a fixture that
    /// omits it reads as a whole artifact, which is the reading these tests want.
    /// `symbol_tables` defaults the same way and no detector reads it.
    pub(crate) fn elf_with_report(self_report: &str) -> crate::elf::ElfFacts {
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
    /// The disjunction is the rule: either spelling is enough on its own. As a
    /// conjunction only a flag that was both `-Wl,`-prefixed *and* one of the three
    /// link-mode words would be dropped (which is no flag at all), so a profile's
    /// `-Wl,-z,now` would reach a `-c` invocation that has no linker to give it to.
    ///
    /// `-fPIE` is the load-bearing negative. It is code generation, it is what the
    /// executable arm of the same probe compiles with, and dropping it would make the
    /// object a different build from the one whose link is being compared against,
    /// which is the entire basis for reading the two together.
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
    /// is dropped whole, `-MF -L/x` is a dependency file named `-L/x` and is kept whole,
    /// `--machine 32` is the target `-m32` and is kept; and gcc's long spellings are read as
    /// the short words, `--shared` as `-shared`, `--pie` as `-pie`, `--for-l -znow` as
    /// `-Xlinker -znow`, `--li /x` as `-L /x`, each dropped. Counted against the rows.
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
    /// own `-fPIC`, through the classifier: the long spellings, a value another word takes,
    /// a word handed to the linker, and the word clang applies for one architecture, read
    /// through the partition and `extra_flags` as the build path reads them.
    #[test]
    fn a_shared_object_build_reads_the_position_choice_through_the_classifier() {
        let strings = |flags: &[&str]| flags.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        // The shared-object kinds read the long spellings too: `--pie` contradicts a shared
        // link, `--shared` does not, and `--no-pie` is a position choice to the reader of
        // them (the partition drops it before a shared-object build, as it drops `-fno-pie`,
        // so the build path never asks).
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
        // Through the build path: a shared-object build drops `--no-pie` as it drops
        // `-fno-pie`, and keeps `--no-pic` as the choice `-fno-pic` is, adding no `-fPIC`.
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
    ///
    /// The per-token rule turned `-z now` into `now` and `-Xlinker -z -Xlinker now` into
    /// `-Xlinker -Xlinker now`; both read `build-failed` under gcc 16.1.1 and clang 22.1.8
    /// where the argv before the rule compiled.
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

        // But a linker pass-through stays paired in every mode. `-Xlinker -pie` is dropped
        // whole for a shared object, where dropping only `-pie` handed chard's `-shared` to
        // the `-Xlinker`; any other argument is kept with its flag.
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

        // The one-token spellings go the same way: `-Wl,-pie` and `--for-linker=-pie` are
        // dropped for a shared object, where they handed the linker `-pie` beside `-shared`,
        // and kept for an executable. A `-Wl,` list with other words in it is kept.
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

    /// The two arms this detector has besides "the symbol is there".
    ///
    /// Both survived mutation: deleting the `libc++` arm, and forcing the `-D_GLIBCXX_DEBUG`
    /// guard to false. They are the arms that stop a wrong `off` (one where the observable
    /// belongs to the other standard library, one where the library substitutes a different
    /// mechanism for the same request), and neither had a test.
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

        // libc++ routes precondition failures through `__libcpp_verbose_abort` and has no
        // libstdc++ assertion symbol at all, so its absence says nothing. `off` here would
        // be a claim about a mechanism this library does not have.
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
    ///
    /// The artifact channel reported the mechanism absent on every libstdc++ up to 11
    /// while the runtime sibling on the same build reported it firing. Only the newer
    /// name was watched, so the older one was never even recorded, which is why no
    /// fixture in the corpus can carry this case and it has to be constructed here.
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
    /// `__ARM_FEATURE_PAC_DEFAULT` selects the signing key, so 2 is B-key PAC and not a
    /// second protection. Reading it as a boolean would report a `b-key` build as having
    /// no return-address signing at all; the false `off` this test exists to prevent.
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

    /// libc++'s mode constants are not in strength order, and its own header says so:
    ///
    /// ```text
    /// #  define _LIBCPP_HARDENING_MODE_NONE      (1 << 1)
    /// #  define _LIBCPP_HARDENING_MODE_FAST      (1 << 2)
    /// #  define _LIBCPP_HARDENING_MODE_EXTENSIVE (1 << 4) // Deliberately not ordered.
    /// #  define _LIBCPP_HARDENING_MODE_DEBUG     (1 << 3)
    /// ```
    ///
    /// `debug` is the *stronger* mode and carries the *smaller* value. Reading the shifts
    /// as ordered swapped the two names from the first release until this test existed:
    /// a build asking for `debug` was published as `extensive` and one asking for
    /// `extensive` was published as `debug`. The verdict survived either way, because
    /// both exceed the guide's recommended `fast`, so only the level name and its rank
    /// were wrong, which is exactly what a verdict-level assertion cannot see.
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
    /// was in.
    ///
    /// `observed` is what a reader audits a verdict against, so the distinction between
    /// "defined to nothing", "defined to a value" and "not defined at all" has to survive
    /// into it: a sentence that rendered the first and the third alike would make an
    /// explicit `-DFOO` indistinguishable from an absent macro, which is the difference a
    /// reader is checking. The sentence is `predicate::render_observed`'s, and the module
    /// documentation of `predicate` states its form.
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
    /// varied instead of the self-report. Kept as one JSON literal for the reason that
    /// one gives: a new `ElfFacts` field has to fail here loudly, with `truncations` the
    /// one field that defaults to empty by design.
    fn elf_with_search_paths(rpath: &[&str], runpath: &[&str]) -> crate::elf::ElfFacts {
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
    /// the value `0`. The boundary is the whole content of these two detectors: a test
    /// that only ever supplies `2` or nothing at all cannot tell `> 0` from `>= 0`, and
    /// `>= 0` reads that explicit refusal as position independence.
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
    /// Every value gets a case because a deleted arm falls through to `absent`, which is
    /// the reading that looks like a finding.
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
    /// it for `1` (or for `>= 0`, which is what the boundary mutates to), reads a
    /// `-mbranch-protection=pac-ret+b-key` build as unsigned. All four corners are here
    /// because each names a different posture and three of them are reachable on real
    /// toolchains.
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

    /// Apple's `_USE_FORTIFY_LEVEL` answers on the same rule as glibc's, zero included.
    ///
    /// One leading underscore, from `<secure/_common.h>`, and it is the branch reached on
    /// a platform whose artifacts chard cannot read. `== 0` is what separates a C library
    /// that settled on no fortification from one that settled on a level; `!= 0` inverts
    /// both answers, and a test supplying only a non-zero level cannot see it.
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
    /// `_CXX_STDLIB` is written into the self-report, so it exists only where the
    /// artifact can be read. On a platform with no reader the preprocessor dump still
    /// carries `_LIBCPP_VERSION` or `__GLIBCXX__`, and the fallback is what keeps this
    /// check answering a level rather than withholding one beside a sibling that
    /// answered. Both arms are unreachable in a Linux report by construction, which is
    /// why neither is covered by the replay corpus.
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
    /// finding.
    ///
    /// The absence is the whole verdict here, so the conjunction that decides it has to
    /// be a conjunction: `||` in its place reports a binary carrying one of the two as
    /// clean, which is a false `absent` on a defect check. Each of the four combinations
    /// is supplied because three of them are reachable and only one of them is common.
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
    /// `__PIE__` is 1 under `-fpie` and 2 under `-fPIE`; both are fully position
    /// independent. Graded against a recommendation of `2`, the smaller value published
    /// `partial` for a completely PIE build while the artifact channel said `on`, and the
    /// two could not disagree because their rollup keys differ. Both halves are pinned:
    /// the check carries no recommendation, and the verdict `report::decide` reaches for
    /// `__PIE__=1` is `on`. The old recommendation is passed explicitly alongside, so the
    /// test states what changed rather than only what is.
    #[test]
    fn a_small_code_model_pie_is_on_and_its_value_is_information_only() {
        use crate::report::{ArmInput, Verdict, decide};
        /// An evaluated arm with no flags: what is under test here is the detector.
        fn arm(d: &Detection) -> ArmInput<'_> {
            ArmInput {
                detection: Some(d),
                flags: Vec::new(),
            }
        }

        // The grade the check carried, spelled on the scale it would need today: `1 < 2`
        // with `2` asked for.
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
