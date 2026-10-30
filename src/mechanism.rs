// SPDX-License-Identifier: BSD-3-Clause

//! The mechanism table: for each question an architecture-bound check answers, which
//! mechanism answers it on each architecture an owned host has witnessed, and which checks
//! read that mechanism there. Every architecture decision a gate takes derives from it.
//!
//! Why a table. A hand-written architecture list per check says only where the check's
//! construction was written for, and off such a list the gating rule `arch-gated` would
//! publish `unsupported` with the statement "the target architecture has no such mechanism".
//! Checked check by check, that statement is false for several of the sixteen gated
//! checks: `textrel-absent` on aarch64, where the linker writes
//! `DT_TEXTREL` as it does on x86_64 and the check has no construction for it;
//! `shadow-stack-enforced` on aarch64, where the kernel enforces a Guarded Control Stack and
//! no check reads it; `ubsan-trap-mode` on i386, where the trap is the same `ud2`. So the
//! table is keyed on the question, a check is one mechanism's answer to it, a mechanism
//! chard has no check for on the target publishes `indeterminate` under a rule id, an absence
//! is `unsupported` only where the target answers the question with another mechanism a
//! check reads, and rows come from owned hosts only.
//!
//! The decision for a check on an architecture is [`decide`]:
//! - the row for the check's question on that architecture names the check among the
//!   mechanism's readers: [`Decision::Measured`], and the check is built and read;
//! - the architecture has the check's own mechanism and no check reads it there (the
//!   construction is written for other architectures), or answers the question with another
//!   mechanism no check reads: [`Decision::Unread`], `no-check-on-target`, `indeterminate`;
//! - the architecture answers the question only with mechanisms other checks read: the
//!   check's mechanism is absent there, [`Decision::Absent`], `arch-gated`, `unsupported`,
//!   which is the one case where "the target architecture has no such mechanism" is true;
//! - the table has no row for the question on that architecture: [`Decision::Outside`],
//!   `arch-outside-table`, `indeterminate`. A target outside [`ARCHS`] (riscv64, armv7,
//!   `outside-arch-macros`) reaches this; it carries no claim about the target.
//!
//! Each decision has an [`Outcome`], which is what the target witness compares: a gate
//! decided under the architecture it read, and `report::withhold_on_contradicted_target`
//! withholds the check where a machine the run's artifacts or macro dumps witnessed gives
//! another outcome. Every outcome but `Outside` is a claim resting on the architecture,
//! and `Outside` equals none of them, so under a read architecture the table has a row
//! for, a witnessed machine it has none for withholds every gated check, whichever way
//! its gate went. Under a read architecture outside the table every gated check is
//! `Outside` already, and withheld under `arch-outside-table`, so such a witness moves
//! nothing there.
//!
//! `Gate.arch` is a literal in `src/probe.rs`, and [`tests::every_gate_list_is_the_tables`]
//! holds every list equal to [`archs_of`], the architectures whose rows name the check as a
//! reader; `report::tests::the_arch_gated_checks_are_the_ones_we_named` holds the literals to
//! the sixteen lists it names. Nothing on the verdict path reads the literal: the gate,
//! the target witness's withholding and the consistency rule that re-derives it read
//! [`decide`]. The field goes once the Check literals are next rewritten.
//!
//! Each row carries a `witness`: the checks that read the mechanism there, or the measurement
//! or source the row rests on and the date it was taken. A row never overrides a measurement:
//! a check that reads on an architecture is measured there whatever the table says beside it,
//! and the rows with no reader decide only what is published where nothing was measured.

/// The architectures the table has rows for, in the order `Gate.arch` lists them: the ones
/// an owned host has witnessed (x86_64 and aarch64 natively, x86 through `-m32` on the x86_64
/// host). A target outside this list has no row and decides [`Decision::Outside`]. Each row
/// stands for one width and byte order, the host's it was measured on (ELF64 little-endian
/// for x86_64 and aarch64, ELF32 little-endian for x86; `toolchain::Abi::of_arch`), so a
/// target of the family at another, an x32, aarch64 ILP32 or `aarch64_be` one, has no row
/// either: the target witness withholds it (`toolchain::TargetArch::abi`), since the gate
/// reads the architecture alone.
pub const ARCHS: &[&str] = &["x86_64", "x86", "aarch64"];

/// A question an architecture-bound check answers, in the words a reader of a gating reason
/// sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Question {
    pub id: &'static str,
    pub asks: &'static str,
}

/// Every question the table has rows for. Each has a row for every architecture in
/// [`ARCHS`], which [`tests::the_table_is_total_and_well_formed`] holds.
pub const QUESTIONS: &[Question] = &[
    Question {
        id: "cfi-marking",
        asks: "is control-flow integrity marked, in the compiler's macros, in the objects' and \
               the link's property notes, and in the landing pads the marking promises",
    },
    Question {
        id: "shadow-stack-enforcement",
        asks: "does the kernel enforce a hardware shadow stack for the running program",
    },
    Question {
        id: "text-relocations",
        asks: "did linking position-dependent code into a shared object leave text relocations",
    },
    Question {
        id: "linker-stack-default",
        asks: "what stack does the linker give an object that says nothing about its own",
    },
    Question {
        id: "stack-execution-enforcement",
        asks: "does the kernel refuse to execute code on the stack of a program whose \
               PT_GNU_STACK asks for that",
    },
    Question {
        id: "sanitizer-traps",
        asks: "are the undefined-behaviour sanitizer's handlers traps",
    },
    Question {
        id: "printf-fortify-level",
        asks: "what fortify level does the compiled call to __printf_chk carry",
    },
    Question {
        id: "call-used-register-clearing",
        asks: "are call-used registers cleared before a return",
    },
    Question {
        id: "object-relocations",
        asks: "are an object's references to its own data position-independent",
    },
];

/// One row: on `arch`, `question` is answered by `mechanism`, which the checks in `read_by`
/// read there. A row with no reader says the mechanism exists on the architecture and chard
/// does not read it; `witness` says what that rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub question: &'static str,
    pub arch: &'static str,
    /// The mechanism as a reader would name it. One mechanism is one string, so a check's
    /// mechanism is found on another architecture's row by equality.
    pub mechanism: &'static str,
    /// The checks whose construction reads the mechanism on this architecture: the checks
    /// whose `Gate.arch` names it.
    pub read_by: &'static [&'static str],
    /// The checks that read it, or the measurement or source and the date the row holds as
    /// of. Never empty.
    pub witness: &'static str,
}

const CET: &str = "x86 CET: IBT landing pads and the shadow stack, marked in __CET__ and the \
                   x86 property note";
const BTI_PAC: &str = "aarch64 BTI and PAC, marked in __ARM_FEATURE_BTI_DEFAULT and \
                       __ARM_FEATURE_PAC_DEFAULT and in the aarch64 property note";
const GCS_MARKING: &str = "aarch64 GCS marking, in __ARM_FEATURE_GCS_DEFAULT and the aarch64 \
                           property note's GCS bit";
const SHADOW_STACK: &str = "the x86 CET shadow stack, which a kernel may enable for a program \
                            (read through ARCH_SHSTK_STATUS and SEGV_CPERR)";
const GCS_ENFORCEMENT: &str = "the aarch64 Guarded Control Stack the kernel enforces";
const TEXTREL: &str = "DT_TEXTREL on a shared object the linker wrote text relocations into";
const STACK_DEFAULT: &str = "the linker's choice of stack permission for an object \
                             carrying no .note.GNU-stack";
const STACK_ENFORCEMENT: &str = "the kernel's stack mapping under PT_GNU_STACK";
const TRAP: &str = "a trap instruction where the sanitizer's handler would be called";
const PRINTF_FLAG: &str = "the flag argument loaded before the call to __printf_chk";
const REGISTER_CLEARING: &str = "the register clearing -fzero-call-used-regs can add before \
                                 a return";
const OBJECT_RELOCATIONS: &str = "the relocation types in an object's code against the \
                                  probe's references";

const X86_64_CELLS: &str = "the checks, measured in every x86_64 cell (Fedora 44 x86_64, gcc \
                            16.1.1, clang 22.1.8)";
const AARCH64_CELLS: &str = "the checks, measured in every native aarch64 cell (Fedora 44 \
                             aarch64, gcc 16.2.1, clang 22.1.8)";
const X86_CELLS: &str = "the checks, measured under -m32 in the i386 cells of 2026-10-10 \
                         (Fedora 44 x86_64 host, gcc 16.2.1 and clang 22.1.8 in a container \
                         holding the i686 C library)";

/// The table. Grouped by question; within a question, [`ARCHS`] order.
pub const ROWS: &[Row] = &[
    Row {
        question: "cfi-marking",
        arch: "x86_64",
        mechanism: CET,
        read_by: &[
            "cet-macro",
            "cet-marked-object",
            "cet-endbr-emitted",
            "cet-marked",
        ],
        witness: X86_64_CELLS,
    },
    Row {
        question: "cfi-marking",
        arch: "x86",
        mechanism: CET,
        read_by: &[
            "cet-macro",
            "cet-marked-object",
            "cet-endbr-emitted",
            "cet-marked",
        ],
        witness: X86_CELLS,
    },
    Row {
        question: "cfi-marking",
        arch: "aarch64",
        mechanism: BTI_PAC,
        read_by: &["branch-protection-macro", "branch-protection-marked"],
        witness: AARCH64_CELLS,
    },
    Row {
        question: "cfi-marking",
        arch: "aarch64",
        mechanism: GCS_MARKING,
        read_by: &["gcs-macro", "gcs-marked"],
        witness: AARCH64_CELLS,
    },
    Row {
        question: "shadow-stack-enforcement",
        arch: "x86_64",
        mechanism: SHADOW_STACK,
        read_by: &["shadow-stack-enforced"],
        witness: "the check; the Fedora 44 x86_64 host is the one machine that has read it \
                  on, partial or off",
    },
    Row {
        question: "shadow-stack-enforcement",
        arch: "x86",
        mechanism: SHADOW_STACK,
        read_by: &[],
        witness: "the instruction set has it in 32-bit mode (Intel SDM, CET shadow stacks), \
                  and Linux enables it for 64-bit programs only (the kernel's \
                  Documentation/arch/x86/shstk.rst), so a 32-bit program runs without one; no \
                  run has witnessed that, and the probe is written for x86_64",
    },
    Row {
        question: "shadow-stack-enforcement",
        arch: "aarch64",
        mechanism: GCS_ENFORCEMENT,
        read_by: &[],
        witness: "FEAT_GCS (Arm Architecture Reference Manual) and Linux's user Guarded \
                  Control Stack (the kernel's Documentation/arch/arm64/gcs.rst); gcs-macro \
                  and gcs-marked read its marking and no check its enforcement; the Fedora 44 \
                  aarch64 host chard has measured on lists no GCS in cpu.relevant_features",
    },
    Row {
        question: "text-relocations",
        arch: "x86_64",
        mechanism: TEXTREL,
        read_by: &["textrel-absent"],
        witness: X86_64_CELLS,
    },
    Row {
        question: "text-relocations",
        arch: "x86",
        mechanism: TEXTREL,
        read_by: &["textrel-absent"],
        witness: "the check's x86 positive control (probe::ARCH_CONTROLS), measured in the \
                  i386 cells of 2026-09-30",
    },
    Row {
        question: "text-relocations",
        arch: "aarch64",
        mechanism: TEXTREL,
        read_by: &[],
        witness: "a hand-written R_AARCH64_ABS64 in .text links into a shared object with \
                  DT_TEXTREL under -z notext with ld.bfd 2.46.1 and ld.lld 22.1.8 and by \
                  default with mold 2.40.4 (Fedora 44 aarch64, 2026-10-05); compiler output \
                  linked into none in those runs, so the check has no construction for \
                  aarch64",
    },
    Row {
        question: "linker-stack-default",
        arch: "x86_64",
        mechanism: STACK_DEFAULT,
        read_by: &["linker-default-noexecstack"],
        witness: X86_64_CELLS,
    },
    Row {
        question: "linker-stack-default",
        arch: "x86",
        mechanism: STACK_DEFAULT,
        read_by: &["linker-default-noexecstack"],
        witness: X86_CELLS,
    },
    Row {
        question: "linker-stack-default",
        arch: "aarch64",
        mechanism: STACK_DEFAULT,
        read_by: &[],
        witness: "for an object without .note.GNU-stack, ld.bfd 2.46.1 omits PT_GNU_STACK and \
                  ld.lld 22.1.8 and mold 2.40.4 write it RW (Fedora 44 aarch64, 2026-10-05); \
                  that a missing header means an executable stack on i386 and arm32 and \
                  not on aarch64 is known from the sources, not measured; the check as written reads a missing header as an \
                  executable stack, so it would publish off for a stack aarch64 does not make \
                  executable, and it has no construction for aarch64",
    },
    Row {
        question: "stack-execution-enforcement",
        arch: "x86_64",
        mechanism: STACK_ENFORCEMENT,
        read_by: &["noexecstack-enforced"],
        witness: X86_64_CELLS,
    },
    Row {
        question: "stack-execution-enforcement",
        arch: "x86",
        mechanism: STACK_ENFORCEMENT,
        read_by: &[],
        witness: "a 32-bit program that copies `mov $42,%eax; ret` to its stack and calls it \
                  faults on the fetch under PT_GNU_STACK RW and returns 42 under RWE \
                  (Fedora 44 x86_64 host, Linux 7.3, gcc 16.2.1 and clang 22.1.8 at -m32 in \
                  a container holding the i686 C library, 2026-10-12); the probe's payload is \
                  written for x86_64 and aarch64",
    },
    Row {
        question: "stack-execution-enforcement",
        arch: "aarch64",
        mechanism: STACK_ENFORCEMENT,
        read_by: &["noexecstack-enforced"],
        witness: AARCH64_CELLS,
    },
    Row {
        question: "sanitizer-traps",
        arch: "x86_64",
        mechanism: TRAP,
        read_by: &["ubsan-trap-mode"],
        witness: X86_64_CELLS,
    },
    Row {
        question: "sanitizer-traps",
        arch: "x86",
        mechanism: TRAP,
        read_by: &[],
        witness: "gcc 16.2.1 and clang 22.1.8 at -m32 compile a trapping signed overflow to \
                  ud2 (Fedora 44 x86_64 host, in a container holding the i686 C library, \
                  2026-10-12); the check's pattern search is written for x86_64 and \
                  aarch64 code",
    },
    Row {
        question: "sanitizer-traps",
        arch: "aarch64",
        mechanism: TRAP,
        read_by: &["ubsan-trap-mode"],
        witness: AARCH64_CELLS,
    },
    Row {
        question: "printf-fortify-level",
        arch: "x86_64",
        mechanism: PRINTF_FLAG,
        read_by: &["fortify-printf-flag"],
        witness: X86_64_CELLS,
    },
    Row {
        question: "printf-fortify-level",
        arch: "x86",
        mechanism: PRINTF_FLAG,
        read_by: &[],
        witness: "gcc 16.2.1 at -m32 under -O2 -D_FORTIFY_SOURCE=2 pushes $0x1 before its \
                  call to __printf_chk, and clang 22.1.8 before __vprintf_chk in its \
                  out-of-line wrapper (Fedora 44 x86_64 host, in a container holding the i686 \
                  C library, 2026-10-12); the check's pattern search is written for x86_64 and \
                  aarch64 code",
    },
    Row {
        question: "printf-fortify-level",
        arch: "aarch64",
        mechanism: PRINTF_FLAG,
        read_by: &["fortify-printf-flag"],
        witness: AARCH64_CELLS,
    },
    Row {
        question: "call-used-register-clearing",
        arch: "x86_64",
        mechanism: REGISTER_CLEARING,
        read_by: &["zero-call-used-regs"],
        witness: X86_64_CELLS,
    },
    Row {
        question: "call-used-register-clearing",
        arch: "x86",
        mechanism: REGISTER_CLEARING,
        read_by: &[],
        witness: "gcc 16.2.1 at -m32 adds `xor %edx,%edx` before the return of a function that \
                  divided, under =used-gpr against =skip; clang 22.1.8 accepts the flag and \
                  added nothing for that function (Fedora 44 x86_64 host, in a container \
                  holding the i686 C library, 2026-10-12); the check's pattern search is \
                  written for x86_64 and aarch64 code",
    },
    Row {
        question: "call-used-register-clearing",
        arch: "aarch64",
        mechanism: REGISTER_CLEARING,
        read_by: &["zero-call-used-regs"],
        witness: AARCH64_CELLS,
    },
    Row {
        question: "object-relocations",
        arch: "x86_64",
        mechanism: OBJECT_RELOCATIONS,
        read_by: &["pic-object-relocs"],
        witness: X86_64_CELLS,
    },
    Row {
        question: "object-relocations",
        arch: "x86",
        mechanism: OBJECT_RELOCATIONS,
        read_by: &["pic-object-relocs"],
        witness: X86_CELLS,
    },
    Row {
        question: "object-relocations",
        arch: "aarch64",
        mechanism: OBJECT_RELOCATIONS,
        read_by: &["pic-object-relocs"],
        witness: AARCH64_CELLS,
    },
];

/// What a check's gate decides on an architecture. See the module documentation for the
/// rule each variant publishes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The check reads its mechanism on this architecture, or is portable: measure it.
    Measured,
    /// `row` is a mechanism for the check's question on this architecture that no check
    /// reads there: the check's own (`own`), whose construction is written for other
    /// architectures, or another the architecture answers the question with.
    Unread { row: &'static Row, own: bool },
    /// The architecture answers the question only with mechanisms other checks read, named
    /// by `answered_by`: the check's mechanism is absent there.
    Absent { answered_by: &'static Row },
    /// The table has no row for the check's question on this architecture.
    Outside,
}

impl Decision {
    /// Whether the check is built and read on the architecture.
    #[must_use]
    pub fn is_measured(self) -> bool {
        matches!(self, Self::Measured)
    }

    /// What the decision publishes, for comparing one gate's decision under two
    /// architectures. The two `Unread` cases share an outcome: both publish `indeterminate`
    /// under `no-check-on-target`.
    #[must_use]
    pub fn outcome(self) -> Outcome {
        match self {
            Self::Measured => Outcome::Measured,
            Self::Unread { .. } => Outcome::Unread,
            Self::Absent { .. } => Outcome::Absent,
            Self::Outside => Outcome::Outside,
        }
    }
}

/// What a [`Decision`] publishes, as the target witness compares it
/// (`report::withhold_on_contradicted_target`): a check is withheld where its outcome
/// under a witnessed machine differs from its outcome under the architecture the gate
/// read. Each outcome rests on that architecture: `Measured`, that the target is one the
/// check reads; `Absent`, that the target answers the question with another mechanism a
/// check reads (`arch-gated`, `unsupported`); `Unread`, that it has a mechanism no check
/// reads there (`no-check-on-target`); `Outside`, that the table claims nothing of it
/// (`arch-outside-table`). Comparing only [`Decision::is_measured`] would let a check gated
/// out under the read architecture keep `unsupported` beside a witness naming a target the
/// table has no row for, with a reason saying "this build targets" the contradicted
/// architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Measured,
    Unread,
    Absent,
    Outside,
}

impl Outcome {
    /// The outcome as a gating reason names it, after "it was".
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Unread => "left unread",
            Self::Absent => "gated out",
            Self::Outside => "left outside the table",
        }
    }
}

/// The question and mechanism a check is one reader of, from the rows that name it; `None`
/// for a check no row names, which is a portable check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub question: &'static str,
    pub mechanism: &'static str,
}

/// The binding of `check`, from the first row naming it as a reader. Every row naming it
/// names the same question and mechanism, which the table test holds.
#[must_use]
pub fn binding(check: &str) -> Option<Binding> {
    ROWS.iter()
        .find(|r| r.read_by.contains(&check))
        .map(|r| Binding {
            question: r.question,
            mechanism: r.mechanism,
        })
}

/// The architectures `check` reads its mechanism on, in [`ARCHS`] order: the list `Gate.arch`
/// carries, and `{:?}` of it is what the `arch-gated` reason has always quoted. Empty for a
/// portable check.
#[must_use]
pub fn archs_of(check: &str) -> Vec<&'static str> {
    ARCHS
        .iter()
        .copied()
        .filter(|arch| {
            ROWS.iter()
                .any(|r| r.arch == *arch && r.read_by.contains(&check))
        })
        .collect()
}

/// The gate's decision for `check` on `arch`. A portable check is measured everywhere; a
/// bound one decides from its question's rows for `arch`, by the rule in the module
/// documentation. `arch` is in the gate vocabulary (`x86_64`, `x86`, `aarch64`, or whatever
/// `-dumpmachine`, the kernel or an artifact's machine named), and a value outside
/// [`ARCHS`] has no row.
#[must_use]
pub fn decide(check: &str, arch: &str) -> Decision {
    let Some(bound) = binding(check) else {
        return Decision::Measured;
    };
    let mut rows = ROWS
        .iter()
        .filter(|r| r.question == bound.question && r.arch == arch);
    let Some(first) = rows.next() else {
        return Decision::Outside;
    };
    let rows = std::iter::once(first).chain(rows);
    let mut answered_by = None;
    let mut unread_sibling = None;
    for row in rows {
        if row.mechanism == bound.mechanism {
            if row.read_by.contains(&check) {
                return Decision::Measured;
            }
            return Decision::Unread { row, own: true };
        }
        if row.read_by.is_empty() {
            unread_sibling.get_or_insert(row);
        } else {
            answered_by.get_or_insert(row);
        }
    }
    match (answered_by, unread_sibling) {
        (Some(answered_by), _) => Decision::Absent { answered_by },
        (None, Some(row)) => Decision::Unread { row, own: false },
        (None, None) => Decision::Outside,
    }
}

/// The question `id` names, for a reason that quotes what the question asks.
#[must_use]
pub fn question(id: &str) -> Option<&'static Question> {
    QUESTIONS.iter().find(|q| q.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A question is found by its own id, and an id no question has finds none.
    #[test]
    fn a_question_is_found_by_its_id() {
        for q in QUESTIONS {
            assert_eq!(question(q.id).map(|found| found.id), Some(q.id));
        }
        assert!(question("no-such-question").is_none());
    }
    use crate::probe;
    use std::collections::{BTreeMap, BTreeSet};

    fn corpus_checks() -> Vec<&'static probe::Check> {
        probe::CORPUS.iter().flat_map(|p| p.checks).collect()
    }

    /// Every `Gate.arch` literal in the corpus is the list the table derives for its check,
    /// in order, and a check the table names reads on exactly the architectures its gate
    /// lists. This is what makes the literal a copy of the table rather than a second
    /// source: with `report::tests::the_arch_gated_checks_are_the_ones_we_named` holding
    /// the literals to the sixteen lists it names, the derived lists are those sixteen.
    #[test]
    fn every_gate_list_is_the_tables() {
        let mut bound = 0;
        for check in corpus_checks() {
            let derived = archs_of(check.id);
            assert_eq!(
                derived, check.gate.arch,
                "{}: Gate.arch is {:?} and the mechanism table reads it on {derived:?}",
                check.id, check.gate.arch
            );
            if !derived.is_empty() {
                bound += 1;
            }
        }
        assert_eq!(bound, 16, "the table binds the sixteen gated checks");
    }

    /// The table's shape: every question has a row for every architecture in `ARCHS`; a row
    /// names a question and architecture the table knows, a non-empty mechanism and
    /// witness, and readers that are corpus checks; no (question, architecture, mechanism)
    /// twice; a check reads one mechanism of one question; and the checks the table names
    /// are exactly the corpus's gated checks.
    #[test]
    fn the_table_is_total_and_well_formed() {
        let question_ids: BTreeSet<&str> = QUESTIONS.iter().map(|q| q.id).collect();
        assert_eq!(question_ids.len(), QUESTIONS.len(), "a question id twice");
        for q in QUESTIONS {
            assert!(!q.asks.is_empty(), "{}: asks nothing", q.id);
            for arch in ARCHS {
                assert!(
                    ROWS.iter().any(|r| r.question == q.id && r.arch == *arch),
                    "{}: no row for {arch}",
                    q.id
                );
            }
        }
        let corpus: BTreeMap<&str, &probe::Check> =
            corpus_checks().into_iter().map(|c| (c.id, c)).collect();
        let mut keys = BTreeSet::new();
        let mut bindings: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
        for row in ROWS {
            assert!(
                question_ids.contains(row.question),
                "{}: unknown question",
                row.question
            );
            assert!(
                ARCHS.contains(&row.arch),
                "{}: {} is outside ARCHS",
                row.question,
                row.arch
            );
            assert!(
                !row.mechanism.is_empty() && !row.witness.is_empty(),
                "{}: an empty row",
                row.question
            );
            assert!(
                keys.insert((row.question, row.arch, row.mechanism)),
                "{} on {} names {} twice",
                row.question,
                row.arch,
                row.mechanism
            );
            let mut seen = BTreeSet::new();
            for reader in row.read_by {
                assert!(
                    corpus.contains_key(reader),
                    "{reader} is not a check in the corpus"
                );
                assert!(seen.insert(reader), "{reader} twice on one row");
                let bound = bindings
                    .entry(reader)
                    .or_insert((row.question, row.mechanism));
                assert_eq!(
                    *bound,
                    (row.question, row.mechanism),
                    "{reader} reads two mechanisms or two questions"
                );
            }
        }
        let gated: BTreeSet<&str> = corpus
            .values()
            .filter(|c| !c.gate.arch.is_empty())
            .map(|c| c.id)
            .collect();
        let named: BTreeSet<&str> = bindings.keys().copied().collect();
        assert_eq!(
            named, gated,
            "the table names the gated checks and no other"
        );
        assert!(
            !gated.is_empty(),
            "the corpus gates nothing, and this test holds nothing"
        );
    }

    /// The decision of every gated check on every architecture in the table, named cell by
    /// cell, with a target outside the table beside them. `M` is measured; `A` is absent
    /// (`arch-gated`, `unsupported`); `U` is unread, the check's own mechanism; `S` is
    /// unread, a sibling mechanism. The aarch64 column of `shadow-stack-enforced`,
    /// `textrel-absent` and `linker-default-noexecstack`, and the x86 column of
    /// `shadow-stack-enforced`, `noexecstack-enforced`, `ubsan-trap-mode`,
    /// `fortify-printf-flag` and `zero-call-used-regs`, are the cells a hand-written list per
    /// check reads `A`, an absence chard did not measure.
    #[test]
    fn the_decision_of_every_gated_check_on_every_architecture_is_the_one_named() {
        // (check, x86_64, x86, aarch64)
        const CELLS: &[(&str, [char; 3])] = &[
            ("cet-macro", ['M', 'M', 'A']),
            ("cet-marked-object", ['M', 'M', 'A']),
            ("cet-endbr-emitted", ['M', 'M', 'A']),
            ("cet-marked", ['M', 'M', 'A']),
            ("branch-protection-macro", ['A', 'A', 'M']),
            ("branch-protection-marked", ['A', 'A', 'M']),
            ("gcs-macro", ['A', 'A', 'M']),
            ("gcs-marked", ['A', 'A', 'M']),
            ("shadow-stack-enforced", ['M', 'U', 'S']),
            ("textrel-absent", ['M', 'M', 'U']),
            ("linker-default-noexecstack", ['M', 'M', 'U']),
            ("noexecstack-enforced", ['M', 'U', 'M']),
            ("ubsan-trap-mode", ['M', 'U', 'M']),
            ("fortify-printf-flag", ['M', 'U', 'M']),
            ("zero-call-used-regs", ['M', 'U', 'M']),
            ("pic-object-relocs", ['M', 'M', 'M']),
        ];
        assert_eq!(CELLS.len(), 16);
        // The columns are `ARCHS` in order; a fourth architecture would fall off the zip
        // below unseen, so the list is held to its three names here.
        assert_eq!(ARCHS, &["x86_64", "x86", "aarch64"]);
        let kind = |d: Decision| match d {
            Decision::Measured => 'M',
            Decision::Absent { .. } => 'A',
            Decision::Unread { own: true, .. } => 'U',
            Decision::Unread { own: false, .. } => 'S',
            Decision::Outside => 'O',
        };
        // The outcome the target witness compares: one per letter, the two unread
        // letters sharing one, and no in-table outcome equal to a target outside it.
        let outcome = |want: char| match want {
            'M' => Outcome::Measured,
            'A' => Outcome::Absent,
            'U' | 'S' => Outcome::Unread,
            _ => Outcome::Outside,
        };
        let mut named = BTreeSet::new();
        for (check, expected) in CELLS {
            named.insert(*check);
            for (arch, want) in ARCHS.iter().zip(expected) {
                let got = decide(check, arch);
                assert_eq!(kind(got), *want, "{check} on {arch}: {got:?}");
                assert_eq!(got.outcome(), outcome(*want), "{check} on {arch}");
                assert_ne!(got.outcome(), Outcome::Outside, "{check} on {arch}");
                assert_eq!(got.is_measured(), got.outcome() == Outcome::Measured);
            }
            for outside in ["riscv64", "arm", "outside-arch-macros", "no-such-arch"] {
                assert_eq!(
                    decide(check, outside),
                    Decision::Outside,
                    "{check} on {outside}"
                );
                assert_eq!(decide(check, outside).outcome(), Outcome::Outside);
            }
            // An absence names a sibling a check reads, and an unread row names no reader.
            for arch in ARCHS {
                match decide(check, arch) {
                    Decision::Absent { answered_by } => {
                        assert!(!answered_by.read_by.is_empty(), "{check} on {arch}");
                        assert_ne!(answered_by.mechanism, binding(check).unwrap().mechanism);
                    }
                    Decision::Unread { row, own } => {
                        assert!(row.read_by.is_empty(), "{check} on {arch}: {row:?}");
                        assert_eq!(own, row.mechanism == binding(check).unwrap().mechanism);
                    }
                    Decision::Measured | Decision::Outside => {}
                }
            }
        }
        let gated: BTreeSet<&str> = corpus_checks()
            .into_iter()
            .filter(|c| !c.gate.arch.is_empty())
            .map(|c| c.id)
            .collect();
        assert_eq!(named, gated, "every gated check has a line here");

        // A portable check is measured on every architecture, inside the table and out.
        for check in corpus_checks() {
            if check.gate.arch.is_empty() {
                for arch in ARCHS.iter().chain(&["riscv64", "no-such-arch"]) {
                    assert_eq!(
                        decide(check.id, arch),
                        Decision::Measured,
                        "{} on {arch}",
                        check.id
                    );
                }
            }
        }
    }
}
