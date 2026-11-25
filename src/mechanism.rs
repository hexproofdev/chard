// SPDX-License-Identifier: BSD-3-Clause

//! The mechanism table: for each question an architecture-bound check answers, which
//! mechanism answers it on each architecture an owned host has witnessed, and which checks
//! read that mechanism there. Every architecture decision a gate takes derives from it.

/// The architectures the table has rows for, in `Gate.arch` order: the ones an owned host
/// has witnessed (x86_64 and aarch64 natively, x86 through `-m32` on the x86_64 host). A
/// target outside this list decides [`Decision::Outside`]. Each row stands for the width and
/// byte order of the host it was measured on (`toolchain::Abi::of_arch`), so a target of the
/// family at another (x32, aarch64 ILP32, `aarch64_be`) has no row either, and the target
/// witness withholds it (`toolchain::TargetArch::abi`), since the gate reads the
/// architecture alone.
pub const ARCHS: &[&str] = &["x86_64", "x86", "aarch64"];

/// A question an architecture-bound check answers, in the words a reader of a gating reason
/// sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Question {
    pub id: &'static str,
    pub asks: &'static str,
}

/// Every question the table has rows for. Each has a row for every architecture in
/// [`ARCHS`], which `tests::the_table_is_total_and_well_formed` holds.
pub const QUESTIONS: &[Question] = &[
    Question {
        id: "cfi-marking",
        asks: "is control-flow integrity marked",
    },
    Question {
        id: "shadow-stack-enforcement",
        asks: "does the kernel enforce a hardware shadow stack for the running program",
    },
    Question {
        id: "forward-edge-enforcement",
        asks: "does an indirect branch to an instruction that is not a landing pad fault in a \
               running program marked for it",
    },
    Question {
        id: "return-address-authentication",
        asks: "does a return through a corrupted saved return address fail in a running program \
               built for it",
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
/// read there under this question. Whether the mechanism is read on the architecture is
/// [`Row::readers`], never this row's list alone, since a mechanism answering two questions
/// lists its checks under one. A row with no reader says chard does not read the mechanism
/// there, and `witness` says what that rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub question: &'static str,
    pub arch: &'static str,
    /// The mechanism as a reader would name it. One mechanism is one string, so a check's
    /// mechanism is found on another architecture's row by equality.
    pub mechanism: &'static str,
    /// The checks bound to this question whose construction reads the mechanism on this
    /// architecture: the checks whose `Gate.arch` names it. A check is listed under one
    /// question, so a row of a second question the mechanism answers lists none, and its
    /// `witness` names the reader and its question.
    pub read_by: &'static [&'static str],
    /// The checks that read it, or the measurement or source and the date the row holds as
    /// of. Never empty.
    pub witness: &'static str,
}

impl Row {
    /// Every check that reads this row's mechanism on this row's architecture, under any
    /// question, in table order. [`decide`] asks this of a sibling mechanism, not `read_by`,
    /// so no row publishes that no check reads a mechanism another row has a check reading.
    pub fn readers(&self) -> impl Iterator<Item = &'static str> {
        readers_in(ROWS, self.arch, self.mechanism)
    }
}

/// [`Row::readers`] over `table`: the readers of every row of it naming `mechanism` on `arch`.
fn readers_in(
    table: &'static [Row],
    arch: &'static str,
    mechanism: &'static str,
) -> impl Iterator<Item = &'static str> {
    table
        .iter()
        .filter(move |r| r.arch == arch && r.mechanism == mechanism)
        .flat_map(|r| r.read_by.iter().copied())
}

const CET: &str = "x86 CET: IBT landing pads and the shadow stack, marked in __CET__ and the \
                   x86 property note";
const BTI_PAC: &str = "aarch64 BTI and PAC, marked in __ARM_FEATURE_BTI_DEFAULT and \
                       __ARM_FEATURE_PAC_DEFAULT and in the aarch64 property note";
const GCS_MARKING: &str = "aarch64 GCS marking, in __ARM_FEATURE_GCS_DEFAULT and the aarch64 \
                           property note's GCS bit";
const SHADOW_STACK: &str = "the x86 CET shadow stack";
const GCS_ENFORCEMENT: &str = "the aarch64 Guarded Control Stack the kernel enforces";
const BTI_ENFORCEMENT: &str =
    "the aarch64 branch-target exception a kernel enables for a BTI-marked program";
const PAC_ENFORCEMENT: &str = "aarch64 pointer authentication of the saved return address";
const IBT_ENFORCEMENT: &str = "x86 CET indirect branch tracking";
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

const X86_64_CELLS: &str = "the checks, measured under gcc and clang on x86_64";
const AARCH64_CELLS: &str = "the checks, measured natively under gcc and clang on aarch64";
const X86_CELLS: &str = "the checks, measured under -m32 with gcc and clang against the i686 C \
                         library";

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
        witness: "the check",
    },
    Row {
        question: "shadow-stack-enforcement",
        arch: "x86",
        mechanism: SHADOW_STACK,
        read_by: &[],
        witness: "the instruction set has it in 32-bit mode",
    },
    Row {
        question: "shadow-stack-enforcement",
        arch: "aarch64",
        mechanism: GCS_ENFORCEMENT,
        read_by: &[],
        witness: "FEAT_GCS (Arm Architecture Reference Manual; the aarch64 binutils assembles its instructions) and Linux's user Guarded Control Stack",
    },
    Row {
        question: "forward-edge-enforcement",
        arch: "x86_64",
        mechanism: IBT_ENFORCEMENT,
        read_by: &[],
        witness: "CET indirect branch tracking",
    },
    Row {
        question: "forward-edge-enforcement",
        arch: "x86",
        mechanism: IBT_ENFORCEMENT,
        read_by: &[],
        witness: "CET indirect branch tracking in 32-bit mode",
    },
    Row {
        question: "forward-edge-enforcement",
        arch: "aarch64",
        mechanism: BTI_ENFORCEMENT,
        read_by: &["bti-enforced"],
        witness: "the check; FEAT_BTI (Arm Architecture Reference Manual) and Linux's PROT_BTI mapping of a marked program",
    },
    Row {
        question: "return-address-authentication",
        arch: "x86_64",
        mechanism: SHADOW_STACK,
        read_by: &[],
        witness: "shadow-stack-enforced is built to read it",
    },
    Row {
        question: "return-address-authentication",
        arch: "x86",
        mechanism: SHADOW_STACK,
        read_by: &[],
        witness: "the instruction set has the shadow stack in 32-bit mode",
    },
    Row {
        question: "return-address-authentication",
        arch: "aarch64",
        mechanism: PAC_ENFORCEMENT,
        read_by: &["pac-ret-enforced"],
        witness: "the check; FEAT_PAuth and FEAT_FPAC",
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
        witness: "the check's x86 positive control",
    },
    Row {
        question: "text-relocations",
        arch: "aarch64",
        mechanism: TEXTREL,
        read_by: &["textrel-absent"],
        witness: "the check's positive control",
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
        witness: "for an object without .note.GNU-stack, ld.bfd omits PT_GNU_STACK and ld.lld and mold write it RW",
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
        witness: "a 32-bit program that copies `mov $42,%eax; ret` to its stack and calls it faults on the fetch under PT_GNU_STACK RW and returns 42 under RWE",
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
        witness: "gcc and clang at -m32 compile a trapping signed overflow to ud2",
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
        witness: "gcc at -m32 under -O2 -D_FORTIFY_SOURCE=2 pushes $0x1 before its call to __printf_chk",
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
        witness: "gcc at -m32 adds `xor %edx,%edx` before the return of a function that divided",
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
    /// by `answered_by`, whose [`Row::readers`] are those checks: the check's mechanism is
    /// absent there.
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
/// check reads; `Unread`, that it has a mechanism no check reads there; `Outside`, that the
/// table claims nothing of it. Comparing only [`Decision::is_measured`] would let a check
/// gated out under the read architecture keep `unsupported` beside a witness naming a
/// target the table has no row for.
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
    binding_in(ROWS, check)
}

fn binding_in(table: &'static [Row], check: &str) -> Option<Binding> {
    table
        .iter()
        .find(|r| r.read_by.contains(&check))
        .map(|r| Binding {
            question: r.question,
            mechanism: r.mechanism,
        })
}

/// The architectures `check` reads its mechanism on, in [`ARCHS`] order: the list `Gate.arch`
/// carries and the `arch-gated` reason quotes. Empty for a portable check.
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
    decide_in(ROWS, check, arch)
}

/// [`decide`] over `table`, so the rule is held on planted tables as well as on [`ROWS`].
fn decide_in(table: &'static [Row], check: &str, arch: &str) -> Decision {
    let Some(bound) = binding_in(table, check) else {
        return Decision::Measured;
    };
    let mut rows = table
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
        if readers_in(table, row.arch, row.mechanism).next().is_none() {
            unread_sibling.get_or_insert(row);
        } else {
            answered_by.get_or_insert(row);
        }
    }
    // An unread sibling outranks a read one: where the architecture answers the question
    // with two mechanisms and no check reads one of them, "answered only with mechanisms
    // other checks read" is false, and the check is withheld.
    match (unread_sibling, answered_by) {
        (Some(row), _) => Decision::Unread { row, own: false },
        (None, Some(answered_by)) => Decision::Absent { answered_by },
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
        assert_eq!(bound, 18, "the table binds the eighteen gated checks");
    }

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

    #[test]
    fn a_row_read_under_another_question_names_the_reader_and_the_question() {
        let mut found = Vec::new();
        for row in ROWS {
            if !row.read_by.is_empty() {
                continue;
            }
            let readers: Vec<&str> = row.readers().collect();
            if readers.is_empty() {
                continue;
            }
            found.push((row.question, row.arch));
            // No check is bound to this row's question and mechanism: such a check would
            // decide `Unread` here, and its reason would say no check reads a mechanism
            // that one does.
            assert!(
                !ROWS.iter().any(|r| r.question == row.question
                    && r.mechanism == row.mechanism
                    && !r.read_by.is_empty()),
                "{} on {}: a check is bound to {} under this question",
                row.question,
                row.arch,
                row.mechanism
            );
            for reader in readers {
                let home = binding(reader).expect("a reader is bound").question;
                assert_ne!(home, row.question, "{reader} is bound to this question");
            }
        }
        assert_eq!(found, [("return-address-authentication", "x86_64")]);
    }

    #[test]
    fn the_readers_of_a_mechanism_on_an_architecture_are_listed_on_one_row() {
        let mut listed = BTreeSet::new();
        let mut rows = 0;
        for row in ROWS.iter().filter(|r| !r.read_by.is_empty()) {
            rows += 1;
            assert!(
                listed.insert((row.arch, row.mechanism)),
                "{} on {}: readers of {} are listed on two rows",
                row.question,
                row.arch,
                row.mechanism
            );
        }
        assert!(
            rows > 0,
            "no row lists a reader, and this test holds nothing"
        );
    }

    /// Two questions one mechanism answers, and a third answered by two mechanisms, on
    /// tables written for the rule: [`ROWS`] has one cell of the first shape and none of the
    /// second.
    const PLANTED: &[Row] = &[
        Row {
            question: "q-stack",
            arch: "a",
            mechanism: "stack",
            read_by: &["stack-check"],
            witness: "planted",
        },
        Row {
            question: "q-return",
            arch: "a",
            mechanism: "stack",
            read_by: &[],
            witness: "planted",
        },
        Row {
            question: "q-return",
            arch: "b",
            mechanism: "signing",
            read_by: &["signing-check"],
            witness: "planted",
        },
        Row {
            question: "q-stack",
            arch: "b",
            mechanism: "other-stack",
            read_by: &[],
            witness: "planted",
        },
        // On `c` the stack is unread under both questions.
        Row {
            question: "q-stack",
            arch: "c",
            mechanism: "stack",
            read_by: &[],
            witness: "planted",
        },
        Row {
            question: "q-return",
            arch: "c",
            mechanism: "stack",
            read_by: &[],
            witness: "planted",
        },
        // On `d` the return question has two answers, one read and one not, in each order.
        Row {
            question: "q-return",
            arch: "d",
            mechanism: "read-first",
            read_by: &["first-check"],
            witness: "planted",
        },
        Row {
            question: "q-return",
            arch: "d",
            mechanism: "unread-second",
            read_by: &[],
            witness: "planted",
        },
        Row {
            question: "q-return",
            arch: "e",
            mechanism: "unread-first",
            read_by: &[],
            witness: "planted",
        },
        Row {
            question: "q-return",
            arch: "e",
            mechanism: "read-first",
            read_by: &["first-check"],
            witness: "planted",
        },
    ];

    #[test]
    fn a_mechanism_read_under_one_question_is_read_under_every_question_it_answers() {
        let mechanism = |d: Decision| match d {
            Decision::Absent { answered_by } => ('A', answered_by.mechanism),
            Decision::Unread { row, own } => (if own { 'U' } else { 'S' }, row.mechanism),
            Decision::Measured => ('M', ""),
            Decision::Outside => ('O', ""),
        };
        let cell = |check: &str, arch: &str| mechanism(decide_in(PLANTED, check, arch));
        // The stack is read on `a` under `q-stack`, so signing is absent there, not unread.
        assert_eq!(cell("signing-check", "a"), ('A', "stack"));
        // Nothing reads the stack on `c`, under either question.
        assert_eq!(cell("signing-check", "c"), ('S', "stack"));
        assert_eq!(cell("stack-check", "c"), ('U', "stack"));
        // The check's own question decides for it: `b` answers `q-stack` with a mechanism no
        // check reads, whatever reads `q-return` there.
        assert_eq!(cell("stack-check", "b"), ('S', "other-stack"));
        assert_eq!(cell("stack-check", "a"), ('M', ""));
        assert_eq!(cell("signing-check", "b"), ('M', ""));
        // One unread sibling withholds, before or after a read one.
        assert_eq!(cell("signing-check", "d"), ('S', "unread-second"));
        assert_eq!(cell("signing-check", "e"), ('S', "unread-first"));
        assert_eq!(cell("signing-check", "no-such-arch"), ('O', ""));
    }

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
            ("bti-enforced", ['S', 'S', 'M']),
            ("pac-ret-enforced", ['A', 'S', 'M']),
            ("textrel-absent", ['M', 'M', 'M']),
            ("linker-default-noexecstack", ['M', 'M', 'U']),
            ("noexecstack-enforced", ['M', 'U', 'M']),
            ("ubsan-trap-mode", ['M', 'U', 'M']),
            ("fortify-printf-flag", ['M', 'U', 'M']),
            ("zero-call-used-regs", ['M', 'U', 'M']),
            ("pic-object-relocs", ['M', 'M', 'M']),
        ];
        assert_eq!(CELLS.len(), 18);
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
                        assert!(answered_by.readers().next().is_some(), "{check} on {arch}");
                        assert_ne!(answered_by.mechanism, binding(check).unwrap().mechanism);
                    }
                    Decision::Unread { row, own } => {
                        assert!(row.readers().next().is_none(), "{check} on {arch}: {row:?}");
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
