// SPDX-License-Identifier: BSD-3-Clause

//! The predicates for the elf-static checks, one entry per check id.

use std::sync::LazyLock;

use super::{Clause, Conclusion, Cond, ElfField, Entry, LevelOf, Predicate, Term};
use crate::elf::{ElfTable, UNATTRIBUTED_REFERENCE};
use crate::probe;

fn elf(field: ElfField) -> Term {
    Term::Elf(field)
}

fn truth(field: ElfField) -> Cond {
    Cond::Truth(elf(field))
}

fn missing(field: ElfField) -> Cond {
    Cond::Missing(elf(field))
}

fn defined_symbol(name: &str) -> Cond {
    Cond::Defined(Term::Symbol(name.to_owned()))
}

fn word(level: &str) -> Conclusion {
    Conclusion::Present(LevelOf::Word(level.to_owned()))
}

fn clause(id: &str, when: Cond, then: Conclusion, because: &str) -> Clause {
    Clause {
        id: id.to_owned(),
        when,
        then,
        because: because.to_owned(),
    }
}

/// The prelude for a detector that reads link-classification fields: any of them `None`
/// withholds the reading.
fn unclassified(fields: &[ElfField], what: &str) -> Clause {
    clause(
        "unclassified",
        Cond::Any(fields.iter().copied().map(missing).collect()),
        Conclusion::Indeterminate,
        &format!("the loader cannot run this object, so it carries no {what}"),
    )
}

/// A one-bit check: the field set is `present` with no level, clear is `absent`.
fn one_bit(tables: &[ElfTable], field: ElfField, id: &str, because: &str) -> Predicate {
    Predicate {
        tables: tables.to_vec(),
        clauses: vec![clause(
            id,
            truth(field),
            Conclusion::Present(LevelOf::None),
            because,
        )],
        otherwise: Conclusion::Absent,
    }
}

/// A two-bit feature word read as `full`, `branch` or `return`: the first bit is the
/// branch half, the second the return half. `cet-marked` and `branch-protection-marked`
/// share this shape.
fn two_bit(tables: &[ElfTable], branch: ElfField, ret: ElfField, what: &str) -> Predicate {
    Predicate {
        tables: tables.to_vec(),
        clauses: vec![
            clause(
                "full",
                Cond::All(vec![truth(branch), truth(ret)]),
                word("full"),
                &format!("{what} marks both the branch and the return protection"),
            ),
            clause(
                "branch",
                truth(branch),
                word("branch"),
                &format!("{what} marks the branch protection alone"),
            ),
            clause(
                "return",
                truth(ret),
                word("return"),
                &format!("{what} marks the return protection alone"),
            ),
        ],
        otherwise: Conclusion::Absent,
    }
}

/// `ET_DYN` alone would also match a shared library, so the reader's `pie` classification
/// asks for `DF_1_PIE`, `PT_INTERP` or `DT_DEBUG` beside it. `None` is an object the
/// loader cannot run, which carries no classification (`elf::LinkKind`).
static PIE: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::Header,
        ElfTable::ProgramHeaders,
        ElfTable::Dynamic,
    ],
    clauses: vec![
        unclassified(&[ElfField::Pie, ElfField::StaticPie], "PIE classification"),
        clause(
            "pie",
            truth(ElfField::Pie),
            word("pie"),
            "the object is ET_DYN and marked as executable output",
        ),
    ],
    otherwise: Conclusion::Absent,
});

static RELRO: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::ProgramHeaders, ElfTable::Dynamic],
    clauses: vec![
        unclassified(
            &[ElfField::GnuRelro, ElfField::BindNow, ElfField::Relro],
            "RELRO classification",
        ),
        clause(
            "gnu-relro",
            truth(ElfField::GnuRelro),
            Conclusion::Present(LevelOf::Value(elf(ElfField::Relro))),
            "PT_GNU_RELRO is present, and the level is the RELRO classification",
        ),
    ],
    otherwise: Conclusion::Absent,
});

/// No `PT_GNU_STACK` defers to the kernel's default, a different state from a header that
/// marks the stack non-executable, and the artifact alone supports neither `on` nor `off`
/// for it.
static NOEXECSTACK: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::Header,
        ElfTable::ProgramHeaders,
        ElfTable::GnuStack,
    ],
    clauses: vec![
        unclassified(
            &[ElfField::GnuStackPresent, ElfField::GnuStackExecutable],
            "PT_GNU_STACK",
        ),
        clause(
            "kernel-default",
            Cond::Eq(elf(ElfField::GnuStackPresent), "false".to_owned()),
            Conclusion::Indeterminate,
            "no PT_GNU_STACK defers to the kernel's default",
        ),
        clause(
            "executable",
            truth(ElfField::GnuStackExecutable),
            Conclusion::Absent,
            "PT_GNU_STACK carries PF_X",
        ),
    ],
    otherwise: Conclusion::Present(LevelOf::None),
});

static NODLOPEN: LazyLock<Predicate> = LazyLock::new(|| {
    one_bit(
        &[ElfTable::Dynamic],
        ElfField::Df1Noopen,
        "df-1-noopen",
        "DT_FLAGS_1 carries DF_1_NOOPEN",
    )
});

static RPATH: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::Dynamic, ElfTable::DynStr],
    clauses: vec![
        clause(
            "rpath",
            Cond::NonEmpty(elf(ElfField::Rpath)),
            word("rpath"),
            "the object carries a DT_RPATH entry",
        ),
        clause(
            "runpath",
            Cond::NonEmpty(elf(ElfField::Runpath)),
            word("runpath"),
            "the object carries a DT_RUNPATH entry and no DT_RPATH",
        ),
    ],
    otherwise: Conclusion::Absent,
});

/// The `DT_NEEDED` prefix of a C library: glibc's `libc.so.6`, musl's `libc.so` and
/// `libc.musl-<arch>.so.1`, FreeBSD's `libc.so.7`, OpenBSD's `libc.so.<major>.<minor>`.
/// `as-needed` reads its list only where an entry carries it, since the probe's executable
/// link records the C library whenever it takes the library from a shared object; the precondition
/// row in `report::ARTIFACT_PRECONDITIONS` reads the same prefix.
pub const C_LIBRARY_PREFIX: &str = "libc.";

/// The `DT_NEEDED` prefix of the library the `as-needed` probe links and never calls,
/// derived from the probe's one `-l` argument, so the argument and the prefix cannot
/// disagree (`probe::AS_NEEDED_LINK_ARG` says why that matters). `None` when the probe does
/// not pass exactly one `-l` argument.
fn as_needed_soname_prefix() -> Option<String> {
    let libs: Vec<&str> = probe::CORPUS
        .iter()
        .filter(|p| p.checks.iter().any(|c| c.id == "as-needed"))
        .flat_map(|p| p.link_libs.iter())
        .filter_map(|arg| arg.strip_prefix("-l"))
        .collect();
    match libs.as_slice() {
        [lib] => Some(format!("lib{lib}.")),
        _ => None,
    }
}

/// The whole `DT_NEEDED` list is in the sentence, because the interesting failure is a libc
/// that merged libm into itself: the entry is then absent from both arms, the controls
/// agree, and a reader needs to see why the check went `probe-invalid`.
static AS_NEEDED: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::Header,
        ElfTable::ProgramHeaders,
        ElfTable::Dynamic,
        ElfTable::DynStr,
    ],
    clauses: vec![
        clause(
            "unclassified",
            Cond::NoneOf(vec![
                Cond::Eq(elf(ElfField::ElfType), "ET_EXEC".to_owned()),
                Cond::Eq(elf(ElfField::ElfType), "ET_DYN".to_owned()),
            ]),
            Conclusion::Indeterminate,
            "the loader cannot run an object of this type",
        ),
        clause(
            "no-dynamic",
            Cond::Eq(elf(ElfField::HasDynamic), "false".to_owned()),
            Conclusion::Indeterminate,
            "the object has no dynamic section",
        ),
        // A -shared link has no startup object to reference the C library.
        clause(
            "shared-output",
            Cond::All(vec![
                Cond::NoneOf(vec![Cond::AnyStartsWith(
                    elf(ElfField::Needed),
                    C_LIBRARY_PREFIX.to_owned(),
                )]),
                truth(ElfField::SharedObject),
            ]),
            Conclusion::Indeterminate,
            "a shared object with no DT_NEEDED entry for the C library is what both a -shared link and a static PIE with neither marker write",
        ),
        clause(
            "no-c-library",
            Cond::NoneOf(vec![Cond::AnyStartsWith(
                elf(ElfField::Needed),
                C_LIBRARY_PREFIX.to_owned(),
            )]),
            Conclusion::Indeterminate,
            "no DT_NEEDED entry names the C library on executable output",
        ),
        as_needed_soname_prefix().map_or_else(
            || {
                clause(
                    "no-library",
                    Cond::All(Vec::new()),
                    Conclusion::Indeterminate,
                    "the as-needed probe links no single library",
                )
            },
            |prefix| {
                clause(
                    "recorded",
                    Cond::AnyStartsWith(elf(ElfField::Needed), prefix),
                    Conclusion::Absent,
                    "DT_NEEDED records the library nothing uses",
                )
            },
        ),
        clause(
            "no-loader-output",
            truth(ElfField::StaticallyLinked),
            Conclusion::Indeterminate,
            "the unused library's entry is missing on output linked with no dynamic loader",
        ),
    ],
    otherwise: Conclusion::Present(LevelOf::None),
});

/// The property means something only for a shared object: an executable does not get text
/// relocations from non-PIC code, it gets a fixed load address. The clause reads `textrel`
/// alone, and the artifact's classification is in the fact store.
static TEXTREL: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::Header,
        ElfTable::ProgramHeaders,
        ElfTable::Dynamic,
    ],
    clauses: vec![clause(
        "textrel",
        truth(ElfField::Textrel),
        word("textrel"),
        "the dynamic section records text relocations",
    )],
    otherwise: Conclusion::Absent,
});

static RELR: LazyLock<Predicate> = LazyLock::new(|| {
    one_bit(
        &[ElfTable::Dynamic],
        ElfField::DtRelr,
        "dt-relr",
        "the dynamic section carries DT_RELR",
    )
});

static CET_MARKED: LazyLock<Predicate> = LazyLock::new(|| {
    two_bit(
        &[ElfTable::Header, ElfTable::Notes],
        ElfField::X86Ibt,
        ElfField::X86Shstk,
        "the x86 feature word",
    )
});

/// The artifact half of `branch-protection-macro`, reading the note `elf.rs` parses.
static BRANCH_PROTECTION_MARKED: LazyLock<Predicate> = LazyLock::new(|| {
    two_bit(
        &[ElfTable::Header, ElfTable::Notes],
        ElfField::Aarch64Bti,
        ElfField::Aarch64Pac,
        "the aarch64 feature word",
    )
});

/// The artifact half of `gcs-macro`, reading bit 2 of the feature word BTI and PAC share.
/// The word is an AND across input objects, so a single unmarked object clears it.
/// Fedora 44's aarch64 startup files carry all three bits, so the AND survives there; see
/// [`branch_protection_marked`] for the measurements on two libcs and the rule under which
/// both checks carry `Confidence::High`.
static GCS_MARKED: LazyLock<Predicate> = LazyLock::new(|| {
    one_bit(
        &[ElfTable::Header, ElfTable::Notes],
        ElfField::Aarch64Gcs,
        "gcs",
        "the aarch64 feature word marks GCS",
    )
});

/// The artifact half of `canary-emitted` and `ssp-covers-small-arrays`: a reference to the
/// function a failed canary check calls.
static CANARY: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::Symbols],
    clauses: vec![clause(
        "stack-chk-fail",
        Cond::Any(vec![
            defined_symbol("__stack_chk_fail"),
            defined_symbol("__stack_chk_fail_local"),
            defined_symbol("__stack_smash_handler"),
        ]),
        Conclusion::Present(LevelOf::None),
        "a symbol table holds the canary failure handler",
    )],
    otherwise: Conclusion::Absent,
});

/// The probe's four functions, one per stack protector rule, in the order the levels add
/// them: admitted by `-fstack-protector-all` alone, by `-strong` too, and two at every
/// level, one through a character array at the default threshold and one through `alloca`
/// at any threshold. `probes/ssp_function_map.c` defines each, which `probe`'s tests hold
/// it to.
pub const SSP_FUNCTIONS: [&str; 4] = ["ssp_any", "ssp_addr_taken", "ssp_char_array", "ssp_alloca"];

/// The external each of [`SSP_FUNCTIONS`] calls, by position: the probe declares both and
/// defines neither, so every object holds a relocation against it from inside the
/// function, at every level and every optimization, canary or not. A call that is never a
/// tail call, since each function uses the result or its local after it. `probe`'s tests
/// hold the probe to the pairing.
pub const SSP_CALLEES: [&str; 4] = ["ssp_use", "ssp_escape", "ssp_escape", "ssp_escape"];

/// The probe's fifth function, the one that tells `-strong`'s selection from `SafeStack`'s: a
/// character array every access to which is masked into range and whose address never
/// escapes. `-strong` and plain `-fstack-protector` admit it; `SafeStack` at `-O1` and above
/// proves it safe and leaves it bare. `probes/ssp_function_map.c` defines it and says why,
/// and `probe`'s tests hold the probe to it as to [`SSP_FUNCTIONS`].
pub const SSP_DISCRIMINATOR: &str = "ssp_safe_array";

/// The external [`SSP_DISCRIMINATOR`] calls, as [`SSP_CALLEES`] pairs each of the four.
pub const SSP_DISCRIMINATOR_CALLEE: &str = "ssp_use";

/// The symbol a function refers to when clang's `SafeStack` gave it an unsafe frame: the
/// thread-local pointer to the unsafe stack, loaded in the prologue of every such function
/// (`R_X86_64_GOTTPOFF` against it on x86_64, measured 2026-10-08 with clang 22.1.8 on
/// Fedora 44 x86_64). The marker is the artifact's own, so it follows the build rather than the
/// flag list: `report::safestack_cross_check` compares the two and says so where they differ.
pub const SAFESTACK_MARKER: &str = "__safestack_unsafe_stack_ptr";

/// The targets that mark a function as canaried, read as prefixes of the referenced name:
/// `__stack_chk_fail` covers its local alias `__stack_chk_fail_local` (i386 under `-fPIC`),
/// `__stack_chk_guard` is the guard where the target loads it from memory rather than from
/// thread-local storage (aarch64, measured), and `__stack_smash_handler` is OpenBSD's
/// handler, as [`CANARY`] reads it.
const SSP_TARGETS: [&str; 3] = [
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__stack_smash_handler",
];

/// The function, or gcc's `.cold` part split from it, refers to a canary target.
fn canaried(function: &str) -> Cond {
    Cond::Any(
        [function.to_owned(), format!("{function}.cold")]
            .iter()
            .flat_map(|name| {
                SSP_TARGETS.iter().map(move |target| {
                    Cond::AnyStartsWith(
                        elf(ElfField::FunctionReferences),
                        format!("{name}:{target}"),
                    )
                })
            })
            .collect(),
    )
}

/// The function, where the object defines it and its call was read, refers to the unsafe
/// stack pointer: `SafeStack` gave it an unsafe frame.
fn unsafe_frame(function: &str) -> Cond {
    Cond::AnyStartsWith(
        elf(ElfField::FunctionReferences),
        format!("{function}:{SAFESTACK_MARKER}"),
    )
}

/// The stack protector level read per function from the object the compiler produced:
/// which of [`SSP_FUNCTIONS`] got a canary, and whether [`SSP_DISCRIMINATOR`] did.
static SSP_LEVEL_EMITTED: LazyLock<Predicate> = LazyLock::new(|| {
    let [any, addr_taken, char_array, alloca] = SSP_FUNCTIONS.map(canaried);
    let not = |c: &Cond| Cond::NoneOf(vec![c.clone()]);
    // The discriminator, read where the object defines it with its call: see
    // `SSP_DISCRIMINATOR` for why it is not roll-called.
    let safe = canaried(SSP_DISCRIMINATOR);
    let safe_read = Cond::AnyStartsWith(
        elf(ElfField::FunctionReferences),
        format!("{SSP_DISCRIMINATOR}:{SSP_DISCRIMINATOR_CALLEE}"),
    );
    // Any code in the object refers to the unsafe stack pointer: SafeStack built a frame
    // somewhere, whether or not in a probe function.
    let safestack = Cond::AnyContains(
        elf(ElfField::FunctionReferences),
        format!(":{SAFESTACK_MARKER}"),
    );
    // SafeStack's rule, function by function: a canary exactly where there is an unsafe
    // frame.
    let canary_iff_unsafe_frame = Cond::All(
        SSP_FUNCTIONS
            .iter()
            .chain(std::iter::once(&SSP_DISCRIMINATOR))
            .map(|f| {
                Cond::Any(vec![
                    Cond::All(vec![canaried(f), unsafe_frame(f)]),
                    Cond::NoneOf(vec![canaried(f), unsafe_frame(f)]),
                ])
            })
            .collect(),
    );
    Predicate {
        tables: vec![
            ElfTable::SectionHeaders,
            ElfTable::Symbols,
            ElfTable::Relocations,
        ],
        clauses: vec![
            clause(
                "not-an-object",
                missing(ElfField::FunctionReferences),
                Conclusion::Indeterminate,
                "the artifact is not a relocatable object with a symbol table",
            ),
            clause(
                "roll-call",
                Cond::NoneOf(vec![Cond::All(
                    SSP_FUNCTIONS
                        .iter()
                        .map(|f| {
                            Cond::AnyStartsWith(elf(ElfField::FunctionReferences), format!("{f}:"))
                        })
                        .collect(),
                )]),
                Conclusion::Indeterminate,
                "a probe function is not in the symbol table",
            ),
            clause(
                "unread-calls",
                Cond::NoneOf(vec![Cond::All(
                    SSP_FUNCTIONS
                        .iter()
                        .zip(SSP_CALLEES)
                        .map(|(f, callee)| {
                            Cond::AnyStartsWith(
                                elf(ElfField::FunctionReferences),
                                format!("{f}:{callee}"),
                            )
                        })
                        .collect(),
                )]),
                // The object must relocate the external call whatever the level.
                Conclusion::Indeterminate,
                "a probe function does not refer to the external it calls",
            ),
            clause(
                "unattributed-canary",
                Cond::Any(
                    SSP_TARGETS
                        .iter()
                        .map(|target| {
                            Cond::AnyStartsWith(
                                elf(ElfField::FunctionReferences),
                                format!("{UNATTRIBUTED_REFERENCE}{target}"),
                            )
                        })
                        .collect(),
                ),
                Conclusion::Indeterminate,
                "code outside every function's range refers to the canary failure handler or the guard",
            ),
            clause(
                "all",
                Cond::All(vec![
                    any.clone(),
                    addr_taken.clone(),
                    char_array.clone(),
                    alloca.clone(),
                    not(&safestack),
                    Cond::Any(vec![not(&safe_read), safe.clone()]),
                ]),
                // The function only `-all` admits has no array and no address taken.
                word("all"),
                "every probe function has a canary",
            ),
            clause(
                "unsafe-frame",
                Cond::All(vec![
                    not(&any),
                    addr_taken.clone(),
                    char_array.clone(),
                    alloca.clone(),
                    safestack.clone(),
                    canary_iff_unsafe_frame,
                ]),
                word(probe::SSP_UNSAFE_FRAME),
                "the functions with a canary are exactly those referring to SafeStack's unsafe stack pointer",
            ),
            clause(
                "strong",
                Cond::All(vec![
                    not(&any),
                    addr_taken.clone(),
                    char_array.clone(),
                    alloca.clone(),
                    not(&safestack),
                    Cond::Any(vec![not(&safe_read), safe.clone()]),
                ]),
                word("strong"),
                "the function whose local's address is taken has a canary and the one with neither array nor address taken does not",
            ),
            clause(
                "basic",
                Cond::All(vec![
                    not(&any),
                    not(&addr_taken),
                    alloca.clone(),
                    not(&safestack),
                    // The two 64-byte character arrays stand or fall together under plain
                    // -fstack-protector, whatever the threshold: see `SSP_DISCRIMINATOR`.
                    Cond::Any(vec![
                        not(&safe_read),
                        Cond::All(vec![char_array.clone(), safe.clone()]),
                        Cond::NoneOf(vec![char_array.clone(), safe.clone()]),
                    ]),
                ]),
                word("basic"),
                "the function calling alloca has a canary and the one whose local's address is taken does not",
            ),
            // Under -fno-stack-protector with SafeStack, the unsafe stack is still in use and
            // still no function has a canary, so this clause reads that build too.
            clause(
                "none",
                Cond::NoneOf(vec![any, addr_taken, char_array, alloca, safe]),
                Conclusion::Absent,
                "no probe function refers to the canary failure handler or the guard",
            ),
        ],
        // Any other row: the functions with a canary fit no level's rule, and no
        // SafeStack rule either.
        otherwise: Conclusion::Indeterminate,
    }
});

/// The `ssp_level_emitted` predicate.
#[must_use]
pub fn ssp_level_emitted() -> &'static Predicate {
    &SSP_LEVEL_EMITTED
}

/// `-D_GLIBCXX_ASSERTIONS` read from the artifact: did the compiler leave libstdc++'s
/// assertion handler behind?
static CXX_ASSERTIONS_SYMBOL: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::Symbols],
    clauses: vec![
        clause(
            "libc++",
            Cond::Eq(Term::CxxStdlib, "libc++".to_owned()),
            Conclusion::Indeterminate,
            "libc++ routes precondition failures through __libcpp_verbose_abort",
        ),
        clause(
            "debug-mode",
            Cond::AnyContains(Term::SymbolNames, "_Error_formatter".to_owned()),
            Conclusion::Present(LevelOf::None),
            "-D_GLIBCXX_DEBUG supersedes _GLIBCXX_ASSERTIONS and leaves __gnu_debug's \
             _Error_formatter in its place",
        ),
        clause(
            "handler",
            Cond::Any(vec![
                defined_symbol("_ZSt21__glibcxx_assert_failPKciS0_S0_"),
                defined_symbol("_ZSt20__replacement_assertPKciS0_S0_"),
            ]),
            Conclusion::Present(LevelOf::None),
            "a symbol table holds libstdc++'s assertion handler",
        ),
    ],
    otherwise: Conclusion::Absent,
});

/// The section-name prefix OpenBSD's clang gives each RETGUARD cookie's COMDAT section.
pub const RETGUARD_SECTION_PREFIX: &str = ".openbsd.randomdata.retguard.";

/// `-fret-protector` (OpenBSD's RETGUARD) read from the object the compiler produced: a
/// section holding a per-function return-address cookie.
static RET_PROTECTOR: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::SectionHeaders, ElfTable::SectionNames],
    clauses: vec![clause(
        "retguard-section",
        Cond::AnyStartsWith(elf(ElfField::Sections), RETGUARD_SECTION_PREFIX.to_owned()),
        Conclusion::Present(LevelOf::None),
        "the object holds a RETGUARD cookie section",
    )],
    otherwise: Conclusion::Absent,
});

/// The `ret_protector` predicate.
#[must_use]
pub fn ret_protector() -> &'static Predicate {
    &RET_PROTECTOR
}

/// The section-name prefix of the table that describes a function's landing pads.
pub const EXCEPT_TABLE_SECTION_PREFIX: &str = ".gcc_except_table";

/// The section-name prefix of the relocation section for 32-bit ARM's exception-handling
/// table, which carries a landing-pad table's personality routine there: see
/// [`except_table`].
pub const EHABI_EXCEPT_TABLE_RELOCATION_PREFIX: &str = ".rel.ARM.extab";

/// `-fexceptions` in C read from the object the compiler produced: a `.gcc_except_table`
/// section, the language-specific data area that lists a function's landing pads.
static EXCEPT_TABLE: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::SectionHeaders, ElfTable::SectionNames],
    clauses: vec![
        clause(
            "except-table",
            Cond::AnyStartsWith(
                elf(ElfField::Sections),
                EXCEPT_TABLE_SECTION_PREFIX.to_owned(),
            ),
            Conclusion::Present(LevelOf::None),
            "the object holds a .gcc_except_table, the landing-pad table a cleanup region gets \
             only under -fexceptions",
        ),
        clause(
            "ehabi-except-table",
            Cond::AnyStartsWith(
                elf(ElfField::Sections),
                EHABI_EXCEPT_TABLE_RELOCATION_PREFIX.to_owned(),
            ),
            // ARM's unwind table gets the relocation section where an entry names a
            // personality routine.
            Conclusion::Present(LevelOf::None),
            "the object holds a .rel.ARM.extab",
        ),
    ],
    otherwise: Conclusion::Absent,
});

/// `-z separate-code` read from the linked program: does any page an executable segment
/// maps hold bytes the linker did not mark as instructions?
static SEPARATE_CODE: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::ProgramHeaders,
        ElfTable::SectionHeaders,
        ElfTable::SectionNames,
    ],
    clauses: vec![
        clause(
            "unclassified",
            missing(ElfField::DataInCodePages),
            Conclusion::Indeterminate,
            "the object has no executable segment",
        ),
        clause(
            "data-in-code-pages",
            Cond::NonEmpty(elf(ElfField::DataInCodePages)),
            Conclusion::Absent,
            "a page an executable PT_LOAD maps holds an allocated section that is not code",
        ),
    ],
    otherwise: Conclusion::Present(LevelOf::None),
});

/// The `separate_code` predicate.
#[must_use]
pub fn separate_code() -> &'static Predicate {
    &SEPARATE_CODE
}

/// The global `probes/pic_object_relocs.c` defines, exports and reads.
pub const PIC_OBJECT_ANCHOR: &str = "chard_pic_object_anchor";

/// The relocation types through which code reaches a global by way of the GOT, as
/// measured against [`PIC_OBJECT_ANCHOR`] under `-fPIC` or `-fpic`: x86_64 relaxable and
/// not (`-Wa,-mrelax-relocations=no`), x86_64 `-mcmodel=large`, i386 relaxable and not,
/// aarch64's small model, its `-fpic` form and its tiny model.
pub const PIC_OBJECT_GOT_TYPES: &[&str] = &[
    "R_X86_64_REX_GOTPCRELX",
    "R_X86_64_GOTPCREL",
    "R_X86_64_GOT64",
    "R_386_GOT32X",
    "R_386_GOT32",
    "R_AARCH64_ADR_GOT_PAGE",
    "R_AARCH64_LD64_GOT_LO12_NC",
    "R_AARCH64_LD64_GOTPAGE_LO15",
    "R_AARCH64_GOT_LD_PREL19",
];

/// The relocation types through which code reaches a global directly, as measured
/// against [`PIC_OBJECT_ANCHOR`] under `-fPIE`, `-fpie` and `-fno-pic`: x86_64
/// PC-relative, absolute (without PIC: clang at every level, gcc on the 4096-byte array),
/// large-model absolute and GOT-relative; i386 GOT-relative (an offset from the GOT's
/// base, which addresses the object itself rather than a GOT slot) and absolute; aarch64
/// page-relative, tiny-model, and large-model absolute.
pub const PIC_OBJECT_DIRECT_TYPES: &[&str] = &[
    "R_X86_64_PC32",
    "R_X86_64_32S",
    "R_X86_64_64",
    "R_X86_64_GOTOFF64",
    "R_386_GOTOFF",
    "R_386_32",
    "R_AARCH64_ADR_PREL_PG_HI21",
    "R_AARCH64_ADD_ABS_LO12_NC",
    "R_AARCH64_ADR_PREL_LO21",
    "R_AARCH64_ABS64",
    "R_AARCH64_MOVW_UABS_G0_NC",
    "R_AARCH64_MOVW_UABS_G1_NC",
    "R_AARCH64_MOVW_UABS_G2_NC",
    "R_AARCH64_MOVW_UABS_G3",
];

/// Some code relocation names [`PIC_OBJECT_ANCHOR`] with one of `types`.
fn names_anchor_with(types: &[&str]) -> Cond {
    Cond::Any(
        types
            .iter()
            .map(|t| {
                Cond::AnyStartsWith(
                    elf(ElfField::CodeRelocations),
                    format!("{t} {PIC_OBJECT_ANCHOR}"),
                )
            })
            .collect(),
    )
}

/// `-fPIC` read from the object the compiler wrote: does the code reach a defined,
/// exported global through the GOT, which it does only when the global may be preempted
/// by another module, that is, only when the code is built for a shared object?
static PIC_OBJECT: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::Header,
        ElfTable::SectionHeaders,
        ElfTable::Symbols,
        ElfTable::Relocations,
    ],
    clauses: vec![
        clause(
            "unclassified",
            missing(ElfField::CodeRelocations),
            Conclusion::Indeterminate,
            "the artifact is not a relocatable object with a section-header table",
        ),
        clause(
            "anchor-not-default",
            Cond::AnyContains(
                elf(ElfField::CodeRelocations),
                format!("{PIC_OBJECT_ANCHOR} STV_"),
            ),
            Conclusion::Indeterminate,
            "the probe's global lost its default visibility",
        ),
        clause(
            "mixed",
            Cond::All(vec![
                names_anchor_with(PIC_OBJECT_GOT_TYPES),
                names_anchor_with(PIC_OBJECT_DIRECT_TYPES),
            ]),
            Conclusion::Indeterminate,
            "the code reaches the probe's global both through the GOT and directly",
        ),
        clause(
            "got",
            names_anchor_with(PIC_OBJECT_GOT_TYPES),
            Conclusion::Present(LevelOf::None),
            "the code reaches the probe's exported global through the GOT",
        ),
        clause(
            "direct",
            names_anchor_with(PIC_OBJECT_DIRECT_TYPES),
            Conclusion::Absent,
            "the code reaches the probe's exported global directly",
        ),
    ],
    otherwise: Conclusion::Indeterminate,
});

/// The `pic_object` predicate.
#[must_use]
pub fn pic_object() -> &'static Predicate {
    &PIC_OBJECT
}

/// The `except_table` predicate.
#[must_use]
pub fn except_table() -> &'static Predicate {
    &EXCEPT_TABLE
}

/// gcc's `-ftrapv` read from the object it compiled: a symbol-table entry for one of
/// libgcc's trapping helpers for `int`, `__addvsi3`, `__subvsi3` or `__mulvsi3`, which gcc
/// calls in place of the signed arithmetic in `probes/trapv_helper.c`.
static TRAPV_HELPER: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::Symbols],
    clauses: vec![clause(
        "trapv-helper",
        Cond::Any(vec![
            defined_symbol("__addvsi3"),
            defined_symbol("__subvsi3"),
            defined_symbol("__mulvsi3"),
        ]),
        Conclusion::Present(LevelOf::None),
        "the object's symbol table names a libgcc trapping helper for int arithmetic",
    )],
    otherwise: Conclusion::Absent,
});

/// The `trapv_helper` predicate.
#[must_use]
pub fn trapv_helper() -> &'static Predicate {
    &TRAPV_HELPER
}

/// The function `probes/optimization_applied.c` defines, whose relocations
/// `OPTIMIZATION_APPLIED` reads.
pub const OPTIMIZATION_FUNCTION: &str = "chard_opt_probe";

/// The external that function calls behind a branch on a local zero, which only an
/// unoptimised build keeps.
pub const OPTIMIZATION_DEAD_CALLEE: &str = "chard_opt_dead";

/// The external that function calls unconditionally, at every level.
pub const OPTIMIZATION_ANCHOR_CALLEE: &str = "chard_opt_anchor";

/// Whether the compiler optimised, read from the object `probes/optimization_applied.c`
/// compiles to: `chard_opt_probe` calls `chard_opt_dead` only behind a branch on a local
/// that is zero, so an object whose function still refers to it was built unoptimised, and
/// one whose function refers to its unconditional callee `chard_opt_anchor` and not to
/// `chard_opt_dead` was built at a level above `-O0`, every one of which removes the call in
/// the compilers measured. Which pass removes it is not what the reading rests on: gcc
/// still removes it with its constant propagation and the passes beside it turned off (the
/// list below). The fact is [`crate::elf::ElfFacts::function_references`].
static OPTIMIZATION_APPLIED: LazyLock<Predicate> = LazyLock::new(|| {
    let f = OPTIMIZATION_FUNCTION;
    let reference = |callee: &str| {
        Cond::AnyStartsWith(elf(ElfField::FunctionReferences), format!("{f}:{callee}"))
    };
    Predicate {
        tables: vec![
            ElfTable::SectionHeaders,
            ElfTable::Symbols,
            ElfTable::Relocations,
        ],
        clauses: vec![
            // The reader attributes references only in a relocatable object with a symbol
            // table it can place.
            clause(
                "not-an-object",
                missing(ElfField::FunctionReferences),
                Conclusion::Indeterminate,
                "the reader attributes no reference to a function in this artifact",
            ),
            // A function goes unlisted when it is absent from the symbol table or sits in a
            // section the reader cannot place.
            clause(
                "roll-call",
                Cond::NoneOf(vec![Cond::AnyStartsWith(
                    elf(ElfField::FunctionReferences),
                    format!("{f}:"),
                )]),
                Conclusion::Indeterminate,
                "the probe function is not listed with its references",
            ),
            clause(
                "unread-call",
                Cond::NoneOf(vec![reference(OPTIMIZATION_ANCHOR_CALLEE)]),
                Conclusion::Indeterminate,
                "the probe function does not refer to the external it calls at every level",
            ),
            clause(
                "unattributed-call",
                Cond::AnyStartsWith(
                    elf(ElfField::FunctionReferences),
                    format!("{UNATTRIBUTED_REFERENCE}{OPTIMIZATION_DEAD_CALLEE}"),
                ),
                Conclusion::Indeterminate,
                "code outside every function's range refers to the external called only behind the folded branch",
            ),
            clause(
                "dead-call-kept",
                reference(OPTIMIZATION_DEAD_CALLEE),
                Conclusion::Absent,
                "the probe function still calls the external behind a branch on a local zero",
            ),
            clause(
                "call-elsewhere",
                Cond::AnyContains(
                    elf(ElfField::FunctionReferences),
                    format!(":{OPTIMIZATION_DEAD_CALLEE}"),
                ),
                Conclusion::Indeterminate,
                "another function of the object refers to the external behind the folded branch",
            ),
        ],
        otherwise: Conclusion::Present(LevelOf::None),
    }
});

/// The `optimization_applied` predicate.
#[must_use]
pub fn optimization_applied() -> &'static Predicate {
    &OPTIMIZATION_APPLIED
}

/// The function `probes/ubsan_trap.c` defines for the code reader to search, which
/// `elf::code::SCANS` lists.
pub const UBSAN_TRAP_FUNCTION: &str = "chard_ubsan_trap_probe";

/// The prefix every sanitizer runtime handler's name starts with. `elf::WATCHED_SYMBOLS`
/// lists the handlers the probe's functions call, in every spelling measured, so
/// `symbol-names` holds one of them wherever the object calls the runtime.
const UBSAN_HANDLER_PREFIX: &str = "__ubsan_handle_";

/// Every trap pattern, whatever check it carries: a trap beside a handler or a call is
/// read through these.
const UBSAN_ANY_TRAP: [&str; 4] = ["x86-ud2", "x86-ud1", "a64-brk", "a64-brk-clang-check"];

/// The trap patterns an `on` is read from, the level word each publishes, and why. clang's
/// leave out its trap for check 0, signed overflow on an add, which clang's `-ftrapv` also
/// emits.
const UBSAN_TRAP_PATTERNS: [(&[&str], &str, &str); 3] = [
    (
        &["x86-ud2"],
        "ud2",
        "the probe's function holds ud2, gcc's trap for a failed sanitizer check",
    ),
    (
        &["x86-ud1-check"],
        "ud1",
        "the probe's function holds ud1 with a nonzero check number, clang's trap for a \
         failed sanitizer check other than signed overflow",
    ),
    (
        &["a64-brk-check", "a64-brk-clang-check"],
        "brk",
        "the probe's function holds brk other than clang's brk #0x5500, the aarch64 trap \
         both compilers emit for a failed sanitizer check",
    ),
];

/// gcc's cold part of the probe's function, where -O2 can move a failed check's trap.
const UBSAN_TRAP_COLD: &str = "chard_ubsan_trap_probe.cold";

/// The probe's second function, a construct for each sanitizer group the first does not
/// exercise, which `elf::code::SCANS` lists with its own patterns.
pub const UBSAN_TRAP_GROUPS: &str = "chard_ubsan_trap_groups";

/// gcc's cold part of the second function.
const UBSAN_TRAP_GROUPS_COLD: &str = "chard_ubsan_trap_groups.cold";

/// The probe's third function, an indexed access to a global array of known size, which
/// gcc checks under `object-size` and clang under `local-bounds`; `elf::code::SCANS` lists
/// it with the trap patterns alone.
pub const UBSAN_TRAP_SIZED: &str = "chard_ubsan_trap_sized";

/// gcc's cold part of the third function.
const UBSAN_TRAP_SIZED_COLD: &str = "chard_ubsan_trap_sized.cold";

/// The probe's fourth function, a call through a function pointer, which clang checks
/// under `function`; `elf::code::SCANS` lists it with clang's trap patterns alone.
pub const UBSAN_TRAP_INDIRECT: &str = "chard_ubsan_trap_indirect";

/// gcc's cold part of the fourth function.
const UBSAN_TRAP_INDIRECT_COLD: &str = "chard_ubsan_trap_indirect.cold";

/// Every function a trap or a call is read in.
const UBSAN_TRAP_FUNCTIONS: [&str; 8] = [
    UBSAN_TRAP_FUNCTION,
    UBSAN_TRAP_COLD,
    UBSAN_TRAP_GROUPS,
    UBSAN_TRAP_GROUPS_COLD,
    UBSAN_TRAP_SIZED,
    UBSAN_TRAP_SIZED_COLD,
    UBSAN_TRAP_INDIRECT,
    UBSAN_TRAP_INDIRECT_COLD,
];

/// The symbol `probes/ubsan_trap.c` defines where the compiler reports an
/// undefined-behavior sanitizer group enabled; `elf::WATCHED_SYMBOLS` lists it.
pub const UBSAN_TRAP_FEATURE: &str = "chard_ubsan_trap_feature";

/// The call patterns, whose match with neither a trap nor a handler is withheld: on x86_64
/// a relocated `call`, a `call` through the GOT, and under `-mcmodel=large` a `call` through
/// a register or through a GOT entry two registers address; `bl` or `blr` on aarch64.
const UBSAN_CALL_PATTERNS: [&str; 6] = [
    "x86-call-rel32",
    "x86-call-got",
    "x86-call-reg",
    "x86-call-sib",
    "a64-bl",
    "a64-blr",
];

/// A match of `pattern` in any of the probe's functions or in a cold part of one.
fn ubsan_trap_matched(pattern: &str) -> Cond {
    Cond::Any(
        UBSAN_TRAP_FUNCTIONS
            .iter()
            .map(|function| {
                Cond::AnyStartsWith(elf(ElfField::CodeMatches), format!("{function}:{pattern}@"))
            })
            .collect(),
    )
}

fn ubsan_trap_searched(function: &str, pattern: &str) -> Cond {
    Cond::AnyStartsWith(elf(ElfField::CodeScanned), format!("{function}:{pattern}="))
}

/// `function` was searched for a trap, on a machine the trap patterns are for.
fn ubsan_function_searched(function: &str) -> Cond {
    Cond::Any(vec![
        Cond::All(vec![
            ubsan_trap_searched(function, "x86-ud2"),
            ubsan_trap_searched(function, "x86-ud1"),
        ]),
        ubsan_trap_searched(function, "a64-brk"),
    ])
}

/// The function that calls through a pointer was searched for clang's trap, the one
/// pattern per machine `elf::code::SCANS` lists it with.
fn ubsan_indirect_searched() -> Cond {
    Cond::Any(vec![
        ubsan_trap_searched(UBSAN_TRAP_INDIRECT, "x86-ud1"),
        ubsan_trap_searched(UBSAN_TRAP_INDIRECT, "a64-brk-clang-check"),
    ])
}

/// `-fsanitize-trap=undefined` read from the code of the probe's own functions: a trap
/// instruction where a handler-mode build has a call to the sanitizer runtime, and no
/// handler referenced beside it.
static UBSAN_TRAP: LazyLock<Predicate> = LazyLock::new(|| {
    let traps = Cond::Any(
        UBSAN_ANY_TRAP
            .iter()
            .map(|pattern| ubsan_trap_matched(pattern))
            .collect(),
    );
    let handlers = Cond::AnyStartsWith(Term::SymbolNames, UBSAN_HANDLER_PREFIX.to_owned());
    let calls = Cond::Any(
        UBSAN_CALL_PATTERNS
            .iter()
            .map(|pattern| ubsan_trap_matched(pattern))
            .collect(),
    );
    let mut clauses = vec![
        clause(
            "function-unsearched",
            Cond::NoneOf(vec![ubsan_function_searched(UBSAN_TRAP_FUNCTION)]),
            Conclusion::Indeterminate,
            "the probe's function was not searched for a trap",
        ),
        clause(
            "trap-beside-handler",
            Cond::All(vec![traps.clone(), handlers.clone()]),
            Conclusion::Indeterminate,
            "the function traps and the object also calls a sanitizer runtime handler",
        ),
        // The probe's source calls nothing, so a call in a probe function is the compiler's.
        clause(
            "trap-beside-call",
            Cond::All(vec![traps.clone(), calls.clone()]),
            Conclusion::Indeterminate,
            "the function traps and also makes a compiler-added call",
        ),
    ];
    clauses.extend(
        UBSAN_TRAP_PATTERNS
            .iter()
            .map(|(patterns, level, because)| {
                let matched = Cond::Any(
                    patterns
                        .iter()
                        .map(|pattern| ubsan_trap_matched(pattern))
                        .collect(),
                );
                clause(level, matched, word(level), because)
            }),
    );
    // After the level clauses, so it reads only traps none of them took.
    clauses.push(clause(
        "overflow-trap-only",
        traps,
        Conclusion::Indeterminate,
        "the function's only traps are clang's -ftrapv signed-overflow trap on an add",
    ));
    // After the trap clauses, so it reads only a function with no trap; the handler clause
    // keeps handler mode, whose failed checks are calls, at `absent`.
    clauses.push(clause(
        "call-without-trap-or-handler",
        Cond::All(vec![calls, Cond::NoneOf(vec![handlers.clone()])]),
        Conclusion::Indeterminate,
        "the function makes a compiler-added call, holds no trap",
    ));
    // After every clause that reads a trap, so a trap in the first function reads as trap
    // mode whether or not the others are there; before `otherwise`, so no `absent` is read
    // over constructs that were not there to search.
    clauses.push(clause(
        "groups-unsearched",
        Cond::NoneOf(vec![Cond::All(vec![
            ubsan_function_searched(UBSAN_TRAP_GROUPS),
            ubsan_function_searched(UBSAN_TRAP_SIZED),
            ubsan_indirect_searched(),
        ])]),
        Conclusion::Indeterminate,
        "one of the probe's construct functions was not found in the object",
    ));
    // Last, so it reads only an object with no trap, no call the handlers do not account
    // for, and every function searched.
    clauses.push(clause(
        "sanitizer-group-unexercised",
        Cond::All(vec![
            Cond::Truth(Term::Symbol(UBSAN_TRAP_FEATURE.to_owned())),
            Cond::NoneOf(vec![handlers]),
        ]),
        Conclusion::Indeterminate,
        // The group enabled is then one the probe holds no construct for.
        "the compiler reports an undefined-behavior sanitizer group enabled",
    ));
    Predicate {
        tables: vec![ElfTable::SectionHeaders, ElfTable::Symbols, ElfTable::Code],
        clauses,
        otherwise: Conclusion::Absent,
    }
});

/// The `ubsan_trap` predicate.
#[must_use]
pub fn ubsan_trap() -> &'static Predicate {
    &UBSAN_TRAP
}

/// The function `probes/fortify_printf_flag.c` defines for its `printf`, and clang's two
/// spellings of glibc's out-of-line wrapper, each an `elf::code::SCANS` entry searched for
/// the flag argument.
const FORTIFY_FLAG_FUNCTIONS: [&str; 3] = [
    "chard_fortify_printf_probe",
    "_ZL6printfPKcU17pass_object_size1z",
    "_ZL6printfPKcU25pass_dynamic_object_size1z",
];

/// The patterns for each flag value, `__USE_FORTIFY_LEVEL - 1`.
const FORTIFY_FLAG_1: [&str; 3] = ["x86-mov-edi-1", "x86-push-1", "a64-mov-w0-1"];
const FORTIFY_FLAG_2: [&str; 3] = ["x86-mov-edi-2", "x86-push-2", "a64-mov-w0-2"];

/// The checking `printf` entries, gcc's and clang's.
const PRINTF_CHK: [&str; 2] = ["__printf_chk", "__vprintf_chk"];

fn fortify_flag(patterns: &[&str]) -> Cond {
    Cond::Any(
        FORTIFY_FLAG_FUNCTIONS
            .iter()
            .flat_map(|function| {
                patterns.iter().map(move |pattern| {
                    Cond::AnyStartsWith(
                        elf(ElfField::CodeMatches),
                        format!("{function}:{pattern}@"),
                    )
                })
            })
            .collect(),
    )
}

/// `_FORTIFY_SOURCE`'s level read from the object's code: the flag argument glibc passes a
/// checking `printf`, and the `__strcpy_chk` call that level 1 already makes.
static FORTIFY_PRINTF_FLAG: LazyLock<Predicate> = LazyLock::new(|| {
    let printf_chk = Cond::Any(PRINTF_CHK.iter().map(|name| defined_symbol(name)).collect());
    let flag_1 = fortify_flag(&FORTIFY_FLAG_1);
    let flag_2 = fortify_flag(&FORTIFY_FLAG_2);
    let any_flag = Cond::Any(vec![flag_1.clone(), flag_2.clone()]);
    Predicate {
        tables: vec![ElfTable::SectionHeaders, ElfTable::Symbols, ElfTable::Code],
        clauses: vec![
            clause(
                "function-unsearched",
                Cond::NoneOf(vec![Cond::AnyStartsWith(
                    elf(ElfField::CodeScanned),
                    format!("{}:", FORTIFY_FLAG_FUNCTIONS[0]),
                )]),
                Conclusion::Indeterminate,
                "the probe's printf function was not searched",
            ),
            clause(
                "both-flags",
                Cond::All(vec![flag_1.clone(), flag_2.clone()]),
                Conclusion::Indeterminate,
                "both flag values were found, so the code names no one level",
            ),
            clause(
                "printf-chk-without-flag",
                Cond::All(vec![
                    printf_chk.clone(),
                    Cond::NoneOf(vec![any_flag.clone()]),
                ]),
                Conclusion::Indeterminate,
                "a checking printf is called and no flag argument was found in the searched code",
            ),
            clause(
                "flag-without-printf-chk",
                Cond::All(vec![any_flag, Cond::NoneOf(vec![printf_chk])]),
                Conclusion::Indeterminate,
                "a flag pattern was found and no checking printf is referenced",
            ),
            clause(
                "freebsd-unoptimized",
                Cond::All(vec![
                    Cond::Defined(Term::Macro("__FreeBSD__".to_owned())),
                    Cond::Missing(Term::Macro("__OPTIMIZE__".to_owned())),
                    defined_symbol("__strcpy_chk"),
                ]),
                Conclusion::Indeterminate,
                "FreeBSD's <ssp/string.h> wrappers are referenced without optimization",
            ),
            clause(
                "level-3",
                flag_2,
                word("3"),
                "printf's checking call is passed flag 2, glibc's argument at level 3",
            ),
            clause(
                "level-2",
                flag_1,
                word("2"),
                "printf's checking call is passed flag 1, glibc's argument at level 2",
            ),
            clause(
                "level-1",
                defined_symbol("__strcpy_chk"),
                word("1"),
                "printf is not wrapped and strcpy calls __strcpy_chk",
            ),
        ],
        otherwise: Conclusion::Absent,
    }
});

/// The `fortify_printf_flag` predicate.
#[must_use]
pub fn fortify_printf_flag() -> &'static Predicate {
    &FORTIFY_PRINTF_FLAG
}

/// `endbr64` (`f3 0f 1e fa`), the x86_64 landing pad, as `elf::entry` spells it.
pub const ENDBR64: &str = "f30f1efa";
/// `endbr32` (`f3 0f 1e fb`), the i386 landing pad.
pub const ENDBR32: &str = "f30f1efb";

/// Every function `elf::entry` read begins with `pad`.
fn every_entry_is(pad: &str) -> Cond {
    Cond::All(
        crate::elf::entry::ENTRY_FUNCTIONS
            .iter()
            .map(|f| Cond::AnyStartsWith(elf(ElfField::FunctionEntries), format!("{f}={pad}")))
            .collect(),
    )
}

/// `-fcf-protection=branch` (or `=full`) read from the code the compiler generated: every
/// one of the `cet-endbr` probe's functions begins with the IBT landing pad for the
/// object's machine, `endbr64` on x86_64 and `endbr32` on i386.
static CET_ENDBR: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::Header,
        ElfTable::SectionHeaders,
        ElfTable::Symbols,
        ElfTable::FunctionEntries,
    ],
    clauses: vec![
        clause(
            "function-unread",
            Cond::NoneOf(vec![Cond::All(
                crate::elf::entry::ENTRY_FUNCTIONS
                    .iter()
                    .map(|f| Cond::AnyStartsWith(elf(ElfField::FunctionEntries), format!("{f}=")))
                    .collect(),
            )]),
            Conclusion::Indeterminate,
            "a function of the probe's was not read",
        ),
        clause(
            "machine-without-ibt",
            Cond::NoneOf(vec![
                Cond::Eq(elf(ElfField::Machine), "x86_64".to_owned()),
                Cond::Eq(elf(ElfField::Machine), "i386".to_owned()),
            ]),
            Conclusion::Indeterminate,
            "the object's machine has no IBT landing pad to look for",
        ),
        clause(
            "endbr64",
            Cond::All(vec![
                Cond::Eq(elf(ElfField::Machine), "x86_64".to_owned()),
                every_entry_is(ENDBR64),
            ]),
            Conclusion::Present(LevelOf::None),
            "every one of the probe's functions begins with endbr64",
        ),
        clause(
            "endbr32",
            Cond::All(vec![
                Cond::Eq(elf(ElfField::Machine), "i386".to_owned()),
                every_entry_is(ENDBR32),
            ]),
            Conclusion::Present(LevelOf::None),
            "every one of the probe's functions begins with endbr32",
        ),
        clause(
            "landing-pad-partial",
            Cond::Any(vec![
                Cond::AnyContains(elf(ElfField::FunctionEntries), format!("={ENDBR64}")),
                Cond::AnyContains(elf(ElfField::FunctionEntries), format!("={ENDBR32}")),
            ]),
            Conclusion::Indeterminate,
            "some of the probe's functions begin with a landing pad and others do not",
        ),
    ],
    otherwise: Conclusion::Absent,
});

/// The `cet_endbr` predicate.
#[must_use]
pub fn cet_endbr() -> &'static Predicate {
    &CET_ENDBR
}

/// The function the `no-plt` probe calls and never takes the address of.
pub const NO_PLT_CALLEE: &str = "chard_no_plt_callee";

/// The relocation types of a call compiled to go through the callee's GOT slot, as
/// `elf::reloc_type_name` names them: what -fno-plt emits.
pub const GOT_CALL_TYPES: &[&str] = &[
    "R_X86_64_GOTPCRELX",
    "R_X86_64_REX_GOTPCRELX",
    "R_X86_64_GOTPCREL",
    "R_386_GOT32X",
    "R_386_GOT32",
    "R_AARCH64_ADR_GOT_PAGE",
    "R_AARCH64_LD64_GOT_LO12_NC",
    "R_AARCH64_GOT_LD_PREL19",
    "R_AARCH64_LD64_GOTPAGE_LO15",
    "R_RISCV_GOT_HI20",
];

/// The relocation types of a direct call to an external function, which the linker routes
/// through a PLT entry when the callee is in another module: what the object carries
/// without -fno-plt. `R_X86_64_PC32` and `R_386_PC32` are the non-PIC spellings (i386's
/// under `-fno-pic` in Debian 12's gcc 12.2.0, measured 2026-10-02), and `R_AARCH64_JUMP26`
/// is a tail call. RISC-V's call is `R_RISCV_CALL_PLT` under every position-independence
/// choice (gcc 16.1.1 and clang 22.1.8, Fedora 44 x86_64 cross, 2026-10-05). The deprecated
/// `R_RISCV_CALL` is not here: no toolchain on hand writes it, so no build measured the
/// reading, and an object carrying it reads `indeterminate`.
pub const PLT_CALL_TYPES: &[&str] = &[
    "R_X86_64_PLT32",
    "R_X86_64_PC32",
    "R_386_PLT32",
    "R_386_PC32",
    "R_AARCH64_CALL26",
    "R_AARCH64_JUMP26",
    "R_RISCV_CALL_PLT",
];

/// The callee named under any of `types` in `code_relocations`, whose entries are `TYPE
/// SYMBOL`, with a visibility other than `STV_DEFAULT` as a third word. Matched by prefix,
/// which `a_prefix_match_on_a_relocation_is_an_exact_one` holds to be exact.
fn callee_relocated(types: &[&str]) -> Cond {
    Cond::Any(
        types
            .iter()
            .map(|t| {
                Cond::AnyStartsWith(
                    elf(ElfField::CodeRelocations),
                    format!("{t} {NO_PLT_CALLEE}"),
                )
            })
            .collect(),
    )
}

/// -fno-plt read from the object it compiled: is the `no-plt` probe's one external call
/// relocated through the callee's GOT slot, or as a direct call a PLT entry serves?
static PLT_BYPASSED: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![
        ElfTable::Header,
        ElfTable::SectionHeaders,
        ElfTable::Symbols,
        ElfTable::Relocations,
    ],
    clauses: vec![
        clause(
            "not-relocatable",
            missing(ElfField::CodeRelocations),
            Conclusion::Indeterminate,
            "the object is not relocatable or has no section headers",
        ),
        clause(
            "both-forms",
            Cond::All(vec![
                callee_relocated(GOT_CALL_TYPES),
                callee_relocated(PLT_CALL_TYPES),
            ]),
            Conclusion::Indeterminate,
            "the probe's one external call is relocated both through the GOT and as a direct call",
        ),
        clause(
            "got-call",
            callee_relocated(GOT_CALL_TYPES),
            Conclusion::Present(LevelOf::None),
            "the probe's external call is relocated through the callee's GOT slot",
        ),
        clause(
            "plt-call",
            callee_relocated(PLT_CALL_TYPES),
            Conclusion::Absent,
            "the probe's external call is a direct call the linker routes through a PLT \
             entry",
        ),
    ],
    otherwise: Conclusion::Indeterminate,
});

/// The `plt_bypassed` predicate.
#[must_use]
pub fn plt_bypassed() -> &'static Predicate {
    &PLT_BYPASSED
}

/// The `pie` predicate.
#[must_use]
pub fn pie() -> &'static Predicate {
    &PIE
}

/// The `relro` predicate.
#[must_use]
pub fn relro() -> &'static Predicate {
    &RELRO
}

/// The `noexecstack` predicate.
#[must_use]
pub fn noexecstack() -> &'static Predicate {
    &NOEXECSTACK
}

/// The `rwx_segment` predicate.
#[must_use]
pub fn rwx_segment() -> &'static Predicate {
    &RWX_SEGMENT
}

/// The `rwx_segment` predicate: `rwx-segment-absent`'s decoder.
static RWX_SEGMENT: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::Header, ElfTable::ProgramHeaders],
    clauses: vec![
        unclassified(&[ElfField::RwxSegment], "load-segment flags"),
        clause(
            "rwx",
            truth(ElfField::RwxSegment),
            Conclusion::Present(LevelOf::None),
            "a PT_LOAD or PT_TLS segment carries both PF_W and PF_X",
        ),
    ],
    otherwise: Conclusion::Absent,
});

/// The `nodlopen` predicate.
#[must_use]
pub fn nodlopen() -> &'static Predicate {
    &NODLOPEN
}

/// The `rpath` predicate.
#[must_use]
pub fn rpath() -> &'static Predicate {
    &RPATH
}

/// The `as_needed` predicate.
#[must_use]
pub fn as_needed() -> &'static Predicate {
    &AS_NEEDED
}

/// The `textrel` predicate.
#[must_use]
pub fn textrel() -> &'static Predicate {
    &TEXTREL
}

/// The `relr` predicate.
#[must_use]
pub fn relr() -> &'static Predicate {
    &RELR
}

/// The `cet_marked` predicate.
#[must_use]
pub fn cet_marked() -> &'static Predicate {
    &CET_MARKED
}

/// The `branch_protection_marked` predicate.
#[must_use]
pub fn branch_protection_marked() -> &'static Predicate {
    &BRANCH_PROTECTION_MARKED
}

/// The `gcs_marked` predicate.
#[must_use]
pub fn gcs_marked() -> &'static Predicate {
    &GCS_MARKED
}

/// The `canary` predicate.
#[must_use]
pub fn canary() -> &'static Predicate {
    &CANARY
}

/// The `cxx_assertions_symbol` predicate.
#[must_use]
pub fn cxx_assertions_symbol() -> &'static Predicate {
    &CXX_ASSERTIONS_SYMBOL
}

/// The elf-static checks' predicates, keyed by check id.
#[must_use]
pub fn table() -> &'static [Entry] {
    &[
        ("pie", pie),
        ("relro", relro),
        ("noexecstack", noexecstack),
        ("rwx-segment-absent", rwx_segment),
        ("separate-code", separate_code),
        ("linker-default-noexecstack", noexecstack),
        ("rpath-absent", rpath),
        ("relative-relocs", relr),
        ("nodlopen", nodlopen),
        ("textrel-absent", textrel),
        ("as-needed", as_needed),
        ("cet-marked", cet_marked),
        ("cet-marked-object", cet_marked),
        ("branch-protection-marked", branch_protection_marked),
        ("gcs-marked", gcs_marked),
        ("canary-emitted", canary),
        ("ssp-covers-small-arrays", canary),
        ("ssp-level-emitted", ssp_level_emitted),
        ("cxx-assertions-symbol", cxx_assertions_symbol),
        ("ret-protector-emitted", ret_protector),
        ("except-table-emitted", except_table),
        ("ubsan-trap-mode", ubsan_trap),
        ("fortify-printf-flag", fortify_printf_flag),
        ("trapv-helper-called", trapv_helper),
        ("optimization-applied", optimization_applied),
        ("cet-endbr-emitted", cet_endbr),
        ("plt-bypassed", plt_bypassed),
        ("pic-object-relocs", pic_object),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        GOT_CALL_TYPES, NO_PLT_CALLEE, OPTIMIZATION_ANCHOR_CALLEE, OPTIMIZATION_DEAD_CALLEE,
        OPTIMIZATION_FUNCTION, PLT_CALL_TYPES,
    };

    #[test]
    fn the_optimisation_probe_names_no_symbol_a_prefix_would_take() {
        let code = include_str!("../../probes/optimization_applied.c");
        for name in [
            OPTIMIZATION_FUNCTION,
            OPTIMIZATION_ANCHOR_CALLEE,
            OPTIMIZATION_DEAD_CALLEE,
        ] {
            let mut rest = code;
            let mut seen = 0;
            while let Some(at) = rest.find(name) {
                let after = &rest[at + name.len()..];
                assert!(
                    !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'),
                    "the probe names an identifier that begins with {name}"
                );
                seen += 1;
                rest = after;
            }
            assert!(seen >= 1, "the probe names {name}");
        }
        assert!(code.contains(&format!("{OPTIMIZATION_ANCHOR_CALLEE}();")));
        assert!(code.contains(&format!("{OPTIMIZATION_DEAD_CALLEE}();")));
        // The dead call is the one behind the branch on the local zero, and the anchor's is
        // not.
        let body = format!(
            "int keep = 0;\n\n    {OPTIMIZATION_ANCHOR_CALLEE}();\n    if (keep) {{\n        \
             {OPTIMIZATION_DEAD_CALLEE}();\n    }}\n}}"
        );
        assert!(code.contains(&body), "the probe's body is the one read");
        assert_eq!(code.matches("();").count(), 2, "the probe makes two calls");
        // Every word of the probe's code, read from the code itself, is undefined before the
        // code, so a header cannot rename it by macro.
        let after = code
            .split_once("CHARD_EMIT_REPORT;")
            .map(|(_, rest)| rest)
            .expect("the probe emits its self-report");
        let code_at = after
            .find("extern void")
            .expect("the probe declares its callees");
        let code_end = after
            .rfind("\n}\n")
            .map_or(after.len(), |end| end + "\n}\n".len());
        let words: std::collections::BTreeSet<&str> = after[code_at..code_end]
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
            .collect();
        for name in [
            OPTIMIZATION_FUNCTION,
            OPTIMIZATION_ANCHOR_CALLEE,
            OPTIMIZATION_DEAD_CALLEE,
            "if",
            "__attribute__",
        ] {
            assert!(words.contains(name), "the code is read whole: {name}");
        }
        for name in &words {
            let undef = format!("#undef {name}\n");
            let at = after
                .find(&undef)
                .unwrap_or_else(|| panic!("the probe's code is written in {name}: {undef}"));
            assert!(at < code_at, "{name} before the code");
        }
    }
    use crate::elf::reloc_type_name;

    /// The four machines whose relocation types `elf::reloc_type_name` names, by
    /// `e_machine`: x86_64, i386, aarch64, riscv.
    const MACHINES: [u16; 4] = [62, 3, 183, 243];

    /// `callee_relocated` matches `TYPE SYMBOL` by prefix, which is exact while each listed
    /// type is a name the reader gives, on one list only, and the probe names no other
    /// symbol that begins with the callee's name; this holds all three.
    #[test]
    fn a_prefix_match_on_a_relocation_is_an_exact_one() {
        for t in GOT_CALL_TYPES.iter().chain(PLT_CALL_TYPES) {
            assert!(
                MACHINES
                    .iter()
                    .any(|m| (0..1024).any(|k| reloc_type_name(*m, k) == *t)),
                "{t} is a type the reader never names"
            );
            assert!(!t.contains(' '), "{t} carries the separator");
        }
        for t in GOT_CALL_TYPES {
            assert!(!PLT_CALL_TYPES.contains(t), "{t} is on both lists");
        }
        let source = include_str!("../../probes/no_plt.c");
        let mut rest = source;
        let mut seen = 0;
        while let Some(at) = rest.find(NO_PLT_CALLEE) {
            let after = &rest[at + NO_PLT_CALLEE.len()..];
            assert!(
                !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'),
                "the probe names a symbol that begins with {NO_PLT_CALLEE}"
            );
            seen += 1;
            rest = after;
        }
        assert!(seen >= 2, "the probe declares and calls {NO_PLT_CALLEE}");
    }
}
