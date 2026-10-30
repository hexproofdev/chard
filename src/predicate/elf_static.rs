// SPDX-License-Identifier: BSD-3-Clause

//! The predicates for the elf-static checks, one entry per check id.
//!
//! Each entry pairs a check id with a function returning a predicate built once behind a
//! `std::sync::LazyLock`, so the value `predicate::for_check` hands out is the value a
//! report serializes. The table lives in its own file so that work on the two channels
//! edits disjoint files.
//!
//! Each predicate is the decoder of its check: `probe::Check::decode` evaluates it over the
//! facts `elf::Elf::facts` read from the artifact. Three rules describe the predicates:
//!
//! - `tables` is the check's `reads`, derived: `probe::Check::reads` returns it. The
//!   truncation step is the evaluator's `@truncated` preamble, applied before the clauses,
//!   and `report::truncation_limitation` intersects the same list on the measured build.
//! - An `Option` field is `None` exactly where the loader cannot run the object, and such
//!   an object carries no classification to read as `off`; the first clause is `missing`
//!   over the fields, concluding `indeterminate`.
//! - Checks that read one observable share a predicate: `noexecstack` and
//!   `linker-default-noexecstack`, `cet-marked` and `cet-marked-object`, `canary-emitted`
//!   and `ssp-covers-small-arrays`. `tests/predicates.rs` names the pairs.
//!
//! One value lies outside the reader's domain, and there the predicate is the stricter
//! reading. A `relro` of empty text is `indeterminate` here, since the language gives an
//! empty level no rendering; `detect_relro` read it `present` at level `""`. `Elf::facts`
//! writes one of `elf::RELRO_*` or `null`, so no measured artifact reaches that case.

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
///
/// `gnu-stack` beside `program-headers`: two stack headers that disagree on
/// `PF_X` are recorded against it (`elf::Elf::gnu_stack`), and the checks this predicate
/// decodes are the ones that read the stack header.
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
            "no PT_GNU_STACK defers to the kernel's default, which the artifact does not state",
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
/// link records the C library whenever it takes the library from a shared object
/// (`probe-executable-link-records-its-c-library` in `report::ASSUMPTIONS`); the precondition
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
///
/// The observable is an absence, so `@otherwise` is `present`, and a list that is empty
/// because nothing was dynamically linked read as the flag acting: a `-static` link has no
/// `.dynamic` at all, a static PIE has one with no `DT_NEEDED`, and either read `on` over
/// profile-free arms that stayed dynamic and discriminated (gcc 13.3 on Ubuntu 24.04
/// x86_64 under `--profile explicit --flags -O2 --ldflags -static`). Four clauses ahead of
/// `recorded` withhold where no entry names the C library, so that the list has no entry to
/// leave the unused library's out beside: `unclassified` for an object the loader cannot
/// run, read from `e_type` so that a forged dynamic section on a relocatable or core file is
/// not read as a link; `no-dynamic` for an object with no dynamic section (a `-static`
/// executable; also an interpreter forged onto one); `shared-output` for a list with no
/// `libc.` entry on an artifact that classifies as a shared object; and `no-c-library` for
/// such a list on anything else (a static PIE; a `-static-pie` link given an interpreter; a
/// `-static-pie` link given one shared library). The measured reading is then
/// `not-applicable` under `artifact-cannot-carry-observable`, since
/// `report::ARTIFACT_PRECONDITIONS` reads the same entry, or, for the shared-object
/// classification, `indeterminate` under `report::link_mode_limitation`, which comes first.
/// DESIGN.md's `not-applicable` section carries the measured shapes and their frames; what
/// follows is the mechanism.
///
/// The list is read ahead of the link classification, because the two disagree on measured
/// shapes and the list is where the flag leaves its mark: a `-static-pie
/// -Wl,--dynamic-linker=<path>` link carries an interpreter, so it classifies as a dynamic
/// PIE, and records no library, and a clause on the classification read it `on`; a `-pie
/// -Wl,--no-dynamic-linker` link has no interpreter and is marked as executable output, so it
/// classifies as a static PIE, and keeps its entries, and the same clause withheld it with a
/// sentence saying the artifact records no library. What the list has to carry is the C
/// library's entry and not merely an entry, because a profile can take the C library from an
/// archive while naming another shared library: `-static-pie -Wl,--no-as-needed -Wl,-Bdynamic
/// libz.so.1 -Wl,-Bstatic` records `libz.so.1`'s entry alone, libm and libc having come from
/// their archives, and read `on` while the clause asked for any entry. The rule rests on
/// `probe-executable-link-records-its-c-library` in `report::ASSUMPTIONS`: the probe's
/// executable link names its C library through its startup object whenever it takes the
/// library from a shared object, so a list with no `libc.` entry came from a link that took
/// the C library, and the unused library beside it, from an archive. A `-shared` link has no
/// startup object, and under `--as-needed` it records nothing at all (gcc 13.3 with GNU ld
/// 2.42 on Ubuntu 24.04 x86_64, whose driver passes the flag by default, and gcc 16.1.1 with
/// GNU ld 2.46.1 on Fedora 44 x86_64 given it, `--profile explicit --flags "-O2 -fPIC"
/// --ldflags -shared`, 2026-10-27): there the missing entry may be the flag's own doing, so
/// `shared-output` reads the classification and withholds without naming a cause the tags
/// cannot settle. That read is read only where no entry names the C library, which
/// `Cond::All`'s order holds: the list first, the classification second. The other
/// classification read is `no-loader-output`, after `recorded`: output linked with no dynamic
/// loader (`statically_linked`: a static PIE, or an `ET_EXEC` with no interpreter) takes its
/// libraries from archives unless the link chose shared ones, and the tags cannot say which
/// this link chose, so where the C library is recorded and the unused library's entry is
/// missing, the archive may have supplied the library: `-static-pie -Wl,--no-as-needed
/// -Wl,-Bdynamic libc.so.6 -Wl,-Bstatic`, and the same under `-no-pie
/// -Wl,--no-dynamic-linker`, record `libc.so.6` alone, the trailing `-Bstatic` sending the
/// probe's own `-lm` to `libm.a`, and read `on` while `@otherwise` stood there (gcc 9.4 with
/// GNU ld 2.34 and clang 10 with GNU ld 2.34 on Ubuntu 20.04 x86_64, gcc 13.3 with GNU ld 2.42
/// on Ubuntu 24.04 x86_64, 2026-10-27); a `-pie -Wl,--no-dynamic-linker` link under
/// `--as-needed` reaches the same clause, and there the flag did drop the entry, which the
/// tags cannot show. The clause withholds `indeterminate` with no precondition row, since the
/// artifact could carry the entry; a recorded entry is read before it, `off`. The same route
/// with an interpreter, a dynamic link whose profile ends in `-Wl,-Bstatic`, reads `on`: the
/// observable cannot say whether the flag or the archive left the entry out, and a ledger row
/// carries it. `report::link_mode_limitation` is keyed on the fields a reading rested on, so
/// over an executable link's artifact that classifies as a shared object the gate withholds
/// `as-needed` where the list named no C library or no unused library, and a list that
/// recorded the unused library is read.
/// `unclassified` reads `e_type` and not a classification field for the same reason: a
/// classification read on every evaluation would put every reading within the gate's reach.
/// The header and program-header tables are on `tables` because `e_type` and the
/// classification are read from them.
///
/// A probe with no single library leaves no `DT_NEEDED` entry to look for, and a clause
/// matching nothing would read every artifact as `on`; the predicate then withholds every
/// reading under a clause that says why, and `tests/predicates.rs` fails on it.
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
            "the loader cannot run an object of this type, so no link of the probe wrote it \
             and its DT_NEEDED list measures nothing",
        ),
        clause(
            "no-dynamic",
            Cond::Eq(elf(ElfField::HasDynamic), "false".to_owned()),
            Conclusion::Indeterminate,
            "the object has no dynamic section, so there is no DT_NEEDED list to read",
        ),
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
            "no DT_NEEDED entry names the C library and the artifact classifies as a shared \
             object: a -shared link has no startup object to reference the C library, so \
             --as-needed may have dropped its entry with the unused library's, and a static \
             PIE written with neither marker classifies the same way with none to drop; the \
             tags cannot say which",
        ),
        clause(
            "no-c-library",
            Cond::NoneOf(vec![Cond::AnyStartsWith(
                elf(ElfField::Needed),
                C_LIBRARY_PREFIX.to_owned(),
            )]),
            Conclusion::Indeterminate,
            "no DT_NEEDED entry names the C library on executable output, whose startup \
             object references the library, so this link took it from an archive and the \
             unused library from its archive the same way, leaving no entry --as-needed could \
             have dropped",
        ),
        as_needed_soname_prefix().map_or_else(
            || {
                clause(
                    "no-library",
                    Cond::All(Vec::new()),
                    Conclusion::Indeterminate,
                    "the as-needed probe links no single library, so no DT_NEEDED entry is its",
                )
            },
            |prefix| {
                clause(
                    "recorded",
                    Cond::AnyStartsWith(elf(ElfField::Needed), prefix),
                    Conclusion::Absent,
                    "DT_NEEDED records the library nothing uses, so --as-needed is not acting",
                )
            },
        ),
        clause(
            "no-loader-output",
            truth(ElfField::StaticallyLinked),
            Conclusion::Indeterminate,
            "the unused library's entry is missing on output linked with no dynamic loader, \
             which takes its libraries from archives unless the link chose shared ones, and the \
             tags cannot say which this link chose: --as-needed may have left the entry out, or \
             the archive may have supplied the library",
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
///
/// The reader is checked against real compiler output as well as the synthesized bytes in
/// `elf.rs`: cross-compiling to `aarch64-linux-gnu` and inspecting the objects with
/// `chard elf` agrees with `readelf -n` on all four cases (`standard` gives BTI and PAC,
/// `bti` and `pac-ret` one each, `none` no note).
///
/// Linked artifacts have been read too, cross-linked against Fedora 44's aarch64 sysroot:
/// `standard`, `bti` and `pac-ret` each produce the note `readelf -n` reports, and `none`
/// produces none. That was the part that could surprise, because
/// `GNU_PROPERTY_AARCH64_FEATURE_1_AND` is an AND across every input object, so one
/// unmarked object clears the feature from the whole binary, the mechanism that makes CET
/// unmeasurable on Debian, where glibc's startup files carry no property note and the
/// check withholds rather than reads `off`. Fedora's aarch64 `crt1.o` and `crti.o` carry
/// BTI, PAC and GCS, and the linked binary keeps all three.
///
/// Two things that cross-link did not settle were measured natively since: whether other
/// aarch64 libcs mark their startup objects (the control triple answers on each host: an
/// intersection that zeroes the note fails the positive control, so the check reads
/// `probe-invalid`), and what a native aarch64 compiler defaults to.
///
/// # Confidence, and the rule that set it
///
/// An artifact-marking check whose feature word is an AND across input objects is
/// `Confidence::High` once it has met both outcomes of that AND on real linked artifacts,
/// on two libcs from two distributions: one whose startup objects carry the note, where the
/// check reads the marking the build asked for, and one whose startup objects carry none,
/// where the check withholds rather than reads `off`. One distribution answering is not
/// grounds for promotion. Both outcomes were measured on 2026-09-28:
///
/// - Fedora 44 aarch64, glibc 2.43, gcc 16.2.1 and clang 22.1.8: under `openssf-tldr` this
///   check reads `on` at `full` and `gcs-marked` reads `on`, the positive control present
///   and the negative absent, with both compilers. Under `bare` both checks read `off` with
///   both compilers, which is the native
///   default the cross-link could not speak for.
/// - Alpine edge aarch64, musl 1.2.6, gcc 15.2.0, in a container on the same host: under
///   `bare`, `openssf-tldr` and `--profile explicit --flags -mbranch-protection=standard`
///   both checks read `probe-invalid` with `withheld_because` `positive-silent`, positive
///   and negative arms both absent, so some input object zeroed the AND. No `off` was
///   published. Which inputs did is a second measurement, outside chard: GNU readelf
///   2.45.1 in the same image, exit status 0 and empty stderr on every file, prints
///   `AArch64 feature: BTI, PAC, GCS` for a control object compiled with
///   `-mbranch-protection=standard`, and no property note for that control linked into a
///   program, nor for `crt1.o`, `Scrt1.o`, `rcrt1.o`, `crti.o`, `crtn.o`, `crtbegin.o`,
///   `crtbeginS.o`, `crtend.o` or `crtendS.o` as the driver resolves them.
///
/// The second outcome is a withholding rather than an explanation; a named rule that would
/// turn it into an earned `unsupported` is an entry in the project ledger.
///
/// Only BTI and PAC are read. `-mbranch-protection=standard` also sets the GCS bit
/// (`0x4`), so a `-mbranch-protection=gcs` build reads `absent` here, which is right, since
/// it has neither BTI nor PAC; `gcs-marked` reads bit 2 of the same word.
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
///
/// Three names answer for it. `__stack_chk_fail` and its local alias
/// `__stack_chk_fail_local` are what gcc and clang call on glibc and musl.
/// `__stack_smash_handler` is OpenBSD's: its libc defines it, and its clang calls it with
/// the function's name after comparing the saved slot against a load of the hidden
/// `__guard_local`. Measured 2026-09-30 on OpenBSD 7.9 amd64, clang 19.1.7, `objdump -dr`
/// of a function holding a four-byte array, built `-O2 -fno-ret-protector
/// -fstack-protector-all`:
///
/// ```text
/// mov  0(%rip),%rax        R_X86_64_PC32  __guard_local-4
/// mov  %rax,-0x8(%rbp)
/// ...
/// mov  0(%rip),%rcx        R_X86_64_PC32  __guard_local-4
/// cmp  -0x8(%rbp),%rcx
/// jne  fail
/// ...
/// fail: lea .LSSH.1(%rip),%rdi ; call __stack_smash_handler
/// ```
///
/// `__guard_local` is not an observable: every linked OpenBSD program defines it, a local
/// hidden object from the startup code, under `-fno-stack-protector` as under
/// `-fstack-protector-all`. `__stack_smash_handler` is: over both chard probes
/// (`stack_canary.c`, `ssp_small_array.c`) at `-O0` and `-O2`, it was an undefined
/// reference in every build that emitted a canary and in no build that did not.
///
/// # Why OpenBSD amd64 still withholds
///
/// There, by default, no build emits a canary. OpenBSD's clang turns RETGUARD on with the
/// stack protector and emits no canary in a function RETGUARD covers: the return address
/// is combined by XOR with a per-function cookie, `__retguard_<n>`, on entry and checked before
/// `ret`, trapping through `int3` on a mismatch. Same host, same probes, `-O0` and `-O2`:
/// `-fstack-protector-all`, `-fstack-protector-strong`, `-fstack-protector` and the flagless
/// build carry no `__stack_smash_handler` reference and a RETGUARD cookie in every probe
/// function; `-fno-stack-protector` carries neither; `-fno-ret-protector` brings the handler
/// reference back in every protector mode, the flagless build (the default
/// `-fstack-protector-strong`) included.
///
/// The controls are profile-free, so the positive arm is a RETGUARD build with no canary
/// and the triple withholds as `probe-invalid` (`positive-silent`). That is the truthful
/// reading. Read as a canary, RETGUARD would publish `on` for a mechanism that guards the
/// return address and nothing else in the frame; a positive arm forcing RETGUARD off would
/// publish `off` for an as-configured build RETGUARD protects.
///
/// Whether a `__retguard_<n>` symbol is present does not separate the arms: the startup
/// objects carry cookies of their own, so the `-fno-stack-protector` arm's table holds some
/// too. How many are present does. Same host, both probes at `-O0` and `-O2`, counted with
/// `readelf -s` (dated 2026-09-30): `stack_canary.c` links 9 under `-fstack-protector-all`,
/// `-strong`, plain and flagless and 4 under `-fno-stack-protector` or `-fno-ret-protector`;
/// `ssp_small_array.c` links 6 against 4; an empty `main` links 5 at `-O2` and 4 under
/// `-fno-stack-protector`. The count is not read: it is RETGUARD's mark rather than a
/// canary's, and it means something only against the startup objects' baseline, which a
/// one-artifact predicate cannot see. Why that also keeps it from being a RETGUARD
/// observable, and what a RETGUARD check needs instead, is the project ledger's entry.
///
/// RETGUARD has a check of its own, `ret-protector-emitted`, which reads an object rather
/// than a link so the startup objects' cookies never reach it; see [`ret_protector`]. This
/// predicate does not read RETGUARD.
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
///
/// Missing, it is the relocations that were not read: `ssp-level-emitted`'s `unread-calls`
/// clause withholds rather than reading four functions with no references as `none`.
pub const SSP_CALLEES: [&str; 4] = ["ssp_use", "ssp_escape", "ssp_escape", "ssp_escape"];

/// The probe's fifth function, the one that tells `-strong`'s selection from `SafeStack`'s: a
/// character array every access to which is masked into range and whose address never
/// escapes. `-strong` and plain `-fstack-protector` admit it; `SafeStack` at `-O1` and above
/// proves it safe and leaves it bare. `probes/ssp_function_map.c` defines it and says why,
/// and `probe`'s tests hold the probe to it as to [`SSP_FUNCTIONS`].
///
/// Read where the object defines it, through the call it makes
/// ([`SSP_DISCRIMINATOR_CALLEE`]), and not roll-called: the four functions above earn each
/// level by themselves, and the objects that lack it (the `ssp-level-emitted` rows of
/// `tests/fixtures/detectors.json` mined on 2026-10-02, and the synthetic objects of
/// `tests/elf_builder`) read by the four alone. An object a measurement builds always
/// defines it, by the same external linkage and `used` attribute that keep the four
/// present; one that lacks it with the four present comes from a probe without it, and
/// its absence earns nothing, since the clauses that read it only ever move a reading from
/// a level to `indeterminate` or to `unsafe-frame`.
pub const SSP_DISCRIMINATOR: &str = "ssp_safe_array";

/// The external [`SSP_DISCRIMINATOR`] calls, as [`SSP_CALLEES`] pairs each of the four.
pub const SSP_DISCRIMINATOR_CALLEE: &str = "ssp_use";

/// The symbol a function refers to when clang's `SafeStack` gave it an unsafe frame: the
/// thread-local pointer to the unsafe stack, loaded in the prologue of every such function
/// (`R_X86_64_GOTTPOFF` against it on x86_64, measured 2026-10-08 with clang 22.1.8 on
/// Fedora 44 x86_64). The runtime's initializer, `__safestack_init`, is called from a
/// constructor in the translation unit holding `main` and is in no object of this probe, so
/// it is not read. The marker is the artifact's own, so it follows the build rather than the
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
///
/// The fact is [`crate::elf::ElfFacts::function_references`], whose doc comment carries
/// how a reference is attributed to a function. The functions answer the rules a level
/// adds, so the readings that are levels are five rows, and any other row is withheld
/// rather than rounded to the nearest level:
///
/// ```text
/// ssp_any  ssp_addr_taken  ssp_char_array  ssp_alloca  ssp_safe_array
///    -           -               -             -             -          absent
///    -           -               C             C             C          basic
///    -           -               -             C             -          basic, threshold above 64 bytes
///    -           C               C             C             C          strong
///    C           C               C             C             C          all
///    -           CU              CU            CU            -          unsafe-frame (`SafeStack`, -O1 and above)
///    -           CU              CU            CU            CU         unsafe-frame (`SafeStack`, -O0)
/// ```
///
/// `U` is a reference to [`SAFESTACK_MARKER`]. The `basic` rows read the fifth column as a
/// pair with the third: the two arrays are the same 64-byte character array to plain
/// `-fstack-protector`, so where the object defines the fifth it has a canary exactly when
/// `ssp_char_array` does, at the default threshold and above it alike (measured 2026-10-08,
/// clang 22.1.8 and gcc 16.1.1, -O0 to -O3 and -Os, with and without
/// `--param=ssp-buffer-size=128`).
///
/// Every rung excludes the marker. With the marker present the selection rule is
/// `SafeStack`'s, a canary exactly where it built a frame, and no plain `-fstack-protector`
/// rung describes that rule, so an object with the marker fits `unsafe-frame` where the
/// pattern holds and otherwise fits no rule and withholds. Two objects are withheld that a
/// rung admitting the marker would read. One refers to [`SAFESTACK_MARKER`] with a canary
/// set that breaks the canary-iff-unsafe-frame rule by `ssp_addr_taken` alone (built from a
/// copy of the probe with `no_stack_protector` on that function, clang 22.1.8 `-O2
/// -fstack-protector-strong -fsanitize=safe-stack`), which `basic` would read as a rung;
/// the shipped probe cannot produce it. The other holds the marker beside a canary on every
/// function, which `all` would read on the argument that five canaries are `-all`'s set
/// whichever pass placed them. The register's assumption
/// (`safestack-canaries-follow-the-unsafe-frame`) says clang does not build that object,
/// and it did not: clang 22.1.8 ignores `stack_protect` as an unknown attribute, so a copy
/// of the probe asking for a canary on `ssp_any` under `-O2 -fstack-protector-all
/// -fsanitize=safe-stack` still read `unsafe-frame`, and `tests/predicates.rs` holds the
/// row synthetically (the marker-plus-five-canaries row of its `FUNCTION_ROWS`,
/// `@otherwise`). No measured object reads differently for the exclusion: the 42 objects of
/// the 2026-10-08 matrix (`probes/ssp_function_map.c` at -O0, -O1, -O2, -O3 and -Os under
/// `-fstack-protector`, `-strong`, `-all` and `--param=ssp-buffer-size=128` for clang 22.1.8
/// and gcc 16.1.1 on Fedora 44 x86_64, and the two edited-probe objects) decoded
/// identically with `basic` and `all` admitting the marker and excluding it.
///
/// `ssp_alloca` is what keeps a raised `--param=ssp-buffer-size` from reading as no
/// protector: plain `-fstack-protector` admits a function calling `alloca` whatever the
/// threshold, so above 64 bytes the level still reads `basic`, as `ssp-level` reads it.
/// How large the threshold is, is `ssp-covers-small-arrays`' question.
///
/// # `SafeStack`
///
/// Under clang's `-fsanitize=safe-stack` the canary set is not the requested level's. The
/// frontend records the request only (the `__SSP_*` macro, an ssp attribute on every
/// function); in the backend the `SafeStack` pass runs before `StackProtector`, moves each local
/// whose address escapes or whose accesses it cannot prove in range to a separately mapped
/// unsafe stack, and places its own canary in that frame in any function carrying an ssp
/// attribute, while the `safestack` attribute suppresses the ordinary canary on the rest
/// (measured by deleting that one attribute from the IR and compiling again with `llc`).
/// So the canary set is "has an unsafe frame", identical under `-fstack-protector`,
/// `-strong` and `-all`: it widens `basic` (`ssp_addr_taken` gains a canary) and narrows
/// `-all` (`ssp_any` loses its), and matches `strong` on the four escaping functions by
/// coincidence: read as a rung, the rows would read `strong` under every requested level.
///
/// The reading is `unsafe-frame`, a word `probe::SSP_LEVELS` admits on no rung
/// (`ungraded`), earned by the pattern and the marker together (`unsafe-frame`): `ssp_any`
/// bare, the three escaping functions canaried, and every function that has a canary
/// referring to the unsafe stack pointer and every function referring to it carrying a
/// canary, `ssp_any` and the discriminator included. That last conjunction is the rule as
/// measured, a canary exactly where `SafeStack` built a frame, so a clang that one day put an
/// ordinary canary on a function with no unsafe frame falls out of the clause rather than
/// into it. `strong` excludes any object referring to the marker, and requires the
/// discriminator's canary where the object defines it, since plain `-strong` admits that
/// array on both compilers at every optimization level measured; a `strong` pattern with
/// the discriminator bare and no marker fits no rule and withholds. Which LLVM pass
/// implements the suppression is unread (no LLVM source on the measuring host), and whether
/// the rule holds on other targets or other clang releases is unmeasured;
/// `report::ASSUMPTIONS` carries `safestack-canaries-follow-the-unsafe-frame` with both as
/// its retirement.
///
/// Measured 2026-10-08 over `probes/ssp_function_map.c` with clang 22.1.8 and gcc 16.1.1 on
/// Fedora 44 x86_64 (glibc 2.43), `-c` at -O0, -O1, -O2, -Os and -O3, attributed by symbol
/// range from `readelf -rW` and `readelf -sW`: the two `SafeStack` rows above under each of
/// `-fstack-protector`, `-strong`, `-all` and `-fstack-protector --param=ssp-buffer-size=128`
/// with `-fsanitize=safe-stack`, and under `-fno-stack-protector -fsanitize=safe-stack` no
/// canary anywhere with `U` on the three escaping functions, which reads `absent`; the five
/// level rows for both compilers without it, gcc rejecting the flag. gcc has no `SafeStack`,
/// and its macro and artifact agree on `all` under `-fstack-protector-all`.
///
/// A function the list does not hold withholds the reading (`roll-call`). Read as a
/// function with no canary, a missing `ssp_addr_taken` would turn `strong` into `basic`,
/// and an object with no functions at all (gcc's slim `-flto` object, which holds GIMPLE
/// and no code) would read `absent`; the detection recipe names this as the one false zero
/// the method has, and it is why every probe function is named here rather than counted.
///
/// Measured 2026-10-02 over `probes/ssp_function_map.c` compiled `-c` at `-O0` and `-O2`,
/// attributed by symbol range from `readelf -rW` and `readelf -sW`: the rows above for
/// `-fno-stack-protector`, `-fstack-protector`, `-fstack-protector-strong` and
/// `-fstack-protector-all`, and the threshold row for `-fstack-protector
/// --param=ssp-buffer-size=128` (gcc refuses a value above 65535), under gcc 16.1.1 and clang 22.1.8 (Fedora 44 x86_64), gcc
/// 16.2.1 and clang 22.1.8 (Fedora 44 aarch64, where each canaried function also refers to
/// `__stack_chk_guard`), gcc 11.4.0 and clang 14.0.0 (Ubuntu 22.04), gcc 13.3.0 and
/// clang 18.1.3 (Ubuntu 24.04), gcc 15.2.0 (Alpine, musl) and gcc 12.2.0 (Debian 12 i386,
/// through `__stack_chk_fail_local`). Alpine's clang 23.1.2 reads `strong` under plain
/// `-fstack-protector`, with or without a threshold, and its preprocessor defines
/// `__SSP_STRONG__` for that flag too, so the two readers agree that the distribution's
/// clang raises the level.
///
/// A function present with no reference to the external it calls withholds the reading
/// too (`unread-calls`, [`SSP_CALLEES`]). Relocations in an encoding the reader skipped
/// (clang's `-Wa,--crel`) would leave all four functions listed with no references and the
/// `none` row reading `off`; the reader records that encoding unread, and this clause
/// catches any other way the references go missing.
///
/// A canary reference in code outside every function's range withholds the reading as
/// well (`unattributed-canary`, before any level is read, since the reference could be any
/// function's). clang 22.1.8 on Fedora 44 x86_64 under `-O2 -fstack-protector-strong
/// -fbasic-block-sections=all` puts each canaried function's `__stack_chk_fail` call in a
/// section of its own with no function symbol, only a `NOTYPE` `<fn>.__part.N`, and keeps
/// the calls `unread-calls` reads in the function's own range. A reader that skipped those
/// sections read every function as one without a canary, and `none` published `off` while
/// `canary-emitted` and `ssp-level` read `strong`. clang's `-fsplit-machine-functions` with
/// a profile does the same, its fragments named `<fn>.cold` but `NOTYPE`, so `canaried`'s
/// `.cold` reading never sees them. The reader lists such references under
/// [`crate::elf::UNATTRIBUTED_REFERENCE`], and both forms read `indeterminate` here.
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
    // frame. Over the four roll-called functions and the discriminator alike; a function the
    // object lacks has neither, and the `all` and `unsafe-frame` clauses require canaries
    // where the rule needs a function present.
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
                "the artifact is not a relocatable object with a symbol table, so no \
                 reference is attributed to a function",
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
                "a probe function is not in the symbol table, and a function that is \
                 missing is not one without a canary",
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
                Conclusion::Indeterminate,
                "a probe function does not refer to the external it calls, which the object \
                 must relocate whatever the level, so its relocations were not read and its \
                 missing canary is not one it lacks",
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
                "code outside every function's range refers to the canary failure handler \
                 or the guard, so a canary the object holds is not placed in the function it \
                 protects",
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
                word("all"),
                "every probe function has a canary, including one with no array and no \
                 address taken, which only -fstack-protector-all admits, and nothing refers \
                 to SafeStack's unsafe stack pointer",
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
                "the object refers to SafeStack's unsafe stack pointer, and every function \
                 with a canary refers to it and every function referring to it has a canary, \
                 while the one with neither array nor address taken has none: the canary \
                 follows the unsafe frame SafeStack built, not the level requested, which \
                 SafeStack applies alike at basic, strong and all",
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
                "the function whose local's address is taken has a canary and the one \
                 with neither array nor address taken does not, which is \
                 -fstack-protector-strong's rule; the array every access to which is in \
                 range has one too where the object defines it, as -strong admits any \
                 array, and nothing refers to SafeStack's unsafe stack pointer",
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
                "the function calling alloca has a canary and the one whose local's address \
                 is taken does not, which is plain -fstack-protector's rule; the 64-byte \
                 character array has one too unless the threshold was raised above it, and \
                 the in-range array of the same size, where the object defines it, has one \
                 exactly when it does; and nothing refers to SafeStack's unsafe stack pointer",
            ),
            clause(
                "none",
                Cond::NoneOf(vec![any, addr_taken, char_array, alloca, safe]),
                Conclusion::Absent,
                "no probe function refers to the canary failure handler or the guard; under \
                 -fno-stack-protector with SafeStack the unsafe stack is still in use and \
                 still no function has a canary",
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
///
/// The third channel on a flag the macro and runtime channels already answer. A request, a
/// trip, and the artifact that carries the trip's landing site are three questions, and a
/// decoder wrong about one is unlikely to be wrong about the others the same way. They are
/// three readers of one artifact rather than three witnesses, though: a fault in that
/// build reaches all three alike, which is what `corroboration.*.independent_witnesses`
/// counts (2026-09-28).
///
/// # The inversion, which is why this cannot be a one-symbol grep
///
/// `-D_GLIBCXX_DEBUG` is stronger than `-D_GLIBCXX_ASSERTIONS`, and under it
/// `__glibcxx_assert_fail` is absent: the debug mode routes failures through
/// `__gnu_debug::_Error_formatter` instead. A decoder watching the one symbol reads `off`
/// for the more hardened of the two builds. Measured with gcc 16.2.1 and clang 22.1.8 over
/// libstdc++ 16, identical counts for both compilers:
///
/// ```text
/// -O2                            assert_fail=0  error_formatter=0
/// -O2 -D_GLIBCXX_ASSERTIONS      assert_fail=1  error_formatter=0
/// -O2 -D_GLIBCXX_DEBUG           assert_fail=0  error_formatter=2   <- the inversion
/// -O0                            assert_fail=1  error_formatter=0   <- auto-enabled
/// -O2 -D_GLIBCXX_NO_ASSERTIONS   assert_fail=0  error_formatter=0
/// ```
///
/// Two names answer for the handler, and the older is not a fallback: libstdc++ before
/// GCC 12 has no out-of-line handler, so `__replacement_assert` is what present looks like
/// there. Reading only the newer name read the mechanism absent on every libstdc++ up to
/// 11, the artifact channel disagreeing with its own runtime sibling on the same build.
///
/// # Why absence is only absence for chard's own probe
///
/// The symbol appears only where the translation unit instantiated a checked operation the
/// optimizer could not discharge. A program that indexes nothing has assertions fully on
/// and no symbol, so this recipe is worthless against an arbitrary binary and sound here,
/// because the positive control proves the symbol appears on this probe when the flag is
/// set. libc++ has no equivalent symbol: an observable belonging to the other
/// implementation is `indeterminate`, never `off`. The library is identified by the
/// `cxx-stdlib` ladder, as `cxx-hardening-requested` identifies it.
static CXX_ASSERTIONS_SYMBOL: LazyLock<Predicate> = LazyLock::new(|| Predicate {
    tables: vec![ElfTable::Symbols],
    clauses: vec![
        clause(
            "libc++",
            Cond::Eq(Term::CxxStdlib, "libc++".to_owned()),
            Conclusion::Indeterminate,
            "libc++ routes precondition failures through __libcpp_verbose_abort, so the \
             libstdc++ handler's absence says nothing about the request",
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
///
/// Each function RETGUARD protects gets a hidden weak `__retguard_<n>` object, alone in a
/// COMDAT group whose section is `.openbsd.randomdata.retguard.<n>`, loaded at entry and
/// checked before `ret`. Measured 2026-09-30 on OpenBSD 7.9 amd64, clang 19.1.7, with
/// `readelf -S`, `-g`, `-s` and `-r` over a three-function file compiled `-c`: at `-O0` and
/// `-O2`, flagless and under `-fret-protector`, the object holds three such sections, three
/// `__retguard_<n>` symbols and six `R_X86_64_PC32` relocations against them from
/// `.rela.text` (a load at entry and one before `ret` in each function); under
/// `-fno-ret-protector` or `-fno-stack-protector` it holds none of the three.
///
/// Read on an object, never on a linked program. OpenBSD's startup objects bring cookies
/// of their own into every link, so a linked program carries the sections and symbols under
/// `-fno-ret-protector` too: the `canary` predicate above records 4 in every link on the
/// same host. An object holds what the compiler made of chard's source and nothing else,
/// which is what lets presence alone be the observable.
///
/// The section table rather than the symbol table because the cookie names vary by
/// function, and the symbol channel reads a fixed watch list; a section-name prefix is the
/// same mark, one per protected function, in a list the reader already publishes whole.
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
///
/// In C a landing pad exists only to run a `cleanup` attribute's handler while an
/// exception unwinds through the frame, so the table appears when `-fexceptions` is in
/// effect and the translation unit holds a cleanup region spanning a call that may
/// unwind; `probes/exceptions.c` holds one. Measured 2026-10-01 with `readelf -SW` over
/// that probe compiled `-c` at `-O0` and `-O2`: one `.gcc_except_table` under
/// `-fexceptions` and under `-fno-exceptions -fexceptions`, none flagless, under
/// `-fno-exceptions` or under `-fexceptions -fno-exceptions`, for gcc and clang on Fedora
/// 44 x86_64 (gcc 16.1.1, clang 22.1.8) and aarch64 (gcc 16.2.1, clang 22.1.8), Alpine
/// x86_64 with musl (gcc 15.2.0, clang 23.1.2), Ubuntu 22.04 x86_64 (gcc 11.4.0, clang
/// 14.0.0) and Ubuntu 24.04 x86_64 (gcc 13.3.0, clang 18.1.3). `.eh_frame` was present in
/// every one of those builds, so it is not the observable.
///
/// The probe source is load-bearing. The detection recipe measured a function with no
/// cleanup region compiling to the same sections under either flag. A cleanup whose
/// handler has no visible effect, around the same opaque call, left no table under
/// `-fexceptions` at `-O2` and one at `-O0` (gcc 16.1.1 and clang 22.1.8, Fedora 44
/// x86_64, measured 2026-10-01); the measured arm runs at whatever `-O` the profile sets,
/// so the handler here calls `printf`. A source that lost its landing pad would read absent
/// in the positive control arm, and the triple turns that into `probe-invalid`.
///
/// A prefix rather than the exact name because `-ffunction-sections` splits the table per
/// function as `.gcc_except_table.<name>` (gcc 16.1.1 and clang 22.1.8 on Fedora 44
/// x86_64, measured 2026-10-01), which is the same mark. `.rela.gcc_except_table` does not start with the prefix.
///
/// 32-bit ARM writes no `.gcc_except_table`. Its exception-handling ABI (the EHABI) gives
/// each function an entry in `.ARM.exidx`, and an entry too long to sit inline there, or one
/// that names a personality routine, goes in `.ARM.extab`, where the landing-pad table
/// follows the routine. `.ARM.extab` is not the mark: gcc's `-funwind-tables` and
/// `-fasynchronous-unwind-tables`, and under either of those or `-fexceptions` either
/// compiler's frame whose unwind description is long, write one without a landing pad, empty
/// or holding compact-model entries that name the routine by an index in the entry; nothing
/// in such an `.ARM.extab` is relocated (the
/// `.ARM.exidx` entries that point at it are, in `.rel.ARM.exidx`). An entry that names its
/// personality routine does so through an `R_ARM_PREL31` relocation in `.ARM.extab`, so the
/// mark is that section's relocation section, [`EHABI_EXCEPT_TABLE_RELOCATION_PREFIX`],
/// read by name. Measured 2026-10-20 on Raspbian 13
/// armv6 (gcc 14.2.0, clang 19.1.7) over this probe and over a function with no cleanup
/// region and a long unwind description, each compiled `-c` at `-O0` and `-O2` under no
/// flag, `-fexceptions`, `-fno-exceptions`, both orders of the pair, `-funwind-tables`,
/// `-fasynchronous-unwind-tables`, `-fno-exceptions -funwind-tables`, `-fexceptions
/// -ffunction-sections` and `-fno-asynchronous-unwind-tables -fno-unwind-tables`: of the 80
/// builds, the 12 of this probe in which `-fexceptions` came last held a `.rel.ARM.extab`
/// (one `R_ARM_PREL31` against `__gcc_personality_v0`), and no other build did, while 30 of
/// the others held an `.ARM.extab` with no relocation section. `-ffunction-sections` names
/// it `.rel.ARM.extab.text.<name>`, which the prefix covers. The ARM EABI relocates with REL
/// only; a toolchain writing a RELA form would read absent in the positive control arm, and
/// the triple would withhold it as `probe-invalid`.
///
/// Not read: clang's other exception models. Under `-fsjlj-exceptions` or `-fdwarf-exceptions`
/// clang 19.1.7 on the same board puts the table inside `.text`, so no section marks it (the
/// DWARF form writes `.eh_frame` beside it, which is not the observable). The model selector
/// reaches the control arms ([`crate::toolchain::runtime_selecting_flags`]), so both arms
/// build under it, neither carries a mark, and the triple reads `probe-invalid` there; a
/// model chosen otherwise (a `--config=` file, the frontend option) does not reach the arms,
/// and the reading is withheld by the compile listing (`report::EXCEPTION_MODEL_READINGS`).
/// Arms built under the default model would make the reading `off`.
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
            Conclusion::Present(LevelOf::None),
            "the object holds a .rel.ARM.extab, the relocation section ARM's unwind table gets \
             where an entry names a personality routine, as a cleanup region's landing-pad \
             table does only under -fexceptions",
        ),
    ],
    otherwise: Conclusion::Absent,
});

/// `-z separate-code` read from the linked program: does any page an executable segment
/// maps hold bytes the linker did not mark as instructions?
///
/// The fact is [`crate::elf::ElfFacts::data_in_code_pages`], whose doc comment carries the
/// reading and why it is by page and by `SHF_EXECINSTR` rather than by segment membership
/// and section name. A non-empty list is the observable's absence, and the sentence names
/// the sections, as the detection recipe asks: an `off` that says which bytes were mapped
/// executable can be checked against `readelf -lSW` by anyone holding the artifact.
///
/// `null` withholds. An object with no executable segment, or one whose section headers
/// are gone, cannot say what its code pages hold, and reading the empty classification as
/// clean would be an `on` from silence; reading it as data would be the false `off` the
/// recipe found when it zeroed `e_shoff`. A section-header table or name table the reader
/// could not finish is the `@truncated` step's, through the tables declared here.
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
            "the object has no executable segment, or no section header describing an \
             allocated section, so what its code pages hold cannot be read",
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
///
/// `any-starts-with` over `TYPE SYMBOL` entries, the type first: the space after the type
/// is what keeps `R_X86_64_32` from matching `R_X86_64_32S`, and the anchor's name is
/// the probe's own, which no other symbol in the object extends.
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
///
/// The fact is [`crate::elf::ElfFacts::code_relocations`]. An anchor whose visibility is
/// not default is `indeterminate` before any type is read (below); otherwise a GOT type
/// against the anchor is `present`; a direct type is `absent`; both at once is `indeterminate`, since no
/// measured build mixes them and the two readings cannot both be the compiler's; no
/// relocation naming the anchor, or only types outside both lists, is `indeterminate`.
/// Only the two measured lists conclude, so a toolchain emitting a type no row names
/// withholds rather than reading as either answer.
///
/// Measured 2026-10-02 by hand with `readelf -rW` over `probes/pic_object_relocs.c`
/// compiled `-c`, gcc and clang each: Fedora 44 x86_64 (gcc 16.1.1, clang 22.1.8) and
/// aarch64 (gcc 16.2.1, clang 22.1.8), Ubuntu 22.04 (gcc 11.4.0, clang 14.0.0), Ubuntu
/// 24.04 (gcc 13.3.0, clang 18.1.3) and Alpine with musl (gcc 15.2.0, clang 23.1.2) on
/// x86_64, and Debian 12 i386 (gcc 12.2.0). `-fPIC`, `-fpic`, `-fPIE -fPIC`,
/// `-fno-pic -fPIC` and `-fpie -fpic` reached the anchor through the GOT at every `-O`
/// measured (`-O0`, `-Og`, `-O2`), and so did `-fPIC` beside `-fvisibility=hidden` or
/// `=protected`, `-fno-semantic-interposition`, `-fno-plt`, `-fcommon`,
/// `-ffunction-sections -fdata-sections`, `-g`, `-fsanitize=address` and the
/// `openssf-tldr` flags, and beside each of these where the compiler accepts it: gcc's
/// `-fhardened`, `-fwhole-program` and `-mno-direct-extern-access`, clang's
/// `-fdirect-access-external-data`, `-fcf-protection=full` on x86 and
/// `-mbranch-protection=standard` on aarch64. `-fPIE`, `-fpie`, `-fno-pic`, `-fno-PIE`,
/// `-fPIC -fPIE`, `-fPIC -fpie`, `-fPIC -fno-pic` and `-fPIC -fno-pie` reached it
/// directly at `-O0` and `-O2` (and `-fPIE` at `-O3` and `-Os`), and so did the
/// `openssf-tldr` flags and `-fhardened`. No form among these whose last PIC flag was not
/// `-fPIC` or `-fpic` produced a GOT type; the list covers the forms measured, not every
/// form a profile can carry. The measured exception is clang's `-fsanitize=hwaddress`,
/// which reaches the anchor through the GOT under `-fPIE` and `-fno-pic` alike
/// (`R_X86_64_GOTPCREL` with clang 14.0.0, 18.1.3, 22.1.8 and 23.1.2 on x86_64,
/// `R_AARCH64_ADR_GOT_PAGE` with clang 22.1.8 on aarch64; gcc's hwasan stays direct).
/// The check's regime arm, the profile followed by `-fPIE`, reads `present` there and
/// withholds the cell; the forms measured beside `-fno-pic` and `-fPIE` for that arm are
/// in the assumption `pic-object-got-means-preemptible`. The large and tiny code models
/// change the types and not
/// the split: x86_64 `-mcmodel=large` gives `GOT64` under -fPIC and `GOTOFF64` under
/// -fPIE, aarch64 `-mcmodel=tiny` `GOT_LD_PREL19` and `ADR_PREL_LO21`, and both
/// architectures' large model without PIC an absolute type.
///
/// The direct reading, `absent`, holds only while the anchor keeps the default visibility
/// the probe declares for it: a hidden global cannot be preempted, so `-fPIC` reaches it
/// directly. `-fvisibility=hidden` and `=protected` leave the explicit attribute alone, but
/// clang's `-fvisibility-from-dllstorageclass -fvisibility-nodllstorageclass=hidden`
/// (measured 2026-10-02) overrides it on ELF: the anchor is `GLOBAL HIDDEN` in the
/// object's symbol table and `-O2 -fPIC` reaches it with `R_X86_64_PC32`, with clang
/// 14.0.0, 18.1.3, 22.1.8 and 23.1.2 on x86_64. The regime arm adds `-fPIE`, which is
/// direct too, so it read `absent` and the cell read `off` over a discriminating triple.
/// The visibility is read from the entry (`STV_HIDDEN` as its third word), and the clause
/// `anchor-not-default` withholds before the types are read.
///
/// What withholds, measured the same day: `-flto` without `-ffat-lto-objects` leaves no
/// code relocation (gcc writes an ELF object of LTO sections, clang a bitcode file chard
/// does not read as ELF), and with it the GOT and direct types appear as above. A
/// 4-byte global under gcc `-O2 -fPIE` on aarch64 was reached through a section anchor,
/// and under gcc's `-fwhole-program` an anchor without `externally_visible` became local,
/// both reached through `.data`; `probes/pic_object_relocs.c` says why its anchor has
/// neither problem.
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
            "the artifact is not a relocatable object with a section-header table, so it \
             carries no relocation the compiler wrote",
        ),
        clause(
            "anchor-not-default",
            Cond::AnyContains(
                elf(ElfField::CodeRelocations),
                format!("{PIC_OBJECT_ANCHOR} STV_"),
            ),
            Conclusion::Indeterminate,
            "the probe's global lost its default visibility, so the code may reach it \
             directly under -fPIC as well and the relocation does not say how it was built",
        ),
        clause(
            "mixed",
            Cond::All(vec![
                names_anchor_with(PIC_OBJECT_GOT_TYPES),
                names_anchor_with(PIC_OBJECT_DIRECT_TYPES),
            ]),
            Conclusion::Indeterminate,
            "the code reaches the probe's global both through the GOT and directly, which \
             no measured build does",
        ),
        clause(
            "got",
            names_anchor_with(PIC_OBJECT_GOT_TYPES),
            Conclusion::Present(LevelOf::None),
            "the code reaches the probe's exported global through the GOT, as code built \
             for a shared object does",
        ),
        clause(
            "direct",
            names_anchor_with(PIC_OBJECT_DIRECT_TYPES),
            Conclusion::Absent,
            "the code reaches the probe's exported global directly, as code built for an \
             executable does",
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
///
/// Measured 2026-10-02 with `readelf -sW` over that probe's three functions compiled `-c`
/// at each of `-O0`, `-O1`, `-O2`, `-O3`, `-Os` and `-Og`: all three helpers undefined
/// under `-ftrapv`, `-fno-trapv -ftrapv` and `-fwrapv -ftrapv`, and none flagless, under
/// `-fno-trapv`, or where a later `-fno-trapv`, `-fwrapv` or `-fno-strict-overflow`
/// countermands the flag, for gcc 16.1.1 on Fedora 44 x86_64, 16.2.1 on Fedora 44
/// aarch64, 15.2.0 on Alpine x86_64 (musl), 13.3.0 on Ubuntu 24.04 x86_64, 12.2.0 on
/// Debian 12 i386 and 11.4.0 on Ubuntu 22.04 x86_64. With UBSAN's signed-integer-overflow
/// check beside `-ftrapv`, in trap mode or not, there were none either: the sanitizer
/// takes the arithmetic, and the overflow trapped or was reported by UBSAN instead
/// (`decode::runtime::detect_trapv`). The last-flag-wins precedence against `-fwrapv`
/// is gcc's own; the detection recipe measured the same order effect.
///
/// clang implements `-ftrapv` inline, as an overflow branch to a trap instruction, and
/// none of its objects named a helper: clang 22.1.8 on both Fedora hosts, 23.1.2 on
/// Alpine, 18.1.3 on Ubuntu 24.04 and 14.0.0 on Ubuntu 22.04, same levels and forms. The
/// check declares clang in its compiler gate, so the absent positive control there reads
/// `unsupported` rather than letting a clang build read `off`.
///
/// Read on the object, where the helpers are references. A linked program defines them,
/// copied in from libgcc.a, and stripping removes them from `.symtab`.
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
        "the object's symbol table names a libgcc trapping helper for int arithmetic, \
         which gcc calls only under -ftrapv",
    )],
    otherwise: Conclusion::Absent,
});

/// The `trapv_helper` predicate.
#[must_use]
pub fn trapv_helper() -> &'static Predicate {
    &TRAPV_HELPER
}

/// The function `probes/ubsan_trap.c` defines for the code reader to search, which
/// `elf::code::SCANS` lists.
pub const UBSAN_TRAP_FUNCTION: &str = "chard_ubsan_trap_probe";

/// The prefix every sanitizer runtime handler's name starts with. `elf::WATCHED_SYMBOLS`
/// lists the handlers the probe's two constructs call, in every spelling measured, beside
/// three others, so `symbol-names` holds one of them wherever the object calls the runtime.
/// It lists those the probe's second function calls as well.
const UBSAN_HANDLER_PREFIX: &str = "__ubsan_handle_";

/// Every trap pattern, whatever check it carries: a trap beside a handler or a call is
/// read through these. `a64-brk-clang-check` is the one the function that calls through a
/// pointer is searched for in place of `a64-brk` (`elf::code::SCANS`).
const UBSAN_ANY_TRAP: [&str; 4] = ["x86-ud2", "x86-ud1", "a64-brk", "a64-brk-clang-check"];

/// The trap patterns an `on` is read from, the level word each publishes, and why. clang's
/// leave out its trap for check 0, signed overflow on an add, which clang's `-ftrapv` also
/// emits. The `brk` word is read from either aarch64 pattern, since the function that
/// calls through a pointer is searched for clang's numbered `brk` alone.
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

/// gcc's cold part of the probe's function, where -O2 can move a failed check's trap; see
/// `elf::code::SCANS`.
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

/// The call patterns, whose match with neither a trap nor a handler is withheld.
const UBSAN_CALL_PATTERNS: [&str; 6] = [
    "x86-call-rel32",
    "x86-call-got",
    "x86-call-reg",
    "x86-call-sib",
    "a64-bl",
    "a64-blr",
];

/// A match of `pattern` in either of the probe's functions or in a cold part of one.
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
///
/// The reader is `elf::code`, which holds the argument for why a byte search over one
/// known function in an object file is sound; this predicate reads its two facts, over the
/// probe's functions and gcc's `.cold` part of each, where -O2 moves blocks gcc predicts
/// are not taken, failed checks' traps among them. The probe's first function,
/// `chard_ubsan_trap_probe`, loads an element of
/// an array through a pointer, shifts it and adds to it, which `-fsanitize=undefined`
/// checks as `null`, `alignment`, `bounds`, `pointer-overflow`, `shift` and
/// `signed-integer-overflow`. In trap mode each failed check is a trap instruction; in
/// handler mode it is a call to `__ubsan_handle_*`, and the function holds no trap.
///
/// The first form of the probe held a shift and a load and no array index or signed
/// arithmetic, and was measured 2026-10-02 with `objdump -d` and `nm -u`, over
/// `probes/ubsan_trap.c`'s function compiled `-c` and over the same function compiled
/// without the self-report header. Under `-fsanitize=undefined -fsanitize-trap=undefined`,
/// with no handler referenced: on Fedora 44 x86_64, gcc 16.1.1 `ud2` 3 at -O0 and 1 at -O2
/// and clang 22.1.8 `ud1` 2 at both; on Fedora 44 aarch64, gcc 16.2.1 `brk #0x3e8` 3 at -O0
/// and 1 at -O2 and clang 22.1.8 `brk #0x5514` and `#0x5516` at both; under
/// `-fsanitize=undefined` no trap, with `__ubsan_handle_shift_out_of_bounds` and
/// `__ubsan_handle_type_mismatch_v1`. The -O2 count on x86_64 was of the function alone: gcc
/// had moved a second `ud2` into `chard_ubsan_trap_probe.cold`, which that form did not
/// search, and under `-fsanitize=shift -fsanitize-trap=shift -O2` the only `ud2` was there,
/// so the check read `off` over a trap. The function alone, on Fedora 44 x86_64 under both
/// compilers: 1 or 2 traps at -Og, -Os, -Oz and -O3 and under `-fPIC`,
/// `-fsanitize-undefined-trap-on-error` (gcc) and `-fsanitize-trap=all`; no trap and no
/// handler flagless, under `-fsanitize-trap=undefined` alone, `-ftrapv`, the
/// `openssf-tldr` flags (with and without `-fhardened` on gcc),
/// `-fisolate-erroneous-paths-dereference` (gcc) and `-mharden-sls=all`; and no `0f 0b`
/// under clang anywhere. That form also read `off` under a trap configuration narrower
/// than the whole sanitizer whose checks it did not exercise: `-fsanitize=bounds
/// -fsanitize-trap=bounds` and `-fsanitize=signed-integer-overflow
/// -fsanitize-trap=signed-integer-overflow`, under gcc 16.1.1 and clang 22.1.8 on x86_64.
///
/// The first function as it is, in the one-function probe, measured 2026-10-02 the same
/// way under gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64 and gcc 16.2.1 and clang
/// 22.1.8 on Fedora 44 aarch64, at -O0 and -O2: under `-fsanitize=undefined
/// -fsanitize-trap=undefined` gcc traps 8 times at -O0 and twice at -O2 (on x86_64 one
/// in the function and one in its `.cold` part), clang 5 or 6 times, with no handler
/// referenced; under each of the six groups with its own `-fsanitize-trap=` the object
/// traps once at -O2 (and `shift`, `bounds` and
/// `signed-integer-overflow` at -O0), under gcc on x86_64 at -O2 in the `.cold` part for
/// `shift`, and under `vla-bound`, which has no construct here, not at all; under
/// `-fsanitize=undefined`
/// alone, with `-fno-sanitize-recover=all`, and under clang's
/// `-fsanitize-minimal-runtime`, no trap, and the recovering, `_abort` or `_minimal`
/// handlers for `add_overflow`, `out_of_bounds`, `pointer_overflow`,
/// `shift_out_of_bounds` and `type_mismatch` (`_v1` but for the minimal runtime); flagless,
/// neither a trap nor a call. The measurements through chard are in the 2026-10-02
/// review note under "Coverage against the guide" in the project ledger.
///
/// A trap mode that routes the trap through a call is `indeterminate`: clang's
/// `-ftrap-function=NAME` turns each trap into a call to `NAME`, which leaves the function
/// with neither a trap nor a sanitizer handler, and the name is the caller's, so no watch
/// list can hold it. The probe's source calls nothing, so a call in the function (on x86_64
/// a relocated `call`, a `call` through the GOT, and under `-mcmodel=large` a `call`
/// through a register or through a GOT entry two registers address; `bl` or `blr` on
/// aarch64) with no trap and no handler is withheld rather than read as no sanitizer.
/// Anything else that puts a call there is withheld with it, and the list is not
/// exhaustive: `-fstack-protector-all`'s `__stack_chk_fail` under both compilers, gcc's
/// `-ftrapv`, which calls libgcc's `__addvsi3` (clang's `-ftrapv` traps on the signed add;
/// see below), and, measured 2026-10-02 under both compilers on both hosts above, `-pg`'s
/// `mcount` and `-fsanitize=address`'s instrumentation without the undefined-behavior
/// sanitizer.
///
/// A trap beside a handler is `indeterminate`: `-fsanitize=undefined
/// -fsanitize-trap=shift` traps the shift and calls the runtime for the rest (measured on
/// both compilers), so the sanitizer runs partly in each mode. So is a trap beside a call
/// in the function or its `.cold` part (clause `trap-beside-call`), which needs no
/// handler's name. `trap-beside-handler` reads a handler only by a name `symbol-names`
/// holds, and before `trap-beside-call` clang 22.1.8's
/// `-fsanitize-handler-preserve-all-regs` with `-fsanitize-minimal-runtime`, which calls
/// `__ubsan_handle_*_minimal_preserve`, names the watch list did not then hold, read `on`
/// under `-O2 -fsanitize=undefined -fsanitize-trap=shift`: `ud1` beside five calls on
/// Fedora 44 x86_64 and `brk` beside five `bl` on Fedora 44 aarch64 (reported 2026-10-02
/// in review). The cost is that a trap-mode build which also puts a call there for another
/// reason (`-fstack-protector-all` and `-pg` measured, the address sanitizer likewise) is
/// withheld; in the measurements the 2026-10-02 review notes record, no `on` reading held
/// a call. A function the reader did not search is `indeterminate` too, before any clause
/// about traps, so an object whose function is missing or whose machine has no pattern
/// cannot read `absent`.
///
/// clang's trap for signed overflow on an add is not read as trap mode. clang's `-ftrapv`,
/// with no sanitizer, lowers the probe's add to the same trap as
/// `-fsanitize=signed-integer-overflow -fsanitize-trap=signed-integer-overflow`, check
/// number 0 (`ud1 (%eax),%eax` on x86_64, `brk #0x5500` on aarch64), so the bytes cannot
/// say which flag the profile carries, and an `on` there credited the sanitizer's trap mode
/// to a profile with no `-fsanitize` (reported 2026-10-02 in review, clang 22.1.8 on Fedora
/// 44 x86_64, -O0 and -O2). The level clauses read clang's traps only with a nonzero check
/// number, and a function whose traps are all check 0, or a `ud1` in a form clang was not
/// measured to emit, reads `indeterminate` under `overflow-trap-only`. gcc's traps carry no
/// check number and gcc's `-ftrapv` calls `__addvsi3`, so gcc is read as before. The cost
/// is that `-fsanitize-trap=signed-integer-overflow` alone, a real trap configuration, is
/// withheld under clang; any other group trapped beside it carries its own number, and
/// `-fsanitize=undefined -fsanitize-trap=undefined` traps the probe with numbers `0x12`,
/// `0x13`, `0x14` and `0x16` as well as 0 (measured with `objdump -d`, clang 22.1.8 on
/// Fedora 44 x86_64 and aarch64, -O0 and -O2).
///
/// The first function exercises six groups, and over it alone `absent` said only that none
/// of those six trapped. A trap configuration covering only groups it does not exercise
/// read `off`: `-fsanitize=integer-divide-by-zero -fsanitize-trap=integer-divide-by-zero`
/// under gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64, and likewise `vla-bound`,
/// `unreachable`, `builtin`, `bool`, the two float groups, `nonnull-attribute`,
/// `returns-nonnull-attribute`, clang's nullability and implicit-conversion groups and its
/// `unsigned-integer-overflow` and `unsigned-shift-base`. So the probe holds three more
/// functions, each searched with gcc's `.cold` part of it, and every clause above reads all
/// four (`probes/ubsan_trap.c` lists the constructs, `elf::code::SCANS` the patterns each is
/// searched for and why):
///
/// - `chard_ubsan_trap_groups` holds a construct for each of those groups, searched for
///   every trap pattern and for the call patterns that cannot be forged there. Each group
///   alone, with its own `-fsanitize-trap=`, traps in it at -O0 and -O2 under both
///   compilers, and each alone in handler mode calls a handler `elf::WATCHED_SYMBOLS` lists,
///   so it reads `off`. The first function's code is the same byte for byte with and without
///   this one under the 14 flag sets compared per compiler (relocation addends into the
///   sanitizer's data aside), so the measurements of the first function above hold for it.
/// - `chard_ubsan_trap_sized` indexes a global array of known size through a pointer to its
///   element type, `((int *)cells)[i]`, for clang's `local-bounds` and gcc's `object-size`,
///   and is searched for the trap patterns alone: gcc 16.1.1 encodes the global's relocated
///   immediate in its `object-size` check as `49 81 e8 00 00 00 00`, which
///   `x86-call-rel32` matches. The pointer hides the array type from the front end, so
///   `bounds` (the front end's `array-bounds`) does not check the access under either
///   compiler (`objdump -d`, clang 22.1.8 and gcc 16.1.1 at -O0 and -O2), while
///   `local-bounds` and gcc's `object-size` size the object itself and check it (`ud1` with
///   check number 3 or `__ubsan_handle_local_out_of_bounds_abort`; `ud2` or
///   `__ubsan_handle_type_mismatch_v1`); `bounds` has its construct in the first function's
///   `row->cell[i]`. Indexed as an array, `cells[i]` was checked by both groups, and under
///   `-fsanitize=bounds,local-bounds -fsanitize-trap=bounds -fno-sanitize-trap=local-bounds`
///   at -O2 clang folded the `local-bounds` handler call away beneath the dominating
///   `array-bounds` trap, so the object held a trap and no handler and read `on` over a
///   build with a group in handler mode (at -O0 the call survived and it read
///   `indeterminate`); `-fsanitize=undefined,local-bounds -fsanitize-trap=undefined
///   -fno-sanitize-trap=local-bounds` at -O2 read `on` the same way. Through the pointer,
///   both read `indeterminate` under `trap-beside-handler` at -O0 and -O2.
/// - `chard_ubsan_trap_indirect` calls through a function pointer, for clang's `function`
///   (`ud1` with check number 6, or `__ubsan_handle_function_type_mismatch` in its five
///   spellings). Its check sits on an indirect call, which the call clauses would read, so
///   the function is searched for clang's `ud1` and `a64-brk-clang-check` alone; clang's
///   `-fsanitize=kcfi` puts a `ud2` (`brk #0x82NN` on aarch64) in exactly such a function
///   and no undefined-behavior sanitizer with it, and `-fsanitize=kcfi` alone reads `off` at
///   -O0 and -O2. The level clauses read the `brk` word from either aarch64 pattern.
///
/// gcc refuses both `-fsanitize=function` and `-fsanitize=local-bounds`, and
/// `elf::WATCHED_SYMBOLS` holds the nine handler spellings of the two clang groups. clang's
/// `local-bounds` sets no feature witness (`chard_ubsan_trap_feature` absent under
/// `-fsanitize=local-bounds` at -O0 and -O2, with and without `-fsanitize-trap=local-bounds`),
/// which is why it needs a construct. The group traps by default (`ud1` with check number
/// 3), and `-fno-sanitize-trap=local-bounds` calls `__ubsan_handle_local_out_of_bounds_abort`
/// (`_minimal`, `_minimal_abort` and the bare name under the minimal runtime and
/// `-fsanitize-recover`). Its check fires on an indexed access to a global array of known
/// size as well as a local one, so the construct needs no local array and no canary. Not
/// before clang 20: under Ubuntu 24.04's clang 18.1.3 (x86_64, `objdump -d` and
/// `readelf -r`, 2026-10-14) the group compiles to `ud2` with or without the negation and
/// references no handler, so the flag chooses nothing there and `on` is true of the object;
/// clang 19.1.1 reads the same through `tests/probe_sources.rs`, whose rows name the floor.
///
/// Two clauses guard the construct functions:
///
/// - `groups-unsearched`: an object whose second, third or fourth function was not
///   searched reads `indeterminate` where it
///   would read `absent`. A trap in the first function still reads as trap mode; the clause
///   sits after the trap clauses.
/// - `sanitizer-group-unexercised`: the probe defines `chard_ubsan_trap_feature` where
///   `__has_feature(undefined_behavior_sanitizer)` holds, and an object holding it with no
///   trap and no handler reads `indeterminate`. That covers the groups with no construct,
///   each measured to set the witness under both compilers: `enum` (neither compiler
///   instruments it in C), `return` (C++ only under both) and clang's `object-size`. At -O2
///   clang keeps an `object-size` check only where the access is a provable fault (a 4-byte
///   load from a 3-byte global, which gcc warns about under `-Wall`); an indexed global, a
///   variable offset into a smaller object and a wider-type access all fold away, so the
///   group has no construct under clang. At -O0 clang drops it with a warning, which the
///   observation's own `build.stderr` carries, and `off` there is true of the artifact: no
///   check exists to run in either mode, and the published notes say so. An `off` beside
///   those groups rests on `ubsan-feature-covers-unconstructed-groups` in
///   `report::ASSUMPTIONS`, where the compiler answers `__has_feature`; a gcc that does not
///   (13.3.0) never defines the witness, so there this clause never fires and
///   `report::sanitizer_group_limitation` withholds the `off` from the compile's words (the
///   measurement is on that function).
///
/// What `off` says: no construct in any of the four functions traps, the object calls no
/// sanitizer handler the predicate cannot account for, and the compiler reports no
/// undefined-behavior group enabled that the probe holds no construct for. Every group
/// either compiler instruments in C has a construct in a function the reader searches, but
/// for the three above, so a group left in handler mode beside trapped ones shows its
/// handler and reads `indeterminate` under `trap-beside-handler`, and a group trapping alone
/// shows its trap and reads `on`. The three with no construct read `indeterminate` alone,
/// under `sanitizer-group-unexercised`, in handler mode as in trap mode. One of them named
/// by `-fno-sanitize-trap=` beside trapped groups reads `on` from the artifact (measured:
/// `-O2 -fsanitize=undefined -fsanitize-trap=undefined` with `-fno-sanitize-trap=enum` under
/// both compilers, `=return` under gcc, `=object-size` under clang), which is true of the
/// artifact, since the compiler compiled no check of that group into it, and not of the
/// request. The predicate does not read the request: that would mean parsing the profile's
/// `-fsanitize=` lists with each compiler's expansion of `undefined`, which is the
/// packaging-spec reading this project does not do. `report::sanitizer_group_limitation`
/// reads the driver's own `-###` words for those groups instead, without expanding
/// `undefined`, and withholds that `on` as `indeterminate` under
/// `sanitizer-group-unmeasured`, naming the group, as it does a group whose handler the
/// compiler folds beneath a trapped check on the same access; it withholds the `off` of a
/// trapped group with no trap found the same way, which is the reading a compiler without
/// `__has_feature` needs, under every profile.
///
/// The cost, measured 2026-10-07 through chard on Fedora 44 x86_64 (gcc 16.1.1, clang
/// 22.1.8): gcc's `-fsanitize=shift-base -fsanitize-trap=shift-base`, which calls
/// `__ubsan_handle_shift_out_of_bounds` for the second function's unsigned shift, reads
/// `indeterminate` under `trap-beside-handler`. clang's `local-bounds` traps by default
/// and `-fsanitize-trap=undefined` leaves that default in place: `clang -###` lists
/// `local-bounds` in the `-fsanitize-trap=` it hands cc1 for that line, and only
/// `-fno-sanitize-trap=local-bounds` removes it. So `-fsanitize=undefined,local-bounds
/// -fsanitize-trap=undefined` (at -O0 and -O2, and with `,function`) reads `on`, and the
/// artifact traps every group named. For the same reason `-fsanitize=bounds` alone under
/// clang, with no trap flag, reads `indeterminate` under `trap-beside-handler`:
/// `array-bounds` calls its handler while `local-bounds`, which `bounds` includes, traps, a
/// mixed build read as one. gcc's `bounds` reads `off` in handler mode and `on` in trap
/// mode.
///
/// Measured 2026-10-07 through chard (`--profile explicit --probe ubsan-trap`) on Fedora 44
/// x86_64 with gcc 16.1.1 and clang 22.1.8, the probe with its second function against the
/// one-function probe: every group either accepts, alone, in trap and in handler mode, at
/// -O0 and -O2 (232 lists, 90 moved, none toward `off`); seven lists leaving a group with a
/// construct in handler mode beside trapped ones, or the reverse, all of which moved to
/// `indeterminate`; and 82 others, from the 2026-10-02 measurements above, the
/// `inert_flags` rows and trap mode beside the common hardening flags, none of which moved.
/// Over 315 builds of the probe (both compilers, -O0 to -Og, 22 to 24 flag sets each),
/// every trap and call the reader matched in the four functions was an instruction
/// `objdump -d` decodes there, the counts were equal, and no build without a sanitizer,
/// `-pg`, `-fstack-protector-all` or `-ftrapv` held a call in any of them.
///
/// Measured 2026-10-07 through chard on Fedora 44 x86_64, gcc 16.1.1 and clang 22.1.8, 89
/// flag sets, the probe with its third and fourth functions against a build without
/// them: `-O2 -fsanitize=local-bounds` `off` to `on`; `-O0 -fsanitize=object-size
/// -fsanitize-trap=object-size` under clang `off` to `off`; `-fno-sanitize-trap=function`
/// under clang at -O2 and `-fno-sanitize-trap=object-size` under gcc at -O0 and -O2, beside
/// the whole sanitizer in trap mode, `on` to `indeterminate`; `local-bounds` alone in its
/// four forms `off` to `on` and in handler mode `off` to `off`; gcc's `object-size` and
/// clang's `function` alone `indeterminate` to `on` in trap mode and to `off` in handler
/// mode (clang's `function` in the recovering, `_abort`, minimal and preserve-all-regs
/// spellings); `-fsanitize=local-bounds -ftrap-function=` `off` to `on` (the group ignores
/// the routing); every other cell unchanged, among them the whole sanitizer at -O0 to -O3,
/// -Os and -Oz, `-fPIC`, `-mcmodel=large`, `-mindirect-branch=thunk`, the `openssf-tldr`
/// flags with and without trap mode, `-fstack-protector-all`, `-ftrapv`, kcfi, `enum` and
/// `return`. Over every object those cells built, the reader's counts of `ud2`, `ud1` and
/// the call patterns in the eight functions equalled `objdump -d`'s (the same cells). The
/// same day, the same frame, `((int *)cells)[i]` against `cells[i]`:
/// the two `-fno-sanitize-trap=local-bounds` cells of the `chard_ubsan_trap_sized` item
/// moved to `indeterminate` at -O2,
/// and no other cell of the 89 (the 52- and 37-cell frames of that measurement) moved
/// against the reviewed revision. The second, third and fourth functions are unmeasured on
/// aarch64.
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
            "the probe's function was not searched for a trap: the object defines no sized \
             function of that name, or its machine has no trap pattern",
        ),
        clause(
            "trap-beside-handler",
            Cond::All(vec![traps.clone(), handlers.clone()]),
            Conclusion::Indeterminate,
            "the function traps and the object also calls a sanitizer runtime handler, so \
             some checks trap and others do not",
        ),
        clause(
            "trap-beside-call",
            Cond::All(vec![traps.clone(), calls.clone()]),
            Conclusion::Indeterminate,
            "the function traps and also makes a call: the probe's source calls nothing, so \
             the call is the compiler's, and some checks may call a handler whose name no \
             watch list holds",
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
        "the function's only traps are clang's for signed overflow on an add (ud1 or brk \
         with check number 0), which clang's -ftrapv emits with no sanitizer, or a ud1 of a \
         form the reader does not take a check number from",
    ));
    // After the trap clauses, so it reads only a function with no trap; the handler clause
    // keeps handler mode, whose failed checks are calls, at `absent`.
    clauses.push(clause(
        "call-without-trap-or-handler",
        Cond::All(vec![calls, Cond::NoneOf(vec![handlers.clone()])]),
        Conclusion::Indeterminate,
        "the function makes a call and holds no trap, and the object calls no sanitizer \
         handler: the probe's source calls nothing, so the call is the compiler's, as a \
         trap routed through a function the caller named is",
    ));
    // After every clause that reads a trap, so a trap in the first function reads as it
    // did over an object without the others; before `otherwise`, so no `absent` is read
    // over constructs that were not there to search. The clause reads all three construct
    // functions, so an object without the third and fourth reads `indeterminate` here
    // rather than `absent`.
    clauses.push(clause(
        "groups-unsearched",
        Cond::NoneOf(vec![Cond::All(vec![
            ubsan_function_searched(UBSAN_TRAP_GROUPS),
            ubsan_function_searched(UBSAN_TRAP_SIZED),
            ubsan_indirect_searched(),
        ])]),
        Conclusion::Indeterminate,
        "one of the probe's construct functions, which hold a construct for each sanitizer \
         group the first function does not exercise, was not searched: the object lacks \
         those functions or defines no sized function of that name, so a group trapping \
         there could not be read",
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
        "the compiler reports an undefined-behavior sanitizer group enabled, and no \
         function traps or calls a handler: the group is one the probe holds no construct \
         for (enum and return, which neither compiler checks in C, or clang's object-size, \
         whose check clang keeps only for a provable fault), so whether it traps was not \
         read",
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
///
/// glibc's `printf` wrapper exists from level 2 and passes `__USE_FORTIFY_LEVEL - 1` as the
/// first argument of `__printf_chk` (gcc, from the probe's own function) or `__vprintf_chk`
/// (clang, from glibc's out-of-line wrapper), so the immediate loaded into the first
/// argument register is 1 at level 2 and 2 at level 3. `elf::code` searches the three
/// functions `FORTIFY_FLAG_FUNCTIONS` names for it and holds the argument for a byte search
/// over a known function. At level 1 `printf` is not wrapped, and the `strcpy` into an
/// array of known size in the probe's second function calls `__strcpy_chk`.
///
/// Measured 2026-10-02 with `nm` and `objdump -d` over `probes/fortify_printf_flag.c`
/// compiled `-c` at -O0, -O1, -O2, -Os and -Oz with `-U_FORTIFY_SOURCE
/// -D_FORTIFY_SOURCE=N` for N from 0 to 3, gcc 16.1.1 and clang 22.1.8 on Fedora 44
/// x86_64 and gcc 16.2.1 and clang 22.1.8 on Fedora 44 aarch64, glibc 2.43 on both: at
/// level 0, and at every level under -O0, `printf` and `strcpy` and no flag; at level 1
/// `__strcpy_chk` and no flag; at level 2 `__printf_chk` (gcc) or `__vprintf_chk` (clang)
/// and flag 1, and at level 3 the same with flag 2, as `mov $N,%edi` on x86_64 (`push $N`
/// and a later `pop %rdi` at -Oz) and `mov w0, #N` on aarch64. chard from the wf-t tree
/// read the same through the predicate on Fedora 44 x86_64 under `--profile explicit` at
/// -O2 and -Oz with levels 1, 2 and 3: `partial` at 1 and 2, `on` at 3, and `off` without
/// -O and under a trailing `-U_FORTIFY_SOURCE`.
///
/// The -Oz pattern is two bytes, `6a 0N`, since gcc puts other moves between the push and
/// the pop; the function holds no constant that could carry them. A spurious match beside
/// the real flag reads both values and is withheld under `both-flags`.
///
/// Every reading the immediate cannot settle is withheld: a checking `printf` with no flag
/// found (another glibc's wrapper name, another encoding), a flag with no checking
/// `printf` referenced, and both flag values at once. A probe function the reader did not
/// search is withheld before any of those, as `ubsan-trap-mode`'s is.
///
/// FreeBSD's `<ssp/string.h>` wrappers are referenced without optimization too, under
/// clang, and check nothing there: their `__builtin_object_size` queries answer unknown at
/// -O0, so the `strcpy` into a known array calls `__strcpy_chk` with no size to hold it to.
/// Measured on FreeBSD 15.1 amd64 (clang 19.1.7), 2026-10-27: this probe's object at -O0 with
/// `-D_FORTIFY_SOURCE=2` references `__strcpy_chk` as the -O2 object does, and the
/// known-object probe built the same way survives its overrun with `__memcpy_chk`
/// referenced. So on FreeBSD a referenced `__strcpy_chk` beside no `__OPTIMIZE__` is
/// withheld (`freebsd-unoptimized`), where level 1 would be the inert form
/// `tests/inert_flags.rs` refuses; glibc never reaches the clause, since its headers
/// install no wrapper at -O0 and the symbol is absent.
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
                "the probe's printf function was not searched: the object defines no sized \
                 function of that name, or its machine has no flag pattern",
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
                "a checking printf is called and no flag argument was found in the searched \
                 code, so its level is not read",
            ),
            clause(
                "flag-without-printf-chk",
                Cond::All(vec![any_flag, Cond::NoneOf(vec![printf_chk])]),
                Conclusion::Indeterminate,
                "a flag pattern was found and no checking printf is referenced, so the \
                 pattern is not the flag argument",
            ),
            clause(
                "freebsd-unoptimized",
                Cond::All(vec![
                    Cond::Defined(Term::Macro("__FreeBSD__".to_owned())),
                    Cond::Missing(Term::Macro("__OPTIMIZE__".to_owned())),
                    defined_symbol("__strcpy_chk"),
                ]),
                Conclusion::Indeterminate,
                "FreeBSD's <ssp/string.h> wrappers are referenced without optimization, which \
                 clang allows, but their size queries answer unknown there and no copy is \
                 checked (measured on FreeBSD 15.1: the known-object overrun survived at -O0 \
                 with __memcpy_chk referenced), so a referenced __strcpy_chk says the wrapper \
                 was instantiated and not that it checks, and the level is withheld",
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
                "printf is not wrapped and strcpy calls __strcpy_chk, which is level 1",
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
///
/// The fact is [`crate::elf::ElfFacts::function_entries`], the first four bytes at each
/// function's address in the object; the `elf::entry` module carries why those bytes are
/// the function's first instruction. `probes/cet_endbr.c` defines three global functions,
/// each `noinline` and stored in a `volatile` table of function pointers, so a compiler
/// instrumenting indirect-branch targets must give each a landing pad at every -O level.
///
/// Measured 2026-10-02 with `objdump -d` over that source compiled `-c`, at `-O0`, `-O1`,
/// `-O2`, `-O3` and `-Os`: every function began with `endbr64` under
/// `-fcf-protection=branch`, `=full` and `-fcf-protection=none -fcf-protection=branch`, and
/// none did flagless, under `=return`, `=none` or `-fcf-protection=branch
/// -fcf-protection=none`, for gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64; at `-O0` and
/// `-O2` the same under gcc 15.2.0 and clang 23.1.2 on Alpine x86_64 (musl), gcc 13.3.0 and
/// clang 18.1.3 on Ubuntu 24.04 and gcc 11.4.0 and clang 14.0.0 on Ubuntu 22.04, except that
/// Ubuntu's gcc began every function with `endbr64` flagless, its packaged default being
/// `-fcf-protection`; and with `endbr32` under gcc 12.2.0 in a Debian 12 i386 container.
/// `-fcf-protection=full -fcf-protection=return` kept the landing pads under gcc 15.2.0 and
/// 16.1.1, which combine the two values, and dropped them under gcc 11.4.0, 12.2.0 and
/// 13.3.0 and every clang, where the later value replaces the earlier.
///
/// `=return` is `absent` here, not withheld: it asks for the shadow stack alone, and
/// compiles no landing pad, so an `off` for the branch half is the measurement and not a
/// silence. `cet-marked-object` reads the return half from the property note.
///
/// Withheld rather than read: a function the reader did not read (absent from the object,
/// or recorded under `function-entries`); an object whose machine has no IBT landing pad;
/// and a landing pad at some functions and not others, or of the other width, which no
/// measured flag produces and which a reading of either verdict would misstate.
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
            "a function of the probe's was not read: the object defines no function of that \
             name, or its bytes could not be reached",
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
            "some of the probe's functions begin with a landing pad and others do not, or \
             the landing pad is the other width's",
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
///
/// x86_64's `call *f@GOTPCREL(%rip)` is `R_X86_64_GOTPCRELX`; a call through a register
/// loaded from the slot first, as `-mindirect-branch=thunk` compiles it, is
/// `R_X86_64_REX_GOTPCRELX`; `R_X86_64_GOTPCREL` is the older assemblers' spelling of both.
/// i386's is `R_386_GOT32X`, and `R_386_GOT32` before it. aarch64 loads the slot with an
/// `adrp` and an `ldr` and calls the register, `R_AARCH64_ADR_GOT_PAGE` beside
/// `R_AARCH64_LD64_GOT_LO12_NC`, or with one `ldr` under `-mcmodel=tiny`,
/// `R_AARCH64_GOT_LD_PREL19`. Under gcc's small-model `-fpic` and `-fpie` the `ldr` is
/// `R_AARCH64_LD64_GOTPAGE_LO15`, an offset from the page of `_GLOBAL_OFFSET_TABLE_`, which
/// an `R_AARCH64_ADR_PREL_PG_HI21` against that symbol rather than the callee loads (gcc
/// 16.2.1, Fedora 44 aarch64, 2026-10-02). The thunk form and the tiny-model `ldr` were
/// measured after the rest: gcc 16.1.1's `-mindirect-branch=thunk-extern` and `thunk-inline` and
/// clang 22.1.8's `-mretpoline` with `-fno-plt` write `R_X86_64_REX_GOTPCRELX` against the
/// callee (Fedora 44 x86_64), and gcc 16.2.1 and clang 22.1.8 under `-mcmodel=tiny -fno-plt`
/// write `R_AARCH64_GOT_LD_PREL19` (Fedora 44 aarch64), and `R_X86_64_PLT32` and `R_AARCH64_CALL26`
/// without the flag (2026-10-02; the project ledger's -fno-plt review note).
///
/// RISC-V loads the slot with an `auipc` carrying `R_RISCV_GOT_HI20` against the callee and
/// an `ld` whose `R_RISCV_PCREL_LO12_I` names the `auipc`'s local label, then calls the
/// register: gcc 16.1.1 (Fedora 44's riscv64-linux-gnu cross compiler, on x86_64, 2026-10-05)
/// under `-fno-plt` with `-fPIE`, `-fpie`, `-fPIC` or `-fpic`, for rv64 and rv32, and
/// `R_RISCV_CALL_PLT` without the flag. The label's relocation names no callee, so only the
/// `auipc`'s is listed here.
///
/// x86_64's large-model `R_X86_64_GOT64` is not here, though gcc writes it for the call
/// under `-fpic -mcmodel=large -fno-plt`: clang 23.1.2 writes it under `-fpic
/// -mcmodel=large` without the flag too (Alpine, 2026-10-02), so it does not distinguish
/// the two, and the reading there stays `indeterminate`.
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
/// choice (gcc 16.1.1 and clang 22.1.8, Fedora 44 x86_64 cross, 2026-10-05). Its deprecated
/// `R_RISCV_CALL`, which older assemblers wrote for a call without `@plt`, is not here: no
/// toolchain on hand writes it, so no build measured the reading, and an object carrying
/// it reads `indeterminate`.
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
/// SYMBOL`. Matched by prefix, which is exact on the type, since the space ends it, and
/// exact on the symbol for the probe's object, which names no other symbol that begins
/// with [`NO_PLT_CALLEE`] (`a_prefix_match_on_a_relocation_is_an_exact_one` below holds
/// the probe source to that).
///
/// An entry whose symbol is not `STV_DEFAULT` carries the visibility as a third word; the
/// prefix match reads such an entry as it reads the two-word one.
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
///
/// The fact is [`crate::elf::ElfFacts::code_relocations`], keyed by symbol because the GOT
/// types also load external data's addresses; `probes/no_plt.c` calls
/// [`NO_PLT_CALLEE`] and does nothing else with it. A GOT relocation against it is the
/// flag's observable, and a direct one its absence.
///
/// Measured by hand on 2026-10-02 with `readelf -rW` over a translation unit of the probe's
/// shape (one function calling an undeclared-elsewhere external and adding one), compiled
/// `-c` with no flag, `-fno-plt`, `-fplt`, and both orders of the two, each at `-O0` and
/// `-O2` and under `-fno-pic`, and on the two Fedora hosts under `-fPIE` and `-fPIC` too:
/// - x86_64, gcc 16.1.1 and clang 22.1.8 (Fedora 44), gcc 11.4.0 and clang 14.0.0 (Ubuntu
///   22.04), gcc 13.3.0 and clang 18.1.3 (Ubuntu 24.04), gcc 15.2.0 and clang 23.1.2
///   (Alpine, musl): `R_X86_64_PLT32` without the flag and `R_X86_64_GOTPCRELX` with it,
///   under every position-independence choice, the last of the two flags winning.
/// - i386, gcc 12.2.0 (Debian 12): `R_386_PLT32`, or `R_386_PC32` under `-fno-pic`, without
///   it, and `R_386_GOT32X` with it, the last flag winning.
/// - aarch64, clang 22.1.8 (Fedora 44): `R_AARCH64_CALL26` without and the GOT pair with,
///   under every choice. gcc 16.2.1 (Fedora 44), 13.3.0 (Ubuntu 24.04) and 12.2.0 (Debian
///   12) emit the GOT pair only for position-independent code: under `-fPIE`, `-fPIC`, or
///   no choice where the compiler defaults to PIE (Ubuntu's and Debian's), and
///   `R_AARCH64_CALL26` under `-fno-pic` or where it does not (Fedora's gcc), with the flag
///   or without. That is the flag doing nothing, and the call does go through the PLT, so
///   the reading is `absent`; the check's positive control carries `-fPIE` so the triple
///   still shows the instrument can see the flag there.
/// - gcc under `-flto` writes an object with no code and so no relocation naming the
///   callee, and clang's is LLVM bitcode, which the reader refuses.
///
/// The small-model `-fpie` and `-fpic`, measured 2026-10-02 apart from the above: under
/// those gcc
/// 16.2.1 on Fedora 44 aarch64 does honour the flag, with a different `ldr`: the callee's
/// entry is `R_AARCH64_LD64_GOTPAGE_LO15` beside an `R_AARCH64_ADR_PREL_PG_HI21` against
/// `_GLOBAL_OFFSET_TABLE_`, a type [`GOT_CALL_TYPES`] lists; without the flag the call is
/// `R_AARCH64_CALL26`. x86_64's large model under PIC is `indeterminate` by design: gcc
/// 15.2.0 on Alpine writes `R_X86_64_GOT64` for the call with `-fpic -mcmodel=large
/// -fno-plt` and `R_X86_64_PLTOFF64` without the flag, but clang 23.1.2 there writes
/// `R_X86_64_GOT64` under `-fpic -mcmodel=large` without the flag, so the type does not
/// tell the two apart. The entries are `TYPE SYMBOL` over every named symbol, defined or
/// not, with an unnamed type spelt `reloc-type-` and hex, so that one reader and one
/// encoding serve every check that reads an object's relocations; a relocation through a
/// section symbol is listed as `TYPE [section]`, which no clause here matches.
///
/// RISC-V, measured 2026-10-05 the same way with Fedora 44's riscv64-linux-gnu
/// cross compilers on x86_64 over a file holding the probe's caller and callee declaration
/// alone (the cross gcc has no C library headers, so `probes/no_plt.c` itself does not
/// build), at `-O0` and `-O2`, with no position-independence choice, `-fno-pic`, `-fPIE`,
/// `-fPIC`, `-fpie` and `-fpic`, and the five flag spellings above:
/// - gcc 16.1.1: `R_RISCV_GOT_HI20` under `-fno-plt` in position-independent code and
///   `R_RISCV_CALL_PLT` otherwise, the last flag winning; with no choice or under
///   `-fno-pic`, `R_RISCV_CALL_PLT` with the flag or without, the aarch64 gcc shape, so
///   the positive control's `-fPIE` serves here too. The same for rv32 (`-march=rv32gc
///   -mabi=ilp32d`), under `-mcmodel=medlow` and `medany`, and under
///   `-march=rv64gc_zicfilp_zicfiss -fcf-protection=full`, where the call goes through
///   `t2` after a `mv`. Under `-mcmodel=large`, which refuses PIC, the callee's address
///   is `R_RISCV_64` in a literal pool, a type on neither list.
/// - clang 22.1.8: `R_RISCV_CALL_PLT` under every choice, `-fno-plt` included, with
///   `argument unused during compilation: '-fno-plt'`. The flag does nothing there, the
///   positive control reads `absent`, and the triple does not discriminate.
///
/// Every reading that is neither is withheld. `null` is an object that is not relocatable
/// or has no section headers. No relocation naming the callee is the vacuous case the
/// recipe measured, a file without an external call, here a caller deleted or compiled to
/// IR; both kinds at once is a reading no build measured gave, and a type on neither list
/// cannot be classified: one the reader does not name (`reloc-type-` and hex, every machine
/// but these four), or one it names that is not a call's (`R_X86_64_64` under x86_64's
/// large model, `R_X86_64_GOT64` and `R_X86_64_PLTOFF64` under its large-model PIC, and
/// `R_RISCV_64` under RISC-V's large model). A relocation section the reader could not
/// finish is the `@truncated` step's, through the tables.
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
            "the object is not relocatable or has no section headers, so the relocations \
             the compiler emitted for its calls cannot be read",
        ),
        clause(
            "both-forms",
            Cond::All(vec![
                callee_relocated(GOT_CALL_TYPES),
                callee_relocated(PLT_CALL_TYPES),
            ]),
            Conclusion::Indeterminate,
            "the probe's one external call is relocated both through the GOT and as a \
             direct call, which no build measured produced",
        ),
        clause(
            "got-call",
            callee_relocated(GOT_CALL_TYPES),
            Conclusion::Present(LevelOf::None),
            "the probe's external call is relocated through the callee's GOT slot, so it \
             bypasses the PLT",
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
        ("cet-endbr-emitted", cet_endbr),
        ("plt-bypassed", plt_bypassed),
        ("pic-object-relocs", pic_object),
    ]
}

#[cfg(test)]
mod tests {
    use super::{GOT_CALL_TYPES, NO_PLT_CALLEE, PLT_CALL_TYPES};
    use crate::elf::reloc_type_name;

    /// The four machines whose relocation types `elf::reloc_type_name` names, by
    /// `e_machine`: x86_64, i386, aarch64, riscv.
    const MACHINES: [u16; 4] = [62, 3, 183, 243];

    /// `callee_relocated` matches `TYPE SYMBOL` by prefix. The type is delimited by the
    /// space, so the match on it is exact; this holds that each listed type is a name the
    /// reader gives and that no type is on both lists. The symbol is the last token, so the
    /// match on it is exact as long as the probe names no other symbol that begins with
    /// the callee's name, which the probe source is held to here.
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
