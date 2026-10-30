// SPDX-License-Identifier: BSD-3-Clause

//! The synthetic ELF fixtures under `tests/fixtures/elf/`: what is checked in is what
//! the builder builds, and what the reader reads from it is what the record beside it
//! says.
//!
//! Three things are pinned, and each catches a different drift. The bytes against the
//! builder, so a fixture cannot be edited by hand and a builder change cannot go
//! unrecorded. The reader's facts against the recorded `.expected.json`, so a change in
//! what the reader says about a fixed input surfaces as a red test before it can reach
//! a published table. And a short table of the facts each fixture was *built* to carry,
//! written by hand, so the recorded JSON cannot be regenerated into agreement with a
//! wrong reader without a human noticing the fact it was built for.
//!
//! Regenerate both files with `CHARD_REGENERATE_ELF_FIXTURES=1`, and read the diff: the
//! record is evidence, and a regeneration that makes a test green needs a reason.
//!
//! Every fixture here is synthetic, which the record says in its first field. None was
//! produced by a linker, so the ELF32, big-endian and relocatable cases are pinned by
//! bytes this builder wrote, with no toolchain's output behind them; `tests/elf_readelf.rs`
//! is what compares the reader against an independent oracle over them.

use std::path::PathBuf;

mod common;
mod elf_builder;

use chard::elf;
use common::ELF_FIXTURE_COUNT;
use elf_builder::{RiscvCall, catalogue};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf")
}

fn regenerating() -> bool {
    std::env::var_os("CHARD_REGENERATE_ELF_FIXTURES").is_some()
}

/// The record beside each fixture's bytes.
#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    synthetic: bool,
    built_by: String,
    description: String,
    facts: serde_json::Value,
}

/// The bytes checked in are the bytes the builder produces, byte for byte.
#[test]
fn the_checked_in_bytes_are_what_the_builder_builds() {
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).expect("the fixture directory exists");
    let fixtures = catalogue();
    assert_eq!(
        fixtures.len(),
        ELF_FIXTURE_COUNT,
        "the catalogue changed size"
    );
    let mut compared = 0;
    for f in &fixtures {
        let path = dir.join(format!("{}.elf", f.name));
        if regenerating() {
            std::fs::write(&path, &f.bytes).expect("writing the fixture");
        }
        let on_disk = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; regenerate with CHARD_REGENERATE_ELF_FIXTURES=1",
                path.display()
            )
        });
        assert!(
            on_disk == f.bytes,
            "{}: the checked-in bytes differ from the builder's ({} vs {} bytes). Either the \
             builder changed, in which case regenerate and record why, or the file was \
             edited by hand, which is not how a fixture changes.",
            path.display(),
            on_disk.len(),
            f.bytes.len()
        );
        compared += 1;
    }
    assert_eq!(compared, ELF_FIXTURE_COUNT);
}

/// The reader's facts about each fixture are the facts on record.
#[test]
fn the_checked_in_facts_are_what_the_reader_reads() {
    let dir = fixture_dir();
    let fixtures = catalogue();
    let mut compared = 0;
    for f in &fixtures {
        let path = dir.join(format!("{}.expected.json", f.name));
        let facts = elf::Elf::parse(&f.bytes)
            .unwrap_or_else(|e| panic!("{}: the builder's bytes do not parse: {e}", f.name))
            .facts();
        let live = serde_json::to_value(&facts).expect("facts serialize");
        if regenerating() {
            let record = Record {
                synthetic: true,
                built_by: "tests/elf_builder/mod.rs".to_owned(),
                description: f.description.to_owned(),
                facts: live.clone(),
            };
            let text = serde_json::to_string_pretty(&record).expect("record serializes");
            std::fs::write(&path, format!("{text}\n")).expect("writing the record");
        }
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; regenerate with CHARD_REGENERATE_ELF_FIXTURES=1",
                path.display()
            )
        });
        let record: Record = serde_json::from_str(&text).expect("the record parses");
        assert!(
            record.synthetic,
            "{}: every fixture here is synthetic and must say so",
            f.name
        );
        assert_eq!(
            record.description, f.description,
            "{}: the description drifted",
            f.name
        );
        assert!(
            record.facts == live,
            "{}: the reader now says something different from the record.\n  record: {}\n  live:   {}\nRead the \
             difference and decide which is right before regenerating.",
            f.name,
            record.facts,
            live
        );
        compared += 1;
    }
    assert_eq!(compared, ELF_FIXTURE_COUNT);
}

/// The facts each fixture was built to carry, by hand.
///
/// Independent of the recorded JSON on purpose: the record is what the reader said, and
/// this is what the input is. A regeneration that makes the record agree with a wrong
/// reader still has to get past these.
#[test]
fn each_fixture_carries_the_facts_it_was_built_to_carry() {
    let mut checked = 0;
    for f in catalogue() {
        let facts = elf::Elf::parse(&f.bytes).expect("parses").facts();
        let recognised = [
            expect_bind_now,
            expect_kinds,
            expect_static_pies,
            expect_widths,
            expect_riscv,
            expect_forged_marking,
        ]
        .iter()
        .filter(|table| table(f.name, &facts))
        .count();
        assert_eq!(
            recognised, 1,
            "{}: exactly one expectation table must know this fixture",
            f.name
        );
        checked += 1;
    }
    assert_eq!(checked, ELF_FIXTURE_COUNT);
}

/// The control and the three `BIND_NOW` spellings. Returns whether `name` is one of them.
fn expect_bind_now(name: &str, facts: &elf::ElfFacts) -> bool {
    let canary = facts.watched_symbols.get("__stack_chk_fail");
    match name {
        "elf64-le-x86_64-exec-relro-lazy" => {
            assert_eq!((facts.elf_class, facts.elf_type.as_str()), (64, "ET_EXEC"));
            assert_eq!(facts.machine, "x86_64");
            assert_eq!(facts.relro.as_deref(), Some("partial"));
            assert_eq!(facts.bind_now, Some(false));
            assert_eq!(facts.pie, Some(false));
            assert_eq!(facts.statically_linked, Some(false));
            assert!(facts.x86_ibt && facts.x86_shstk);
            assert_eq!(facts.needed, vec!["libc.so.6".to_owned()]);
            let canary = canary.expect("the canary is watched");
            assert_eq!(
                canary.tables,
                vec![".dynsym".to_owned(), ".symtab".to_owned()]
            );
            assert_eq!(
                canary.versioned,
                vec!["__stack_chk_fail@GLIBC_2.4".to_owned()]
            );
            assert!(!canary.defined);
            assert!(facts.truncations.is_empty(), "{:?}", facts.truncations);
        }
        "elf64-le-x86_64-exec-dt-bind-now"
        | "elf64-le-x86_64-exec-df-bind-now"
        | "elf64-le-x86_64-exec-df-1-now" => {
            assert_eq!(facts.bind_now, Some(true), "{name}");
            assert_eq!(facts.relro.as_deref(), Some("full"), "{name}");
            assert_eq!(facts.gnu_relro, Some(true));
        }
        _ => return false,
    }
    true
}

/// The static executable: no interpreter, no dynamic section, a `.symtab` alone, and the
/// link classification a static link gets.
fn expect_static_executable(facts: &elf::ElfFacts) {
    assert_eq!((facts.elf_class, facts.elf_type.as_str()), (64, "ET_EXEC"));
    assert!(!facts.has_interp && !facts.has_dynamic);
    assert_eq!(facts.statically_linked, Some(true));
    assert_eq!(facts.pie, Some(false));
    assert_eq!(facts.static_pie, Some(false));
    assert_eq!(facts.shared_object, Some(false));
    assert!(facts.needed.is_empty() && facts.dynamic_tags.is_empty());
    assert_eq!(facts.gnu_relro, Some(false));
    assert_eq!(facts.relro.as_deref(), Some("none"));
    assert_eq!(facts.gnu_stack_executable, Some(false));
    assert!(facts.x86_ibt && facts.x86_shstk);
    assert_eq!(facts.symbol_tables, vec![".symtab".to_owned()]);
    assert!(
        !facts
            .sections
            .iter()
            .any(|s| s == ".dynamic" || s == ".dynsym" || s == ".dynstr"),
        "{:?}",
        facts.sections
    );
    let canary = facts
        .watched_symbols
        .get("__stack_chk_fail")
        .expect("the canary is watched");
    assert_eq!(canary.tables, vec![".symtab".to_owned()]);
    assert!(facts.truncations.is_empty(), "{:?}", facts.truncations);
}

/// The stripped copy, the shared object, the static executable, the three relocatable
/// objects and the executable with lld's `.comment`.
fn expect_kinds(name: &str, facts: &elf::ElfFacts) -> bool {
    let canary = facts.watched_symbols.get("__stack_chk_fail");
    match name {
        "elf64-le-x86_64-exec-lld-comment" => {
            assert_eq!(
                facts.comment,
                vec![
                    "GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)".to_owned(),
                    "Linker: LLD 22.1.8".to_owned(),
                ],
                "first occurrences, in file order"
            );
            assert!(
                facts.comment_truncation().is_none(),
                "{:?}",
                facts.truncations
            );
            assert!(facts.sections.iter().any(|s| s == ".comment"));
            assert_eq!(facts.bind_now, Some(false), "otherwise the control");
        }
        "elf64-le-x86_64-exec-stripped-section-headers" => {
            assert!(facts.sections.is_empty());
            assert_eq!(facts.symbol_count, 0);
            // `.comment` could not be looked up, and the field says so; an empty list
            // would read as a section read to its end with no lines.
            assert!(facts.comment.is_empty());
            assert!(
                facts
                    .comment_truncation()
                    .is_some_and(|why| why.contains("could not be looked up")),
                "{:?}",
                facts.truncations
            );
            assert!(canary.is_none());
            assert!(
                facts.truncations.iter().any(|t| {
                    t.table == elf::ElfTable::Symbols
                        && t.kind == elf::TruncationKind::Unread
                        && t.detail.starts_with("no section-header table")
                }),
                "{:?}",
                facts.truncations
            );
            // Reached through the segments the loader reads.
            assert_eq!(facts.bind_now, Some(true));
            assert_eq!(facts.relro.as_deref(), Some("full"));
            assert!(facts.x86_ibt && facts.x86_shstk);
            assert_eq!(facts.needed, vec!["libc.so.6".to_owned()]);
        }
        "elf64-le-x86_64-exec-static" => expect_static_executable(facts),
        "elf64-le-x86_64-shared-object" => {
            assert_eq!(facts.elf_type, "ET_DYN");
            assert_eq!(facts.shared_object, Some(true));
            assert_eq!(facts.pie, Some(false));
            assert_eq!(facts.static_pie, Some(false));
            assert_eq!(facts.statically_linked, Some(false));
            assert!(
                facts.dt_soname && !facts.dt_debug,
                "a name, and no executable mark"
            );
            assert!(facts.df_1_noopen);
            assert!(facts.textrel, "DT_TEXTREL as a standalone tag");
            assert_eq!(facts.gnu_stack_executable, Some(true));
            assert_eq!(facts.relro.as_deref(), Some("none"));
            assert_eq!(facts.rpath, vec!["/opt/chard/lib".to_owned()]);
            assert_eq!(facts.runpath, vec!["$ORIGIN/../lib".to_owned()]);
        }
        "elf64-le-x86_64-rel" => {
            assert_eq!(facts.elf_type, "ET_REL");
            assert!(facts.x86_ibt && facts.x86_shstk, "the marking a .o carries");
            for (field, value) in [
                ("pie", facts.pie),
                ("static_pie", facts.static_pie),
                ("shared_object", facts.shared_object),
                ("statically_linked", facts.statically_linked),
                ("gnu_relro", facts.gnu_relro),
                ("bind_now", facts.bind_now),
                ("gnu_stack_present", facts.gnu_stack_present),
                ("gnu_stack_executable", facts.gnu_stack_executable),
            ] {
                assert_eq!(value, None, "{field} must be null for a relocatable object");
            }
            assert_eq!(facts.relro, None);
            let canary = canary.expect("the undefined reference is watched");
            assert!(!canary.defined);
            assert_eq!(canary.tables, vec![".symtab".to_owned()]);
            assert_eq!(facts.symbol_count, 2);
            // One function of size 0 and no relocation section: listed, referring to nothing.
            assert_eq!(
                facts.function_references,
                Some(vec!["chard_test_probe:".to_owned()])
            );
        }
        "elf64-le-x86_64-rel-functions" => expect_function_references(facts, "__stack_chk_fail"),
        "elf32-le-i386-rel-functions" => {
            assert_eq!(facts.elf_class, 32);
            expect_function_references(facts, "__stack_chk_fail_local");
        }
        _ => return false,
    }
    true
}

/// The executable whose CET marking its code does not carry: both property bits, and the
/// `cet-endbr` probe's functions each read at its address with no `endbr64`.
fn expect_forged_marking(name: &str, facts: &elf::ElfFacts) -> bool {
    if name != "elf64-le-x86_64-exec-cet-forged" {
        return false;
    }
    assert_eq!(
        (facts.elf_type.as_str(), facts.machine.as_str()),
        ("ET_EXEC", "x86_64")
    );
    assert!(
        facts.x86_ibt && facts.x86_shstk,
        "both bits, as the linker forced them"
    );
    assert_eq!(
        facts.function_entries,
        vec![
            "chard_ibt_target_a=8d4701c3".to_owned(),
            "chard_ibt_target_b=8d4702c3".to_owned(),
            "chard_ibt_target_c=8d4703c3".to_owned(),
        ],
        "each function read at its address, and none begins with endbr64"
    );
    let canary = facts.watched_symbols.get("__stack_chk_fail");
    assert!(!canary.expect("the canary is watched").defined);
    assert!(facts.truncations.is_empty(), "{:?}", facts.truncations);
    true
}

/// A relocatable object with the four functions: each function's references, attributed
/// by range, the canary reference against `canary`.
fn expect_function_references(facts: &elf::ElfFacts, canary: &str) {
    assert_eq!(facts.elf_type, "ET_REL");
    let refs = |f: &str, targets: &[&str]| {
        std::iter::once(format!("{f}:"))
            .chain(targets.iter().map(|t| format!("{f}:{t}")))
            .collect::<Vec<_>>()
    };
    let expected: Vec<String> = [
        refs("ssp_any", &["ssp_use"]),
        refs("ssp_addr_taken", &[canary, "ssp_escape"]),
        refs("ssp_char_array", &[canary, "ssp_escape"]),
        refs("ssp_alloca", &[canary, "ssp_escape"]),
    ]
    .concat();
    assert_eq!(facts.function_references, Some(expected));
    assert!(facts.truncations.is_empty(), "{:?}", facts.truncations);
}

/// Six objects: three static PIEs, one marked by `DF_1_PIE`, one by `DT_DEBUG` alone, and
/// one marked by neither, which the reader classifies as a shared object; and the three
/// shapes on which the classification and the `DT_NEEDED` list disagree, a static PIE given
/// an interpreter, one given an interpreter and one shared library, and a PIE linked with no
/// interpreter.
fn expect_static_pies(name: &str, facts: &elf::ElfFacts) -> bool {
    match name {
        "elf64-le-x86_64-static-pie-interp-libz" => {
            assert_eq!(facts.elf_type, "ET_DYN");
            assert!(facts.has_interp && facts.has_dynamic);
            assert!(facts.df_1_pie && facts.dt_debug && !facts.dt_soname);
            assert_eq!(
                facts.needed,
                ["libz.so.1"],
                "one shared library, no C library"
            );
            assert_eq!(facts.pie, Some(true), "an interpreter decides");
            assert_eq!(facts.static_pie, Some(false));
            assert_eq!(facts.shared_object, Some(false));
            assert_eq!(facts.statically_linked, Some(false));
        }
        "elf64-le-x86_64-static-pie-interp" => {
            assert_eq!(facts.elf_type, "ET_DYN");
            assert!(facts.has_interp && facts.has_dynamic);
            assert!(facts.df_1_pie && facts.dt_debug && !facts.dt_soname);
            assert!(facts.needed.is_empty(), "libm and libc came from archives");
            assert_eq!(facts.pie, Some(true), "an interpreter decides");
            assert_eq!(facts.static_pie, Some(false));
            assert_eq!(facts.shared_object, Some(false));
            assert_eq!(facts.statically_linked, Some(false));
        }
        "elf64-le-x86_64-pie-no-interp-needed" => {
            assert_eq!(facts.elf_type, "ET_DYN");
            assert!(!facts.has_interp && facts.has_dynamic);
            assert!(!facts.df_1_pie, "no DT_FLAGS_1 at all");
            assert!(facts.dt_debug && !facts.dt_soname);
            assert_eq!(facts.needed, ["libc.so.6", "libm.so.6"], "the list is kept");
            assert_eq!(facts.static_pie, Some(true), "DT_DEBUG marks it executable");
            assert_eq!(facts.pie, Some(true));
            assert_eq!(facts.shared_object, Some(false));
            assert_eq!(facts.statically_linked, Some(true));
        }
        "elf64-le-x86_64-static-pie-relr" => {
            assert_eq!(facts.static_pie, Some(true));
            assert_eq!(facts.pie, Some(true));
            assert_eq!(
                facts.statically_linked,
                Some(true),
                "a static PIE is statically linked"
            );
            assert_eq!(facts.shared_object, Some(false));
            assert!(facts.dt_relr);
            assert_eq!(facts.bind_now, Some(true));
        }
        "elf64-le-x86_64-static-pie-dt-debug" => {
            assert_eq!(facts.elf_type, "ET_DYN");
            assert!(!facts.has_interp);
            assert!(!facts.df_1_pie, "no DT_FLAGS_1 at all");
            assert!(facts.dt_debug && !facts.dt_soname);
            assert_eq!(facts.static_pie, Some(true), "DT_DEBUG marks it executable");
            assert_eq!(facts.pie, Some(true));
            assert_eq!(facts.shared_object, Some(false));
            assert_eq!(facts.statically_linked, Some(true));
        }
        "elf64-le-x86_64-static-pie-unmarked" => {
            assert_eq!(facts.elf_type, "ET_DYN");
            assert!(!facts.has_interp && facts.has_dynamic);
            assert!(!facts.df_1_pie && !facts.dt_debug && !facts.dt_soname);
            assert!(facts.needed.is_empty(), "a static PIE records no library");
            assert_eq!(
                facts.shared_object,
                Some(true),
                "with neither marker the tags are a shared object's"
            );
            assert_eq!(facts.pie, Some(false));
            assert_eq!(facts.static_pie, Some(false));
            assert_eq!(facts.statically_linked, Some(false));
        }
        _ => return false,
    }
    true
}

/// ELF32 in both byte orders and ELF64 big-endian.
fn expect_widths(name: &str, facts: &elf::ElfFacts) -> bool {
    let canary = facts.watched_symbols.get("__stack_chk_fail");
    match name {
        "elf32-le-i386-pie" => {
            assert_eq!((facts.elf_class, facts.machine.as_str()), (32, "i386"));
            assert_eq!(facts.elf_data, Some(elf::ByteOrder::LittleEndian));
            assert_eq!(facts.pie, Some(true));
            assert!(facts.df_1_pie);
            assert_eq!(facts.bind_now, Some(true), "DF_BIND_NOW at ELF32 width");
            assert_eq!(facts.relro.as_deref(), Some("full"));
            assert!(
                facts.x86_ibt && !facts.x86_shstk,
                "IBT only, from a 4-byte-aligned note"
            );
            assert_eq!(facts.needed, vec!["libc.so.6".to_owned()]);
            let canary = canary.expect("the canary is watched at ELF32 width");
            assert_eq!(
                canary.tables,
                vec![".dynsym".to_owned(), ".symtab".to_owned()]
            );
        }
        "elf32-be-ppc-exec" => {
            assert_eq!((facts.elf_class, facts.machine.as_str()), (32, "ppc"));
            assert_eq!(facts.elf_data, Some(elf::ByteOrder::BigEndian));
            assert_eq!(facts.bind_now, Some(true), "DT_BIND_NOW read big-endian");
            assert_eq!(facts.relro.as_deref(), Some("full"));
            assert_eq!(facts.gnu_property_types, vec!["0xc0000002".to_owned()]);
            assert!(
                !facts.x86_ibt && !facts.x86_shstk,
                "listed and left undecoded on PowerPC"
            );
            assert_eq!(facts.needed, vec!["libc.so.6".to_owned()]);
            assert!(canary.is_some(), "symbols read big-endian");
            assert_eq!(facts.sections.len(), 9, "{:?}", facts.sections);
        }
        "elf64-be-aarch64-pie-bti-pac" => {
            assert_eq!((facts.elf_class, facts.machine.as_str()), (64, "aarch64"));
            assert_eq!(facts.elf_data, Some(elf::ByteOrder::BigEndian));
            assert_eq!(facts.pie, Some(true));
            assert_eq!(facts.bind_now, Some(true), "DF_1_NOW read big-endian");
            assert!(facts.aarch64_bti && facts.aarch64_pac && !facts.aarch64_gcs);
            assert!(!facts.x86_ibt);
            assert_eq!(facts.gnu_property_notes.get("0xc0000000"), Some(&1));
            assert!(canary.is_some(), "symbols read big-endian at ELF64 width");
        }
        "elf32-le-aarch64-ilp32-exec" => {
            assert_eq!(
                (facts.elf_class, facts.elf_data, facts.machine.as_str()),
                (32, Some(elf::ByteOrder::LittleEndian), "aarch64")
            );
            assert_eq!(facts.elf_type, "ET_EXEC");
            assert_eq!(facts.bind_now, Some(true), "DT_BIND_NOW at ELF32 width");
            assert_eq!(facts.relro.as_deref(), Some("full"));
            assert!(
                facts.aarch64_bti && !facts.aarch64_pac,
                "BTI on its own machine"
            );
            assert!(canary.is_some(), "symbols read at ELF32 width");
        }
        "elf32-le-x86_64-x32-exec" => {
            assert_eq!(
                (facts.elf_class, facts.elf_data, facts.machine.as_str()),
                (32, Some(elf::ByteOrder::LittleEndian), "x86_64")
            );
            assert_eq!(facts.pie, Some(true));
            assert_eq!(facts.bind_now, Some(true), "DF_1_NOW at ELF32 width");
            assert!(
                facts.x86_ibt && facts.x86_shstk,
                "the x86 feature word on its machine"
            );
            assert!(canary.is_some());
        }
        "elf64-be-ppc64-exec" => {
            assert_eq!(
                (facts.elf_class, facts.elf_data, facts.machine.as_str()),
                (64, Some(elf::ByteOrder::BigEndian), "ppc64")
            );
            assert_eq!(facts.bind_now, Some(true), "DT_BIND_NOW read big-endian");
            assert_eq!(facts.relro.as_deref(), Some("full"));
            assert!(
                facts.gnu_property_types.is_empty(),
                "{:?}",
                facts.gnu_property_types
            );
            assert!(!facts.x86_ibt && !facts.aarch64_bti);
            assert!(canary.is_some(), "symbols read big-endian at ELF64 width");
        }
        _ => return false,
    }
    true
}

/// The RISC-V object: its relocations named, its `0xc0000000` property listed and not
/// decoded, and its `.riscv.attributes` listed with nothing cut.
fn expect_riscv(name: &str, facts: &elf::ElfFacts) -> bool {
    if name != "elf64-le-riscv-rel-no-plt-got" {
        return false;
    }
    assert_eq!(
        (
            facts.elf_class,
            facts.machine.as_str(),
            facts.elf_type.as_str()
        ),
        (64, "riscv", "ET_REL")
    );
    assert_eq!(
        facts.code_relocations,
        Some(riscv_relocations(RiscvCall::Got))
    );
    assert_eq!(
        facts.function_references,
        Some(vec![
            "chard_no_plt_caller:".to_owned(),
            "chard_no_plt_caller:.L0 ".to_owned(),
            "chard_no_plt_caller:chard_no_plt_callee".to_owned(),
        ]),
        "the label and the callee, attributed to the caller's range"
    );
    expect_riscv_property(facts);
    assert!(
        facts.sections.iter().any(|s| s == ".riscv.attributes"),
        "{:?}",
        facts.sections
    );
    assert!(facts.truncations.is_empty(), "{:?}", facts.truncations);
    true
}

/// The `0xc0000000` property on `EM_RISCV`, holding 3: listed by type, counted once, and
/// read as no feature bit of any other machine, since on RISC-V it is
/// `GNU_PROPERTY_RISCV_FEATURE_1_AND` (landing pads and shadow stack) and on aarch64 the 3
/// would be BTI and PAC.
fn expect_riscv_property(facts: &elf::ElfFacts) {
    assert_eq!(facts.gnu_property_types, vec!["0xc0000000".to_owned()]);
    assert_eq!(facts.gnu_property_notes.get("0xc0000000"), Some(&1));
    assert_eq!(
        [
            facts.aarch64_bti,
            facts.aarch64_pac,
            facts.aarch64_gcs,
            facts.x86_ibt,
            facts.x86_shstk,
        ],
        [false; 5],
        "RISC-V's feature word decoded as another machine's"
    );
}

/// What `code_relocations` holds for each of the builder's RISC-V objects: the callee's
/// relocation, and under the GOT form the label's, whose name carries GNU as's trailing
/// space. `R_RISCV_RELAX` and `R_RISCV_ALIGN` are against symbol 0 and name nothing.
fn riscv_relocations(call: RiscvCall) -> Vec<String> {
    match call {
        RiscvCall::Got => vec![
            "R_RISCV_GOT_HI20 chard_no_plt_callee",
            "R_RISCV_PCREL_LO12_I .L0 ",
        ],
        RiscvCall::Plt => vec!["R_RISCV_CALL_PLT chard_no_plt_callee"],
    }
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// `plt-bypassed` over the builder's two RISC-V objects: the GOT form reads `present` and
/// the PLT form `absent`, each by its own clause.
///
/// Without RISC-V's type names, both objects' entries would be `reloc-type-0x14` and
/// `reloc-type-0x13`, which no clause matches, and both would read `indeterminate`, the safe
/// direction. The reader names them because of a measurement, not this test: gcc
/// 16.1.1 (Fedora 44's riscv64 cross compiler, 2026-10-05) writes these two shapes under
/// `-fPIE` with and without `-fno-plt`, the measurements `predicate::elf_static`'s
/// `PLT_BYPASSED` carries.
#[test]
fn plt_bypassed_reads_the_riscv_got_call_present_and_the_plt_call_absent() {
    use chard::predicate::{self, Live, elf_static};
    use chard::probe::Outcome;
    let mut read = 0;
    for (call, outcome, clause) in [
        (RiscvCall::Got, Outcome::Present, "got-call"),
        (RiscvCall::Plt, Outcome::Absent, "plt-call"),
    ] {
        let facts = elf::Elf::parse(&elf_builder::relocatable_riscv_no_plt(call).build())
            .expect("the builder's object parses")
            .facts();
        assert_eq!(
            facts.code_relocations,
            Some(riscv_relocations(call)),
            "{call:?}"
        );
        expect_riscv_property(&facts);
        let evaluation = predicate::evaluate(
            elf_static::plt_bypassed(),
            &Live {
                macros: None,
                elf: Some(&facts),
            },
        )
        .expect("a live view is complete");
        assert_eq!(
            (evaluation.outcome, evaluation.clause.as_str()),
            (outcome, clause),
            "{call:?}"
        );
        read += 1;
    }
    assert_eq!(read, 2);
}

/// `code_relocations` on the builder's objects: the relocation a `.rela.text` holds,
/// named by machine and keyed on its symbol; nothing for a relocation section patching
/// data; a type no row names spelt by number; an i386 `SHT_REL` entry in the ELF32
/// layout; a hidden anchor's visibility as a third word at both widths; and `None` on a
/// linked object, whose static relocations are gone.
///
/// The objects are synthetic, so this holds the reader's arithmetic over the two entry
/// layouts and its filters, not what a compiler writes; the measurements of that are
/// beside `pic-object-relocs`' predicate.
#[test]
fn code_relocations_name_the_type_and_symbol_of_each_relocation_in_code() {
    use elf_builder::{EM_PPC, Object, relocatable, relocatable_with_code_relocation};
    let facts = |object: &Object| {
        elf::Elf::parse(&object.build())
            .expect("the builder's object parses")
            .facts()
    };
    let anchor = |kind: &str| Some(vec![format!("{kind} chard_pic_object_anchor")]);

    let object = relocatable_with_code_relocation();
    let read = facts(&object);
    assert_eq!(
        read.code_relocations,
        anchor("R_X86_64_REX_GOTPCRELX"),
        "{:?}",
        read.truncations
    );
    assert!(read.truncations.is_empty(), "{:?}", read.truncations);

    // A relocatable object with no relocation section lists none; a linked one is `None`.
    assert_eq!(facts(&relocatable()).code_relocations, Some(Vec::new()));
    assert_eq!(
        facts(&elf_builder::linked_default().object()).code_relocations,
        None
    );

    // The same entry patching the property note, which is not code, is not read.
    let mut data = relocatable_with_code_relocation();
    let rela = data
        .sections
        .iter_mut()
        .find(|s| s.name == ".rela.text")
        .expect("a .rela.text");
    rela.info = 2;
    assert_eq!(facts(&data).code_relocations, Some(Vec::new()));

    // On a machine with no name table, type 42 is spelt by number.
    let mut unnamed = relocatable_with_code_relocation();
    unnamed.e_machine = EM_PPC;
    assert_eq!(facts(&unnamed).code_relocations, anchor("reloc-type-0x2a"));

    // i386: ELF32, `SHT_REL`, `r_info` the symbol shifted by eight and the type below it.
    let i386 = elf_builder::relocatable_i386_with_code_relocation();
    let read = facts(&i386);
    assert_eq!(read.machine, "i386");
    assert_eq!(
        read.code_relocations,
        anchor("R_386_GOT32X"),
        "{:?}",
        read.truncations
    );

    let aarch64 = facts(&elf_builder::relocatable_aarch64_with_code_relocation());
    assert_eq!(aarch64.code_relocations, anchor("R_AARCH64_ADR_GOT_PAGE"));

    // A relocation through a section symbol lists the section in brackets, beside the
    // named one, and the predicate's anchor prefix does not match it.
    let section = facts(&elf_builder::with_section_symbol_relocation(
        relocatable_with_code_relocation(),
    ));
    assert_eq!(
        section.code_relocations,
        Some(vec![
            "R_X86_64_PC32 [.text]".to_owned(),
            "R_X86_64_REX_GOTPCRELX chard_pic_object_anchor".to_owned(),
        ]),
        "{:?}",
        section.truncations
    );
    assert!(section.truncations.is_empty(), "{:?}", section.truncations);

    // A hidden anchor carries its visibility as a third word, read from `st_other` at
    // each width's offset; the predicate withholds on it before reading the type.
    for (object, kind) in [
        (relocatable_with_code_relocation(), "R_X86_64_PC32"),
        (
            elf_builder::relocatable_i386_with_code_relocation(),
            "R_386_PC32",
        ),
    ] {
        let hidden = facts(&elf_builder::with_anchor_visibility(
            object,
            elf_builder::STV_HIDDEN,
            elf_builder::R_X86_64_PC32,
        ));
        assert_eq!(
            hidden.code_relocations,
            Some(vec![format!("{kind} chard_pic_object_anchor STV_HIDDEN")]),
            "{:?}",
            hidden.truncations
        );
        assert!(hidden.truncations.is_empty(), "{:?}", hidden.truncations);
    }
}

/// `PT_GNU_STACK` headers in pairs: two that agree read as one does, and two that disagree
/// on `PF_X`, in either order, publish the last and record the `gnu-stack` table
/// unread, which withholds `noexecstack`.
///
/// Linux takes the last header (`elf::Elf::gnu_stack` cites the loop), so a reader taking
/// the first reads the pair RW then RWX `on` over a file whose stack Linux maps executable.
/// A pair differing only in `PF_R` or `PF_W` agrees on the one bit published, and records
/// nothing.
///
/// The disagreement is recorded against `gnu-stack`, not `program-headers`, and the gate is
/// held over every check that declares a table. Exactly the checks declaring `gnu-stack`
/// are withheld over the pair, which are `noexecstack` and `linker-default-noexecstack`;
/// every other, `pie`, `relro` and `textrel-absent` among them, is not, and those three
/// read over the pair what they read over the single `RW` header.
#[test]
fn two_pt_gnu_stack_headers_read_as_one_where_they_agree_and_withhold_where_they_do_not() {
    use elf_builder::{Covers, PF_R, PF_W, PF_X, PT_GNU_STACK, Segment};
    const RW: u32 = PF_R | PF_W;
    const RWX: u32 = PF_R | PF_W | PF_X;
    let noexecstack = corpus_check("noexecstack");
    let read = |stacks: &[u32]| {
        let mut object = elf_builder::linked_default().object();
        object.segments.retain(|s| s.p_type != PT_GNU_STACK);
        for &flags in stacks {
            object.segments.push(Segment {
                p_type: PT_GNU_STACK,
                flags,
                align: 16,
                covers: Covers::Nothing,
            });
        }
        let bytes = object.build();
        elf::Elf::parse(&bytes)
            .expect("the builder's object parses")
            .facts()
    };
    // (headers, the last header's PF_X, whether the pair disagrees)
    let cases: [(&[u32], bool, bool); 7] = [
        (&[RW], false, false),
        (&[RWX], true, false),
        (&[RW, RW], false, false),
        (&[RWX, RWX], true, false),
        (&[RW, PF_R], false, false),
        (&[RW, RWX], true, true),
        (&[RWX, RW], false, true),
    ];
    let single = read(&[RW]);
    let mut withheld = 0;
    let mut held_over = 0;
    for (stacks, executable, disagree) in cases {
        let facts = read(stacks);
        assert_eq!(facts.gnu_stack_present, Some(true), "{stacks:?}");
        assert_eq!(
            facts.gnu_stack_executable,
            Some(executable),
            "{stacks:?}: the last header is the one published"
        );
        let unread = facts.unread(&[elf::ElfTable::GnuStack]);
        let gated = chard::report::truncation_limitation(noexecstack, Some(&facts));
        if disagree {
            let entry = unread.unwrap_or_else(|| panic!("{stacks:?}: {:?}", facts.truncations));
            assert!(
                entry.detail.contains("disagree on PF_X"),
                "{stacks:?}: {}",
                entry.detail
            );
            assert_eq!(
                facts.truncations.len(),
                1,
                "{stacks:?}: the pair is one entry, and the header table is read whole: {:?}",
                facts.truncations
            );
            let gating = gated.expect("a disagreeing pair withholds noexecstack");
            assert!(gating.reason.contains("gnu-stack"), "{}", gating.reason);
            held_over += assert_the_pair_withholds_the_stack_readers_alone(stacks, &facts, &single);
            withheld += 1;
        } else {
            assert!(unread.is_none(), "{stacks:?}: {:?}", facts.truncations);
            assert!(gated.is_none(), "{stacks:?}: an agreeing pair is read");
            assert!(facts.truncations.is_empty(), "{:?}", facts.truncations);
        }
    }
    assert_eq!(withheld, 2, "both orders of the disagreeing pair were read");
    let declaring = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| !c.reads().is_empty())
        .count();
    assert_eq!(
        held_over,
        2 * declaring,
        "every declaring check was held over both orders"
    );
    eprintln!("held the gate over {declaring} declaring checks on {withheld} disagreeing pairs");
}

/// Over a disagreeing `PT_GNU_STACK` pair's `facts`, exactly the checks declaring
/// `gnu-stack` are withheld, and `pie`, `relro` and `textrel-absent`, which the
/// program-header entry withheld until `gnu-stack` took it (2026-10-05), read over the pair
/// what they read over `single`, one `RW` header. Returns how many declaring checks the
/// gate was held over, so the caller can count the frame.
fn assert_the_pair_withholds_the_stack_readers_alone(
    stacks: &[u32],
    facts: &elf::ElfFacts,
    single: &elf::ElfFacts,
) -> usize {
    // Every check declaring a table, the frame the gate is held over; a corpus that lost
    // its declarations would hold the gate to nothing.
    let declaring: Vec<&chard::probe::Check> = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| !c.reads().is_empty())
        .collect();
    let stack_readers: Vec<&str> = declaring
        .iter()
        .filter(|c| c.reads().contains(&elf::ElfTable::GnuStack))
        .map(|c| c.id)
        .collect();
    assert_eq!(
        stack_readers,
        ["noexecstack", "linker-default-noexecstack"],
        "the checks reading the stack header are the ones declaring gnu-stack"
    );
    let gated: Vec<&str> = declaring
        .iter()
        .filter(|c| chard::report::truncation_limitation(c, Some(facts)).is_some())
        .map(|c| c.id)
        .collect();
    assert_eq!(
        gated, stack_readers,
        "{stacks:?}: the pair withholds the stack readers and nothing else"
    );
    let decode = |c: &chard::probe::Check, facts: &elf::ElfFacts| {
        let macros = std::collections::BTreeMap::new();
        c.decode(&chard::probe::Evidence {
            macros: &macros,
            elf: Some(facts),
            build: None,
            run: None,
            workdir: None,
        })
        .detection
    };
    // The three the program-header entry withheld, which read no stack header.
    for bystander in ["pie", "relro", "textrel-absent"].map(corpus_check) {
        assert!(
            bystander.reads().contains(&elf::ElfTable::ProgramHeaders),
            "{}: declares program-headers, so a pair recorded there withheld it",
            bystander.id
        );
        let (over_pair, over_one) = (decode(bystander, facts), decode(bystander, single));
        assert_ne!(
            over_pair.outcome,
            chard::probe::Outcome::Indeterminate,
            "{stacks:?}: {} reads over the pair",
            bystander.id
        );
        assert_eq!(
            (over_pair.outcome, over_pair.level),
            (over_one.outcome, over_one.level),
            "{stacks:?}: {} reads over the pair what it reads over one header",
            bystander.id
        );
    }
    declaring.len()
}

/// The forged CET marking on one artifact: `cet-marked` reads the property note `present`
/// at `full`, `cet-endbr-emitted` reads the same file's code `absent`, and the control
/// triple a profile that forces the marking owes `cet-marked` withholds it as
/// `regime-confounded`, so `cfi-effective` is `indeterminate` and `fhardened-effective`'s
/// CET slot not established.
///
/// The host-independent half of the two `INERT_FORMS` rows in `tests/inert_flags.rs` for
/// `-fcf-protection=none -Wl,-z,ibt -Wl,-z,shstk`, which build live and so run only where
/// `cc` targets x86 and its linker takes `-z ibt`. Each arm here is a builder object: the
/// positive the control fixture, marked on both edges as `-fcf-protection=full` marks it;
/// the negative the control with no property, as `-fcf-protection=none` leaves it; and the
/// measured build and the regime arm both the forged fixture, since appending
/// `-fcf-protection=none` to a profile whose linker flags force the bits leaves them
/// forced (measured 2026-10-05 on Fedora 44 x86_64 under gcc 16.1.1 and clang 22.1.8, GNU
/// ld 2.46.1: the regime arm's artifact read `x86_ibt=true x86_shstk=true`). Whether the
/// regime arm is built at all is `Check::owes_regime_control`'s answer under a profile that
/// adds flags, the question `measure` asks; the plain arms alone discriminate, and without
/// the regime arm the forged marking reads `on`.
#[test]
fn a_forged_cet_marking_reads_on_beside_no_landing_pad_and_the_triple_withholds() {
    use chard::probe::Outcome;
    use chard::report::{self, ArmInput, Discrimination, Verdict, WithheldBecause};

    let forged = catalogued_facts("elf64-le-x86_64-exec-cet-forged");
    let marked = corpus_check("cet-marked");

    // The two readers over one artifact.
    let marking = decode(marked, &forged);
    assert_eq!(
        (marking.outcome, marking.level.as_deref()),
        (Outcome::Present, Some("full")),
        "{}",
        marking.observed
    );
    let pads = decode(corpus_check("cet-endbr-emitted"), &forged);
    assert_eq!(pads.outcome, Outcome::Absent, "{}", pads.observed);

    // The triple.
    let positive = decode(marked, &catalogued_facts("elf64-le-x86_64-exec-relro-lazy"));
    let mut unmarked = elf_builder::linked_default();
    unmarked.property = None;
    let negative = decode(
        marked,
        &elf::Elf::parse(&unmarked.object().build())
            .expect("parses")
            .facts(),
    );
    assert_eq!(
        (positive.outcome, negative.outcome),
        (Outcome::Present, Outcome::Absent),
        "the plain arms discriminate"
    );
    let profile = ["-O2", "-fcf-protection=none", "-Wl,-z,ibt", "-Wl,-z,shstk"];
    let arm = |detection, flags: &[&str]| ArmInput {
        detection: Some(detection),
        flags: flags.iter().map(|f| (*f).to_owned()).collect(),
    };
    let triple = |regime: bool| {
        let regime_flags: Vec<&str> = profile
            .iter()
            .chain(
                marked
                    .regime_arm()
                    .expect("cet-marked declares a regime arm"),
            )
            .copied()
            .collect();
        report::decide(
            &marking,
            arm(&positive, marked.positive),
            arm(&negative, marked.negative),
            regime.then(|| arm(&marking, &regime_flags)),
            marked.levels.grade(),
        )
    };
    assert!(
        marked.owes_regime_control(false),
        "cet-marked owes no regime arm under a profile that adds flags, so a marking the \
         profile's linker flags forced is credited to the flag"
    );
    let (verdict, controls) = triple(marked.owes_regime_control(false));
    assert_eq!(
        (verdict, controls.discrimination),
        (
            Verdict::ProbeInvalid,
            Discrimination::Withheld(WithheldBecause::RegimeConfounded)
        )
    );
    // The arm is what withholds: the plain arms alone credit the forged marking.
    assert_eq!(triple(false).0, Verdict::On);

    composites_over_the_withheld_marking(marked, verdict, controls);
}

fn corpus_check(id: &str) -> &'static chard::probe::Check {
    chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} is in the corpus"))
}

fn catalogued_facts(name: &str) -> elf::ElfFacts {
    let f = catalogue()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{name} is in the catalogue"));
    elf::Elf::parse(&f.bytes).expect("parses").facts()
}

/// One elf-static check's decoder over `facts`, with no macros, build or run.
fn decode(check: &chard::probe::Check, facts: &elf::ElfFacts) -> chard::probe::Detection {
    let macros = std::collections::BTreeMap::new();
    check
        .decode(&chard::probe::Evidence {
            macros: &macros,
            elf: Some(facts),
            build: None,
            run: None,
            workdir: None,
        })
        .detection
}

/// `cfi-effective` and `fhardened-effective`'s CET slot over `cet-marked` published at
/// `verdict` on x86_64 under glibc: `indeterminate`, and not established.
fn composites_over_the_withheld_marking(
    marked: &chard::probe::Check,
    verdict: chard::report::Verdict,
    controls: chard::report::Controls,
) {
    use chard::composite::ConstituentState;
    use chard::report::{self, Verdict};

    let observation = report::Observation {
        probe: "link-defaults".to_owned(),
        check: marked.id.to_owned(),
        flag: marked.flag.to_owned(),
        channel: marked.channel(),
        polarity: marked.polarity,
        verdict,
        level: None,
        recommended_level: None,
        confidence: "high".to_owned(),
        observable: String::new(),
        boundary: None,
        defects: Vec::new(),
        observes: chard::probe::Observes::Protection,
        references: Vec::new(),
        evidence: report::EvidenceOut::default(),
        build: None,
        run: None,
        controls: Some(controls),
        gating: None,
        build_rejection: None,
        structured_diagnostics: None,
        notes: String::new(),
    };
    let obs = [observation];
    let libc = chard::env::Libc {
        impl_name: "glibc".to_owned(),
        version: None,
        detection: "fixture".to_owned(),
    };
    let store = report::FactStore::default();
    let cfi = chard::composite::cfi(&obs, "x86_64", &libc, &store);
    assert_eq!(cfi.verdict, Verdict::Indeterminate, "{}", cfi.reason);
    let umbrella =
        chard::composite::fhardened(&obs, "x86_64", &refused_fhardened(), &libc, None, &store);
    let slot = umbrella
        .constituents
        .iter()
        .find(|k| k.check == "cet-marked")
        .expect("the umbrella carries its CET slot");
    assert_eq!(
        slot.state,
        ConstituentState::NotEstablished,
        "{:?}",
        slot.note
    );
}

/// A driver that refuses `-fhardened`, as clang does, so the umbrella's fortify bar is read
/// from the library alone.
fn refused_fhardened() -> chard::toolchain::FhardenedFortify {
    chard::toolchain::FhardenedFortify {
        flags: Vec::new(),
        exit_status: 1,
        stdout_unterminated: false,
        macros_defined: 0,
        diagnostic: None,
        fortify_source: None,
        baseline: chard::toolchain::FortifyBaseline {
            flags: Vec::new(),
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 0,
            fortify_source: None,
        },
    }
}
