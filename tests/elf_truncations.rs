// SPDX-License-Identifier: BSD-3-Clause

//! A truncation moves an elf-static detector only where the check declared the table.
//!
//! `Check::reads` is a declaration, and a declaration nothing holds to the decoder is
//! prose: a decoder reading a table its check does not declare is a decoder a cut
//! table can still move silently, which is the false `absent` `ElfFacts::truncations`
//! exists to name. So every elf-static check is read through `Check::decode` over a whole
//! object and over the same object cut on one table at a time, every declared table that
//! has a recording site, and any reading that moved is held to having declared that table.
//! The decoders are predicates, whose `tables` are the declaration and whose `@truncated`
//! preamble withholds on it, so a declared cut moves a reading through the preamble and
//! an undeclared one can move it only through a clause; "detector" below is the reading
//! a check's decoder gives. The converse is held too: every
//! `unread` entry on a declared table gates the check through
//! `report::truncation_limitation`, and an entry on an undeclared table gates nothing.
//! Each pair is counted per cut, and a cut over which nothing was examined fails, since a
//! loop over nothing is the failure this project has produced before.
//!
//! The objects are the builder's, byte-patched where it has no knob: `e_shstrndx` aimed
//! at a `PROGBITS` section and `.shstrtab` moved past the end of the file for the two
//! section-name cuts; the `PT_DYNAMIC` program header, the `SHT_NOTE` section header and
//! the `PT_NOTE` program header moved to the last eight bytes of the file for the
//! `.dynamic` and note cuts; `PT_DYNAMIC`'s `p_filesz` shortened past `DT_NULL`; the two
//! symbol string tables moved past the end; both symbol tables' `sh_size` set below one
//! entry, and to one entry and a byte; the first `PT_LOAD` moved past the end, which
//! takes the dynamic string table with it; `DT_STRSZ` patched to 1, so every string
//! offset lies past the table; and, beside the cut section names that leave `.dynstr`
//! unfindable, `DT_STRTAB` aimed at an address no `PT_LOAD` maps and `DT_STRTAB` retagged
//! away. `strip_section_headers` and a symbol table whose `sh_link` names `.text` are the
//! builder's own. `section-names` is declared by elf-static checks that read the section
//! list (`ret-protector-emitted`, `except-table-emitted`, `separate-code`) as well as by the
//! runtime fortify checks (for the self-report they read), so the section-name cuts are
//! required to move a detector, and companions are credited through `examine`'s
//! declared-table rule.
//!
//! Some cuts are made from a relocatable object rather than the linked base, since a link
//! keeps no relocations per function and the linked base carries no relocation the
//! compiler wrote; `relocation_cuts` pairs each with the object it is read against. The
//! `relocations` cut is five bytes after the one `.rela.text` record of the builder's
//! relocatable object, a record naming an undefined callee. Two more move `.rela.text`
//! past the end of the file and aim its `sh_link` at `.text`; each leaves `relocations`
//! unread, and `ssp-level-emitted`, which declares it, moves from `strong` to withheld. A
//! third, from the ELF32 i386 object whose `.rel.text` holds `Elf32_Rel` entries, sizes
//! that section half an entry short, the one cut over `SHT_REL` arithmetic. Two tests
//! retype `.rela.text`, to `SHT_CREL` and to a type in the user range carrying
//! `SHF_INFO_LINK`; a reader recording neither reads four functions with no references,
//! which `ssp-level-emitted` would publish `off`
//! (`relocations_in_an_undecoded_encoding_withhold_ssp_level_emitted`). Two more retype
//! `.rela.text.part`, whose target is code with no function symbol, the same two ways
//! (`undecoded_relocations_into_code_outside_every_function_withhold_ssp_level_emitted`).
//!
//! The base object also defines the code reader's function (`elf::code`), `ud2; ret` in a
//! section of its own sized after the build, and one cut moves that section past the end
//! of the file, which leaves the `code` table unread and moves `ubsan-trap-mode`, the check
//! declaring it that reads the base object's function. It defines the three functions
//! `elf::entry` reads as well, at `endbr64; ret` in a section of their own sized after the
//! build, and one cut moves that section past the end of the file, which leaves the
//! `function-entries` table unread and moves `cet-endbr-emitted`, the check declaring it.
//! The reader's other address paths (`ET_REL`, ELF32) and each of its refusals are held
//! over their own objects at the end of the file, in every width and object type.
//!
//! One row is a contradiction rather than a cut: the base object with a second
//! `PT_GNU_STACK` carrying `PF_X`, where the first does not. It leaves `gnu-stack` unread
//! (`elf::Elf::gnu_stack`); `noexecstack`, reading the last header ungated, would move from
//! `on` to `off`, the reading the gate exists to withhold. `examine` holds every check
//! declaring a table to being gated exactly when it declares `gnu-stack`, so `pie`, `relro`
//! and `textrel-absent` read over it. A program-header table `Elf::parse` refuses, or an
//! `unread` entry naming it, withholds every check declaring it, the two stack readers
//! included (`a_program_header_table_not_read_withholds_every_check_declaring_it`).
//!
//! Two more objects are read beside the cuts: a note section cut beside a whole `PT_NOTE`,
//! which is a dropped view and gates nothing, and both symbol tables retyped away, which
//! is an object with no symbol table and the precondition's business.
//!
//! The reader's half of the same promise is held over generated objects at the end of
//! the file: every fact a cut changes is covered by a recorded truncation
//! (`every_fact_a_cut_changes_is_covered_by_a_recorded_truncation`).

use std::collections::{BTreeMap, BTreeSet};

mod elf_builder;
mod seeded;

use chard::elf::{self, ElfFacts, ElfTable};
use chard::probe::{CORPUS, Channel, Check, Evidence, Outcome};
use chard::report;
use elf_builder::{
    BindNow, Content, Covers, DF_1_NOW, DT_FLAGS_1, DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_STRSZ,
    DT_STRTAB, DT_SYMTAB, DynValue, ET_DYN, Linked, Object, PF_R, PF_W, PF_X, PT_DYNAMIC,
    PT_GNU_STACK, PT_LOAD, PT_NOTE, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_DYNAMIC, SHT_DYNSYM,
    SHT_PROGBITS, SHT_RELA, Section, Segment, Symbol, generate::Spec, linked_default,
    relocatable_with_code_relocation,
};

/// The ELF64 record sizes the patches step by.
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const SHDR_SIZE: usize = 64;
const SYM_SIZE: u64 = 24;

/// A builder of one object, as a cut and a case name it.
type Build = fn() -> Vec<u8>;

/// One way to cut the base object, the table it leaves unread, and the tables the same
/// cut leaves unread beside it.
///
/// `also` names what the file loses with the table under test: a strip takes the section
/// names and `.comment` with the symbol tables, since a section nothing can look up is a
/// section not read, and
/// a cut name table takes it the same way. A companion may be declared by an elf-static
/// check (`ret-protector-emitted` declares `section-names`, a strip's companion), and a move
/// through a cut is credited to any declared table among `table` and `also`, as `examine`
/// says.
struct Cut {
    name: &'static str,
    table: ElfTable,
    also: &'static [ElfTable],
    build: Build,
}

/// The default linked object with `DF_1_NOW`, a `DT_NEEDED` for libm and a `DT_RPATH`.
///
/// Each is there so a cut moves a detector: `relro` reads `full` whole and `partial`
/// once `.dynamic` is cut, `as-needed` reads the libm entry whole and nothing once the
/// string table is cut, and `rpath-absent` reads the path whole and none once it is. A
/// cut that moved no detector would hold that table's declarations to nothing. The
/// RETGUARD cookie section, appended after the sections the linked builder lays out, is
/// there for the same reason: `ret-protector-emitted` reads it whole and nothing once the
/// section names or the section-header table are cut. So is the code
/// reader's function: `.text.chard` holds `ud2; ret` and `.symtab` defines
/// `chard_ubsan_trap_probe` there, which `whole` sizes, so `ubsan-trap-mode` reads `ud2`
/// whole and is withheld once the function's bytes or the symbol table are cut. So are the three
/// functions `elf::entry` reads: `.text.chard_ibt` holds
/// `endbr64; ret` and `.symtab` defines each of them there, which `whole` sizes, so
/// `cet-endbr-emitted` reads the landing pads whole and is withheld once their bytes or the
/// symbol table are cut.
fn base() -> Object {
    base_with(|_| {})
}

/// [`base`], with `tweak` applied to the linked object before it is laid out.
fn base_with(tweak: impl FnOnce(&mut Linked)) -> Object {
    let mut linked = linked_default();
    linked.bind_now = BindNow::Flag1;
    linked.extra_dynstr = vec!["libm.so.6", "/opt/chard/lib"];
    linked.extra_dynamic = vec![
        (DT_NEEDED, DynValue::StrOff(".dynstr", "libm.so.6")),
        (DT_RPATH, DynValue::StrOff(".dynstr", "/opt/chard/lib")),
    ];
    tweak(&mut linked);
    let mut object = linked.object();
    object.sections.push(Section {
        name: ".openbsd.randomdata.retguard.1",
        sh_type: SHT_PROGBITS,
        flags: 0,
        addralign: 8,
        entsize: 0,
        link: None,
        info: 0,
        content: Content::Bytes(vec![0; 8]),
    });
    object.sections.push(Section {
        name: PROBE_CODE_SECTION,
        sh_type: SHT_PROGBITS,
        flags: SHF_ALLOC | SHF_EXECINSTR,
        addralign: 16,
        entsize: 0,
        link: None,
        info: 0,
        content: Content::Bytes(vec![0x0f, 0x0b, 0xc3]),
    });
    let name = chard::predicate::elf_static::UBSAN_TRAP_FUNCTION;
    for section in &mut object.sections {
        match (section.name, &mut section.content) {
            (".symtab", Content::Symbols(syms)) => syms.push(Symbol {
                name,
                defined_in: Some(PROBE_CODE_SECTION),
                st_other: 0,
            }),
            (".strtab", Content::Strings(strings)) => strings.push(name),
            _ => {}
        }
    }
    object.sections.push(Section {
        name: ENTRY_SECTION,
        sh_type: SHT_PROGBITS,
        flags: SHF_ALLOC | SHF_EXECINSTR,
        addralign: 16,
        entsize: 0,
        link: None,
        info: 0,
        content: Content::Bytes(ENTRY_CODE.to_vec()),
    });
    for section in &mut object.sections {
        for name in elf::entry::ENTRY_FUNCTIONS {
            match (section.name, &mut section.content) {
                (".symtab", Content::Symbols(syms)) => syms.push(Symbol {
                    name,
                    defined_in: Some(ENTRY_SECTION),
                    st_other: 0,
                }),
                (".strtab", Content::Strings(strings)) => strings.push(name),
                _ => {}
            }
        }
    }
    object
}

/// The section `base` puts the code reader's function in.
const PROBE_CODE_SECTION: &str = ".text.chard";

/// The section `base` puts `elf::entry`'s functions in, and what it holds: `endbr64; ret`.
const ENTRY_SECTION: &str = ".text.chard_ibt";
const ENTRY_CODE: [u8; 5] = [0xf3, 0x0f, 0x1e, 0xfa, 0xc3];

/// The base object, with the code reader's function sized by `size_probe_function` and
/// `elf::entry`'s functions by `size_entry_functions`.
fn whole() -> Vec<u8> {
    let mut d = base().build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
    d
}

/// Give the code reader's function in a build of `base` (or of `base` with sections
/// appended) the size of its section: the builder writes every `st_size` as 0, and the
/// reader refuses a function of no extent.
fn size_probe_function(d: &mut [u8]) {
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let symtab = shoff + section_index(".symtab") * SHDR_SIZE;
    let offset = usize::try_from(le_u64(&d[symtab + 24..symtab + 32])).expect("fits");
    let size = usize::try_from(le_u64(&d[symtab + 32..symtab + 40])).expect("fits");
    let code = u16::try_from(section_index(PROBE_CODE_SECTION)).expect("a small index");
    let mut sized = 0;
    for entry in (offset..offset + size).step_by(24) {
        if u16::from_le_bytes([d[entry + 6], d[entry + 7]]) == code {
            d[entry + 16..entry + 24].copy_from_slice(&3u64.to_le_bytes());
            sized += 1;
        }
    }
    assert_eq!(
        sized, 1,
        "the base object defines the code reader's function once"
    );
}

/// The code reader's function's section moved wholly past the end of the file: the
/// symbol is read whole and its bytes are not.
fn probe_code_cut() -> Vec<u8> {
    let mut d = whole();
    let moved =
        (u64::try_from(d.len()).expect("a fixture length fits in u64") + 0x100).to_le_bytes();
    let field = sh_offset_field(&d, PROBE_CODE_SECTION);
    d[field].copy_from_slice(&moved);
    d
}

/// Give the functions `elf::entry` reads, in a build of `base` (or of `base` with sections
/// appended), the size of their section: the builder writes every `st_size` as 0, and the
/// reader refuses a function of no extent.
fn size_entry_functions(d: &mut [u8]) {
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let symtab = shoff + section_index(".symtab") * SHDR_SIZE;
    let offset = usize::try_from(le_u64(&d[symtab + 24..symtab + 32])).expect("fits");
    let size = usize::try_from(le_u64(&d[symtab + 32..symtab + 40])).expect("fits");
    let code = u16::try_from(section_index(ENTRY_SECTION)).expect("a small index");
    let len = u64::try_from(ENTRY_CODE.len()).expect("fits");
    let mut sized = 0;
    for entry in (offset..offset + size).step_by(24) {
        if u16::from_le_bytes([d[entry + 6], d[entry + 7]]) == code {
            d[entry + 16..entry + 24].copy_from_slice(&len.to_le_bytes());
            sized += 1;
        }
    }
    assert_eq!(
        sized,
        elf::entry::ENTRY_FUNCTIONS.len(),
        "the base object defines each of elf::entry's functions once"
    );
}

/// The section holding `elf::entry`'s functions moved wholly past the end of the file: the
/// symbols are read whole and the bytes are not.
fn entry_code_cut() -> Vec<u8> {
    let mut d = whole();
    let moved =
        (u64::try_from(d.len()).expect("a fixture length fits in u64") + 0x100).to_le_bytes();
    let field = sh_offset_field(&d, ENTRY_SECTION);
    d[field].copy_from_slice(&moved);
    d
}

/// The base object with a second `PT_GNU_STACK` after its non-executable one, carrying
/// `PF_X`: Linux acts on the second and a first-header reader on the first, so the
/// program-header table is recorded unread.
fn gnu_stack_disagreement() -> Vec<u8> {
    let mut object = base();
    object.segments.push(Segment {
        p_type: PT_GNU_STACK,
        flags: PF_R | PF_W | PF_X,
        align: 16,
        covers: Covers::Nothing,
    });
    let mut d = object.build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
    d
}

/// The base object with a second `DT_FLAGS_1` ahead of the one the builder writes last:
/// `DF_1_NOW` first and `DF_1_PIE` after. `ld.so` keeps the last entry of a repeated tag (see
/// `elf::Elf::dynamic`), so the object binds lazily; the reader that kept the first said
/// `bind_now`.
fn repeated_flags1() -> Vec<u8> {
    let object = base_with(|linked| {
        linked.bind_now = BindNow::Absent;
        linked
            .extra_dynamic
            .push((DT_FLAGS_1, DynValue::Const(DF_1_NOW)));
        linked.e_type = ET_DYN;
    });
    let mut d = object.build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
    d
}

/// The base object with a second `PT_DYNAMIC` over the same `.dynamic`: the loader reads
/// the last, and a reader that concatenated both saw every entry twice.
fn second_dynamic_segment() -> Vec<u8> {
    let mut object = base();
    object.segments.push(Segment {
        p_type: PT_DYNAMIC,
        flags: PF_R | PF_W,
        align: 8,
        covers: Covers::Section(".dynamic"),
    });
    let mut d = object.build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
    d
}

fn stripped() -> Vec<u8> {
    let mut object = base();
    object.strip_section_headers = true;
    object.build()
}

/// The stripped object with `e_shoff` naming a `shdr[0]` past the end of the file while
/// `e_shnum` is 0: the count escape cannot be followed, and the file is read as having no
/// section-header table, with the cause recorded against `section-headers`.
fn section_header_escape_cut() -> Vec<u8> {
    let mut d = stripped();
    let stale = u64::try_from(d.len()).expect("a fixture length fits in u64") + 0x10000;
    d[40..48].copy_from_slice(&stale.to_le_bytes());
    d
}

/// The builder's relocatable object with a call to an undefined `chard_no_plt_callee`
/// relocated through its GOT slot (`R_X86_64_GOTPCRELX`) in `.rela.text`, which
/// `plt-bypassed` reads `present`. `trailing` bytes follow the one record.
fn relocatable_with_relocations(trailing: usize) -> Vec<u8> {
    let mut object = elf_builder::relocatable();
    for section in &mut object.sections {
        match (section.name, &mut section.content) {
            (".symtab", Content::Symbols(symbols)) => symbols.push(elf_builder::Symbol {
                name: "chard_no_plt_callee",
                defined_in: None,
                st_other: 0,
            }),
            (".strtab", Content::Strings(strings)) => strings.push("chard_no_plt_callee"),
            _ => {}
        }
    }
    // One `Elf64_Rela`: offset 1, symbol 3 (after the null symbol, the defined function
    // and the canary reference), type 41 (0x29), addend -4.
    let mut record = Vec::new();
    record.extend_from_slice(&1u64.to_le_bytes());
    record.extend_from_slice(&((3u64 << 32) | 0x29).to_le_bytes());
    record.extend_from_slice(&(-4i64).to_le_bytes());
    record.extend(std::iter::repeat_n(0u8, trailing));
    object.sections.push(Section {
        name: ".rela.text",
        sh_type: 4,
        flags: 0x40,
        addralign: 8,
        entsize: 24,
        link: Some(".symtab"),
        info: 1,
        content: Content::Bytes(record),
    });
    object.build()
}

fn relocatable_with_call() -> Vec<u8> {
    relocatable_with_relocations(0)
}

/// The same object with five bytes after the one whole record, which the reader records
/// as a partial record it did not read.
fn relocation_section_cut() -> Vec<u8> {
    relocatable_with_relocations(5)
}

/// Both symbol tables' `sh_link` aimed at `.text`, which is no string table. Patched
/// after the build, because the builder resolves symbol names through the linked table
/// and refuses a link that is not one.
fn symbols_linked_to_text() -> Vec<u8> {
    let mut d = whole();
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let text = u32::try_from(section_index(".text")).expect("a small index");
    for table in [".symtab", ".dynsym"] {
        let shdr = shoff + section_index(table) * SHDR_SIZE;
        d[shdr + 40..shdr + 44].copy_from_slice(&text.to_le_bytes());
    }
    d
}

/// The index a section has in the header table: its position plus the null header.
fn section_index(name: &str) -> usize {
    base()
        .sections
        .iter()
        .position(|s| s.name == name)
        .unwrap_or_else(|| panic!("the base object has no {name}"))
        + 1
}

fn segment_index(p_type: u32) -> usize {
    base()
        .segments
        .iter()
        .position(|s| s.p_type == p_type)
        .unwrap_or_else(|| panic!("the base object has no segment of type {p_type}"))
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
}

/// An offset that leaves eight readable bytes and then the end of the file.
fn past_end(d: &[u8]) -> [u8; 8] {
    u64::try_from(d.len() - 8)
        .expect("a fixture length fits in u64")
        .to_le_bytes()
}

fn section_names_cut() -> Vec<u8> {
    let mut d = whole();
    let text = u16::try_from(section_index(".text")).expect("a small index");
    d[62..64].copy_from_slice(&text.to_le_bytes());
    d
}

/// The file offset field of the header at `index`, as a byte range into the object.
fn sh_offset_field_at(d: &[u8], index: usize) -> std::ops::Range<usize> {
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let shdr = shoff + index * SHDR_SIZE;
    shdr + 24..shdr + 32
}

/// The file offset field of `section`'s header, as a byte range into the object.
fn sh_offset_field(d: &[u8], section: &str) -> std::ops::Range<usize> {
    sh_offset_field_at(d, section_index(section))
}

/// The relocatable object `ssp-level-emitted` reads: four functions and the references
/// inside them, which reads `strong` whole.
fn relocatable_whole() -> Vec<u8> {
    elf_builder::relocatable_functions().build()
}

/// The relocatable object whose `.rela.text` names `chard_pic_object_anchor`, so
/// `pic-object-relocs` reads it `present` whole and withholds once the table is cut.
fn pic_relocatable_whole() -> Vec<u8> {
    relocatable_with_code_relocation().build()
}

/// [`pic_relocatable_whole`] with `.rela.text`'s `sh_size` one byte past its one entry: the
/// entry is read, and the partial one after it is recorded as an unread relocation table.
fn pic_relocations_with_a_partial_entry() -> Vec<u8> {
    let object = relocatable_with_code_relocation();
    let index = object
        .sections
        .iter()
        .position(|s| s.name == ".rela.text")
        .expect("the object has a .rela.text")
        + 1;
    let mut d = object.build();
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let shdr = shoff + index * SHDR_SIZE;
    d[shdr + 32..shdr + 40].copy_from_slice(&25u64.to_le_bytes());
    d
}

/// `.rela.text`'s index in the relocatable object's header table.
fn rela_index() -> usize {
    elf_builder::relocatable_functions()
        .sections
        .iter()
        .position(|s| s.name == ".rela.text")
        .expect("the relocatable object has .rela.text")
        + 1
}

/// The ELF32 i386 relocatable object with the same four functions and a `.rel.text`, which
/// reads `strong` whole.
fn relocatable_rel32_whole() -> Vec<u8> {
    elf_builder::relocatable_functions_rel32().build()
}

/// `.rel.text`'s `sh_size` four bytes short of its seven eight-byte `Elf32_Rel` entries:
/// the last entry is partial, so the section is not whole entries and none of it is read.
/// The ELF32 header puts `e_shoff` at 32, and a 40-byte section header its `sh_size` at 20.
fn rel32_partial_entry() -> Vec<u8> {
    let object = elf_builder::relocatable_functions_rel32();
    let index = object
        .sections
        .iter()
        .position(|s| s.name == ".rel.text")
        .expect("the ELF32 object has .rel.text")
        + 1;
    let mut d = object.build();
    let shoff = usize::try_from(u32::from_le_bytes(
        d[32..36].try_into().expect("four bytes"),
    ))
    .expect("a fixture offset fits in usize");
    let size = shoff + index * 40 + 20;
    let whole = u32::from_le_bytes(d[size..size + 4].try_into().expect("four bytes"));
    assert_eq!(whole, 7 * 8, "seven Elf32_Rel entries");
    d[size..size + 4].copy_from_slice(&(whole - 4).to_le_bytes());
    d
}

/// `.rela.text` moved past the end of the file: the references are in no bytes the file
/// holds, so no function can be read as having or lacking them.
fn relocations_cut() -> Vec<u8> {
    let mut d = relocatable_whole();
    let moved = past_end(&d);
    let field = sh_offset_field_at(&d, rela_index());
    d[field].copy_from_slice(&moved);
    d
}

/// `.rela.text`'s `sh_link` aimed at `.text`: the references name symbols through a table
/// that is not a symbol table, so none can be named.
fn relocations_unlinked() -> Vec<u8> {
    let mut d = relocatable_whole();
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let link = shoff + rela_index() * SHDR_SIZE + 40;
    d[link..link + 4].copy_from_slice(&1u32.to_le_bytes());
    d
}

/// `.rela.text` retyped to `sh_type`, and its flags to `flags`, the entries left as they
/// are: a relocation section in an encoding the reader does not decode.
fn relocations_retyped(sh_type: u32, flags: u64) -> Vec<u8> {
    let mut d = relocatable_whole();
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let shdr = shoff + rela_index() * SHDR_SIZE;
    d[shdr + 4..shdr + 8].copy_from_slice(&sh_type.to_le_bytes());
    d[shdr + 8..shdr + 16].copy_from_slice(&flags.to_le_bytes());
    d
}

/// `SHT_CREL`, the type clang gives `.crel.text` under `-Wa,--crel`.
const SHT_CREL: u32 = 0x4000_0014;
/// `SHF_INFO_LINK`: `sh_info` is a section index.
const SHF_INFO_LINK: u64 = 0x40;
/// A type in the user range, which no reader decodes.
const SHT_LOUSER: u32 = 0x8000_0000;

/// `.rela.text` as `SHT_CREL`, the shape of clang's `-Wa,--crel` object.
fn relocations_crel() -> Vec<u8> {
    relocations_retyped(SHT_CREL, SHF_INFO_LINK)
}

/// `.rela.text` as a type no reader knows, `SHF_INFO_LINK` naming `.text`: the next
/// encoding a toolchain adopts.
fn relocations_unknown_info_link() -> Vec<u8> {
    relocations_retyped(SHT_LOUSER, SHF_INFO_LINK)
}

/// `.shstrtab` itself moved past the end of the file: the header names a table the file
/// does not hold, and every name is unread. The builder appends the table last and names
/// it in `e_shstrndx`, which is where its index is read from.
fn section_name_table_cut() -> Vec<u8> {
    let mut d = whole();
    let moved = past_end(&d);
    let shstrndx = usize::from(u16::from_le_bytes([d[62], d[63]]));
    let field = sh_offset_field_at(&d, shstrndx);
    d[field].copy_from_slice(&moved);
    d
}

/// Both symbol string tables moved past the end of the file. The dynamic string table is
/// reached through `DT_STRTAB` and the segment, so `.dynstr`'s header moving leaves the
/// library lists whole and the symbol names alone unread.
fn symbol_strings_cut() -> Vec<u8> {
    let mut d = whole();
    let moved = past_end(&d);
    for table in [".dynstr", ".strtab"] {
        let field = sh_offset_field(&d, table);
        d[field].copy_from_slice(&moved);
    }
    d
}

/// Both symbol tables' `sh_size` set to `size`, the rest of each header left alone.
fn symbol_tables_sized(size: u64) -> Vec<u8> {
    let mut d = whole();
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    for table in [".symtab", ".dynsym"] {
        let shdr = shoff + section_index(table) * SHDR_SIZE;
        d[shdr + 32..shdr + 40].copy_from_slice(&size.to_le_bytes());
    }
    d
}

/// Both symbol tables sized below one 24-byte entry: a table that holds not even the
/// null symbol, which is malformed rather than empty.
fn symbol_tables_below_one_entry() -> Vec<u8> {
    symbol_tables_sized(SYM_SIZE - 1)
}

/// Both symbol tables sized at the null symbol and one byte of the next entry: the whole
/// entry is read and the partial one, where the base object's symbols begin, is not.
fn symbol_tables_with_a_partial_entry() -> Vec<u8> {
    symbol_tables_sized(SYM_SIZE + 1)
}

/// The first `PT_LOAD` moved past the end of the file, so `DT_STRTAB` translates to an
/// offset the file does not hold.
fn load_segment_cut() -> Vec<u8> {
    let mut d = whole();
    let phdr = EHDR_SIZE + segment_index(PT_LOAD) * PHDR_SIZE;
    let moved = past_end(&d);
    d[phdr + 8..phdr + 16].copy_from_slice(&moved);
    d
}

/// The first `.dynamic` entry tagged `tag`, with its tag and value fields overwritten by
/// `patch`; the base object carries the tag exactly once, and the patch is asserted to
/// have landed.
fn patch_dynamic_entry(d: &mut [u8], tag: i64, patch: impl Fn(&mut [u8])) {
    let field = sh_offset_field(d, ".dynamic");
    let dynamic = usize::try_from(le_u64(&d[field])).expect("a fixture offset fits in usize");
    let wanted = u64::try_from(tag).expect("a small tag");
    let mut patched = 0;
    for entry in (dynamic..d.len() - 16).step_by(16) {
        if le_u64(&d[entry..entry + 8]) == wanted {
            patch(&mut d[entry..entry + 16]);
            patched += 1;
            break;
        }
    }
    assert_eq!(patched, 1, "the base object carries dynamic tag {tag:#x}");
}

/// `DT_STRSZ` patched to 1: the table is held, and every string offset lies past it.
fn strsz_cut() -> Vec<u8> {
    let mut d = whole();
    patch_dynamic_entry(&mut d, DT_STRSZ, |entry| {
        entry[8..16].copy_from_slice(&1u64.to_le_bytes());
    });
    d
}

/// `DT_STRTAB` aimed at vaddr 0x10, below the base every `PT_LOAD` starts at, in the
/// object whose section names are cut: the segment maps nothing there and `.dynstr`
/// cannot be found by name, so the table is located nowhere.
fn strtab_unmapped_cut() -> Vec<u8> {
    let mut d = section_names_cut();
    patch_dynamic_entry(&mut d, DT_STRTAB, |entry| {
        entry[8..16].copy_from_slice(&0x10u64.to_le_bytes());
    });
    d
}

/// `DT_STRTAB` retagged as `DT_DEBUG`, a tag the reader reads nothing through, in the
/// object whose section names are cut: `.dynamic` names three strings and no table to
/// read them from, and `.dynstr` cannot be found by name.
fn strtab_absent_cut() -> Vec<u8> {
    const DT_DEBUG: u64 = 21;
    let mut d = section_names_cut();
    patch_dynamic_entry(&mut d, DT_STRTAB, |entry| {
        entry[..8].copy_from_slice(&DT_DEBUG.to_le_bytes());
    });
    d
}

/// `PT_DYNAMIC`'s `p_filesz` shortened by two entries, which drops `DT_NULL` and the
/// `DT_FLAGS_1` before it: the segment view ends without the loader's terminator.
fn dynamic_shortened() -> Vec<u8> {
    let mut d = whole();
    let phdr = EHDR_SIZE + segment_index(PT_DYNAMIC) * PHDR_SIZE;
    let filesz = le_u64(&d[phdr + 32..phdr + 40]);
    d[phdr + 32..phdr + 40].copy_from_slice(&(filesz - 32).to_le_bytes());
    d
}

fn dynamic_cut() -> Vec<u8> {
    let mut d = whole();
    let phdr = EHDR_SIZE + segment_index(PT_DYNAMIC) * PHDR_SIZE;
    let moved = past_end(&d);
    d[phdr + 8..phdr + 16].copy_from_slice(&moved);
    d
}

/// The note section alone moved past the end of the file: `notes()` falls back to
/// `PT_NOTE` when every `SHT_NOTE` section yields nothing, so the segment rescues it.
fn note_section_cut() -> Vec<u8> {
    let mut d = whole();
    let field = sh_offset_field(&d, ".note.gnu.property");
    let moved = past_end(&d);
    d[field].copy_from_slice(&moved);
    d
}

/// Both views of the note cut, so nothing rescues the section.
fn notes_cut() -> Vec<u8> {
    let mut d = note_section_cut();
    let phdr = EHDR_SIZE + segment_index(PT_NOTE) * PHDR_SIZE;
    let moved = past_end(&d);
    d[phdr + 8..phdr + 16].copy_from_slice(&moved);
    d
}

/// Both symbol tables retyped to `SHT_PROGBITS` and `DT_SYMTAB` retagged as `DT_DEBUG`: the
/// bytes are there and neither a header nor the dynamic table says they are a symbol
/// table, which is what `-static -s` leaves behind with the bytes gone too. With `DT_SYMTAB`
/// left in place, the loader's table it names is recorded unread
/// (`a_dynsym_header_retyped_away_beside_dt_symtab_is_recorded_unread`).
fn no_symbol_tables() -> Vec<u8> {
    const DT_DEBUG: u64 = 21;
    let mut d = retyped_away(whole(), &[".symtab", ".dynsym"]);
    patch_dynamic_entry(&mut d, DT_SYMTAB, |entry| {
        entry[..8].copy_from_slice(&DT_DEBUG.to_le_bytes());
    });
    d
}

/// `d` with the named sections' headers retyped to `SHT_PROGBITS`.
fn retyped_away(mut d: Vec<u8>, tables: &[&str]) -> Vec<u8> {
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    for table in tables {
        let shdr = shoff + section_index(table) * SHDR_SIZE;
        d[shdr + 4..shdr + 8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
    }
    d
}

/// `d` with the named sections' `sh_entsize` set to `entsize`.
fn with_entsize(mut d: Vec<u8>, tables: &[&str], entsize: u64) -> Vec<u8> {
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    for table in tables {
        let shdr = shoff + section_index(table) * SHDR_SIZE;
        d[shdr + 56..shdr + 64].copy_from_slice(&entsize.to_le_bytes());
    }
    d
}

/// The base object with `.symtab` retyped away, so `.dynsym` is the one symbol table and
/// the canary reference is read there alone, and `.dynsym`'s `sh_entsize` set to `entsize`.
fn dynsym_alone_with_entsize(entsize: u64) -> Vec<u8> {
    with_entsize(retyped_away(whole(), &[".symtab"]), &[".dynsym"], entsize)
}

fn facts(bytes: &[u8]) -> ElfFacts {
    elf::Elf::parse(bytes)
        .expect("the builder's bytes parse")
        .facts()
}

/// What an elf-static detector is handed: the facts, and no macros, build or run.
fn evidence<'a>(macros: &'a BTreeMap<String, String>, elf: &'a ElfFacts) -> Evidence<'a> {
    Evidence {
        macros,
        elf: Some(elf),
        build: None,
        run: None,
        workdir: None,
    }
}

/// One detector over the whole object and the cut one: a move is held to the check's
/// declaration, and the gate is held to the declaration whether or not anything moved.
/// Returns whether the detector moved.
///
/// The cut's table and its companions are all unread, so a check declaring any of them is
/// withheld through it, not through the cut's own table alone: `ret-protector-emitted` reads
/// the section list, which a section-header strip empties beside the symbol tables.
///
/// What that gives up: a move through a cut with companions is credited to any declared
/// table among them, not to the one whose loss moved it. A check that declares only
/// `section-names` but moved because the strip took its symbols away passes the strip cut,
/// and is caught only by the cuts that leave the symbol tables unreadable alone, where
/// `section-names` is no companion and the move must be declared as `symbols`.
fn examine(check: &Check, cut: &Cut, whole_facts: &ElfFacts, cut_facts: &ElfFacts) -> bool {
    let macros = BTreeMap::new();
    let before = check.decode(&evidence(&macros, whole_facts)).detection;
    let after = check.decode(&evidence(&macros, cut_facts)).detection;
    let moved = before.outcome != after.outcome || before.level != after.level;
    let declared: Vec<ElfTable> = std::iter::once(&cut.table)
        .chain(cut.also)
        .copied()
        .filter(|t| check.reads().contains(t))
        .collect();
    if moved {
        assert!(
            !declared.is_empty(),
            "{}: {} moved from {:?}/{:?} to {:?}/{:?} on a cut {:?} table (and {:?}) it does \
             not declare (reads {:?}); the truncation gate cannot withhold it",
            cut.name,
            check.id,
            before.outcome,
            before.level,
            after.outcome,
            after.level,
            cut.table,
            cut.also,
            check.reads()
        );
    }
    let gated = report::truncation_limitation(check, Some(cut_facts));
    assert_eq!(
        gated.is_some(),
        !declared.is_empty(),
        "{}: {} is gated={} while it declares {:?}",
        cut.name,
        check.id,
        gated.is_some(),
        check.reads()
    );
    if let Some(gating) = gated {
        assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
        assert!(
            declared.iter().any(|t| gating.reason.contains(t.as_str())),
            "{}: the reason names a declared cut table: {}",
            cut.name,
            gating.reason
        );
    }
    moved
}

/// The cut did what it claims: the named table and its companions are unread, and every
/// other table is whole.
fn assert_cut_exactly(cut: &Cut, cut_facts: &ElfFacts) {
    for expected in std::iter::once(&cut.table).chain(cut.also) {
        assert!(
            cut_facts.unread(&[*expected]).is_some(),
            "{}: the object was built to leave {:?} unread, got {:?}",
            cut.name,
            expected,
            cut_facts.truncations
        );
    }
    for other in ElfTable::ALL
        .iter()
        .filter(|t| **t != cut.table && !cut.also.contains(t))
    {
        assert!(
            cut_facts.unread(&[*other]).is_none(),
            "{}: cut {:?} as well as {:?}: {:?}",
            cut.name,
            other,
            cut.table,
            cut_facts.truncations
        );
    }
}

/// The whole object a cut is read against: [`whole`] for every cut but the relocation
/// section's, whose table only a relocatable object has (2026-10-02).
fn base_of(cut: &Cut) -> Build {
    if cut.table == ElfTable::Relocations {
        relocatable_with_call
    } else {
        whole
    }
}

/// Every cut, one per way the base object is left short of a table.
#[allow(
    clippy::too_many_lines,
    reason = "one table, a row per cut; split, a reader would look in two places for the cut \
              a table is declared against"
)]
fn cuts() -> Vec<Cut> {
    vec![
        Cut {
            name: "two PT_GNU_STACK headers that disagree on PF_X",
            table: ElfTable::GnuStack,
            also: &[],
            build: gnu_stack_disagreement,
        },
        Cut {
            name: "DT_FLAGS_1 repeated",
            table: ElfTable::Dynamic,
            also: &[],
            build: repeated_flags1,
        },
        Cut {
            name: "a second PT_DYNAMIC segment",
            table: ElfTable::Dynamic,
            also: &[],
            build: second_dynamic_segment,
        },
        Cut {
            name: "section headers stripped",
            table: ElfTable::Symbols,
            also: &[ElfTable::SectionNames, ElfTable::Comment],
            build: stripped,
        },
        Cut {
            name: "a count escape naming a shdr[0] past the end of the file",
            table: ElfTable::SectionHeaders,
            also: &[ElfTable::Symbols, ElfTable::SectionNames, ElfTable::Comment],
            build: section_header_escape_cut,
        },
        Cut {
            name: "symbol tables linked to .text",
            table: ElfTable::Symbols,
            also: &[],
            build: symbols_linked_to_text,
        },
        Cut {
            name: "symbol string tables past the end of the file",
            table: ElfTable::Symbols,
            also: &[],
            build: symbol_strings_cut,
        },
        Cut {
            name: "symbol tables sized below one entry",
            table: ElfTable::Symbols,
            also: &[],
            build: symbol_tables_below_one_entry,
        },
        Cut {
            name: "symbol tables sized one entry and one byte",
            table: ElfTable::Symbols,
            also: &[],
            build: symbol_tables_with_a_partial_entry,
        },
        Cut {
            name: "e_shstrndx names a PROGBITS section",
            table: ElfTable::SectionNames,
            also: &[ElfTable::Comment],
            build: section_names_cut,
        },
        Cut {
            name: ".shstrtab past the end of the file",
            table: ElfTable::SectionNames,
            also: &[ElfTable::Comment],
            build: section_name_table_cut,
        },
        Cut {
            name: "PT_DYNAMIC past the end of the file",
            table: ElfTable::Dynamic,
            also: &[],
            build: dynamic_cut,
        },
        Cut {
            name: "PT_DYNAMIC shortened past DT_NULL",
            table: ElfTable::Dynamic,
            also: &[],
            build: dynamic_shortened,
        },
        Cut {
            name: "PT_LOAD past the end of the file",
            table: ElfTable::DynStr,
            // `DT_SYMTAB` translates through the same segment, so
            // the loader's dynamic symbol table moves with it and no `SHT_DYNSYM` header
            // lies where it now resolves; the symbols are recorded unread beside the strings.
            also: &[ElfTable::Symbols],
            build: load_segment_cut,
        },
        Cut {
            name: "DT_STRSZ of 1",
            table: ElfTable::DynStr,
            also: &[],
            build: strsz_cut,
        },
        Cut {
            name: "DT_STRTAB in no PT_LOAD, with .dynstr unfindable by name",
            table: ElfTable::DynStr,
            also: &[ElfTable::SectionNames, ElfTable::Comment],
            build: strtab_unmapped_cut,
        },
        Cut {
            name: "no DT_STRTAB beside DT_NEEDED, with .dynstr unfindable by name",
            table: ElfTable::DynStr,
            also: &[ElfTable::SectionNames, ElfTable::Comment],
            build: strtab_absent_cut,
        },
        Cut {
            name: "SHT_NOTE and PT_NOTE past the end of the file",
            table: ElfTable::Notes,
            also: &[],
            build: notes_cut,
        },
        Cut {
            name: "the code reader's function past the end of the file",
            table: ElfTable::Code,
            also: &[],
            build: probe_code_cut,
        },
        Cut {
            name: "elf::entry's functions past the end of the file",
            table: ElfTable::FunctionEntries,
            also: &[],
            build: entry_code_cut,
        },
        Cut {
            name: "a code relocation section with a partial record",
            table: ElfTable::Relocations,
            also: &[],
            build: relocation_section_cut,
        },
    ]
}

/// The cuts of the relocatable objects, each paired with the whole object it is read
/// against rather than the linked base, since a link keeps no relocations per function.
fn relocation_cuts() -> Vec<(Build, Cut)> {
    vec![
        (
            relocatable_whole,
            Cut {
                name: ".rela.text past the end of the file",
                table: ElfTable::Relocations,
                also: &[],
                build: relocations_cut,
            },
        ),
        (
            relocatable_whole,
            Cut {
                name: ".rela.text linked to .text",
                table: ElfTable::Relocations,
                also: &[],
                build: relocations_unlinked,
            },
        ),
        (
            relocatable_whole,
            Cut {
                name: ".rela.text retyped SHT_CREL",
                table: ElfTable::Relocations,
                also: &[],
                build: relocations_crel,
            },
        ),
        (
            relocatable_whole,
            Cut {
                name: ".rela.text retyped to an unknown type with SHF_INFO_LINK",
                table: ElfTable::Relocations,
                also: &[],
                build: relocations_unknown_info_link,
            },
        ),
        (
            pic_relocatable_whole,
            Cut {
                name: "pic-object-relocs' .rela.text sized one entry and one byte",
                table: ElfTable::Relocations,
                also: &[],
                build: pic_relocations_with_a_partial_entry,
            },
        ),
        (
            relocatable_rel32_whole,
            Cut {
                name: "ELF32 .rel.text ending in a partial entry",
                table: ElfTable::Relocations,
                also: &[],
                build: rel32_partial_entry,
            },
        ),
    ]
}

/// The frame around the examination: every cut examined every elf-static check, every
/// declared table with a recording site was cut, the section-name cut moved nothing, and
/// each other cut moved something.
fn assert_frame(
    cuts: &[Cut],
    elf_static: &[&Check],
    examined: &BTreeMap<&str, usize>,
    moved: &BTreeMap<&str, Vec<&str>>,
) {
    // The frame: every cut examined every elf-static check.
    for cut in cuts {
        assert_eq!(
            examined.get(cut.name).copied().unwrap_or(0),
            elf_static.len(),
            "{}: not every check was examined",
            cut.name
        );
    }
    // Every declared table with a recording site was cut at least once, so no
    // declaration is held to nothing.
    let declared: BTreeSet<ElfTable> = elf_static
        .iter()
        .flat_map(|c| c.reads().iter().copied())
        .collect();
    let cut_tables: BTreeSet<ElfTable> = cuts.iter().map(|c| c.table).collect();
    let soft: BTreeSet<ElfTable> = ElfTable::SOFT_SITES.iter().copied().collect();
    let uncut: Vec<ElfTable> = (&declared & &soft)
        .difference(&cut_tables)
        .copied()
        .collect();
    assert!(
        uncut.is_empty(),
        "a declared table with a recording site was never cut here: {uncut:?}"
    );
    // Each cut moves something, so each declaration was held to a detector that reads
    // the table. The section-name cuts move `ret-protector-emitted`, which reads the
    // section list, and `examine` holds every move to a declared table.
    for cut in cuts {
        let movers = moved.get(cut.name).map_or(0, Vec::len);
        assert!(
            movers > 0,
            "{}: no detector moved, so the {:?} declarations were held to nothing",
            cut.name,
            cut.table
        );
    }
}

#[test]
fn a_truncation_moves_a_detector_only_where_it_declared_the_table() {
    let cuts = cuts();
    let whole_facts = facts(&whole());
    assert!(
        whole_facts.truncations.is_empty(),
        "the control carries no truncation: {:?}",
        whole_facts.truncations
    );
    assert_eq!(whole_facts.relro.as_deref(), Some("full"));
    assert_eq!(
        whole_facts.needed,
        vec!["libc.so.6".to_owned(), "libm.so.6".to_owned()]
    );
    assert_eq!(whole_facts.rpath, vec!["/opt/chard/lib".to_owned()]);

    let elf_static: Vec<&Check> = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| c.channel() == Channel::ElfStatic)
        .collect();
    assert!(!elf_static.is_empty(), "no elf-static check in the corpus");

    let mut examined: BTreeMap<&str, usize> = BTreeMap::new();
    let mut moved: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let base_cuts: Vec<(ElfFacts, &Cut)> = cuts
        .iter()
        .map(|cut| {
            let base_facts = facts(&base_of(cut)());
            assert!(
                base_facts.truncations.is_empty(),
                "{}: the base carries no truncation: {:?}",
                cut.name,
                base_facts.truncations
            );
            (base_facts, cut)
        })
        .collect();
    let relocation_cuts: Vec<(ElfFacts, Cut)> = relocation_cuts()
        .into_iter()
        .map(|(base, cut)| {
            let base_facts = facts(&base());
            assert!(
                base_facts.truncations.is_empty(),
                "{}: the relocatable control carries no truncation: {:?}",
                cut.name,
                base_facts.truncations
            );
            (base_facts, cut)
        })
        .collect();
    let bases = base_cuts
        .iter()
        .map(|(f, c)| (*c, f))
        .chain(relocation_cuts.iter().map(|(f, c)| (c, f)));
    for (cut, base_facts) in bases {
        let cut_facts = facts(&(cut.build)());
        assert_cut_exactly(cut, &cut_facts);
        for check in &elf_static {
            if examine(check, cut, base_facts, &cut_facts) {
                moved.entry(cut.name).or_default().push(check.id);
            }
            *examined.entry(cut.name).or_insert(0) += 1;
        }
    }
    drop(base_cuts);

    let every_cut: Vec<Cut> = cuts
        .into_iter()
        .chain(relocation_cuts.into_iter().map(|(_, c)| c))
        .collect();
    assert_frame(&every_cut, &elf_static, &examined, &moved);
    eprintln!(
        "examined {} detector pairs over {} cuts; movers: {moved:?}",
        examined.values().sum::<usize>(),
        every_cut.len()
    );
}

/// A `.dynamic` the reader could not finish withholds `pic-shared-link`, the one
/// compiler-diag check that reads the artifact (through `DT_TEXTREL`), on the measured
/// build and on every arm.
///
/// The measured build is gated by `report::truncation_limitation`, an arm by
/// `measure::withhold_unreadable` through `report::truncated_reading`; this holds what the
/// two return for the check, and `measure`'s unit test
/// `a_shared_link_read_over_a_cut_dynamic_table_is_withheld` that both are applied to it.
/// Without them a half-read dynamic table under a hidden `-z notext` reads `textrel` false
/// and the link `on`.
#[test]
fn a_dynamic_table_not_read_withholds_the_compiler_diag_check_reading_it() {
    let declaring: Vec<&Check> = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| c.channel() == Channel::CompilerDiag && c.reads().contains(&ElfTable::Dynamic))
        .collect();
    assert_eq!(
        declaring.iter().map(|c| c.id).collect::<Vec<_>>(),
        ["pic-shared-link"]
    );
    for (name, bytes) in [
        ("dynamic_cut", dynamic_cut()),
        ("dynamic_shortened", dynamic_shortened()),
    ] {
        let cut = facts(&bytes);
        assert!(
            cut.truncations.iter().any(|t| t.table == ElfTable::Dynamic),
            "{name}: the reader records the dynamic table: {:?}",
            cut.truncations
        );
        for check in &declaring {
            let gating = report::truncation_limitation(check, Some(&cut))
                .unwrap_or_else(|| panic!("{name}: {} read over a cut dynamic table", check.id));
            assert_eq!(
                gating.rule,
                report::gating_rule::ARTIFACT_UNREADABLE,
                "{name}"
            );
            assert!(
                report::truncated_reading(check, Some(&cut)).is_some(),
                "{name}: {} arm read over a cut dynamic table",
                check.id
            );
        }
    }
    let whole = facts(&whole());
    for check in &declaring {
        assert!(
            report::truncation_limitation(check, Some(&whole)).is_none(),
            "{}",
            check.id
        );
    }
}

/// A program-header table not read withholds every check declaring it, the stack readers
/// with `pie`, `relro` and `textrel-absent`.
///
/// The other half of `gnu-stack` (2026-10-05): the disagreeing `PT_GNU_STACK` pair is
/// recorded against a table of its own so it withholds the stack readers alone, and that
/// must not leave the stack readers gated on `gnu-stack` alone, which a cut in the header
/// table does not record. Two routes are held. The header table moved past the end of the
/// file is refused by `Elf::parse`, which `measure::gather` stores as `elf_error`, and
/// `Variant::sufficient_for` withholds every elf-static check over it as `indeterminate`;
/// every check declaring `program-headers` is on that channel. And an `unread` entry naming
/// `program-headers` itself, which no site in the reader writes today and a facts record
/// could carry, gates every check declaring it through `report::truncation_limitation`,
/// with no `gnu-stack` entry beside it.
#[test]
fn a_program_header_table_not_read_withholds_every_check_declaring_it() {
    let declaring: Vec<&Check> = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| c.reads().contains(&ElfTable::ProgramHeaders))
        .collect();
    let ids: BTreeSet<&str> = declaring.iter().map(|c| c.id).collect();
    for id in [
        "pie",
        "relro",
        "textrel-absent",
        "noexecstack",
        "linker-default-noexecstack",
    ] {
        assert!(ids.contains(id), "{id} declares program-headers: {ids:?}");
    }

    // The header table past the end of the file: `parse` refuses it.
    let mut cut = whole();
    let past = u64::try_from(cut.len()).expect("a file length fits u64") + 8;
    cut[32..40].copy_from_slice(&past.to_le_bytes()); // e_phoff
    let elf_error = match elf::Elf::parse(&cut) {
        Ok(_) => panic!("a program-header table past the end of the file parsed"),
        Err(e) => report::ArtifactRefusal::of(&e),
    };
    let variant = report::Variant {
        macros: BTreeMap::new(),
        macros_preprocessor: BTreeMap::new(),
        macro_source: "preprocessor",
        macro_dump: None,
        elf: None,
        build: None,
        run: None,
        run_error: None,
        elf_error: Some(elf_error),
        artifact: None,
        structured: None,
        workdir: None,
    };
    for check in &declaring {
        assert_eq!(
            check.channel(),
            Channel::ElfStatic,
            "{}: a check declaring program-headers is withheld by the parse refusal only \
             on the elf-static channel",
            check.id
        );
        assert_eq!(
            variant.sufficient_for(check.channel()),
            Err(report::Verdict::Indeterminate),
            "{}: a header table parse refused withholds it",
            check.id
        );
    }

    // An `unread` entry naming the table, over facts otherwise whole.
    let mut facts = facts(&whole());
    assert!(facts.truncations.is_empty(), "{:?}", facts.truncations);
    facts.truncations.push(elf::Truncation {
        table: ElfTable::ProgramHeaders,
        kind: elf::TruncationKind::Unread,
        detail: "the program-header table could not be read".to_owned(),
    });
    let mut gated = 0usize;
    for check in &declaring {
        let gating = report::truncation_limitation(check, Some(&facts))
            .unwrap_or_else(|| panic!("{}: read over an unread program-header table", check.id));
        assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
        assert!(
            gating.reason.contains("program-headers"),
            "{}: {}",
            check.id,
            gating.reason
        );
        gated += 1;
    }
    assert_eq!(gated, declaring.len());
    eprintln!(
        "{} checks declare program-headers, each withheld by the refusal and the entry: {ids:?}",
        declaring.len()
    );
}

/// The dynamic string table the file does not hold is recorded once.
///
/// `dyn_strtab` locates the table once and `dyn_strings` is called three times over
/// what it located, so the record lands once by construction; this pins it, since three
/// entries for one condition would name the cut three times in the facts.
#[test]
fn the_dynamic_string_table_the_file_does_not_hold_is_recorded_once() {
    let cut = facts(&load_segment_cut());
    let records: Vec<&elf::Truncation> = cut
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::DynStr)
        .collect();
    assert_eq!(records.len(), 1, "one table, one record: {records:?}");
    assert_eq!(records[0].kind, elf::TruncationKind::Unread);
    assert!(cut.needed.is_empty() && cut.rpath.is_empty());
}

/// A note section the file does not hold, beside a `PT_NOTE` the reader finished, is a
/// view dropped for the loader's: the bits are decoded, the entry is `ignored`, and no
/// check is withheld.
///
/// Recorded as `unread` before, the section cut withheld `cet-marked` under
/// `artifact-unreadable` over a property that had been read whole from the segment,
/// which is the case `TruncationKind::Ignored` was defined for. The control is the
/// notes cut with both views moved, which stays `unread`.
#[test]
fn a_note_section_cut_beside_a_whole_segment_is_a_dropped_view() {
    let control = facts(&whole());
    assert!(
        control.x86_ibt && control.x86_shstk,
        "the base object is CET-marked"
    );

    let rescued = facts(&note_section_cut());
    assert!(
        rescued.x86_ibt && rescued.x86_shstk,
        "the segment carried the property: {rescued:?}"
    );
    let notes: Vec<&elf::Truncation> = rescued
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Notes)
        .collect();
    assert_eq!(
        notes.len(),
        1,
        "the section stop is recorded once: {notes:?}"
    );
    assert_eq!(notes[0].kind, elf::TruncationKind::Ignored, "{notes:?}");
    assert!(
        notes[0].detail.contains("lies outside every PT_NOTE"),
        "the entry says what rescued it: {}",
        notes[0].detail
    );
    assert!(
        rescued.unread(&[ElfTable::Notes]).is_none(),
        "a dropped view leaves the table read: {:?}",
        rescued.truncations
    );
    let mut examined = 0usize;
    for check in CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| c.channel() == Channel::ElfStatic)
    {
        assert!(
            report::truncation_limitation(check, Some(&rescued)).is_none(),
            "{}: a dropped view gates nothing",
            check.id
        );
        examined += 1;
    }
    assert!(examined > 0, "no elf-static check was examined");

    let unrescued = facts(&notes_cut());
    assert!(
        unrescued.unread(&[ElfTable::Notes]).is_some(),
        "both views cut is a table unread: {:?}",
        unrescued.truncations
    );
}

/// An object with no symbol table names none, records no truncation, and the checks
/// that read a symbol reference are `not-applicable` over it under the precondition.
///
/// The reader's half of the stripped-static-link case: `symbol_tables` is filled from the
/// tables `symbols()` walked, so the whole object lists both and the retyped one lists
/// none, and an absent table is never a truncation. `measure::tests` holds the gate's
/// ordering over the same facts.
#[test]
fn an_object_with_no_symbol_table_names_none_and_records_no_truncation() {
    let control = facts(&whole());
    assert_eq!(
        control.symbol_tables,
        vec![".dynsym".to_owned(), ".symtab".to_owned()],
        "the base object's symbol tables, in header order"
    );
    assert!(control.watched_symbols.contains_key("__stack_chk_fail"));

    let none = facts(&no_symbol_tables());
    assert!(none.symbol_tables.is_empty(), "{:?}", none.symbol_tables);
    assert_eq!(none.symbol_count, 0);
    assert!(none.watched_symbols.is_empty());
    assert!(
        none.truncations.is_empty(),
        "an absent table is not a cut one: {:?}",
        none.truncations
    );
    let mut examined = 0usize;
    for check in CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| c.reads().contains(&ElfTable::Symbols))
    {
        let gating =
            report::artifact_limitation(report::Verdict::Off, check, Outcome::Absent, Some(&none))
                .unwrap_or_else(|| panic!("{}: no symbol table gates a symbol reading", check.id));
        assert_eq!(
            gating.rule,
            report::gating_rule::ARTIFACT_CANNOT_CARRY,
            "{}",
            check.id
        );
        assert!(
            report::artifact_limitation(
                report::Verdict::Off,
                check,
                Outcome::Absent,
                Some(&control)
            )
            .is_none(),
            "{}: the whole object carries a symbol table",
            check.id
        );
        examined += 1;
    }
    // Ten: among them `trapv-helper-called`, `ubsan-trap-mode` and `fortify-printf-flag`,
    // which locate their functions through `.symtab`, `cet-endbr-emitted`, `plt-bypassed`,
    // `ssp-level-emitted`, and `pic-object-relocs`, which names a relocation's symbol through
    // the symbol table.
    assert_eq!(examined, 10, "the ten symbol-reading checks were examined");
}

/// A symbol table sized below one entry, or past its last whole entry, is recorded as a
/// cut `symbols` table and withholds `canary-emitted` under `artifact-unreadable`.
///
/// Read as zero entries, a table below one entry was listed in `symbol_tables` and
/// yielded no symbols with nothing recorded, so the canary reference read absent over a
/// table that could not hold one. A real table always holds the null symbol at index 0.
/// A trailing partial entry is a symbol the reader did not read, and is recorded the
/// same way while the whole entries before it are read.
#[test]
fn a_symbol_table_short_of_whole_entries_withholds_the_canary_reading() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "canary-emitted")
        .expect("canary-emitted is in the corpus");
    let macros = BTreeMap::new();
    let whole_facts = facts(&whole());
    let before = check.decode(&evidence(&macros, &whole_facts)).detection;
    assert!(report::truncation_limitation(check, Some(&whole_facts)).is_none());

    let cases: [(Build, &str); 2] = [
        (symbol_tables_below_one_entry, "below one 24-byte entry"),
        (symbol_tables_with_a_partial_entry, "1 trailing bytes"),
    ];
    let mut examined = 0usize;
    for (build, says) in cases {
        let cut = facts(&build());
        assert_eq!(
            cut.symbol_tables,
            vec![".dynsym".to_owned(), ".symtab".to_owned()],
            "a short table is still listed"
        );
        let records: Vec<&elf::Truncation> = cut
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::Symbols)
            .collect();
        assert_eq!(records.len(), 2, "one record per table: {records:?}");
        for (record, table) in records.iter().zip([".dynsym", ".symtab"]) {
            assert_eq!(record.kind, elf::TruncationKind::Unread);
            assert!(
                record.detail.starts_with(table) && record.detail.contains(says),
                "the record names the table and its size: {}",
                record.detail
            );
        }
        assert!(
            !cut.watched_symbols.contains_key("__stack_chk_fail"),
            "the canary reference sits past the entries read: {:?}",
            cut.watched_symbols
        );
        let after = check.decode(&evidence(&macros, &cut)).detection;
        assert_ne!(
            before.outcome, after.outcome,
            "the canary reading moved with the cut"
        );
        let gating = report::truncation_limitation(check, Some(&cut))
            .expect("a short symbol table withholds canary-emitted");
        assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
        assert!(gating.reason.contains("symbols"), "{}", gating.reason);
        examined += 1;
    }
    assert_eq!(examined, 2, "both sizes were examined");
}

/// A symbol table whose `sh_entsize` is not the 24-byte record is read in records, as the
/// loader reads `.dynsym` and readelf reads either, and the header that disagreed is
/// recorded `ignored`; the canary reading is the honest table's.
///
/// The base object's `.dynsym` is four records, 96 bytes. Read at a declared 48, it would
/// step over every other record: the null symbol and `main` read, `__stack_chk_fail` and
/// `abort` not, nothing recorded, and with `.symtab` gone `canary-emitted` would lose the
/// canary reference with nothing to withhold on. That is a forged `.dynsym` in the shape a
/// 216-byte table does not reach, a size the forged stride divides. 72 leaves a partial
/// record at that stride; 0, 1 and 23 are the floor's cases, below the record; 25 is
/// one past it. Every declared size from 0 to 130 and `u64::MAX` is read beside them.
#[test]
fn a_symbol_table_declaring_another_entry_size_is_read_in_records() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "canary-emitted")
        .expect("canary-emitted is in the corpus");
    let macros = BTreeMap::new();
    let control = facts(&dynsym_alone_with_entsize(SYM_SIZE));
    assert_eq!(control.symbol_tables, vec![".dynsym".to_owned()]);
    assert_eq!(control.symbol_count, 3, "__stack_chk_fail, main and abort");
    assert!(control.watched_symbols.contains_key("__stack_chk_fail"));
    assert!(control.truncations.is_empty(), "{:?}", control.truncations);
    let before = check.decode(&evidence(&macros, &control)).detection;
    let mut examined = 0usize;
    let named = [2 * SYM_SIZE, 3 * SYM_SIZE, 0, 1, SYM_SIZE - 1, SYM_SIZE + 1];
    let swept = (0..=130).filter(|e| *e != SYM_SIZE).chain([u64::MAX]);
    for entsize in named.into_iter().chain(swept) {
        let forged = facts(&dynsym_alone_with_entsize(entsize));
        assert_eq!(
            (forged.symbol_count, &forged.watched_symbols),
            (control.symbol_count, &control.watched_symbols),
            "sh_entsize {entsize}: every record is read, as the honest table's are"
        );
        assert_eq!(
            forged.truncations,
            vec![elf::Truncation {
                table: ElfTable::Symbols,
                kind: elf::TruncationKind::Ignored,
                detail: format!(
                    ".dynsym: sh_entsize is {entsize} where the record is 24 bytes, so it \
                     was read in 24-byte records, the size the ABI fixes"
                ),
            }],
            "sh_entsize {entsize}: the one record names the header"
        );
        let after = check.decode(&evidence(&macros, &forged)).detection;
        assert_eq!(after.outcome, before.outcome, "sh_entsize {entsize}");
        assert!(
            report::truncation_limitation(check, Some(&forged)).is_none(),
            "sh_entsize {entsize}: an ignored record withholds nothing"
        );
        examined += 1;
    }
    // Six named, then 0 to 130 but 24, then `u64::MAX`.
    assert_eq!(examined, 6 + 130 + 1, "every declared size was examined");

    // Both tables declaring 48: one record each, in header order, and the reading is the
    // base object's.
    let both = facts(&with_entsize(
        whole(),
        &[".dynsym", ".symtab"],
        2 * SYM_SIZE,
    ));
    let plain = facts(&whole());
    assert_eq!(both.symbol_count, plain.symbol_count);
    assert_eq!(both.watched_symbols, plain.watched_symbols);
    let records = symbol_records(&both);
    assert_eq!(records.len(), 2, "{records:?}");
    for (record, table) in records.iter().zip([".dynsym", ".symtab"]) {
        assert_eq!(record.kind, elf::TruncationKind::Ignored);
        assert!(
            record
                .detail
                .starts_with(&format!("{table}: sh_entsize is 48 ")),
            "{}",
            record.detail
        );
    }
}

/// A `PT_DYNAMIC` whose `DT_SYMTAB` names the loader's table, beside section headers of
/// which none is `SHT_DYNSYM`, is the loader's table with no header to read it by: recorded
/// `unread`, as a header aimed elsewhere is, so `canary-emitted` withholds rather than
/// reading the canary reference from `.symtab` alone. A view that was the sections' alone
/// would record nothing. With `DT_SYMTAB` retagged away as well, the loader has no dynamic
/// symbol table and nothing is recorded.
#[test]
fn a_dynsym_header_retyped_away_beside_dt_symtab_is_recorded_unread() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "canary-emitted")
        .expect("canary-emitted is in the corpus");
    let retyped = facts(&retyped_away(whole(), &[".dynsym"]));
    assert_eq!(retyped.symbol_tables, vec![".symtab".to_owned()]);
    let records = symbol_records(&retyped);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].kind, elf::TruncationKind::Unread);
    assert!(
        records[0]
            .detail
            .starts_with("no SHT_DYNSYM header lies at the ")
            && records[0].detail.contains("DT_SYMTAB names"),
        "{}",
        records[0].detail
    );
    let gating = report::truncation_limitation(check, Some(&retyped))
        .expect("the loader's table unread withholds canary-emitted");
    assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);

    let none = facts(&no_symbol_tables());
    assert!(none.symbol_tables.is_empty(), "{:?}", none.symbol_tables);
    assert!(none.truncations.is_empty(), "{:?}", none.truncations);
}

/// A relocation section whose `sh_entsize` is not the 24-byte `Elf64_Rela` is read in
/// records, and recorded `ignored` once though three walks read it (the code
/// relocations, the function references and the code reader's relocated fields): every
/// relocation-reading fact and check is the honest section's.
///
/// Read at a declared 48, the four-function object's `.rela.text` would step over every other
/// entry with nothing recorded, and the one-entry object's would be a partial entry, recorded
/// unread.
#[test]
fn a_relocation_section_declaring_another_entry_size_is_read_in_records() {
    let objects: [(&str, Build, usize); 2] = [
        ("four functions", relocatable_whole, rela_index()),
        ("one code relocation", pic_relocatable_whole, {
            relocatable_with_code_relocation()
                .sections
                .iter()
                .position(|s| s.name == ".rela.text")
                .expect("the object has a .rela.text")
                + 1
        }),
    ];
    let macros = BTreeMap::new();
    let mut examined = 0usize;
    for (name, build, index) in objects {
        let honest = facts(&build());
        assert!(
            honest.truncations.is_empty(),
            "{name}: {:?}",
            honest.truncations
        );
        let mut d = build();
        let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
        let shdr = shoff + index * SHDR_SIZE;
        assert_eq!(
            le_u64(&d[shdr + 56..shdr + 64]),
            24,
            "{name}: the builder's entsize"
        );
        d[shdr + 56..shdr + 64].copy_from_slice(&48u64.to_le_bytes());
        let forged = facts(&d);
        assert_eq!(
            (&forged.code_relocations, &forged.function_references),
            (&honest.code_relocations, &honest.function_references),
            "{name}: every entry is read, as the honest section's are"
        );
        assert_eq!(
            forged.truncations,
            vec![elf::Truncation {
                table: ElfTable::Relocations,
                kind: elf::TruncationKind::Ignored,
                detail: ".rela.text: sh_entsize is 48 where the record is 24 bytes, so it \
                         was read in 24-byte records, the size the ABI fixes"
                    .to_owned(),
            }],
            "{name}: one record though three walks read the section"
        );
        for check in CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .filter(|c| c.reads().contains(&ElfTable::Relocations))
        {
            assert_eq!(
                check.decode(&evidence(&macros, &forged)).detection.outcome,
                check.decode(&evidence(&macros, &honest)).detection.outcome,
                "{name}: {}",
                check.id
            );
            assert!(report::truncation_limitation(check, Some(&forged)).is_none());
            examined += 1;
        }
    }
    assert!(
        examined >= 4,
        "the relocation-reading checks were examined: {examined}"
    );
}

/// `d`, an ELF32 little-endian object, with section `index`'s `sh_entsize` set to `entsize`:
/// `e_shoff` at 32, 40-byte headers, `sh_entsize` the last four bytes of each.
fn with_entsize32(mut d: Vec<u8>, index: usize, entsize: u32) -> Vec<u8> {
    let shoff = usize::try_from(u32::from_le_bytes(
        d[32..36].try_into().expect("four bytes"),
    ))
    .expect("a fixture offset fits in usize");
    let field = shoff + index * 40 + 36;
    d[field..field + 4].copy_from_slice(&entsize.to_le_bytes());
    d
}

/// A case of [`a_relocatable_object_declaring_other_entry_sizes_is_read_in_records_and_recorded_once`]:
/// its name, the honest object, the forged one, and the records the forged one must carry,
/// in order, as (table, the detail's opening).
type EntsizeCase = (&'static str, Vec<u8>, Vec<u8>, Vec<(ElfTable, String)>);

/// The relocatable objects whose headers declare other entry sizes: ELF64 and ELF32, the
/// symbol table alone and with its relocation section, and the one `Elf32_Rela` object.
fn relocatable_entsize_cases() -> Vec<EntsizeCase> {
    let index_in = |object: &Object, name: &str| {
        object
            .sections
            .iter()
            .position(|s| s.name == name)
            .unwrap_or_else(|| panic!("the object has no {name}"))
            + 1
    };
    let elf64 = elf_builder::relocatable_functions();
    let elf32 = elf_builder::relocatable_functions_rel32();
    let rela32 = elf_builder::relocatable_functions_rela32();
    let rela32_text = index_in(&rela32, ".rela.text");
    let (sym64, rela64) = (index_in(&elf64, ".symtab"), index_in(&elf64, ".rela.text"));
    let (sym32, rel32) = (index_in(&elf32, ".symtab"), index_in(&elf32, ".rel.text"));
    let patch64 = |d: Vec<u8>, index: usize, entsize: u64| {
        let mut d = d;
        let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
        let field = shoff + index * SHDR_SIZE + 56;
        d[field..field + 8].copy_from_slice(&entsize.to_le_bytes());
        d
    };
    let cases: [EntsizeCase; 4] = [
        (
            "ELF64 .symtab at 48",
            elf64.build(),
            patch64(elf64.build(), sym64, 48),
            vec![(
                ElfTable::Symbols,
                ".symtab: sh_entsize is 48 where the record is 24".to_owned(),
            )],
        ),
        (
            "ELF64 .symtab and .rela.text at 48",
            elf64.build(),
            patch64(patch64(elf64.build(), sym64, 48), rela64, 48),
            vec![
                (
                    ElfTable::Symbols,
                    ".symtab: sh_entsize is 48 where the record is 24".to_owned(),
                ),
                (
                    ElfTable::Relocations,
                    ".rela.text: sh_entsize is 48 where the record is 24".to_owned(),
                ),
            ],
        ),
        (
            "ELF32 .symtab at 32",
            elf32.build(),
            with_entsize32(elf32.build(), sym32, 32),
            vec![(
                ElfTable::Symbols,
                ".symtab: sh_entsize is 32 where the record is 16".to_owned(),
            )],
        ),
        (
            "ELF32 .symtab at 32 and .rel.text at 16",
            elf32.build(),
            with_entsize32(with_entsize32(elf32.build(), sym32, 32), rel32, 16),
            vec![
                (
                    ElfTable::Symbols,
                    ".symtab: sh_entsize is 32 where the record is 16".to_owned(),
                ),
                (
                    ElfTable::Relocations,
                    ".rel.text: sh_entsize is 16 where the record is 8".to_owned(),
                ),
            ],
        ),
    ];
    cases
        .into_iter()
        .chain([(
            "ELF32 .rela.text at 24",
            rela32.build(),
            with_entsize32(rela32.build(), rela32_text, 24),
            vec![(
                ElfTable::Relocations,
                ".rela.text: sh_entsize is 24 where the record is 12".to_owned(),
            )],
        )])
        .collect()
}

/// A relocatable object's `.symtab` declaring twice its record is read by four walks (the
/// symbol reader, the code-relocation names, the function references and the code reader's
/// definitions), and recorded once; with its relocation section declaring twice its record
/// too, once more, on `relocations`. ELF64 (`Elf64_Sym` 24, `Elf64_Rela` 24) and ELF32
/// (`Elf32_Sym` 16, `Elf32_Rel` 8), so each class's record sizes are held to a forged header,
/// and every fact is the honest object's.
#[test]
fn a_relocatable_object_declaring_other_entry_sizes_is_read_in_records_and_recorded_once() {
    let macros = BTreeMap::new();
    let mut examined = 0usize;
    for (name, honest, forged, expected) in relocatable_entsize_cases() {
        let honest = facts(&honest);
        let forged = facts(&forged);
        assert!(
            honest.truncations.is_empty(),
            "{name}: {:?}",
            honest.truncations
        );
        assert_eq!(
            (
                forged.symbol_count,
                &forged.watched_symbols,
                &forged.code_relocations,
                &forged.function_references,
                &forged.code_scanned,
            ),
            (
                honest.symbol_count,
                &honest.watched_symbols,
                &honest.code_relocations,
                &honest.function_references,
                &honest.code_scanned,
            ),
            "{name}: every record is read, as the honest object's are"
        );
        let got: Vec<(ElfTable, &str)> = forged
            .truncations
            .iter()
            .map(|t| {
                assert_eq!(t.kind, elf::TruncationKind::Ignored, "{name}: {t:?}");
                (t.table, t.detail.as_str())
            })
            .collect();
        assert_eq!(
            got.len(),
            expected.len(),
            "{name}: one record per header: {got:?}"
        );
        for ((table, detail), (want_table, want)) in got.iter().zip(&expected) {
            assert_eq!(table, want_table, "{name}");
            assert!(detail.starts_with(want.as_str()), "{name}: {detail}");
        }
        for check in CORPUS.iter().flat_map(|p| p.checks.iter()).filter(|c| {
            c.reads().contains(&ElfTable::Symbols) || c.reads().contains(&ElfTable::Relocations)
        }) {
            assert_eq!(
                check.decode(&evidence(&macros, &forged)).detection.outcome,
                check.decode(&evidence(&macros, &honest)).detection.outcome,
                "{name}: {}",
                check.id
            );
            examined += 1;
        }
    }
    assert!(
        examined >= 5 * 10,
        "the symbol- and relocation-reading checks: {examined}"
    );
}

/// Two relocation sections that share a name (as a relocatable object's COMDAT copies do)
/// and each declare 48 over 24-byte records leave one record each, told apart by index; one
/// name for both had merged them. Every fact is the honest object's.
#[test]
fn two_sections_sharing_a_name_leave_a_stride_record_each() {
    let build = |entsize: u64| {
        let mut object = elf_builder::relocatable_functions();
        let copy = object
            .sections
            .iter()
            .find(|s| s.name == ".rela.text")
            .expect("the object has a .rela.text")
            .clone();
        object.sections.push(copy);
        let indices: Vec<usize> = object
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.name == ".rela.text")
            .map(|(i, _)| i + 1)
            .collect();
        let mut d = object.build();
        let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
        for index in &indices {
            let field = shoff + index * SHDR_SIZE + 56;
            d[field..field + 8].copy_from_slice(&entsize.to_le_bytes());
        }
        (d, indices)
    };
    let (honest, _) = build(24);
    let (forged, indices) = build(48);
    let (honest, forged) = (facts(&honest), facts(&forged));
    assert_eq!(indices.len(), 2);
    assert_eq!(forged.code_relocations, honest.code_relocations);
    assert_eq!(forged.function_references, honest.function_references);
    let records: Vec<&str> = forged
        .truncations
        .iter()
        .filter(|t| elf::is_stride_record(t))
        .map(|t| t.detail.as_str())
        .collect();
    let expected: Vec<String> = indices
        .iter()
        .map(|i| {
            format!(
                ".rela.text [{i}]: sh_entsize is 48 where the record is 24 bytes, so it was \
                 read in 24-byte records, the size the ABI fixes"
            )
        })
        .collect();
    assert_eq!(records, expected, "one record per section, by index");
}

/// Two symbol tables of one type with no name to read (the section names cut) are
/// labelled by type, which they share, so each record carries its index: two tables that
/// declare 48 leave two records.
#[test]
fn two_unnamed_symbol_tables_leave_a_stride_record_each() {
    let mut d = section_names_cut();
    let shoff = usize::try_from(le_u64(&d[40..48])).expect("a fixture offset fits in usize");
    let indices = [section_index(".symtab"), section_index(".dynsym")];
    for index in indices {
        let shdr = shoff + index * SHDR_SIZE;
        d[shdr + 4..shdr + 8].copy_from_slice(&2u32.to_le_bytes()); // SHT_SYMTAB
        d[shdr + 56..shdr + 64].copy_from_slice(&48u64.to_le_bytes());
    }
    let f = facts(&d);
    let mut records: Vec<&str> = f
        .truncations
        .iter()
        .filter(|t| elf::is_stride_record(t))
        .map(|t| t.detail.as_str())
        .collect();
    records.sort_unstable();
    let mut expected: Vec<String> = indices
        .iter()
        .map(|i| {
            format!(
                "SHT_SYMTAB [{i}]: sh_entsize is 48 where the record is 24 bytes, so it was read \
                 in 24-byte records, the size the ABI fixes"
            )
        })
        .collect();
    expected.sort_unstable();
    assert_eq!(records, expected, "{:?}", f.truncations);
}

/// A `DT_RELAENT` that is not the `Elf64_Rela` size is read past: the dynamic relocation
/// tables are walked in records, so the symbol floor they give is the honest one, and each
/// table read records the tag, `DT_RELA` and `DT_JMPREL` (whose `DT_PLTREL` names
/// `DT_RELA`) apart.
///
/// The shape is the reach the floor exists for: `.dynsym`'s header cut to the null symbol,
/// and `.rela.dyn` naming symbol 1 (`__stack_chk_fail`) in its second entry. Walked at a
/// declared 48, the first entry (no symbol) would be the only one read, the floor 0, and the
/// import absent with nothing recorded. glibc's `ld.so` refuses such an object to run; the
/// reading is still the
/// artifact's, and a forged tag must not choose it.
#[test]
fn a_dynamic_relocation_entry_size_is_read_past_and_recorded() {
    let plain = facts(&whole());
    let build = |relaent: Option<u64>| {
        let mut d = relocated(&[], &[0, 1], None);
        let field = dynsym_size_field(&d);
        dynsym_header_field(&mut d, field, 24);
        if let Some(v) = relaent {
            patch_dynamic_entry(&mut d, DT_RELAENT, |entry| {
                entry[8..16].copy_from_slice(&v.to_le_bytes());
            });
        }
        d
    };
    let honest = facts(&build(None));
    assert_eq!(
        honest.watched_symbols.get("__stack_chk_fail"),
        plain.watched_symbols.get("__stack_chk_fail"),
        "{:?}",
        honest.truncations
    );
    assert!(
        honest
            .truncations
            .iter()
            .all(|t| t.table != ElfTable::Dynamic),
        "{:?}",
        honest.truncations
    );
    let forged = facts(&build(Some(48)));
    assert_eq!(forged.watched_symbols, honest.watched_symbols);
    assert_eq!(forged.symbol_count, honest.symbol_count);
    let dynamic: Vec<&str> = forged
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Dynamic)
        .map(|t| {
            assert_eq!(t.kind, elf::TruncationKind::Ignored, "{t:?}");
            t.detail.as_str()
        })
        .collect();
    assert_eq!(
        dynamic,
        vec![
            "DT_RELA: DT_RELAENT is 48 where the record is 24 bytes, so it was read in 24-byte \
             records, the size the ABI fixes",
            "DT_JMPREL: DT_RELAENT is 48 where the record is 24 bytes, so it was read in \
             24-byte records, the size the ABI fixes",
        ]
    );
    assert_eq!(
        forged
            .truncations
            .iter()
            .filter(|t| t.table != ElfTable::Dynamic)
            .collect::<Vec<_>>(),
        honest.truncations.iter().collect::<Vec<_>>(),
        "the other records are the honest object's"
    );
}

const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const SHT_REL: u32 = 9;

/// `Elf64_Rel` entries naming the given `.dynsym` indices: `r_offset` and `r_info`, no addend.
fn rel_naming(symbols: &[u64]) -> Vec<u8> {
    symbols
        .iter()
        .flat_map(|sym| {
            let mut e = 0x40_1000u64.to_le_bytes().to_vec();
            e.extend_from_slice(&((sym << 32) | 7).to_le_bytes());
            e
        })
        .collect()
}

/// [`relocated`] in the REL form: `.rel.plt` through `DT_JMPREL` with `DT_PLTREL` naming
/// `DT_REL`, `.rel.dyn` through `DT_REL`, and `DT_RELENT` 16, the `Elf64_Rel` size.
fn relocated_rel(plt: &[u64], dyn_: &[u64]) -> Vec<u8> {
    let mut object = base_with(|linked| {
        linked.extra_dynamic.extend([
            (DT_GNU_HASH, DynValue::AddrOf(".gnu.hash")),
            (DT_JMPREL, DynValue::AddrOf(".rel.plt")),
            (DT_PLTRELSZ, DynValue::SizeOf(".rel.plt")),
            (DT_PLTREL, DynValue::Const(17)),
            (DT_REL, DynValue::AddrOf(".rel.dyn")),
            (DT_RELSZ, DynValue::SizeOf(".rel.dyn")),
            (DT_RELENT, DynValue::Const(16)),
        ]);
    });
    for (name, sh_type, bytes) in [
        (".gnu.hash", SHT_GNU_HASH, le32_gnu_hash_of_one()),
        (".rel.plt", SHT_REL, rel_naming(plt)),
        (".rel.dyn", SHT_REL, rel_naming(dyn_)),
    ] {
        object.sections.push(Section {
            name,
            sh_type,
            flags: SHF_ALLOC,
            addralign: 8,
            entsize: if sh_type == SHT_REL { 16 } else { 0 },
            link: None,
            info: 0,
            content: Content::Bytes(bytes),
        });
    }
    object.build()
}

/// [`a_dynamic_relocation_entry_size_is_read_past_and_recorded`] in the REL form: a
/// `DT_RELENT` of 32 over 16-byte `Elf64_Rel` records, with `DT_JMPREL` read through
/// `DT_PLTREL` naming `DT_REL`, so both REL arms of `relocation_reach` are held. At the
/// declared 32 the second `.rel.dyn` entry, naming `__stack_chk_fail`, was the one skipped.
#[test]
fn a_dynamic_rel_entry_size_is_read_past_and_recorded() {
    let plain = facts(&whole());
    let build = |relent: Option<u64>| {
        let mut d = relocated_rel(&[], &[0, 1]);
        let field = dynsym_size_field(&d);
        dynsym_header_field(&mut d, field, 24);
        if let Some(v) = relent {
            patch_dynamic_entry(&mut d, DT_RELENT, |entry| {
                entry[8..16].copy_from_slice(&v.to_le_bytes());
            });
        }
        d
    };
    let honest = facts(&build(None));
    assert_eq!(
        honest.watched_symbols.get("__stack_chk_fail"),
        plain.watched_symbols.get("__stack_chk_fail"),
        "{:?}",
        honest.truncations
    );
    let forged = facts(&build(Some(32)));
    assert_eq!(forged.watched_symbols, honest.watched_symbols);
    let dynamic: Vec<&str> = forged
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Dynamic)
        .map(|t| t.detail.as_str())
        .collect();
    assert_eq!(
        dynamic,
        vec![
            "DT_REL: DT_RELENT is 32 where the record is 16 bytes, so it was read in 16-byte \
             records, the size the ABI fixes",
            "DT_JMPREL: DT_RELENT is 32 where the record is 16 bytes, so it was read in \
             16-byte records, the size the ABI fixes",
        ]
    );
}

/// A dynamic table cut short beside section headers of which none is `SHT_DYNSYM` leaves
/// the loader's table unestablished, so it is recorded `unread` on `symbols`: with a
/// `.dynsym` header the headers are the reading, and with none there is no reading of the
/// table a loader binds. A view that returned the
/// sections with nothing recorded on `symbols` would leave the cut unrecorded.
#[test]
fn a_cut_dynamic_table_with_no_dynsym_header_leaves_the_symbols_unread() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "canary-emitted")
        .expect("canary-emitted is in the corpus");
    for (name, build) in [
        ("cut", dynamic_cut as Build),
        ("shortened", dynamic_shortened),
    ] {
        let f = facts(&retyped_away(build(), &[".dynsym"]));
        let unread: Vec<&elf::Truncation> = symbol_records(&f)
            .into_iter()
            .filter(|t| t.kind == elf::TruncationKind::Unread)
            .collect();
        assert_eq!(unread.len(), 1, "{name}: {:?}", f.truncations);
        let gating = report::truncation_limitation(check, Some(&f))
            .unwrap_or_else(|| panic!("{name}: the symbols unread withhold canary-emitted"));
        assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
    }
}

/// The base object with a `.chard.report` section carrying `report`, and the section's
/// index in the header table.
fn with_self_report(report: &[u8]) -> (Vec<u8>, usize) {
    let mut object = base();
    object.sections.push(Section {
        name: ".chard.report",
        sh_type: SHT_PROGBITS,
        flags: 0,
        addralign: 1,
        entsize: 0,
        link: None,
        info: 0,
        content: Content::Bytes(report.to_vec()),
    });
    let index = object.sections.len();
    let mut d = object.build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
    (d, index)
}

/// A `.chard.report` listed and not held is an unread `section-names` entry naming it,
/// and withholds the runtime fortify checks that read it through `fortify_impl`.
///
/// Returned empty with no record, a cut self-report would read as a probe that reported no
/// fortify implementation, and a bare trap from `fortify-headers` or Apple would go
/// uncredited as an unexplained `indeterminate`. The entry names the section, the
/// checks that declare `section-names` are gated under `artifact-unreadable`, and the
/// elf-static checks that declare none are not.
///
/// Elf-static checks declare `section-names` too (`ret-protector-emitted`,
/// `except-table-emitted`, `separate-code`), and the gate is table-granular, so a named
/// section whose bytes are not held withholds them as well, though the list of names they
/// read is whole. The withholding is `indeterminate`, never a reading, and is counted here.
#[test]
fn a_self_report_listed_and_not_held_withholds_the_checks_that_read_it() {
    let (whole_bytes, index) = with_self_report(b"_FORTIFY_IMPL=fortify-headers\0");
    let whole_facts = facts(&whole_bytes);
    assert!(
        whole_facts
            .self_report
            .contains("_FORTIFY_IMPL=fortify-headers"),
        "the control reads the report: {:?}",
        whole_facts.self_report
    );
    assert!(
        whole_facts.truncations.is_empty(),
        "{:?}",
        whole_facts.truncations
    );

    let mut cut_bytes = whole_bytes;
    let moved = past_end(&cut_bytes);
    let field = sh_offset_field_at(&cut_bytes, index);
    cut_bytes[field].copy_from_slice(&moved);
    let cut = facts(&cut_bytes);
    assert!(cut.self_report.is_empty(), "{:?}", cut.self_report);
    let records: Vec<&elf::Truncation> = cut
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::SectionNames)
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one section, one record: {:?}",
        cut.truncations
    );
    assert_eq!(records[0].kind, elf::TruncationKind::Unread);
    assert!(
        records[0].detail.starts_with(".chard.report"),
        "the record names the section: {}",
        records[0].detail
    );

    let mut readers = 0usize;
    let mut elf_static = 0usize;
    for check in CORPUS.iter().flat_map(|p| p.checks.iter()) {
        let gated = report::truncation_limitation(check, Some(&cut));
        assert!(
            report::truncation_limitation(check, Some(&whole_facts)).is_none(),
            "{}: the whole object gates nothing",
            check.id
        );
        if check.reads().contains(&ElfTable::SectionNames) {
            let gating = gated.unwrap_or_else(|| panic!("{}: withheld", check.id));
            assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
            assert!(
                gating.reason.contains("section-names") && gating.reason.contains(".chard.report"),
                "{}: the reason names the table and the section: {}",
                check.id,
                gating.reason
            );
            readers += 1;
        } else {
            assert!(gated.is_none(), "{}: declares no section-names", check.id);
        }
        if check.channel() == Channel::ElfStatic {
            elf_static += 1;
        }
    }
    // Seven: the three runtime fortify checks and `strict-flex-arrays-enforced`, which credit a
    // trap through `fortify_impl`; `ret-protector-emitted` and `except-table-emitted`, which read
    // the section list; and `separate-code`, which names the sections it finds in the code pages
    // through the same table.
    assert_eq!(
        readers, 7,
        "the three runtime fortify checks, strict-flex-arrays-enforced, ret-protector-emitted, \
         except-table-emitted and separate-code were withheld"
    );
    assert!(elf_static > 0, "no elf-static check was examined");
}

/// An object stripped of its section-header table withholds the runtime fortify checks,
/// whose self-report is reached by section name, and leaves every elf-static check that
/// does not declare `section-names` to the tables it does declare.
///
/// The strip records `section-names` beside `symbols`: `.chard.report` cannot be looked
/// up, and read empty with no entry against that table, the trap credit in
/// `detect_fortify_runtime` fell to an `indeterminate` with no table named.
#[test]
fn a_stripped_object_withholds_the_checks_that_read_the_self_report() {
    let stripped_facts = facts(&stripped());
    assert!(
        stripped_facts.unread(&[ElfTable::SectionNames]).is_some(),
        "{:?}",
        stripped_facts.truncations
    );
    assert!(
        stripped_facts.unread(&[ElfTable::SectionHeaders]).is_none(),
        "a strip is no header escape, so no cause entry: {:?}",
        stripped_facts.truncations
    );
    let mut readers = 0usize;
    let mut elf_static = 0usize;
    for check in CORPUS.iter().flat_map(|p| p.checks.iter()) {
        let gated = report::truncation_limitation(check, Some(&stripped_facts));
        if check.reads().contains(&ElfTable::SectionNames) {
            let gating = gated
                .as_ref()
                .unwrap_or_else(|| panic!("{}: withheld", check.id));
            assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
            assert!(
                gating.reason.contains("section-names"),
                "{}: the reason names the table: {}",
                check.id,
                gating.reason
            );
            readers += 1;
        }
        if check.channel() == Channel::ElfStatic {
            elf_static += 1;
            assert_eq!(
                gated.is_some(),
                check.reads().contains(&ElfTable::Symbols)
                    || check.reads().contains(&ElfTable::SectionNames),
                "{}: gated through symbols or section names alone, reads {:?}",
                check.id,
                check.reads()
            );
        }
    }
    // Seven: the three runtime fortify checks and `strict-flex-arrays-enforced`, which credit a
    // trap through `fortify_impl`; `ret-protector-emitted` and `except-table-emitted`, which read
    // the section list; and `separate-code`, which names the sections it finds in the code pages
    // through the same table.
    assert_eq!(
        readers, 7,
        "the three runtime fortify checks, strict-flex-arrays-enforced, ret-protector-emitted, \
         except-table-emitted and separate-code were withheld"
    );
    assert!(elf_static > 0, "no elf-static check was examined");
}

/// How many objects the truncation property draws by default, and how many cuts each.
const GENERATED_OBJECTS: usize = 128;
const CUTS_PER_OBJECT: usize = 24;

/// The tables whose `unread` entry accounts for a change in each serialized fact.
///
/// Keyed on the serialized name, and checked for totality on every comparison: a field
/// added to `ElfFacts` and not listed here fails the property rather than escaping it.
/// `Header` and `ProgramHeaders` have no recording site, so a fact that only they cover
/// may never move under a cut the parse accepted. `truncations` is the record itself and
/// covered by nothing. A disagreeing `PT_GNU_STACK` pair is recorded against `GnuStack`,
/// which covers the two stack facts beside `ProgramHeaders`.
fn covering_tables(fact: &str) -> Option<&'static [ElfTable]> {
    use ElfTable::{
        Comment, DynStr, Dynamic, FunctionEntries, GnuStack, Header, Notes, ProgramHeaders,
        Relocations, SectionHeaders, SectionNames, Symbols,
    };
    Some(match fact {
        "elf_class" | "elf_data" | "elf_type" | "machine" => &[Header],
        "has_interp" | "gnu_relro" | "openbsd_nobtcfi" => &[ProgramHeaders],
        "gnu_stack_present" | "gnu_stack_executable" => &[ProgramHeaders, GnuStack],
        "has_dynamic" | "pie" | "df_1_pie" | "static_pie" | "shared_object"
        | "statically_linked" | "relro" | "bind_now" | "df_1_noopen" | "textrel" | "dt_relr"
        | "dt_debug" | "dt_soname" | "dynamic_tags" => &[Dynamic],
        "needed" | "rpath" | "runpath" => &[Dynamic, DynStr],
        "gnu_property_types" | "gnu_property_notes" | "x86_ibt" | "x86_shstk" | "aarch64_bti"
        | "aarch64_pac" | "aarch64_gcs" => &[Notes],
        "sections" => &[SectionHeaders, SectionNames],
        // The executable segments' pages come from the program headers, whose cut is a
        // parse error; the sections and their names from the other two.
        "data_in_code_pages" => &[ProgramHeaders, SectionHeaders, SectionNames],
        // The relocation sections, their targets' flags and the symbols they name; for
        // `function_references`, function symbols from `.symtab` and references from the
        // relocation sections, both found through the section-header table.
        "code_relocations" | "function_references" => &[SectionHeaders, Symbols, Relocations],
        "symbol_tables" | "symbol_count" | "watched_symbols" => &[Symbols],
        "self_report" | "recorded_command_line" => &[SectionNames],
        "comment" => &[Comment],
        // A function found through `.symtab`, its bytes through its section header.
        "function_entries" => &[SectionHeaders, Symbols, FunctionEntries],
        _ => return None,
    })
}

/// Every fact a cut changed that no `unread` entry on a covering table accounts for, with
/// each fact that moved tallied in `moved`.
///
/// A symbol table is labelled by its section name, or by `SHT_SYMTAB` and `SHT_DYNSYM`
/// where the names could not be read (`ElfFacts::symbol_tables`). The fallback is the
/// section-name cut showing through, recorded against `section-names`, and says nothing
/// about the symbols; so both spellings are compared as one here, and a symbol that moved
/// is held to `symbols` alone.
fn uncovered_changes(
    whole: &ElfFacts,
    cut: &ElfFacts,
    moved: &mut BTreeMap<String, usize>,
) -> Vec<String> {
    let as_map = |f: &ElfFacts| {
        let text = serde_json::to_string(f)
            .expect("facts serialize")
            .replace("\"SHT_SYMTAB\"", "\".symtab\"")
            .replace("\"SHT_DYNSYM\"", "\".dynsym\"");
        match serde_json::from_str(&text).expect("facts reparse") {
            serde_json::Value::Object(m) => m,
            other => panic!("facts serialize to an object, not {other}"),
        }
    };
    let (before, after) = (as_map(whole), as_map(cut));
    let keys: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut out = Vec::new();
    for key in keys {
        if key == "truncations" {
            continue;
        }
        let Some(tables) = covering_tables(key) else {
            out.push(format!(
                "{key}: a fact with no covering table in covering_tables; list it"
            ));
            continue;
        };
        if before.get(key) == after.get(key) {
            continue;
        }
        *moved.entry(key.clone()).or_insert(0) += 1;
        if cut.unread(tables).is_none() {
            out.push(format!(
                "{key} moved from {} to {} and no unread entry on {tables:?} says so",
                before
                    .get(key)
                    .map_or("absent".to_owned(), ToString::to_string),
                after
                    .get(key)
                    .map_or("absent".to_owned(), ToString::to_string),
            ));
        }
    }
    out
}

/// Every fact a cut changes is covered by a recorded truncation.
///
/// The cuts above are hand-placed, one per way a table can be lost. This is the same
/// promise over objects drawn from a seed (`tests/elf_builder/generate.rs`) and cut at
/// offsets drawn from the same seed: the file ends at the cut, as a short read or a
/// partial copy leaves it. Either the parse refuses the object, which is loud, or every
/// fact that differs from the whole object's is covered by an `unread` entry on a table
/// [`covering_tables`] names for it. A fact that moved with nothing recorded is the
/// silent absence `ElfFacts::truncations` exists to prevent, and is reported with the
/// seed that replays it, the object's spec, and the smallest cut offset of that object
/// that still breaks the property.
///
/// A property no cut can break is a property checked over nothing, so every fact that
/// moved is tallied and printed, and a default-sized run is held to [`MUST_MOVE`]: one
/// fact per recording table the cuts reach, each of which must have moved at least once.
#[test]
fn every_fact_a_cut_changes_is_covered_by_a_recorded_truncation() {
    let (seed, from_env) = seeded::seed();
    let cases = seeded::cases(GENERATED_OBJECTS);
    let mut refused = 0usize;
    let mut read = 0usize;
    let mut recorded = 0usize;
    let mut moved: BTreeMap<String, usize> = BTreeMap::new();
    // Cuts recorded by `section_text` itself, a named section listed and its bytes cut
    // off, per section: `self_report` moving under a lost name table alone would leave
    // that site unreached.
    let mut text_sites: BTreeMap<&str, usize> = BTreeMap::new();
    for case in 0..cases {
        let mut rng = seeded::Rng::for_case(seed, case);
        let spec = Spec::draw(&mut |n| rng.below(n));
        let bytes = spec.build();
        let whole_facts = facts(&bytes);
        let len = u64::try_from(bytes.len()).expect("a length fits u64");
        let mut offsets: Vec<usize> = (0..CUTS_PER_OBJECT)
            .map(|_| usize::try_from(rng.below(len)).expect("an offset fits usize"))
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        for cut in offsets {
            let Ok(elf) = elf::Elf::parse(&bytes[..cut]) else {
                refused += 1;
                continue;
            };
            let cut_facts = elf.facts();
            read += 1;
            let bad = uncovered_changes(&whole_facts, &cut_facts, &mut moved);
            if bad.is_empty() {
                recorded += cut_facts.truncations.len();
                for name in TEXT_SECTIONS {
                    if cut_facts.truncations.iter().any(|t| {
                        t.table == ElfTable::SectionNames
                            && t.detail.starts_with(&format!("{name}: "))
                    }) {
                        *text_sites.entry(name).or_insert(0) += 1;
                    }
                }
                continue;
            }
            // The smallest offset of this object that still breaks the property: a
            // shorter file is the simpler counter-example.
            let mut scratch = BTreeMap::new();
            let smallest = (0..cut)
                .find(|k| {
                    elf::Elf::parse(&bytes[..*k]).is_ok_and(|e| {
                        !uncovered_changes(&whole_facts, &e.facts(), &mut scratch).is_empty()
                    })
                })
                .unwrap_or(cut);
            let at_smallest = uncovered_changes(
                &whole_facts,
                &elf::Elf::parse(&bytes[..smallest])
                    .expect("found parseable above")
                    .facts(),
                &mut scratch,
            );
            panic!(
                "a {}-byte object cut at {cut} (smallest failing cut {smallest}) changed a \
                 fact no truncation covers ({}):\n  {}\nat the smallest cut:\n  {}\n\
                 spec: {spec:#?}",
                bytes.len(),
                seeded::replay(seed, case),
                bad.join("\n  "),
                at_smallest.join("\n  ")
            );
        }
    }
    seeded::announce(
        "truncation subset property",
        seed,
        from_env,
        cases,
        &format!(
            "{read} cuts read and held to the property, {refused} refused by the parse, \
             {recorded} truncation entries recorded over them; facts moved: {moved:?}; \
             named sections cut by section_text: {text_sites:?}"
        ),
    );
    assert!(
        read > 0 && refused > 0,
        "the cuts must include both kinds: {read} read, {refused} refused ({})",
        seeded::replay(seed, 0)
    );
    if cases >= GENERATED_OBJECTS {
        let still: Vec<&&str> = MUST_MOVE
            .iter()
            .filter(|f| !moved.contains_key(**f))
            .collect();
        assert!(
            still.is_empty(),
            "no cut moved {still:?}, so the property was never tested on them ({})",
            seeded::replay(seed, 0)
        );
        let unreached: Vec<&&str> = TEXT_SECTIONS
            .iter()
            .filter(|n| !text_sites.contains_key(**n))
            .collect();
        assert!(
            unreached.is_empty(),
            "no cut reached section_text's record for {unreached:?} ({})",
            seeded::replay(seed, 0)
        );
    }
}

/// One fact per table a tail cut can take: `.dynamic`, the dynamic string table, the
/// notes, the section names, the symbol tables and `.comment`; and the two sections read
/// as text by name, whose recording site is `section_text`, since `self_report` is what
/// the runtime fortify checks read.
const MUST_MOVE: &[&str] = &[
    "dynamic_tags",
    "needed",
    "x86_ibt",
    "sections",
    "watched_symbols",
    "comment",
    "self_report",
    "recorded_command_line",
];

/// The sections `section_text` reads by name, each of which a default run must cut with
/// its name still readable.
const TEXT_SECTIONS: &[&str] = &[".chard.report", ".GCC.command.line"];

/// A relocation section in an encoding the reader does not decode is recorded unread, and
/// the predicate withholds on its own when nothing is recorded.
///
/// Measured 2026-10-02 with clang 22.1.8 on Fedora 44 x86_64 under `-fstack-protector-strong
/// -Wa,--crel,--allow-experimental-crel`: the canaries sat in a `.crel.text` of type
/// `0x40000014`, the reader skipped it with nothing recorded, every function was listed with
/// no references, and `ssp-level-emitted` published `off` at its `none` clause. Each retyped
/// object here is that shape. Read whole, its facts carry a `relocations` truncation naming
/// the section and its type. With the truncation taken away, which is a reader that skips a
/// section the next way nobody thought of, the four functions hold no reference to the
/// externals they call and the predicate reads `unread-calls`, not `none`. Last, the same
/// section with neither a known type nor `SHF_INFO_LINK` records nothing, and the
/// predicate's clause is what withholds it.
#[test]
fn relocations_in_an_undecoded_encoding_withhold_ssp_level_emitted() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "ssp-level-emitted")
        .expect("ssp-level-emitted is in the corpus");
    let macros = BTreeMap::new();
    let bare: Vec<String> = chard::predicate::elf_static::SSP_FUNCTIONS
        .iter()
        .map(|f| format!("{f}:"))
        .collect();
    let cases: [(Build, bool, &str); 3] = [
        (relocations_crel, true, "type 0x40000014"),
        (relocations_unknown_info_link, true, "type 0x80000000"),
        (|| relocations_retyped(SHT_LOUSER, 0), false, ""),
    ];
    let mut examined = 0usize;
    for (build, recorded, says) in cases {
        let mut cut = facts(&build());
        assert_eq!(cut.function_references.as_ref(), Some(&bare), "{says}");
        let records: Vec<&elf::Truncation> = cut
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::Relocations)
            .collect();
        if recorded {
            assert_eq!(records.len(), 1, "{records:?}");
            assert!(
                records[0].detail.starts_with(".rela.text: ") && records[0].detail.contains(says),
                "the record names the section and its type: {}",
                records[0].detail
            );
            let gating = report::truncation_limitation(check, Some(&cut))
                .expect("an undecoded relocation section withholds ssp-level-emitted");
            assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
        } else {
            assert!(cut.truncations.is_empty(), "{:?}", cut.truncations);
        }
        cut.truncations.clear();
        let decoded = check.decode(&evidence(&macros, &cut));
        assert_eq!(decoded.detection.outcome, Outcome::Indeterminate, "{says}");
        assert_eq!(
            decoded.proof.as_ref().map(|p| p.clause.as_str()),
            Some("unread-calls"),
            "{says}"
        );
        examined += 1;
    }
    assert_eq!(examined, 3, "every retyped object was examined");
}

/// The relocatable object with its three canary references taken out of `.rela.text` and
/// put in a code section of their own, `.text.part`, which holds no function symbol: the
/// shape clang gives each canaried function under `-fbasic-block-sections=all`. With
/// `code` false the section is data, which holds no reference the field reads.
fn canary_in_a_section_of_its_own(code: bool) -> Vec<u8> {
    canary_in_a_section_of_its_own_as(code, None)
}

/// [`canary_in_a_section_of_its_own`], with `.rela.text.part` retyped to `retype`'s
/// section type and flags when it is given, the entries left as they are.
fn canary_in_a_section_of_its_own_as(code: bool, retype: Option<(u32, u64)>) -> Vec<u8> {
    let mut object = elf_builder::relocatable_functions();
    let mut moved = Vec::new();
    for s in &mut object.sections {
        if let (".rela.text", Content::Rela(entries)) = (s.name, &mut s.content) {
            let (canary, calls): (Vec<_>, Vec<_>) = entries
                .drain(..)
                .partition(|r| r.symbol == "__stack_chk_fail");
            *entries = calls;
            moved = canary;
        }
    }
    assert_eq!(moved.len(), 3, "three canary references were moved");
    let part = u32::try_from(object.sections.len() + 1).expect("a small index");
    let flags = if code { 0x2 | 0x4 } else { 0x2 }; // SHF_ALLOC, SHF_EXECINSTR
    object.sections.push(Section {
        name: ".text.part",
        sh_type: SHT_PROGBITS,
        flags,
        addralign: 1,
        entsize: 0,
        link: None,
        info: 0,
        content: Content::Bytes(vec![0xc3; 64]),
    });
    let rela = object
        .sections
        .iter()
        .find(|s| s.name == ".rela.text")
        .expect("the relocatable object has .rela.text");
    let (sh_type, flags) = retype.unwrap_or((rela.sh_type, rela.flags));
    object.sections.push(Section {
        name: ".rela.text.part",
        sh_type,
        flags,
        addralign: rela.addralign,
        entsize: rela.entsize,
        link: Some(".symtab"),
        info: part,
        content: Content::Rela(moved),
    });
    object.build()
}

/// The relocatable object with every function's size cut to 8 bytes: each function's call
/// stays inside its range and each canary reference, 8 bytes past the function's start or
/// more, falls in `.text` outside every range.
fn canary_outside_every_range() -> Vec<u8> {
    let mut object = elf_builder::relocatable_functions();
    for s in &mut object.sections {
        if let Content::ObjectSymbols { functions, .. } = &mut s.content {
            for f in functions.iter_mut() {
                f.size = 8;
            }
        }
    }
    object.build()
}

/// A canary reference the reader cannot place in a function withholds `ssp-level-emitted`.
///
/// Measured 2026-10-02 with clang 22.1.8 on Fedora 44 x86_64 under `-O2
/// -fstack-protector-strong -fbasic-block-sections=all`: each canaried function's
/// `__stack_chk_fail` call sat in a code section whose only symbol is a `NOTYPE`
/// `<fn>.__part.N`, the reader skipped the section because no function's range was in it,
/// the calls the `unread-calls` clause reads stayed in the functions' own ranges, and the
/// `none` clause published `off`. Each object here is one way a reference lands outside
/// every range: a code section with no function, and code past a function's end. Both list
/// `?:__stack_chk_fail` and read `unattributed-canary`, with nothing recorded unread. The
/// control is the same section as data: a data reference is no canary, nothing is listed
/// for it, and the reading is the `none` row, which is what the probe's object would read
/// if it held no canary call at all.
#[test]
fn a_canary_reference_outside_every_function_withholds_ssp_level_emitted() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "ssp-level-emitted")
        .expect("ssp-level-emitted is in the corpus");
    let macros = BTreeMap::new();
    let calls = [
        "ssp_any:ssp_use",
        "ssp_addr_taken:ssp_escape",
        "ssp_char_array:ssp_escape",
        "ssp_alloca:ssp_escape",
    ];
    let cases: [(Build, bool, Outcome, &str); 3] = [
        (
            || canary_in_a_section_of_its_own(true),
            true,
            Outcome::Indeterminate,
            "unattributed-canary",
        ),
        (
            canary_outside_every_range,
            true,
            Outcome::Indeterminate,
            "unattributed-canary",
        ),
        (
            || canary_in_a_section_of_its_own(false),
            false,
            Outcome::Absent,
            "none",
        ),
    ];
    let mut examined = 0usize;
    for (build, listed, outcome, at) in cases {
        let read = facts(&build());
        assert!(read.truncations.is_empty(), "{:?}", read.truncations);
        let refs = read
            .function_references
            .as_ref()
            .expect("a relocatable object with a symbol table");
        for call in calls {
            assert!(refs.iter().any(|r| r == call), "{call} in {refs:?}");
        }
        assert!(
            !refs
                .iter()
                .any(|r| !r.starts_with("?:") && r.ends_with(":__stack_chk_fail")),
            "no function is credited with the canary: {refs:?}"
        );
        assert_eq!(
            refs.iter().any(|r| r == "?:__stack_chk_fail"),
            listed,
            "{refs:?}"
        );
        let decoded = check.decode(&evidence(&macros, &read));
        assert_eq!(decoded.detection.outcome, outcome, "{at}");
        assert_eq!(
            decoded.proof.as_ref().map(|p| p.clause.as_str()),
            Some(at),
            "{refs:?}"
        );
        examined += 1;
    }
    assert_eq!(examined, 3, "every moved reference was examined");
}

/// A relocation section in an encoding the reader does not decode is recorded unread when
/// its target is code that holds no function, as well as when its target holds one.
///
/// `relocations_in_an_undecoded_encoding_withhold_ssp_level_emitted` retypes `.rela.text`,
/// whose target holds every function, so it reaches the reader's first condition alone.
/// Here the retyped section is `.rela.text.part`, the canary references moved into a code
/// section with no function symbol (the `-fbasic-block-sections=all` shape), retyped to
/// `SHT_CREL` and to a user-range type carrying `SHF_INFO_LINK`. Unrecorded, the moved
/// references are read by nobody, the four functions keep their calls, and the predicate
/// reads the `none` row: an `off` over references it never read, which the test shows by
/// taking the record away. Each is recorded against `relocations` and withholds the check. The control is the same retype with `.text.part`
/// as data, which holds no reference the field reads: nothing is recorded.
#[test]
fn undecoded_relocations_into_code_outside_every_function_withhold_ssp_level_emitted() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "ssp-level-emitted")
        .expect("ssp-level-emitted is in the corpus");
    let macros = BTreeMap::new();
    let cases: [(bool, u32, &str); 4] = [
        (true, SHT_CREL, "type 0x40000014"),
        (true, SHT_LOUSER, "type 0x80000000"),
        (false, SHT_CREL, ""),
        (false, SHT_LOUSER, ""),
    ];
    let mut examined = 0usize;
    for (code, sh_type, says) in cases {
        let read = facts(&canary_in_a_section_of_its_own_as(
            code,
            Some((sh_type, SHF_INFO_LINK)),
        ));
        let refs = read
            .function_references
            .as_ref()
            .expect("a relocatable object with a symbol table");
        assert!(
            !refs.iter().any(|r| r.ends_with(":__stack_chk_fail")),
            "the undecoded section's references were read: {refs:?}"
        );
        let records: Vec<&elf::Truncation> = read
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::Relocations)
            .collect();
        if code {
            assert_eq!(records.len(), 1, "{:?}", read.truncations);
            assert!(
                records[0].detail.starts_with(".rela.text.part: ")
                    && records[0].detail.contains(says),
                "the record names the section and its type: {}",
                records[0].detail
            );
            let gating = report::truncation_limitation(check, Some(&read))
                .expect("an undecoded relocation section into code withholds the check");
            assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
            let decoded = check.decode(&evidence(&macros, &read));
            assert_eq!(decoded.detection.outcome, Outcome::Indeterminate, "{says}");
        } else {
            assert!(read.truncations.is_empty(), "{:?}", read.truncations);
        }
        let mut unrecorded = read.clone();
        unrecorded.truncations.clear();
        let decoded = check.decode(&evidence(&macros, &unrecorded));
        assert_eq!(decoded.detection.outcome, Outcome::Absent, "{says}");
        assert_eq!(
            decoded.proof.as_ref().map(|p| p.clause.as_str()),
            Some("none"),
            "without the record the predicate reads the none row: {refs:?}"
        );
        examined += 1;
    }
    assert_eq!(examined, 4, "every retyped part was examined");
}

// --- `elf::entry`'s address paths and refusals ------------------------------------
//
// The cuts above reach `elf::entry` through one linked ELF64 object, so
// its `ET_REL` mapping, its ELF32 field offsets and most of its refusals would run in no test
// on a host that cannot compile the probe for x86. The objects below are the builder's in
// both widths and both object types, with the three functions at their own offsets in one
// section and every symbol field the builder leaves at zero patched after the build.

/// Where each of `elf::entry`'s functions begins in the section that holds them.
const ENTRY_STRIDE: u64 = 16;
/// `SHT_NOBITS`, which the builder has no constant for.
const SHT_NOBITS: u32 = 8;

/// One of the four objects: width and type.
#[derive(Clone, Copy, Debug)]
struct Shape {
    class64: bool,
    relocatable: bool,
}

const SHAPES: [Shape; 4] = [
    Shape {
        class64: true,
        relocatable: false,
    },
    Shape {
        class64: true,
        relocatable: true,
    },
    Shape {
        class64: false,
        relocatable: false,
    },
    Shape {
        class64: false,
        relocatable: true,
    },
];

impl Shape {
    fn machine(self) -> u16 {
        if self.class64 {
            elf_builder::EM_X86_64
        } else {
            elf_builder::EM_386
        }
    }

    /// The landing pad of this shape's machine, as `elf::entry` spells it.
    fn pad(self) -> [u8; 4] {
        [0xf3, 0x0f, 0x1e, if self.class64 { 0xfa } else { 0xfb }]
    }

    /// The object, before its symbols are patched: the functions each `prefix` then `ret`,
    /// at `ENTRY_STRIDE` apart in `ENTRY_SECTION`, and `extra` more definitions of the
    /// first function. A relocatable keeps the builder's nonzero `sh_addr` for the section,
    /// so a reader that mapped an `ET_REL` `st_value` through it reads nothing.
    fn object(self, prefixes: [[u8; 4]; 3], extra: usize) -> Object {
        let mut object = if self.relocatable {
            let mut o = elf_builder::relocatable();
            o.class64 = self.class64;
            o.e_machine = self.machine();
            // The note's descriptor is padded for ELF64; no property is read here.
            o.sections.retain(|s| s.name != ".note.gnu.property");
            for s in &mut o.sections {
                if s.name == ".symtab" {
                    s.entsize = if self.class64 { 24 } else { 16 };
                }
            }
            o
        } else {
            let mut l = linked_default();
            l.class64 = self.class64;
            l.e_machine = self.machine();
            if !self.class64 {
                l.e_type = elf_builder::ET_DYN;
                l.property = None;
            }
            l.object()
        };
        let mut code = Vec::new();
        for prefix in prefixes {
            let start = code.len();
            code.extend_from_slice(&prefix);
            code.push(0xc3);
            code.resize(start + usize::try_from(ENTRY_STRIDE).expect("fits"), 0xcc);
        }
        object.sections.push(Section {
            name: ENTRY_SECTION,
            sh_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            addralign: 16,
            entsize: 0,
            link: None,
            info: 0,
            content: Content::Bytes(code),
        });
        let names = elf::entry::ENTRY_FUNCTIONS
            .iter()
            .copied()
            .chain(std::iter::repeat_n(elf::entry::ENTRY_FUNCTIONS[0], extra));
        for name in names {
            for section in &mut object.sections {
                match (section.name, &mut section.content) {
                    (".symtab", Content::Symbols(syms)) => syms.push(Symbol {
                        name,
                        defined_in: Some(ENTRY_SECTION),
                        st_other: 0,
                    }),
                    (".strtab", Content::Strings(strings)) if !strings.contains(&name) => {
                        strings.push(name);
                    }
                    _ => {}
                }
            }
        }
        object
    }
}

/// A little-endian field of `len` bytes at `at`.
fn get(d: &[u8], at: usize, len: usize) -> u64 {
    let mut v = [0u8; 8];
    v[..len].copy_from_slice(&d[at..at + len]);
    u64::from_le_bytes(v)
}

fn put(d: &mut [u8], at: usize, len: usize, value: u64) {
    d[at..at + len].copy_from_slice(&value.to_le_bytes()[..len]);
}

/// A built object's section and symbol fields, in its width, by offset into the file.
struct Fields {
    class64: bool,
    /// The section-header table's file offset.
    shoff: usize,
}

impl Fields {
    fn of(d: &[u8], class64: bool) -> Self {
        let shoff = if class64 {
            get(d, 40, 8)
        } else {
            get(d, 32, 4)
        };
        Self {
            class64,
            shoff: usize::try_from(shoff).expect("fits"),
        }
    }

    fn word(&self) -> usize {
        if self.class64 { 8 } else { 4 }
    }

    /// `(offset, len)` of a section header's field: `sh_type`, `sh_flags`, `sh_addr`,
    /// `sh_offset`, `sh_size` or `sh_link`.
    fn sh(&self, index: usize, field: &str) -> (usize, usize) {
        let (size, w) = (if self.class64 { 64 } else { 40 }, self.word());
        let within = match field {
            "type" => return (self.shoff + index * size + 4, 4),
            "flags" => 8,
            "addr" => 8 + w,
            "offset" => 8 + 2 * w,
            "size" => 8 + 3 * w,
            "link" => return (self.shoff + index * size + 8 + 4 * w, 4),
            other => panic!("no field {other}"),
        };
        (self.shoff + index * size + within, w)
    }

    fn sh_get(&self, d: &[u8], index: usize, field: &str) -> u64 {
        let (at, len) = self.sh(index, field);
        get(d, at, len)
    }

    fn sh_put(&self, d: &mut [u8], index: usize, field: &str, value: u64) {
        let (at, len) = self.sh(index, field);
        put(d, at, len, value);
    }

    /// `(offset, len)` of a symbol's `st_info`, `st_shndx`, `st_value` or `st_size`, in the
    /// layout `elf::entry::entry_symbol` reads.
    fn st(&self, entry: usize, field: &str) -> (usize, usize) {
        let (info, shndx, value, size, w) = if self.class64 {
            (4, 6, 8, 16, 8)
        } else {
            (12, 14, 4, 8, 4)
        };
        match field {
            "info" => (entry + info, 1),
            "shndx" => (entry + shndx, 2),
            "value" => (entry + value, w),
            "size" => (entry + size, w),
            other => panic!("no field {other}"),
        }
    }

    /// The file offset of every `.symtab` entry naming `name`.
    fn entries(&self, d: &[u8], symtab: usize, name: &str) -> Vec<usize> {
        let step = if self.class64 { 24 } else { 16 };
        let offset = usize::try_from(self.sh_get(d, symtab, "offset")).expect("fits");
        let size = usize::try_from(self.sh_get(d, symtab, "size")).expect("fits");
        let strtab = usize::try_from(self.sh_get(d, symtab, "link")).expect("fits");
        let strings = usize::try_from(self.sh_get(d, strtab, "offset")).expect("fits");
        (offset..offset + size)
            .step_by(step)
            .filter(|&entry| {
                let at = strings + usize::try_from(get(d, entry, 4)).expect("fits");
                d[at..].split(|b| *b == 0).next() == Some(name.as_bytes())
            })
            .collect()
    }
}

/// A built object of `shape`, its symbols patched to the functions' own offsets and sizes,
/// and the field map and indices a case patches further.
struct Built {
    d: Vec<u8>,
    fields: Fields,
    symtab: usize,
    code: usize,
}

impl Built {
    fn new(shape: Shape, prefixes: [[u8; 4]; 3], extra: usize) -> Self {
        let object = shape.object(prefixes, extra);
        let index = |name: &str| {
            object
                .sections
                .iter()
                .position(|s| s.name == name)
                .expect("the object has the section")
                + 1
        };
        let (symtab, code) = (index(".symtab"), index(ENTRY_SECTION));
        let mut d = object.build();
        let fields = Fields::of(&d, shape.class64);
        let base = if shape.relocatable {
            0
        } else {
            fields.sh_get(&d, code, "addr")
        };
        assert_ne!(
            fields.sh_get(&d, code, "addr"),
            0,
            "the section has an address an ET_REL mapping must not use"
        );
        let mut patched = 0;
        for (i, name) in elf::entry::ENTRY_FUNCTIONS.iter().enumerate() {
            for entry in fields.entries(&d, symtab, name) {
                let (at, len) = fields.st(entry, "value");
                put(
                    &mut d,
                    at,
                    len,
                    base + ENTRY_STRIDE * u64::try_from(i).expect("fits"),
                );
                let (at, len) = fields.st(entry, "size");
                put(&mut d, at, len, ENTRY_STRIDE);
                patched += 1;
            }
        }
        assert_eq!(patched, 3 + extra, "every definition was patched");
        Self {
            d,
            fields,
            symtab,
            code,
        }
    }

    /// Set one field of the first function's symbol (every definition of it).
    fn set_first(&mut self, field: &str, value: u64) {
        for entry in self
            .fields
            .entries(&self.d, self.symtab, elf::entry::ENTRY_FUNCTIONS[0])
        {
            let (at, len) = self.fields.st(entry, field);
            put(&mut self.d, at, len, value);
        }
    }
}

fn cet_endbr_check() -> &'static Check {
    CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "cet-endbr-emitted")
        .expect("cet-endbr-emitted is in the corpus")
}

/// Each function's first four bytes are read from its own offset, in either width and
/// either object type, with nothing recorded against `function-entries`.
///
/// The prefixes differ, so a reader that took one function's bytes for another's, or
/// mapped an `ET_REL` `st_value` through `sh_addr`, or read an ELF32 symbol at ELF64
/// offsets, reads a different list or records a refusal. A function of `st_size` 2 reads
/// two bytes.
#[test]
fn elf_entry_reads_each_function_at_its_own_offset_in_every_width_and_type() {
    let prefixes = [
        [0xf3, 0x0f, 0x1e, 0xfa],
        [0x55, 0x48, 0x89, 0xe5],
        [0x31, 0xc0, 0x90, 0x90],
    ];
    let mut examined = 0usize;
    for shape in SHAPES {
        let built = Built::new(shape, prefixes, 0);
        let read = facts(&built.d);
        assert_eq!(
            read.function_entries,
            vec![
                "chard_ibt_target_a=f30f1efa".to_owned(),
                "chard_ibt_target_b=554889e5".to_owned(),
                "chard_ibt_target_c=31c09090".to_owned(),
            ],
            "{shape:?}"
        );
        assert!(
            !read
                .truncations
                .iter()
                .any(|t| t.table == ElfTable::FunctionEntries),
            "{shape:?}: {:?}",
            read.truncations
        );

        let mut short = built;
        short.set_first("size", 2);
        assert_eq!(
            facts(&short.d).function_entries.first().map(String::as_str),
            Some("chard_ibt_target_a=f30f"),
            "{shape:?}: st_size 2 reads two bytes"
        );
        examined += 1;
    }
    assert_eq!(examined, SHAPES.len(), "every shape was examined");
}

/// The check reads its own machine's landing pad at every function as present, a
/// function without one as absent, and the other width's landing pad as indeterminate, in
/// each width and type: the synthetic half of the control triple, over the reader's every
/// address path.
#[test]
fn cet_endbr_emitted_reads_each_shape_through_the_reader() {
    let check = cet_endbr_check();
    let macros = BTreeMap::new();
    let mut examined = 0usize;
    for shape in SHAPES {
        let other = Shape {
            class64: !shape.class64,
            ..shape
        }
        .pad();
        let cases = [
            ([shape.pad(); 3], Outcome::Present),
            ([[0x55, 0x48, 0x89, 0xe5]; 3], Outcome::Absent),
            (
                [shape.pad(), shape.pad(), [0x55, 0x48, 0x89, 0xe5]],
                Outcome::Indeterminate,
            ),
            ([other; 3], Outcome::Indeterminate),
        ];
        for (prefixes, expected) in cases {
            let read = facts(&Built::new(shape, prefixes, 0).d);
            let detection = check.decode(&evidence(&macros, &read)).detection;
            assert_eq!(
                detection.outcome, expected,
                "{shape:?} {prefixes:x?}: {:?}",
                read.function_entries
            );
            assert!(report::truncation_limitation(check, Some(&read)).is_none());
            examined += 1;
        }
    }
    assert_eq!(examined, SHAPES.len() * 4, "every case was examined");
}

/// A patch to a built object, given its shape.
type Patch = fn(&mut Built, Shape);

/// Each refusal `elf::entry` can make: a name, how many extra definitions of the first
/// function the object carries, the patch, and what the record says.
fn refusals() -> [(&'static str, usize, Patch, &'static str); 11] {
    [
        (
            "two definitions",
            1,
            |_, _| {},
            "2 defined functions carry the name",
        ),
        (
            "st_size 0",
            0,
            |b, _| b.set_first("size", 0),
            "st_size is 0",
        ),
        (
            "SHN_ABS",
            0,
            |b, _| b.set_first("shndx", 0xfff1),
            "st_shndx 0xfff1 is a reserved index",
        ),
        (
            "SHN_COMMON",
            0,
            |b, _| b.set_first("shndx", 0xfff2),
            "st_shndx 0xfff2 is a reserved index",
        ),
        (
            "st_shndx past the table",
            0,
            |b, _| b.set_first("shndx", 200),
            "st_shndx 200 is past the section-header table",
        ),
        (
            "SHT_NOBITS",
            0,
            |b, _| {
                let code = b.code;
                b.fields
                    .sh_put(&mut b.d, code, "type", u64::from(SHT_NOBITS));
            },
            "holds no instructions in the file",
        ),
        (
            "no SHF_EXECINSTR",
            0,
            |b, _| {
                let code = b.code;
                b.fields.sh_put(&mut b.d, code, "flags", SHF_ALLOC);
            },
            "holds no instructions in the file",
        ),
        (
            "st_value below the section",
            0,
            |b, shape| {
                // An `ET_REL` `st_value` is an offset and cannot fall below its section;
                // the one value that falls outside it is one whose end overflows.
                let below = if shape.relocatable {
                    if shape.class64 { u64::MAX } else { 0 }
                } else {
                    b.fields.sh_get(&b.d, b.code, "addr") - 1
                };
                b.set_first("value", below);
            },
            "",
        ),
        (
            "st_value past the section",
            0,
            |b, shape| {
                let base = if shape.relocatable {
                    0
                } else {
                    b.fields.sh_get(&b.d, b.code, "addr")
                };
                b.set_first("value", base + 3 * ENTRY_STRIDE - 2);
            },
            "runs past section",
        ),
        (
            "section bytes past the file",
            0,
            |b, _| {
                let code = b.code;
                let past = u64::try_from(b.d.len()).expect("fits") + 0x100;
                b.fields.sh_put(&mut b.d, code, "offset", past);
            },
            "its bytes lie past the end of the file",
        ),
        (
            "symbol entry unreadable",
            0,
            |b, _| {
                // `.symtab` moved to the last eight bytes: its first entry cannot be read
                // whole, and the walk stops before any function is found.
                let symtab = b.symtab;
                let at = u64::try_from(b.d.len() - 8).expect("fits");
                b.fields.sh_put(&mut b.d, symtab, "offset", at);
            },
            "not found before the symbol walk stopped",
        ),
    ]
}

/// Every refusal in `elf::entry` records the first function under `function-entries` with
/// its reason, drops it from the fact, and withholds `cet-endbr-emitted`, in each width and
/// type the refusal can arise in.
#[test]
fn every_elf_entry_refusal_is_recorded_and_withholds_the_check() {
    let cases = refusals();
    let check = cet_endbr_check();
    let macros = BTreeMap::new();
    let first = elf::entry::ENTRY_FUNCTIONS[0];
    let mut examined = 0usize;
    for shape in SHAPES {
        for (name, extra, patch, says) in cases {
            let says = match (name, shape.relocatable, shape.class64) {
                // ELF32 `ET_REL` has no value outside its section that `elf::entry` can be
                // handed below it: 0 is the first byte, and a 32-bit value cannot
                // overflow a 64-bit sum.
                ("st_value below the section", true, false) => continue,
                ("st_value below the section", _, _) => "does not fall in section",
                _ => says,
            };
            let mut built = Built::new(shape, [shape.pad(); 3], extra);
            patch(&mut built, shape);
            let read = facts(&built.d);
            let records: Vec<&elf::Truncation> = read
                .truncations
                .iter()
                .filter(|t| t.table == ElfTable::FunctionEntries)
                .filter(|t| t.detail.starts_with(&format!("{first}: ")))
                .collect();
            assert!(
                records.len() == 1
                    && records[0].kind == elf::TruncationKind::Unread
                    && records[0].detail.contains(says),
                "{shape:?} {name}: one unread record saying {says:?}: {:?}",
                read.truncations
            );
            assert!(
                !read
                    .function_entries
                    .iter()
                    .any(|e| e.starts_with(&format!("{first}="))),
                "{shape:?} {name}: {:?}",
                read.function_entries
            );
            let detection = check.decode(&evidence(&macros, &read)).detection;
            assert_eq!(
                detection.outcome,
                Outcome::Indeterminate,
                "{shape:?} {name}"
            );
            let gating = report::truncation_limitation(check, Some(&read))
                .unwrap_or_else(|| panic!("{shape:?} {name}: the check is withheld"));
            assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
            examined += 1;
        }
    }
    assert_eq!(
        examined,
        SHAPES.len() * cases.len() - 1,
        "every refusal was examined in every shape it can arise in"
    );
}

/// The shape of a gcc 16.1.1 `-z now` PIE (2026-10-09): `DF_1_NOW` ahead of the real
/// `DF_1_PIE`, no `DT_FLAGS`. `ld.so` keeps the last entry of a repeated tag, so the loader
/// binds lazily, `DF_1_PIE` is set and `DF_1_NOW` is not; a first-match reader would publish
/// `bind_now: true` and `df_1_pie: false`. The value is the loader's, and the repeat is
/// recorded unread, which withholds the checks that read `.dynamic`.
#[test]
fn a_repeated_flags_tag_reads_as_the_loader_reads_it_and_is_recorded() {
    let f = facts(&repeated_flags1());
    assert_eq!(
        f.bind_now,
        Some(false),
        "the last DT_FLAGS_1 is PIE alone: {f:?}"
    );
    assert!(f.df_1_pie, "the last DT_FLAGS_1 carries DF_1_PIE: {f:?}");
    let records: Vec<&elf::Truncation> = f
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Dynamic)
        .collect();
    assert_eq!(records.len(), 1, "one repeat, one record: {records:?}");
    assert_eq!(records[0].kind, elf::TruncationKind::Unread);
    assert!(
        records[0].detail.contains("DT_FLAGS_1"),
        "the record names the tag: {records:?}"
    );
}

/// Entries past `DT_NULL` are not read: `ld.so` and musl stop there (experiment recorded with
/// the change). The base object ends `.dynamic` with `DT_FLAGS_1` (`DF_1_NOW`) and `DT_NULL`;
/// the two are exchanged, so the flag lies behind the terminator and the object binds lazily.
#[test]
fn entries_after_dt_null_are_not_read() {
    let mut d = whole();
    let before = facts(&d);
    assert_eq!(before.bind_now, Some(true), "the base object binds now");
    let seg = EHDR_SIZE + segment_index(PT_DYNAMIC) * PHDR_SIZE;
    let off = usize::try_from(le_u64(&d[seg + 8..seg + 16])).expect("fits");
    let size = usize::try_from(le_u64(&d[seg + 32..seg + 40])).expect("fits");
    let last = off + size - 16;
    assert_eq!(
        le_u64(&d[last..last + 8]),
        0,
        "DT_NULL ends the table the builder writes"
    );
    assert_eq!(
        le_u64(&d[last - 16..last - 8]),
        u64::try_from(DT_FLAGS_1).expect("positive"),
        "DT_FLAGS_1 is the entry before it"
    );
    let flags1: [u8; 16] = d[last - 16..last].try_into().expect("sixteen bytes");
    let null: [u8; 16] = d[last..last + 16].try_into().expect("sixteen bytes");
    d[last - 16..last].copy_from_slice(&null);
    d[last..last + 16].copy_from_slice(&flags1);
    let after = facts(&d);
    assert_eq!(
        after.bind_now,
        Some(false),
        "DF_1_NOW behind DT_NULL is not read"
    );
    assert!(
        after
            .truncations
            .iter()
            .all(|t| t.table != ElfTable::Dynamic),
        "a table that ends at DT_NULL is whole: {:?}",
        after.truncations
    );
}

/// The base object with a second `.dynamic` table, `.dynamic.second`, naming only
/// `libm.so.6`, under a `PT_DYNAMIC` of its own placed after the original (`second_last`)
/// or before it.
fn two_dynamic_tables(second_last: bool) -> Vec<u8> {
    let mut object = base();
    object.sections.push(Section {
        name: ".dynamic.second",
        sh_type: SHT_DYNAMIC,
        flags: SHF_ALLOC | SHF_WRITE,
        addralign: 8,
        entsize: 16,
        link: Some(".dynstr"),
        info: 0,
        content: Content::Dynamic(vec![
            (DT_NEEDED, DynValue::StrOff(".dynstr", "libm.so.6")),
            (DT_STRTAB, DynValue::AddrOf(".dynstr")),
            (DT_STRSZ, DynValue::SizeOf(".dynstr")),
            (DT_SYMTAB, DynValue::AddrOf(".dynsym")),
        ]),
    });
    let at = object
        .segments
        .iter()
        .position(|g| g.p_type == PT_DYNAMIC)
        .expect("the base object has a PT_DYNAMIC");
    let second = Segment {
        p_type: PT_DYNAMIC,
        flags: PF_R | PF_W,
        align: 8,
        covers: Covers::Section(".dynamic.second"),
    };
    object
        .segments
        .insert(if second_last { at + 1 } else { at }, second);
    let mut d = object.build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
    d
}

/// A second `PT_DYNAMIC`: `ld.so` and musl take the last, so the earlier is not walked, and
/// the disagreement is recorded unread because other loaders were not run. The two tables
/// differ, and both header orders are read, so the test tells the last from the first and
/// from the two read together.
#[test]
fn a_second_pt_dynamic_is_the_one_the_loader_reads_and_is_recorded() {
    let whole_facts = facts(&whole());
    assert_ne!(whole_facts.needed, vec!["libm.so.6".to_owned()]);
    for (second_last, needed) in [
        (true, vec!["libm.so.6".to_owned()]),
        (false, whole_facts.needed.clone()),
    ] {
        let f = facts(&two_dynamic_tables(second_last));
        assert_eq!(
            f.needed, needed,
            "second last: {second_last}: {:?}",
            f.truncations
        );
        let records: Vec<&elf::Truncation> = f
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::Dynamic)
            .collect();
        assert_eq!(records.len(), 1, "one record: {records:?}");
        assert_eq!(records[0].kind, elf::TruncationKind::Unread);
        assert!(records[0].detail.contains("PT_DYNAMIC"), "{records:?}");
    }
}

/// A repeated `DT_STRTAB`: the loader keeps the last entry, so the names are read through
/// the table the last one names, here a copy of `.dynstr` with `libm` spelt `libz`, and the
/// repeat is recorded. Reading the first entry while the record says the last was read
/// published the other table's names.
#[test]
fn a_repeated_strtab_tag_reads_the_names_through_the_last() {
    let whole_bytes = whole();
    let field = sh_offset_field(&whole_bytes, ".dynstr");
    let off = usize::try_from(le_u64(&whole_bytes[field.clone()])).expect("fits");
    let len = usize::try_from(le_u64(&whole_bytes[field.end..field.end + 8])).expect("fits");
    let forged: Vec<u8> = String::from_utf8(whole_bytes[off..off + len].to_vec())
        .expect("ASCII names")
        .replace("libm.so.6", "libz.so.6")
        .into_bytes();
    let mut object = base_with(|linked| {
        linked
            .extra_dynamic
            .push((DT_STRTAB, DynValue::AddrOf(".dynstr.forged")));
    });
    object.sections.push(Section {
        name: ".dynstr.forged",
        sh_type: SHT_PROGBITS,
        flags: SHF_ALLOC,
        addralign: 1,
        entsize: 0,
        link: None,
        info: 0,
        content: Content::Bytes(forged),
    });
    let mut d = object.build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
    let f = facts(&d);
    let whole_facts = facts(&whole_bytes);
    assert!(whole_facts.needed.contains(&"libm.so.6".to_owned()));
    let expected: Vec<String> = whole_facts
        .needed
        .iter()
        .map(|n| n.replace("libm.so.6", "libz.so.6"))
        .collect();
    assert_eq!(f.needed, expected, "{:?}", f.truncations);
    assert!(
        f.truncations.iter().any(|t| t.table == ElfTable::Dynamic
            && t.kind == elf::TruncationKind::Unread
            && t.detail.contains("DT_STRTAB appears 2 times")),
        "{:?}",
        f.truncations
    );
}

/// A repeated `DT_STRSZ` bounds the names by the last entry: one of 1 holds no name past
/// the leading NUL, so `needed` is not read whole and says so, where the first entry read
/// them all.
#[test]
fn a_repeated_strsz_tag_bounds_the_names_by_the_last() {
    let f = facts(&{
        let mut d = base_with(|linked| {
            linked.extra_dynamic.push((DT_STRSZ, DynValue::Const(1)));
        })
        .build();
        size_probe_function(&mut d);
        size_entry_functions(&mut d);
        d
    });
    let whole_facts = facts(&whole());
    assert_ne!(f.needed, whole_facts.needed, "{:?}", f.truncations);
    assert!(
        f.truncations
            .iter()
            .any(|t| t.table == ElfTable::DynStr && t.kind == elf::TruncationKind::Unread),
        "{:?}",
        f.truncations
    );
}

// ---------------------------------------------------------------------------------------
// The dynamic symbol table, repeated rpath tags and several SHT_DYNAMIC sections.
// ---------------------------------------------------------------------------------------

const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const SHT_HASH: u32 = 5;
const SHT_GNU_HASH: u32 = 0x6fff_fff6;

fn le32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// A `DT_GNU_HASH` table over `.dynsym`'s four entries (the null symbol and three): one
/// bucket naming symbol 1, `symoffset` 1, a one-word bloom filter, and a chain that ends
/// at symbol 3.
fn gnu_hash_of_four() -> Vec<u8> {
    let mut b = le32(&[1, 1, 1, 6]);
    b.extend_from_slice(&[0; 8]);
    b.extend(le32(&[1, 0, 0, 1]));
    b
}

/// A `DT_HASH` table naming `nchain` symbols.
fn sysv_hash_of(nchain: u32) -> Vec<u8> {
    le32(&[1, nchain, 0, 0, 0, 0])
}

/// The base object with the named hash tables, each a section a `DT_HASH` or `DT_GNU_HASH`
/// entry addresses. `forge` edits the object before it is laid out.
fn hashed(gnu: Option<Vec<u8>>, sysv: Option<Vec<u8>>, forge: impl FnOnce(&mut Object)) -> Vec<u8> {
    let (has_gnu, has_sysv) = (gnu.is_some(), sysv.is_some());
    let mut object = base_with(|linked| {
        if has_sysv {
            linked
                .extra_dynamic
                .push((DT_HASH, DynValue::AddrOf(".hash")));
        }
        if has_gnu {
            linked
                .extra_dynamic
                .push((DT_GNU_HASH, DynValue::AddrOf(".gnu.hash")));
        }
    });
    for (name, sh_type, bytes) in [(".hash", SHT_HASH, sysv), (".gnu.hash", SHT_GNU_HASH, gnu)] {
        if let Some(bytes) = bytes {
            object.sections.push(Section {
                name,
                sh_type,
                flags: SHF_ALLOC,
                addralign: 8,
                entsize: 0,
                link: None,
                info: 0,
                content: Content::Bytes(bytes),
            });
        }
    }
    forge(&mut object);
    object.build()
}

fn symbol_records(f: &ElfFacts) -> Vec<&elf::Truncation> {
    f.truncations
        .iter()
        .filter(|t| t.table == ElfTable::Symbols)
        .collect()
}

fn dynsym_header_field(d: &mut [u8], field: std::ops::Range<usize>, value: u64) {
    d[field].copy_from_slice(&value.to_le_bytes());
}

/// `.dynsym`'s `sh_size` field, as a byte range into the object.
fn dynsym_size_field(d: &[u8]) -> std::ops::Range<usize> {
    let field = sh_offset_field(d, ".dynsym");
    field.end..field.end + 8
}

/// Both hash styles name the symbol count the section header also names, so reading
/// `.dynsym` through the dynamic table is the same reading, with nothing recorded.
#[test]
fn the_loaders_symbol_table_reads_as_the_section_does_where_the_two_agree() {
    let plain = facts(&whole());
    for (gnu, sysv) in [
        (Some(gnu_hash_of_four()), None),
        (None, Some(sysv_hash_of(4))),
        (Some(gnu_hash_of_four()), Some(sysv_hash_of(4))),
    ] {
        let f = facts(&hashed(gnu, sysv, |_| {}));
        assert_eq!(f.symbol_tables, plain.symbol_tables);
        assert_eq!(f.symbol_count, plain.symbol_count);
        assert_eq!(f.watched_symbols, plain.watched_symbols);
        assert!(symbol_records(&f).is_empty(), "{:?}", f.truncations);
    }
}

/// A hash table counts the symbols a lookup can find, not the symbols the table holds: an
/// object that exports nothing has a hash table of one symbol over a `.dynsym` of its
/// imports. The hash reach is a floor, so the section's longer table is read whole and
/// nothing is recorded (the Fedora 44 x86_64 `7z` executable has this shape).
#[test]
fn a_hash_table_shorter_than_dynsym_does_not_shorten_it() {
    let plain = facts(&whole());
    for (gnu, sysv) in [
        (Some(le32_gnu_hash_of_one()), None),
        (None, Some(sysv_hash_of(1))),
        (Some(gnu_hash_of_four()), Some(sysv_hash_of(2))),
    ] {
        let f = facts(&hashed(gnu, sysv, |_| {}));
        assert_eq!(f.symbol_count, plain.symbol_count, "{:?}", f.truncations);
        assert_eq!(f.watched_symbols, plain.watched_symbols);
        assert!(symbol_records(&f).is_empty(), "{:?}", f.truncations);
    }
}

/// A `DT_GNU_HASH` table of one symbol and no populated bucket.
fn le32_gnu_hash_of_one() -> Vec<u8> {
    let mut b = le32(&[1, 1, 1, 6]);
    b.extend_from_slice(&[0; 8]);
    b.extend(le32(&[0]));
    b
}

/// A forged `.dynsym` `sh_size` of 0 hid every dynamic symbol from a reader that took the
/// count from the section header; the hash table reaches all four, and that much is read.
#[test]
fn a_forged_dynsym_size_cannot_hide_the_loaders_symbols() {
    let plain = facts(&whole());
    for (gnu, sysv) in [
        (Some(gnu_hash_of_four()), None),
        (None, Some(sysv_hash_of(4))),
    ] {
        let mut d = hashed(gnu, sysv, |_| {});
        let field = dynsym_size_field(&d);
        dynsym_header_field(&mut d, field, 0);
        let f = facts(&d);
        assert_eq!(f.symbol_count, plain.symbol_count, "{:?}", f.truncations);
        assert_eq!(f.watched_symbols, plain.watched_symbols);
        let records = symbol_records(&f);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].kind, elf::TruncationKind::Ignored);
        assert!(
            records[0].detail.contains("hash and relocation tables"),
            "{records:?}"
        );
    }
}

const DT_PLTRELSZ: i64 = 2;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;

/// `Elf64_Rela` entries naming the given `.dynsym` indices, as raw bytes: the builder's
/// `Content::Rela` resolves names against an object symbol table, and these name indices.
fn rela_naming(symbols: &[u64]) -> Vec<u8> {
    symbols
        .iter()
        .flat_map(|sym| {
            let mut e = 0x40_1000u64.to_le_bytes().to_vec();
            e.extend_from_slice(&((sym << 32) | 7).to_le_bytes()); // R_X86_64_JUMP_SLOT
            e.extend_from_slice(&0u64.to_le_bytes());
            e
        })
        .collect()
}

/// The hash table of one symbol over the base object, as an executable that exports
/// nothing has it, with a `.rela.plt` naming `plt` through `DT_JMPREL` and a `.rela.dyn`
/// naming `dyn_` through `DT_RELA`, `DT_PLTREL` naming `DT_RELA`. `omit` leaves that one
/// tag out.
fn relocated(plt: &[u64], dyn_: &[u64], omit: Option<i64>) -> Vec<u8> {
    let mut object = base_with(|linked| {
        let tags = [
            (DT_GNU_HASH, DynValue::AddrOf(".gnu.hash")),
            (DT_JMPREL, DynValue::AddrOf(".rela.plt")),
            (DT_PLTRELSZ, DynValue::SizeOf(".rela.plt")),
            (DT_PLTREL, DynValue::Const(7)),
            (DT_RELA, DynValue::AddrOf(".rela.dyn")),
            (DT_RELASZ, DynValue::SizeOf(".rela.dyn")),
            (DT_RELAENT, DynValue::Const(24)),
        ];
        linked
            .extra_dynamic
            .extend(tags.into_iter().filter(|(tag, _)| Some(*tag) != omit));
    });
    for (name, sh_type, bytes) in [
        (".gnu.hash", SHT_GNU_HASH, le32_gnu_hash_of_one()),
        (".rela.plt", SHT_RELA, rela_naming(plt)),
        (".rela.dyn", SHT_RELA, rela_naming(dyn_)),
    ] {
        object.sections.push(Section {
            name,
            sh_type,
            flags: SHF_ALLOC,
            addralign: 8,
            entsize: if sh_type == SHT_RELA { 24 } else { 0 },
            link: None,
            info: 0,
            content: Content::Bytes(bytes),
        });
    }
    object.build()
}

/// The cut-`.dynsym` shape: the Fedora 44 x86_64 `7z` executable, its `.gnu.hash` reaching one
/// symbol, read one symbol and no `__stack_chk_fail` with `.dynsym`'s `sh_size` cut from
/// 3216 to 48, and recorded nothing. The loader binds an import through the relocation
/// that names its index, so the relocations reach the imports whatever the header says:
/// here `.rela.plt` names symbol 1 (`__stack_chk_fail`) and `.rela.dyn` symbol 2, the
/// header holds the null symbol alone, and the first three entries are read.
#[test]
fn a_forged_dynsym_size_cannot_hide_an_import_a_relocation_names() {
    let plain = facts(&whole());
    let honest = facts(&relocated(&[1], &[2], None));
    assert_eq!(
        honest.symbol_count, plain.symbol_count,
        "{:?}",
        honest.truncations
    );
    assert_eq!(honest.watched_symbols, plain.watched_symbols);
    assert!(
        symbol_records(&honest).is_empty(),
        "{:?}",
        honest.truncations
    );

    for (plt, dyn_) in [(&[1u64][..], &[2u64][..]), (&[2, 1], &[]), (&[], &[1])] {
        let mut d = relocated(plt, dyn_, None);
        let field = dynsym_size_field(&d);
        dynsym_header_field(&mut d, field, 24);
        let f = facts(&d);
        // `symbol_count` names each symbol once across `.dynsym` and `.symtab`, so it
        // cannot tell; the watched entry lists the tables a name was read from.
        assert_eq!(
            f.watched_symbols.get("__stack_chk_fail"),
            plain.watched_symbols.get("__stack_chk_fail"),
            "{plt:?} {dyn_:?}: {:?}",
            f.truncations
        );
        let records = symbol_records(&f);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].kind, elf::TruncationKind::Ignored);
        assert!(
            records[0].detail.contains("relocation tables reach"),
            "{records:?}"
        );
    }
}

/// A relocation table the floor cannot be read from withholds the symbols, as an
/// unreadable hash table does: `DT_JMPREL` with no `DT_PLTREL` has no entry size,
/// `DT_RELA` with no `DT_RELASZ` has no length, and a relocation naming symbol 1000 reaches
/// past the end of the file.
#[test]
fn a_relocation_table_that_cannot_bound_dynsym_is_recorded_unread() {
    for (d, says) in [
        (relocated(&[1], &[], Some(DT_PLTREL)), "DT_PLTREL"),
        (relocated(&[], &[1], Some(DT_RELASZ)), "has no DT_RELASZ"),
        (relocated(&[1000], &[], None), "past the end of the file"),
    ] {
        let f = facts(&d);
        let records = symbol_records(&f);
        assert!(
            records
                .iter()
                .any(|t| t.kind == elf::TruncationKind::Unread && t.detail.contains(says)),
            "{records:?}"
        );
    }
}

/// A forged `.dynsym` `sh_offset` aimed at another table: the loader reads `DT_SYMTAB`'s,
/// no header names it, and its length is not in the file, so the symbols are unread and
/// the forged table is not read in its place.
#[test]
fn a_forged_dynsym_offset_cannot_replace_the_loaders_table() {
    let plain = facts(&whole());
    let mut d = hashed(Some(gnu_hash_of_four()), None, |_| {});
    let symtab = le_u64(&d[sh_offset_field(&d, ".symtab")]);
    let field = sh_offset_field(&d, ".dynsym");
    dynsym_header_field(&mut d, field, symtab);
    let f = facts(&d);
    assert!(
        f.unread(&[ElfTable::Symbols]).is_some(),
        "{:?}",
        f.truncations
    );
    assert!(
        !f.symbol_tables.contains(&".dynsym".to_owned()),
        "{:?}",
        f.symbol_tables
    );
    assert!(
        f.watched_symbols
            .values()
            .all(|s| s.tables.iter().all(|t| t != ".dynsym")),
        "a table the loader does not read supplied a symbol: {:?} against {:?}",
        f.watched_symbols,
        plain.watched_symbols
    );
    assert!(
        symbol_records(&f)
            .iter()
            .any(|t| t.kind == elf::TruncationKind::Ignored),
        "{:?}",
        f.truncations
    );
}

/// A section header the loader never reads, typed `SHT_DYNSYM` and naming a fortify symbol
/// the real table lacks, added a symbol to the file; the hashless base object reaches the
/// same refusal through the offset comparison alone.
#[test]
fn a_second_dynsym_section_header_is_not_a_symbol_table_the_loader_reads() {
    let forge = |object: &mut Object| {
        object.sections.push(Section {
            name: ".forged",
            sh_type: SHT_DYNSYM,
            flags: SHF_ALLOC,
            addralign: 8,
            entsize: 24,
            link: Some(".dynstr"),
            info: 1,
            content: Content::Symbols(vec![Symbol {
                name: "__memcpy_chk",
                defined_in: None,
                st_other: 0,
            }]),
        });
        for section in &mut object.sections {
            if let (".dynstr", Content::Strings(strings)) = (section.name, &mut section.content) {
                strings.push("__memcpy_chk");
            }
        }
    };
    for hash in [None, Some(gnu_hash_of_four())] {
        let d = hashed(hash, None, forge);
        let f = facts(&d);
        assert!(
            !f.watched_symbols.contains_key("__memcpy_chk"),
            "a table the loader does not read named a symbol: {:?}",
            f.watched_symbols
        );
        assert_eq!(f.symbol_count, facts(&whole()).symbol_count);
        let records = symbol_records(&f);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].kind, elf::TruncationKind::Ignored);
    }
}

/// A dynamic table with no `DT_SYMTAB` gives the loader no dynamic symbols, so a
/// `SHT_DYNSYM` section is a table nothing loads.
#[test]
fn a_dynsym_section_beside_a_dynamic_table_with_no_dt_symtab_is_not_read() {
    let mut d = whole();
    patch_dynamic_entry(&mut d, DT_SYMTAB, |entry| {
        entry[0..8].copy_from_slice(&0x7fff_0000u64.to_le_bytes());
    });
    let f = facts(&d);
    assert!(
        !f.symbol_tables.contains(&".dynsym".to_owned()),
        "{:?}",
        f.symbol_tables
    );
    assert!(
        f.watched_symbols
            .values()
            .all(|s| !s.tables.contains(&".dynsym".to_owned())),
        "{:?}",
        f.watched_symbols
    );
    let records = symbol_records(&f);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].kind, elf::TruncationKind::Ignored);
    assert!(records[0].detail.contains("DT_SYMTAB"), "{records:?}");
}

/// Where the loader's table cannot be read to a count the dynamic table names, the
/// symbols are unread: a hash table that names more symbols than the file holds, two hash
/// tables that disagree, and a `DT_SYMTAB` no segment maps.
#[test]
fn a_loader_symbol_table_that_cannot_be_counted_is_recorded_unread() {
    let past_the_end = sysv_hash_of(u32::MAX);
    let shapes: Vec<(&str, Vec<u8>)> = vec![
        (
            "count past the file",
            hashed(None, Some(past_the_end), |_| {}),
        ),
        ("bucket below symoffset", {
            let mut b = le32(&[1, 2, 1, 6]);
            b.extend_from_slice(&[0; 8]);
            b.extend(le32(&[1, 1, 1, 1]));
            hashed(Some(b), None, |_| {})
        }),
        ("DT_SYMTAB unmapped", {
            let mut d = hashed(Some(gnu_hash_of_four()), None, |_| {});
            patch_dynamic_entry(&mut d, DT_SYMTAB, |entry| {
                entry[8..16].copy_from_slice(&0x10u64.to_le_bytes());
            });
            d
        }),
    ];
    for (name, d) in shapes {
        let f = facts(&d);
        assert!(
            f.unread(&[ElfTable::Symbols]).is_some(),
            "{name}: {:?}",
            f.truncations
        );
        assert!(
            f.watched_symbols
                .values()
                .all(|s| !s.tables.contains(&".dynsym".to_owned())),
            "{name}: a table that could not be counted was read: {:?}",
            f.watched_symbols
        );
    }
}

/// An object with no program headers has no loader view, so its section headers are the
/// only reading there is.
#[test]
fn a_dynsym_section_in_an_object_with_no_program_headers_is_still_read() {
    let mut object = base();
    object.segments.clear();
    let f = facts(&object.build());
    assert!(f.symbol_tables.contains(&".dynsym".to_owned()));
    assert!(symbol_records(&f).is_empty(), "{:?}", f.truncations);
}

/// `ld.so` keeps the last `DT_RPATH` and the last `DT_RUNPATH`; a list of each told a
/// reader the object searched a path the loader never consults.
#[test]
fn a_repeated_rpath_or_runpath_tag_reads_as_the_loader_reads_it_and_is_recorded() {
    for tag in [DT_RPATH, DT_RUNPATH] {
        let object = base_with(|linked| {
            linked.extra_dynstr.extend(["/first", "/second"]);
            linked.extra_dynamic.retain(|(t, _)| *t != DT_RPATH);
            linked
                .extra_dynamic
                .push((tag, DynValue::StrOff(".dynstr", "/first")));
            linked
                .extra_dynamic
                .push((tag, DynValue::StrOff(".dynstr", "/second")));
        });
        let f = facts(&object.build());
        let (read, other) = if tag == DT_RPATH {
            (&f.rpath, &f.runpath)
        } else {
            (&f.runpath, &f.rpath)
        };
        assert_eq!(read, &vec!["/second".to_owned()], "{f:?}");
        assert!(other.is_empty(), "{f:?}");
        let name = if tag == DT_RPATH {
            "DT_RPATH"
        } else {
            "DT_RUNPATH"
        };
        let records: Vec<&elf::Truncation> = f
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::Dynamic)
            .collect();
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].kind, elf::TruncationKind::Unread);
        assert!(records[0].detail.contains(name), "{records:?}");
    }
}

/// Without a `PT_DYNAMIC` no loader reads the object, and several `SHT_DYNAMIC` sections
/// were concatenated. The rule is the program-header rule's: the last is read, and the
/// repeat is recorded unread.
#[test]
fn several_dynamic_sections_with_no_segment_are_read_as_one_and_recorded() {
    let mut object = base();
    object.segments.retain(|s| s.p_type != PT_DYNAMIC);
    object.sections.push(Section {
        name: ".dynamic.forged",
        sh_type: SHT_DYNAMIC,
        flags: SHF_ALLOC | SHF_WRITE,
        addralign: 8,
        entsize: 16,
        link: Some(".dynstr"),
        info: 0,
        content: Content::Dynamic(vec![(DT_FLAGS_1, DynValue::Const(0))]),
    });
    let f = facts(&object.build());
    assert_eq!(
        f.bind_now,
        Some(false),
        "the last table carries no DF_1_NOW: {f:?}"
    );
    let records: Vec<&elf::Truncation> = f
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Dynamic)
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].kind, elf::TruncationKind::Unread);
    assert!(records[0].detail.contains("SHT_DYNAMIC"), "{records:?}");
}
