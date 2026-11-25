// SPDX-License-Identifier: BSD-3-Clause

//! A truncation moves an elf-static detector only where the check declared the table.

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
struct Cut {
    name: &'static str,
    table: ElfTable,
    also: &'static [ElfTable],
    build: Build,
}

/// The default linked object with `DF_1_NOW`, a `DT_NEEDED` for libm and a `DT_RPATH`.
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

/// [`whole`] with a second definition of the last of `elf::entry`'s functions after every
/// other, in a section of its own: read whole, the name is withheld as two definitions, and
/// a walk stopped between the two must not read the first as the only one.
fn whole_with_a_later_second_entry_definition() -> Vec<u8> {
    let mut object = base();
    let name = elf::entry::ENTRY_FUNCTIONS[elf::entry::ENTRY_FUNCTIONS.len() - 1];
    for section in &mut object.sections {
        if let (".symtab", Content::Symbols(syms)) = (section.name, &mut section.content) {
            syms.push(Symbol {
                name,
                defined_in: Some(".openbsd.randomdata.retguard.1"),
                st_other: 0,
            });
        }
    }
    let mut d = object.build();
    size_probe_function(&mut d);
    size_entry_functions(&mut d);
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

/// One of the two header tables, for [`header_table_at_stride`] and [`with_header_entsize`].
#[derive(Clone, Copy)]
enum HeaderTable {
    Program,
    Section,
}

impl HeaderTable {
    /// The offsets of the ELF64 header's `e_*off`, `e_*entsize` and `e_*num` for this table.
    fn fields(self) -> (usize, usize, usize) {
        match self {
            Self::Program => (32, 54, 56),
            Self::Section => (40, 58, 60),
        }
    }
}

/// `d` with `table` copied to the end of the file at `stride` bytes a header, each header
/// followed by zeros to the stride, the offset field aimed at the copy and the entry-size
/// field set to `stride`. A walk at the declared size reads that table whole, as an honest
/// padded one; a walk at the record size reads it part header, part padding.
fn header_table_at_stride(mut d: Vec<u8>, table: HeaderTable, stride: u16) -> Vec<u8> {
    let (off_at, ent_at, num_at) = table.fields();
    let at = |d: &[u8], i: usize| usize::from(u16::from_le_bytes([d[i], d[i + 1]]));
    let off = usize::try_from(le_u64(&d[off_at..off_at + 8])).expect("a fixture offset fits");
    let (ent, num) = (at(&d, ent_at), at(&d, num_at));
    let stride_bytes = usize::from(stride);
    assert!(
        num > 0 && stride_bytes > ent,
        "a table to copy out, wider apart"
    );
    d.resize(d.len().next_multiple_of(8), 0);
    let copy = d.len();
    for i in 0..num {
        let header = d[off + i * ent..off + (i + 1) * ent].to_vec();
        d.extend_from_slice(&header);
        d.resize(d.len() + stride_bytes - ent, 0);
    }
    let copy = u64::try_from(copy).expect("a fixture length fits u64");
    d[off_at..off_at + 8].copy_from_slice(&copy.to_le_bytes());
    d[ent_at..ent_at + 2].copy_from_slice(&stride.to_le_bytes());
    d
}

/// `d` with `table`'s entry-size field alone set to `entsize`, the table where it was.
fn with_header_entsize(mut d: Vec<u8>, table: HeaderTable, entsize: u16) -> Vec<u8> {
    let (_, ent_at, _) = table.fields();
    d[ent_at..ent_at + 2].copy_from_slice(&entsize.to_le_bytes());
    d
}

/// The base object's section-header table copied out at a 128-byte stride, `e_shentsize`
/// 128: no loader reads the table to say which stride is the file's, so the reader reads
/// neither and the file as one with no section-header table, the cause recorded against
/// `section-headers` (`elf::section_table_withheld`).
fn section_headers_at_another_stride() -> Vec<u8> {
    header_table_at_stride(whole(), HeaderTable::Section, 128)
}

/// The builder's relocatable object, whose `.note.gnu.property` marks IBT and SHSTK and
/// which has no program headers: its notes are reached through its section headers alone,
/// and `cet-marked-object` reads `full` from it.
fn relocatable_marked() -> Vec<u8> {
    elf_builder::relocatable().build()
}

/// [`relocatable_marked`] with its section-header table copied out at a 128-byte stride.
/// With no program headers there is no other route to the note, so `notes` is recorded
/// unread beside the section tables, and `cet-marked-object` is withheld rather than read
/// `absent`.
fn relocatable_section_headers_at_another_stride() -> Vec<u8> {
    header_table_at_stride(relocatable_marked(), HeaderTable::Section, 128)
}

/// [`relocatable_marked`] with `e_shnum` 0 and `e_shoff` past the end of the file: the count
/// escape cannot be followed, the file is read as having no section-header table, and,
/// with no program headers, no note either.
fn relocatable_section_header_escape_cut() -> Vec<u8> {
    let mut d = relocatable_marked();
    let stale = u64::try_from(d.len()).expect("a fixture length fits in u64") + 0x10000;
    d[40..48].copy_from_slice(&stale.to_le_bytes());
    d[60..62].copy_from_slice(&0u16.to_le_bytes());
    d
}

/// `d` with a program-header table of one `PT_NULL` header appended to the end of the file,
/// `e_phoff`, `e_phnum` and `e_phentsize` set to name it: a relocatable object no linker
/// writes, which no loader of a program loads either, so its marking is still read from its
/// sections.
fn with_a_null_program_header(mut d: Vec<u8>) -> Vec<u8> {
    d.resize(d.len().next_multiple_of(8), 0);
    let at = u64::try_from(d.len()).expect("a fixture length fits u64");
    d.resize(d.len() + PHDR_SIZE, 0);
    d[32..40].copy_from_slice(&at.to_le_bytes()); // e_phoff
    let size = u16::try_from(PHDR_SIZE).expect("the record size fits u16");
    d[54..56].copy_from_slice(&size.to_le_bytes()); // e_phentsize
    d[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    d
}

/// [`relocatable_marked`] carrying one `PT_NULL` program header.
fn relocatable_marked_with_a_program_header() -> Vec<u8> {
    with_a_null_program_header(relocatable_marked())
}

/// [`relocatable_marked_with_a_program_header`] with its section-header table copied out at
/// a 128-byte stride: the notes are still the sections', so `notes` is recorded unread.
fn relocatable_marked_with_a_program_header_at_another_stride() -> Vec<u8> {
    header_table_at_stride(
        relocatable_marked_with_a_program_header(),
        HeaderTable::Section,
        128,
    )
}

/// The builder's aarch64 relocatable object marking BTI, PAC and GCS in its build attributes
/// alone, carrying one `PT_NULL` program header: `branch-protection-marked` reads it whole.
fn aarch64_attributes_with_a_program_header() -> Vec<u8> {
    with_a_null_program_header(elf_builder::relocatable_aarch64_build_attributes().build())
}

/// [`aarch64_attributes_with_a_program_header`] with its section-header table copied out at a
/// 128-byte stride. The build attributes are read from sections whatever the program headers
/// are, so `notes` is recorded unread; without the record `branch-protection-marked` would
/// read `absent`.
fn aarch64_attributes_with_a_program_header_at_another_stride() -> Vec<u8> {
    header_table_at_stride(
        aarch64_attributes_with_a_program_header(),
        HeaderTable::Section,
        128,
    )
}

/// The linked base with `e_phnum` set to 0: a file no loader runs, whose dynamic section
/// and notes are reached through its sections alone, read whole that way.
fn linked_without_program_headers() -> Vec<u8> {
    let mut d = whole();
    d[56..58].copy_from_slice(&0u16.to_le_bytes()); // e_phnum
    d
}

/// [`linked_without_program_headers`] with its section-header table copied out at a 128-byte
/// stride: neither route to `.dynamic` is left, so `dynamic` is recorded unread with the
/// section tables and `notes`. Without the record `textrel-absent` would read a file with no
/// `DT_TEXTREL`.
fn linked_without_program_headers_at_another_stride() -> Vec<u8> {
    header_table_at_stride(linked_without_program_headers(), HeaderTable::Section, 128)
}

/// The linked base with its `PT_DYNAMIC` header retyped to `PT_NULL`: program headers and no
/// dynamic segment, so `Elf::dynamic` reads `.dynamic` through its section, whole.
fn linked_dynamic_by_section() -> Vec<u8> {
    let mut d = whole();
    let phdr = EHDR_SIZE + segment_index(PT_DYNAMIC) * PHDR_SIZE;
    d[phdr..phdr + 4].copy_from_slice(&0u32.to_le_bytes()); // PT_NULL
    d
}

/// [`linked_dynamic_by_section`] with its section-header table copied out at a 128-byte
/// stride: the section was the one route to `.dynamic`, so `dynamic` is recorded unread.
/// Without the record `relro` and `textrel-absent` would read a file with no dynamic section.
fn linked_dynamic_by_section_at_another_stride() -> Vec<u8> {
    header_table_at_stride(linked_dynamic_by_section(), HeaderTable::Section, 128)
}

/// The builder's relocatable object with a call to an undefined `chard_no_plt_callee`
/// relocated through its GOT slot (`R_X86_64_GOTPCRELX`) in `.rela.text`, which
/// `plt-bypassed` reads `present`. `trailing` bytes follow the one record.
fn relocatable_with_relocations(trailing: usize) -> Vec<u8> {
    let mut object = elf_builder::relocatable();
    for section in &mut object.sections {
        match (section.name, &mut section.content) {
            (".symtab", Content::Symbols(symbols)) => symbols.push(Symbol {
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
            "{}: {} moved {:?}/{:?} to {:?}/{:?} on a cut {:?} (and {:?}) outside its reads {:?}",
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
#[expect(
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
            name: "the section-header table copied out at a 128-byte stride",
            table: ElfTable::SectionHeaders,
            also: &[ElfTable::Symbols, ElfTable::SectionNames, ElfTable::Comment],
            build: section_headers_at_another_stride,
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
    let mut cuts: Vec<(Build, Cut)> = vec![
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
    ];
    cuts.extend(relocatable_section_table_cuts());
    cuts
}

/// The section-header tables left unread for what the ELF header declares, each paired with
/// the object read whole: the module doc's seven cuts but the linked base's.
fn relocatable_section_table_cuts() -> Vec<(Build, Cut)> {
    vec![
        (
            linked_dynamic_by_section,
            Cut {
                name: "a linked file whose .dynamic only a section reaches, its section-header table at a 128-byte stride",
                table: ElfTable::SectionHeaders,
                also: &[
                    ElfTable::Symbols,
                    ElfTable::SectionNames,
                    ElfTable::Comment,
                    ElfTable::Dynamic,
                ],
                build: linked_dynamic_by_section_at_another_stride,
            },
        ),
        (
            linked_without_program_headers,
            Cut {
                name: "a linked file with no program headers, its section-header table at a 128-byte stride",
                table: ElfTable::SectionHeaders,
                also: &[
                    ElfTable::Symbols,
                    ElfTable::SectionNames,
                    ElfTable::Comment,
                    ElfTable::Notes,
                    ElfTable::Dynamic,
                ],
                build: linked_without_program_headers_at_another_stride,
            },
        ),
        (
            relocatable_marked,
            Cut {
                name: "a relocatable object's section-header table copied out at a 128-byte stride",
                table: ElfTable::SectionHeaders,
                also: &[
                    ElfTable::Symbols,
                    ElfTable::SectionNames,
                    ElfTable::Comment,
                    ElfTable::Notes,
                    ElfTable::Dynamic,
                ],
                build: relocatable_section_headers_at_another_stride,
            },
        ),
        (
            relocatable_marked,
            Cut {
                name: "a relocatable object's count escape naming a shdr[0] past the end of the file",
                table: ElfTable::SectionHeaders,
                also: &[
                    ElfTable::Symbols,
                    ElfTable::SectionNames,
                    ElfTable::Comment,
                    ElfTable::Notes,
                    ElfTable::Dynamic,
                ],
                build: relocatable_section_header_escape_cut,
            },
        ),
        (
            relocatable_marked_with_a_program_header,
            Cut {
                name: "a relocatable object carrying a program header, its section-header table at a 128-byte stride",
                table: ElfTable::SectionHeaders,
                also: &[
                    ElfTable::Symbols,
                    ElfTable::SectionNames,
                    ElfTable::Comment,
                    ElfTable::Notes,
                    ElfTable::Dynamic,
                ],
                build: relocatable_marked_with_a_program_header_at_another_stride,
            },
        ),
        (
            aarch64_attributes_with_a_program_header,
            Cut {
                name: "an aarch64 relocatable object carrying a program header, its section-header table at a 128-byte stride",
                table: ElfTable::SectionHeaders,
                also: &[
                    ElfTable::Symbols,
                    ElfTable::SectionNames,
                    ElfTable::Comment,
                    ElfTable::Notes,
                    ElfTable::Dynamic,
                ],
                build: aarch64_attributes_with_a_program_header_at_another_stride,
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
    // the table.
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

#[test]
fn a_relocatable_object_reads_its_marking_from_its_sections_whatever_its_program_headers() {
    let macros = BTreeMap::new();
    for (shape, bytes, id) in [
        (
            "x86-64 SHT_NOTE",
            relocatable_marked_with_a_program_header(),
            "cet-marked-object",
        ),
        (
            "aarch64 build attributes",
            aarch64_attributes_with_a_program_header(),
            "branch-protection-marked",
        ),
    ] {
        let read = facts(&bytes);
        assert!(
            read.truncations.is_empty(),
            "{shape}: {:?}",
            read.truncations
        );
        let detection = corpus_check(id).decode(&evidence(&macros, &read)).detection;
        assert_eq!(detection.outcome, Outcome::Present, "{shape}: {id}");
    }
}

/// The measured variant whose artifact `cut` is, refused by `Elf::parse` as `measure::gather`
/// stores the refusal; where `stride` is a declared `e_phentsize`, the refusal is the
/// malformed header that names it.
fn refused_variant(shape: &str, cut: &[u8], stride: Option<u16>) -> report::Variant {
    let elf_error = match elf::Elf::parse(cut) {
        Ok(_) => panic!("{shape}: the program-header table parsed"),
        Err(e) => {
            if let Some(stride) = stride {
                let elf::ElfError::Malformed { what, .. } = &e else {
                    panic!("{shape}: refused as malformed, got {e:?}");
                };
                assert!(
                    what.starts_with(&format!(
                        "e_phentsize is {stride}, not the 56-byte program header"
                    )),
                    "{shape}: {what}"
                );
            }
            report::ArtifactRefusal::of(&e)
        }
    };
    report::Variant {
        macros: BTreeMap::new(),
        macros_preprocessor: BTreeMap::new(),
        macro_source: "preprocessor",
        macro_dump: None,
        elf: None,
        build: None,
        run: None,
        run_error: None,
        elf_error: Some(elf_error),
        unwitnessed: None,
        artifact: None,
        structured: None,
        workdir: None,
    }
}

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

    // The header table past the end of the file, and the table declared at a stride other
    // than the record's, copied out at it or left where it was: `parse` refuses each.
    let mut past_end = whole();
    let past = u64::try_from(past_end.len()).expect("a file length fits u64") + 8;
    past_end[32..40].copy_from_slice(&past.to_le_bytes()); // e_phoff
    let refused = [
        ("e_phoff past the end of the file", past_end, None),
        (
            "the table copied out at a 112-byte stride",
            header_table_at_stride(whole(), HeaderTable::Program, 112),
            Some(112),
        ),
        (
            "e_phentsize alone set to 64",
            with_header_entsize(whole(), HeaderTable::Program, 64),
            Some(64),
        ),
    ];
    for (shape, cut, stride) in &refused {
        let variant = refused_variant(shape, cut, *stride);
        for check in &declaring {
            assert_eq!(
                check.channel(),
                Channel::ElfStatic,
                "{}: declares program-headers and is not on the elf-static channel",
                check.id
            );
            assert_eq!(
                variant.sufficient_for(check.channel()),
                Err(report::Verdict::Indeterminate),
                "{shape}: {}: a header table parse refused withholds it",
                check.id
            );
        }
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
    // The predicate's input: no reference attributed to a function, which its
    // `not-an-object` clause withholds.
    assert!(
        none.function_references.is_none(),
        "{:?}",
        none.function_references
    );
    assert!(none.watched_symbols.is_empty());
    assert!(
        none.truncations.is_empty(),
        "an absent table is not a cut one: {:?}",
        none.truncations
    );
    let mut examined = 0usize;
    let mut left_to_the_predicate = 0usize;
    for check in CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| c.reads().contains(&ElfTable::Symbols))
    {
        // An object without a symbol table was still compiled at its optimisation level, so
        // the level is not inert there: no row gates `optimization-applied`, and its
        // predicate's `not-an-object` clause withholds it as `indeterminate` instead.
        if check.id == "optimization-applied" {
            assert!(
                report::artifact_limitation(
                    report::Verdict::Indeterminate,
                    check,
                    Outcome::Absent,
                    Some(&none)
                )
                .is_none(),
                "{}: no precondition calls the level inert",
                check.id
            );
            left_to_the_predicate += 1;
            continue;
        }
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
    // the symbol table; and `optimization-applied`, left to its predicate.
    assert_eq!(
        examined, 10,
        "the ten gated symbol-reading checks were examined"
    );
    assert_eq!(
        left_to_the_predicate, 1,
        "optimization-applied was examined"
    );
}

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
        "the withheld checks are not the seven the comment above lists"
    );
    assert!(elf_static > 0, "no elf-static check was examined");
}

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
        "the withheld checks are not the seven the comment above lists"
    );
    assert!(elf_static > 0, "no elf-static check was examined");
}

/// How many objects the truncation property draws by default, and how many cuts each.
const GENERATED_OBJECTS: usize = 128;
const CUTS_PER_OBJECT: usize = 24;

/// The tables whose `unread` entry accounts for a change in each serialized fact.
fn covering_tables(fact: &str) -> Option<&'static [ElfTable]> {
    use ElfTable::{
        Code, Comment, DynStr, Dynamic, FunctionEntries, GnuStack, Header, Notes, ProgramHeaders,
        Relocations, SectionHeaders, SectionNames, Symbols,
    };
    Some(match fact {
        "elf_class" | "elf_data" | "elf_type" | "machine" => &[Header],
        "has_interp" | "gnu_relro" | "openbsd_nobtcfi" | "rwx_segment" => &[ProgramHeaders],
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
        "code_scanned" | "code_matches" => &[SectionHeaders, Symbols, Code],
        _ => return None,
    })
}

/// Every fact a cut changed that no `unread` entry on a covering table accounts for, with
/// each fact that moved tallied in `moved`.
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
                "{}-byte cut at {cut}, smallest {smallest}, moved an uncovered fact ({}):\n  {}\nsmallest:\n  {}\n{spec:#?}",
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

/// How many budgets [`every_fact_a_spent_budget_changes_is_covered_by_a_recorded_truncation`]
/// reads each object under, at most: every budget below the one the object needs where that
/// is fewer, evenly spaced ones otherwise.
const BUDGETS_PER_OBJECT: u64 = 4096;

#[test]
fn every_fact_a_spent_budget_changes_is_covered_by_a_recorded_truncation() {
    let (seed, from_env) = seeded::seed();
    let cases = seeded::cases(GENERATED_OBJECTS / 4);
    let mut objects: Vec<(String, Vec<u8>)> = vec![
        ("the linked base".to_owned(), whole()),
        ("the relocatable base".to_owned(), relocatable_with_call()),
        (
            "the linked base with a later second entry definition".to_owned(),
            whole_with_a_later_second_entry_definition(),
        ),
    ];
    for case in 0..cases {
        let mut rng = seeded::Rng::for_case(seed, case);
        let spec = Spec::draw(&mut |n| rng.below(n));
        objects.push((seeded::replay(seed, case), spec.build()));
    }
    let mut read = 0usize;
    let mut moved: BTreeMap<String, usize> = BTreeMap::new();
    for (name, bytes) in &objects {
        let elf = elf::Elf::parse(bytes).expect("the builder's bytes parse");
        let whole_facts = elf.facts();
        let needed = elf.work_spent();
        // A second reading of the same `Elf` starts from where the parse left the budget, so
        // it is the same reading at the same cost.
        assert_eq!(
            serde_json::to_value(elf.facts()).expect("serializes"),
            serde_json::to_value(&whole_facts).expect("serializes"),
            "{name}: a second reading of one parse differs from the first"
        );
        assert_eq!(
            elf.work_spent(),
            needed,
            "{name}: a second reading cost more"
        );
        assert!(
            needed > 0 && needed < elf::work_budget(bytes.len()),
            "{name}: a whole reading spent {needed} units of {}",
            elf::work_budget(bytes.len())
        );
        let exact = elf::Elf::parse_within(bytes, needed).expect("parses");
        assert_eq!(
            serde_json::to_value(exact.facts()).expect("serializes"),
            serde_json::to_value(&whole_facts).expect("serializes"),
            "{name}: the {needed} units a whole reading spent did not read it whole again"
        );
        let step = needed.div_ceil(BUDGETS_PER_OBJECT).max(1);
        for units in (0..needed).step_by(usize::try_from(step).expect("fits")) {
            let cut = elf::Elf::parse_within(bytes, units).expect("parses");
            let cut_facts = cut.facts();
            read += 1;
            assert!(
                cut_facts
                    .truncations
                    .iter()
                    .any(|t| t.kind == elf::TruncationKind::Unread),
                "{name}: under budget {units}/{needed}, nothing was recorded unread: {:?}",
                cut_facts.truncations
            );
            let bad = uncovered_changes(&whole_facts, &cut_facts, &mut moved);
            assert!(
                bad.is_empty(),
                "{name}: budget {units}/{needed} moved an uncovered fact:\n  {}\ntruncations: {:?}",
                bad.join("\n  "),
                cut_facts.truncations
            );
        }
    }
    seeded::announce(
        "spent budget subset property",
        seed,
        from_env,
        cases,
        &format!(
            "{} objects, {read} budgets read and held to the property; facts moved: {moved:?}",
            objects.len()
        ),
    );
    if cases >= GENERATED_OBJECTS / 4 {
        let still: Vec<&&str> = MUST_MOVE
            .iter()
            .filter(|f| !moved.contains_key(**f))
            .collect();
        assert!(
            still.is_empty(),
            "no budget moved {still:?}, so the property was never tested on them ({})",
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
                l.e_type = ET_DYN;
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

#[test]
fn a_dynsym_section_in_an_object_with_no_program_headers_is_still_read() {
    let mut object = base();
    object.segments.clear();
    let f = facts(&object.build());
    assert!(f.symbol_tables.contains(&".dynsym".to_owned()));
    assert!(symbol_records(&f).is_empty(), "{:?}", f.truncations);
}

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

/// An ELF64 little-endian x86_64 header: `e_type`, the program and section header tables'
/// offsets and counts, and `e_shstrndx`.
fn raw_header(
    e_type: u16,
    (phoff, phnum): (u64, u16),
    (shoff, shnum, shstrndx): (u64, u16, u16),
) -> Vec<u8> {
    let mut h = b"\x7fELF\x02\x01\x01".to_vec();
    h.resize(16, 0);
    h.extend_from_slice(&e_type.to_le_bytes());
    h.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    h.extend_from_slice(&1u32.to_le_bytes());
    h.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    h.extend_from_slice(&phoff.to_le_bytes());
    h.extend_from_slice(&shoff.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    for half in [64u16, 56, phnum, 64, shnum, shstrndx] {
        h.extend_from_slice(&half.to_le_bytes());
    }
    h
}

/// One ELF64 section header with no flags, link, info or entry size.
fn raw_section(sh_name: u32, sh_type: u32, (offset, size): (u64, u64)) -> Vec<u8> {
    raw_section_linked(sh_name, (sh_type, 0), (offset, size), (0, 0), 0)
}

/// One ELF64 section header: name, type and flags, offset and size, link and info, entry size.
fn raw_section_linked(
    sh_name: u32,
    (sh_type, sh_flags): (u32, u64),
    (offset, size): (u64, u64),
    (link, info): (u32, u32),
    entsize: u64,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(SHDR_SIZE);
    s.extend_from_slice(&sh_name.to_le_bytes());
    s.extend_from_slice(&sh_type.to_le_bytes());
    for word in [sh_flags, 0, offset, size] {
        s.extend_from_slice(&word.to_le_bytes());
    }
    s.extend_from_slice(&link.to_le_bytes());
    s.extend_from_slice(&info.to_le_bytes());
    s.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
    s.extend_from_slice(&entsize.to_le_bytes());
    s
}

/// One ELF64 symbol: name offset, `st_info`, section index, value and size.
fn raw_symbol(name: u32, info: u8, shndx: u16, (value, size): (u64, u64)) -> Vec<u8> {
    let mut sym = name.to_le_bytes().to_vec();
    sym.extend_from_slice(&[info, 0]);
    sym.extend_from_slice(&shndx.to_le_bytes());
    sym.extend_from_slice(&value.to_le_bytes());
    sym.extend_from_slice(&size.to_le_bytes());
    sym
}

/// An `ET_REL` laid out from `(name, (type, flags), bytes, (link, info), entsize)` sections in
/// order after the null header, the last of them the section-name table. A section's `bytes`
/// are its contents, or `Err(i)` for a header over section `i`'s contents at `size` bytes.
/// One section [`raw_object`] lays out: name, (type, flags), contents or `Err((section, size))`,
/// (link, info), entry size.
type RawSection<'a> = (
    u32,
    (u32, u64),
    Result<&'a [u8], (usize, u64)>,
    (u32, u32),
    u64,
);

fn raw_relocatable(sections: &[RawSection<'_>]) -> Vec<u8> {
    raw_object(1, sections)
}

/// [`raw_relocatable`] with another `e_type`.
fn raw_object(e_type: u16, sections: &[RawSection<'_>]) -> Vec<u8> {
    let mut d = vec![0u8; 64];
    let mut placed = Vec::new();
    for (_, _, bytes, _, _) in sections {
        match bytes {
            Ok(b) => {
                d.resize(d.len().next_multiple_of(8), 0);
                placed.push((
                    u64::try_from(d.len()).expect("fits"),
                    u64::try_from(b.len()).expect("fits"),
                ));
                d.extend_from_slice(b);
            }
            Err(_) => placed.push((0, 0)),
        }
    }
    d.resize(d.len().next_multiple_of(8), 0);
    let shoff = u64::try_from(d.len()).expect("fits");
    d.extend_from_slice(&[0; SHDR_SIZE]);
    for (i, (name, kind, bytes, linked, entsize)) in sections.iter().enumerate() {
        let at = match bytes {
            Ok(_) => placed[i],
            Err((other, size)) => (placed[*other].0, *size),
        };
        d.extend_from_slice(&raw_section_linked(*name, *kind, at, *linked, *entsize));
    }
    let count = u16::try_from(sections.len() + 1).expect("fits");
    let header = raw_header(e_type, (0, 0), (shoff, count, count - 1));
    d[..64].copy_from_slice(&header);
    d
}

/// The offset of `name` in a NUL-separated name table.
fn name_offset(table: &[u8], name: &str) -> u32 {
    let needle = [&[0][..], name.as_bytes(), &[0]].concat();
    let at = table
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the name is in the table");
    u32::try_from(at + 1).expect("fits")
}

/// An `ET_REL` whose section-name table is `table`, named
/// by `headers` section headers, every one at offset 0. With no NUL in the table every name
/// is the whole table, so a reader that copies each name holds `headers` copies of it.
fn names_amplified(headers: u16, table: &[u8]) -> Vec<u8> {
    let len = u64::try_from(table.len()).expect("fits");
    let shoff = (64 + len).next_multiple_of(8);
    let mut d = raw_header(1, (0, 0), (shoff, headers, 1));
    d.extend_from_slice(table);
    d.resize(usize::try_from(shoff).expect("fits"), 0);
    d.extend_from_slice(&[0; SHDR_SIZE]);
    d.extend_from_slice(&raw_section(0, 3, (64, len))); // SHT_STRTAB
    for _ in 2..headers {
        d.extend_from_slice(&raw_section(0, 1, (64, 0))); // SHT_PROGBITS
    }
    d
}

/// An `ET_EXEC` whose one `PT_NOTE` covers `size` zero
/// bytes, which read as `size / 12` empty notes.
fn empty_notes(size: u64) -> Vec<u8> {
    let data_off: u64 = 64 + 56;
    let mut d = raw_header(2, (64, 1), (0, 0, 0));
    d.extend_from_slice(&4u32.to_le_bytes()); // PT_NOTE
    d.extend_from_slice(&4u32.to_le_bytes()); // PF_R
    for word in [
        data_off,
        0x40_0000 + data_off,
        0x40_0000 + data_off,
        size,
        size,
        4,
    ] {
        d.extend_from_slice(&word.to_le_bytes());
    }
    d.resize(d.len() + usize::try_from(size).expect("fits"), 0);
    d
}

/// The bound a generator's reading is held to: its serialized facts at most `max_facts`
/// bytes, and its wall time within `seconds`, a backstop far above what a linear reading
/// takes, which the quadratic and amplified readings these shapes describe exceed by orders of
/// magnitude. The facts come back for the caller's own assertions, beside the units spent.
fn read_within_bound(name: &str, bytes: &[u8], max_facts: usize, seconds: u64) -> (ElfFacts, u64) {
    let started = std::time::Instant::now();
    let elf = elf::Elf::parse(bytes).expect("the generator's bytes parse");
    let read = elf.facts();
    let took = started.elapsed();
    let serialized = serde_json::to_vec(&read).expect("facts serialize").len();
    assert!(
        serialized <= max_facts,
        "{name}: a {}-byte file read as {serialized} bytes of facts, past {max_facts}",
        bytes.len()
    );
    assert!(
        took <= std::time::Duration::from_secs(seconds),
        "{name}: a {}-byte file took {took:?} to read",
        bytes.len()
    );
    (read, elf.work_spent())
}

/// What the budget lets a reading publish: about a byte of facts a unit, with room for the
/// fields every reading carries.
fn budget_bound(bytes: &[u8]) -> usize {
    usize::try_from(elf::work_budget(bytes.len()) * 2).expect("fits")
}

#[test]
fn a_name_table_with_no_nul_named_by_every_header_is_refused_at_the_first_name() {
    let bytes = names_amplified(400, &vec![b'A'; 1 << 20]);
    let (read, _) = read_within_bound(
        "one name table named by every header",
        &bytes,
        bytes.len(),
        10,
    );
    assert!(read.sections.is_empty(), "{:?}", read.sections.len());
    let cut = read
        .unread(&[ElfTable::SectionNames])
        .expect("the names are recorded unread");
    assert!(cut.detail.contains("bound on one name"), "{}", cut.detail);
}

#[test]
fn names_within_the_bound_named_by_every_header_spend_the_budget_and_are_recorded() {
    let mut table = vec![b'A'; 60 << 10];
    table.push(0);
    let bytes = names_amplified(4000, &table);
    let (read, _) = read_within_bound(
        "names within the bound named by every header",
        &bytes,
        bytes.len(),
        10,
    );
    assert!(read.sections.is_empty(), "{:?}", read.sections.len());
    let cut = read
        .unread(&[ElfTable::SectionNames])
        .expect("the names are recorded unread");
    assert!(cut.detail.contains("work budget"), "{}", cut.detail);
}

#[test]
fn a_note_segment_of_empty_notes_is_read_whole_in_linear_work() {
    let half = empty_notes(8 << 20);
    let bytes = empty_notes(16 << 20);
    let (_, half_work) = read_within_bound("a note segment of empty notes", &half, half.len(), 10);
    let (read, work) = read_within_bound("a note segment of empty notes", &bytes, bytes.len(), 10);
    assert!(
        read.unread(&[ElfTable::Notes]).is_none(),
        "{:?}",
        read.truncations
    );
    assert!(
        read.gnu_property_types.is_empty(),
        "a reader that stopped in the notes publishes no property type: {:?}",
        read.gnu_property_types
    );
    assert!(
        work <= half_work * 21 / 10,
        "twice the notes spent {work} units against {half_work}"
    );
}

/// An `ET_REL` with no program headers whose `headers` `SHT_NOTE` section headers all name
/// one region holding `region`, so each header's walk reads the same notes.
fn notes_named_by_every_header(headers: u16, region: &[u8]) -> Vec<u8> {
    let size = u64::try_from(region.len()).expect("fits");
    let shoff = (64 + size).next_multiple_of(8);
    let mut d = raw_header(1, (0, 0), (shoff, headers + 1, 0));
    d.extend_from_slice(region);
    d.resize(usize::try_from(shoff).expect("fits"), 0);
    d.extend_from_slice(&[0; SHDR_SIZE]);
    for _ in 0..headers {
        d.extend_from_slice(&raw_section(0, 7, (64, size))); // SHT_NOTE
    }
    d
}

/// `notes` empty GNU property notes, 16 bytes each: `n_namesz` 4, `n_descsz` 0,
/// `NT_GNU_PROPERTY_TYPE_0`, `GNU`.
fn empty_property_notes(notes: u64) -> Vec<u8> {
    let mut d = Vec::new();
    for _ in 0..notes {
        for word in [4u32, 0, 5] {
            d.extend_from_slice(&word.to_le_bytes());
        }
        d.extend_from_slice(b"GNU\0");
    }
    d
}

/// An `ET_EXEC` with an empty `PT_GNU_PROPERTY` and `headers` `PT_NOTE` headers that all name
/// one region of `notes` empty GNU property notes, 16 bytes each, so each `PT_NOTE` walk meets
/// the same `notes` property notes outside the segment the loader reads.
fn property_notes_named_by_every_header(headers: u16, notes: u64) -> Vec<u8> {
    let phnum = headers + 1;
    let region = (64 + 56 * u64::from(phnum)).next_multiple_of(8);
    let mut d = raw_header(2, (64, phnum), (0, 0, 0));
    let mut segment = |p_type: u32, p_align: u64, size: u64| {
        d.extend_from_slice(&p_type.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes()); // PF_R
        for word in [region, 0, 0, size, size, p_align] {
            d.extend_from_slice(&word.to_le_bytes());
        }
    };
    segment(0x6474_e553, 8, 0); // PT_GNU_PROPERTY
    for _ in 0..headers {
        segment(4, 4, notes * 16); // PT_NOTE
    }
    d.resize(usize::try_from(region).expect("fits"), 0);
    d.extend(empty_property_notes(notes));
    d
}

#[test]
fn note_sections_that_name_one_region_keep_each_note_once() {
    let (headers, notes) = (200u16, 1000u64);
    let region = empty_property_notes(notes);
    let bytes = notes_named_by_every_header(headers, &region);
    let elf = elf::Elf::parse(&bytes).expect("the generator's bytes parse");
    let read = elf.facts();
    assert!(
        read.unread(&[ElfTable::Notes]).is_none(),
        "{:?}",
        read.truncations
    );
    assert_eq!(
        elf.notes_kept(),
        Some(notes),
        "{headers} headers over {notes} notes"
    );
    assert!(
        elf.work_spent() >= u64::from(headers) * notes,
        "each header's walk is charged: {} units",
        elf.work_spent()
    );
    let one = notes_named_by_every_header(1, &region);
    let one_elf = elf::Elf::parse(&one).expect("the generator's bytes parse");
    let _: ElfFacts = one_elf.facts();
    assert_eq!(one_elf.notes_kept(), elf.notes_kept());

    // One note carrying `X86_FEATURE_1_AND` = `IBT|SHSTK`, named by two headers, counts its
    // type once in `gnu_property_notes`.
    let mut marked = [4u32, 16, 5].map(u32::to_le_bytes).concat();
    marked.extend_from_slice(b"GNU\0");
    marked.extend([0xc000_0002u32, 4, 3, 0].map(u32::to_le_bytes).concat());
    let twice = elf::Elf::parse(&notes_named_by_every_header(2, &marked))
        .expect("the generator's bytes parse")
        .facts();
    assert!(twice.x86_ibt && twice.x86_shstk, "{twice:?}");
    assert_eq!(twice.gnu_property_notes.get("0xc0000002"), Some(&1));

    let zeros = notes_named_by_every_header(1000, &[0; 12_000]);
    let zeros_elf = elf::Elf::parse(&zeros).expect("the generator's bytes parse");
    let read = zeros_elf.facts();
    assert!(
        read.unread(&[ElfTable::Notes]).is_none(),
        "{:?}",
        read.truncations
    );
    assert_eq!(zeros_elf.notes_kept(), Some(0));
    assert!(
        zeros_elf.work_spent() >= 1000 * 1000,
        "each header's walk is charged: {} units",
        zeros_elf.work_spent()
    );
}

#[test]
fn a_spent_budget_over_note_headers_leaves_at_most_a_record_a_header() {
    let headers = 4000u16;
    let bytes = notes_named_by_every_header(headers, &vec![0; 65_536]);
    let elf = elf::Elf::parse(&bytes).expect("the generator's bytes parse");
    let read = elf.facts();
    assert!(
        read.unread(&[ElfTable::Notes])
            .is_some_and(|t| t.detail.contains("work budget")),
        "the budget is spent: {:?}",
        read.truncations.first()
    );
    assert_eq!(elf.notes_kept(), Some(0));
    assert!(
        read.truncations.len() <= usize::from(headers) + 8,
        "{} records for {headers} headers",
        read.truncations.len()
    );
}

#[test]
fn a_note_of_another_name_or_type_is_walked_and_not_kept() {
    let mut region = Vec::new();
    for (name, ntype) in [
        (&b"GNU\0"[..], 1u32),
        (b"GNU\0", 3),
        (b"GNX\0", 5),
        (b"GN\0\0", 5),
    ] {
        region.extend([4u32, 16, ntype].map(u32::to_le_bytes).concat());
        region.extend_from_slice(name);
        region.extend([0xc000_0002u32, 4, 3, 0].map(u32::to_le_bytes).concat());
    }
    let bytes = notes_named_by_every_header(1, &region);
    let elf = elf::Elf::parse(&bytes).expect("the bytes parse");
    let read = elf.facts();
    assert_eq!(elf.notes_kept(), Some(0));
    assert!(!read.x86_ibt && !read.x86_shstk, "{read:?}");
    assert!(read.gnu_property_types.is_empty(), "{read:?}");
    assert!(
        read.unread(&[ElfTable::Notes]).is_none(),
        "{:?}",
        read.truncations
    );
}

/// The feature word that marks every feature the reader decodes on `machine`, as a property's
/// header and word: `X86_FEATURE_1_AND` with `IBT|SHSTK` on x86-64, `AARCH64_FEATURE_1_AND` with
/// `BTI|PAC|GCS` on aarch64.
fn marking_property(machine: u16) -> [u32; 3] {
    if machine == elf_builder::EM_AARCH64 {
        [0xc000_0000, 4, 7]
    } else {
        [0xc000_0002, 4, 3]
    }
}

/// Whether `read` carries every feature [`marking_property`] marks on `machine`, and whether it
/// carries none of them.
fn marking(read: &ElfFacts, machine: u16) -> (bool, bool) {
    let bits = if machine == elf_builder::EM_AARCH64 {
        vec![read.aarch64_bti, read.aarch64_pac, read.aarch64_gcs]
    } else {
        vec![read.x86_ibt, read.x86_shstk]
    };
    (bits.iter().all(|b| *b), bits.iter().all(|b| !*b))
}

/// An ELF64 GNU property note: `n_namesz`, `n_descsz` and the type, then `name` (its NUL and
/// padding included), then `desc`, each word little-endian.
fn property_note(namesz: u32, descsz: u32, name: &[u8], desc: &[u32]) -> Vec<u8> {
    let mut note = [namesz, descsz, 5].map(u32::to_le_bytes).concat();
    note.extend_from_slice(name);
    note.extend(desc.iter().flat_map(|w| w.to_le_bytes()));
    note
}

/// One view the reader takes a property note through, the machine it is built for, and the
/// checks that read its marking.
struct NoteView {
    view: &'static str,
    machine: u16,
    checks: &'static [&'static str],
    bytes: Vec<u8>,
}

/// The views the reader takes a property note through, each holding `note(machine)` as its
/// `.note.gnu.property`: an x86-64 and an aarch64 program's `PT_NOTE`, each program again with
/// a `PT_GNU_PROPERTY` over the note, which the reader then reads alone, and an x86-64
/// relocatable object's `SHT_NOTE` section, read where there are no program headers.
fn property_note_views(note: impl Fn(u16) -> Vec<u8>) -> Vec<NoteView> {
    let with_note = |mut object: Object| {
        let bytes = note(object.e_machine);
        let section = object
            .sections
            .iter_mut()
            .find(|s| s.name == ".note.gnu.property")
            .expect("the builder writes a property note");
        section.content = Content::Bytes(bytes);
        object
    };
    let with_property_segment = |mut object: Object| {
        object.segments.push(Segment {
            p_type: 0x6474_e553, // PT_GNU_PROPERTY
            flags: PF_R,
            align: 8,
            covers: Covers::Section(".note.gnu.property"),
        });
        object
    };
    let x86 = with_note(linked_default().object());
    let mut arm = linked_default();
    arm.e_machine = elf_builder::EM_AARCH64;
    arm.property = Some((elf_builder::GNU_PROPERTY_AARCH64_FEATURE_1_AND, 7));
    let arm = with_note(arm.object());
    let (cet, arm_marks): (&[&str], &[&str]) =
        (&["cet-marked"], &["branch-protection-marked", "gcs-marked"]);
    let view = |view, machine, checks, object: Object| NoteView {
        view,
        machine,
        checks,
        bytes: object.build(),
    };
    vec![
        view("x86-64 PT_NOTE", EM_X86_64, cet, x86.clone()),
        view(
            "x86-64 PT_GNU_PROPERTY",
            EM_X86_64,
            cet,
            with_property_segment(x86),
        ),
        view(
            "x86-64 SHT_NOTE",
            EM_X86_64,
            &["cet-marked-object"],
            with_note(elf_builder::relocatable()),
        ),
        view(
            "aarch64 PT_NOTE",
            elf_builder::EM_AARCH64,
            arm_marks,
            arm.clone(),
        ),
        view(
            "aarch64 PT_GNU_PROPERTY",
            elf_builder::EM_AARCH64,
            arm_marks,
            with_property_segment(arm),
        ),
    ]
}

/// The x86-64 machine number, for [`property_note_views`]' views.
const EM_X86_64: u16 = 62;

/// The check `id`, from the corpus.
fn corpus_check(id: &str) -> &'static Check {
    CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} is in the corpus"))
}

/// The note of `view` reads its marking whole, with no `notes` record and no check withheld:
/// the control the shapes below are cut from.
fn assert_marked_whole(view: &NoteView) {
    let read = facts(&view.bytes);
    assert!(marking(&read, view.machine).0, "{}: {read:?}", view.view);
    assert!(
        read.unread(&[ElfTable::Notes]).is_none(),
        "{}: {:?}",
        view.view,
        read.truncations
    );
    for id in view.checks {
        assert!(
            report::truncation_limitation(corpus_check(id), Some(&read)).is_none(),
            "{}: {id} is withheld over the whole note",
            view.view
        );
    }
}

/// The note of `view` is recorded as an `unread` `notes` truncation naming `says` (among any
/// others the walk records) and withholds each of its checks under `artifact-unreadable`; where
/// `unmarked`, the facts carry no feature of the marking either.
fn assert_withheld(view: &NoteView, says: &str, unmarked: bool) {
    let read = facts(&view.bytes);
    let name = view.view;
    let records: Vec<&str> = read
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Notes && t.kind == elf::TruncationKind::Unread)
        .map(|t| t.detail.as_str())
        .collect();
    assert!(
        records.iter().any(|d| d.contains(says)),
        "{name}: no unread notes record says {says:?}: {records:?}"
    );
    if unmarked {
        assert!(marking(&read, view.machine).1, "{name}, {says}: {read:?}");
    }
    for id in view.checks {
        let gating = report::truncation_limitation(corpus_check(id), Some(&read))
            .unwrap_or_else(|| panic!("{name}, {says}: {id} is not withheld"));
        assert_eq!(
            gating.rule,
            report::gating_rule::ARTIFACT_UNREADABLE,
            "{name}, {says}: {id}"
        );
    }
}

#[test]
fn a_property_note_whose_name_size_is_not_four_withholds_the_marking() {
    let desc = |machine: u16| [marking_property(machine).as_slice(), &[0]].concat();
    for view in property_note_views(|m| property_note(4, 16, b"GNU\0", &desc(m))) {
        assert_marked_whole(&view);
    }
    // The 0 to 3 have their descriptor at 16 and the 5 to 12 at 24, the 12 bytes of header and
    // 5 to 12 bytes of name padded to 8, so their name field is 12 bytes.
    let mut shapes: Vec<(u32, &[u8])> = (0..4).map(|n| (n, &b"GNU\0"[..])).collect();
    for n in [5, 6, 7, 8, 9, 12] {
        shapes.push((n, b"GNU\0\0\0\0\0\0\0\0\0"));
    }
    let mut examined = 0usize;
    for (namesz, name) in &shapes {
        let views = property_note_views(|m| property_note(*namesz, 16, name, &desc(m)));
        for view in &views {
            assert_withheld(view, &format!("n_namesz {namesz},"), true);
            examined += 1;
        }
    }
    assert_eq!(examined, shapes.len() * 5);
}

#[test]
fn a_property_type_note_of_another_name_is_not_kept_at_any_name_size() {
    let desc = |machine: u16| [marking_property(machine).as_slice(), &[0]].concat();
    let mut examined = 0usize;
    let cases = [&b"GNUx"[..], b"GN\0\0", b"gnu\0"]
        .into_iter()
        .flat_map(|name| (0..5).map(move |namesz| (name, namesz)))
        .filter(|&(name, namesz)| !(name == b"GNUx" && namesz == 3));
    for (name, namesz) in cases {
        {
            for view in property_note_views(|m| property_note(namesz, 16, name, &desc(m))) {
                let read = facts(&view.bytes);
                let says = format!("{}: n_namesz {namesz} over {name:?}", view.view);
                assert!(
                    read.unread(&[ElfTable::Notes]).is_none(),
                    "{says}: {:?}",
                    read.truncations
                );
                assert!(marking(&read, view.machine).1, "{says}: {read:?}");
                examined += 1;
            }
        }
    }
    assert_eq!(examined, (3 * 5 - 1) * 5);
}

#[test]
fn an_elf32_property_is_padded_to_four() {
    let note = |descsz: u32| {
        let mut linked = linked_default();
        linked.class64 = false;
        linked.e_machine = 3; // EM_386
        let mut object = linked.object();
        let section = object
            .sections
            .iter_mut()
            .find(|s| s.name == ".note.gnu.property")
            .expect("the builder writes a property note");
        section.content = Content::Bytes(property_note(
            4,
            descsz,
            b"GNU\0",
            &[marking_property(EM_X86_64).as_slice(), &[0]].concat(),
        ));
        NoteView {
            view: "i386 PT_NOTE",
            machine: EM_X86_64,
            checks: &["cet-marked"],
            bytes: object.build(),
        }
    };
    assert_marked_whole(&note(12));
    assert_withheld(
        &note(8),
        "a property's 4-byte data, padded to 4, runs past the descriptor",
        true,
    );
    assert_withheld(
        &note(14),
        "the descriptor's last 2 bytes hold no whole property header",
        false,
    );
}

#[test]
fn a_property_that_does_not_lie_whole_in_its_descriptor_withholds_the_marking() {
    let desc = |machine: u16| [marking_property(machine).as_slice(), &[0, 0, 0]].concat();
    for view in property_note_views(|m| property_note(4, 16, b"GNU\0", &desc(m))) {
        assert_marked_whole(&view);
    }
    // The 20 reads its whole first property before the stop, so its facts carry the marking
    // its checks are withheld over.
    let past = "a property's 4-byte data, padded to 8, runs past the descriptor";
    let tail = "the descriptor's last 4 bytes hold no whole property header";
    let shapes = [
        (8, past, true),
        (12, past, true),
        (20, tail, false),
        (4, tail, true),
    ];
    let mut examined = 0usize;
    for (descsz, says, unmarked) in shapes {
        for view in &property_note_views(|m| property_note(4, descsz, b"GNU\0", &desc(m))) {
            assert_withheld(view, says, unmarked);
            examined += 1;
        }
    }
    assert_eq!(examined, shapes.len() * 5);
}

#[test]
fn a_witness_note_of_another_name_size_is_still_read_as_a_witness() {
    let len = elf::RUN_WITNESS_BYTES;
    let mut note = [
        8u32,
        u32::try_from(len).expect("fits"),
        elf::RUN_WITNESS_TYPE,
    ]
    .map(u32::to_le_bytes)
    .concat();
    note.extend_from_slice(b"chard\0\0\0");
    note.extend(vec![0xb2; len]);
    let read = facts(&with_note_section(
        elf::RUN_WITNESS_SECTION,
        elf_builder::SHT_NOTE,
        &[
            witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, 0xa1, len),
            note,
        ],
    ));
    assert_eq!(
        read.run_witness,
        ["a1".repeat(len), "b2".repeat(len)],
        "the look-alike is counted beside the witness"
    );
}

#[test]
fn a_dynsym_name_carrying_an_at_is_read_whole() {
    let check = corpus_check("canary-emitted");
    let macros = BTreeMap::new();
    let renamed = |dynamic: &'static str, symtab: &'static str| {
        let mut object = linked_default().object();
        for section in &mut object.sections {
            let (from, to) = match section.name {
                ".dynsym" | ".dynstr" => ("__stack_chk_fail", dynamic),
                ".symtab" | ".strtab" => ("__stack_chk_fail@GLIBC_2.4", symtab),
                _ => continue,
            };
            match &mut section.content {
                Content::Symbols(syms) => {
                    for sym in syms.iter_mut().filter(|s| s.name == from) {
                        sym.name = to;
                    }
                }
                Content::Strings(strings) => {
                    for s in strings.iter_mut().filter(|s| **s == from) {
                        *s = to;
                    }
                }
                _ => {}
            }
        }
        facts(&object.build())
    };
    let base = renamed("__stack_chk_fail", "__stack_chk_fail@GLIBC_2.4");
    let canary = base
        .watched_symbols
        .get("__stack_chk_fail")
        .expect("the base program references the canary");
    assert_eq!(canary.tables, [".dynsym", ".symtab"]);
    assert_eq!(
        canary.versioned,
        ["__stack_chk_fail@GLIBC_2.4"],
        "the .symtab spelling alone carries a version"
    );
    let reading = |read: &ElfFacts| {
        assert!(read.truncations.is_empty(), "{:?}", read.truncations);
        assert!(report::truncation_limitation(check, Some(read)).is_none());
        check.decode(&evidence(&macros, read)).detection.outcome
    };
    assert_eq!(reading(&base), Outcome::Present);
    let mut examined = 0usize;
    for (dynamic, says) in [
        ("__stack_chk_fail@xy", "a .dynsym name carrying @"),
        (
            "__stack_chk_fail_xy",
            "the same program, its name spelled without @",
        ),
    ] {
        let read = renamed(dynamic, "chard_other_symbol");
        assert!(
            !read.watched_symbols.contains_key("__stack_chk_fail"),
            "{says}: {:?}",
            read.watched_symbols
        );
        assert_eq!(reading(&read), Outcome::Absent, "{says}");
        examined += 1;
    }
    assert_eq!(examined, 2);
    let symtab_only = renamed("chard_other_symbol", "__stack_chk_fail@xy");
    assert_eq!(
        symtab_only
            .watched_symbols
            .get("__stack_chk_fail")
            .map(|s| s.tables.clone()),
        Some(vec![".symtab".to_owned()]),
        "a .symtab name is still cut at its @"
    );
}

#[test]
fn notes_at_one_descriptor_offset_are_kept_once_and_withheld_where_their_lengths_differ() {
    let region = |short: u32| {
        let mut region = vec![0u8; 64];
        let mut put = |at: usize, bytes: &[u8]| region[at..at + bytes.len()].copy_from_slice(bytes);
        for (at, descsz) in [(0, 32u32), (16, short)] {
            put(at, &[4, descsz, 5].map(u32::to_le_bytes).concat());
            put(at + 12, b"GNU\0");
        }
        put(
            32,
            &[0xc000_0002u32, 4, 3, 0].map(u32::to_le_bytes).concat(),
        );
        put(
            48,
            &[0xc000_8002u32, 4, 1, 0].map(u32::to_le_bytes).concat(),
        );
        region
    };
    // `(start, size, alignment)` of each header's table within the region.
    let (long, short) = ((0, 64, 32u64), (16, 32, 4u64));
    let sections = |region: &[u8], first: (u64, u64, u64), second: (u64, u64, u64)| {
        let mut d = raw_header(1, (0, 0), (64 + 64, 3, 0));
        d.extend_from_slice(region);
        d.extend_from_slice(&[0; SHDR_SIZE]);
        for (start, size, align) in [first, second] {
            let mut header = raw_section(0, 7, (64 + start, size)); // SHT_NOTE
            header[48..56].copy_from_slice(&align.to_le_bytes()); // sh_addralign
            d.extend_from_slice(&header);
        }
        d
    };
    let segments = |region: &[u8], first: (u64, u64, u64), second: (u64, u64, u64)| {
        let at: u64 = 64 + 56 * 2;
        let mut d = raw_header(2, (64, 2), (0, 0, 0));
        for (start, size, align) in [first, second] {
            d.extend_from_slice(&4u32.to_le_bytes()); // PT_NOTE
            d.extend_from_slice(&4u32.to_le_bytes()); // PF_R
            for word in [at + start, 0, 0, size, size, align] {
                d.extend_from_slice(&word.to_le_bytes());
            }
        }
        d.extend_from_slice(region);
        d
    };
    let mut examined = 0usize;
    for view in ["sections", "segments"] {
        let cases = [
            ("long first", long, short, 16, true),
            ("short first", short, long, 16, true),
            ("long first", long, short, 8, true),
            ("short first", short, long, 8, true),
            ("one reading", long, long, 32, false),
        ];
        {
            for (order, first, second, descsz, withheld) in cases {
                let says = format!("{view}, {order}, readings of 32 and {descsz}");
                let bytes = if view == "sections" {
                    sections(&region(descsz), first, second)
                } else {
                    segments(&region(descsz), first, second)
                };
                let elf = elf::Elf::parse(&bytes).expect("the bytes parse");
                let read = elf.facts();
                assert_eq!(elf.notes_kept(), Some(1), "{says}");
                let records: Vec<&str> = read
                    .truncations
                    .iter()
                    .filter(|t| t.table == ElfTable::Notes && t.kind == elf::TruncationKind::Unread)
                    .map(|t| t.detail.as_str())
                    .collect();
                if withheld {
                    assert_eq!(
                        records,
                        [format!(
                            "property note at {:#x}: headers read its descriptor as {descsz:#x} \
                             and 0x20 bytes",
                            if view == "sections" { 96 } else { 208 }
                        )],
                        "{says}"
                    );
                    assert!(!read.x86_ibt && !read.x86_shstk, "{says}: {read:?}");
                    assert!(read.gnu_property_notes.is_empty(), "{says}: {read:?}");
                } else {
                    assert!(records.is_empty(), "{says}: {records:?}");
                    assert!(read.x86_ibt && read.x86_shstk, "{says}: {read:?}");
                    assert_eq!(
                        read.gnu_property_notes.get("0xc0000002"),
                        Some(&1),
                        "{says}: one note"
                    );
                }
                examined += 1;
            }
        }
    }
    assert_eq!(examined, 10);
}

#[test]
fn three_readings_of_one_descriptor_are_withheld() {
    let mut region = vec![0u8; 96];
    let mut put = |at: usize, bytes: &[u8]| region[at..at + bytes.len()].copy_from_slice(bytes);
    for (at, descsz) in [(0, 32u32), (32, 24), (48, 16)] {
        put(at, &[4, descsz, 5].map(u32::to_le_bytes).concat());
        put(at + 12, b"GNU\0");
    }
    put(
        64,
        &[0xc000_8002u32, 4, 1, 0].map(u32::to_le_bytes).concat(),
    );
    put(
        80,
        &[0xc000_0002u32, 4, 3, 0].map(u32::to_le_bytes).concat(),
    );
    let at: u64 = 64 + 56 * 3;
    let mut d = raw_header(2, (64, 3), (0, 0, 0));
    for (start, size, align) in [(0u64, 96u64, 64u64), (32, 56, 32), (48, 32, 4)] {
        d.extend_from_slice(&4u32.to_le_bytes()); // PT_NOTE
        d.extend_from_slice(&4u32.to_le_bytes()); // PF_R
        for word in [at + start, 0, 0, size, size, align] {
            d.extend_from_slice(&word.to_le_bytes());
        }
    }
    d.extend_from_slice(&region);
    let elf = elf::Elf::parse(&d).expect("the bytes parse");
    let read = elf.facts();
    assert_eq!(elf.notes_kept(), Some(1));
    let record = read
        .unread(&[ElfTable::Notes])
        .unwrap_or_else(|| panic!("no unread notes record: {:?}", read.truncations));
    assert!(
        record
            .detail
            .contains("headers read its descriptor as 0x10 and 0x20 bytes"),
        "{}",
        record.detail
    );
    assert!(!read.x86_ibt && !read.x86_shstk, "{read:?}");
}

/// An `ET_EXEC` whose `PT_NOTE` headers climb a ladder of alignments over one region of
/// `notes` 16-byte GNU property note headers, the `m`th declaring `n_descsz` `m % lengths + 1`,
/// and 256 zero bytes after them. For each rung `k` from 1 to `rungs`, `2k` headers at
/// `p_align` `16k` start at each of the first `2k` notes and run to the end. At an alignment of
/// `16k` a note's descriptor starts `16k` bytes after its header and the next note `32k` after
/// it, so each rung reads every note header once, at descriptors `16k` bytes on, and the
/// lengths read at one descriptor offset differ from rung to rung. With `property_segment`
/// an empty `PT_GNU_PROPERTY` comes first, so the notes are the `PT_NOTE` walk's to record.
/// Returns the bytes and the region's offset.
fn alignment_ladder(
    notes: u64,
    rungs: u64,
    lengths: u32,
    property_segment: bool,
) -> (Vec<u8>, u64) {
    let headers = u64::from(property_segment) + rungs * (rungs + 1);
    let phnum = u16::try_from(headers).expect("fits");
    let region = (64 + 56 * headers).next_multiple_of(16);
    let end = region + 16 * notes + 256;
    let mut d = raw_header(2, (64, phnum), (0, 0, 0));
    let mut segment = |p_type: u32, offset: u64, size: u64, p_align: u64| {
        d.extend_from_slice(&p_type.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes()); // PF_R
        for word in [offset, 0, 0, size, size, p_align] {
            d.extend_from_slice(&word.to_le_bytes());
        }
    };
    if property_segment {
        segment(0x6474_e553, region, 0, 8); // PT_GNU_PROPERTY
    }
    for k in 1..=rungs {
        for first in 0..2 * k {
            let offset = region + 16 * first;
            segment(4, offset, end - offset, 16 * k); // PT_NOTE
        }
    }
    d.resize(usize::try_from(region).expect("fits"), 0);
    for m in 0..notes {
        let descsz = u32::try_from(m % u64::from(lengths)).expect("fits") + 1;
        d.extend([4u32, descsz, 5].map(u32::to_le_bytes).concat());
        d.extend_from_slice(b"GNU\0");
    }
    d.resize(usize::try_from(end).expect("fits"), 0);
    (d, region)
}

#[test]
fn note_segments_on_a_ladder_of_alignments_keep_a_note_once_per_descriptor_offset() {
    let (notes, rungs) = (4096u64, 64u64);
    let (bytes, region) = alignment_ladder(notes, rungs, 64, false);
    let steps = (u64::try_from(bytes.len()).expect("fits") - region) / 16;
    let elf = elf::Elf::parse(&bytes).expect("the generator's bytes parse");
    let read = elf.facts();
    // Each walk stops where the zeros after the notes put a descriptor past the segment's end,
    // and that stop is recorded; the budget is not what bounds the notes kept.
    assert!(
        !read
            .truncations
            .iter()
            .any(|t| t.detail.contains("work budget")),
        "{:?}",
        read.truncations.first()
    );
    let kept = elf.notes_kept().expect("a reading sets the count");
    assert!(
        kept >= notes && kept <= steps,
        "{kept} notes kept from {notes} note headers in {steps} 16-byte steps"
    );

    let (bytes, _) = alignment_ladder(notes, rungs, 64, true);
    let (read, _) = read_within_bound(
        "note segments on a ladder of alignments beside PT_GNU_PROPERTY",
        &bytes,
        bytes.len(),
        10,
    );
    assert!(
        read.truncations
            .iter()
            .any(|t| t.table == ElfTable::Notes && t.kind == elf::TruncationKind::Ignored),
        "the notes outside the property segment are recorded"
    );
}

#[test]
fn a_spent_budget_over_kept_property_notes_leaves_one_record_for_the_property_walk() {
    let (headers, notes) = (1000u16, 4000usize);
    let mut one = [4u32, 8, 5].map(u32::to_le_bytes).concat();
    one.extend_from_slice(b"GNU\0");
    one.extend([0xc000_0002u32, 0].map(u32::to_le_bytes).concat());
    let bytes = notes_named_by_every_header(headers, &one.repeat(notes));
    let elf = elf::Elf::parse(&bytes).expect("the generator's bytes parse");
    let read = elf.facts();
    assert!(
        read.unread(&[ElfTable::Notes])
            .is_some_and(|t| t.detail.contains("work budget")),
        "the budget is spent: {:?}",
        read.truncations.first()
    );
    assert_eq!(elf.notes_kept(), Some(u64::try_from(notes).expect("fits")));
    let property_walk = read
        .truncations
        .iter()
        .filter(|t| t.detail.starts_with("property note at"))
        .count();
    assert_eq!(property_walk, 1, "{:?}", read.truncations.last());
    assert!(
        read.truncations.len() <= usize::from(headers) + 8,
        "{} records for {headers} headers",
        read.truncations.len()
    );
}

#[test]
fn property_notes_named_by_every_note_segment_are_recorded_once() {
    let bytes = property_notes_named_by_every_header(50, 1000);
    let (read, _) = read_within_bound(
        "property notes named by every note segment",
        &bytes,
        bytes.len(),
        10,
    );
    let ignored: Vec<_> = read
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Notes && t.kind == elf::TruncationKind::Ignored)
        .collect();
    assert_eq!(ignored.len(), 1, "{ignored:?}");
    assert!(
        ignored[0]
            .detail
            .contains("and 999 more after it lie in a PT_NOTE"),
        "{}",
        ignored[0].detail
    );
    assert!(
        read.unread(&[ElfTable::Notes]).is_none(),
        "{:?}",
        read.truncations
    );

    // One header over one note is a record of that note alone.
    let one = property_notes_named_by_every_header(1, 1);
    let read = elf::Elf::parse(&one).expect("the bytes parse").facts();
    let ignored: Vec<_> = read
        .truncations
        .iter()
        .filter(|t| t.table == ElfTable::Notes && t.kind == elf::TruncationKind::Ignored)
        .collect();
    assert_eq!(ignored.len(), 1, "{ignored:?}");
    assert!(
        ignored[0].detail.contains("+0x0 lies in a PT_NOTE") && !ignored[0].detail.contains("more"),
        "{}",
        ignored[0].detail
    );
}

#[test]
fn aliased_functions_referencing_distinct_long_names_publish_within_the_budget() {
    let (functions, targets, run) = (800u32, 800u32, 10usize);
    let mut strtab = vec![0u8];
    strtab.extend(std::iter::repeat_n(b'a', run + targets as usize));
    strtab.push(0);
    let mut symtab = vec![0u8; 24];
    for _ in 0..functions {
        symtab.extend(raw_symbol(1 + targets, 0x12, 1, (0, 0x100)));
    }
    for j in 0..targets {
        symtab.extend(raw_symbol(1 + j, 0x10, 0, (0, 0)));
    }
    let mut rela = Vec::new();
    for j in 0..targets {
        rela.extend_from_slice(&0x10u64.to_le_bytes());
        rela.extend_from_slice(&((u64::from(1 + functions + j) << 32) | 2).to_le_bytes());
        rela.extend_from_slice(&0i64.to_le_bytes());
    }
    let shstr = b"\0.text\0.symtab\0.strtab\0.rela.text\0.shstrtab\0";
    let n = |name: &str| name_offset(shstr, name);
    let text = [0x90u8; 0x100];
    let bytes = raw_relocatable(&[
        (n(".text"), (1, 6), Ok(&text), (0, 0), 0),
        (n(".symtab"), (2, 0), Ok(&symtab), (3, 1), 24),
        (n(".strtab"), (3, 0), Ok(&strtab), (0, 0), 0),
        (n(".rela.text"), (4, 0x40), Ok(&rela), (2, 1), 24),
        (n(".shstrtab"), (3, 0), Ok(shstr), (0, 0), 0),
    ]);
    let (read, _) = read_within_bound(
        "aliased functions referencing distinct long names",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    let cut = read
        .unread(&[ElfTable::Relocations])
        .expect("the references are recorded unread");
    assert!(cut.detail.contains("work budget"), "{}", cut.detail);
}

#[test]
fn a_symbol_table_under_a_long_name_holding_many_symbols_keeps_a_capped_label() {
    let label = vec![b'S'; 65_000];
    let shstr = [&[0][..], &label, b"\0.strtab\0.shstrtab\0"].concat();
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24];
    for i in 0..4000u32 {
        let name = u32::try_from(strtab.len()).expect("fits");
        strtab.extend(format!("s{i}").bytes());
        strtab.push(0);
        symtab.extend(raw_symbol(name, 0x12, 1, (0, 0)));
    }
    let bytes = raw_relocatable(&[
        (1, (2, 0), Ok(&symtab), (2, 1), 24),
        (
            name_offset(&shstr, ".strtab"),
            (3, 0),
            Ok(&strtab),
            (0, 0),
            0,
        ),
        (
            name_offset(&shstr, ".shstrtab"),
            (3, 0),
            Ok(&shstr),
            (0, 0),
            0,
        ),
    ]);
    let (read, _) = read_within_bound(
        "a symbol table under a long name holding many symbols",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    assert!(
        read.unread(&[ElfTable::Symbols]).is_none(),
        "{:?}",
        read.truncations.first()
    );
    assert_eq!(read.symbol_count, 4000);
}

#[test]
fn one_string_table_under_two_sizes_names_a_relocations_symbol_through_each() {
    let strtab = b"\0__stack_chk_fail\0".to_vec();
    let symtab = [vec![0u8; 24], raw_symbol(1, 0x10, 0, (0, 0))].concat();
    let rela = [
        0u64.to_le_bytes(),
        ((1u64 << 32) | 4).to_le_bytes(),
        0u64.to_le_bytes(),
    ]
    .concat();
    let shstr =
        b"\0.text\0.strtab\0.strtab.cut\0.symtab\0.symtab.cut\0.rela.a\0.rela.b\0.shstrtab\0";
    let n = |name: &str| name_offset(shstr, name);
    let text = [0x90u8; 16];
    for small_first in [true, false] {
        let (first, second) = if small_first { (5, 4) } else { (4, 5) };
        let bytes = raw_relocatable(&[
            (n(".text"), (1, 6), Ok(&text), (0, 0), 0),
            (n(".strtab"), (3, 0), Ok(&strtab), (0, 0), 0),
            (n(".strtab.cut"), (3, 0), Err((1, 4)), (0, 0), 0),
            (n(".symtab"), (2, 0), Ok(&symtab), (2, 1), 24),
            (n(".symtab.cut"), (2, 0), Err((3, 48)), (3, 1), 24),
            (n(".rela.a"), (4, 0x40), Ok(&rela), (first, 1), 24),
            (n(".rela.b"), (4, 0x40), Ok(&rela), (second, 1), 24),
            (n(".shstrtab"), (3, 0), Ok(shstr), (0, 0), 0),
        ]);
        let read = facts(&bytes);
        let listed = read.code_relocations.clone().unwrap_or_default();
        for name in ["__s", "__stack_chk_fail"] {
            assert!(
                listed.iter().any(|r| r.split(' ').nth(1) == Some(name)),
                "small first {small_first}: {name} is not listed in {listed:?}"
            );
        }
    }
}

/// A base-36 spelling of `i`, distinct for every `i`.
fn distinct(mut i: u32) -> String {
    let mut out = String::new();
    loop {
        out.push(char::from_digit(i % 36, 36).expect("a digit"));
        i /= 36;
        if i == 0 {
            return out;
        }
    }
}

#[test]
fn a_comment_section_of_distinct_lines_is_read_whole_in_linear_time() {
    let mut comment = Vec::new();
    for i in 0..300_000u32 {
        comment.extend(distinct(i).bytes());
        comment.push(0);
    }
    let shstr = b"\0.comment\0.shstrtab\0";
    let bytes = raw_relocatable(&[
        (
            name_offset(shstr, ".comment"),
            (1, 0x30),
            Ok(&comment),
            (0, 0),
            1,
        ),
        (
            name_offset(shstr, ".shstrtab"),
            (3, 0),
            Ok(shstr),
            (0, 0),
            0,
        ),
    ]);
    let (read, _) = read_within_bound(
        "a comment section of distinct lines",
        &bytes,
        bytes.len() * 2,
        10,
    );
    assert_eq!(read.comment.len(), 300_000);
    assert!(
        read.comment_truncation().is_none(),
        "{:?}",
        read.truncations
    );
}

#[test]
fn one_symbol_name_under_many_versions_is_read_whole_in_linear_time() {
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24];
    for i in 0..300_000u32 {
        let name = u32::try_from(strtab.len()).expect("fits");
        strtab.extend(format!("f@V{}", distinct(i)).bytes());
        strtab.push(0);
        symtab.extend(raw_symbol(name, 0x12, 0, (0, 0)));
    }
    let shstr = b"\0.symtab\0.strtab\0.shstrtab\0";
    let n = |name: &str| name_offset(shstr, name);
    let bytes = raw_relocatable(&[
        (n(".symtab"), (2, 0), Ok(&symtab), (2, 1), 24),
        (n(".strtab"), (3, 0), Ok(&strtab), (0, 0), 0),
        (n(".shstrtab"), (3, 0), Ok(shstr), (0, 0), 0),
    ]);
    let (read, _) = read_within_bound(
        "one symbol name under many versions",
        &bytes,
        bytes.len() * 2,
        10,
    );
    assert!(
        read.unread(&[ElfTable::Symbols]).is_none(),
        "{:?}",
        read.truncations
    );
    assert_eq!(read.symbol_count, 1);
}

#[test]
fn symbols_naming_one_long_name_spend_the_budget_and_are_recorded() {
    let mut strtab = vec![0u8];
    strtab.extend(std::iter::repeat_n(b'n', 60 << 10));
    strtab.push(0);
    let mut symtab = vec![0u8; 24];
    for _ in 0..4000 {
        symtab.extend(raw_symbol(1, 0x12, 0, (0, 0)));
    }
    let shstr = b"\0.symtab\0.strtab\0.shstrtab\0";
    let n = |name: &str| name_offset(shstr, name);
    let bytes = raw_object(
        2,
        &[
            (n(".symtab"), (2, 0), Ok(&symtab), (2, 1), 24),
            (n(".strtab"), (3, 0), Ok(&strtab), (0, 0), 0),
            (n(".shstrtab"), (3, 0), Ok(shstr), (0, 0), 0),
        ],
    );
    let (read, _) = read_within_bound(
        "symbols naming one long name",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    let cut = read
        .unread(&[ElfTable::Symbols])
        .expect("the symbols are recorded unread");
    assert!(cut.detail.contains("work budget"), "{}", cut.detail);
}

#[test]
fn headers_aliasing_a_table_of_overlong_names_each_pay_for_the_search() {
    let strtab = vec![b'n'; 2 << 16];
    let symtab = [vec![0u8; 24], raw_symbol(0, 0x12, 0, (0, 0))].concat();
    let shstr = b"\0.strtab\0.symtab\0.shstrtab\0";
    let n = |name: &str| name_offset(shstr, name);
    let mut sections: Vec<RawSection<'_>> = vec![
        (n(".strtab"), (3, 0), Ok(&strtab), (0, 0), 0),
        (n(".symtab"), (2, 0), Ok(&symtab), (1, 1), 24),
    ];
    for _ in 0..2000 {
        sections.push((n(".symtab"), (2, 0), Err((1, 48)), (1, 1), 24));
    }
    sections.push((n(".shstrtab"), (3, 0), Ok(shstr), (0, 0), 0));
    let bytes = raw_object(2, &sections);
    let (read, _) = read_within_bound(
        "headers aliasing a table of overlong names",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    assert!(
        read.truncations.iter().any(|t| t.table == ElfTable::Symbols
            && t.kind == elf::TruncationKind::Unread
            && t.detail.contains("work budget")),
        "no symbol table was recorded unread for the budget: {:?}",
        read.truncations.iter().take(3).collect::<Vec<_>>()
    );
}

#[test]
fn headers_sharing_one_long_section_name_copy_a_capped_label() {
    let name = vec![b'L'; 1000];
    let shstr = [&[0][..], &name, b"\0.strtab\0.shstrtab\0"].concat();
    let strtab = b"\0".to_vec();
    let symtab = vec![0u8; 24];
    let mut sections: Vec<RawSection<'_>> = vec![
        (
            name_offset(&shstr, ".strtab"),
            (3, 0),
            Ok(&strtab),
            (0, 0),
            0,
        ),
        (1, (2, 0), Ok(&symtab), (1, 1), 24),
    ];
    for _ in 0..20_000 {
        sections.push((1, (2, 0), Err((1, 24)), (1, 1), 24));
    }
    sections.push((
        name_offset(&shstr, ".shstrtab"),
        (3, 0),
        Ok(&shstr),
        (0, 0),
        0,
    ));
    let bytes = raw_object(2, &sections);
    let (read, _) = read_within_bound(
        "headers sharing one long section name",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    assert!(
        !read.symbol_tables.is_empty(),
        "the symbol tables are read within the budget"
    );
}

#[test]
fn scanned_functions_defined_over_one_section_are_charged_for_each_search() {
    let text = [0x0f_u8, 0x0b].repeat(2 << 20);
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24];
    for scan in elf::code::SCANS {
        let at = u32::try_from(strtab.len()).expect("fits");
        strtab.extend(scan.function.bytes());
        strtab.push(0);
        let size = u64::try_from(text.len()).expect("fits");
        symtab.extend(raw_symbol(at, 0x12, 1, (0, size)));
    }
    let shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    let n = |name: &str| name_offset(shstr, name);
    let bytes = raw_object(
        2,
        &[
            (n(".text"), (1, 6), Ok(&text), (0, 0), 0),
            (n(".symtab"), (2, 0), Ok(&symtab), (3, 1), 24),
            (n(".strtab"), (3, 0), Ok(&strtab), (0, 0), 0),
            (n(".shstrtab"), (3, 0), Ok(shstr), (0, 0), 0),
        ],
    );
    let (read, _) = read_within_bound(
        "scanned functions defined over one section",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    let cut = read
        .unread(&[ElfTable::Code])
        .expect("the code is recorded unread");
    assert!(
        read.truncations
            .iter()
            .any(|t| t.table == ElfTable::Code && t.detail.contains("work budget")),
        "{}",
        cut.detail
    );
}

/// A relocatable object of `functions` aliased functions over one `.text` range, named by the
/// one name at `function_name`, and `relocations` relocations into it through the symbols at
/// `targets` (cycled), each an undefined symbol whose name offset is given; `strtab` holds the
/// names and `headers` relocation headers alias the one relocation section.
fn references(
    (functions, function_name): (u32, u32),
    targets: &[u32],
    (relocations, headers): (u32, u32),
    strtab: &[u8],
) -> Vec<u8> {
    let mut symtab = vec![0u8; 24];
    for _ in 0..functions {
        symtab.extend(raw_symbol(function_name, 0x12, 1, (0, 0x100)));
    }
    for &name in targets {
        symtab.extend(raw_symbol(name, 0x10, 0, (0, 0)));
    }
    let count = u32::try_from(targets.len()).expect("fits");
    let mut rela = Vec::new();
    for r in 0..relocations {
        let symbol = u64::from(1 + functions + r % count);
        rela.extend_from_slice(&0x10u64.to_le_bytes());
        rela.extend_from_slice(&((symbol << 32) | 2).to_le_bytes());
        rela.extend_from_slice(&0i64.to_le_bytes());
    }
    let shstr = b"\0.text\0.symtab\0.strtab\0.rela.text\0.shstrtab\0";
    let n = |name: &str| name_offset(shstr, name);
    let text = [0x90u8; 0x100];
    let rela_size = u64::try_from(rela.len()).expect("fits");
    let mut sections: Vec<RawSection<'_>> = vec![
        (n(".text"), (1, 6), Ok(&text), (0, 0), 0),
        (n(".symtab"), (2, 0), Ok(&symtab), (3, 1), 24),
        (n(".strtab"), (3, 0), Ok(strtab), (0, 0), 0),
        (n(".rela.text"), (4, 0x40), Ok(&rela), (2, 1), 24),
    ];
    for _ in 1..headers {
        sections.push((n(".rela.text"), (4, 0x40), Err((3, rela_size)), (2, 1), 24));
    }
    sections.push((n(".shstrtab"), (3, 0), Ok(shstr), (0, 0), 0));
    raw_relocatable(&sections)
}

#[test]
fn repeated_relocations_through_aliased_functions_are_charged_for_each_range_tried() {
    let strtab = b"\0f\0s\0".to_vec();
    let bytes = references((2000, 1), &[3], (2000, 1), &strtab);
    let (read, _) = read_within_bound(
        "repeated relocations through aliased functions",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    let cut = read
        .unread(&[ElfTable::Relocations])
        .expect("the references are recorded unread");
    assert!(cut.detail.contains("work budget"), "{}", cut.detail);
}

#[test]
fn a_long_function_name_is_charged_in_every_pair_it_is_published_in() {
    let mut strtab = vec![0u8];
    strtab.extend(std::iter::repeat_n(b'F', 2000));
    strtab.push(0);
    let mut targets = Vec::new();
    for i in 0..200u32 {
        targets.push(u32::try_from(strtab.len()).expect("fits"));
        strtab.extend(distinct(i).bytes());
        strtab.push(0);
    }
    let bytes = references((200, 1), &targets, (200, 1), &strtab);
    let (read, _) = read_within_bound(
        "a long function name in every pair",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    assert!(read.unread(&[ElfTable::Relocations]).is_some());
}

#[test]
fn references_through_names_sharing_a_long_prefix_are_found_by_index() {
    let mut strtab = vec![0u8];
    strtab.extend(std::iter::repeat_n(b'a', 500));
    strtab.push(0);
    let targets: Vec<u32> = (0..500).map(|i| 1 + i).collect();
    let bytes = references((1, 1), &targets, (1000, 200), &strtab);
    let (read, _) = read_within_bound(
        "references through names sharing a long prefix",
        &bytes,
        budget_bound(&bytes),
        10,
    );
    assert!(
        read.unread(&[ElfTable::Relocations, ElfTable::Symbols])
            .is_none(),
        "{:?}",
        read.truncations.first()
    );
    assert!(read.function_references.is_some());
}

/// The relocatable base object with a section named `name`, typed `sh_type`, holding
/// `notes` end to end, each as [`note_image`] lays one out.
fn with_note_section(name: &'static str, sh_type: u32, notes: &[Vec<u8>]) -> Vec<u8> {
    let mut object = elf_builder::relocatable();
    object.sections.insert(
        1,
        Section {
            name,
            sh_type,
            flags: SHF_ALLOC,
            addralign: 4,
            entsize: 0,
            link: None,
            info: 0,
            content: Content::Bytes(notes.concat()),
        },
    );
    object.build()
}

/// One note padded to four bytes, as the run's generated header pads the witness whatever
/// the object's class: `namesz`, `descsz` and `type` in the byte order `little` names, the
/// owner and its NUL padded to four bytes, the descriptor padded to four bytes.
fn note_image(owner: &str, ntype: u32, desc: &[u8], little: bool) -> Vec<u8> {
    let word = |value: usize| {
        let value = u32::try_from(value).expect("a small length");
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    };
    let mut note = Vec::new();
    note.extend_from_slice(&word(owner.len() + 1));
    note.extend_from_slice(&word(desc.len()));
    note.extend_from_slice(&word(usize::try_from(ntype).expect("a small type")));
    for field in [owner.as_bytes(), &[0u8][..]] {
        note.extend_from_slice(field);
    }
    note.resize(note.len().next_multiple_of(4), 0);
    note.extend_from_slice(desc);
    note.resize(note.len().next_multiple_of(4), 0);
    note
}

/// A run-witness note as the generated header writes one, with `fill` as each byte of a
/// descriptor `len` long.
fn witness_note(owner: &'static str, ntype: u32, fill: u8, len: usize) -> Vec<u8> {
    note_image(owner, ntype, &vec![fill; len], true)
}

#[test]
fn the_run_witness_is_read_from_its_own_notes_alone() {
    let (owner, ntype, len) = (
        elf::RUN_WITNESS_OWNER,
        elf::RUN_WITNESS_TYPE,
        elf::RUN_WITNESS_BYTES,
    );
    let section = elf::RUN_WITNESS_SECTION;
    let hex = |fill: u8| format!("{fill:02x}").repeat(len);
    let read = |name: &'static str, sh_type: u32, notes: Vec<Vec<u8>>| {
        facts(&with_note_section(name, sh_type, &notes)).run_witness
    };
    let own = |fill: u8| witness_note(owner, ntype, fill, len);

    assert_eq!(
        facts(&elf_builder::relocatable().build()).run_witness,
        Vec::<String>::new(),
        "an object with no witness section carries a witness"
    );
    assert_eq!(
        read(section, elf_builder::SHT_NOTE, vec![own(0xa1)]),
        [hex(0xa1)]
    );
    // Two units of one run: the note twice, one value.
    assert_eq!(
        read(section, elf_builder::SHT_NOTE, vec![own(0xa1), own(0xa1)]),
        [hex(0xa1)]
    );
    // This run's object linked with another's: both, in file order.
    assert_eq!(
        read(
            section,
            elf_builder::SHT_NOTE,
            vec![own(0xb2), own(0xa1), own(0xb2)]
        ),
        [hex(0xb2), hex(0xa1)]
    );

    // Each look-alike, alone and beside a real note it must not hide or join.
    let look_alikes = [
        ("another owner", witness_note("GNU", ntype, 0xcc, len)),
        ("a longer owner", witness_note("chardx", ntype, 0xcc, len)),
        ("another type", witness_note(owner, ntype + 1, 0xcc, len)),
        (
            "a short descriptor",
            witness_note(owner, ntype, 0xcc, len - 1),
        ),
        (
            "a long descriptor",
            witness_note(owner, ntype, 0xcc, len + 1),
        ),
        ("no descriptor", witness_note(owner, ntype, 0xcc, 0)),
    ];
    for (what, note) in look_alikes {
        assert_eq!(
            read(section, elf_builder::SHT_NOTE, vec![note.clone()]),
            Vec::<String>::new(),
            "a note with {what} read as a run witness"
        );
        assert_eq!(
            read(section, elf_builder::SHT_NOTE, vec![note, own(0xa1)]),
            [hex(0xa1)],
            "a note with {what} hid or joined the witness after it"
        );
    }
    assert_eq!(
        read(".note.chard.runs", elf_builder::SHT_NOTE, vec![own(0xa1)]),
        Vec::<String>::new(),
        "a section of a longer name read as the witness section"
    );
    assert_eq!(
        read(".note.chard", elf_builder::SHT_NOTE, vec![own(0xa1)]),
        Vec::<String>::new(),
        "a section of a shorter name read as the witness section"
    );
    assert_eq!(
        read(section, SHT_PROGBITS, vec![own(0xa1)]),
        Vec::<String>::new(),
        "a section of the witness's name that is not a note section read as one"
    );

    // More distinct values than are kept: the first RUN_WITNESSES_KEPT, in order.
    let many: Vec<u8> =
        (1..=u8::try_from(elf::RUN_WITNESSES_KEPT + 3).expect("a small bound")).collect();
    let kept: Vec<String> = many
        .iter()
        .take(elf::RUN_WITNESSES_KEPT)
        .map(|fill| hex(*fill))
        .collect();
    assert_eq!(
        read(
            section,
            elf_builder::SHT_NOTE,
            many.iter().map(|f| own(*f)).collect()
        ),
        kept
    );
}

#[test]
fn the_run_witness_is_read_in_the_files_own_class_and_byte_order() {
    let len = elf::RUN_WITNESS_BYTES;
    let own = note_image(
        elf::RUN_WITNESS_OWNER,
        elf::RUN_WITNESS_TYPE,
        &vec![0xd4; len],
        false,
    );
    let mut big32 = elf_builder::relocatable();
    big32.class64 = false;
    big32.little = false;
    big32.e_machine = elf_builder::EM_PPC;
    big32.sections.retain(|s| s.name != ".note.gnu.property");
    big32.sections.insert(
        1,
        Section {
            name: elf::RUN_WITNESS_SECTION,
            sh_type: elf_builder::SHT_NOTE,
            flags: SHF_ALLOC,
            addralign: 4,
            entsize: 0,
            link: None,
            info: 0,
            content: Content::Bytes(own),
        },
    );
    assert_eq!(facts(&big32.build()).run_witness, ["d4".repeat(len)]);
}

#[test]
fn a_witness_section_cut_after_its_first_note_gives_no_witness() {
    let len = elf::RUN_WITNESS_BYTES;
    let note = |fill: u8| witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, fill, len);
    let mut bytes = with_note_section(
        elf::RUN_WITNESS_SECTION,
        elf_builder::SHT_NOTE,
        &[note(0xa1), note(0xb2)],
    );
    assert_eq!(
        facts(&bytes).run_witness,
        ["a1".repeat(len), "b2".repeat(len)],
        "the whole file does not read both notes, so the cut shows nothing"
    );
    // The second note's `descsz`, the word eight bytes before its owner's name.
    let second = bytes
        .windows(len)
        .position(|w| w == vec![0xb2; len].as_slice())
        .expect("the second note's descriptor is in the file");
    let owner = bytes[..second]
        .windows(6)
        .rposition(|w| w == b"chard\0")
        .expect("the second note's owner precedes its descriptor");
    bytes[owner - 8..owner - 4].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
    let cut = facts(&bytes);
    assert_eq!(
        cut.run_witness,
        Vec::<String>::new(),
        "a section the reader stopped in still lists its first note"
    );
    // The section's name was read, so the empty list is the stop's doing.
    assert!(
        cut.sections.iter().any(|s| s == elf::RUN_WITNESS_SECTION),
        "{:?}",
        cut.sections
    );
}

/// An allocated note section for the run-witness tests, aligned to `addralign`.
fn note_section(name: &'static str, addralign: u64, bytes: Vec<u8>) -> Section {
    Section {
        name,
        sh_type: elf_builder::SHT_NOTE,
        flags: SHF_ALLOC,
        addralign,
        entsize: 0,
        link: None,
        info: 0,
        content: Content::Bytes(bytes),
    }
}

/// A `PT_NOTE` segment over `covers`, at alignment `align`.
fn note_segment(align: u64, covers: Covers) -> Segment {
    Segment {
        p_type: PT_NOTE,
        flags: PF_R,
        align,
        covers,
    }
}

#[test]
fn the_witness_is_read_at_four_bytes_in_a_segment_aligned_to_eight() {
    let len = elf::RUN_WITNESS_BYTES;
    let notes = [
        (
            ".note.gnu.property",
            8,
            note_image("GNU", 5, &[0; 0x30], true),
        ),
        (
            ".note.ABI-tag",
            4,
            note_image("GNU", 1, &[0x3a; 0x10], true),
        ),
        (
            elf::RUN_WITNESS_SECTION,
            4,
            witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, 0xa1, len),
        ),
        (
            ".note.gnu.build-id",
            4,
            note_image("GNU", 3, &[0x5b; 0x14], true),
        ),
    ];
    assert_eq!(
        notes.iter().map(|(_, _, n)| n.len()).collect::<Vec<_>>(),
        [0x40, 0x20, 0x24, 0x24],
        "the notes are not mold's sizes"
    );
    let mut object = elf_builder::relocatable();
    object.sections.retain(|s| s.name != ".note.gnu.property");
    for (at, (name, align, note)) in notes.into_iter().enumerate() {
        object
            .sections
            .insert(1 + at, note_section(name, align, note));
    }
    object.segments.push(note_segment(
        8,
        Covers::Sections(".note.gnu.property", ".note.gnu.build-id"),
    ));
    assert_eq!(
        facts(&object.build()).run_witness,
        ["a1".repeat(len)],
        "the witness section, beside mold's segment of alignment 8, is not read as the one nonce"
    );
    object.strip_section_headers = true;
    let stripped = facts(&object.build());
    assert!(
        stripped.sections.is_empty(),
        "the file still shows sections, so the segment was not what was read: {:?}",
        stripped.sections
    );
    assert_eq!(
        stripped.run_witness,
        ["a1".repeat(len)],
        "mold's note segment, read where no section shows, is not read as the one nonce"
    );
}

#[test]
fn a_witness_section_shadows_a_segment_that_holds_another_value() {
    let len = elf::RUN_WITNESS_BYTES;
    let own = |fill: u8| witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, fill, len);
    let mut object = elf_builder::relocatable();
    object
        .sections
        .insert(1, note_section(elf::RUN_WITNESS_SECTION, 4, own(0xa1)));
    object
        .sections
        .insert(2, note_section(".note.relabelled", 4, own(0xb2)));
    object
        .segments
        .push(note_segment(4, Covers::Section(".note.relabelled")));
    assert_eq!(
        facts(&object.build()).run_witness,
        ["a1".repeat(len)],
        "a segment was read beside the witness section"
    );
    let mut unnamed = object.clone();
    unnamed
        .sections
        .retain(|s| s.name != elf::RUN_WITNESS_SECTION);
    assert_eq!(
        facts(&unnamed.build()).run_witness,
        ["b2".repeat(len)],
        "the segment is not read beside a note section of another name, so the test shows nothing"
    );
    object.strip_section_headers = true;
    assert_eq!(
        facts(&object.build()).run_witness,
        ["b2".repeat(len)],
        "the segment's note is not readable where no section shows, so the test shows nothing"
    );
}

#[test]
fn an_empty_witness_section_beside_a_segment_gives_no_witness() {
    let len = elf::RUN_WITNESS_BYTES;
    let mut object = elf_builder::relocatable();
    object.sections.insert(
        1,
        note_section(
            ".note.relabelled",
            4,
            witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, 0xa1, len),
        ),
    );
    object
        .segments
        .push(note_segment(4, Covers::Section(".note.relabelled")));
    assert_eq!(
        facts(&object.build()).run_witness,
        ["a1".repeat(len)],
        "the segment is not read where no witness section shows, so the test shows nothing"
    );
    object
        .sections
        .insert(1, note_section(elf::RUN_WITNESS_SECTION, 4, Vec::new()));
    let shadowed = facts(&object.build());
    assert!(
        shadowed
            .sections
            .iter()
            .any(|s| s == elf::RUN_WITNESS_SECTION),
        "{:?}",
        shadowed.sections
    );
    assert_eq!(
        shadowed.run_witness,
        Vec::<String>::new(),
        "an empty witness section let the segment beside it confirm the artifact"
    );
}

/// The bytes of a note whose descriptor runs past the end of any table it is walked in.
fn cut_note() -> Vec<u8> {
    let mut cut = Vec::new();
    for word in [4u32, 0x00ff_ffff, 3] {
        cut.extend_from_slice(&word.to_le_bytes());
    }
    cut.extend_from_slice(b"GNU\0");
    cut
}

#[test]
fn a_stop_in_a_segment_keeps_the_witness_read_before_it() {
    let len = elf::RUN_WITNESS_BYTES;
    let own = |fill: u8| witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, fill, len);
    let bytes = [own(0xa1), cut_note(), own(0xb2)].concat();
    let mut object = elf_builder::relocatable();
    object
        .sections
        .insert(1, note_section(".note.relabelled", 4, bytes));
    object
        .segments
        .push(note_segment(4, Covers::Section(".note.relabelled")));
    let read = facts(&object.build());
    assert!(
        !read.sections.iter().any(|s| s == elf::RUN_WITNESS_SECTION),
        "{:?}",
        read.sections
    );
    assert_eq!(
        read.run_witness,
        ["a1".repeat(len)],
        "a stop in a segment emptied the witness read before it, or a note after it was read"
    );
}

#[test]
fn a_witness_section_declared_at_eight_is_walked_at_four_bytes() {
    let len = elf::RUN_WITNESS_BYTES;
    let own = |fill: u8| witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, fill, len);
    let mut object = elf_builder::relocatable();
    object.sections.insert(
        1,
        note_section(elf::RUN_WITNESS_SECTION, 8, [own(0xa1), own(0xb2)].concat()),
    );
    assert_eq!(
        facts(&object.build()).run_witness,
        ["a1".repeat(len), "b2".repeat(len)],
        "a witness section declared at 8 is not walked at four bytes"
    );
}

#[test]
fn only_note_segments_are_read_for_the_witness() {
    let len = elf::RUN_WITNESS_BYTES;
    let own = |fill: u8| witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, fill, len);
    let mut object = elf_builder::relocatable();
    object
        .sections
        .insert(1, note_section(".note.relabelled", 4, own(0xa1)));
    let mut data = note_section(".data.relabelled", 4, own(0xb2));
    data.sh_type = SHT_PROGBITS;
    object.sections.insert(2, data);
    object
        .segments
        .push(note_segment(4, Covers::Section(".note.relabelled")));
    object.segments.push(Segment {
        p_type: PT_LOAD,
        flags: PF_R,
        align: 4,
        covers: Covers::Section(".data.relabelled"),
    });
    assert_eq!(
        facts(&object.build()).run_witness,
        ["a1".repeat(len)],
        "a segment that is not a note segment was read for the witness"
    );
}

#[test]
fn every_note_segment_is_read_where_no_witness_section_shows() {
    let len = elf::RUN_WITNESS_BYTES;
    let own = |fill: u8| witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, fill, len);
    let mut object = elf_builder::relocatable();
    object
        .sections
        .insert(1, note_section(".note.first", 4, own(0xa1)));
    object
        .sections
        .insert(2, note_section(".note.second", 4, own(0xb2)));
    for name in [".note.first", ".note.second"] {
        object.segments.push(note_segment(4, Covers::Section(name)));
    }
    assert_eq!(
        facts(&object.build()).run_witness,
        ["a1".repeat(len), "b2".repeat(len)],
        "a note segment was not read, or the segments were not read in file order"
    );
}

#[test]
fn every_witness_section_is_read_and_a_stop_in_one_empties_the_list() {
    let len = elf::RUN_WITNESS_BYTES;
    let own = |fill: u8| witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, fill, len);
    let two = |first: Vec<u8>, second: Vec<u8>| {
        let mut object = elf_builder::relocatable();
        object
            .sections
            .insert(1, note_section(elf::RUN_WITNESS_SECTION, 4, first));
        object
            .sections
            .insert(2, note_section(elf::RUN_WITNESS_SECTION, 4, second));
        facts(&object.build()).run_witness
    };
    assert_eq!(
        two(own(0xb2), own(0xa1)),
        ["b2".repeat(len), "a1".repeat(len)],
        "a second section of the witness's name was not read"
    );
    for (what, cut) in [
        ("after its note", [own(0xa1), cut_note()].concat()),
        ("before any note", cut_note()),
    ] {
        assert_eq!(
            two(cut.clone(), own(0xa1)),
            Vec::<String>::new(),
            "a stop {what} in the first witness section was passed over and the second confirmed the file"
        );
        assert_eq!(
            two(own(0xa1), cut),
            Vec::<String>::new(),
            "a stop {what} in the second witness section was passed over and the first confirmed the file"
        );
    }
}

#[test]
fn a_stop_in_one_note_segment_leaves_the_next_segment_read() {
    let len = elf::RUN_WITNESS_BYTES;
    let witness = || witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, 0xa1, len);
    for (what, first, second) in [
        ("after", cut_note(), witness()),
        ("before", witness(), cut_note()),
    ] {
        let mut object = elf_builder::relocatable();
        object
            .sections
            .insert(1, note_section(".note.first", 4, first));
        object
            .sections
            .insert(2, note_section(".note.second", 4, second));
        for name in [".note.first", ".note.second"] {
            object.segments.push(note_segment(4, Covers::Section(name)));
        }
        assert_eq!(
            facts(&object.build()).run_witness,
            ["a1".repeat(len)],
            "a stop in one note segment lost the witness in the segment {what} it"
        );
    }
}

#[test]
fn the_witness_is_read_before_a_walk_that_spends_the_budget() {
    let len = elf::RUN_WITNESS_BYTES;
    let mut region = witness_note(elf::RUN_WITNESS_OWNER, elf::RUN_WITNESS_TYPE, 0xa1, len);
    region.resize(region.len() + 65_536, 0);
    let headers: u16 = 4000;
    let phnum = headers + 1;
    let at = (64 + 56 * u64::from(phnum)).next_multiple_of(8);
    let size = u64::try_from(region.len()).expect("fits");
    let mut d = raw_header(2, (64, phnum), (0, 0, 0));
    let mut segment = |p_type: u32, p_align: u64, size: u64| {
        d.extend_from_slice(&p_type.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes()); // PF_R
        for word in [at, 0, 0, size, size, p_align] {
            d.extend_from_slice(&word.to_le_bytes());
        }
    };
    segment(0x6474_e553, 8, 0); // PT_GNU_PROPERTY
    for _ in 0..headers {
        segment(PT_NOTE, 4, size);
    }
    d.resize(usize::try_from(at).expect("fits"), 0);
    d.extend_from_slice(&region);
    let elf = elf::Elf::parse(&d).expect("the bytes parse");
    let read = elf.facts();
    assert!(
        read.truncations
            .iter()
            .any(|t| t.detail.contains("run-witness notes were not all read")
                && t.detail.contains("work budget")),
        "the witness walk did not spend and record the budget: {:?}",
        read.truncations.first()
    );
    assert_eq!(
        read.run_witness,
        ["a1".repeat(len)],
        "the witness, first in the first segment, was not read before the budget was spent"
    );
}
