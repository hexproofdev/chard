// SPDX-License-Identifier: BSD-3-Clause

//! A builder for the synthetic ELF objects under `tests/fixtures/elf/`, and the
//! catalogue of what is built.
//!
//! Every fixture the reader is pinned against comes from here, so the bytes checked in
//! and the code that made them cannot drift apart: `tests/elf_fixtures.rs` asserts the
//! two are equal on every run and rewrites the files only under
//! `CHARD_REGENERATE_ELF_FIXTURES=1`. The objects are synthetic and labelled so in the
//! record beside each one. They are not the output of any linker, and a fact that only a
//! linker could get wrong is not what they pin; what they pin is the reader's arithmetic
//! over the two widths, the two byte orders, the object types and the three spellings of
//! `BIND_NOW`, on inputs no compiler on a given host can be asked to produce.
//!
//! The layout is the plainest one `readelf` accepts: the ELF header, the program headers,
//! every section's bytes in declaration order at its own alignment, then the
//! section-header table, with one `PT_LOAD` mapping the whole file at `base` so a virtual
//! address is a file offset plus `base`. Shared between `tests/elf_fixtures.rs` and
//! `tests/elf_readelf.rs` as a directory module for the reason `tests/common` gives: a
//! builder in two copies is a builder that disagrees with itself.
//!
//! A note writer that padded the owner name as `12 + align_up(namesz, align)` would make
//! the off-by-four `src/elf.rs`'s header names as the one rule that must not be got wrong,
//! and `llvm-readelf -n` would report the property note corrupt before any test of the
//! reader did. An oracle earns its keep on the fixture before it earns it on the
//! reader, which is the argument for `tests/elf_readelf.rs` running over these files.

// Each test binary that declares this module uses a different subset of it.
#![allow(dead_code)]

pub mod generate;

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_386: u16 = 3;
pub const EM_PPC: u16 = 20;
pub const EM_PPC64: u16 = 21;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_REL: u32 = 9;

pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
/// `sh_info` holds a section index, as a relocation section's names the section it patches.
pub const SHF_INFO_LINK: u64 = 0x40;

pub const DT_NEEDED: i64 = 1;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_RELRSZ: i64 = 35;
pub const DT_RELR: i64 = 36;
pub const DT_RELRENT: i64 = 37;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;

pub const DF_TEXTREL: u64 = 0x4;
pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_1_NOW: u64 = 0x1;
pub const DF_1_NOOPEN: u64 = 0x40;
pub const DF_1_PIE: u64 = 0x0800_0000;

pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
pub const X86_FEATURE_1_IBT: u32 = 0x1;
pub const X86_FEATURE_1_SHSTK: u32 = 0x2;
pub const AARCH64_FEATURE_1_BTI: u32 = 0x1;
pub const AARCH64_FEATURE_1_PAC: u32 = 0x2;

/// A value in `.dynamic`, resolved once the layout is known.
#[derive(Clone, Debug)]
pub enum DynValue {
    Const(u64),
    /// The virtual address of the named section.
    AddrOf(&'static str),
    /// The size in bytes of the named section.
    SizeOf(&'static str),
    /// The offset of `string` in the named string table.
    StrOff(&'static str, &'static str),
}

/// One symbol-table entry.
#[derive(Clone, Debug)]
pub struct Symbol {
    /// As the table stores it. `.strtab` may spell a version into it.
    pub name: &'static str,
    /// The section that defines it; `None` is `SHN_UNDEF`.
    pub defined_in: Option<&'static str>,
    /// `st_other`, whose low two bits are the visibility; 0 is `STV_DEFAULT`.
    pub st_other: u8,
}

/// A function an object defines: placed at `offset` into `section`, `size` bytes long. In
/// a relocatable object `.symtab` holds `st_value` as that offset; in a linked one, as the
/// section's address plus it, which is how a linker writes the entry.
#[derive(Clone, Debug)]
pub struct Function {
    pub name: &'static str,
    pub section: &'static str,
    pub offset: u64,
    pub size: u64,
}

/// One relocation entry, written as `Elf64_Rela` or as `Elf32_Rel`/`Elf64_Rel`: a
/// reference at `offset` into the section the relocation section's `sh_info` names, to
/// `symbol`, which the linked symbol table holds.
#[derive(Clone, Debug)]
pub struct Rela {
    pub offset: u64,
    pub symbol: &'static str,
    pub r_type: u32,
}

/// One note in an `SHT_NOTE` section.
#[derive(Clone, Debug)]
pub struct NoteSpec {
    pub owner: &'static str,
    pub ntype: u32,
    pub desc: Vec<u8>,
}

/// What a section holds.
#[derive(Clone, Debug)]
pub enum Content {
    Bytes(Vec<u8>),
    /// A string table: a leading NUL, then each string NUL-terminated.
    Strings(Vec<&'static str>),
    /// `(tag, value)` pairs; `DT_NULL` is appended.
    Dynamic(Vec<(i64, DynValue)>),
    /// A symbol table whose names live in the linked string table; the null symbol is
    /// prepended.
    Symbols(Vec<Symbol>),
    /// An object's symbol table: the null symbol, each function (`STT_FUNC`, sized, at
    /// its offset or, in a linked object, its address), then each undefined name.
    ObjectSymbols {
        functions: Vec<Function>,
        undefined: Vec<&'static str>,
    },
    /// `Elf64_Rela` entries against the linked `ObjectSymbols` table. ELF64 only.
    Rela(Vec<Rela>),
    /// `Elf32_Rel` or `Elf64_Rel` entries, by the object's class, against the linked
    /// `ObjectSymbols` table: no addend, and in ELF32 the symbol index in `r_info`'s
    /// upper 24 bits.
    Rel(Vec<Rela>),
    Notes(Vec<NoteSpec>),
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: &'static str,
    pub sh_type: u32,
    pub flags: u64,
    pub addralign: u64,
    pub entsize: u64,
    /// `sh_link`, by section name.
    pub link: Option<&'static str>,
    pub info: u32,
    pub content: Content,
}

/// What a program header covers.
#[derive(Clone, Debug)]
pub enum Covers {
    /// The whole file, from offset 0.
    File,
    /// One section's bytes.
    Section(&'static str),
    /// Nothing: offset, address and size all zero (`PT_GNU_STACK`).
    Nothing,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub p_type: u32,
    pub flags: u32,
    pub align: u64,
    pub covers: Covers,
}

/// An object to build.
#[derive(Clone, Debug)]
pub struct Object {
    pub class64: bool,
    pub little: bool,
    pub e_type: u16,
    pub e_machine: u16,
    /// Virtual address of file offset 0.
    pub base: u64,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    /// Write `e_shoff = 0`, `e_shnum = 0`, `e_shstrndx = 0` and stop the file before the
    /// section-header table, as `objcopy --strip-section-headers` does.
    pub strip_section_headers: bool,
    /// Write the section-header table straight after the program headers, before any
    /// section's bytes, rather than last. A file cut short then keeps every header and
    /// loses section contents, which is what reaches the reader's recording sites: cut
    /// with the table last, the parse refuses the file outright. `false` in every
    /// catalogue object, so no fixture's bytes move.
    pub section_headers_first: bool,
}

/// A byte sink that writes in the object's byte order and width.
struct Out {
    buf: Vec<u8>,
    little: bool,
    class64: bool,
}

impl Out {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        let b = if self.little {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.buf.extend_from_slice(&b);
    }
    fn u32(&mut self, v: u32) {
        let b = if self.little {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.buf.extend_from_slice(&b);
    }
    fn u64(&mut self, v: u64) {
        let b = if self.little {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.buf.extend_from_slice(&b);
    }
    /// An address, offset or size: 8 bytes on ELF64, 4 on ELF32.
    fn addr(&mut self, v: u64) {
        if self.class64 {
            self.u64(v);
        } else {
            self.u32(u32::try_from(v).expect("an ELF32 value fits 32 bits"));
        }
    }
    fn pad_to(&mut self, off: usize) {
        assert!(self.buf.len() <= off, "layout wrote past {off}");
        self.buf.resize(off, 0);
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 { v } else { v.div_ceil(a) * a }
}

/// A file offset or size as a buffer index. Every value here is a few kilobytes.
fn us(v: u64) -> usize {
    usize::try_from(v).expect("a fixture offset fits in usize")
}

fn u64_of(v: usize) -> u64 {
    u64::try_from(v).expect("a fixture length fits in u64")
}

fn u32_of(v: usize) -> u32 {
    u32::try_from(v).expect("a fixture length fits in u32")
}

fn strtab_bytes(strings: &[&str]) -> Vec<u8> {
    let mut b = vec![0u8];
    for s in strings {
        b.extend_from_slice(s.as_bytes());
        b.push(0);
    }
    b
}

/// The offset of `s` in a table built by `strtab_bytes`, as a whole string.
fn strtab_offset(strings: &[&str], s: &str) -> u32 {
    // The empty name is the table's leading NUL, which every string table has.
    if s.is_empty() {
        return 0;
    }
    let mut off = 1u32;
    for candidate in strings {
        if *candidate == s {
            return off;
        }
        off += u32_of(candidate.len() + 1);
    }
    panic!("{s:?} is not in the string table {strings:?}");
}

/// The offsets a layout pass settled on.
struct Layout {
    offsets: Vec<u64>,
    sizes: Vec<u64>,
    shoff: u64,
    shnum: u64,
    file_end: u64,
}

impl Object {
    fn ehsize(&self) -> u64 {
        if self.class64 { 64 } else { 52 }
    }
    fn phentsize(&self) -> u64 {
        if self.class64 { 56 } else { 32 }
    }
    fn shentsize(&self) -> u64 {
        if self.class64 { 64 } else { 40 }
    }
    fn symsize(&self) -> u64 {
        if self.class64 { 24 } else { 16 }
    }
    fn dynsize(&self) -> u64 {
        if self.class64 { 16 } else { 8 }
    }
    /// The alignment a GNU note carries in this class.
    pub fn note_align(&self) -> u64 {
        if self.class64 { 8 } else { 4 }
    }

    fn section_index(&self, name: &str) -> usize {
        self.sections
            .iter()
            .position(|s| s.name == name)
            .map_or_else(|| panic!("no section named {name:?}"), |i| i + 1)
    }

    fn strings_of(&self, name: &str) -> &[&'static str] {
        match &self.sections[self.section_index(name) - 1].content {
            Content::Strings(v) => v,
            other => panic!("{name:?} is not a string table: {other:?}"),
        }
    }

    fn section_size(&self, s: &Section) -> u64 {
        match &s.content {
            Content::Bytes(b) => u64_of(b.len()),
            Content::Strings(v) => u64_of(strtab_bytes(v).len()),
            Content::Dynamic(entries) => (u64_of(entries.len()) + 1) * self.dynsize(),
            Content::Symbols(syms) => (u64_of(syms.len()) + 1) * self.symsize(),
            Content::ObjectSymbols {
                functions,
                undefined,
            } => (u64_of(functions.len() + undefined.len()) + 1) * self.symsize(),
            // Three words of the class: `r_offset`, `r_info` and `r_addend`.
            Content::Rela(entries) => u64_of(entries.len()) * if self.class64 { 24 } else { 12 },
            // Two words of the class: `r_offset` and `r_info`.
            Content::Rel(entries) => u64_of(entries.len()) * if self.class64 { 16 } else { 8 },
            // The descriptor begins at `align_up(12 + namesz, align)` from the note's
            // start: absolute, as the module header records.
            Content::Notes(notes) => notes
                .iter()
                .map(|n| {
                    align_up(12 + u64_of(n.owner.len()) + 1, self.note_align())
                        + align_up(u64_of(n.desc.len()), self.note_align())
                })
                .sum(),
        }
    }

    /// Serialise to bytes. `.shstrtab` is appended by this function.
    pub fn build(&self) -> Vec<u8> {
        let mut obj = self.clone();
        let mut names: Vec<&'static str> = obj.sections.iter().map(|s| s.name).collect();
        names.push(".shstrtab");
        obj.sections.push(Section {
            name: ".shstrtab",
            sh_type: SHT_STRTAB,
            flags: 0,
            addralign: 1,
            entsize: 0,
            link: None,
            info: 0,
            content: Content::Strings(names),
        });
        obj.serialise()
    }

    fn serialise(&self) -> Vec<u8> {
        let layout = self.layout();
        let mut out = Out {
            buf: Vec::with_capacity(us(layout.file_end)),
            little: self.little,
            class64: self.class64,
        };
        self.write_header(&mut out, &layout);
        self.write_phdrs(&mut out, &layout);
        if self.section_headers_first && !self.strip_section_headers {
            out.pad_to(us(layout.shoff));
            self.write_shdrs(&mut out, &layout);
        }
        for (i, s) in self.sections.iter().enumerate() {
            out.pad_to(us(layout.offsets[i]));
            self.write_section(&mut out, &layout, s);
            assert_eq!(
                u64_of(out.buf.len()),
                layout.offsets[i] + layout.sizes[i],
                "section {} wrote a different size than it declared",
                s.name
            );
        }
        if self.strip_section_headers || self.section_headers_first {
            out.pad_to(us(layout.file_end));
            return out.buf;
        }
        out.pad_to(us(layout.shoff));
        self.write_shdrs(&mut out, &layout);
        assert_eq!(u64_of(out.buf.len()), layout.file_end);
        out.buf
    }

    /// Where everything lands.
    fn layout(&self) -> Layout {
        let phnum = u64_of(self.segments.len());
        let shnum = u64_of(self.sections.len()) + 1;
        let mut off = self.ehsize() + phnum * self.phentsize();
        let early_shoff = align_up(off, 8);
        if self.section_headers_first && !self.strip_section_headers {
            off = early_shoff + shnum * self.shentsize();
        }
        let mut offsets = Vec::new();
        let mut sizes = Vec::new();
        for s in &self.sections {
            off = align_up(off, s.addralign.max(1));
            offsets.push(off);
            let size = self.section_size(s);
            sizes.push(size);
            off += size;
        }
        let (shoff, file_end) = if self.strip_section_headers {
            (align_up(off, 8), off)
        } else if self.section_headers_first {
            (early_shoff, off)
        } else {
            let shoff = align_up(off, 8);
            (shoff, shoff + shnum * self.shentsize())
        };
        Layout {
            offsets,
            sizes,
            shoff,
            shnum,
            file_end,
        }
    }

    fn offset_of(&self, layout: &Layout, name: &str) -> u64 {
        layout.offsets[self.section_index(name) - 1]
    }

    fn size_of(&self, layout: &Layout, name: &str) -> u64 {
        layout.sizes[self.section_index(name) - 1]
    }

    fn addr_of(&self, layout: &Layout, name: &str) -> u64 {
        self.base + self.offset_of(layout, name)
    }

    fn write_header(&self, out: &mut Out, layout: &Layout) {
        let phnum = u64_of(self.segments.len());
        out.buf.extend_from_slice(b"\x7fELF");
        out.u8(if self.class64 { 2 } else { 1 });
        out.u8(if self.little { 1 } else { 2 });
        out.u8(1); // EI_VERSION
        out.u8(0); // EI_OSABI: SYSV
        out.buf.extend_from_slice(&[0u8; 8]);
        out.u16(self.e_type);
        out.u16(self.e_machine);
        out.u32(1); // e_version
        let entry = if self.sections.iter().any(|s| s.name == ".text") {
            self.addr_of(layout, ".text")
        } else {
            0
        };
        out.addr(entry);
        out.addr(if phnum > 0 { self.ehsize() } else { 0 });
        out.addr(if self.strip_section_headers {
            0
        } else {
            layout.shoff
        });
        out.u32(0); // e_flags
        out.u16(u16::try_from(self.ehsize()).expect("fits"));
        out.u16(u16::try_from(self.phentsize()).expect("fits"));
        out.u16(u16::try_from(phnum).expect("fits"));
        out.u16(u16::try_from(self.shentsize()).expect("fits"));
        if self.strip_section_headers {
            out.u16(0);
            out.u16(0);
        } else {
            out.u16(u16::try_from(layout.shnum).expect("fits"));
            // Last in every catalogue object, and wherever `generate` shuffled it.
            out.u16(u16::try_from(self.section_index(".shstrtab")).expect("fits"));
        }
        assert_eq!(u64_of(out.buf.len()), self.ehsize());
    }

    fn write_phdrs(&self, out: &mut Out, layout: &Layout) {
        for seg in &self.segments {
            let (p_offset, p_vaddr, p_filesz) = match &seg.covers {
                Covers::File => (0, self.base, layout.file_end),
                Covers::Section(name) => (
                    self.offset_of(layout, name),
                    self.addr_of(layout, name),
                    self.size_of(layout, name),
                ),
                Covers::Nothing => (0, 0, 0),
            };
            out.u32(seg.p_type);
            if self.class64 {
                out.u32(seg.flags);
                out.u64(p_offset);
                out.u64(p_vaddr);
                out.u64(p_vaddr); // p_paddr
                out.u64(p_filesz);
                out.u64(p_filesz); // p_memsz
                out.u64(seg.align);
            } else {
                out.addr(p_offset);
                out.addr(p_vaddr);
                out.addr(p_vaddr);
                out.addr(p_filesz);
                out.addr(p_filesz);
                out.u32(seg.flags);
                out.addr(seg.align);
            }
        }
    }

    fn write_section(&self, out: &mut Out, layout: &Layout, s: &Section) {
        match &s.content {
            Content::Bytes(b) => out.buf.extend_from_slice(b),
            Content::Strings(v) => out.buf.extend_from_slice(&strtab_bytes(v)),
            Content::Dynamic(entries) => {
                for (tag, value) in entries {
                    let v = match value {
                        DynValue::Const(c) => *c,
                        DynValue::AddrOf(name) => self.addr_of(layout, name),
                        DynValue::SizeOf(name) => self.size_of(layout, name),
                        DynValue::StrOff(table, string) => {
                            u64::from(strtab_offset(self.strings_of(table), string))
                        }
                    };
                    out.addr(u64::try_from(*tag).expect("no negative tag is written"));
                    out.addr(v);
                }
                out.addr(0);
                out.addr(0);
            }
            Content::Symbols(syms) => self.write_symbols(out, layout, s, syms),
            Content::ObjectSymbols {
                functions,
                undefined,
            } => self.write_object_symbols(out, layout, s, functions, undefined),
            Content::Rela(entries) => self.write_rela(out, s, entries),
            Content::Rel(entries) => self.write_rel(out, s, entries),
            Content::Notes(notes) => {
                let align = self.note_align();
                for n in notes {
                    let namesz = u64_of(n.owner.len()) + 1;
                    let note_start = out.buf.len();
                    out.u32(u32::try_from(namesz).expect("fits"));
                    out.u32(u32_of(n.desc.len()));
                    out.u32(n.ntype);
                    out.buf.extend_from_slice(n.owner.as_bytes());
                    out.u8(0);
                    // Absolute, from the note's own start: see `section_size`.
                    out.pad_to(note_start + us(align_up(12 + namesz, align)));
                    let dstart = out.buf.len();
                    out.buf.extend_from_slice(&n.desc);
                    out.pad_to(dstart + us(align_up(u64_of(n.desc.len()), align)));
                }
            }
        }
    }

    fn write_symbols(&self, out: &mut Out, layout: &Layout, s: &Section, syms: &[Symbol]) {
        let table = s.link.expect("a symbol table links its string table");
        let strings = self.strings_of(table);
        // The null symbol.
        out.buf.extend(std::iter::repeat_n(0u8, us(self.symsize())));
        for sym in syms {
            let st_name = strtab_offset(strings, sym.name);
            let (shndx, value) = match sym.defined_in {
                Some(sec) => (
                    u16::try_from(self.section_index(sec)).expect("fits"),
                    self.addr_of(layout, sec),
                ),
                None => (0, 0),
            };
            let st_info: u8 = match (sym.name.is_empty(), sym.defined_in.is_some()) {
                // An unnamed defined symbol is the section's own, as a compiler writes
                // for a reference to local data ([`with_section_symbol_relocation`]).
                (true, true) => 0x03,  // STB_LOCAL, STT_SECTION
                (false, true) => 0x12, // STB_GLOBAL, STT_FUNC
                (_, false) => 0x10,    // STB_GLOBAL, STT_NOTYPE
            };
            out.u32(st_name);
            if self.class64 {
                out.u8(st_info);
                out.u8(sym.st_other);
                out.u16(shndx);
                out.u64(value);
                out.u64(0);
            } else {
                out.u32(u32::try_from(value).expect("fits"));
                out.u32(0);
                out.u8(st_info);
                out.u8(sym.st_other);
                out.u16(shndx);
            }
        }
    }

    fn write_object_symbols(
        &self,
        out: &mut Out,
        layout: &Layout,
        s: &Section,
        functions: &[Function],
        undefined: &[&'static str],
    ) {
        let strings = self.strings_of(s.link.expect("a symbol table links its string table"));
        out.buf.extend(std::iter::repeat_n(0u8, us(self.symsize())));
        // Every `ET_REL` object holding this table has base 0, so the address arm leaves
        // those fixtures' bytes unchanged.
        let base = |section: &str| {
            if self.e_type == ET_REL {
                0
            } else {
                self.addr_of(layout, section)
            }
        };
        let entries = functions
            .iter()
            .map(|f| {
                (
                    f.name,
                    0x12, // STB_GLOBAL, STT_FUNC
                    u16::try_from(self.section_index(f.section)).expect("fits"),
                    base(f.section) + f.offset,
                    f.size,
                )
            })
            .chain(undefined.iter().map(|name| (*name, 0x10, 0, 0, 0))); // STT_NOTYPE
        for (name, st_info, shndx, value, size) in entries {
            out.u32(strtab_offset(strings, name));
            if self.class64 {
                out.u8(st_info);
                out.u8(0);
                out.u16(shndx);
                out.u64(value);
                out.u64(size);
            } else {
                out.u32(u32::try_from(value).expect("fits"));
                out.u32(u32::try_from(size).expect("fits"));
                out.u8(st_info);
                out.u8(0);
                out.u16(shndx);
            }
        }
    }

    /// The index `name` has in the `ObjectSymbols` table `symtab`, counting the null symbol.
    fn object_symbol_index(&self, symtab: &str, name: &str) -> u64 {
        let Content::ObjectSymbols {
            functions,
            undefined,
        } = &self.sections[self.section_index(symtab) - 1].content
        else {
            panic!("{symtab:?} is not an object symbol table");
        };
        let at = functions
            .iter()
            .map(|f| f.name)
            .chain(undefined.iter().copied())
            .position(|n| n == name)
            .unwrap_or_else(|| panic!("{symtab:?} holds no {name:?}"));
        u64_of(at) + 1
    }

    /// `r_offset`, `r_info` and an addend of -4, each one word of the class (`Elf64_Rela` or
    /// `Elf32_Rela`): `ELF64_R_INFO` puts the symbol index above bit 32, `ELF32_R_INFO` above
    /// bit 8.
    fn write_rela(&self, out: &mut Out, s: &Section, entries: &[Rela]) {
        let symtab = s.link.expect("a relocation section links its symbol table");
        for r in entries {
            let symbol = self.object_symbol_index(symtab, r.symbol);
            out.addr(r.offset);
            out.addr(if self.class64 {
                (symbol << 32) | u64::from(r.r_type)
            } else {
                assert!(r.r_type < 0x100, "an ELF32 relocation type is one byte");
                (symbol << 8) | u64::from(r.r_type)
            });
            out.addr(if self.class64 {
                (-4i64).cast_unsigned()
            } else {
                u64::from((-4i32).cast_unsigned())
            });
        }
    }

    /// `r_offset` then `r_info`, each one word of the class: `ELF64_R_INFO` puts the
    /// symbol index above bit 32, `ELF32_R_INFO` above bit 8.
    fn write_rel(&self, out: &mut Out, s: &Section, entries: &[Rela]) {
        let symtab = s.link.expect("a relocation section links its symbol table");
        for r in entries {
            let symbol = self.object_symbol_index(symtab, r.symbol);
            out.addr(r.offset);
            out.addr(if self.class64 {
                (symbol << 32) | u64::from(r.r_type)
            } else {
                assert!(r.r_type < 0x100, "an ELF32 relocation type is one byte");
                (symbol << 8) | u64::from(r.r_type)
            });
        }
    }

    fn write_shdrs(&self, out: &mut Out, layout: &Layout) {
        let shstrtab = self.strings_of(".shstrtab");
        for _ in 0..self.shentsize() {
            out.u8(0);
        }
        for (i, s) in self.sections.iter().enumerate() {
            out.u32(strtab_offset(shstrtab, s.name));
            out.u32(s.sh_type);
            out.addr(s.flags);
            out.addr(if s.flags & SHF_ALLOC != 0 {
                self.base + layout.offsets[i]
            } else {
                0
            });
            out.addr(layout.offsets[i]);
            out.addr(layout.sizes[i]);
            out.u32(s.link.map_or(0, |l| u32_of(self.section_index(l))));
            out.u32(s.info);
            out.addr(s.addralign);
            out.addr(s.entsize);
        }
    }
}

// --- The catalogue --------------------------------------------------------------

/// A GNU property note descriptor holding one 4-byte property, padded to `align`.
pub fn property_desc(pr_type: u32, value: u32, little: bool, align: u64) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [pr_type, 4, value] {
        d.extend_from_slice(&if little {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        });
    }
    let padded = us(align_up(u64_of(d.len()), align));
    d.resize(padded, 0);
    d
}

fn section(
    name: &'static str,
    sh_type: u32,
    flags: u64,
    addralign: u64,
    content: Content,
) -> Section {
    Section {
        name,
        sh_type,
        flags,
        addralign,
        entsize: 0,
        link: None,
        info: 0,
        content,
    }
}

/// Which spelling of `BIND_NOW` a linked fixture carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindNow {
    Absent,
    /// The `DT_BIND_NOW` tag.
    Tag,
    /// `DF_BIND_NOW` in `DT_FLAGS`.
    Flag,
    /// `DF_1_NOW` in `DT_FLAGS_1`.
    Flag1,
}

/// The shape every linked fixture shares: `.interp`, `.text`, `.dynsym`/`.dynstr`,
/// `.symtab`/`.strtab`, `.dynamic`, a property note, and the program headers a loader
/// reads. What varies is the class, the byte order, the machine, the property, and the
/// dynamic tags. `dynamic` off leaves out the three dynamic sections and `PT_DYNAMIC`,
/// the shape of a static link.
pub struct Linked {
    pub class64: bool,
    pub little: bool,
    pub e_machine: u16,
    pub e_type: u16,
    pub interp: bool,
    pub property: Option<(u32, u32)>,
    pub bind_now: BindNow,
    pub relro: bool,
    pub extra_dynamic: Vec<(i64, DynValue)>,
    pub extra_dynstr: Vec<&'static str>,
    pub stack_executable: bool,
    /// A `DT_DEBUG` entry, the mark every linker measured leaves on executable output.
    /// Off in `linked_default`, so every fixture that does not turn it on keeps its bytes.
    pub dt_debug: bool,
    /// A dynamic link: `.dynsym`, `.dynstr`, `.dynamic` and `PT_DYNAMIC`. Off, the object
    /// is a static link's shape, `.symtab` and no dynamic section at all; `relro` goes off
    /// with it, since the builder's `PT_GNU_RELRO` covers `.dynamic`.
    pub dynamic: bool,
    /// The `DT_NEEDED` entry naming `libc.so.6`. On in `linked_default`, so every fixture that
    /// does not turn it off keeps its bytes; off, the dynamic section
    /// records no library, as a static PIE's does.
    pub needs_libc: bool,
}

impl Linked {
    pub fn object(&self) -> Object {
        assert!(
            self.dynamic || !self.relro,
            "PT_GNU_RELRO covers .dynamic, which a static shape lacks"
        );
        Object {
            class64: self.class64,
            little: self.little,
            e_type: self.e_type,
            e_machine: self.e_machine,
            base: if self.class64 { 0x40_0000 } else { 0x0804_8000 },
            sections: self.sections(),
            segments: self.segments(),
            strip_section_headers: false,
            section_headers_first: false,
        }
    }

    fn dynamic(&self) -> Vec<(i64, DynValue)> {
        let mut dynamic: Vec<(i64, DynValue)> = Vec::new();
        if self.needs_libc {
            dynamic.push((DT_NEEDED, DynValue::StrOff(".dynstr", "libc.so.6")));
        }
        dynamic.extend([
            (DT_STRTAB, DynValue::AddrOf(".dynstr")),
            (DT_SYMTAB, DynValue::AddrOf(".dynsym")),
            (DT_STRSZ, DynValue::SizeOf(".dynstr")),
            (
                DT_SYMENT,
                DynValue::Const(if self.class64 { 24 } else { 16 }),
            ),
        ]);
        let mut flags1 = 0u64;
        if self.e_type == ET_DYN && self.interp {
            flags1 |= DF_1_PIE;
        }
        match self.bind_now {
            BindNow::Absent => {}
            BindNow::Tag => dynamic.push((DT_BIND_NOW, DynValue::Const(0))),
            BindNow::Flag => dynamic.push((DT_FLAGS, DynValue::Const(DF_BIND_NOW))),
            BindNow::Flag1 => flags1 |= DF_1_NOW,
        }
        if self.dt_debug {
            dynamic.push((DT_DEBUG, DynValue::Const(0)));
        }
        dynamic.extend(self.extra_dynamic.iter().cloned());
        if flags1 != 0 {
            dynamic.push((DT_FLAGS_1, DynValue::Const(flags1)));
        }
        dynamic
    }

    fn sections(&self) -> Vec<Section> {
        let align = if self.class64 { 8 } else { 4 };
        let mut sections = Vec::new();
        if self.interp {
            sections.push(section(
                ".interp",
                SHT_PROGBITS,
                SHF_ALLOC,
                1,
                Content::Bytes(b"/lib64/ld-linux-x86-64.so.2\0".to_vec()),
            ));
        }
        if let Some((pr_type, value)) = self.property {
            sections.push(section(
                ".note.gnu.property",
                SHT_NOTE,
                SHF_ALLOC,
                align,
                Content::Notes(vec![NoteSpec {
                    owner: "GNU",
                    ntype: NT_GNU_PROPERTY_TYPE_0,
                    desc: property_desc(pr_type, value, self.little, align),
                }]),
            ));
        }
        sections.push(section(
            ".text",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            16,
            Content::Bytes(vec![0xc3; 16]),
        ));
        if self.dynamic {
            let mut dynstr: Vec<&'static str> =
                vec!["libc.so.6", "__stack_chk_fail", "main", "abort"];
            dynstr.extend(self.extra_dynstr.iter().copied());
            sections.push(self.dynsym());
            sections.push(section(
                ".dynstr",
                SHT_STRTAB,
                SHF_ALLOC,
                1,
                Content::Strings(dynstr),
            ));
            sections.push(Section {
                name: ".dynamic",
                sh_type: SHT_DYNAMIC,
                flags: SHF_ALLOC | SHF_WRITE,
                addralign: 8,
                entsize: if self.class64 { 16 } else { 8 },
                link: Some(".dynstr"),
                info: 0,
                content: Content::Dynamic(self.dynamic()),
            });
        }
        sections.push(self.symtab());
        sections.push(section(
            ".strtab",
            SHT_STRTAB,
            0,
            1,
            Content::Strings(vec![
                "__stack_chk_fail@GLIBC_2.4",
                "abort@GLIBC_2.2.5",
                "main",
                "chard_local_helper",
            ]),
        ));
        sections
    }

    /// `.dynsym`: the names bare, as `.dynstr` stores them.
    fn dynsym(&self) -> Section {
        Section {
            name: ".dynsym",
            sh_type: SHT_DYNSYM,
            flags: SHF_ALLOC,
            addralign: 8,
            entsize: if self.class64 { 24 } else { 16 },
            link: Some(".dynstr"),
            info: 1,
            content: Content::Symbols(vec![
                Symbol {
                    name: "__stack_chk_fail",
                    defined_in: None,
                    st_other: 0,
                },
                Symbol {
                    name: "abort",
                    defined_in: None,
                    st_other: 0,
                },
                Symbol {
                    name: "main",
                    defined_in: Some(".text"),
                    st_other: 0,
                },
            ]),
        }
    }

    /// `.symtab`: the version spelled into the name, as `.strtab` stores it.
    fn symtab(&self) -> Section {
        Section {
            name: ".symtab",
            sh_type: SHT_SYMTAB,
            flags: 0,
            addralign: 8,
            entsize: if self.class64 { 24 } else { 16 },
            link: Some(".strtab"),
            info: 1,
            content: Content::Symbols(vec![
                Symbol {
                    name: "__stack_chk_fail@GLIBC_2.4",
                    defined_in: None,
                    st_other: 0,
                },
                Symbol {
                    name: "abort@GLIBC_2.2.5",
                    defined_in: None,
                    st_other: 0,
                },
                Symbol {
                    name: "main",
                    defined_in: Some(".text"),
                    st_other: 0,
                },
                Symbol {
                    name: "chard_local_helper",
                    defined_in: Some(".text"),
                    st_other: 0,
                },
            ]),
        }
    }

    fn segments(&self) -> Vec<Segment> {
        let align = if self.class64 { 8 } else { 4 };
        let mut segments = vec![Segment {
            p_type: PT_LOAD,
            flags: PF_R | PF_W | PF_X,
            align: 0x1000,
            covers: Covers::File,
        }];
        if self.interp {
            segments.push(Segment {
                p_type: PT_INTERP,
                flags: PF_R,
                align: 1,
                covers: Covers::Section(".interp"),
            });
        }
        if self.dynamic {
            segments.push(Segment {
                p_type: PT_DYNAMIC,
                flags: PF_R | PF_W,
                align: 8,
                covers: Covers::Section(".dynamic"),
            });
        }
        if self.property.is_some() {
            segments.push(Segment {
                p_type: PT_NOTE,
                flags: PF_R,
                align,
                covers: Covers::Section(".note.gnu.property"),
            });
        }
        if self.relro {
            segments.push(Segment {
                p_type: PT_GNU_RELRO,
                flags: PF_R,
                align: 1,
                covers: Covers::Section(".dynamic"),
            });
        }
        segments.push(Segment {
            p_type: PT_GNU_STACK,
            flags: if self.stack_executable {
                PF_R | PF_W | PF_X
            } else {
                PF_R | PF_W
            },
            align: 16,
            covers: Covers::Nothing,
        });
        segments
    }
}

/// The default linked object: ELF64 little-endian x86-64 executable, CET-marked, with
/// an interpreter and `PT_GNU_RELRO` and no `BIND_NOW` at all.
pub fn linked_default() -> Linked {
    Linked {
        class64: true,
        little: true,
        e_machine: EM_X86_64,
        e_type: ET_EXEC,
        interp: true,
        property: Some((
            GNU_PROPERTY_X86_FEATURE_1_AND,
            X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK,
        )),
        bind_now: BindNow::Absent,
        relro: true,
        extra_dynamic: Vec::new(),
        extra_dynstr: Vec::new(),
        stack_executable: false,
        dt_debug: false,
        dynamic: true,
        needs_libc: true,
    }
}

/// A relocatable object: no program headers, a property note, a `.symtab` with a defined
/// function and an undefined canary reference.
pub fn relocatable() -> Object {
    let align = 8;
    Object {
        class64: true,
        little: true,
        e_type: ET_REL,
        e_machine: EM_X86_64,
        base: 0,
        sections: vec![
            section(
                ".text",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                16,
                Content::Bytes(vec![0xc3; 16]),
            ),
            section(
                ".note.gnu.property",
                SHT_NOTE,
                SHF_ALLOC,
                align,
                Content::Notes(vec![NoteSpec {
                    owner: "GNU",
                    ntype: NT_GNU_PROPERTY_TYPE_0,
                    desc: property_desc(
                        GNU_PROPERTY_X86_FEATURE_1_AND,
                        X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK,
                        true,
                        align,
                    ),
                }]),
            ),
            Section {
                name: ".symtab",
                sh_type: SHT_SYMTAB,
                flags: 0,
                addralign: 8,
                entsize: 24,
                link: Some(".strtab"),
                info: 1,
                content: Content::Symbols(vec![
                    Symbol {
                        name: "chard_test_probe",
                        defined_in: Some(".text"),
                        st_other: 0,
                    },
                    Symbol {
                        name: "__stack_chk_fail",
                        defined_in: None,
                        st_other: 0,
                    },
                ]),
            },
            section(
                ".strtab",
                SHT_STRTAB,
                0,
                1,
                Content::Strings(vec!["chard_test_probe", "__stack_chk_fail"]),
            ),
        ],
        segments: Vec::new(),
        strip_section_headers: false,
        section_headers_first: false,
    }
}

/// A relocatable object holding `probes/ssp_function_map.c`'s four functions, sixteen bytes
/// each in `.text`, and a `.rela.text` placing references inside them: each function calls
/// its helper four bytes in, and every function but `ssp_any` refers to
/// `__stack_chk_fail` eight bytes in. `ssp-level-emitted` reads `strong` from it.
pub fn relocatable_functions() -> Object {
    functions_object(FunctionsObject {
        class64: true,
        e_machine: EM_X86_64,
        relocations: ".rela.text",
        canary: "__stack_chk_fail",
        r_type: 4, // R_X86_64_PLT32
    })
}

/// The same four functions as an ELF32 i386 object, the shape gcc gives one under `-fPIC`:
/// a `.rel.text` of `Elf32_Rel` entries, with no addend and the symbol index in `r_info`'s
/// upper 24 bits, and the canary reference against `__stack_chk_fail_local`. Every other
/// relocatable fixture is ELF64 with addends, so this is the one the `SHT_REL` arithmetic
/// is pinned by: a wrong shift or entry size moves `ssp-level-emitted` off `strong`.
pub fn relocatable_functions_rel32() -> Object {
    functions_object(FunctionsObject {
        class64: false,
        e_machine: EM_386,
        relocations: ".rel.text",
        canary: "__stack_chk_fail_local",
        r_type: 2, // R_386_PC32, as gcc calls the hidden local alias
    })
}

/// [`relocatable_functions_rel32`] with its relocations in `.rela.text` as 12-byte
/// `Elf32_Rela` records: the ELF32 RELA record no other object here carries, so its size is
/// held by a fixture (2026-10-20). i386's ABI uses REL; the reader and readelf read
/// either form for any machine.
pub fn relocatable_functions_rela32() -> Object {
    functions_object(FunctionsObject {
        class64: false,
        e_machine: EM_386,
        relocations: ".rela.text",
        canary: "__stack_chk_fail_local",
        r_type: 2,
    })
}

/// What differs between the two four-function objects.
#[derive(Clone, Copy)]
struct FunctionsObject {
    class64: bool,
    e_machine: u16,
    /// `.rela.text` for the class's `Rela`, `.rel.text` for the class's `Rel`.
    relocations: &'static str,
    canary: &'static str,
    r_type: u32,
}

fn functions_object(spec: FunctionsObject) -> Object {
    let function = |name, offset| Function {
        name,
        section: ".text",
        offset,
        size: 16,
    };
    let rela = |offset, symbol| Rela {
        offset,
        symbol,
        r_type: spec.r_type,
    };
    let entries = vec![
        rela(4, "ssp_use"),
        rela(20, "ssp_escape"),
        rela(24, spec.canary),
        rela(36, "ssp_escape"),
        rela(40, spec.canary),
        rela(52, "ssp_escape"),
        rela(56, spec.canary),
    ];
    let word: u64 = if spec.class64 { 8 } else { 4 };
    let (sh_type, entsize, content) = if spec.relocations == ".rela.text" {
        (SHT_RELA, 3 * word, Content::Rela(entries))
    } else {
        (SHT_REL, 2 * word, Content::Rel(entries))
    };
    let symsize = if spec.class64 { 24 } else { 16 };
    Object {
        class64: spec.class64,
        little: true,
        e_type: ET_REL,
        e_machine: spec.e_machine,
        base: 0,
        sections: vec![
            section(
                ".text",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                16,
                Content::Bytes(vec![0xc3; 64]),
            ),
            Section {
                name: spec.relocations,
                sh_type,
                flags: 0x40, // SHF_INFO_LINK
                addralign: word,
                entsize,
                link: Some(".symtab"),
                info: 1, // .text
                content,
            },
            Section {
                name: ".symtab",
                sh_type: SHT_SYMTAB,
                flags: 0,
                addralign: word,
                entsize: symsize,
                link: Some(".strtab"),
                info: 1,
                content: Content::ObjectSymbols {
                    functions: vec![
                        function("ssp_any", 0),
                        function("ssp_addr_taken", 16),
                        function("ssp_char_array", 32),
                        function("ssp_alloca", 48),
                    ],
                    undefined: vec!["ssp_use", "ssp_escape", spec.canary],
                },
            },
            section(
                ".strtab",
                SHT_STRTAB,
                0,
                1,
                Content::Strings(vec![
                    "ssp_any",
                    "ssp_addr_taken",
                    "ssp_char_array",
                    "ssp_alloca",
                    "ssp_use",
                    "ssp_escape",
                    spec.canary,
                ]),
            ),
        ],
        segments: Vec::new(),
        strip_section_headers: false,
        section_headers_first: false,
    }
}

/// `R_X86_64_REX_GOTPCRELX`, the type x86_64 compilers write for a GOT access under -fPIC.
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

/// [`relocatable`] with a `.rela.text` holding one `R_X86_64_REX_GOTPCRELX` against a
/// defined `chard_pic_object_anchor`: the relocation `pic-object-relocs` reads as `-fPIC`.
///
/// The anchor is the fourth symbol table entry (the null symbol, the function, the canary
/// reference, then it), which the entry's `r_info` names. Not in the catalogue, so no
/// checked-in fixture's bytes move; `tests/elf_truncations.rs` cuts it.
pub fn relocatable_with_code_relocation() -> Object {
    let mut object = relocatable();
    let symtab = object
        .sections
        .iter_mut()
        .find(|s| s.name == ".symtab")
        .expect("the relocatable object has a .symtab");
    if let Content::Symbols(symbols) = &mut symtab.content {
        symbols.push(Symbol {
            name: "chard_pic_object_anchor",
            defined_in: Some(".text"),
            st_other: 0,
        });
    }
    let strtab = object
        .sections
        .iter_mut()
        .find(|s| s.name == ".strtab")
        .expect("the relocatable object has a .strtab");
    if let Content::Strings(strings) = &mut strtab.content {
        strings.push("chard_pic_object_anchor");
    }
    let anchor: u64 = 3;
    let mut entry = Vec::new();
    entry.extend_from_slice(&3u64.to_le_bytes()); // r_offset
    entry.extend_from_slice(&((anchor << 32) | u64::from(R_X86_64_REX_GOTPCRELX)).to_le_bytes());
    entry.extend_from_slice(&(-4i64).to_le_bytes()); // r_addend
    object.sections.push(Section {
        name: ".rela.text",
        sh_type: SHT_RELA,
        flags: SHF_INFO_LINK,
        addralign: 8,
        entsize: 24,
        link: Some(".symtab"),
        // `.text` is the first section, index 1 after the null header.
        info: 1,
        content: Content::Bytes(entry),
    });
    object
}

/// `R_386_GOT32X`, the type i386 compilers write for a GOT access under -fPIC.
pub const R_386_GOT32X: u32 = 43;
/// `R_AARCH64_ADR_GOT_PAGE`, the first of the pair aarch64 compilers write for a GOT
/// access under -fPIC.
pub const R_AARCH64_ADR_GOT_PAGE: u32 = 311;
/// `R_X86_64_PC32`, a direct PC-relative reference.
pub const R_X86_64_PC32: u32 = 2;
/// `STV_HIDDEN` in `st_other`.
pub const STV_HIDDEN: u8 = 2;

/// `object`, a [`relocatable_with_code_relocation`] of either width, with the anchor's
/// visibility set to `visibility` and its one code relocation's type to `kind`: what
/// clang writes under `-fPIC -fvisibility-from-dllstorageclass
/// -fvisibility-nodllstorageclass=hidden`, a hidden anchor reached directly.
pub fn with_anchor_visibility(mut object: Object, visibility: u8, kind: u32) -> Object {
    let class64 = object.class64;
    for section in &mut object.sections {
        match (section.name, &mut section.content) {
            (".symtab", Content::Symbols(symbols)) => {
                for symbol in symbols.iter_mut() {
                    if symbol.name == "chard_pic_object_anchor" {
                        symbol.st_other = visibility;
                    }
                }
            }
            (".rela.text" | ".rel.text", Content::Bytes(bytes)) => {
                if class64 {
                    bytes[8..16].copy_from_slice(&((3u64 << 32) | u64::from(kind)).to_le_bytes());
                } else {
                    bytes[4..8].copy_from_slice(&((3u32 << 8) | kind).to_le_bytes());
                }
            }
            _ => {}
        }
    }
    object
}

/// [`relocatable_with_code_relocation`] as an i386 object: ELF32, an `SHT_REL`
/// `.rel.text` whose one entry's `r_info` is the symbol shifted by eight and
/// `R_386_GOT32X` below it, and no x86_64 property note.
pub fn relocatable_i386_with_code_relocation() -> Object {
    let mut i386 = relocatable_with_code_relocation();
    i386.class64 = false;
    i386.e_machine = EM_386;
    i386.sections.retain(|s| s.name != ".note.gnu.property");
    for section in &mut i386.sections {
        match section.name {
            ".symtab" => section.entsize = 16,
            ".rela.text" => {
                section.name = ".rel.text";
                section.sh_type = 9;
                section.entsize = 8;
                section.addralign = 4;
                let mut entry = Vec::new();
                entry.extend_from_slice(&3u32.to_le_bytes());
                entry.extend_from_slice(&((3u32 << 8) | R_386_GOT32X).to_le_bytes());
                section.content = Content::Bytes(entry);
            }
            _ => {}
        }
    }
    i386
}

/// [`relocatable_with_code_relocation`] as an aarch64 object: the same `RELA` entry with
/// `R_AARCH64_ADR_GOT_PAGE`, and no x86_64 property note.
pub fn relocatable_aarch64_with_code_relocation() -> Object {
    let mut object = relocatable_with_code_relocation();
    object.e_machine = EM_AARCH64;
    object.sections.retain(|s| s.name != ".note.gnu.property");
    for section in &mut object.sections {
        if section.name == ".rela.text" {
            let mut entry = Vec::new();
            entry.extend_from_slice(&3u64.to_le_bytes());
            entry.extend_from_slice(
                &((3u64 << 32) | u64::from(R_AARCH64_ADR_GOT_PAGE)).to_le_bytes(),
            );
            entry.extend_from_slice(&0i64.to_le_bytes());
            section.content = Content::Bytes(entry);
        }
    }
    object
}

/// `object`, a 64-bit [`relocatable_with_code_relocation`], with `.text`'s section symbol
/// appended to `.symtab` and a second `.rela.text` entry, `R_X86_64_PC32`, against it:
/// the relocation a compiler writes for a reference to local data, which names no symbol.
pub fn with_section_symbol_relocation(mut object: Object) -> Object {
    let mut index = 0u64;
    for section in &mut object.sections {
        if let (".symtab", Content::Symbols(symbols)) = (section.name, &mut section.content) {
            symbols.push(Symbol {
                name: "",
                defined_in: Some(".text"),
                st_other: 0,
            });
            index = u64_of(symbols.len());
        }
    }
    assert!(index > 0, "the object has a .symtab");
    for section in &mut object.sections {
        if let (".rela.text", Content::Bytes(bytes)) = (section.name, &mut section.content) {
            bytes.extend_from_slice(&7u64.to_le_bytes());
            bytes.extend_from_slice(&((index << 32) | u64::from(R_X86_64_PC32)).to_le_bytes());
            bytes.extend_from_slice(&(-4i64).to_le_bytes());
        }
    }
    object
}

/// `EM_RISCV`, both classes.
pub const EM_RISCV: u16 = 243;
/// `SHT_RISCV_ATTRIBUTES`, `SHT_LOPROC + 3`: the type `.riscv.attributes` carries.
pub const SHT_RISCV_ATTRIBUTES: u32 = 0x7000_0003;
/// `R_RISCV_CALL_PLT`: a call, `auipc` and `jalr`, that the linker routes through a PLT
/// entry where the callee is in another module.
pub const R_RISCV_CALL_PLT: u32 = 19;
/// `R_RISCV_GOT_HI20`: the `auipc` of a load from the symbol's GOT slot.
pub const R_RISCV_GOT_HI20: u32 = 20;
/// `R_RISCV_PCREL_LO12_I`: the low half of a PC-relative pair, against the label on the
/// `auipc` that carries the high half rather than against the target.
pub const R_RISCV_PCREL_LO12_I: u32 = 24;
/// `R_RISCV_ALIGN`: alignment padding the linker may shrink. Symbol index 0.
pub const R_RISCV_ALIGN: u32 = 43;
/// `R_RISCV_RELAX`: the preceding relocation's instruction may be relaxed. Symbol index 0.
pub const R_RISCV_RELAX: u32 = 51;

/// How a [`relocatable_riscv_no_plt`] object's one external call is relocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiscvCall {
    /// Through the callee's GOT slot: what gcc writes under `-fPIE -fno-plt`.
    Got,
    /// As a direct call a PLT entry serves: what gcc writes without `-fno-plt`.
    Plt,
}

/// The `.riscv.attributes` gcc 16.1.1 (Fedora 44's riscv64 cross compiler) writes under
/// `-march=rv64gc_zicfilp_zicfiss`: format version `A`, one `riscv` vendor subsection, and
/// in it one `Tag_File` (1) holding `Tag_RISCV_stack_align` (4) = 16 and
/// `Tag_RISCV_arch` (5) as a string. The lengths are computed rather than written, and
/// the result is byte for byte what that compiler wrote.
fn riscv_attributes() -> Vec<u8> {
    const ARCH: &str = "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicfilp1p0_zicfiss1p0_zicsr2p0_\
                        zifencei2p0_zimop1p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0_zcd1p0";
    let mut file = vec![4, 16, 5];
    file.extend_from_slice(ARCH.as_bytes());
    file.push(0);
    let file_len = u32_of(1 + 4 + file.len());
    let mut vendor = b"riscv\0".to_vec();
    vendor.push(1);
    vendor.extend_from_slice(&file_len.to_le_bytes());
    vendor.extend_from_slice(&file);
    let mut out = vec![b'A'];
    out.extend_from_slice(&u32_of(4 + vendor.len()).to_le_bytes());
    out.extend_from_slice(&vendor);
    out
}

/// The `.text`, `.rela.text` and `.symtab` bytes and the string table of
/// [`relocatable_riscv_no_plt`], for `call`.
fn riscv_code(call: RiscvCall) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<&'static str>) {
    let (text, auipc, caller_size): (&[u8], u64, u64) = match call {
        RiscvCall::Got => (
            &[
                0x01, 0x00, 0x17, 0x00, 0x00, 0x00, 0x73, 0x40, 0x10, 0xce, 0x41, 0x11, 0x17, 0x03,
                0x00, 0x00, 0x03, 0x33, 0x03, 0x00, 0x06, 0xe4, 0x9a, 0x83, 0x82, 0x93, 0xa2, 0x62,
                0x05, 0x25, 0x41, 0x01, 0x73, 0xc0, 0xc2, 0xcd, 0x82, 0x82, 0x01, 0x00,
            ],
            0xc,
            36,
        ),
        RiscvCall::Plt => (
            &[
                0x01, 0x00, 0x17, 0x00, 0x00, 0x00, 0x73, 0x40, 0x10, 0xce, 0x41, 0x11, 0x06, 0xe4,
                0x97, 0x00, 0x00, 0x00, 0xe7, 0x80, 0x00, 0x00, 0xa2, 0x62, 0x05, 0x25, 0x41, 0x01,
                0x73, 0xc0, 0xc2, 0xcd, 0x82, 0x82, 0x01, 0x00,
            ],
            0xe,
            32,
        ),
    };
    // The symbol table: the null symbol, the label (local), the caller (2, the first
    // global), the callee.
    let (label, callee) = (1u64, 3u64);
    let strings = vec![".L0 ", "chard_no_plt_caller", "chard_no_plt_callee"];
    let mut symtab = vec![0u8; 24];
    for (name, st_info, shndx, value, size) in [
        // STB_LOCAL, STT_NOTYPE
        (".L0 ", 0x00u8, 1u16, auipc, 0u64),
        // STB_GLOBAL, STT_FUNC
        ("chard_no_plt_caller", 0x12, 1, 2, caller_size),
        // STB_GLOBAL, STT_NOTYPE, SHN_UNDEF
        ("chard_no_plt_callee", 0x10, 0, 0, 0),
    ] {
        symtab.extend_from_slice(&strtab_offset(&strings, name).to_le_bytes());
        symtab.push(st_info);
        symtab.push(0);
        symtab.extend_from_slice(&shndx.to_le_bytes());
        symtab.extend_from_slice(&value.to_le_bytes());
        symtab.extend_from_slice(&size.to_le_bytes());
    }
    let mut entries: Vec<(u64, u64, u32, i64)> = vec![(0, 0, R_RISCV_ALIGN, 2)];
    match call {
        RiscvCall::Got => entries.extend([
            (auipc, callee, R_RISCV_GOT_HI20, 0),
            (auipc, 0, R_RISCV_RELAX, 0),
            (auipc + 4, label, R_RISCV_PCREL_LO12_I, 0),
            (auipc + 4, 0, R_RISCV_RELAX, 0),
        ]),
        RiscvCall::Plt => entries.extend([
            (auipc, callee, R_RISCV_CALL_PLT, 0),
            (auipc, 0, R_RISCV_RELAX, 0),
        ]),
    }
    let mut rela = Vec::new();
    for (offset, symbol, r_type, addend) in entries {
        rela.extend_from_slice(&offset.to_le_bytes());
        rela.extend_from_slice(&((symbol << 32) | u64::from(r_type)).to_le_bytes());
        rela.extend_from_slice(&addend.to_le_bytes());
    }
    (text.to_vec(), rela, symtab, strings)
}

/// A RISC-V relocatable object in the shape gcc 16.1.1 (Fedora 44's riscv64 cross
/// compiler) writes for `probes/no_plt.c`'s caller under `-O2 -fPIE
/// -march=rv64gc_zicfilp_zicfiss -fcf-protection=full`, with `-fno-plt` for
/// [`RiscvCall::Got`] and without it for [`RiscvCall::Plt`]: that compiler's `.text` bytes
/// (a landing pad, a shadow-stack push, the call, a shadow-stack check), its code
/// relocations, its `GNU_PROPERTY_RISCV_FEATURE_1_AND` property with the landing-pad and
/// shadow-stack bits (3), whose type is `0xc0000000` and which read as the aarch64 word
/// would be BTI and PAC, and its `.riscv.attributes`. The sections gcc writes and no fact
/// reads (`.data`, `.bss`, `.comment`, `.eh_frame` and its relocations) are left out, and
/// the symbol table keeps the three symbols the relocations need: the `auipc`'s local label,
/// which GNU as names `.L0 ` with a trailing space, the caller, and the undefined callee.
///
/// Under [`RiscvCall::Got`] the code relocations are `R_RISCV_GOT_HI20` against the callee
/// and `R_RISCV_PCREL_LO12_I` against the label; under [`RiscvCall::Plt`],
/// `R_RISCV_CALL_PLT` against the callee. Each carries an `R_RISCV_RELAX` and the section
/// an `R_RISCV_ALIGN`, both against symbol 0, which names nothing.
pub fn relocatable_riscv_no_plt(call: RiscvCall) -> Object {
    let (text, rela, symtab, strings) = riscv_code(call);
    let align = 8;
    Object {
        class64: true,
        little: true,
        e_type: ET_REL,
        e_machine: EM_RISCV,
        base: 0,
        sections: vec![
            section(
                ".text",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                4,
                Content::Bytes(text),
            ),
            Section {
                name: ".rela.text",
                sh_type: SHT_RELA,
                flags: SHF_INFO_LINK,
                addralign: 8,
                entsize: 24,
                link: Some(".symtab"),
                info: 1, // .text
                content: Content::Bytes(rela),
            },
            section(
                ".note.gnu.property",
                SHT_NOTE,
                SHF_ALLOC,
                align,
                Content::Notes(vec![NoteSpec {
                    owner: "GNU",
                    ntype: NT_GNU_PROPERTY_TYPE_0,
                    desc: property_desc(GNU_PROPERTY_AARCH64_FEATURE_1_AND, 3, true, align),
                }]),
            ),
            section(
                ".riscv.attributes",
                SHT_RISCV_ATTRIBUTES,
                0,
                1,
                Content::Bytes(riscv_attributes()),
            ),
            Section {
                name: ".symtab",
                sh_type: SHT_SYMTAB,
                flags: 0,
                addralign: 8,
                entsize: 24,
                link: Some(".strtab"),
                // The first global: the caller.
                info: 2,
                content: Content::Bytes(symtab),
            },
            section(".strtab", SHT_STRTAB, 0, 1, Content::Strings(strings)),
        ],
        segments: Vec::new(),
        strip_section_headers: false,
        section_headers_first: false,
    }
}

/// The first bytes of each `cet-endbr` probe function as gcc 16.1.1 and clang 22.1.8
/// compile it under `-O2 -fcf-protection=none` on Fedora 44 x86_64: `lea 0xN(%rdi),%eax`
/// then `ret`, with no `endbr64` (2026-10-05, `chard detect cet-endbr-emitted --artifact`
/// over both compilers' output, each reading these three entries).
pub const UNMARKED_ENTRIES: [(&str, [u8; 4]); 3] = [
    ("chard_ibt_target_a", [0x8d, 0x47, 0x01, 0xc3]),
    ("chard_ibt_target_b", [0x8d, 0x47, 0x02, 0xc3]),
    ("chard_ibt_target_c", [0x8d, 0x47, 0x03, 0xc3]),
];

/// A linked x86_64 program whose property note claims both CET edges and whose code has
/// no landing pad: [`linked_default`], its IBT|SHSTK property kept, with `.text` holding
/// `main` and the `cet-endbr` probe's three functions as [`UNMARKED_ENTRIES`] spells them,
/// each sixteen bytes apart and sized in `.symtab` at its address.
///
/// The shape GNU ld 2.46.1 writes for that probe built `-O2 -fcf-protection=none` and
/// linked `-z ibt -z shstk` under gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64
/// (2026-10-05): the linker forces both bits of `GNU_PROPERTY_X86_FEATURE_1_AND` whatever
/// its inputs carry, so the marking claims what the code does not hold. `cet-marked`
/// reads that note and `cet-endbr-emitted` reads those bytes, one artifact under both.
pub fn linked_cet_forged() -> Object {
    const STRIDE: u64 = 16;
    let mut object = linked_default().object();
    let mut code = vec![0x31, 0xc0, 0xc3]; // main: xor %eax,%eax; ret
    let mut functions = vec![Function {
        name: "main",
        section: ".text",
        offset: 0,
        size: 3,
    }];
    for (i, (name, entry)) in UNMARKED_ENTRIES.iter().enumerate() {
        let offset = STRIDE * (u64_of(i) + 1);
        code.resize(us(offset), 0xcc);
        code.extend_from_slice(entry);
        functions.push(Function {
            name,
            section: ".text",
            offset,
            size: u64_of(entry.len()),
        });
    }
    let undefined = vec!["__stack_chk_fail@GLIBC_2.4", "abort@GLIBC_2.2.5"];
    let mut strings: Vec<&'static str> = functions.iter().map(|f| f.name).collect();
    strings.extend(undefined.iter().copied());
    for section in &mut object.sections {
        match section.name {
            ".text" => section.content = Content::Bytes(code.clone()),
            ".symtab" => {
                section.content = Content::ObjectSymbols {
                    functions: functions.clone(),
                    undefined: undefined.clone(),
                }
            }
            ".strtab" => section.content = Content::Strings(strings.clone()),
            _ => {}
        }
    }
    object
}

/// One checked-in fixture.
pub struct Fixture {
    /// The file stem under `tests/fixtures/elf/`.
    pub name: &'static str,
    /// What it is for, recorded beside the bytes.
    pub description: &'static str,
    pub bytes: Vec<u8>,
}

fn fixture(name: &'static str, description: &'static str, bytes: Vec<u8>) -> Fixture {
    Fixture {
        name,
        description,
        bytes,
    }
}

/// The control and the three spellings of `BIND_NOW`, differing by one tag each.
fn bind_now_fixtures() -> Vec<Fixture> {
    let bind_now = |encoding| {
        let mut l = linked_default();
        l.bind_now = encoding;
        l.object().build()
    };
    vec![
        fixture(
            "elf64-le-x86_64-exec-relro-lazy",
            "ELF64 little-endian x86-64 executable: interpreter, PT_GNU_RELRO, no BIND_NOW \
             in any spelling, IBT|SHSTK property, versioned names in .strtab. The control \
             the three BIND_NOW fixtures differ from by one tag.",
            bind_now(BindNow::Absent),
        ),
        fixture(
            "elf64-le-x86_64-exec-dt-bind-now",
            "As the control, plus the DT_BIND_NOW tag: the original spelling.",
            bind_now(BindNow::Tag),
        ),
        fixture(
            "elf64-le-x86_64-exec-df-bind-now",
            "As the control, plus DT_FLAGS carrying DF_BIND_NOW.",
            bind_now(BindNow::Flag),
        ),
        fixture(
            "elf64-le-x86_64-exec-df-1-now",
            "As the control, plus DT_FLAGS_1 carrying DF_1_NOW: the spelling every current \
             linker emits for -z now.",
            bind_now(BindNow::Flag1),
        ),
    ]
}

/// The other object kinds: stripped of section headers, a shared object, a static PIE, a
/// relocatable object.
fn kind_fixtures() -> Vec<Fixture> {
    vec![
        fixture(
            "elf64-le-x86_64-exec-stripped-section-headers",
            "The DF_1_NOW executable with e_shoff, e_shnum and e_shstrndx zeroed and the file \
             cut before the section-header table, as objcopy --strip-section-headers leaves \
             it. .dynamic is reached through PT_DYNAMIC and the property note through \
             PT_NOTE; the symbol tables are unreachable and the reader must say so.",
            {
                let mut l = linked_default();
                l.bind_now = BindNow::Flag1;
                let mut o = l.object();
                o.strip_section_headers = true;
                o.build()
            },
        ),
        fixture(
            "elf64-le-x86_64-shared-object",
            "ELF64 little-endian x86-64 shared object: ET_DYN, no interpreter, DT_SONAME, \
             DT_FLAGS_1 with DF_1_NOOPEN, an executable PT_GNU_STACK, DT_RPATH and \
             DT_RUNPATH both set, DT_TEXTREL as a standalone tag.",
            {
                let mut l = linked_default();
                l.e_type = ET_DYN;
                l.interp = false;
                l.relro = false;
                l.stack_executable = true;
                l.extra_dynstr = vec!["libchard.so.1", "/opt/chard/lib", "$ORIGIN/../lib"];
                l.extra_dynamic = vec![
                    (DT_SONAME, DynValue::StrOff(".dynstr", "libchard.so.1")),
                    (DT_RPATH, DynValue::StrOff(".dynstr", "/opt/chard/lib")),
                    (DT_RUNPATH, DynValue::StrOff(".dynstr", "$ORIGIN/../lib")),
                    (DT_TEXTREL, DynValue::Const(0)),
                    (DT_FLAGS_1, DynValue::Const(DF_1_NOOPEN)),
                ];
                l.object().build()
            },
        ),
        fixture(
            "elf64-le-x86_64-static-pie-relr",
            "ELF64 little-endian x86-64 static PIE: ET_DYN, DF_1_PIE, no interpreter, \
             DT_RELR present with its size and entry tags, DF_1_NOW.",
            {
                let mut l = linked_default();
                l.e_type = ET_DYN;
                l.interp = false;
                // One DT_FLAGS_1 carrying both bits, written here by hand: `bind_now`
                // would emit a second copy of the tag.
                l.extra_dynamic = vec![
                    (DT_RELR, DynValue::AddrOf(".text")),
                    (DT_RELRSZ, DynValue::Const(8)),
                    (DT_RELRENT, DynValue::Const(8)),
                    (DT_FLAGS_1, DynValue::Const(DF_1_PIE | DF_1_NOW)),
                ];
                l.object().build()
            },
        ),
        fixture(
            "elf64-le-x86_64-static-pie-dt-debug",
            "ELF64 little-endian x86-64 static PIE as lld 10.0.0 links one: ET_DYN, no \
             interpreter, DT_DEBUG, and no DT_FLAGS_1 at all, so no DF_1_PIE. The tag shape \
             lld 10.0.0 wrote under clang 10 -static-pie on 2026-09-28, on an object that \
             segfaults at startup; DT_DEBUG is what marks it executable output.",
            {
                let mut l = linked_default();
                l.e_type = ET_DYN;
                l.interp = false;
                l.dt_debug = true;
                l.object().build()
            },
        ),
        fixture(
            "elf64-le-x86_64-rel",
            "ELF64 little-endian x86-64 relocatable object: no program headers, IBT|SHSTK \
             property, a .symtab with one defined function and an undefined canary \
             reference. Every link-classification fact must be null.",
            relocatable().build(),
        ),
        fixture(
            "elf64-le-x86_64-exec-lld-comment",
            "The control with a .comment section as lld leaves one: a merged string table \
             holding a compiler's line, `Linker: LLD 22.1.8`, and the compiler's line a \
             second time, so a reader that keeps first occurrences in file order is told \
             apart from one that keeps every string. What toolchain.linker.artifact reads.",
            {
                let mut o = linked_default().object();
                o.sections.push(section(
                    ".comment",
                    SHT_PROGBITS,
                    SHF_MERGE | SHF_STRINGS,
                    1,
                    Content::Bytes(
                        b"GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)\0Linker: LLD 22.1.8\0\
                          GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)\0"
                            .to_vec(),
                    ),
                ));
                o.build()
            },
        ),
    ]
}

/// The other width and the other byte order, in every combination but the default.
fn width_and_order_fixtures() -> Vec<Fixture> {
    vec![
        fixture(
            "elf32-le-i386-pie",
            "ELF32 little-endian i386 position-independent executable: ET_DYN with an \
             interpreter and DF_1_PIE, DF_BIND_NOW, PT_GNU_RELRO, IBT-only property in a \
             4-byte-aligned note. Exercises every ELF32 offset branch.",
            {
                let mut l = linked_default();
                l.class64 = false;
                l.e_machine = EM_386;
                l.e_type = ET_DYN;
                l.bind_now = BindNow::Flag;
                l.property = Some((GNU_PROPERTY_X86_FEATURE_1_AND, X86_FEATURE_1_IBT));
                l.object().build()
            },
        ),
        fixture(
            "elf32-be-ppc-exec",
            "ELF32 big-endian PowerPC executable: DT_BIND_NOW, PT_GNU_RELRO, and a \
             property note of type 0xc0000002 that PowerPC does not define, so it is listed \
             and left undecoded. Exercises the big-endian arms of every read at ELF32 width. \
             Re-recorded 2026-09-20: `machine` read `EM_20` until the reader named EM_PPC, \
             and reads `ppc` now, the machine readelf calls PowerPC.",
            {
                let mut l = linked_default();
                l.class64 = false;
                l.little = false;
                l.e_machine = EM_PPC;
                l.bind_now = BindNow::Tag;
                l.object().build()
            },
        ),
        fixture(
            "elf32-le-aarch64-ilp32-exec",
            "ELF32 little-endian aarch64 (the ILP32 ABI) executable: EM_AARCH64 at ELFCLASS32, \
             DT_BIND_NOW, PT_GNU_RELRO, BTI property. The family of the aarch64 rows at the \
             other width, which the target witness holds (toolchain.target.abi).",
            {
                let mut l = linked_default();
                l.class64 = false;
                l.e_machine = EM_AARCH64;
                l.bind_now = BindNow::Tag;
                l.property = Some((GNU_PROPERTY_AARCH64_FEATURE_1_AND, AARCH64_FEATURE_1_BTI));
                l.object().build()
            },
        ),
        fixture(
            "elf32-le-x86_64-x32-exec",
            "ELF32 little-endian x86-64 (the x32 ABI) executable: EM_X86_64 at ELFCLASS32, \
             DF_1_NOW, PT_GNU_RELRO, IBT|SHSTK property. The family of the x86_64 rows at the \
             other width; chard refuses -mx32 in a profile, and this is the artifact-level \
             backstop behind that refusal (toolchain.target.abi).",
            {
                let mut l = linked_default();
                l.class64 = false;
                l.e_type = ET_DYN;
                l.bind_now = BindNow::Flag1;
                l.object().build()
            },
        ),
        fixture(
            "elf64-be-ppc64-exec",
            "ELF64 big-endian PowerPC64 executable: EM_PPC64, DT_BIND_NOW, PT_GNU_RELRO, no \
             property note. machine reads ppc64 and elf_data big-endian, which is what tells \
             it from a ppc64le object (env::runs_natively on a ppc64le kernel).",
            {
                let mut l = linked_default();
                l.little = false;
                l.e_machine = EM_PPC64;
                l.bind_now = BindNow::Tag;
                l.property = None;
                l.object().build()
            },
        ),
        fixture(
            "elf64-be-aarch64-pie-bti-pac",
            "ELF64 big-endian aarch64 (aarch64_be) position-independent executable: \
             DF_1_NOW, PT_GNU_RELRO, BTI|PAC property. Exercises the big-endian arms of \
             every read at ELF64 width, and the aarch64 feature word on its own machine.",
            {
                let mut l = linked_default();
                l.little = false;
                l.e_machine = EM_AARCH64;
                l.e_type = ET_DYN;
                l.bind_now = BindNow::Flag1;
                l.property = Some((
                    GNU_PROPERTY_AARCH64_FEATURE_1_AND,
                    AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC,
                ));
                l.object().build()
            },
        ),
    ]
}

/// The static link: the one linked shape with no dynamic section at all.
fn static_fixtures() -> Vec<Fixture> {
    vec![fixture(
        "elf64-le-x86_64-exec-static",
        "ELF64 little-endian x86-64 statically linked executable: ET_EXEC, no interpreter, \
         no .dynamic, .dynsym or .dynstr and no PT_DYNAMIC, a .symtab, the CET property \
         and a non-executable PT_GNU_STACK. The shape of a -static link, which records no \
         DT_NEEDED list for as-needed to read and has no dynamic section for relro.",
        {
            let mut l = linked_default();
            l.interp = false;
            l.relro = false;
            l.dynamic = false;
            l.object().build()
        },
    )]
}

/// The static PIE with neither marker of executable output, as lld 10.0.0 links one under
/// `-z rodynamic`: the classifier's open case, which `report::link_mode_limitation` withholds
/// a reading of over an executable link's artifact.
fn unmarked_static_pie_fixture() -> Fixture {
    fixture(
        "elf64-le-x86_64-static-pie-unmarked",
        "ELF64 little-endian x86-64 static PIE as lld 10.0.0 links one under -z \
         rodynamic: ET_DYN, no interpreter, a dynamic section with no DT_NEEDED, and \
         neither DT_DEBUG nor DT_FLAGS_1, so no marker of executable output. The tag \
         shape lld 10.0.0 wrote under clang 10 -static-pie -Wl,-z,rodynamic on \
         2026-10-26, on an object that segfaults at startup. The reader classifies it as \
         a shared object, which the tags cannot contradict; an executable-mode probe's \
         reading of the classification over it is withheld.",
        {
            let mut l = linked_default();
            l.e_type = ET_DYN;
            l.interp = false;
            l.needs_libc = false;
            l.object().build()
        },
    )
}

/// The two link shapes on which the link classification and the `DT_NEEDED` list disagree,
/// which is why `as-needed` reads the list: a static PIE given an interpreter, which
/// classifies as a dynamic PIE and records no library, and a PIE linked with no
/// interpreter, which classifies as a static PIE and keeps its entries.
fn as_needed_shape_fixtures() -> Vec<Fixture> {
    vec![
        fixture(
            "elf64-le-x86_64-static-pie-interp",
            "ELF64 little-endian x86-64 static PIE given an interpreter, as GNU ld 2.46.1 \
             links one under -static-pie -Wl,--dynamic-linker=<path>: ET_DYN, PT_INTERP, \
             DF_1_PIE, DT_DEBUG, and a dynamic section with no DT_NEEDED, libm and libc having \
             come from their archives. The tag shape lld 10.0.0 and GNU ld 2.34 (Ubuntu 20.04 \
             x86_64), GNU ld 2.42 (Ubuntu 24.04 x86_64) and GNU ld 2.46.1 and lld 22.1.8 under \
             gcc 16.2.1 (Fedora 44 x86_64) wrote on 2026-10-27, on objects that crash at \
             startup. The reader classifies it as a dynamic PIE; as-needed reads the empty \
             list and withholds.",
            {
                let mut l = linked_default();
                l.e_type = ET_DYN;
                l.needs_libc = false;
                l.dt_debug = true;
                l.object().build()
            },
        ),
        fixture(
            "elf64-le-x86_64-static-pie-interp-libz",
            "ELF64 little-endian x86-64 static PIE given an interpreter and one shared \
             library, as GNU ld 2.34 and 2.42 and lld 10.0.0 link one under -static-pie \
             -Wl,--no-as-needed -Wl,-Bdynamic libz.so.1 -Wl,-Bstatic (Ubuntu 20.04 and 24.04 \
             x86_64, 2026-10-27): ET_DYN, PT_INTERP, DF_1_PIE, DT_DEBUG, and a dynamic section \
             whose one DT_NEEDED names libz.so.1, libm and libc having come from their \
             archives. The reader classifies it as a dynamic PIE; as-needed finds no entry \
             naming the C library and withholds, since the unused library's absence is the \
             archive's doing and not the flag's.",
            {
                let mut l = linked_default();
                l.e_type = ET_DYN;
                l.needs_libc = false;
                l.dt_debug = true;
                l.extra_dynstr = vec!["libz.so.1"];
                l.extra_dynamic = vec![(DT_NEEDED, DynValue::StrOff(".dynstr", "libz.so.1"))];
                l.object().build()
            },
        ),
        fixture(
            "elf64-le-x86_64-pie-no-interp-needed",
            "ELF64 little-endian x86-64 PIE linked with no interpreter, as lld 10.0.0 links \
             one under -pie -Wl,--no-dynamic-linker (Ubuntu 20.04 x86_64, clang 10, \
             2026-10-26): ET_DYN, no PT_INTERP, DT_DEBUG, no DT_FLAGS_1 (GNU ld 2.34, 2.42 \
             and 2.46.1 write DF_1_PIE beside DT_DEBUG on the same link), and DT_NEEDED \
             entries for libc.so.6 and libm.so.6 kept, on an object that crashes at startup. \
             The reader classifies it as a static PIE; as-needed reads the list, which \
             records what the linker kept.",
            {
                let mut l = linked_default();
                l.e_type = ET_DYN;
                l.interp = false;
                l.dt_debug = true;
                l.extra_dynstr = vec!["libm.so.6"];
                l.extra_dynamic = vec![(DT_NEEDED, DynValue::StrOff(".dynstr", "libm.so.6"))];
                l.object().build()
            },
        ),
    ]
}

/// Every fixture, in a fixed order.
///
/// A count is asserted against this list by `tests/elf_fixtures.rs`; adding an entry means
/// raising it there, which is the point.
pub fn catalogue() -> Vec<Fixture> {
    let mut all = bind_now_fixtures();
    all.extend(kind_fixtures());
    all.extend(static_fixtures());
    all.push(unmarked_static_pie_fixture());
    all.extend(as_needed_shape_fixtures());
    all.extend(width_and_order_fixtures());
    all.push(fixture(
        "elf64-le-x86_64-rel-functions",
        "ELF64 little-endian x86-64 relocatable object holding four sized functions in .text \
         and a .rela.text whose references fall inside them: three of the four refer to \
         __stack_chk_fail. What function_references attributes, and ssp-level-emitted reads \
         as strong.",
        relocatable_functions().build(),
    ));
    all.push(fixture(
        "elf32-le-i386-rel-functions",
        "ELF32 little-endian i386 relocatable object holding the same four functions and a \
         .rel.text of Elf32_Rel entries, no addend and the symbol index above bit 8, whose \
         references fall inside them: three of the four refer to __stack_chk_fail_local. \
         What function_references attributes through SHT_REL, and ssp-level-emitted reads \
         as strong.",
        relocatable_functions_rel32().build(),
    ));
    all.push(fixture(
        "elf64-le-riscv-rel-no-plt-got",
        "ELF64 little-endian RISC-V relocatable object in the shape gcc 16.1.1 writes for \
         the no-plt probe's caller under -fPIE -fno-plt -march=rv64gc_zicfilp_zicfiss \
         -fcf-protection=full: R_RISCV_GOT_HI20 against chard_no_plt_callee and \
         R_RISCV_PCREL_LO12_I against the local label .L0 (with GNU as's trailing space), \
         R_RISCV_RELAX and R_RISCV_ALIGN against symbol 0, a 0xc0000000 property holding 3 \
         (RISC-V landing pads and shadow stack, which read as the aarch64 word would be BTI \
         and PAC), and a .riscv.attributes section. What code_relocations names on RISC-V \
         and plt-bypassed reads as present.",
        relocatable_riscv_no_plt(RiscvCall::Got).build(),
    ));
    all.push(fixture(
        "elf64-le-x86_64-exec-cet-forged",
        "The control's x86-64 executable, its IBT|SHSTK property kept, with .text holding \
         main and the cet-endbr probe's three functions sized in .symtab at their addresses, \
         each beginning lea then ret and none with endbr64: the bytes gcc 16.1.1 and clang \
         22.1.8 compile under -O2 -fcf-protection=none, and the property GNU ld 2.46.1 forces \
         under -z ibt -z shstk (Fedora 44 x86_64, 2026-10-05). The marking and the code \
         disagree on one artifact: cet-marked reads the note present at full, \
         cet-endbr-emitted reads the code absent.",
        linked_cet_forged().build(),
    ));
    all
}
