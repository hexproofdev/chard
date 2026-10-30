// SPDX-License-Identifier: BSD-3-Clause

//! Objects drawn from a seed, for the tests that hold the reader to a property over many
//! objects rather than to a record over thirteen.
//!
//! The catalogue in the parent module pins one object per shape a reviewer thought of.
//! What it cannot reach is a combination nobody listed: a big-endian ELF32 shared object
//! with two property notes and a versioned canary in `.symtab`, say. A [`Spec`] is the
//! set of choices that separate such objects, drawn by [`Spec::draw`] from a generator the
//! caller seeds, and built with the same [`Object`] writer the fixtures use, so a
//! generated object and a fixture cannot disagree on layout. [`Spec::simpler`] lists the
//! specs one choice smaller, which is what a failing test shrinks through: a greedy walk
//! that keeps any smaller spec that still fails ends at one no single step can simplify
//! without the failure going away, and that is the spec the failure message prints.
//!
//! Every draw is an object `readelf` accepts and the reader reads whole, with no
//! malformed table; the one truncation a draw carries is the one a stripped
//! section-header table records by design. Cutting it is the caller's business
//! (`tests/elf_truncations.rs`).
//!
//! The draw takes a closure rather than a generator type, so this module needs nothing
//! from a sibling the test binaries declare and the fixture tests that never draw do not.

use super::{
    AARCH64_FEATURE_1_BTI, BindNow, Content, Covers, DF_1_NOOPEN, DF_1_NOW, DF_1_PIE, DF_BIND_NOW,
    DF_TEXTREL, DT_BIND_NOW, DT_DEBUG, DT_FLAGS, DT_FLAGS_1, DT_NEEDED, DT_RELR, DT_RELRENT,
    DT_RELRSZ, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB,
    DT_TEXTREL, DynValue, EM_386, EM_AARCH64, EM_PPC, EM_X86_64, ET_DYN, ET_EXEC, ET_REL,
    GNU_PROPERTY_AARCH64_FEATURE_1_AND, GNU_PROPERTY_X86_FEATURE_1_AND, NT_GNU_PROPERTY_TYPE_0,
    NoteSpec, Object, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD,
    PT_NOTE, SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE, SHF_STRINGS, SHF_WRITE, SHT_DYNAMIC, SHT_DYNSYM,
    SHT_NOTE, SHT_PROGBITS, SHT_STRTAB, SHT_SYMTAB, Section, Segment, Symbol, X86_FEATURE_1_IBT,
    property_desc, section,
};

/// A draw from `0..n`, supplied by the caller's seeded generator.
pub type Draw<'a> = &'a mut dyn FnMut(u64) -> u64;

/// The machines drawn from: the ten the reader names, and one it does not. The two
/// whose feature words the reader decodes are listed three times each, so a property
/// note on its own machine is drawn in about one object in ten.
pub const MACHINES: &[u16] = &[
    EM_X86_64, EM_X86_64, EM_X86_64, EM_AARCH64, EM_AARCH64, EM_AARCH64, EM_386, EM_PPC, 21, 40,
    243, 22, 8, 258, 0x4242,
];

const INTERPRETERS: &[&str] = &["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"];

const LIBRARIES: &[&str] = &[
    "libc.so.6",
    "libm.so.6",
    "libpthread.so.0",
    "libchard.so.1",
    "libz.so.1",
];

const PATHS: &[&str] = &[
    "/opt/chard/lib",
    "$ORIGIN/../lib",
    "/usr/local/lib:/opt/x/lib",
];

const SONAMES: &[&str] = &["libchard.so.1", "libgenerated.so.0"];

/// Names beside the watched ones, so a table is never only watched names.
const OTHER_SYMBOLS: &[&str] = &["main", "chard_local_helper", "memcpy", "_start"];

/// Version spellings `.strtab` stores in a name; `""` is the bare name.
const VERSIONS: &[&str] = &["", "", "@GLIBC_2.4", "@@GLIBC_2.2.5", "@GLIBC_2.3.4"];

/// Section names beyond the ones the layout needs, including names that do not begin with
/// `.`, which a parser keeping only dotted names once dropped.
const EXTRA_SECTIONS: &[&str] = &[
    ".rodata",
    ".data.rel.ro",
    ".chard.extra",
    "__libc_freeres_ptrs",
    "__ksymtab_gpl",
    ".gnu.warning.chard",
];

/// Lines a `.comment` carries, in the shapes the producers write.
const COMMENT_LINES: &[&str] = &[
    "GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)",
    "clang version 22.1.8 (Fedora 22.1.8-4.fc44)",
    "Linker: LLD 22.1.8",
    "mold 2.40.4 (compatible with GNU ld)",
    "GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0",
];

/// Lines of a `.chard.report`, in the `key=value` shape the probes embed. The runtime
/// fortify checks read this section's text, so a cut that takes its bytes is a fact
/// the truncation property has to see recorded.
const SELF_REPORT_LINES: &[&str] = &[
    "_FORTIFY_IMPL=glibc",
    "_FORTIFY_IMPL=fortify-headers",
    "_FORTIFY_SOURCE=3",
    "__SSP_STRONG__=3",
    "__PIE__=2",
];

/// Arguments of a `.GCC.command.line`, as `-frecord-gcc-switches` writes them.
const COMMAND_LINE_ARGS: &[&str] = &[
    "-O2",
    "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=3",
    "-fcf-protection=full",
    "-mbranch-protection=standard",
];

/// The choices that separate one generated object from another.
#[derive(Clone, Debug)]
pub struct Spec {
    pub class64: bool,
    pub little: bool,
    pub e_machine: u16,
    /// `ET_EXEC`, `ET_DYN` or `ET_REL`. A relocatable object carries no program headers
    /// and no dynamic section, whatever the fields below say; [`Spec::draw`] leaves them
    /// empty for one.
    pub e_type: u16,
    pub interp: Option<&'static str>,
    /// A `.dynamic`, `.dynsym` and `.dynstr`, with `PT_DYNAMIC`.
    pub dynamic: bool,
    /// One `NT_GNU_PROPERTY_TYPE_0` note per entry, each carrying one property.
    pub notes: Vec<(u32, u32)>,
    pub bind_now: BindNow,
    pub flags_textrel: bool,
    pub flags1_pie: bool,
    pub flags1_noopen: bool,
    pub dt_textrel: bool,
    pub dt_relr: bool,
    pub dt_debug: bool,
    pub soname: Option<&'static str>,
    pub needed: Vec<&'static str>,
    pub rpath: Vec<&'static str>,
    pub runpath: Vec<&'static str>,
    pub relro: bool,
    /// `Some(executable)` for a `PT_GNU_STACK`.
    pub gnu_stack: Option<bool>,
    pub strip_section_headers: bool,
    /// The section-header table before the section contents; see
    /// [`Object::section_headers_first`].
    pub section_headers_first: bool,
    /// `(name, defined)`, bare as `.dynstr` stores them.
    pub dynsym: Vec<(&'static str, bool)>,
    /// `(name as stored, defined)`; a name may carry a version.
    pub symtab: Option<Vec<(&'static str, bool)>>,
    pub extra_sections: Vec<&'static str>,
    pub comment: Option<Vec<&'static str>>,
    /// A `.chard.report`, one NUL-terminated `key=value` line per entry; never empty,
    /// so a whole object's `self_report` is text a cut can take.
    pub self_report: Option<Vec<&'static str>>,
    /// A `.GCC.command.line`, one NUL-terminated argument per entry; never empty.
    pub command_line: Option<Vec<&'static str>>,
    /// The order `.dynamic`'s entries are written in, as a rotation.
    pub dynamic_rotation: usize,
    /// The order the sections' bytes are laid out in: `0` is declaration order, and any
    /// other value seeds a shuffle. A file cut short loses a suffix of the layout, so
    /// without the shuffle every cut lost the same tables in the same order, and a fact
    /// that moved was covered by whichever later table went with it.
    pub section_order: u64,
}

fn pick<T: Copy>(draw: Draw<'_>, items: &[T]) -> T {
    let n = u64::try_from(items.len()).expect("a length fits u64");
    items[usize::try_from(draw(n)).expect("an index fits usize")]
}

fn coin(draw: Draw<'_>, num: u64, den: u64) -> bool {
    draw(den) < num
}

fn some_of<T: Copy>(draw: Draw<'_>, items: &[T], max: u64) -> Vec<T> {
    let n = draw(max + 1);
    (0..n).map(|_| pick(draw, items)).collect()
}

/// One time in three, one to three entries of `items`; never an empty list, so the
/// section drawn from it has text a cut can take.
fn some_lines(draw: Draw<'_>, items: &[&'static str]) -> Option<Vec<&'static str>> {
    coin(draw, 1, 3).then(|| {
        let mut lines = vec![pick(draw, items)];
        lines.extend(some_of(draw, items, 2));
        lines
    })
}

/// A static name for a composed string. Bounded by the case count, and a test binary's
/// lifetime is the lifetime the builder's `&'static str` fields ask for.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn symbol_name(draw: Draw<'_>) -> &'static str {
    if coin(draw, 2, 3) {
        pick(draw, chard::elf::WATCHED_SYMBOLS)
    } else {
        pick(draw, OTHER_SYMBOLS)
    }
}

/// Fisher-Yates over `items`, driven by an LCG seeded with `key`; `0` leaves the order.
fn shuffle<T>(items: &mut [T], key: u64) {
    if key == 0 {
        return;
    }
    let mut state = key;
    for i in (1..items.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let bound = u64::try_from(i + 1).expect("an index fits u64");
        let j = usize::try_from((state >> 33) % bound).expect("below a usize bound");
        items.swap(i, j);
    }
}

impl Spec {
    /// One object's choices.
    pub fn draw(draw: Draw<'_>) -> Self {
        let e_type = pick(draw, &[ET_EXEC, ET_DYN, ET_DYN, ET_REL]);
        let e_machine = pick(draw, MACHINES);
        let linked = e_type != ET_REL;
        let dynamic = linked && coin(draw, 5, 6);
        // The machine's own feature type three times in four where it has one, the
        // other type otherwise, and the low bit set three times in four, so the decoded
        // arm is drawn often and the undecoded one is still drawn.
        let native = match e_machine {
            EM_X86_64 | EM_386 => Some(GNU_PROPERTY_X86_FEATURE_1_AND),
            EM_AARCH64 => Some(GNU_PROPERTY_AARCH64_FEATURE_1_AND),
            _ => None,
        };
        let notes = (0..draw(3))
            .map(|_| {
                let pr_type = match native {
                    Some(t) if coin(draw, 3, 4) => t,
                    _ => pick(
                        draw,
                        &[
                            GNU_PROPERTY_X86_FEATURE_1_AND,
                            GNU_PROPERTY_AARCH64_FEATURE_1_AND,
                        ],
                    ),
                };
                let low = u32::from(coin(draw, 3, 4));
                (pr_type, u32::try_from(draw(16)).expect("below 16") | low)
            })
            .collect();
        let dynsym = if dynamic {
            (0..draw(6))
                .map(|_| (symbol_name(draw), coin(draw, 1, 3)))
                .collect()
        } else {
            Vec::new()
        };
        let symtab = coin(draw, 4, 5).then(|| {
            (0..draw(7))
                .map(|_| {
                    let name = symbol_name(draw);
                    let version = pick(draw, VERSIONS);
                    let stored = if version.is_empty() {
                        name
                    } else {
                        leak(format!("{name}{version}"))
                    };
                    (stored, coin(draw, 1, 2))
                })
                .collect()
        });
        Self {
            class64: coin(draw, 2, 3),
            little: coin(draw, 3, 4),
            e_machine,
            e_type,
            interp: (dynamic && coin(draw, 2, 3)).then(|| pick(draw, INTERPRETERS)),
            dynamic,
            notes,
            bind_now: if dynamic {
                pick(
                    draw,
                    &[BindNow::Absent, BindNow::Tag, BindNow::Flag, BindNow::Flag1],
                )
            } else {
                BindNow::Absent
            },
            flags_textrel: dynamic && coin(draw, 1, 5),
            flags1_pie: dynamic && coin(draw, 1, 3),
            flags1_noopen: dynamic && coin(draw, 1, 6),
            dt_textrel: dynamic && coin(draw, 1, 6),
            dt_relr: dynamic && coin(draw, 1, 4),
            dt_debug: dynamic && coin(draw, 1, 3),
            soname: (dynamic && coin(draw, 1, 3)).then(|| pick(draw, SONAMES)),
            needed: if dynamic {
                some_of(draw, LIBRARIES, 3)
            } else {
                Vec::new()
            },
            rpath: if dynamic {
                some_of(draw, PATHS, 2)
            } else {
                Vec::new()
            },
            runpath: if dynamic {
                some_of(draw, PATHS, 2)
            } else {
                Vec::new()
            },
            relro: linked && coin(draw, 2, 3),
            gnu_stack: (linked && coin(draw, 5, 6)).then(|| coin(draw, 1, 4)),
            strip_section_headers: linked && coin(draw, 1, 8),
            section_headers_first: coin(draw, 1, 2),
            dynsym,
            symtab,
            extra_sections: some_of(draw, EXTRA_SECTIONS, 3),
            comment: coin(draw, 1, 2).then(|| some_of(draw, COMMENT_LINES, 4)),
            self_report: some_lines(draw, SELF_REPORT_LINES),
            command_line: some_lines(draw, COMMAND_LINE_ARGS),
            dynamic_rotation: usize::try_from(draw(16)).expect("below 16"),
            section_order: draw(u64::MAX),
        }
    }

    /// Every spec one choice smaller than this one, for shrinking a failure.
    ///
    /// Each candidate drops one entry of a list, clears one flag or option, or moves the
    /// width, byte order or machine to the default fixture's. `e_type` and `dynamic` are
    /// not shrunk: the other fields are drawn for them, and changing either under the
    /// rest would build an object [`Spec::draw`] never produces.
    #[must_use]
    pub fn simpler(&self) -> Vec<Self> {
        let mut out = Vec::new();
        let mut with = |f: &dyn Fn(&mut Self)| {
            let mut s = self.clone();
            f(&mut s);
            out.push(s);
        };
        macro_rules! drop_each {
            ($field:ident) => {
                for i in 0..self.$field.len() {
                    with(&|s: &mut Self| {
                        s.$field.remove(i);
                    });
                }
            };
        }
        drop_each!(notes);
        drop_each!(needed);
        drop_each!(rpath);
        drop_each!(runpath);
        drop_each!(dynsym);
        drop_each!(extra_sections);
        // An optional list: each entry dropped, and the whole list.
        macro_rules! drop_optional {
            ($field:ident) => {
                if let Some(list) = &self.$field {
                    for i in 0..list.len() {
                        with(&|s: &mut Self| {
                            if let Some(list) = &mut s.$field {
                                list.remove(i);
                            }
                        });
                    }
                    with(&|s: &mut Self| s.$field = None);
                }
            };
        }
        drop_optional!(symtab);
        drop_optional!(comment);
        drop_optional!(self_report);
        drop_optional!(command_line);
        macro_rules! clear {
            ($field:ident, $value:expr) => {
                with(&|s: &mut Self| s.$field = $value);
            };
        }
        if self.interp.is_some() {
            clear!(interp, None);
        }
        if self.soname.is_some() {
            clear!(soname, None);
        }
        if self.bind_now != BindNow::Absent {
            clear!(bind_now, BindNow::Absent);
        }
        for (set, which) in [
            (self.flags_textrel, 0),
            (self.flags1_pie, 1),
            (self.flags1_noopen, 2),
            (self.dt_textrel, 3),
            (self.dt_relr, 4),
            (self.dt_debug, 5),
            (self.relro, 6),
            (self.strip_section_headers, 7),
            (self.section_headers_first, 8),
        ] {
            if set {
                with(&|s: &mut Self| match which {
                    0 => s.flags_textrel = false,
                    1 => s.flags1_pie = false,
                    2 => s.flags1_noopen = false,
                    3 => s.dt_textrel = false,
                    4 => s.dt_relr = false,
                    5 => s.dt_debug = false,
                    6 => s.relro = false,
                    7 => s.strip_section_headers = false,
                    _ => s.section_headers_first = false,
                });
            }
        }
        if self.gnu_stack.is_some() {
            clear!(gnu_stack, None);
        }
        if self.section_order != 0 {
            clear!(section_order, 0);
        }
        if self.dynamic_rotation != 0 {
            clear!(dynamic_rotation, 0);
        }
        if !self.class64 {
            clear!(class64, true);
        }
        if !self.little {
            clear!(little, true);
        }
        if self.e_machine != EM_X86_64 {
            clear!(e_machine, EM_X86_64);
        }
        out
    }

    fn word(&self) -> u64 {
        if self.class64 { 8 } else { 4 }
    }

    fn dynamic_entries(&self) -> Vec<(i64, DynValue)> {
        let mut entries: Vec<(i64, DynValue)> = Vec::new();
        for lib in &self.needed {
            entries.push((DT_NEEDED, DynValue::StrOff(".dynstr", lib)));
        }
        if let Some(name) = self.soname {
            entries.push((DT_SONAME, DynValue::StrOff(".dynstr", name)));
        }
        for p in &self.rpath {
            entries.push((DT_RPATH, DynValue::StrOff(".dynstr", p)));
        }
        for p in &self.runpath {
            entries.push((DT_RUNPATH, DynValue::StrOff(".dynstr", p)));
        }
        entries.push((DT_STRTAB, DynValue::AddrOf(".dynstr")));
        entries.push((DT_SYMTAB, DynValue::AddrOf(".dynsym")));
        entries.push((DT_STRSZ, DynValue::SizeOf(".dynstr")));
        entries.push((
            DT_SYMENT,
            DynValue::Const(if self.class64 { 24 } else { 16 }),
        ));
        let mut flags = 0u64;
        let mut flags1 = 0u64;
        match self.bind_now {
            BindNow::Absent => {}
            BindNow::Tag => entries.push((DT_BIND_NOW, DynValue::Const(0))),
            BindNow::Flag => flags |= DF_BIND_NOW,
            BindNow::Flag1 => flags1 |= DF_1_NOW,
        }
        if self.flags_textrel {
            flags |= DF_TEXTREL;
        }
        if self.flags1_pie {
            flags1 |= DF_1_PIE;
        }
        if self.flags1_noopen {
            flags1 |= DF_1_NOOPEN;
        }
        if flags != 0 {
            entries.push((DT_FLAGS, DynValue::Const(flags)));
        }
        if flags1 != 0 {
            entries.push((DT_FLAGS_1, DynValue::Const(flags1)));
        }
        if self.dt_textrel {
            entries.push((DT_TEXTREL, DynValue::Const(0)));
        }
        if self.dt_relr {
            entries.push((DT_RELR, DynValue::AddrOf(".text")));
            entries.push((DT_RELRSZ, DynValue::Const(self.word())));
            entries.push((DT_RELRENT, DynValue::Const(self.word())));
        }
        if self.dt_debug {
            entries.push((DT_DEBUG, DynValue::Const(0)));
        }
        let n = entries.len();
        entries.rotate_left(self.dynamic_rotation % n);
        entries
    }

    fn dynstr(&self) -> Vec<&'static str> {
        let mut strings: Vec<&'static str> = Vec::new();
        strings.extend(&self.needed);
        strings.extend(self.soname);
        strings.extend(&self.rpath);
        strings.extend(&self.runpath);
        strings.extend(self.dynsym.iter().map(|(n, _)| *n));
        strings
    }

    fn symbols(list: &[(&'static str, bool)]) -> Content {
        Content::Symbols(
            list.iter()
                .map(|(name, defined)| Symbol {
                    name,
                    defined_in: defined.then_some(".text"),
                    st_other: 0,
                })
                .collect(),
        )
    }

    /// `.dynsym`, `.dynstr` and `.dynamic` for a dynamic object, and `.symtab` with
    /// `.strtab` where the spec carries one.
    fn symbol_sections(&self) -> Vec<Section> {
        let entsize = if self.class64 { 24 } else { 16 };
        let mut sections = Vec::new();
        if self.dynamic {
            sections.push(Section {
                name: ".dynsym",
                sh_type: SHT_DYNSYM,
                flags: SHF_ALLOC,
                addralign: 8,
                entsize,
                link: Some(".dynstr"),
                info: 1,
                content: Self::symbols(&self.dynsym),
            });
            sections.push(section(
                ".dynstr",
                SHT_STRTAB,
                SHF_ALLOC,
                1,
                Content::Strings(self.dynstr()),
            ));
            sections.push(Section {
                name: ".dynamic",
                sh_type: SHT_DYNAMIC,
                flags: SHF_ALLOC | SHF_WRITE,
                addralign: 8,
                entsize: 2 * self.word(),
                link: Some(".dynstr"),
                info: 0,
                content: Content::Dynamic(self.dynamic_entries()),
            });
        }
        if let Some(symtab) = &self.symtab {
            sections.push(Section {
                name: ".symtab",
                sh_type: SHT_SYMTAB,
                flags: 0,
                addralign: 8,
                entsize,
                link: Some(".strtab"),
                info: 1,
                content: Self::symbols(symtab),
            });
            sections.push(section(
                ".strtab",
                SHT_STRTAB,
                0,
                1,
                Content::Strings(symtab.iter().map(|(n, _)| *n).collect()),
            ));
        }
        sections
    }

    /// `.chard.report`'s text as `section_text` returns it: NULs as newlines, trimmed.
    #[must_use]
    pub fn self_report_text(&self) -> String {
        self.self_report
            .as_ref()
            .map(|lines| lines.join("\n"))
            .unwrap_or_default()
    }

    /// `.GCC.command.line`'s text as `section_text` returns it.
    #[must_use]
    pub fn command_line_text(&self) -> String {
        self.command_line
            .as_ref()
            .map(|args| args.join("\n"))
            .unwrap_or_default()
    }

    fn sections(&self) -> Vec<Section> {
        let align = self.word();
        let mut sections = Vec::new();
        if let Some(path) = self.interp {
            let mut bytes = path.as_bytes().to_vec();
            bytes.push(0);
            sections.push(section(
                ".interp",
                SHT_PROGBITS,
                SHF_ALLOC,
                1,
                Content::Bytes(bytes),
            ));
        }
        if !self.notes.is_empty() {
            sections.push(section(
                ".note.gnu.property",
                SHT_NOTE,
                SHF_ALLOC,
                align,
                Content::Notes(
                    self.notes
                        .iter()
                        .map(|(pr_type, value)| NoteSpec {
                            owner: "GNU",
                            ntype: NT_GNU_PROPERTY_TYPE_0,
                            desc: property_desc(*pr_type, *value, self.little, align),
                        })
                        .collect(),
                ),
            ));
        }
        sections.push(section(
            ".text",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            16,
            Content::Bytes(vec![0xc3; 16]),
        ));
        sections.extend(self.symbol_sections());
        for name in &self.extra_sections {
            sections.push(section(
                name,
                SHT_PROGBITS,
                0,
                1,
                Content::Bytes(name.as_bytes().to_vec()),
            ));
        }
        if let Some(lines) = &self.comment {
            let mut bytes = Vec::new();
            for line in lines {
                bytes.extend_from_slice(line.as_bytes());
                bytes.push(0);
            }
            sections.push(section(
                ".comment",
                SHT_PROGBITS,
                SHF_MERGE | SHF_STRINGS,
                1,
                Content::Bytes(bytes),
            ));
        }
        // Read as text by name: a tail cut can take their bytes while `.shstrtab` and
        // the header table survive, which is the recording site `section_text` owns.
        for (name, strings) in [
            (".chard.report", &self.self_report),
            (".GCC.command.line", &self.command_line),
        ] {
            if let Some(strings) = strings {
                let mut bytes = Vec::new();
                for s in strings {
                    bytes.extend_from_slice(s.as_bytes());
                    bytes.push(0);
                }
                sections.push(section(name, SHT_PROGBITS, 0, 1, Content::Bytes(bytes)));
            }
        }
        // `.shstrtab` is written here rather than appended by `Object::build`, so the
        // shuffle places it too: appended, it was last in every layout, and every cut
        // took the section names, and `.comment` with them, whatever else it took.
        let mut names: Vec<&'static str> = sections.iter().map(|s| s.name).collect();
        names.push(".shstrtab");
        sections.push(section(
            ".shstrtab",
            SHT_STRTAB,
            0,
            1,
            Content::Strings(names),
        ));
        shuffle(&mut sections, self.section_order);
        sections
    }

    fn segments(&self) -> Vec<Segment> {
        if self.e_type == ET_REL {
            return Vec::new();
        }
        let mut segments = vec![Segment {
            p_type: PT_LOAD,
            flags: PF_R | PF_W | PF_X,
            align: 0x1000,
            covers: Covers::File,
        }];
        if self.interp.is_some() {
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
        if !self.notes.is_empty() {
            segments.push(Segment {
                p_type: PT_NOTE,
                flags: PF_R,
                align: self.word(),
                covers: Covers::Section(".note.gnu.property"),
            });
        }
        if self.relro {
            segments.push(Segment {
                p_type: PT_GNU_RELRO,
                flags: PF_R,
                align: 1,
                covers: Covers::Section(if self.dynamic { ".dynamic" } else { ".text" }),
            });
        }
        if let Some(executable) = self.gnu_stack {
            segments.push(Segment {
                p_type: PT_GNU_STACK,
                flags: if executable {
                    PF_R | PF_W | PF_X
                } else {
                    PF_R | PF_W
                },
                align: 16,
                covers: Covers::Nothing,
            });
        }
        segments
    }

    /// The object, `.shstrtab` included; serialised by [`Spec::build`].
    #[must_use]
    pub fn object(&self) -> Object {
        Object {
            class64: self.class64,
            little: self.little,
            e_type: self.e_type,
            e_machine: self.e_machine,
            base: if self.class64 { 0x40_0000 } else { 0x0804_8000 },
            sections: self.sections(),
            segments: self.segments(),
            strip_section_headers: self.strip_section_headers,
            section_headers_first: self.section_headers_first,
        }
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.object().serialise()
    }

    /// The coverage buckets this spec falls in, for the tally a generated test prints and
    /// holds to a floor.
    #[must_use]
    pub fn buckets(&self) -> Vec<&'static str> {
        let mut b = vec![
            if self.class64 { "elf64" } else { "elf32" },
            if self.little {
                "little-endian"
            } else {
                "big-endian"
            },
            match self.e_type {
                ET_EXEC => "ET_EXEC",
                ET_DYN => "ET_DYN",
                _ => "ET_REL",
            },
            match self.notes.len() {
                0 => "no property note",
                1 => "one property note",
                _ => "several property notes",
            },
        ];
        if self.dynamic {
            b.push(match self.bind_now {
                BindNow::Absent => "no BIND_NOW",
                BindNow::Tag => "DT_BIND_NOW",
                BindNow::Flag => "DF_BIND_NOW",
                BindNow::Flag1 => "DF_1_NOW",
            });
        } else {
            b.push("no dynamic section");
        }
        if self.strip_section_headers {
            b.push("section headers stripped");
        } else if self.section_headers_first {
            b.push("section headers first");
        }
        if self.interp.is_some() {
            b.push("interpreter");
        }
        if self.e_machine == EM_AARCH64
            && self.notes.iter().any(|(t, v)| {
                *t == GNU_PROPERTY_AARCH64_FEATURE_1_AND && v & AARCH64_FEATURE_1_BTI != 0
            })
        {
            b.push("aarch64 BTI marked");
        }
        if matches!(self.e_machine, EM_X86_64 | EM_386)
            && self
                .notes
                .iter()
                .any(|(t, v)| *t == GNU_PROPERTY_X86_FEATURE_1_AND && v & X86_FEATURE_1_IBT != 0)
        {
            b.push("x86 IBT marked");
        }
        if self
            .symtab
            .as_ref()
            .is_some_and(|t| t.iter().any(|(n, _)| n.contains('@')))
        {
            b.push("versioned .symtab name");
        }
        if self.comment.is_some() {
            b.push(".comment");
        }
        if self.self_report.is_some() {
            b.push(".chard.report");
        }
        if self.command_line.is_some() {
            b.push(".GCC.command.line");
        }
        b
    }
}

/// The buckets a default-sized run must reach, so a generator that stopped drawing a
/// shape fails rather than passing over fewer shapes than it claims.
pub const REQUIRED_BUCKETS: &[&str] = &[
    "elf64",
    "elf32",
    "little-endian",
    "big-endian",
    "ET_EXEC",
    "ET_DYN",
    "ET_REL",
    "no property note",
    "one property note",
    "several property notes",
    "no BIND_NOW",
    "DT_BIND_NOW",
    "DF_BIND_NOW",
    "DF_1_NOW",
    "no dynamic section",
    "section headers stripped",
    "section headers first",
    "interpreter",
    "aarch64 BTI marked",
    "x86 IBT marked",
    "versioned .symtab name",
    ".comment",
    ".chard.report",
    ".GCC.command.line",
];
