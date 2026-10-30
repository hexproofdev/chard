// SPDX-License-Identifier: BSD-3-Clause

//! The reader against `readelf`, over the checked-in fixtures, a sample of the host's
//! own objects, and objects drawn from a printed seed
//! (`generated_objects_agree_with_readelf`).
//!
//! Every other ELF test in this suite asserts the reader against itself or against a
//! record the reader wrote. This one asks an independent implementation the same
//! questions and diffs the answers, fact by fact, and it is the only test that can say
//! the reader is right; every other can say only that it agrees with itself. `readelf` is an oracle here and nowhere
//! else: `src/elf.rs` parses the bytes itself, for the reasons its header gives, and
//! nothing in `src/` runs a binutils program.
//!
//! Two oracles are accepted, in this order: GNU `readelf`, and `llvm-readelf`, whose
//! default output style is GNU's. The parser below reads the GNU layout with `-W`. The
//! fixtures were compared against `llvm-readelf` while it was written, and the parser is
//! pinned on a captured GNU `readelf` transcript; `eu-readelf` prints a different layout
//! and is not read.
//!
//! ## What is compared
//!
//! Class, type and machine from the file header; `PT_INTERP`, `PT_GNU_RELRO` and the
//! `PT_GNU_STACK` flags from the program headers; the set of dynamic tags and the
//! `NEEDED`, `RPATH` and `RUNPATH` strings; `BIND_NOW` in its three spellings,
//! `DF_1_NOOPEN`, `DF_1_PIE`, `TEXTREL` in both spellings, `DT_RELR`, `DT_DEBUG`, which the
//! link classification reads, and `DT_SONAME`, which it records and does not consult; the
//! x86 and aarch64 feature bits from the property note; the section names; the presence,
//! tables and definedness of every watched symbol in both directions; the distinct
//! symbol count; and the lines of `.comment`, from a second oracle run with `-p`, which
//! is what `toolchain.linker.artifact` reads. A relocatable object's code relocations
//! (`ElfFacts::code_relocations`) are compared in their own test,
//! `code_relocations_agree_with_readelf`, from a `-r` run over x86_64, i386 and aarch64
//! objects the builder writes and the host's `cc` compiles, and RISC-V objects the builder
//! writes. Each comparison is counted, and the total
//! is printed with the number of files it ran over, because a differential over zero
//! files is the clean-looking zero this project refuses.
//!
//! ## Both states, or no discrimination
//!
//! Agreement on a fact that was false in every file compared says nothing about a reader
//! that answers false unconditionally. A synthetic corpus that never showed the oracle a
//! linked object without `PT_GNU_STACK`, a `TEXTREL` spelled only as `DF_TEXTREL`, or a
//! watched symbol that is defined would compare `gnu_stack_present`, the second `textrel`
//! spelling and the definedness of every watched symbol in one state only, and the checks
//! that read them would be held to the reader's own consistency in the other. Each fact in
//! [`DISCRIMINATED`] is tallied by the
//! state the oracle read, and the synthetic arm (the fixtures plus [`discriminators`])
//! must show the oracle each one both ways, with the reader agreeing both times. The
//! tallies are printed for the system arm as well, and asserted only for the synthetic
//! arm, whose contents do not depend on the host.
//!
//! ## Skips
//!
//! On a host whose `cc` emits ELF the oracle is required, through `common::refuse`, and
//! the system sample must be non-empty. On any other host a missing oracle is announced
//! as an arm not exercised and the test returns; the fixtures still run wherever an
//! oracle is on `PATH`, since `llvm-readelf` reads any ELF on any host.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
mod elf_builder;
mod seeded;

use chard::elf::{self, ElfFacts};
use elf_builder::generate::{REQUIRED_BUCKETS, Spec};

/// How many system objects to sample, across every root that exists.
const SYSTEM_SAMPLE: usize = 200;
/// Roots to sample from, in order. Merged-usr hosts alias some of these; the walk
/// dedupes by canonical path.
const SYSTEM_ROOTS: &[&str] = &["/usr/bin", "/usr/lib", "/usr/lib64", "/lib"];
/// An ELF object larger than this is skipped: `readelf -s` over a debug-heavy library is
/// slow, and the point is breadth. Each one skipped is counted and printed with the
/// differential's totals, so a sample the limit emptied reads as skipped rather than as
/// a root with nothing in it.
const MAX_SYSTEM_OBJECT: u64 = 32 * 1024 * 1024;

/// The facts the synthetic arm must show the oracle in both states. Named as
/// [`Diff::witness`] names them.
const DISCRIMINATED: &[&str] = &[
    "gnu_stack_present",
    "gnu_stack_executable",
    "textrel",
    "textrel as DT_TEXTREL",
    "textrel as DF_TEXTREL",
    "watched symbol present",
    "watched symbol defined",
    "watched symbol in .dynsym",
    "watched symbol in .symtab",
];

const DT_SONAME: u64 = 14;
const DT_DEBUG: u64 = 21;
const DT_TEXTREL: u64 = 22;
const DT_BIND_NOW: u64 = 24;
const DT_RELR: u64 = 36;

struct Oracle {
    program: &'static str,
    version: String,
}

/// The first oracle on `PATH`.
fn find_oracle() -> Option<Oracle> {
    for program in ["readelf", "llvm-readelf"] {
        if let Ok(out) = Command::new(program).arg("--version").output()
            && out.status.success()
        {
            let version = String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_owned();
            return Some(Oracle { program, version });
        }
    }
    None
}

/// What the oracle said about one file.
#[derive(Default, Debug)]
struct Seen {
    class: Option<u8>,
    /// `Data:` after "2's complement, ": `little endian` or `big endian`.
    data: Option<String>,
    e_type: Option<String>,
    pie_declared: bool,
    machine: Option<String>,
    interp: bool,
    gnu_relro: bool,
    /// `Some(executable)` when a `PT_GNU_STACK` was printed.
    gnu_stack: Option<bool>,
    dyn_tags: BTreeSet<u64>,
    needed: Vec<String>,
    rpath: Vec<String>,
    runpath: Vec<String>,
    flags_bind_now: bool,
    flags_textrel: bool,
    flags1_now: bool,
    flags1_pie: bool,
    flags1_noopen: bool,
    /// Every x86 feature word printed, one per note; the loader's view is their AND.
    x86_words: Vec<u32>,
    aarch64_words: Vec<u32>,
    sections: BTreeSet<String>,
    /// bare name -> (tables, defined)
    symbols: BTreeMap<String, (Vec<String>, bool)>,
}

/// Which block of the transcript a line belongs to.
#[derive(PartialEq, Eq)]
enum Block {
    Other,
    ProgramHeaders,
    Dynamic,
    Symbols(String),
}

fn bracketed(rest: &str) -> String {
    rest.split_once('[')
        .and_then(|(_, r)| r.rsplit_once(']'))
        .map(|(inner, _)| inner.to_owned())
        .unwrap_or_default()
}

/// The feature word a property line prints, read from its comma-separated items.
///
/// Each item reads as bits or fails the test. A named bit reads as its value, and a bit the
/// oracle has no name for reads from the number it prints in the name's place: GNU's
/// `<unknown: 4>` (hexadecimal, no prefix) and llvm's `<unknown flags: 0x30>` (every
/// unnamed bit at once). The list ends at the line's end or at the next property: with
/// `-W` GNU prints every property of a note on one line (`x86 feature: IBT, SHSTK, x86 ISA
/// needed: x86-64-baseline`), so an item that does not begin with `<` and carries a colon
/// is the next property's label. A bracketed item is never a label: `<corrupt length:
/// 0x8>`, which GNU 2.42, GNU 2.46.1 and llvm-readelf 22.1.8 all print for a feature
/// property whose data size is not 4, is an oracle stating no feature word, read as a
/// word of zero, since the reader reads no bit from such a property; any other bracketed
/// item it cannot read is a panic. An empty list is a word of zero (GNU's `AArch64
/// feature: ` for 0; x86 and llvm print `<None>`). Any other item is a panic naming it,
/// since a bit the parser cannot read would otherwise compare as a bit the oracle said was
/// clear. Dropping such an item is wrong: GNU readelf 2.42 (Ubuntu 24.04) has no name for GCS
/// and prints `AArch64 feature: BTI, <unknown: 4>` for a word of 5, which would read as an
/// oracle saying GCS is clear where the reader, and readelf 2.46.1's `BTI, GCS`, say set.
fn feature_word(list: &str, names: &[(&str, u32)]) -> u32 {
    if list.trim().is_empty() {
        return 0;
    }
    let mut word = 0;
    for item in list.split(',').map(str::trim) {
        if item == "<None>" {
            continue;
        }
        if let Some((_, bit)) = names.iter().find(|(n, _)| *n == item) {
            word |= bit;
            continue;
        }
        let unknown = item
            .strip_prefix("<unknown: ")
            .or_else(|| item.strip_prefix("<unknown flags: 0x"))
            .and_then(|rest| rest.strip_suffix('>'));
        if let Some(hex) = unknown {
            word |= u32::from_str_radix(hex, 16).unwrap_or_else(|e| {
                panic!("the oracle printed the feature {item:?} in {list:?}: {e}")
            });
            continue;
        }
        if item.starts_with("<corrupt length: 0x") && item.ends_with('>') {
            assert!(
                word == 0 && list.split(',').count() == 1,
                "the oracle printed {item:?} beside other items in {list:?}"
            );
            return 0;
        }
        if !item.starts_with('<') && item.contains(':') {
            break;
        }
        panic!(
            "the oracle printed the feature {item:?} in {list:?}, which this parser cannot \
             read as bits"
        );
    }
    word
}

impl Seen {
    /// Lines the file header, section table and notes contribute, wherever they sit.
    fn line_anywhere(&mut self, trimmed: &str) {
        if let Some(v) = trimmed.strip_prefix("Class:") {
            self.class = match v.trim() {
                "ELF64" => Some(64),
                "ELF32" => Some(32),
                _ => None,
            };
        } else if let Some(v) = trimmed.strip_prefix("Data:") {
            self.data = v
                .trim()
                .strip_prefix("2's complement, ")
                .map(|order| order.replace(' ', "-"));
        } else if let Some(v) = trimmed.strip_prefix("Type:") {
            let v = v.trim();
            self.e_type = v.split_whitespace().next().map(str::to_owned);
            self.pie_declared = v.contains("Position-Independent Executable");
        } else if let Some(v) = trimmed.strip_prefix("Machine:") {
            self.machine = Some(v.trim().to_owned());
        }

        // `[ 1] .interp PROGBITS ...`: a numbered row of the section table, whose name is
        // the token after the bracket, whatever it begins with. The reader lists every
        // non-empty name, so the oracle records every one: glibc carries
        // `__libc_freeres_ptrs`, a kernel module `__ksymtab_gpl` and `__param`, and a
        // parser that kept only names beginning with `.` reported each as a section the
        // reader had invented. The null section's row has no name, so after the bracket
        // and its one space the next character is another space, and the type is left
        // where it is; the header row's bracket holds `Nr`, and is no row.
        if let Some(rest) = trimmed.strip_prefix('[')
            && let Some((index, rest)) = rest.split_once(']')
            && index.trim().parse::<u32>().is_ok()
            && let Some(rest) = rest.strip_prefix(' ')
            && let Some(name) = rest.split_whitespace().next()
            && rest.starts_with(name)
        {
            self.sections.insert(name.to_owned());
        }

        // `x86 feature: IBT, SHSTK`, `AArch64 feature: BTI, PAC` (GNU) or
        // `aarch64 feature: ...` (llvm). `<None>` is a word of zero.
        if let Some(idx) = trimmed.find("feature:") {
            let head = trimmed[..idx].to_ascii_lowercase();
            let list = &trimmed[idx + "feature:".len()..];
            if head.ends_with("x86 ") {
                self.x86_words.push(feature_word(
                    list,
                    &[("IBT", 1), ("SHSTK", 2), ("LAM_U48", 4), ("LAM_U57", 8)],
                ));
            } else if head.ends_with("aarch64 ") {
                self.aarch64_words
                    .push(feature_word(list, &[("BTI", 1), ("PAC", 2), ("GCS", 4)]));
            }
        }
    }

    /// A program-header row. `false` when the line is not one, which ends the block.
    fn phdr_row(&mut self, trimmed: &str) -> bool {
        if trimmed.starts_with("Type ") || trimmed.starts_with("[Requesting") {
            return true;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(kind) = tokens.first() else {
            return false;
        };
        if !kind
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit())
        {
            return false;
        }
        match *kind {
            "INTERP" => self.interp = true,
            "GNU_RELRO" => self.gnu_relro = true,
            "GNU_STACK" => {
                // Wide format: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align.
                // With no flags at all the Flg column is empty and the row is one token
                // short.
                let flags = if tokens.len() >= 8 { tokens[6] } else { "" };
                self.gnu_stack = Some(flags.contains('E'));
            }
            _ => {}
        }
        true
    }

    /// A dynamic-section row. `false` when the line is not one, which ends the block.
    fn dynamic_row(&mut self, trimmed: &str) -> bool {
        if trimmed.starts_with("Tag ") {
            return true;
        }
        let Some((tag_hex, rest)) = trimmed.split_once(' ') else {
            return false;
        };
        let Ok(tag) = u64::from_str_radix(tag_hex.trim_start_matches("0x"), 16) else {
            return false;
        };
        if tag == 0 {
            return true; // DT_NULL: the oracle prints it, the reader stops before it.
        }
        self.dyn_tags.insert(tag);
        let rest = rest.trim();
        let (kind, rest) = rest.split_once(')').unwrap_or((rest, ""));
        let kind = kind.trim_start_matches('(');
        let words: Vec<&str> = rest.split_whitespace().collect();
        match kind {
            "NEEDED" => self.needed.push(bracketed(rest)),
            "RPATH" => self.rpath.push(bracketed(rest)),
            "RUNPATH" => self.runpath.push(bracketed(rest)),
            "FLAGS" => {
                self.flags_bind_now = words.contains(&"BIND_NOW");
                self.flags_textrel = words.contains(&"TEXTREL");
            }
            "FLAGS_1" => {
                self.flags1_now = words.contains(&"NOW");
                self.flags1_pie = words.contains(&"PIE");
                self.flags1_noopen = words.contains(&"NOOPEN");
            }
            _ => {}
        }
        true
    }

    /// A symbol row of `table`. `false` when the line is not one, which ends the block.
    ///
    /// The columns are `Num: Value Size Type Bind Vis Ndx Name`, and two of them are not
    /// where counting from the left puts them. The oracle prints any number of bracketed
    /// annotations between `Vis` and `Ndx`, and appends a parenthesised version index
    /// after `Name`. Read at a fixed `tokens[7]`, an `AArch64` row carrying `[VARIANT_PCS]`
    /// yields `UND` as the symbol's name and loses the name itself: measured on Fedora 44
    /// aarch64, 4 of 4758 rows of one `.dynsym` shift that way, which published `UND` as a
    /// name and dropped `_ZGVnN2v_cos`, `_ZGVnN2v_log`, `_ZGVnN4v_cosf` and
    /// `_ZGVnN4v_logf`. The reader had all four and the oracle did not, so the differential
    /// reported the reader as wrong. x86_64 never prints the annotation, so the same test
    /// passed there. `Ndx` is therefore found by skipping the annotations, and the name is
    /// the token after it.
    fn symbol_row(&mut self, table: &str, trimmed: &str) -> bool {
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.first() == Some(&"Num:") {
            return true;
        }
        if tokens.len() < 7
            || !tokens[0].ends_with(':')
            || tokens[0].trim_end_matches(':').parse::<u64>().is_err()
        {
            return false;
        }
        let kind = tokens[3];
        // `Vis` is tokens[5]; `Ndx` is the first token after it that is not an annotation.
        let ndx_at = (6..tokens.len())
            .find(|i| !tokens[*i].starts_with('['))
            .unwrap_or(tokens.len());
        let ndx = tokens.get(ndx_at).copied().unwrap_or("");
        // The name follows `Ndx` when there is one. A row that ends at `Ndx` is the null
        // symbol, and a trailing `(N)` is the version index rather than a name.
        let raw = tokens
            .get(ndx_at.saturating_add(1))
            .copied()
            .filter(|t| !(t.starts_with('(') && t.ends_with(')')))
            .unwrap_or("");
        let bare = raw.split('@').next().unwrap_or(raw);
        if kind == "SECTION" || bare.is_empty() {
            return true; // the null symbol, or a section symbol named by the oracle
        }
        let entry = self.symbols.entry(bare.to_owned()).or_default();
        if !entry.0.iter().any(|t| t == table) {
            entry.0.push(table.to_owned());
        }
        if ndx != "UND" {
            entry.1 = true;
        }
        true
    }
}

/// Parse the oracle's `-h -l -S -d -n -s -W` output.
///
/// A block ends at the first line that is not one of its rows, and a blank line does not
/// end it:
/// the oracle prints the dynamic section and the notes of a section-header-stripped file
/// back to back, and a parser waiting for a blank line would swallow the `x86 feature:`
/// line and report a disagreement with a reader that is right.
fn parse(text: &str) -> Seen {
    let mut seen = Seen::default();
    let mut block = Block::Other;
    for line in text.lines() {
        let trimmed = line.trim();
        let stays = match &block {
            Block::ProgramHeaders => seen.phdr_row(trimmed),
            Block::Dynamic => seen.dynamic_row(trimmed),
            Block::Symbols(table) => {
                let table = table.clone();
                seen.symbol_row(&table, trimmed)
            }
            Block::Other => false,
        };
        if stays {
            continue;
        }
        block = Block::Other;
        if trimmed.starts_with("Program Headers:") {
            block = Block::ProgramHeaders;
        } else if trimmed.starts_with("Dynamic section at offset") {
            block = Block::Dynamic;
        } else if let Some(rest) = trimmed.strip_prefix("Symbol table '")
            && let Some((name, _)) = rest.split_once('\'')
        {
            block = Block::Symbols(name.to_owned());
        } else {
            seen.line_anywhere(trimmed);
        }
    }
    seen
}

/// The strings the oracle printed for `-p .comment`: each `[ off] text` row, trimmed,
/// non-empty, first occurrence kept. `None` when no dump header appeared, which is how
/// both oracles answer for a section that is not there.
///
/// GNU `readelf` indents the rows and puts two spaces after the bracket; `llvm-readelf`
/// puts one and no indent. Both print the header line first.
fn parse_comment_dump(text: &str) -> Option<Vec<String>> {
    let mut seen_header = false;
    let mut lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("String dump of section") {
            seen_header = true;
            continue;
        }
        if !seen_header {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[')
            && let Some((_, text)) = rest.split_once(']')
        {
            let text = text.trim();
            if !text.is_empty() && !lines.iter().any(|l| l == text) {
                lines.push(text.to_owned());
            }
        }
    }
    seen_header.then_some(lines)
}

/// The machine names the oracle prints for the ones the reader names.
///
/// GNU readelf and llvm-readelf print the same ten strings for these values; an object
/// of any other machine is skipped here, since the reader renders it as unrecognised
/// with its number and the two oracles spell that differently.
fn machine_name(oracle: &str) -> Option<&'static str> {
    match oracle {
        "Intel 80386" => Some("i386"),
        "MIPS R3000" => Some("mips"),
        "PowerPC" => Some("ppc"),
        "PowerPC64" => Some("ppc64"),
        "IBM S/390" => Some("s390"),
        "ARM" => Some("arm"),
        "Advanced Micro Devices X86-64" => Some("x86_64"),
        "AArch64" => Some("aarch64"),
        "RISC-V" => Some("riscv"),
        "LoongArch" => Some("loongarch"),
        _ => None,
    }
}

/// The tags the reader listed, parsed back out of its `tag=value` strings.
fn reader_tags(facts: &ElfFacts) -> BTreeSet<u64> {
    facts
        .dynamic_tags
        .iter()
        .filter_map(|t| t.split_once('='))
        .filter_map(|(tag, _)| u64::from_str_radix(tag.trim_start_matches("0x"), 16).ok())
        .collect()
}

/// One file's comparison: how many facts were compared, how many could not be, and
/// every disagreement.
struct Diff<'a> {
    label: &'a str,
    compared: usize,
    skipped: usize,
    bad: Vec<String>,
    /// fact -> [times the oracle read it false, times it read it true]
    states: Tally,
}

type Tally = BTreeMap<&'static str, [usize; 2]>;

fn merge(into: &mut Tally, from: &Tally) {
    for (fact, [off, on]) in from {
        let slot = into.entry(fact).or_default();
        slot[0] += off;
        slot[1] += on;
    }
}

fn render(tally: &Tally) -> String {
    DISCRIMINATED
        .iter()
        .map(|fact| {
            let [off, on] = tally.get(fact).copied().unwrap_or_default();
            format!("{fact} {on}/{off}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl Diff<'_> {
    /// Record the state the oracle read `fact` in, for a comparison made alongside.
    fn witness(&mut self, fact: &'static str, theirs: bool) {
        assert!(
            DISCRIMINATED.contains(&fact),
            "{fact} is not in DISCRIMINATED"
        );
        self.states.entry(fact).or_default()[usize::from(theirs)] += 1;
    }

    fn check(&mut self, name: &str, ours: impl std::fmt::Debug, theirs: impl std::fmt::Debug) {
        self.compared += 1;
        let (ours, theirs) = (format!("{ours:?}"), format!("{theirs:?}"));
        if ours != theirs {
            self.bad.push(format!(
                "{}: {name}: chard {ours} / readelf {theirs}",
                self.label
            ));
        }
    }

    fn header_and_segments(&mut self, facts: &ElfFacts, seen: &Seen) {
        self.check("elf_class", facts.elf_class, seen.class.unwrap_or(0));
        self.check(
            "elf_data",
            facts.elf_data.map(|o| o.as_str().to_owned()),
            seen.data.clone(),
        );
        let their_type = match seen.e_type.as_deref() {
            Some("EXEC") => "ET_EXEC",
            Some("DYN") => "ET_DYN",
            Some("REL") => "ET_REL",
            Some("CORE") => "ET_CORE",
            _ => "?",
        };
        self.check("elf_type", &facts.elf_type, their_type);
        match seen.machine.as_deref().and_then(machine_name) {
            Some(m) => self.check("machine", &facts.machine, m),
            None => self.skipped += 1,
        }
        if seen.pie_declared {
            self.check("pie (oracle declares a PIE)", facts.pie, Some(true));
        }
        self.check("has_interp", facts.has_interp, seen.interp);

        if matches!(facts.elf_type.as_str(), "ET_EXEC" | "ET_DYN") {
            self.check("gnu_relro", facts.gnu_relro, Some(seen.gnu_relro));
            self.check(
                "gnu_stack_present",
                facts.gnu_stack_present,
                Some(seen.gnu_stack.is_some()),
            );
            self.witness("gnu_stack_present", seen.gnu_stack.is_some());
            if let Some(exec) = seen.gnu_stack {
                self.check(
                    "gnu_stack_executable",
                    facts.gnu_stack_executable,
                    Some(exec),
                );
                self.witness("gnu_stack_executable", exec);
            }
            let their_bind_now =
                seen.dyn_tags.contains(&DT_BIND_NOW) || seen.flags_bind_now || seen.flags1_now;
            self.check("bind_now", facts.bind_now, Some(their_bind_now));
        } else {
            self.skipped += 4;
        }
    }

    fn dynamic_and_notes(&mut self, facts: &ElfFacts, seen: &Seen) {
        self.check("dynamic tags", reader_tags(facts), &seen.dyn_tags);
        self.check("needed", &facts.needed, &seen.needed);
        // `readelf -d` lists every `DT_RPATH` and `DT_RUNPATH` entry; the loader keeps the
        // last of each, and so does the reader, which records the repeat `unread`. The
        // differential is held to that: the reader's list is readelf's last entry, and a
        // repeat is a truncation (the generated corpus writes several, so both hold).
        let last = |all: &[String]| all.last().cloned().into_iter().collect::<Vec<_>>();
        self.check("rpath", &facts.rpath, last(&seen.rpath));
        self.check("runpath", &facts.runpath, last(&seen.runpath));
        for (name, n) in [
            ("DT_RPATH", seen.rpath.len()),
            ("DT_RUNPATH", seen.runpath.len()),
        ] {
            let recorded = facts.truncations.iter().any(|t| {
                t.table == elf::ElfTable::Dynamic
                    && t.kind == elf::TruncationKind::Unread
                    && t.detail.starts_with(name)
            });
            self.check(&format!("{name} repeat recorded"), recorded, n > 1);
        }
        self.check("df_1_noopen", facts.df_1_noopen, seen.flags1_noopen);
        self.check("df_1_pie", facts.df_1_pie, seen.flags1_pie);
        let (tag, flag) = (seen.dyn_tags.contains(&DT_TEXTREL), seen.flags_textrel);
        self.check("textrel", facts.textrel, tag || flag);
        self.witness("textrel", tag || flag);
        self.witness("textrel as DT_TEXTREL", tag);
        self.witness("textrel as DF_TEXTREL", flag);
        self.check("dt_relr", facts.dt_relr, seen.dyn_tags.contains(&DT_RELR));
        self.check(
            "dt_debug",
            facts.dt_debug,
            seen.dyn_tags.contains(&DT_DEBUG),
        );
        self.check(
            "dt_soname",
            facts.dt_soname,
            seen.dyn_tags.contains(&DT_SONAME),
        );

        let x86 = seen
            .x86_words
            .iter()
            .copied()
            .reduce(|a, b| a & b)
            .unwrap_or(0);
        let arm = seen
            .aarch64_words
            .iter()
            .copied()
            .reduce(|a, b| a & b)
            .unwrap_or(0);
        self.check("x86_ibt", facts.x86_ibt, x86 & 1 != 0);
        self.check("x86_shstk", facts.x86_shstk, x86 & 2 != 0);
        self.check("aarch64_bti", facts.aarch64_bti, arm & 1 != 0);
        self.check("aarch64_pac", facts.aarch64_pac, arm & 2 != 0);
        self.check("aarch64_gcs", facts.aarch64_gcs, arm & 4 != 0);
    }

    fn sections_and_symbols(&mut self, facts: &ElfFacts, seen: &Seen) {
        // Reached by section header on both sides; with none, the reader says so and
        // the oracle prints nothing, and the comparison would be of two absences.
        let no_headers = facts.truncations.iter().any(|t| {
            t.table == chard::elf::ElfTable::Symbols
                && t.kind == chard::elf::TruncationKind::Unread
                && t.detail.starts_with("no section-header table")
        });
        if no_headers {
            self.skipped += 3;
            return;
        }
        let ours: BTreeSet<&String> = facts.sections.iter().collect();
        let theirs: BTreeSet<&String> = seen.sections.iter().collect();
        self.check("sections", ours, theirs);

        let mut ours_watched = BTreeMap::new();
        let mut theirs_watched = BTreeMap::new();
        for name in elf::WATCHED_SYMBOLS {
            if let Some(s) = facts.watched_symbols.get(*name) {
                let tables: BTreeSet<&String> = s.tables.iter().collect();
                ours_watched.insert(*name, (tables, s.defined));
            }
            let theirs = seen.symbols.get(*name);
            self.witness("watched symbol present", theirs.is_some());
            if let Some((tables, defined)) = theirs {
                self.witness("watched symbol defined", *defined);
                self.witness(
                    "watched symbol in .dynsym",
                    tables.iter().any(|t| t == ".dynsym"),
                );
                self.witness(
                    "watched symbol in .symtab",
                    tables.iter().any(|t| t == ".symtab"),
                );
                let tables: BTreeSet<&String> = tables.iter().collect();
                theirs_watched.insert(*name, (tables, *defined));
            }
        }
        self.check("watched symbols", ours_watched, theirs_watched);
        self.check("symbol_count", facts.symbol_count, seen.symbols.len());
    }

    /// `.comment`, as the reader lists it against the oracle's string dump.
    ///
    /// Compared as sets: the reader keeps first occurrences in file order and the oracle
    /// prints every string, and the field's consumer reads membership. Two absences (no
    /// section on either side) are a skip, and so is a section the reader recorded as
    /// unreadable, since the oracle would then be compared against a truncation.
    fn comment_lines(&mut self, facts: &ElfFacts, oracle: Option<Vec<String>>) {
        if facts.comment_truncation().is_some() {
            self.skipped += 1;
            return;
        }
        let present = facts.sections.iter().any(|s| s == ".comment");
        match oracle {
            None if !present => self.skipped += 1,
            None => self.check(
                "comment (oracle found no section)",
                &facts.comment,
                Vec::<String>::new(),
            ),
            Some(theirs) => {
                let ours: BTreeSet<&String> = facts.comment.iter().collect();
                let theirs: BTreeSet<&String> = theirs.iter().collect();
                self.check("comment", ours, theirs);
            }
        }
    }
}

/// What the walk found at one path.
#[derive(PartialEq, Eq)]
enum Candidate {
    NotElf,
    Elf,
    /// An ELF object over [`MAX_SYSTEM_OBJECT`]: counted, not compared.
    Oversized,
}

fn candidate(path: &Path) -> Candidate {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Candidate::NotElf;
    };
    if !meta.is_file() || meta.len() < 64 {
        return Candidate::NotElf;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return Candidate::NotElf;
    };
    let mut magic = [0u8; 4];
    if std::io::Read::read_exact(&mut f, &mut magic).is_err() || &magic != b"\x7fELF" {
        return Candidate::NotElf;
    }
    if meta.len() > MAX_SYSTEM_OBJECT {
        Candidate::Oversized
    } else {
        Candidate::Elf
    }
}

/// The system arm: the objects sampled, and the ELF objects the walk passed over for size.
#[derive(Default)]
struct Sample {
    objects: Vec<PathBuf>,
    oversized: usize,
}

/// Up to `cap` ELF files under `root`, in sorted order, regular files only; each ELF file
/// over the size limit met on the way is counted in `oversized`.
fn walk(root: &Path, cap: usize, out: &mut Vec<PathBuf>, oversized: &mut usize) {
    if out.len() >= cap {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if out.len() >= cap {
            return;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || path.to_string_lossy().contains("/debug/") {
            continue;
        }
        if meta.is_dir() {
            walk(&path, cap, out, oversized);
        } else {
            match candidate(&path) {
                Candidate::Elf => out.push(path),
                Candidate::Oversized => *oversized += 1,
                Candidate::NotElf => {}
            }
        }
    }
}

fn system_sample() -> Sample {
    let roots: Vec<PathBuf> = SYSTEM_ROOTS
        .iter()
        .map(Path::new)
        .filter(|r| r.is_dir())
        .filter_map(|r| r.canonicalize().ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut sample = Sample::default();
    if roots.is_empty() {
        return sample;
    }
    let per_root = SYSTEM_SAMPLE.div_ceil(roots.len());
    for root in &roots {
        let mut found = Vec::new();
        walk(root, per_root, &mut found, &mut sample.oversized);
        sample.objects.extend(found);
    }
    sample.objects.truncate(SYSTEM_SAMPLE);
    sample
}

fn announce(text: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

/// What the oracle says about `path`: the tables, and the `.comment` string dump from a
/// second run, since `-p` prints one section apart from everything else. `Err` carries
/// the oracle's stderr when it could not read the file.
fn ask_oracle(oracle: &Oracle, path: &Path) -> Result<(Seen, Option<Vec<String>>), String> {
    let out = Command::new(oracle.program)
        .args(["-h", "-l", "-S", "-d", "-n", "-s", "-W"])
        .arg(path)
        .output()
        .expect("running the oracle");
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    let seen = parse(&String::from_utf8_lossy(&out.stdout));
    let dump = Command::new(oracle.program)
        .args(["-p", ".comment", "-W"])
        .arg(path)
        .output()
        .expect("running the oracle for .comment");
    Ok((
        seen,
        parse_comment_dump(&String::from_utf8_lossy(&dump.stdout)),
    ))
}

/// Objects built for the oracle alone, each the catalogue's control with one fact set to
/// the state no fixture shows: no `PT_GNU_STACK`, `TEXTREL` as the `DF_TEXTREL` bit of
/// `DT_FLAGS` only, and a watched symbol defined, listed in `.dynsym` and absent from
/// `.symtab`, as a library whose static table was stripped exports one. They are not
/// fixtures, since no reader expectation is recorded for them; the oracle is their
/// expectation. [`the_discriminators_differ_from_the_control_where_they_claim`] holds
/// each to the one difference it claims, so a builder change that loses it fails there
/// before the tally reads it as a missing state.
fn discriminators() -> Vec<(&'static str, Vec<u8>)> {
    use elf_builder::{Content, DF_TEXTREL, DT_FLAGS, DynValue, PT_GNU_STACK, Symbol};

    let no_gnu_stack = {
        let mut o = elf_builder::linked_default().object();
        o.segments.retain(|s| s.p_type != PT_GNU_STACK);
        o.build()
    };
    let df_textrel = {
        let mut l = elf_builder::linked_default();
        l.extra_dynamic = vec![(DT_FLAGS, DynValue::Const(DF_TEXTREL))];
        l.object().build()
    };
    let defined_watched = {
        let mut o = elf_builder::linked_default().object();
        for s in &mut o.sections {
            match (s.name, &mut s.content) {
                (".dynsym", Content::Symbols(syms)) => syms.push(Symbol {
                    name: "__stack_chk_guard",
                    defined_in: Some(".text"),
                    st_other: 0,
                }),
                (".dynstr", Content::Strings(strings)) => {
                    strings.push("__stack_chk_guard");
                }
                _ => {}
            }
        }
        o.build()
    };
    vec![
        ("no-gnu-stack", no_gnu_stack),
        ("df-textrel", df_textrel),
        ("defined-watched-symbol", defined_watched),
    ]
}

/// `object` built, with each named section's `sh_entsize` set to `entsize` (ELF64 only).
///
/// The builder writes the record size; a declared size that differs is a forged header
/// (2026-10-20), which the loader and readelf read past at the record size.
fn with_declared_entsize(object: &elf_builder::Object, sections: &[&str], entsize: u64) -> Vec<u8> {
    assert!(object.class64, "the patch reads an ELF64 header");
    let mut d = object.build();
    let shoff = usize::try_from(u64::from_le_bytes(
        d[40..48].try_into().expect("eight bytes"),
    ))
    .expect("a fixture offset fits in usize");
    for name in sections {
        let index = object
            .sections
            .iter()
            .position(|s| s.name == *name)
            .unwrap_or_else(|| panic!("the object has no {name}"))
            + 1;
        let field = shoff + index * 64 + 56;
        d[field..field + 8].copy_from_slice(&entsize.to_le_bytes());
    }
    d
}

/// Objects whose headers declare an entry size the record is not: the catalogue's control
/// with `.dynsym` and `.symtab` at 48 over 24-byte symbols. readelf reports the invalid
/// `sh_entsize`, reads at the expected size and exits 0, so it is the expectation here as
/// for any other object. A reader that stepped by the declared size would read half the
/// symbols.
fn forged() -> Vec<(&'static str, Vec<u8>)> {
    vec![(
        "symbol-tables-entsize-48",
        with_declared_entsize(
            &elf_builder::linked_default().object(),
            &[".dynsym", ".symtab"],
            48,
        ),
    )]
}

/// What the differential runs over: the synthetic arm first, then the system sample.
struct Inputs {
    files: Vec<(String, PathBuf)>,
    fixtures: usize,
    discriminators: usize,
    forged: usize,
    system: usize,
    oversized: usize,
}

impl Inputs {
    fn synthetic(&self) -> usize {
        self.fixtures + self.discriminators + self.forged
    }
}

/// The fixtures and discriminators written to a scratch directory, then the system sample.
fn inputs(work: &common::Work) -> Inputs {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let catalogue = elf_builder::catalogue();
    for f in &catalogue {
        let path = work.path(&format!("{}.elf", f.name));
        std::fs::write(&path, &f.bytes).expect("writing a fixture");
        files.push((format!("fixture {}", f.name), path));
    }
    let built = discriminators();
    for (name, bytes) in &built {
        let path = work.path(&format!("discriminator-{name}.elf"));
        std::fs::write(&path, bytes).expect("writing a discriminator");
        files.push((format!("discriminator {name}"), path));
    }
    let forged = forged();
    for (name, bytes) in &forged {
        let path = work.path(&format!("forged-{name}.elf"));
        std::fs::write(&path, bytes).expect("writing a forged object");
        files.push((format!("forged {name}"), path));
    }
    let sample = system_sample();
    let system = sample.objects.len();
    for path in sample.objects {
        files.push((path.display().to_string(), path));
    }
    Inputs {
        files,
        fixtures: catalogue.len(),
        discriminators: built.len(),
        forged: forged.len(),
        system,
        oversized: sample.oversized,
    }
}

/// Each discriminator differs from the catalogue's control in the fact it names, as the
/// reader sees it. The oracle is not needed, so this runs on every host; it keeps the
/// synthetic arm's second state from resting on the tally alone.
#[test]
fn the_discriminators_differ_from_the_control_where_they_claim() {
    let work = common::Work::new("elf", "discriminators");
    let read = |name: &str, bytes: &[u8]| {
        let path = work.path(&format!("{name}.elf"));
        std::fs::write(&path, bytes).expect("writing");
        elf::facts_for(&path).expect("the reader reads its own builder's output")
    };
    let control = read("control", &elf_builder::linked_default().object().build());
    assert_eq!(control.gnu_stack_present, Some(true));
    assert!(!control.textrel);
    assert!(
        control.watched_symbols.values().all(|s| !s.defined),
        "the control defines no watched symbol"
    );
    let built = discriminators();
    assert_eq!(built.len(), 3);
    for (name, bytes) in &built {
        let facts = read(name, bytes);
        match *name {
            "no-gnu-stack" => assert_eq!(facts.gnu_stack_present, Some(false)),
            "df-textrel" => assert!(facts.textrel),
            "defined-watched-symbol" => {
                let guard = facts
                    .watched_symbols
                    .get("__stack_chk_guard")
                    .expect("__stack_chk_guard is listed");
                assert!(guard.defined);
                assert_eq!(guard.tables, vec![".dynsym".to_owned()]);
            }
            other => panic!("discriminator {other} claims no difference this test knows"),
        }
    }
}

/// What the differential found, summed over every file.
struct Totals {
    files: usize,
    facts_compared: usize,
    facts_skipped: usize,
    unreadable: Vec<String>,
    disagreements: Vec<String>,
    synthetic_states: Tally,
    system_states: Tally,
}

/// Ask the reader and the oracle about every input and diff the answers.
fn differential(oracle: &Oracle, inputs: &Inputs) -> Totals {
    let mut files = 0usize;
    let mut facts_compared = 0usize;
    let mut facts_skipped = 0usize;
    let mut unreadable = Vec::new();
    let mut disagreements = Vec::new();
    let mut synthetic_states = Tally::new();
    let mut system_states = Tally::new();
    for (index, (label, path)) in inputs.files.iter().enumerate() {
        let facts = match elf::facts_for(path) {
            Ok(f) => f,
            Err(e) => {
                unreadable.push(format!("{label}: chard: {e}"));
                continue;
            }
        };
        let (seen, comment) = match ask_oracle(oracle, path) {
            Ok(answer) => answer,
            Err(why) => {
                unreadable.push(format!("{label}: {}: {why}", oracle.program));
                continue;
            }
        };
        let mut diff = Diff {
            label,
            compared: 0,
            skipped: 0,
            bad: Vec::new(),
            states: Tally::new(),
        };
        diff.header_and_segments(&facts, &seen);
        diff.dynamic_and_notes(&facts, &seen);
        diff.sections_and_symbols(&facts, &seen);
        diff.comment_lines(&facts, comment);
        files += 1;
        facts_compared += diff.compared;
        facts_skipped += diff.skipped;
        disagreements.extend(diff.bad);
        if index < inputs.synthetic() {
            merge(&mut synthetic_states, &diff.states);
        } else {
            merge(&mut system_states, &diff.states);
        }
    }

    Totals {
        files,
        facts_compared,
        facts_skipped,
        unreadable,
        disagreements,
        synthetic_states,
        system_states,
    }
}

/// The reader agrees with `readelf` on every fact both report, over every fixture and a
/// sample of the host's objects.
#[test]
fn the_reader_agrees_with_readelf_on_every_fact_both_report() {
    let verifies = "that the ELF reader agrees with readelf on the facts both report";
    let Some(oracle) = find_oracle() else {
        if common::ELF_HOST {
            common::refuse("no readelf or llvm-readelf on PATH", verifies);
        } else {
            common::capability_gap(
                "readelf differential",
                "no readelf or llvm-readelf on PATH, and this host's cc emits Mach-O; \
                 install llvm and put llvm-readelf on PATH to run the fixture arm here",
            );
        }
        return;
    };

    let work = common::Work::new("elf", "readelf");
    let inputs = inputs(&work);
    let Totals {
        files,
        facts_compared,
        facts_skipped,
        unreadable,
        disagreements,
        synthetic_states,
        system_states,
    } = differential(&oracle, &inputs);

    announce(&format!(
        "\nchard: readelf differential: compared {facts_compared} facts over {files} files \
         ({} fixtures, {} discriminators, {} forged, {} system objects) against {} ({}); \
         {facts_skipped} facts not compared, {} files unreadable by one side, {} ELF \
         objects over {MAX_SYSTEM_OBJECT} bytes skipped by the system walk\n\
         chard: readelf differential: oracle states true/false, synthetic arm: {}\n\
         chard: readelf differential: oracle states true/false, system arm: {}\n",
        inputs.fixtures,
        inputs.discriminators,
        inputs.forged,
        inputs.system,
        oracle.program,
        oracle.version,
        unreadable.len(),
        inputs.oversized,
        render(&synthetic_states),
        render(&system_states),
    ));
    assert!(
        !(common::ELF_HOST && inputs.system == 0),
        "no ELF object sampled under {SYSTEM_ROOTS:?} on an ELF host ({} skipped as over \
         {MAX_SYSTEM_OBJECT} bytes); the system arm ran over nothing",
        inputs.oversized
    );
    if inputs.system == 0 {
        common::capability_gap(
            "readelf differential, system arm",
            &format!(
                "no ELF object sampled under the roots on this host ({} skipped as over \
                 {MAX_SYSTEM_OBJECT} bytes); only the synthetic arm was compared",
                inputs.oversized
            ),
        );
    }
    assert_eq!(files + unreadable.len(), inputs.synthetic() + inputs.system);
    assert_eq!(inputs.files.len(), inputs.synthetic() + inputs.system);
    assert!(
        files >= inputs.synthetic() && files > 0,
        "the differential ran over {files} files"
    );
    assert!(
        unreadable.is_empty(),
        "one side could not read {} file(s):\n  {}",
        unreadable.len(),
        unreadable.join("\n  ")
    );
    assert!(
        disagreements.is_empty(),
        "{} disagreement(s) with {} over {files} files:\n  {}",
        disagreements.len(),
        oracle.program,
        disagreements.join("\n  ")
    );
    let one_state: Vec<String> = DISCRIMINATED
        .iter()
        .filter_map(|fact| {
            let [off, on] = synthetic_states.get(fact).copied().unwrap_or_default();
            (off == 0 || on == 0).then(|| format!("{fact}: true {on}, false {off}"))
        })
        .collect();
    assert!(
        one_state.is_empty(),
        "the synthetic arm showed {} fact(s) in one state only, so agreement on them does \
         not tell the reader from one that answers that state unconditionally:\n  {}",
        one_state.len(),
        one_state.join("\n  ")
    );
}

/// How many objects the generated arm draws by default. Each costs two oracle runs.
const GENERATED_CASES: usize = 96;

/// Every disagreement the oracle reports for `spec`, built and written to `path`, with
/// the count of facts compared; `Err` when one side could not read the object, which
/// for a generated object is itself a finding.
fn generated_diff(
    oracle: &Oracle,
    spec: &Spec,
    path: &Path,
    label: &str,
) -> Result<(usize, Vec<String>), String> {
    std::fs::write(path, spec.build()).expect("writing a generated object");
    let facts = elf::facts_for(path).map_err(|e| format!("chard: {e}"))?;
    let (seen, comment) =
        ask_oracle(oracle, path).map_err(|e| format!("{}: {e}", oracle.program))?;
    let mut diff = Diff {
        label,
        compared: 0,
        skipped: 0,
        bad: Vec::new(),
        states: Tally::new(),
    };
    diff.header_and_segments(&facts, &seen);
    diff.dynamic_and_notes(&facts, &seen);
    diff.sections_and_symbols(&facts, &seen);
    diff.comment_lines(&facts, comment);
    // A generated object is whole, so the only truncations it may carry are the ones a
    // stripped section-header table records by design and the repeat of a search-path tag
    // the spec wrote more than once (`dynamic_and_notes` holds that record to the tags).
    let repeated = |t: &elf::Truncation| {
        (spec.rpath.len() > 1 && t.detail.starts_with("DT_RPATH appears"))
            || (spec.runpath.len() > 1 && t.detail.starts_with("DT_RUNPATH appears"))
    };
    let unexpected: Vec<&elf::Truncation> = facts
        .truncations
        .iter()
        .filter(|t| !(spec.strip_section_headers && t.kind == elf::TruncationKind::Unread))
        .filter(|t| !repeated(t))
        .collect();
    if !unexpected.is_empty() {
        diff.bad.push(format!(
            "{label}: truncations on a whole object: {unexpected:?}"
        ));
    }
    // The sections read as text by name read back whole, where the header table they
    // are looked up through was kept.
    if !spec.strip_section_headers {
        for (field, got, want) in [
            ("self_report", &facts.self_report, spec.self_report_text()),
            (
                "recorded_command_line",
                &facts.recorded_command_line,
                spec.command_line_text(),
            ),
        ] {
            diff.compared += 1;
            if *got != want {
                diff.bad
                    .push(format!("{label}: {field} read {got:?}, built {want:?}"));
            }
        }
    }
    Ok((diff.compared, diff.bad))
}

/// Walk `spec` down through [`Spec::simpler`] while the object still fails, and return
/// the smallest failing spec with its failure and the steps taken.
fn shrink(oracle: &Oracle, spec: Spec, path: &Path, failure: String) -> (Spec, String, usize) {
    let fails = |s: &Spec| match generated_diff(oracle, s, path, "shrunk") {
        Ok((_, bad)) if bad.is_empty() => None,
        Ok((_, bad)) => Some(bad.join("\n  ")),
        Err(e) => Some(e),
    };
    let mut current = (spec, failure);
    let mut steps = 0usize;
    'walk: loop {
        for candidate in current.0.simpler() {
            if let Some(why) = fails(&candidate) {
                current = (candidate, why);
                steps += 1;
                continue 'walk;
            }
        }
        return (current.0, current.1, steps);
    }
}

/// The reader agrees with `readelf` over objects drawn from a seed.
///
/// The fixtures are thirteen shapes someone listed. This arm draws widths, byte orders,
/// machines, object types, dynamic tags in every `BIND_NOW` and `TEXTREL` spelling and in
/// rotated order, zero to two property notes of either feature type on any machine,
/// versioned and bare symbols, section names with and without a leading dot, a
/// `.comment`, and stripped section headers, through `tests/elf_builder/generate.rs`,
/// and compares every fact [`Diff`] compares. A failure is shrunk to the smallest spec
/// that still fails and printed with the seed that replays it. The coverage buckets are
/// tallied, printed, and held to [`REQUIRED_BUCKETS`] on a default-sized run, so a
/// generator that stopped drawing a shape fails here rather than passing over fewer
/// shapes than this comment names.
#[test]
fn generated_objects_agree_with_readelf() {
    let verifies = "that the ELF reader agrees with readelf over generated objects";
    let Some(oracle) = find_oracle() else {
        if common::ELF_HOST {
            common::refuse("no readelf or llvm-readelf on PATH", verifies);
        } else {
            common::capability_gap(
                "readelf differential over generated objects",
                "no readelf or llvm-readelf on PATH, and this host's cc emits Mach-O; \
                 install llvm and put llvm-readelf on PATH to run it here",
            );
        }
        return;
    };
    let (seed, from_env) = seeded::seed();
    let cases = seeded::cases(GENERATED_CASES);
    let work = common::Work::new("elf", "generated-readelf");
    let path = work.path("generated.elf");
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    let mut compared = 0usize;
    for case in 0..cases {
        let mut rng = seeded::Rng::for_case(seed, case);
        let spec = Spec::draw(&mut |n| rng.below(n));
        for bucket in spec.buckets() {
            *tally.entry(bucket).or_insert(0) += 1;
        }
        let label = format!("generated case {case}");
        let failure = match generated_diff(&oracle, &spec, &path, &label) {
            Ok((n, bad)) if bad.is_empty() => {
                compared += n;
                continue;
            }
            Ok((_, bad)) => bad.join("\n  "),
            Err(e) => e,
        };
        let (small, why, steps) = shrink(&oracle, spec, &path, failure);
        panic!(
            "{} ({}) disagrees with the reader on a generated object ({}).\n\
             Shrunk in {steps} steps to:\n{small:#?}\n  {why}",
            oracle.program,
            oracle.version,
            seeded::replay(seed, case)
        );
    }
    let coverage = tally
        .iter()
        .map(|(b, n)| format!("{b} {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    seeded::announce(
        "readelf differential over generated objects",
        seed,
        from_env,
        cases,
        &format!(
            "{compared} facts compared against {} ({}); {coverage}",
            oracle.program, oracle.version
        ),
    );
    assert!(compared > 0, "the generated arm compared no fact");
    if cases >= GENERATED_CASES {
        let missing: Vec<&&str> = REQUIRED_BUCKETS
            .iter()
            .filter(|b| !tally.contains_key(**b))
            .collect();
        assert!(
            missing.is_empty(),
            "{cases} generated objects never drew {missing:?} ({})",
            seeded::replay(seed, 0)
        );
    }
}

/// What `readelf -S -s -r -W` says about one relocatable object's code relocations.
#[derive(Default, Debug)]
struct SeenRelocations {
    /// section index -> (name, flags column, `Inf` column)
    sections: BTreeMap<u32, (String, String, u32)>,
    /// `.symtab` index -> the oracle's `Type` and `Vis` columns.
    symbol_kinds: BTreeMap<u64, (String, String)>,
    /// relocation section name -> its rows.
    blocks: Vec<(String, Vec<RelocationRow>)>,
}

/// One relocation row: the type, the symbol index from `Info`, and the name column.
type RelocationRow = (String, u64, String);

/// Parse `readelf -S -s -r -W` for [`code_relocations_agree_with_readelf`].
///
/// A section row is `[Nr] Name Type Address Off Size ES Flg Lk Inf Al`, with the `Flg`
/// column empty (one token short) where a section has no flags. A `.symtab` row is read
/// for its index, `Type` and `Vis` only. A relocation row is `Offset Info Type`, then for a
/// symbol other than index 0 its value and the name column, which for a section symbol
/// both oracles fill with the section's name; the symbol index comes from `Info`, by the
/// class's split, rather than from the columns.
fn parse_relocations(text: &str, elf64: bool) -> SeenRelocations {
    let mut seen = SeenRelocations::default();
    let mut in_symtab = false;
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Relocation section '")
            && let Some((name, _)) = rest.split_once('\'')
        {
            seen.blocks.push((name.to_owned(), Vec::new()));
            in_block = true;
            in_symtab = false;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Symbol table '")
            && let Some((name, _)) = rest.split_once('\'')
        {
            in_symtab = name == ".symtab";
            in_block = false;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[')
            && let Some((index, rest)) = rest.split_once(']')
            && let Ok(index) = index.trim().parse::<u32>()
        {
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            let (flags, inf) = match tokens.len() {
                10 => (tokens[6], tokens[8]),
                9 => ("", tokens[7]),
                _ => continue,
            };
            if let Ok(inf) = inf.parse::<u32>() {
                seen.sections
                    .insert(index, (tokens[0].to_owned(), flags.to_owned(), inf));
            }
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if in_symtab {
            if let Some(num) = tokens.first().and_then(|t| t.strip_suffix(':'))
                && let Ok(num) = num.parse::<u64>()
                && let Some(kind) = tokens.get(3)
                && let Some(vis) = tokens.get(5)
            {
                seen.symbol_kinds
                    .insert(num, ((*kind).to_owned(), (*vis).to_owned()));
            }
            continue;
        }
        if !in_block {
            continue;
        }
        let (Some(info), Some(kind)) = (tokens.get(1), tokens.get(2)) else {
            continue;
        };
        let Ok(info) = u64::from_str_radix(info, 16) else {
            continue;
        };
        let sym = if elf64 { info >> 32 } else { info >> 8 };
        let name = tokens.get(4).copied().unwrap_or("");
        if let Some((_, rows)) = seen.blocks.last_mut() {
            rows.push(((*kind).to_owned(), sym, name.to_owned()));
        }
    }
    seen
}

impl SeenRelocations {
    /// The oracle's answer in `ElfFacts::code_relocations`' form: the rows of every
    /// relocation section whose `Inf` names a section flagged `X`, as `TYPE NAME`, or
    /// `TYPE NAME STV_VIS` where the symbol's `Vis` column is not `DEFAULT`, a section
    /// symbol as `TYPE [section]`, symbol 0 and other unnamed symbols left out.
    fn code_relocations(&self) -> BTreeSet<String> {
        let by_name: BTreeMap<&str, u32> = self
            .sections
            .values()
            .map(|(name, _, inf)| (name.as_str(), *inf))
            .collect();
        let mut found = BTreeSet::new();
        for (section, rows) in &self.blocks {
            let Some(target) = by_name.get(section.as_str()) else {
                continue;
            };
            let code = self
                .sections
                .get(target)
                .is_some_and(|(_, flags, _)| flags.contains('X'));
            if !code {
                continue;
            }
            for (kind, sym, name) in rows {
                if *sym == 0 {
                    continue;
                }
                let (symbol_kind, vis) = self
                    .symbol_kinds
                    .get(sym)
                    .map_or(("", ""), |(k, v)| (k.as_str(), v.as_str()));
                if symbol_kind == "SECTION" {
                    found.insert(format!("{kind} [{name}]"));
                } else if !name.is_empty() && name != "+" && name != "-" {
                    found.insert(if vis.is_empty() || vis == "DEFAULT" {
                        format!("{kind} {name}")
                    } else {
                        format!("{kind} {name} STV_{vis}")
                    });
                }
            }
        }
        found
    }
}

/// The machines whose relocation types the reader names, as `ElfFacts::machine` spells
/// them: the objects [`code_relocations_agree_with_readelf`] compares.
const RELOCATION_MACHINES: &[&str] = &["x86_64", "i386", "aarch64", "riscv"];

/// The inputs of [`code_relocations_agree_with_readelf`]: the builder's objects, then
/// what `cc` compiled, with the two counts.
fn relocation_inputs(
    work: &common::Work,
    verifies: &str,
) -> (Vec<(String, PathBuf)>, usize, usize) {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let builder = [
        ("x86_64", elf_builder::relocatable_with_code_relocation()),
        (
            "riscv-got",
            elf_builder::relocatable_riscv_no_plt(elf_builder::RiscvCall::Got),
        ),
        (
            "riscv-plt",
            elf_builder::relocatable_riscv_no_plt(elf_builder::RiscvCall::Plt),
        ),
        ("i386", elf_builder::relocatable_i386_with_code_relocation()),
        // The one `Elf32_Rela` object (12-byte records), so that record size has an oracle.
        (
            "i386-functions-rela",
            elf_builder::relocatable_functions_rela32(),
        ),
        (
            "aarch64",
            elf_builder::relocatable_aarch64_with_code_relocation(),
        ),
        (
            "x86_64-section-symbol",
            elf_builder::with_section_symbol_relocation(
                elf_builder::relocatable_with_code_relocation(),
            ),
        ),
        (
            "x86_64-hidden-anchor",
            elf_builder::with_anchor_visibility(
                elf_builder::relocatable_with_code_relocation(),
                elf_builder::STV_HIDDEN,
                elf_builder::R_X86_64_PC32,
            ),
        ),
        (
            "i386-hidden-anchor",
            elf_builder::with_anchor_visibility(
                elf_builder::relocatable_i386_with_code_relocation(),
                elf_builder::STV_HIDDEN,
                elf_builder::R_X86_64_PC32,
            ),
        ),
    ];
    // `.rela.text` declaring 48 over 24-byte `Elf64_Rela` records, which readelf reads at
    // the expected size (2026-10-20): in the one-reference object and in the
    // four-function object, whose entries a 48-byte step halved.
    let forged = [
        (
            "x86_64-rela-entsize-48",
            elf_builder::relocatable_with_code_relocation(),
        ),
        (
            "x86_64-functions-rela-entsize-48",
            elf_builder::relocatable_functions(),
        ),
    ];
    let mut written = Vec::new();
    for (name, object) in &builder {
        written.push((*name, object.build()));
    }
    for (name, object) in &forged {
        written.push((*name, with_declared_entsize(object, &[".rela.text"], 48)));
    }
    for (name, bytes) in &written {
        let path = work.path(&format!("builder-{name}.o"));
        std::fs::write(&path, bytes).expect("writing a builder object");
        files.push((format!("builder {name}"), path));
    }
    let mut compiled = 0usize;
    if common::ELF_HOST && common::require_cc(verifies) {
        let probes = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("probes");
        for (tag, flags) in [
            ("fpic", &["-fPIC"][..]),
            ("fpie", &["-fPIE"][..]),
            ("fno-pic", &["-fno-pic"][..]),
            ("m32-fpic", &["-m32", "-fPIC"][..]),
            ("m32-fpie", &["-m32", "-fPIE"][..]),
        ] {
            let path = work.path(&format!("pic-object-{tag}.o"));
            let built = Command::new("cc")
                .args(["-O2", "-c"])
                .args(flags)
                .arg("-I")
                .arg(&probes)
                .arg(probes.join("pic_object_relocs.c"))
                .arg("-o")
                .arg(&path)
                .output()
                .is_ok_and(|o| o.status.success());
            if built {
                compiled += 1;
                files.push((format!("cc -O2 -c {}", flags.join(" ")), path));
            } else if !flags.contains(&"-m32") {
                panic!(
                    "cc -O2 -c {} did not build the pic-object probe",
                    flags.join(" ")
                );
            }
        }
    }

    (files, written.len(), compiled)
}

/// `ElfFacts::code_relocations` against the oracle's `-r` listing, over the builder's
/// relocatable objects for x86_64, i386 and aarch64 (a GOT reference, on x86_64 a
/// second one through a section symbol, and on x86_64 and i386 a direct one against a
/// hidden anchor) and for RISC-V (gcc's GOT and PLT call shapes), and, where `cc` emits
/// ELF, over `probes/pic_object_relocs.c` compiled `-c` under -fPIC, -fPIE and -fno-pic,
/// and under -m32 where `cc` builds it. Only objects of [`RELOCATION_MACHINES`] are
/// compared, the machines the reader names types for; any other is counted as skipped
/// and printed, and every builder object is compared.
///
/// A test asserting that every input was compared while skipping every machine but x86_64,
/// i386 and aarch64 would fail on a riscv64 host through its own `cc` arm. A compiled object
/// of another machine is a counted skip, and only the builder's objects, whose machines are
/// fixed, must all be compared.
///
/// One difference is not the reader's and is normalised: GNU as names RISC-V's local
/// labels `.L0 `, with a trailing space, and both oracles print the name in a
/// whitespace-separated column that drops it. The reader's entry is compared with its
/// trailing whitespace trimmed.
#[test]
fn code_relocations_agree_with_readelf() {
    let verifies = "that the ELF reader's code relocations agree with readelf -r";
    let Some(oracle) = find_oracle() else {
        if common::ELF_HOST {
            common::refuse("no readelf or llvm-readelf on PATH", verifies);
        } else {
            common::capability_gap(
                "readelf differential over code relocations",
                "no readelf or llvm-readelf on PATH, and this host's cc emits Mach-O; \
                 install llvm and put llvm-readelf on PATH to run it here",
            );
        }
        return;
    };
    let work = common::Work::new("elf", "readelf-relocations");
    let (files, builders, compiled) = relocation_inputs(&work, verifies);
    let (mut compared, mut skipped, mut entries) = (0usize, 0usize, 0usize);
    let mut skipped_labels = Vec::new();
    let mut bad = Vec::new();
    for (label, path) in &files {
        let facts = elf::facts_for(path).unwrap_or_else(|e| panic!("{label}: chard: {e}"));
        if !RELOCATION_MACHINES.contains(&facts.machine.as_str()) {
            assert!(
                !label.starts_with("builder "),
                "{label}: a builder object of a machine the reader does not name"
            );
            skipped += 1;
            skipped_labels.push(format!("{label} ({})", facts.machine));
            continue;
        }
        let out = Command::new(oracle.program)
            .args(["-S", "-s", "-r", "-W"])
            .arg(path)
            .output()
            .expect("running the oracle");
        assert!(
            out.status.success(),
            "{label}: {}: {}",
            oracle.program,
            String::from_utf8_lossy(&out.stderr)
        );
        let theirs =
            parse_relocations(&String::from_utf8_lossy(&out.stdout), facts.elf_class == 64)
                .code_relocations();
        let ours: BTreeSet<String> = facts
            .code_relocations
            .clone()
            .unwrap_or_else(|| panic!("{label}: a relocatable object read as linked"))
            .into_iter()
            .map(|entry| entry.trim_end().to_owned())
            .collect();
        compared += 1;
        entries += theirs.len();
        if ours != theirs {
            bad.push(format!(
                "{label}: chard {ours:?} / {} {theirs:?}",
                oracle.program
            ));
        }
    }
    announce(&format!(
        "\nchard: readelf differential, code relocations: {compared} objects compared \
         ({builders} builder, {compiled} compiled), {entries} entries, {skipped} skipped \
         {skipped_labels:?}, against {} ({})\n",
        oracle.program, oracle.version,
    ));
    assert!(
        bad.is_empty(),
        "{} disagreement(s):\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
    assert_eq!(compared + skipped, files.len());
    assert!(
        compared >= builders,
        "{compared} objects compared, fewer than the {builders} the builder wrote"
    );
    assert!(
        entries >= builders,
        "the oracle listed {entries} code relocations over {compared} objects"
    );
}

/// The relocation parser reads the GNU layout: captured from GNU readelf 2.46.1 over
/// `probes/pic_object_relocs.c` compiled `gcc -O2 -fPIC -c` on Fedora 44 x86_64, with one
/// row added to `.rela.text` through the `.text` section symbol. `.rela.eh_frame` patches
/// a section without `X` and is left out; the null section's row, one token short of a
/// section with no flags, is not read as one.
#[test]
fn the_relocation_parser_reads_the_gnu_layout() {
    let text = "\
Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        0000000000000000 000040 000011 00  AX  0   0 16
  [ 2] .rela.text        RELA            0000000000000000 001428 000018 18   I 11   1  8
  [ 7] .note.GNU-stack   PROGBITS        0000000000000000 0012b7 000000 00      0   0  1
  [ 8] .note.gnu.property NOTE            0000000000000000 0012b8 000030 00   A  0   0  8
  [ 9] .eh_frame         PROGBITS        0000000000000000 0012e8 000030 00   A  0   0  8
  [10] .rela.eh_frame    RELA            0000000000000000 001440 000018 18   I 11   9  8
  [11] .symtab           SYMTAB          0000000000000000 001318 0000a8 18     12   4  8

Relocation section '.rela.text' at offset 0x1428 contains 2 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000000003  000000060000002a R_X86_64_REX_GOTPCRELX 0000000000000000 chard_pic_object_anchor - 4
0000000000000009  0000000200000002 R_X86_64_PC32          0000000000000000 .text + 10

Relocation section '.rela.eh_frame' at offset 0x1440 contains 1 entry:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000000020  0000000200000002 R_X86_64_PC32          0000000000000000 .text + 0

Symbol table '.symtab' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS pic_object_relocs.c
     2: 0000000000000000     0 SECTION LOCAL  DEFAULT    1 .text
     3: 0000000000000000   560 OBJECT  LOCAL  DEFAULT    5 chard_report
     4: 0000000000000000    17 FUNC    GLOBAL DEFAULT    1 chard_pic_object_probe
     5: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND _GLOBAL_OFFSET_TABLE_
     6: 0000000000000000  4096 OBJECT  GLOBAL DEFAULT    3 chard_pic_object_anchor
";
    let seen = parse_relocations(text, true);
    assert_eq!(seen.sections.len(), 7, "{:?}", seen.sections);
    assert_eq!(
        seen.sections.get(&1),
        Some(&(".text".to_owned(), "AX".to_owned(), 0))
    );
    assert_eq!(
        seen.sections.get(&7),
        Some(&(".note.GNU-stack".to_owned(), String::new(), 0))
    );
    assert_eq!(
        seen.code_relocations(),
        BTreeSet::from([
            "R_X86_64_PC32 [.text]".to_owned(),
            "R_X86_64_REX_GOTPCRELX chard_pic_object_anchor".to_owned(),
        ])
    );
}

/// The oracle parser reads the layout it is written for.
///
/// Pinned on captured text, so a host with no oracle still checks the parser, and so a change in what the parser extracts is visible here
/// before it is visible as a spurious disagreement. The transcript runs the dynamic
/// section straight into the notes with no blank line, as the oracle does for a file
/// with no section headers.
#[test]
fn the_oracle_parser_reads_the_gnu_layout() {
    let text = "\
ELF Header:
  Class:                             ELF64
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        0000000000400190 000190 00001c 00   A  0   0  1
  [ 2] .note.gnu.property NOTE           00000000004001b0 0001b0 000020 00   A  0   0  8
  [ 3] __libc_freeres_ptrs PROGBITS      00000000004001d0 0001d0 000010 00  WA  0   0  8

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  INTERP         0x000190 0x0000000000400190 0x0000000000400190 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  GNU_RELRO      0x000278 0x0000000000400278 0x0000000000400278 0x000060 0x000060 R   0x1
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10

 Section to Segment mapping:
  Segment Sections...
   00     .interp
Dynamic section at offset 0x278 contains 6 entries:
  Tag                Type     Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000f (RPATH)              Library rpath: [/opt/lib]
 0x000000000000001e (FLAGS)              BIND_NOW TEXTREL
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE NOOPEN
 0x0000000000000000 (NULL)               0x0
Displaying notes found in: .note.gnu.property
  Owner                Data size 	Description
  GNU                  0x00000010	NT_GNU_PROPERTY_TYPE_0
      Properties: x86 feature: IBT, SHSTK
  GNU                  0x00000010	NT_GNU_PROPERTY_TYPE_0
      Properties: AArch64 feature: BTI

Symbol table '.dynsym' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (2)
     2: 0000000000001040     0 SECTION LOCAL  DEFAULT    1 .text

Symbol table '.symtab' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000001139    26 FUNC    GLOBAL DEFAULT   16 main
";
    let seen = parse(text);
    assert_eq!(seen.class, Some(64));
    assert_eq!(seen.e_type.as_deref(), Some("DYN"));
    assert!(seen.pie_declared);
    assert_eq!(
        seen.machine.as_deref(),
        Some("Advanced Micro Devices X86-64")
    );
    assert!(seen.interp && seen.gnu_relro);
    assert_eq!(seen.gnu_stack, Some(true));
    assert_eq!(
        seen.dyn_tags,
        [1u64, 0xf, 0x1e, 0x6fff_fffb].into_iter().collect()
    );
    assert_eq!(seen.needed, vec!["libc.so.6".to_owned()]);
    assert_eq!(seen.rpath, vec!["/opt/lib".to_owned()]);
    assert!(seen.flags_bind_now && seen.flags_textrel);
    assert!(seen.flags1_now && seen.flags1_pie && seen.flags1_noopen);
    assert_eq!(
        seen.x86_words,
        vec![3],
        "the note after an unblanked dynamic block is read"
    );
    assert_eq!(seen.aarch64_words, vec![1]);
    assert_eq!(
        seen.sections,
        [".interp", ".note.gnu.property", "__libc_freeres_ptrs"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>(),
        "every name the oracle prints, whatever it begins with; the null section's row \
         contributes none and the header row is no row"
    );
    assert_eq!(
        seen.symbols.get("__stack_chk_fail"),
        Some(&(vec![".dynsym".to_owned()], false)),
        "the version suffix is cut and UND reads as undefined"
    );
    assert_eq!(
        seen.symbols.get("main"),
        Some(&(vec![".symtab".to_owned()], true))
    );
    assert!(
        !seen.symbols.contains_key(".text"),
        "a section symbol is not a name"
    );
    assert_eq!(seen.symbols.len(), 2);
}

/// A feature bit the oracle prints by number reads as that bit, in either oracle's
/// spelling, and an item the parser cannot read fails rather than reading as clear.
///
/// Most lines are captured from GNU readelf 2.42 (Ubuntu 24.04), GNU readelf 2.46.1 and
/// llvm-readelf 22.1.8 over objects `elf_builder` wrote with one property note each: an
/// aarch64 word of 5 (BTI and GCS; the shrunk case 16 of seed 0xc4a4d020260928, which
/// readelf 2.42 failed on CI's pinned runner), aarch64 words of 0, 12 and 16, x86 words of
/// 15 and 0x31, and aarch64 feature properties of data size 8 and 2, which all three print
/// as `<corrupt length: 0x8>` and `<corrupt length: 0x2>`; the four-property x86 line is
/// GNU readelf 2.46.1's over Fedora 44's `/usr/bin/ls`, verbatim. Three are composed, not
/// captured: `AArch64 feature: GCS, <unknown flags: 0x8>` and `AArch64 feature: <unknown
/// flags: 0x10>` put llvm's item spelling after GNU's prefix, so the parser is held to
/// either spelling under either prefix, and `x86 feature: SHSTK, x86 ISA needed:
/// x86-64-baseline` is the four-property line's shape cut to two properties.
#[test]
fn the_oracle_parser_reads_a_feature_bit_it_has_no_name_for() {
    let notes = [
        ("AArch64 feature: BTI, <unknown: 4>", 5),
        ("AArch64 feature: BTI, GCS", 5),
        ("aarch64 feature: BTI, GCS", 5),
        ("AArch64 feature: <unknown: 4>, <unknown: 8>", 12),
        ("AArch64 feature: GCS, <unknown flags: 0x8>", 12),
        ("AArch64 feature: <unknown: 10>", 16),
        ("AArch64 feature: <unknown flags: 0x10>", 16),
        ("AArch64 feature: ", 0),
        ("aarch64 feature: <None>", 0),
    ];
    for (line, word) in notes {
        let seen = parse(&format!("      Properties: {line}\n"));
        assert_eq!(seen.aarch64_words, vec![word], "{line}");
    }
    let x86 = [
        ("x86 feature: IBT, SHSTK, LAM_U48, LAM_U57", 15),
        ("x86 feature: IBT, SHSTK, <unknown flags: 0xc>", 15),
        ("x86 feature: IBT, <unknown: 10>, <unknown: 20>", 0x31),
        ("x86 feature: IBT, <unknown flags: 0x30>", 0x31),
        ("x86 feature: <None>", 0),
        (
            "x86 feature: IBT, SHSTK, x86 ISA needed: x86-64-baseline, x86 feature used: x86, \
             x87, XMM, x86 ISA used: x86-64-baseline",
            3,
        ),
        ("x86 feature: SHSTK, x86 ISA needed: x86-64-baseline", 2),
    ];
    for (line, word) in x86 {
        let seen = parse(&format!("      Properties: {line}\n"));
        assert_eq!(seen.x86_words, vec![word], "{line}");
    }
    for line in [
        "AArch64 feature: <corrupt length: 0x8>",
        "aarch64 feature: <corrupt length: 0x2>",
    ] {
        let seen = parse(&format!("      Properties: {line}\n"));
        assert_eq!(seen.aarch64_words, vec![0], "{line}");
    }
    for (line, says) in [
        ("AArch64 feature: BTI, XYZ", "XYZ"),
        ("AArch64 feature: BTI, <bogus: 4>, GCS", "<bogus: 4>"),
        ("x86 feature: IBT, <unknown: zz>", "<unknown: zz>"),
        (
            "AArch64 feature: BTI, <corrupt length: 0x8>",
            "<corrupt length: 0x8>",
        ),
        (
            "AArch64 feature: <corrupt length: 0x8>, BTI",
            "<corrupt length: 0x8>",
        ),
    ] {
        let unread = std::panic::catch_unwind(|| parse(&format!("      Properties: {line}\n")));
        let message = unread.expect_err(line);
        let message = message
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| message.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            message.contains(says),
            "{line}: an item the parser cannot read fails naming it, not a clear bit: \
             {message:?}"
        );
    }
}

/// The `.comment` dump parser reads both oracles' layouts, and reads no rows without
/// the header.
///
/// GNU `readelf -p` (binutils 2.46.1) indents each row and separates the bracket from
/// the text with two spaces; `llvm-readelf` (22.1.8) uses one and no indent. A section
/// that is not there produces no header on either, and a parser that returned an empty
/// list for that would compare an absence to the reader's absence as agreement on
/// content.
#[test]
fn the_comment_dump_parser_reads_both_oracle_layouts() {
    let gnu = "\nString dump of section '.comment':\n  [     0]  GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)\n  [    2f]  Linker: LLD 22.1.8\n  [    42]  GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)\n\n";
    assert_eq!(
        parse_comment_dump(gnu),
        Some(vec![
            "GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)".to_owned(),
            "Linker: LLD 22.1.8".to_owned(),
        ]),
        "rows are read, a repeated string is one entry"
    );
    let llvm = "String dump of section '.comment':\n[     0] clang version 22.1.8 (Fedora 22.1.8-4.fc44)\n[    2c] mold 2.40.4 (compatible with GNU ld)\n";
    assert_eq!(
        parse_comment_dump(llvm),
        Some(vec![
            "clang version 22.1.8 (Fedora 22.1.8-4.fc44)".to_owned(),
            "mold 2.40.4 (compatible with GNU ld)".to_owned(),
        ])
    );
    assert_eq!(
        parse_comment_dump(
            "readelf: Warning: Section '.comment' was not dumped because it does not exist!\n"
        ),
        None,
        "no header, no section"
    );
    assert_eq!(
        parse_comment_dump("String dump of section '.comment':\n"),
        Some(Vec::new()),
        "a present, empty section is an empty list rather than an absence"
    );
}
