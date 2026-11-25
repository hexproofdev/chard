// SPDX-License-Identifier: BSD-3-Clause

//! A fixed-pattern search over the code bytes of named functions in the artifact.

use super::{
    EM_AARCH64, EM_X86_64, ET_REL, Elf, ElfTable, SHF_INFO_LINK, SHN_UNDEF, SHT_CREL, SHT_NOBITS,
    SHT_REL, SHT_RELA, SHT_SYMTAB, Shdr, Truncation, reloc_type_name, relocation_record,
};

/// One function to search, and the names of the [`CODE_PATTERNS`] entries it is searched
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    pub function: &'static str,
    pub patterns: &'static [&'static str],
}

/// The functions whose code is searched, each defined by a probe for this purpose. One
/// list for every artifact, as [`super::WATCHED_SYMBOLS`] is, so the facts have the same
/// shape whichever probe built the object. A function is searched only for its own
/// patterns, so no pattern meant for one probe's construct is read in another's code.
pub const SCANS: &[Scan] = &[
    // `probes/ubsan_trap.c`'s first function: constructs the sanitizer checks, and no call.
    Scan {
        function: "chard_ubsan_trap_probe",
        patterns: UBSAN_TRAP_PATTERNS,
    },
    // gcc's cold part of the same function.
    Scan {
        function: "chard_ubsan_trap_probe.cold",
        patterns: UBSAN_TRAP_PATTERNS,
    },
    // `probes/ubsan_trap.c`'s second function, a construct for each sanitizer group the
    // first does not exercise and the compilers instrument without a call, so a trap
    // configuration covering only those groups is read rather than taken for no trap.
    Scan {
        function: "chard_ubsan_trap_groups",
        patterns: UBSAN_GROUP_PATTERNS,
    },
    // gcc's cold part of the second function, for the reason the first's is searched;
    // gcc 16.1.1 on Fedora 44 x86_64 moves most of its traps there at -O2.
    Scan {
        function: "chard_ubsan_trap_groups.cold",
        patterns: UBSAN_GROUP_PATTERNS,
    },
    // `probes/ubsan_trap.c`'s third function: an indexed access to a global array of
    // known size, which gcc checks under `object-size` and clang under `local-bounds`,
    // neither of which the first two functions give anything to check (the probe says why
    // the access is through a pointer to the element type).
    Scan {
        function: "chard_ubsan_trap_sized",
        patterns: UBSAN_SIZED_PATTERNS,
    },
    Scan {
        function: "chard_ubsan_trap_sized.cold",
        patterns: UBSAN_SIZED_PATTERNS,
    },
    // `probes/ubsan_trap.c`'s fourth function: a call through a function pointer, which
    // clang checks under `function` and gcc has no group for.
    Scan {
        function: "chard_ubsan_trap_indirect",
        patterns: UBSAN_INDIRECT_PATTERNS,
    },
    Scan {
        function: "chard_ubsan_trap_indirect.cold",
        patterns: UBSAN_INDIRECT_PATTERNS,
    },
    // `probes/fortify_printf_flag.c`: a `printf` of the function's own arguments, which
    // gcc compiles to `__printf_chk` with the flag argument loaded here.
    Scan {
        function: "chard_fortify_printf_probe",
        patterns: FORTIFY_FLAG_PATTERNS,
    },
    // clang's form of the same: glibc's `printf` wrapper for clang is variadic, so clang
    // keeps it out of line as a local function carrying its `pass_object_size` (level 2)
    // or `pass_dynamic_object_size` (level 3) attribute in its mangled name, and the flag
    // is loaded there before `__vprintf_chk`.
    Scan {
        function: "_ZL6printfPKcU17pass_object_size1z",
        patterns: FORTIFY_FLAG_PATTERNS,
    },
    Scan {
        function: "_ZL6printfPKcU25pass_dynamic_object_size1z",
        patterns: FORTIFY_FLAG_PATTERNS,
    },
];

/// The traps `chard_ubsan_trap_probe` is searched for, each trap that carries clang's
/// check number again for a number other than signed overflow's, and the calls whose
/// presence with neither a trap nor a sanitizer handler marks a trap routed through a
/// function the caller named (clang's `-ftrap-function=`).
const UBSAN_TRAP_PATTERNS: &[&str] = &[
    "x86-ud2",
    "x86-ud1",
    "x86-ud1-check",
    "a64-brk",
    "a64-brk-check",
    "x86-call-rel32",
    "x86-call-got",
    "x86-call-reg",
    "x86-call-sib",
    "a64-bl",
    "a64-blr",
];

/// The patterns `chard_ubsan_trap_groups` is searched for: every trap pattern, and the
/// call patterns that match a call by its zero field or, on `aarch64`, by a whole
/// instruction word. `x86-call-reg` and `x86-call-sib` are left out because two bytes
/// anywhere in a function forge them; the `SCANS` entry has the measurement.
const UBSAN_GROUP_PATTERNS: &[&str] = &[
    "x86-ud2",
    "x86-ud1",
    "x86-ud1-check",
    "a64-brk",
    "a64-brk-check",
    "x86-call-rel32",
    "x86-call-got",
    "a64-bl",
    "a64-blr",
];

/// The patterns `chard_ubsan_trap_sized` is searched for: every trap pattern and no call
/// pattern, since gcc's `object-size` check can encode a relocated immediate as
/// `x86-call-rel32`; the `SCANS` entry has the bytes.
const UBSAN_SIZED_PATTERNS: &[&str] = &[
    "x86-ud2",
    "x86-ud1",
    "x86-ud1-check",
    "a64-brk",
    "a64-brk-check",
];

/// The patterns `chard_ubsan_trap_indirect` is searched for: clang's traps alone, since
/// clang's `-fsanitize=kcfi` puts gcc's `ud2`, and on aarch64 a `brk` outside clang's
/// `#0x55NN`, in a function that calls through a pointer; the `SCANS` entry has the
/// measurement.
const UBSAN_INDIRECT_PATTERNS: &[&str] = &["x86-ud1", "x86-ud1-check", "a64-brk-clang-check"];

/// The flag argument glibc passes a checking `printf`, `__USE_FORTIFY_LEVEL - 1`, as each
/// machine loads it into the first argument register.
const FORTIFY_FLAG_PATTERNS: &[&str] = &[
    "x86-mov-edi-1",
    "x86-mov-edi-2",
    "x86-push-1",
    "x86-push-2",
    "a64-mov-w0-1",
    "a64-mov-w0-2",
];

/// How a pattern is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// These bytes, at any offset in the function.
    Bytes(&'static [u8]),
    /// Bytes at any offset, each compared as `byte & mask == value` with its own
    /// `(mask, value)`: an opcode and the bits of a `ModRM` byte that name one form.
    Masked(&'static [(u8, u8)]),
    /// A little-endian 32-bit word at an address that is a multiple of 4, compared as
    /// `word & mask == value`: one instruction class on a fixed-width instruction set.
    Word { mask: u32, value: u32 },
    /// As `Word`, less the one word `except`: an instruction class but for one immediate.
    WordExcept { mask: u32, value: u32, except: u32 },
}

/// A named encoding to search for, on one machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodePattern {
    /// The spelling `code_scanned` and `code_matches` carry.
    pub name: &'static str,
    /// The `e_machine` the encoding belongs to; the pattern is searched on no other.
    pub machine: u16,
    pub shape: Shape,
}

/// Every pattern, by machine. The trap patterns were measured 2026-10-02 with `objdump -d`
/// over `probes/ubsan_trap.c`'s function compiled `-c` at `-O0` and `-O2` under
/// `-fsanitize=undefined -fsanitize-trap=undefined`: gcc 16.1.1 emits `ud2` and clang
/// 22.1.8 `ud1` on Fedora 44 x86_64, and on Fedora 44 aarch64 gcc 16.2.1 emits `brk
/// #0x3e8` and clang 22.1.8 `brk #0x55NN` with the check's number in the low byte. The
/// flag patterns were measured the same day over `probes/fortify_printf_flag.c` at -O1,
/// -O2, -Os and -Oz, levels 0 to 3: `mov $N,%edi` everywhere on x86_64 but -Oz, where gcc
/// and clang both emit `push $N` and a later `pop %rdi` (gcc 16.1.1 schedules other moves
/// between the two in the probe's function), and `mov w0, #N` at every level on aarch64.
pub const CODE_PATTERNS: &[CodePattern] = &[
    // `ud2`, `0f 0b`: gcc's `__builtin_trap`.
    CodePattern {
        name: "x86-ud2",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0x0f, 0x0b]),
    },
    // `ud1`, `0f b9` and a ModRM byte that carries clang's check number; the two opcode
    // bytes are the instruction.
    CodePattern {
        name: "x86-ud1",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0x0f, 0xb9]),
    },
    // `ud1 NN(%eax),%eax`, `0f b9 40 NN`: clang's trap with a nonzero check number in the
    // 8-bit displacement.
    CodePattern {
        name: "x86-ud1-check",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0x0f, 0xb9, 0x40]),
    },
    // `brk #imm16`: `0xd4200000 | imm16 << 5`.
    CodePattern {
        name: "a64-brk",
        machine: EM_AARCH64,
        shape: Shape::Word {
            mask: 0xffe0_001f,
            value: 0xd420_0000,
        },
    },
    // `brk` but for `brk #0x5500`: clang's immediate is `0x55NN` with the check number in
    // its low byte, and check 0 is signed overflow on an add, which clang's `-ftrapv`
    // emits with the same immediate (measured as `x86-ud1-check` is, on Fedora 44 aarch64,
    // the same numbers in `NN`).
    CodePattern {
        name: "a64-brk-check",
        machine: EM_AARCH64,
        shape: Shape::WordExcept {
            mask: 0xffe0_001f,
            value: 0xd420_0000,
            except: 0xd42a_a000,
        },
    },
    // `brk #0x55NN` but for `#0x5500`: clang's trap for a failed sanitizer check with a
    // nonzero check number and no other `brk`.
    CodePattern {
        name: "a64-brk-clang-check",
        machine: EM_AARCH64,
        shape: Shape::WordExcept {
            mask: 0xffff_e01f,
            value: 0xd42a_a000,
            except: 0xd42a_a000,
        },
    },
    // `call rel32` with the field zero, `e8 00 00 00 00`: a call to another symbol in an
    // object, whose displacement is a relocation (`R_X86_64_PLT32` or `PC32`) that holds
    // zero until the link.
    CodePattern {
        name: "x86-call-rel32",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0xe8, 0x00, 0x00, 0x00, 0x00]),
    },
    // `call *disp32(%rip)` with the field zero, `ff 15 00 00 00 00`: the same call through
    // the GOT, as `-fno-plt` emits it.
    CodePattern {
        name: "x86-call-got",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0xff, 0x15, 0x00, 0x00, 0x00, 0x00]),
    },
    // `call *%reg`, `ff` and a `ModRM` byte `11 010 rrr`, `d0` to `d7`; behind a REX
    // prefix (`41 ff d0`) the same two bytes name `%r8` to `%r15`.
    CodePattern {
        name: "x86-call-reg",
        machine: EM_X86_64,
        shape: Shape::Masked(&[(0xff, 0xff), (0xf8, 0xd0)]),
    },
    // `call *(base,index,scale)`, `ff 14` and a SIB byte: the same call under
    // `-mcmodel=large -fPIC`, through the GOT entry the two registers address (`41 ff 14
    // 00`, `call *(%r8,%rax,1)`), measured as above from -O1; at -O0 it is `x86-call-reg`.
    CodePattern {
        name: "x86-call-sib",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0xff, 0x14]),
    },
    // `bl imm26`: `0x94000000 | imm26`.
    CodePattern {
        name: "a64-bl",
        machine: EM_AARCH64,
        shape: Shape::Word {
            mask: 0xfc00_0000,
            value: 0x9400_0000,
        },
    },
    // `blr xN`: `0xd63f0000 | n << 5`.
    CodePattern {
        name: "a64-blr",
        machine: EM_AARCH64,
        shape: Shape::Word {
            mask: 0xffff_fc1f,
            value: 0xd63f_0000,
        },
    },
    // `mov $imm32,%edi`, `bf` and the immediate: the flag argument at levels 2 and 3.
    CodePattern {
        name: "x86-mov-edi-1",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0xbf, 0x01, 0x00, 0x00, 0x00]),
    },
    CodePattern {
        name: "x86-mov-edi-2",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0xbf, 0x02, 0x00, 0x00, 0x00]),
    },
    // `push $imm8`, `6a NN`: the same argument at -Oz, popped into `%rdi` later.
    CodePattern {
        name: "x86-push-1",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0x6a, 0x01]),
    },
    CodePattern {
        name: "x86-push-2",
        machine: EM_X86_64,
        shape: Shape::Bytes(&[0x6a, 0x02]),
    },
    // `mov w0, #N`, the `movz` alias with no shift: `0x52800000 | N << 5`, register `w0`.
    CodePattern {
        name: "a64-mov-w0-1",
        machine: EM_AARCH64,
        shape: Shape::Word {
            mask: 0xffff_ffff,
            value: 0x5280_0020,
        },
    },
    CodePattern {
        name: "a64-mov-w0-2",
        machine: EM_AARCH64,
        shape: Shape::Word {
            mask: 0xffff_ffff,
            value: 0x5280_0040,
        },
    },
];

/// How many match offsets are kept per function and pattern. The count is kept whole in
/// `code_scanned`; the offsets are evidence for a reader with the artifact, and a probe
/// function holds a handful.
pub const MATCHES_KEPT: usize = 64;

/// What a relocation type patches in an object's code, for `Elf::relocated_fields`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Nothing: a marker the linker reads to choose a sequence and writes no value
    /// through (`R_X86_64_TLSDESC_CALL`, `R_AARCH64_TLSDESC_CALL`).
    Marker,
    /// This many whole bytes at `r_offset`.
    Bytes(u64),
    /// The bits of `mask` in the little-endian instruction word at `r_offset`: an
    /// `aarch64` relocation patches an immediate inside an instruction, whose opcode bits
    /// are never zero, so only the immediate's bits are the field.
    Word(u32),
}

/// The field each relocation type patches, by machine, or `None` for a type the reader
/// does not size: one an object should not carry (the dynamic linker's, `COPY`,
/// `GLOB_DAT`, `JUMP_SLOT`, `RELATIVE` and the like) or one added after this table (the
/// x86_64 `CODE_4_*` to `CODE_6_*` forms of APX). Widths are the x86-64 psABI's and masks
/// the immediates of the `AArch64` ELF ABI's instruction classes, each held to its
/// `elf/reloc_names.rs` name by `every_sized_relocation_type_is_sized_by_its_name`.
#[must_use]
pub fn relocated_field(machine: u16, kind: u32) -> Option<Field> {
    // AArch64 immediates: `movz`/`movk`/`movn` imm16, `adr`/`adrp` immlo and immhi, a
    // 19-bit literal or conditional-branch offset, `tbz` imm14, `b`/`bl` imm26, and the
    // unsigned 12-bit offset of `add` and of a load or store.
    const MOVW: Field = Field::Word(0x001f_ffe0);
    const ADR: Field = Field::Word(0x60ff_ffe0);
    const IMM19: Field = Field::Word(0x00ff_ffe0);
    const IMM14: Field = Field::Word(0x0007_ffe0);
    const IMM26: Field = Field::Word(0x03ff_ffff);
    const IMM12: Field = Field::Word(0x003f_fc00);
    match machine {
        EM_X86_64 => match kind {
            0 | 35 => Some(Field::Marker),
            1 | 24 | 25 | 27..=31 | 33 => Some(Field::Bytes(8)),
            2..=4 | 9..=11 | 19..=23 | 26 | 32 | 34 | 41 | 42 => Some(Field::Bytes(4)),
            12 | 13 => Some(Field::Bytes(2)),
            14 | 15 => Some(Field::Bytes(1)),
            _ => None,
        },
        EM_AARCH64 => match kind {
            0 | 567..=569 => Some(Field::Marker),
            257 | 260 | 307 => Some(Field::Bytes(8)),
            258 | 261 | 308 => Some(Field::Bytes(4)),
            259 | 262 => Some(Field::Bytes(2)),
            263..=272
            | 287..=293
            | 300..=306
            | 515
            | 516
            | 520
            | 521
            | 523..=527
            | 539
            | 540
            | 544..=548
            | 565
            | 566 => Some(MOVW),
            274..=276 | 311 | 512 | 513 | 517 | 518 | 541 | 561 | 562 => Some(ADR),
            273 | 280 | 309 | 522 | 543 | 560 => Some(IMM19),
            279 => Some(IMM14),
            282 | 283 => Some(IMM26),
            277
            | 278
            | 284..=286
            | 299
            | 310
            | 312
            | 313
            | 514
            | 519
            | 528..=538
            | 542
            | 549..=559
            | 563
            | 564
            | 570..=573 => Some(IMM12),
            _ => None,
        },
        _ => None,
    }
}

/// The digits a nonzero relocated field is quoted in.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// `STT_FUNC`, the low nibble of `st_info`.
const STT_FUNC: u8 = 2;
/// `SHF_EXECINSTR`: the section holds instructions.
const SHF_EXECINSTR: u64 = 0x4;
/// The first reserved section index (`SHN_LORESERVE`); `SHN_ABS`, `SHN_COMMON` and
/// `SHN_XINDEX` sit at or above it, and none names a section of the file.
const SHN_LORESERVE: u16 = 0xff00;

/// One symbol-table entry that defines a scanned function.
struct Definition {
    value: u64,
    size: u64,
    shndx: u16,
}

/// Where each match of `pattern` falls in `bytes`, as an offset from the first byte.
/// `base` is the function's address, which fixes word alignment.
fn find(pattern: &CodePattern, bytes: &[u8], base: u64) -> Vec<usize> {
    match pattern.shape {
        Shape::Bytes(needle) if !needle.is_empty() => bytes
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == needle)
            .map(|(at, _)| at)
            .collect(),
        Shape::Masked(needle) if !needle.is_empty() => bytes
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| {
                window
                    .iter()
                    .zip(needle)
                    .all(|(byte, (mask, value))| byte & mask == *value)
            })
            .map(|(at, _)| at)
            .collect(),
        Shape::Bytes(_) | Shape::Masked(_) => Vec::new(),
        Shape::Word { mask, value } => aligned_words(bytes, base, |w| w & mask == value),
        Shape::WordExcept {
            mask,
            value,
            except,
        } => aligned_words(bytes, base, |w| w & mask == value && w != except),
    }
}

/// The offsets of the little-endian words of `bytes` at addresses that are a multiple of
/// 4, `base` being the first byte's, for which `matches` holds.
fn aligned_words(bytes: &[u8], base: u64, matches: impl Fn(u32) -> bool) -> Vec<usize> {
    // The first offset whose address is a multiple of 4.
    let lead: usize = match base & 3 {
        0 => 0,
        1 => 3,
        2 => 2,
        _ => 1,
    };
    let Some(aligned) = bytes.get(lead..) else {
        return Vec::new();
    };
    let (words, _tail) = aligned.as_chunks::<4>();
    words
        .iter()
        .enumerate()
        .filter_map(|(i, word)| {
            matches(u32::from_le_bytes(*word))
                .then(|| i.checked_mul(4).and_then(|o| o.checked_add(lead)))
                .flatten()
        })
        .collect()
}

impl Elf<'_> {
    /// `(code_scanned, code_matches)`, as the module documentation describes them.
    pub(super) fn code_scan(&self, trunc: &mut Vec<Truncation>) -> (Vec<String>, Vec<String>) {
        let mut scanned = Vec::new();
        let mut matches = Vec::new();
        let searched = |scan: &Scan| -> Vec<&'static CodePattern> {
            CODE_PATTERNS
                .iter()
                .filter(|p| p.machine == self.e_machine && scan.patterns.contains(&p.name))
                .collect()
        };
        if SCANS.iter().all(|scan| searched(scan).is_empty()) {
            return (scanned, matches);
        }
        let (definitions, stopped) = self.function_definitions();
        for scan in SCANS {
            let patterns = searched(scan);
            if patterns.is_empty() {
                continue;
            }
            let name = &scan.function;
            let found: Vec<&Definition> = definitions
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, d)| d)
                .collect();
            let definition = match found.as_slice() {
                [] => {
                    // Absent is not recorded; absent behind an entry this walk alone could
                    // not read is (see `function_definitions`).
                    if let Some(at) = &stopped {
                        trunc.push(Truncation::unread(
                            ElfTable::Code,
                            format!("{name}: not found before the symbol walk stopped ({at})"),
                        ));
                    }
                    continue;
                }
                [one] => *one,
                more => {
                    trunc.push(Truncation::unread(
                        ElfTable::Code,
                        format!("{name}: {} defined functions carry the name", more.len()),
                    ));
                    continue;
                }
            };
            let Some(bytes) = self.function_bytes(name, definition, trunc) else {
                continue;
            };
            if self.e_type == ET_REL
                && let Err(why) = self.relocated_fields(definition, trunc)
            {
                trunc.push(Truncation::unread(ElfTable::Code, format!("{name}: {why}")));
                continue;
            }
            for pattern in &patterns {
                // Each search is charged the bytes it reads: every function `SCANS` names may
                // be defined over the same bytes, and each is searched once per pattern.
                let units = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if let Err(spent) = self.budget.spend(units) {
                    trunc.push(Truncation::unread(
                        ElfTable::Code,
                        format!("{name}: {} was not searched: {spent}", pattern.name),
                    ));
                    break;
                }
                let at = find(pattern, bytes, definition.value);
                scanned.push(format!("{name}:{}={}", pattern.name, at.len()));
                matches.extend(
                    at.iter()
                        .take(MATCHES_KEPT)
                        .map(|o| format!("{name}:{}@{o:#x}", pattern.name)),
                );
            }
        }
        (scanned, matches)
    }

    /// Every defined `STT_FUNC` in `.symtab` whose name a [`SCANS`] entry names, and
    /// the entry this walk could not read, if it met one.
    fn function_definitions(&self) -> (Vec<(&'static str, Definition)>, Option<String>) {
        let mut out = Vec::new();
        let mut recorded_by_symbols = Vec::new();
        for (idx, sh) in self.shdrs.iter().enumerate() {
            if sh.sh_type != SHT_SYMTAB {
                continue;
            }
            let table = self.symbol_table_label(idx, sh);
            let Some((step, count)) =
                self.symbol_entries(idx, sh, &table, &mut recorded_by_symbols)
            else {
                return (out, None);
            };
            let Some(strtab) = self.symbol_strtab(sh, &table, &mut recorded_by_symbols) else {
                return (out, None);
            };
            for i in 0..count {
                // A spent budget forgets the definitions found, so every function the walk
                // looks for reads as not found before it stopped, and is recorded so: one
                // found before the stop could have a second definition after it.
                if let Err(spent) = self.step() {
                    return (
                        Vec::new(),
                        Some(format!(
                            "{table} not read past symbol {i} of {count}: {spent}"
                        )),
                    );
                }
                let base = sh.sh_offset.saturating_add(i.saturating_mul(step));
                let (name_off, info, shndx, value, size) = match self.symbol_entry(base) {
                    Ok(entry) => entry,
                    Err(why) => {
                        return (
                            out,
                            Some(format!(
                                "{table} unreadable at symbol {i} of {count} ({why})"
                            )),
                        );
                    }
                };
                if u64::from(name_off) >= strtab.sh_size {
                    return (out, None);
                }
                if info & 0xf != STT_FUNC || shndx == SHN_UNDEF {
                    continue;
                }
                // A name not read, past the bound on one name or the budget, stops the walk
                // as a spent budget does: the definitions found are forgotten and every
                // function looked for is recorded as not found before the stop, whatever
                // `symbols` records over the same entry.
                let name = match self.name_at(strtab.sh_offset, name_off, strtab.sh_size) {
                    Ok(name) => name,
                    Err(fault) => {
                        return (
                            Vec::new(),
                            Some(format!(
                                "{table}: the name of symbol {i} of {count} was not read: {fault}"
                            )),
                        );
                    }
                };
                if let Some(known) = SCANS.iter().find(|scan| scan.function == name) {
                    out.push((known.function, Definition { value, size, shndx }));
                }
            }
        }
        (out, None)
    }

    /// One symbol-table entry at `base`: `st_name`, `st_info`, `st_shndx`, `st_value` and
    /// `st_size`, in either width.
    fn symbol_entry(&self, base: u64) -> super::Read<(u32, u8, u16, u64, u64)> {
        let (info_at, shndx_at, value_at, size_at) = if self.elf64 {
            (4, 6, 8, 16)
        } else {
            (12, 14, 4, 8)
        };
        let name_off = self.cur.u32_at(base)?;
        // `slice` returned exactly one byte or an error, as in `Cursor::u16_at`.
        let [info]: [u8; 1] = self
            .cur
            .slice(base.saturating_add(info_at), 1)?
            .try_into()
            .unwrap_or([0]);
        let shndx = self.cur.u16_at(base.saturating_add(shndx_at))?;
        let value = self
            .cur
            .addr_at(base.saturating_add(value_at), self.elf64)?;
        let size = self.cur.addr_at(base.saturating_add(size_at), self.elf64)?;
        Ok((name_off, info, shndx, value, size))
    }

    /// The bytes of one definition, or `None` with the reason recorded.
    fn function_bytes(
        &self,
        name: &str,
        def: &Definition,
        trunc: &mut Vec<Truncation>,
    ) -> Option<&[u8]> {
        let mut unread = |why: String| -> Option<&[u8]> {
            trunc.push(Truncation::unread(ElfTable::Code, format!("{name}: {why}")));
            None
        };
        if def.size == 0 {
            return unread("st_size is 0, so the function's extent is unknown".to_owned());
        }
        if def.shndx >= SHN_LORESERVE {
            return unread(format!(
                "st_shndx {:#x} is a reserved index that names no section of the file",
                def.shndx
            ));
        }
        let Some(section): Option<&Shdr> = self.shdrs.get(usize::from(def.shndx)) else {
            return unread(format!(
                "st_shndx {} is past the section-header table",
                def.shndx
            ));
        };
        if section.sh_type == SHT_NOBITS || section.sh_flags & SHF_EXECINSTR == 0 {
            return unread(format!(
                "section {} holds no instructions in the file (type {:#x}, flags {:#x})",
                def.shndx, section.sh_type, section.sh_flags
            ));
        }
        // An object's `st_value` is an offset into its section; a linked object's is an
        // address, and the section's own address maps it back.
        let start = if self.e_type == ET_REL {
            Some(def.value)
        } else {
            def.value.checked_sub(section.sh_addr)
        };
        let end = start.and_then(|s| s.checked_add(def.size));
        let (Some(start), Some(end)) = (start, end) else {
            return unread(format!(
                "st_value {:#x} does not fall in section {} at {:#x}",
                def.value, def.shndx, section.sh_addr
            ));
        };
        if end > section.sh_size {
            return unread(format!(
                "[{start:#x}, {end:#x}) runs past section {}'s {:#x} bytes",
                def.shndx, section.sh_size
            ));
        }
        match self
            .cur
            .slice(section.sh_offset.saturating_add(start), def.size)
        {
            Ok(bytes) => Some(bytes),
            Err(why) => unread(format!("its bytes lie past the end of the file ({why})")),
        }
    }

    /// Every field a relocation patches within an object's function, checked to hold
    /// zero, or why the function's bytes cannot be taken as the compiler's own encoding.
    fn relocated_fields(
        &self,
        def: &Definition,
        trunc: &mut Vec<Truncation>,
    ) -> Result<(), String> {
        let start = def.value;
        let end = def.value.saturating_add(def.size);
        let Some(section) = self.shdrs.get(usize::from(def.shndx)) else {
            return Err(format!(
                "st_shndx {} is past the section-header table",
                def.shndx
            ));
        };
        for (idx, sh) in self.shdrs.iter().enumerate() {
            if sh.sh_info != u32::from(def.shndx) {
                continue;
            }
            let label = self.relocation_label(idx);
            let rela = match sh.sh_type {
                SHT_RELA => true,
                SHT_REL => false,
                kind if kind == SHT_CREL || sh.sh_flags & SHF_INFO_LINK != 0 => {
                    return Err(format!(
                        "{label} relocates its section in an encoding the reader does not decode (type {kind:#x})"
                    ));
                }
                _ => continue,
            };
            let step = self.section_stride(idx, sh, relocation_record(self.elf64, rela), trunc);
            if sh.sh_size % step != 0 {
                return Err(format!(
                    "{label}'s sh_size {:#x} is not a whole number of {step}-byte entries",
                    sh.sh_size
                ));
            }
            let count = sh.sh_size / step;
            let step = step.get();
            for i in 0..count {
                self.step().map_err(|spent| {
                    format!("{label} was not read past entry {i} of {count}: {spent}")
                })?;
                let base = sh.sh_offset.saturating_add(i.saturating_mul(step));
                let entry = if self.elf64 {
                    self.cur
                        .u64_at(base)
                        .and_then(|off| Ok((off, self.cur.u64_at(base.saturating_add(8))?)))
                        .map(|(off, info)| (off, info & 0xffff_ffff))
                } else {
                    self.cur.u32_at(base).and_then(|off| {
                        let info = self.cur.u32_at(base.saturating_add(4))?;
                        Ok((u64::from(off), u64::from(info & 0xff)))
                    })
                };
                let Ok((offset, kind)) = entry else {
                    return Err(format!("{label} is unreadable at entry {i} of {count}"));
                };
                let kind = u32::try_from(kind).unwrap_or(u32::MAX);
                self.relocated_field_is_zero(section, offset, kind, (start, end))
                    .map_err(|why| format!("{label} entry {i}: {why}"))?;
            }
        }
        Ok(())
    }

    /// One relocation's field checked: `Ok` where its type writes nothing, where the
    /// field lies outside `[start, end)`, or where it holds zero; otherwise why not.
    fn relocated_field_is_zero(
        &self,
        section: &Shdr,
        offset: u64,
        kind: u32,
        (start, end): (u64, u64),
    ) -> Result<(), String> {
        let name = reloc_type_name(self.e_machine, kind);
        let field = relocated_field(self.e_machine, kind)
            .ok_or_else(|| format!("{name}, whose field the reader does not size"))?;
        let width = match field {
            Field::Marker => return Ok(()),
            Field::Bytes(width) => width,
            Field::Word(_) => 4,
        };
        let field_end = offset.saturating_add(width);
        if offset >= end || field_end <= start {
            return Ok(());
        }
        if field_end > section.sh_size {
            return Err(format!(
                "{name} at {offset:#x} patches {width} bytes past its section's {:#x}",
                section.sh_size
            ));
        }
        let bytes = self
            .cur
            .slice(section.sh_offset.saturating_add(offset), width)
            .map_err(|why| {
                format!("{name} at {offset:#x} patches bytes past the end of the file ({why})")
            })?;
        let zero = match field {
            Field::Word(mask) => bytes
                .try_into()
                .is_ok_and(|word: [u8; 4]| u32::from_le_bytes(word) & mask == 0),
            Field::Marker | Field::Bytes(_) => bytes.iter().all(|b| *b == 0),
        };
        if zero {
            return Ok(());
        }
        let held: String = bytes
            .iter()
            .flat_map(|b| [b >> 4, b & 0xf])
            .map(|nibble| char::from(HEX.get(usize::from(nibble)).copied().unwrap_or(b'?')))
            .collect();
        Err(format!(
            "{name} at {offset:#x} patches a field holding {held}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(name: &str) -> &'static CodePattern {
        CODE_PATTERNS
            .iter()
            .find(|p| p.name == name)
            .expect("a named pattern")
    }

    #[test]
    fn a_byte_pattern_matches_at_every_offset_and_only_there() {
        let ud2 = pattern("x86-ud2");
        assert_eq!(find(ud2, &[0x0f, 0x0b, 0x90, 0x0f, 0x0b], 0), vec![0, 3]);
        assert_eq!(find(ud2, &[0x0f, 0xb9, 0x40, 0x14], 0), Vec::<usize>::new());
        assert_eq!(find(ud2, &[0x0f], 0), Vec::<usize>::new());
        assert_eq!(find(ud2, &[], 0), Vec::<usize>::new());
        let ud1 = pattern("x86-ud1");
        assert_eq!(find(ud1, &[0x0f, 0xb9, 0x40, 0x14], 0), vec![0]);
    }

    #[test]
    fn a_word_pattern_reads_aligned_words_whatever_the_immediate() {
        let brk = pattern("a64-brk");
        // gcc's `brk #0x3e8`, clang's `brk #0x5514`, and a `ret`.
        let gcc = 0xd420_7d00_u32.to_le_bytes();
        let clang = 0xd42a_a280_u32.to_le_bytes();
        let ret = 0xd65f_03c0_u32.to_le_bytes();
        let code: Vec<u8> = [ret, gcc, clang].concat();
        assert_eq!(find(brk, &code, 0), vec![4, 8]);
        // Two bytes in, the same bytes straddle words and match nothing.
        let shifted: Vec<u8> = [&[0, 0][..], &code[..]].concat();
        assert_eq!(find(brk, &shifted, 0), Vec::<usize>::new());
        // A function at an address two bytes short of a word boundary: its first
        // aligned word starts two bytes in.
        assert_eq!(find(brk, &shifted, 2), vec![6, 10]);
        // `hlt #0`, the neighbouring exception-generating class, is not `brk`.
        assert_eq!(
            find(brk, &0xd440_0000_u32.to_le_bytes(), 0),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn the_call_patterns_match_calls_and_not_their_neighbours() {
        let bl = pattern("a64-bl");
        let blr = pattern("a64-blr");
        // `bl` with a zero field and with an offset, `blr x16`, `br x16` and `ret`.
        let code: Vec<u8> = [
            0x9400_0000_u32,
            0x9400_0010,
            0xd63f_0200,
            0xd61f_0200,
            0xd65f_03c0,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        assert_eq!(find(bl, &code, 0), vec![0, 4]);
        assert_eq!(find(blr, &code, 0), vec![8]);
        let call = pattern("x86-call-rel32");
        // `call rel32` with a zero field, then one the assembler resolved.
        let x86 = [0xe8, 0, 0, 0, 0, 0xe8, 0x10, 0, 0, 0];
        assert_eq!(find(call, &x86, 0), vec![0]);
        let got = pattern("x86-call-got");
        assert_eq!(find(got, &[0x90, 0xff, 0x15, 0, 0, 0, 0], 0), vec![1]);
        let reg = pattern("x86-call-reg");
        // clang's large-model call, `movabs $0,%rax` and `call *%rax`; `call *%r8` behind
        // its REX prefix; then `jmp *%rax` (`ff e0`) and `push %rax` behind a `ff` that
        // closes an immediate, neither a call.
        let large = [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xd0];
        assert_eq!(find(reg, &large, 0), vec![10]);
        assert_eq!(find(reg, &[0x41, 0xff, 0xd0, 0xff, 0xd7], 0), vec![1, 3]);
        assert_eq!(
            find(reg, &[0xff, 0xe0, 0xff, 0x50, 0xff], 0),
            Vec::<usize>::new()
        );
        let sib = pattern("x86-call-sib");
        assert_eq!(find(sib, &[0x41, 0xff, 0x14, 0x00], 0), vec![1]);
    }

    #[test]
    fn a_check_pattern_leaves_out_clangs_signed_overflow_trap() {
        let ud1 = pattern("x86-ud1");
        let check = pattern("x86-ud1-check");
        // clang's `ud1 0x14(%eax),%eax` (shift) and `ud1 (%eax),%eax` (signed overflow),
        // each behind its `67` prefix.
        let x86 = [0x67, 0x0f, 0xb9, 0x40, 0x14, 0x67, 0x0f, 0xb9, 0x00];
        assert_eq!(find(ud1, &x86, 0), vec![1, 6]);
        assert_eq!(find(check, &x86, 0), vec![1]);
        let brk = pattern("a64-brk");
        let other = pattern("a64-brk-check");
        // clang's `brk #0x5514` and `brk #0x5500`, and gcc's `brk #0x3e8`.
        let code: Vec<u8> = [0xd42a_a280_u32, 0xd42a_a000, 0xd420_7d00]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert_eq!(find(brk, &code, 0), vec![0, 4, 8]);
        assert_eq!(find(other, &code, 0), vec![0, 8]);
    }

    #[test]
    fn the_clang_check_pattern_leaves_out_every_brk_but_clangs_numbered_ones() {
        let clang = pattern("a64-brk-clang-check");
        let any = pattern("a64-brk-check");
        // clang's `brk #0x5514` (shift), `#0x5506` (function), `#0x5500` (signed overflow),
        // gcc's `#0x3e8`, and kcfi's `#0x8220` (`x0` checked, `w0` scratch).
        let code: Vec<u8> = [
            0xd42a_a280_u32,
            0xd42a_a0c0,
            0xd42a_a000,
            0xd420_7d00,
            0xd430_4400,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        assert_eq!(find(clang, &code, 0), vec![0, 4]);
        assert_eq!(find(any, &code, 0), vec![0, 4, 12, 16]);
    }

    /// A relocatable ELF64 object holding `code` in `.text`, `chard_ubsan_trap_probe`
    /// defined over its first `size` bytes, and `relocs` as `(r_offset, type)` in a
    /// relocation section of type `rel_type` applying to `.text`, each `SHT_REL` entry
    /// 16 bytes and each other 24 (addend 0).
    fn object(
        machine: u16,
        code: &[u8],
        size: u64,
        rel_type: u32,
        relocs: &[(u64, u32)],
    ) -> Vec<u8> {
        const TEXT: usize = 0x40;
        const RELS: usize = 0x100;
        const SYMS: usize = 0x200;
        const STRS: usize = 0x300;
        const SHDRS: usize = 0x400;
        let strings = b"\0chard_ubsan_trap_probe\0.text\0.rel\0.symtab\0.strtab\0";
        let (fname, text, rel, symtab, strtab) = (1u32, 24u32, 30u32, 35u32, 43u32);
        let mut d = vec![0u8; SHDRS + 5 * 64];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[6] = 1;
        d[16..18].copy_from_slice(&ET_REL.to_le_bytes());
        d[18..20].copy_from_slice(&machine.to_le_bytes());
        d[20..24].copy_from_slice(&1u32.to_le_bytes());
        d[40..48].copy_from_slice(&(SHDRS as u64).to_le_bytes());
        d[52..54].copy_from_slice(&64u16.to_le_bytes());
        d[58..60].copy_from_slice(&64u16.to_le_bytes());
        d[60..62].copy_from_slice(&5u16.to_le_bytes());
        d[62..64].copy_from_slice(&4u16.to_le_bytes());
        d[TEXT..TEXT + code.len()].copy_from_slice(code);
        let entsize: usize = if rel_type == SHT_REL { 16 } else { 24 };
        for (i, (offset, kind)) in relocs.iter().enumerate() {
            let at = RELS + i * entsize;
            d[at..at + 8].copy_from_slice(&offset.to_le_bytes());
            d[at + 8..at + 16].copy_from_slice(&u64::from(*kind).to_le_bytes());
        }
        // The null symbol, then the function: global `STT_FUNC` in section 1.
        let sym = SYMS + 24;
        d[sym..sym + 4].copy_from_slice(&fname.to_le_bytes());
        d[sym + 4] = 0x12;
        d[sym + 6..sym + 8].copy_from_slice(&1u16.to_le_bytes());
        d[sym + 16..sym + 24].copy_from_slice(&size.to_le_bytes());
        d[STRS..STRS + strings.len()].copy_from_slice(strings);
        let rel_size = (relocs.len() * entsize) as u64;
        // (name, type, flags, offset, size, link, info, entsize)
        let headers: [Header; 4] = [
            (text, 1, 0x6, TEXT, code.len() as u64, 0, 0, 0),
            (
                rel,
                rel_type,
                SHF_INFO_LINK,
                RELS,
                rel_size,
                3,
                1,
                entsize as u64,
            ),
            (symtab, SHT_SYMTAB, 0, SYMS, 48, 4, 1, 24),
            (strtab, 3, 0, STRS, strings.len() as u64, 0, 0, 0),
        ];
        for (n, (name, kind, flags, off, size, link, info, ent)) in headers.iter().enumerate() {
            let h = SHDRS + (n + 1) * 64;
            d[h..h + 4].copy_from_slice(&name.to_le_bytes());
            d[h + 4..h + 8].copy_from_slice(&kind.to_le_bytes());
            d[h + 8..h + 16].copy_from_slice(&flags.to_le_bytes());
            d[h + 24..h + 32].copy_from_slice(&(*off as u64).to_le_bytes());
            d[h + 32..h + 40].copy_from_slice(&size.to_le_bytes());
            d[h + 40..h + 44].copy_from_slice(&link.to_le_bytes());
            d[h + 44..h + 48].copy_from_slice(&info.to_le_bytes());
            d[h + 56..h + 64].copy_from_slice(&ent.to_le_bytes());
        }
        d
    }

    /// A section header's fields as `object` writes them: name, type, flags, offset, size,
    /// link, info and entry size.
    type Header = (u32, u32, u64, usize, u64, u32, u32, u64);

    /// The function's `code_scanned` entries and the `code` table's unread records.
    fn scan(d: &[u8]) -> (Vec<String>, Vec<String>) {
        let facts = Elf::parse(d).expect("parses").facts();
        let unread = facts
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::Code)
            .map(|t| t.detail.clone())
            .collect();
        (facts.code_scanned, unread)
    }

    /// x86_64 `R_X86_64_PC32` and `R_X86_64_PLT32`.
    const PC32: u32 = 2;
    const PLT32: u32 = 4;

    #[test]
    fn a_function_whose_relocated_fields_hold_zero_is_searched() {
        // `ud2`, then `call rel32` with its field zero, relocated, and `ret`.
        let code = [0x0f, 0x0b, 0xe8, 0, 0, 0, 0, 0xc3];
        let (scanned, unread) = scan(&object(EM_X86_64, &code, 8, SHT_RELA, &[(3, PLT32)]));
        assert!(unread.is_empty(), "{unread:?}");
        assert!(
            scanned.contains(&"chard_ubsan_trap_probe:x86-ud2=1".to_owned()),
            "{scanned:?}"
        );
        assert!(scanned.contains(&"chard_ubsan_trap_probe:x86-call-rel32=1".to_owned()));
    }

    #[test]
    fn a_nonzero_relocated_field_leaves_the_function_unread() {
        let trap_in_field = [0xe8, 0x0f, 0x0b, 0, 0, 0xc3];
        let (scanned, unread) = scan(&object(
            EM_X86_64,
            &trap_in_field,
            6,
            SHT_RELA,
            &[(1, PC32)],
        ));
        assert!(scanned.is_empty(), "{scanned:?}");
        assert!(
            unread
                .iter()
                .any(|u| u.contains("R_X86_64_PC32 at 0x1") && u.contains("holding 0f0b0000")),
            "{unread:?}"
        );
        let addend_in_field = [0xe8, 0xfc, 0xff, 0xff, 0xff, 0xc3];
        let (scanned, unread) = scan(&object(
            EM_X86_64,
            &addend_in_field,
            6,
            SHT_RELA,
            &[(1, PLT32)],
        ));
        assert!(scanned.is_empty() && unread.len() == 1, "{unread:?}");
    }

    #[test]
    fn a_relocation_section_is_walked_in_records_whatever_its_entsize() {
        let code = [0xe8, 0, 0, 0, 0, 0xe8, 0x0f, 0x0b, 0, 0, 0xc3];
        let honest = object(EM_X86_64, &code, 11, SHT_RELA, &[(1, PC32), (6, PC32)]);
        let mut forged = honest.clone();
        // The relocation section's header is the second after the null one.
        let entsize = 0x400 + 2 * 64 + 56;
        assert_eq!(forged[entsize..entsize + 8], 24u64.to_le_bytes());
        forged[entsize..entsize + 8].copy_from_slice(&48u64.to_le_bytes());
        for d in [&honest, &forged] {
            let (scanned, unread) = scan(d);
            assert!(scanned.is_empty(), "{scanned:?}");
            assert!(
                unread.iter().any(|u| u.contains("holding 0f0b0000")),
                "{unread:?}"
            );
        }
        let records: Vec<Truncation> = Elf::parse(&forged)
            .expect("parses")
            .facts()
            .truncations
            .into_iter()
            .filter(|t| t.table == ElfTable::Relocations)
            .collect();
        assert_eq!(records.len(), 1, "{records:?}");
        assert!(
            records[0]
                .detail
                .contains("sh_entsize is 48 where the record is 24 bytes"),
            "{records:?}"
        );
    }

    #[test]
    fn a_rel_entrys_addend_is_read_in_its_field() {
        let code = [0xe8, 0xfc, 0xff, 0xff, 0xff, 0xc3];
        let (scanned, unread) = scan(&object(EM_X86_64, &code, 6, SHT_REL, &[(1, PC32)]));
        assert!(scanned.is_empty(), "{scanned:?}");
        assert!(unread.iter().any(|u| u.contains("fcffffff")), "{unread:?}");
        let zero = [0xe8, 0, 0, 0, 0, 0xc3];
        let (scanned, unread) = scan(&object(EM_X86_64, &zero, 6, SHT_REL, &[(1, PC32)]));
        assert!(unread.is_empty() && !scanned.is_empty(), "{unread:?}");
    }

    #[test]
    fn an_unsized_type_or_undecoded_encoding_stops_and_a_field_outside_does_not() {
        let code = [0x0f, 0x0b, 0xc3, 0, 0xff, 0xff, 0xff, 0xff];
        // `R_X86_64_JUMP_SLOT`, the dynamic linker's.
        let (scanned, unread) = scan(&object(EM_X86_64, &code, 3, SHT_RELA, &[(0, 7)]));
        assert!(scanned.is_empty(), "{scanned:?}");
        assert!(
            unread
                .iter()
                .any(|u| u.contains("R_X86_64_JUMP_SLOT") && u.contains("does not size")),
            "{unread:?}"
        );
        let (scanned, unread) = scan(&object(EM_X86_64, &code, 3, SHT_CREL, &[]));
        assert!(scanned.is_empty(), "{scanned:?}");
        assert!(
            unread.iter().any(|u| u.contains("does not decode")),
            "{unread:?}"
        );
        // The function is the first three bytes; the field at 4 is another function's.
        let (scanned, unread) = scan(&object(EM_X86_64, &code, 3, SHT_RELA, &[(4, PC32)]));
        assert!(unread.is_empty(), "{unread:?}");
        assert!(scanned.contains(&"chard_ubsan_trap_probe:x86-ud2=1".to_owned()));
    }

    #[test]
    fn an_aarch64_field_is_the_immediate_not_the_word() {
        let words = |ws: &[u32]| ws.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        // `brk #0x3e8`, `adrp x0, 0` (ADR_GOT_PAGE), `bl 0` (CALL26), `ret`.
        let zero = words(&[0xd420_7d00, 0x9000_0000, 0x9400_0000, 0xd65f_03c0]);
        let (scanned, unread) = scan(&object(
            EM_AARCH64,
            &zero,
            16,
            SHT_RELA,
            &[(4, 311), (8, 283)],
        ));
        assert!(unread.is_empty(), "{unread:?}");
        assert!(scanned.contains(&"chard_ubsan_trap_probe:a64-brk=1".to_owned()));
        let offset = words(&[0xd420_7d00, 0x9400_0010, 0xd65f_03c0]);
        let (scanned, unread) = scan(&object(EM_AARCH64, &offset, 12, SHT_RELA, &[(4, 283)]));
        assert!(scanned.is_empty(), "{scanned:?}");
        assert!(
            unread.iter().any(|u| u.contains("R_AARCH64_CALL26")),
            "{unread:?}"
        );
    }

    #[test]
    fn a_trap_in_a_relocated_field_withholds_ubsan_trap_mode() {
        let decode = |code: &[u8], at: u64| {
            let facts = Elf::parse(&object(EM_X86_64, code, 6, SHT_RELA, &[(at, PC32)]))
                .expect("parses")
                .facts();
            let macros = std::collections::BTreeMap::new();
            crate::probe::CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .find(|c| c.id == "ubsan-trap-mode")
                .expect("ubsan-trap-mode is in the corpus")
                .decode(&crate::probe::Evidence {
                    macros: &macros,
                    elf: Some(&facts),
                    build: None,
                    run: None,
                    workdir: None,
                })
                .detection
        };
        let trap = decode(&[0x0f, 0x0b, 0, 0, 0, 0], 2);
        assert_eq!(
            trap.outcome,
            crate::probe::Outcome::Present,
            "{}",
            trap.observed
        );
        let in_field = decode(&[0xe8, 0x0f, 0x0b, 0, 0, 0xc3], 1);
        assert_eq!(
            in_field.outcome,
            crate::probe::Outcome::Indeterminate,
            "{}",
            in_field.observed
        );
    }

    #[test]
    fn every_sized_relocation_type_is_sized_by_its_name() {
        const MOVW: Field = Field::Word(0x001f_ffe0);
        const ADR: Field = Field::Word(0x60ff_ffe0);
        const IMM19: Field = Field::Word(0x00ff_ffe0);
        let mut sized = 0;
        for kind in 0..2048 {
            let name = reloc_type_name(EM_X86_64, kind);
            let want = if name.starts_with("reloc-type-") {
                None
            } else if name.ends_with("_NONE") || name.ends_with("TLSDESC_CALL") {
                Some(Field::Marker)
            } else if [
                "COPY",
                "GLOB_DAT",
                "JUMP_SLOT",
                "RELATIVE",
                "DTPMOD64",
                "DTPOFF64",
                "TPOFF64",
                "TLSDESC",
                "IRELATIVE",
                "RELATIVE64",
            ]
            .iter()
            .any(|s| name.strip_prefix("R_X86_64_") == Some(s))
            {
                None
            } else if name.ends_with("64") {
                Some(Field::Bytes(8))
            } else if name.ends_with("_16") || name.ends_with("PC16") {
                Some(Field::Bytes(2))
            } else if name.ends_with("_8") || name.ends_with("PC8") {
                Some(Field::Bytes(1))
            } else {
                Some(Field::Bytes(4))
            };
            assert_eq!(relocated_field(EM_X86_64, kind), want, "{name}");
            sized += usize::from(want.is_some());

            let name = reloc_type_name(EM_AARCH64, kind);
            let has = |s: &str| name.contains(s);
            let want = if name.starts_with("reloc-type-") {
                None
            } else if name.ends_with("_NONE")
                || ["TLSDESC_LDR", "TLSDESC_ADD", "TLSDESC_CALL"]
                    .iter()
                    .any(|s| name.ends_with(s))
            {
                Some(Field::Marker)
            } else if has("MOVW") || has("_OFF_G") {
                Some(MOVW)
            } else if has("ADR_") || has("PAGE21") || has("PREL21") {
                Some(ADR)
            } else if has("PREL19") || has("LO19") || has("CONDBR19") {
                Some(IMM19)
            } else if has("TSTBR14") {
                Some(Field::Word(0x0007_ffe0))
            } else if has("JUMP26") || has("CALL26") {
                Some(Field::Word(0x03ff_ffff))
            } else if has("LO12") || has("HI12") || has("LO15") {
                Some(Field::Word(0x003f_fc00))
            } else if ["ABS64", "PREL64", "GOTREL64"]
                .iter()
                .any(|s| name.ends_with(s))
            {
                Some(Field::Bytes(8))
            } else if ["ABS32", "PREL32", "GOTREL32"]
                .iter()
                .any(|s| name.ends_with(s))
            {
                Some(Field::Bytes(4))
            } else if ["ABS16", "PREL16"].iter().any(|s| name.ends_with(s)) {
                Some(Field::Bytes(2))
            } else {
                None
            };
            assert_eq!(relocated_field(EM_AARCH64, kind), want, "{name}");
            sized += usize::from(want.is_some());
        }
        assert!(
            sized > 100,
            "the table sized {sized} types, so the loop read almost nothing"
        );
    }

    #[test]
    fn every_pattern_names_a_machine_the_reader_names() {
        for p in CODE_PATTERNS {
            assert!(
                !super::super::machine_name(p.machine).starts_with("unrecognised"),
                "{} names an e_machine the reader does not",
                p.name
            );
            assert!(
                !p.name.contains([':', '=', '@']),
                "{} would be ambiguous in the facts' spelling",
                p.name
            );
        }
    }

    #[test]
    fn every_scan_names_an_identifier_once_and_patterns_that_exist() {
        for (i, scan) in SCANS.iter().enumerate() {
            assert!(
                scan.function
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'),
                "{} would be ambiguous in the facts' spelling",
                scan.function
            );
            assert!(
                SCANS
                    .iter()
                    .skip(i + 1)
                    .all(|s| s.function != scan.function),
                "{} is listed twice",
                scan.function
            );
            assert!(
                !scan.patterns.is_empty(),
                "{} searches for nothing",
                scan.function
            );
            for name in scan.patterns {
                assert!(
                    CODE_PATTERNS.iter().any(|p| p.name == *name),
                    "{}: no pattern is named {name}",
                    scan.function
                );
            }
        }
    }
}
