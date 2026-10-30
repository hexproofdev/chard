// SPDX-License-Identifier: BSD-3-Clause

//! The first bytes of a few named functions: what each begins with in the artifact.
//!
//! `-fcf-protection=branch` (and `=full`) has the compiler begin every function an
//! indirect branch may reach with a landing pad, `endbr64` (`f3 0f 1e fa`) on x86_64 and
//! `endbr32` (`f3 0f 1e fb`) on i386. The property note `cet-marked-object` reads is the
//! compiler's claim that it did; the instruction is the instrumentation itself, and this
//! module reads it. A function's first four bytes are the smallest case of a code-byte
//! reader: one fixed prefix at one known address, never decoded and never searched.
//!
//! # What is read
//!
//! [`ENTRY_FUNCTIONS`] names the functions, each the `cet-endbr` probe's own. A function
//! is located through `.symtab`: a defined `STT_FUNC` entry of that exact name. Its first
//! [`ENTRY_BYTES`] bytes (fewer where `st_size` is smaller) are read from
//! `st_value` mapped through the section header its `st_shndx` names: section-relative in
//! an `ET_REL`, a virtual address in a linked object, which the section's `sh_addr` maps
//! back. The section must carry `SHF_EXECINSTR` and file bytes, and every step is bounded
//! by the section's declared extent and by the file through `Cursor`.
//!
//! The fact is `function_entries`, `<function>=<hex>` for each listed function read, the
//! bytes in file order as lowercase hex. A listed function the file does not define is not
//! recorded, since an absent function is a question with no referent here, and the
//! predicate that reads the fact turns a missing entry into `indeterminate` rather than a
//! reading. A listed function that is defined and cannot be read, or that more than one
//! entry defines, is recorded as [`ElfTable::FunctionEntries`] `unread`, with the step
//! that stopped it.
//!
//! # Why a prefix at a symbol's address is the instruction
//!
//! A function's address is an instruction boundary by construction: it is where the
//! function's first instruction begins, so the four bytes there are that instruction's
//! encoding or the start of it, and cannot be the tail of another. `f3 0f 1e fa` and
//! `f3 0f 1e fb` are the whole encodings of `endbr64` and `endbr32`. The probe's functions
//! are global and address-taken, so a compiler instrumenting indirect-branch targets must
//! give each a landing pad, and `noinline` keeps each a function of its own at every -O
//! level. The control triple checks the result: under `-fcf-protection=none` the same
//! functions begin otherwise, on the toolchain being measured.
//!
//! # Overlap
//!
//! `elf::code` is a fixed-pattern search over named functions' whole bodies, with its own
//! symbol walk and its own table (`code`). This reader is the smallest case of it (one
//! pattern, at offset 0), with a walk of its own beside it; unifying the two walks is open
//! in the project ledger.

use super::{ET_REL, Elf, ElfTable, SHF_EXECINSTR, SHN_UNDEF, SHT_NOBITS, SHT_SYMTAB, Truncation};

/// The functions whose first bytes are read, each defined by `probes/cet_endbr.c` for
/// this purpose. One list for every artifact, as [`super::WATCHED_SYMBOLS`] is, so the
/// fact has the same shape whichever probe built the object; no other probe defines a
/// function of these names.
pub const ENTRY_FUNCTIONS: [&str; 3] = [
    "chard_ibt_target_a",
    "chard_ibt_target_b",
    "chard_ibt_target_c",
];

/// How many bytes are read at each function's address: the length of `endbr64` and
/// `endbr32`.
pub const ENTRY_BYTES: u64 = 4;

/// `STT_FUNC`, the low nibble of `st_info`.
const STT_FUNC: u8 = 2;
/// The first reserved section index (`SHN_LORESERVE`); `SHN_ABS`, `SHN_COMMON` and
/// `SHN_XINDEX` sit at or above it, and none names a section of the file.
const SHN_LORESERVE: u16 = 0xff00;

/// One symbol-table entry that defines a listed function.
struct Definition {
    value: u64,
    size: u64,
    shndx: u16,
}

/// Lowercase hex, two digits per byte, in order.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0xf] {
            // A nibble is below 16, so `from_digit` always yields a digit.
            s.extend(char::from_digit(u32::from(nibble), 16));
        }
    }
    s
}

impl Elf<'_> {
    /// `function_entries`, as the module documentation describes it.
    pub(super) fn function_entries(&self, trunc: &mut Vec<Truncation>) -> Vec<String> {
        let (definitions, stopped) = self.entry_definitions();
        let mut out = Vec::new();
        for name in ENTRY_FUNCTIONS {
            let found: Vec<&Definition> = definitions
                .iter()
                .filter(|(n, _)| *n == name)
                .map(|(_, d)| d)
                .collect();
            let definition = match found.as_slice() {
                [] => {
                    // Absent is not recorded; absent behind an entry this walk alone could
                    // not read is (see `entry_definitions`).
                    if let Some(at) = &stopped {
                        trunc.push(Truncation::unread(
                            ElfTable::FunctionEntries,
                            format!("{name}: not found before the symbol walk stopped ({at})"),
                        ));
                    }
                    continue;
                }
                [one] => *one,
                more => {
                    trunc.push(Truncation::unread(
                        ElfTable::FunctionEntries,
                        format!(
                            "{name}: {} defined functions carry the name, so which one is \
                             the probe's cannot be told and none was read",
                            more.len()
                        ),
                    ));
                    continue;
                }
            };
            if let Some(bytes) = self.entry_bytes(name, definition, trunc) {
                out.push(format!("{name}={}", hex(bytes)));
            }
        }
        out
    }

    /// Every defined `STT_FUNC` in `.symtab` that [`ENTRY_FUNCTIONS`] names, and the entry
    /// this walk could not read, if it met one.
    ///
    /// A walk of its own rather than `symbols`', which keeps a name and a definedness and
    /// nothing else. Where it stops for a reason `symbols` meets over the same bounds (a
    /// table below one entry, a string table that cannot be held, a name offset past its
    /// table) the stop is recorded there, against [`ElfTable::Symbols`], which the check
    /// that reads this fact declares, and is not recorded twice. Only this walk reads an
    /// entry's `st_info`, `st_value` and `st_size`, so an entry whose bytes end before
    /// those is a stop it alone meets, and that one is returned for the caller to record.
    fn entry_definitions(&self) -> (Vec<(&'static str, Definition)>, Option<String>) {
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
                let base = sh.sh_offset.saturating_add(i.saturating_mul(step));
                let (name_off, info, shndx, value, size) = match self.entry_symbol(base) {
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
                let name = self.cur.cstr_at(strtab.sh_offset, name_off, strtab.sh_size);
                if let Some(known) = ENTRY_FUNCTIONS.iter().find(|f| **f == name) {
                    out.push((*known, Definition { value, size, shndx }));
                }
            }
        }
        (out, None)
    }

    /// One symbol-table entry at `base`: `st_name`, `st_info`, `st_shndx`, `st_value` and
    /// `st_size`, in either width.
    fn entry_symbol(&self, base: u64) -> super::Read<(u32, u8, u16, u64, u64)> {
        let (info_at, shndx_at, value_at, size_at) = if self.elf64 {
            (4, 6, 8, 16)
        } else {
            (12, 14, 4, 8)
        };
        let name_off = self.cur.u32_at(base)?;
        let at = base.saturating_add(info_at);
        // `slice` returned exactly one byte or an error; the `else` is the error's own
        // shape for a window that did not hold the byte, never a substituted value.
        let &[info] = self.cur.slice(at, 1)? else {
            return Err(super::ReadError::OutOfBounds {
                start: usize::try_from(at).unwrap_or(usize::MAX),
                count: 1,
            });
        };
        let shndx = self.cur.u16_at(base.saturating_add(shndx_at))?;
        let value = self
            .cur
            .addr_at(base.saturating_add(value_at), self.elf64)?;
        let size = self.cur.addr_at(base.saturating_add(size_at), self.elf64)?;
        Ok((name_off, info, shndx, value, size))
    }

    /// The first [`ENTRY_BYTES`] bytes of one definition, fewer where `st_size` is
    /// smaller, or `None` with the reason recorded.
    fn entry_bytes(
        &self,
        name: &str,
        def: &Definition,
        trunc: &mut Vec<Truncation>,
    ) -> Option<&[u8]> {
        let mut unread = |why: String| -> Option<&[u8]> {
            trunc.push(Truncation::unread(
                ElfTable::FunctionEntries,
                format!("{name}: {why}"),
            ));
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
        let Some(section) = self.shdrs.get(usize::from(def.shndx)) else {
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
        let len = def.size.min(ENTRY_BYTES);
        let end = start.and_then(|s| s.checked_add(len));
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
        match self.cur.slice(section.sh_offset.saturating_add(start), len) {
            Ok(bytes) => Some(bytes),
            Err(why) => unread(format!("its bytes lie past the end of the file ({why})")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_spelt_as_lowercase_hex_in_order() {
        assert_eq!(hex(&[0xf3, 0x0f, 0x1e, 0xfa]), "f30f1efa");
        assert_eq!(hex(&[0xc3]), "c3");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn every_listed_function_is_an_identifier_listed_once() {
        for (i, name) in ENTRY_FUNCTIONS.iter().enumerate() {
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{name} would be ambiguous in the fact's spelling"
            );
            assert!(
                ENTRY_FUNCTIONS.iter().skip(i + 1).all(|n| n != name),
                "{name} is listed twice"
            );
        }
    }
}
