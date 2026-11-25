// SPDX-License-Identifier: BSD-3-Clause
//! The ELF reader over arbitrary bytes: `Elf::parse` and `facts` never panic, whatever the
//! input declares. A malformed header is an `Err` that formats, and a table cut short is a
//! recorded truncation, never an index out of bounds or an overflowing offset. The facts a
//! parse yields survive the JSON round trip a report puts them through unchanged, so what
//! the store publishes is what the reader read.

#![no_main]

use std::collections::BTreeMap;

use chard::elf::code::{CODE_PATTERNS, MATCHES_KEPT, SCANS};
use chard::elf::{Elf, ElfFacts, is_stride_record};
use libfuzzer_sys::fuzz_target;

/// The `e_machine` a published machine name stands for, as far as the code reader's
/// patterns need it; 0 for any other, which no pattern carries.
fn facts_machine(facts: &ElfFacts) -> u16 {
    match facts.machine.as_str() {
        "x86_64" => 62,
        "aarch64" => 183,
        _ => 0,
    }
}

/// The code reader's oracle, over one parse's facts.
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
)]
fn code_lists_agree(facts: &ElfFacts) {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &facts.code_scanned {
        let (key, count) = entry
            .split_once('=')
            .expect("a scanned entry carries a count");
        let (function, pattern) = key.split_once(':').expect("function:pattern");
        let scan = SCANS
            .iter()
            .find(|s| s.function == function)
            .unwrap_or_else(|| panic!("{entry}: unlisted function"));
        assert!(
            scan.patterns.contains(&pattern),
            "{entry}: a pattern the function's scan does not list"
        );
        let machine = CODE_PATTERNS
            .iter()
            .find(|p| p.name == pattern)
            .map_or_else(|| panic!("{entry}: unknown pattern"), |p| p.machine);
        assert_eq!(
            machine,
            facts_machine(facts),
            "{entry}: another machine's pattern"
        );
        let count: usize = count.parse().expect("a count is a number");
        assert!(
            counts.insert(key, count).is_none(),
            "{entry}: searched twice"
        );
    }
    let mut kept: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for entry in &facts.code_matches {
        let (key, offset) = entry.split_once('@').expect("a match carries an offset");
        assert!(
            counts.contains_key(key),
            "{entry}: matched where nothing was searched"
        );
        assert!(offset.starts_with("0x"), "{entry}: offset in hex");
        kept.entry(key).or_default().push(offset);
    }
    for (key, count) in &counts {
        let offsets = kept.get(key).map_or(&[][..], Vec::as_slice);
        assert_eq!(
            offsets.len(),
            (*count).min(MATCHES_KEPT),
            "{key}: kept offsets"
        );
        let mut distinct = offsets.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), offsets.len(), "{key}: an offset twice");
    }
}

/// The header fields the rewrite needs, read as the ELF header gives them: class, byte
/// order, the section-header table's offset, entry size and count. `None` where the
/// identification is not one the reader parses or the count escapes to `shdr[0]`.
fn section_table(data: &[u8]) -> Option<(bool, bool, usize, usize, usize)> {
    let (elf64, little) = match (data.get(4)?, data.get(5)?) {
        (1, d @ (1 | 2)) => (false, *d == 1),
        (2, d @ (1 | 2)) => (true, *d == 1),
        _ => return None,
    };
    let word = |at: usize, n: usize| -> Option<u64> {
        let bytes = data.get(at..at.checked_add(n)?)?;
        let mut v = 0u64;
        for (i, b) in bytes.iter().enumerate() {
            let shift = if little { i } else { n - 1 - i };
            v |= u64::from(*b) << (8 * shift);
        }
        Some(v)
    };
    let (shoff, shent, shnum) = if elf64 {
        (word(40, 8)?, word(58, 2)?, word(60, 2)?)
    } else {
        (word(32, 4)?, word(46, 2)?, word(48, 2)?)
    };
    if shnum == 0 {
        return None;
    }
    Some((
        elf64,
        little,
        usize::try_from(shoff).ok()?,
        usize::try_from(shent).ok()?,
        usize::try_from(shnum).ok()?,
    ))
}

/// `data` with every `SHT_SYMTAB`, `SHT_DYNSYM`, `SHT_RELA` and `SHT_REL` header's
/// `sh_entsize` set to its record size, or `None` where nothing moved or a rewritten field
/// lies inside a section's or a segment's file bytes (or the ELF header).
fn entsize_rewritten(data: &[u8]) -> Option<Vec<u8>> {
    let (elf64, little, shoff, shent, shnum) = section_table(data)?;
    let get = |at: usize, n: usize| -> Option<u64> {
        let bytes = data.get(at..at.checked_add(n)?)?;
        let mut v = 0u64;
        for (i, b) in bytes.iter().enumerate() {
            let shift = if little { i } else { n - 1 - i };
            v |= u64::from(*b) << (8 * shift);
        }
        Some(v)
    };
    let w = if elf64 { 8 } else { 4 };
    // (type, offset, size, entsize) field offsets within one header.
    let (type_at, off_at, size_at, ent_at) = if elf64 {
        (4, 24, 32, 56)
    } else {
        (4, 16, 20, 36)
    };
    // Byte ranges a rewrite must not touch, each with the section header it belongs to where
    // it is one: the ELF header, the program-header table, every segment's and section's
    // file bytes, and every section header but the one whose field is rewritten.
    let mut occupied: Vec<(u64, u64, Option<usize>)> = vec![(0, if elf64 { 64 } else { 52 }, None)];
    let mut fields = Vec::new();
    for i in 0..shnum {
        let h = shoff.checked_add(i.checked_mul(shent)?)?;
        let start = u64::try_from(h).ok()?;
        occupied.push((
            start,
            start.saturating_add(u64::try_from(shent).ok()?),
            Some(i),
        ));
        let kind = get(h.saturating_add(type_at), 4)?;
        let (off, size) = (
            get(h.saturating_add(off_at), w)?,
            get(h.saturating_add(size_at), w)?,
        );
        if kind != 8 {
            // SHT_NOBITS holds no file bytes.
            occupied.push((off, off.saturating_add(size), None));
        }
        #[expect(
            clippy::match_same_arms,
            reason = "one arm per section type and class, as the ELF specification tabulates the record sizes"
        )]
        let record = match (kind, elf64) {
            (2 | 11, true) => 24,
            (2 | 11, false) => 16,
            (4, true) => 24,
            (4, false) => 12,
            (9, true) => 16,
            (9, false) => 8,
            _ => continue,
        };
        if get(h.saturating_add(ent_at), w)? != record {
            fields.push((i, h.saturating_add(ent_at), record));
        }
    }
    let (phoff, phent, phnum) = if elf64 {
        (get(32, 8)?, get(54, 2)?, get(56, 2)?)
    } else {
        (get(28, 4)?, get(42, 2)?, get(44, 2)?)
    };
    occupied.push((
        phoff,
        phoff.saturating_add(phnum.saturating_mul(phent)),
        None,
    ));
    for i in 0..phnum {
        let h = usize::try_from(phoff.checked_add(i.checked_mul(phent)?)?).ok()?;
        let (off, filesz) = if elf64 {
            (get(h.saturating_add(8), 8)?, get(h.saturating_add(32), 8)?)
        } else {
            (get(h.saturating_add(4), 4)?, get(h.saturating_add(16), 4)?)
        };
        occupied.push((off, off.saturating_add(filesz), None));
    }
    if fields.is_empty() {
        return None;
    }
    let mut out = data.to_vec();
    for (header, at, record) in fields {
        let (start, end) = (at as u64, at as u64 + w as u64);
        if occupied
            .iter()
            .any(|(s, e, owner)| *owner != Some(header) && start < *e && *s < end)
        {
            return None;
        }
        #[expect(
            clippy::indexing_slicing,
            clippy::cast_possible_truncation,
            reason = "each field's w bytes were read above through get, so they lie inside out; the cast keeps the byte the shift brought down"
        )]
        for i in 0..w {
            let shift = if little { i } else { w - 1 - i };
            out[at + i] = (record >> (8 * shift)) as u8;
        }
    }
    Some(out)
}

/// The facts with the records naming a declared entry size or tag taken out.
fn without_stride_records(mut facts: ElfFacts) -> ElfFacts {
    facts.truncations.retain(|t| !is_stride_record(t));
    facts
}

fuzz_target!(|data: &[u8]| {
    #![expect(
        clippy::expect_used,
        reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
    )]
    match Elf::parse(data) {
        Err(e) => {
            let _: String = e.to_string();
        }
        Ok(elf) => {
            let facts = elf.facts();
            code_lists_agree(&facts);
            let json = serde_json::to_string(&facts).expect("ElfFacts serializes");
            let back: ElfFacts = serde_json::from_str(&json).expect("ElfFacts reads back");
            assert_eq!(back, facts, "ElfFacts changed across a JSON round trip");
            // Several walks read one section, and the facts keep its stride record once.
            let mut strides = std::collections::BTreeSet::new();
            for t in facts.truncations.iter().filter(|t| is_stride_record(t)) {
                assert!(
                    strides.insert((t.table, &t.detail)),
                    "a stride record twice: {t:?}"
                );
            }
            if let Some(rewritten) = entsize_rewritten(data) {
                let honest = Elf::parse(&rewritten)
                    .expect("an sh_entsize rewrite outside every table parses as the original did")
                    .facts();
                // Both sides lose their stride records: a `DT_RELAENT` both declare is
                // recorded on both, and only the rewritten headers' records differ.
                assert_eq!(
                    without_stride_records(facts),
                    without_stride_records(honest),
                    "a declared sh_entsize chose what was read"
                );
            }
        }
    }
});
