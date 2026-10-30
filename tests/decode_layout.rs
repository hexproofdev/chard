// SPDX-License-Identifier: BSD-3-Clause

//! The layout `src/predicate/`, `src/decode/`, `src/elf.rs` and `src/elf/` keep, so that their source
//! can be read as decoder code alone.
//!
//! `probe::decoders_sha256` is a fingerprint over that source, and it has to strip what is
//! not code; `probe::decoder_code` is the strip, and it is only as good as the layout it
//! assumes. Four properties make a line-based strip total:
//!
//! - No file opens a block comment. A line-comment strip leaves the interior of one in
//!   place, so a comment edit would move the fingerprint.
//! - A module's unit tests sit outside the text being read: in a sibling `*_tests.rs` file
//!   under `src/decode/`, and after the one top-level `#[cfg(test)]` in `src/elf.rs`, in
//!   any file under `src/elf/` and in any file under `src/predicate/` that carries tests.
//! - Every runtime and compiler-diag detector the corpus names is defined under
//!   `src/decode/`, so the directory holds the code those verdicts come from.
//! - `probe::DECODER_SOURCES`, the list the fingerprint reads, is every module file of the
//!   two directories, `src/elf.rs` and every file under `src/elf/`, so a file added there is
//!   read or fails here.
//!
//! A source scan, in the style of `tests/evidence_completeness.rs`, and a tripwire rather
//! than a proof: each assertion counts what it read against what it expected, so a scan
//! that stops matching fails instead of passing over nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chard::probe::{CORPUS, Channel, DECODER_SOURCES, decoder_code};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `src/<dir>/`, at any depth, sorted, with its path relative to
/// that directory and its text.
///
/// The walk is recursive so that a nested module, `src/decode/x/mod.rs` say, is read by
/// every tripwire here and fails the pinned module list rather than sitting unscanned.
fn files_under(dir: &str) -> Vec<(String, String)> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, String)>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("a readable entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("a UTF-8 file name")
                .to_owned();
            if path.is_dir() {
                walk(&path, &format!("{prefix}{name}/"), out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
                out.push((format!("{prefix}{name}"), text));
            }
        }
    }
    let mut files = Vec::new();
    walk(&src().join(dir), "", &mut files);
    files.sort();
    files
}

/// Every `.rs` file under `src/decode/`.
fn decode_files() -> Vec<(String, String)> {
    files_under("decode")
}

/// Every `.rs` file under `src/elf/`, the ELF reader's modules.
fn elf_files() -> Vec<(String, String)> {
    files_under("elf")
}

/// Every `.rs` file under `src/predicate/`.
fn predicate_files() -> Vec<(String, String)> {
    files_under("predicate")
}

/// Whether `line` is a `cfg` attribute whose predicate mentions `test`, at any indentation
/// and in any spelling: `#[cfg(test)]`, `#[cfg(any(test, ..))]`, `#[cfg_attr(test, ..)]`,
/// `#![cfg(test)]`.
///
/// A `cfg` attribute that does not close on its own line is refused outright, because its
/// predicate may name `test` on a later line this reading does not join.
fn is_test_gate(file: &str, line: &str) -> bool {
    let t = line.trim_start();
    if !(t.starts_with("#[cfg") || t.starts_with("#![cfg")) {
        return false;
    }
    assert!(
        t.contains(']'),
        "{file}: a cfg attribute spans lines, so its predicate cannot be read here: {line:?}"
    );
    t.contains("test")
}

/// The module files under `src/decode/`, which carry detector code and no tests.
fn module_files() -> Vec<(String, String)> {
    decode_files()
        .into_iter()
        .filter(|(name, _)| !name.ends_with("_tests.rs"))
        .collect()
}

#[test]
fn no_decode_or_elf_source_opens_a_block_comment() {
    let mut read = 0usize;
    let mut offenders = Vec::new();
    let elf = std::fs::read_to_string(src().join("elf.rs")).expect("reading src/elf.rs");
    for (name, text) in decode_files()
        .into_iter()
        .chain(
            predicate_files()
                .into_iter()
                .map(|(n, t)| (format!("../predicate/{n}"), t)),
        )
        .chain(std::iter::once(("../elf.rs".to_owned(), elf)))
        .chain(
            elf_files()
                .into_iter()
                .map(|(n, t)| (format!("../elf/{n}"), t)),
        )
    {
        read += 1;
        for (i, line) in text.lines().enumerate() {
            if line.contains("/*") {
                offenders.push(format!("{name}:{}", i + 1));
            }
        }
    }
    eprintln!("{read} files scanned for a block-comment opener");
    // mod.rs, three modules and three test files, the three predicate files, elf.rs,
    // elf/code.rs, elf/entry.rs and elf/reloc_names.rs.
    assert!(
        read >= 14,
        "only {read} files were read, so the scan is not reaching src/decode/"
    );
    assert!(
        offenders.is_empty(),
        "a block comment survives a line-comment strip, so its text would enter a \
         fingerprint over this source: {offenders:?}"
    );
}

#[test]
fn a_decode_module_file_holds_no_test_code_and_names_its_sibling() {
    let modules = module_files();
    let names: Vec<&str> = modules.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["common.rs", "diag.rs", "mod.rs", "runtime.rs"],
        "the module files under src/decode/ are not the ones this test was written for"
    );
    for (name, text) in &modules {
        assert!(
            !text.contains("#[test]"),
            "{name} carries a #[test]; unit tests belong in its sibling *_tests.rs file"
        );
        let lines: Vec<&str> = text.lines().collect();
        let gates: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| is_test_gate(name, l))
            .map(|(i, _)| i)
            .collect();
        if *name == "mod.rs" {
            assert!(
                gates.is_empty(),
                "mod.rs declares modules and holds no tests"
            );
            continue;
        }
        let stem = name.trim_end_matches(".rs");
        let expected = [
            "#[cfg(test)]".to_owned(),
            format!("#[path = \"{stem}_tests.rs\"]"),
            "mod tests;".to_owned(),
        ];
        assert_eq!(
            gates.len(),
            1,
            "{name}: one test-gated attribute, a #[cfg(test)] on the declaration of its \
             sibling test file"
        );
        let tail: Vec<&str> = lines
            .iter()
            .skip(gates[0])
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        assert_eq!(
            tail, expected,
            "{name}: the test gate is the file's last item and declares {stem}_tests.rs"
        );
        assert!(
            decode_files()
                .iter()
                .any(|(n, _)| *n == format!("{stem}_tests.rs")),
            "{name} declares {stem}_tests.rs and there is no such file"
        );
    }
}

/// `text` has at most one test-gated attribute, at any indentation; where it has one, the
/// gate is a top-level `#[cfg(test)]`, followed by the test module, which closes on the
/// file's last non-empty line. Returns whether a gate was found.
fn assert_one_trailing_test_module(name: &str, text: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    let gates: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| is_test_gate(name, l))
        .map(|(i, _)| i)
        .collect();
    assert!(
        gates.len() <= 1,
        "{name} has {} test-gated attributes at any indentation; the one allowed is the \
         top-level gate, and everything before it is read as decoder code",
        gates.len()
    );
    let Some(&gate) = gates.first() else {
        return false;
    };
    assert_eq!(
        lines[gate], "#[cfg(test)]",
        "{name}: the one test gate is a top-level #[cfg(test)]"
    );
    let rest: Vec<(usize, &str)> = lines
        .iter()
        .copied()
        .enumerate()
        .skip(gate + 1)
        .filter(|(_, l)| !l.trim().is_empty())
        .collect();
    assert_eq!(
        rest.first().map(|(_, l)| *l),
        Some("mod tests {"),
        "the gate in {name} is followed by the test module"
    );
    // The module's own closing brace is the first column-0 `}` after it opens, and it is
    // the last non-empty line of the file.
    let close = rest
        .iter()
        .skip(1)
        .find(|(_, l)| l.starts_with('}'))
        .map_or_else(|| panic!("the test module in {name} closes"), |(i, _)| *i);
    let last = rest.last().map(|(i, _)| *i).expect("a non-empty file");
    assert_eq!(
        close,
        last,
        "{name} carries code after its test module, at line {}",
        close + 2
    );
    true
}

#[test]
fn elf_rs_has_one_test_gate_and_only_the_test_module_follows_it() {
    let text = std::fs::read_to_string(src().join("elf.rs")).expect("reading src/elf.rs");
    assert!(
        assert_one_trailing_test_module("src/elf.rs", &text),
        "src/elf.rs has its test module behind a gate"
    );
}

/// The ELF reader's modules under `src/elf/` keep the layout `src/elf.rs` does: at most one
/// test gate, top-level, with only the test module after it.
#[test]
fn an_elf_module_ends_in_its_test_module_if_it_has_one() {
    let files = elf_files();
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["code.rs", "entry.rs", "reloc_names.rs"],
        "the files under src/elf/ are not the ones this test was written for"
    );
    let gated = files
        .iter()
        .filter(|(n, t)| assert_one_trailing_test_module(&format!("src/elf/{n}"), t))
        .count();
    assert_eq!(
        gated, 2,
        "src/elf/code.rs and src/elf/entry.rs carry their unit tests behind a gate"
    );
}

#[test]
fn a_predicate_file_ends_in_its_test_module_if_it_has_one() {
    let files = predicate_files();
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["elf_static.rs", "macro_channel.rs", "mod.rs"],
        "the files under src/predicate/ are not the ones this test was written for"
    );
    let gated = files
        .iter()
        .filter(|(name, text)| {
            assert_one_trailing_test_module(&format!("src/predicate/{name}"), text)
        })
        .count();
    eprintln!(
        "{} predicate files, {gated} with a trailing test module",
        files.len()
    );
    assert!(
        gated > 0,
        "src/predicate/mod.rs carries the evaluator's unit tests"
    );
}

/// The fingerprint reads every module file under `src/predicate/` and `src/decode/`, and
/// `src/elf.rs` and every file under `src/elf/`, and nothing else; and what it reads of each is that file's code alone.
#[test]
fn the_fingerprint_reads_every_decoder_module_file() {
    let mut on_disk: Vec<String> = predicate_files()
        .into_iter()
        .map(|(n, _)| format!("src/predicate/{n}"))
        .chain(
            decode_files()
                .into_iter()
                .filter(|(n, _)| !n.ends_with("_tests.rs"))
                .map(|(n, _)| format!("src/decode/{n}")),
        )
        .chain(std::iter::once("src/elf.rs".to_owned()))
        .chain(elf_files().into_iter().map(|(n, _)| format!("src/elf/{n}")))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = DECODER_SOURCES
        .iter()
        .map(|(p, _)| (*p).to_owned())
        .collect();
    listed.sort();
    assert_eq!(listed, on_disk, "probe::DECODER_SOURCES against the tree");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut read = 0usize;
    for (path, text) in DECODER_SOURCES {
        let disk = std::fs::read_to_string(manifest.join(path))
            .unwrap_or_else(|e| panic!("reading {path}: {e}"));
        assert_eq!(*text, disk, "{path}: the compiled copy is the file");
        let code = decoder_code(text);
        assert!(!code.is_empty(), "{path} read as no code");
        for line in code.lines() {
            assert!(
                !line.trim_start().starts_with("//") && !line.trim().is_empty(),
                "{path}: a comment or blank line survived the strip: {line:?}"
            );
            assert!(
                !is_test_gate(path, line),
                "{path}: the strip read past the test gate"
            );
        }
        read += 1;
    }
    assert_eq!(read, DECODER_SOURCES.len());
}

/// `(channel, decoder)` for every `Check { .. }` literal in `src/probe.rs`, in order: the
/// `Decoder` variant, and the predicate function a predicate variant names or the `detect`
/// function a code variant names on a later line.
///
/// Read up to the test module. A `decoder: Decoder::` line opens at most one pending code
/// variant, and its `detect:` line closes it, so a variant whose detector is not found
/// fails here rather than pairing with the next check's.
fn corpus_detectors() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(src().join("probe.rs")).expect("reading src/probe.rs");
    let mut pairs = Vec::new();
    let mut channel: Option<String> = None;
    for line in text.lines().take_while(|l| !l.starts_with("#[cfg(test)]")) {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("decoder: Decoder::") {
            assert!(
                channel.is_none(),
                "a decoder opened before the previous one named its detector: {line}"
            );
            let variant: String = rest
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect();
            let after = &rest[variant.len()..];
            if let Some(named) = after.strip_prefix('(') {
                pairs.push((variant, named.trim_end_matches("),").to_owned()));
            } else {
                channel = Some(variant);
            }
        } else if let Some(rest) = line.strip_prefix("detect: ")
            && let Some(ch) = channel.take()
        {
            let named = rest.trim_end_matches(',');
            let named = named
                .strip_prefix("detector!(")
                .and_then(|n| n.strip_suffix(')'))
                .unwrap_or_else(|| panic!("a code decoder not built by detector!: {line}"));
            pairs.push((ch, named.to_owned()));
        }
    }
    assert!(channel.is_none(), "a code decoder named no detector");
    pairs
}

#[test]
fn every_runtime_and_compiler_diag_detector_is_defined_under_decode() {
    let pairs = corpus_detectors();

    // The scan read every check in the corpus, channel by channel.
    let mut scanned: BTreeMap<String, usize> = BTreeMap::new();
    for (ch, _) in &pairs {
        *scanned.entry(ch.clone()).or_default() += 1;
    }
    let mut expected: BTreeMap<String, usize> = BTreeMap::new();
    for check in CORPUS.iter().flat_map(|p| p.checks.iter()) {
        *expected
            .entry(format!("{:?}", check.channel()))
            .or_default() += 1;
    }
    assert_eq!(
        scanned, expected,
        "the source scan of src/probe.rs found a different set of checks than CORPUS holds"
    );

    let modules = module_files();
    let probe = std::fs::read_to_string(src().join("probe.rs")).expect("reading src/probe.rs");
    let defines = |text: &str, name: &str| {
        text.lines().any(|l| {
            let l = l.trim_start();
            let l = l.strip_prefix("pub(crate) ").unwrap_or(l);
            let l = l.strip_prefix("pub ").unwrap_or(l);
            l.starts_with(&format!("fn {name}("))
        })
    };
    let decoded = [
        format!("{:?}", Channel::Runtime),
        format!("{:?}", Channel::CompilerDiag),
    ];
    let mut checked = 0usize;
    let mut misplaced = Vec::new();
    for (ch, name) in &pairs {
        if !decoded.contains(ch) {
            continue;
        }
        checked += 1;
        let homes: Vec<&str> = modules
            .iter()
            .filter(|(_, text)| defines(text, name))
            .map(|(n, _)| n.as_str())
            .collect();
        if homes.len() != 1 || defines(&probe, name) {
            misplaced.push(format!(
                "{ch} {name}: defined in {homes:?} under src/decode/"
            ));
        }
    }
    eprintln!("{checked} runtime and compiler-diag checks name a detector under src/decode/");
    assert_eq!(
        checked,
        expected.get("Runtime").copied().unwrap_or(0)
            + expected.get("CompilerDiag").copied().unwrap_or(0),
        "not every runtime and compiler-diag check was checked"
    );
    assert!(checked > 0, "no runtime or compiler-diag check was found");
    assert!(
        misplaced.is_empty(),
        "each runtime and compiler-diag detector is defined once under src/decode/ and \
         not in src/probe.rs: {misplaced:?}"
    );
}
