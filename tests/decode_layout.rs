// SPDX-License-Identifier: BSD-3-Clause

//! The layout `src/predicate/`, `src/decode/`, `src/elf.rs` and `src/elf/` keep, so that their source
//! can be read as decoder code alone.

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
use std::path::{Path, PathBuf};

use chard::digest::sha256_hex;
use chard::fingerprint::{NOT_DECODER_SOURCES, sources_canonical, test_module_gate};
use chard::probe::{CORPUS, Channel, DECODER_SOURCES, decoder_code, decoder_sources_sha256};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `src/<dir>/`, at any depth, sorted, with its path relative to
/// that directory and its text.
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
        "a decode, predicate or ELF source opens a block comment: {offenders:?}"
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
            "{name}: not exactly one test-gated attribute"
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
        "{name} has {} test-gated attributes; at most one is allowed",
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

/// Every `.rs` file under `src/`, at any depth, with its path from the manifest directory.
fn every_source_file() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = files_under("")
        .into_iter()
        .map(|(n, t)| (format!("src/{n}"), t))
        .collect();
    files.sort();
    files
}

#[test]
fn every_source_file_is_read_by_the_fingerprint_or_set_aside_with_a_reason() {
    let on_disk: Vec<String> = every_source_file().into_iter().map(|(p, _)| p).collect();
    let mut registered: Vec<String> = DECODER_SOURCES
        .iter()
        .map(|p| (*p).to_owned())
        .chain(NOT_DECODER_SOURCES.iter().map(|(p, _)| (*p).to_owned()))
        .collect();
    let listed = registered.len();
    registered.sort();
    registered.dedup();
    assert_eq!(
        registered.len(),
        listed,
        "a file is in both lists, or twice in one"
    );
    assert_eq!(
        registered, on_disk,
        "fingerprint::DECODER_SOURCES and NOT_DECODER_SOURCES against src/"
    );
    // Every file the fingerprint reads besides the detectors, named here rather than trusted
    // to the register's prose: each settles, gates, withholds or derives what a report says
    // (`main.rs` orders the withholdings that run after every probe: the target, twin and
    // no-twin rules and the fortify ratchet), so a reason that sets one aside cannot be
    // true.
    let deciding = [
        "src/compile.rs",
        "src/compile_inputs.rs",
        "src/composite.rs",
        "src/env.rs",
        "src/guide.rs",
        "src/link_inputs.rs",
        "src/listings.rs",
        "src/main.rs",
        "src/measure.rs",
        "src/mechanism.rs",
        "src/overridden.rs",
        "src/probe.rs",
        "src/report.rs",
        "src/report/digest.rs",
        "src/run.rs",
        "src/structured.rs",
        "src/toolchain.rs",
    ];
    for path in deciding {
        assert!(
            DECODER_SOURCES.contains(&path),
            "{path} settles, gates or withholds a verdict and the fingerprint does not read it"
        );
    }
    let always_read = predicate_files()
        .into_iter()
        .map(|(n, _)| format!("src/predicate/{n}"))
        .chain(
            decode_files()
                .into_iter()
                .filter(|(n, _)| !n.ends_with("_tests.rs"))
                .map(|(n, _)| format!("src/decode/{n}")),
        )
        .chain(std::iter::once("src/elf.rs".to_owned()))
        .chain(elf_files().into_iter().map(|(n, _)| format!("src/elf/{n}")));
    let always_read: Vec<String> = always_read.collect();
    let named: BTreeSet<&str> = deciding
        .iter()
        .copied()
        .chain(always_read.iter().map(String::as_str))
        .collect();
    let read: BTreeSet<&str> = DECODER_SOURCES.iter().copied().collect();
    assert_eq!(
        named, read,
        "the fingerprint reads other files than the deciding and detector files named here"
    );
    let mut checked = 0usize;
    for path in always_read {
        assert!(
            DECODER_SOURCES.contains(&path.as_str()),
            "{path} is detector code and the fingerprint does not read it"
        );
        checked += 1;
    }
    assert!(
        checked >= 11,
        "only {checked} detector files were checked, so the walk is not reaching them"
    );
    eprintln!(
        "{} files under src/: {} read, {} set aside",
        on_disk.len(),
        DECODER_SOURCES.len(),
        NOT_DECODER_SOURCES.len()
    );
    the_stamped_digest_is_the_trees_and_the_cut_skips_only_the_test_module();
}

/// The digest the binary was built with is the digest of the files as they are, each read
/// as code alone, and each read file's cut skips no shipped code: where a gate opens a test
/// module, the module runs to the end of the file. Run by the register's test, after it has
/// held the list to the tree.
fn the_stamped_digest_is_the_trees_and_the_cut_skips_only_the_test_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut texts = Vec::new();
    for path in DECODER_SOURCES {
        let text = std::fs::read_to_string(manifest.join(path))
            .unwrap_or_else(|e| panic!("reading {path}: {e}"));
        let code = decoder_code(&text);
        assert!(!code.is_empty(), "{path} read as no code");
        for line in code.lines() {
            assert!(
                !line.trim_start().starts_with("//") && !line.trim().is_empty(),
                "{path}: a comment or blank line survived the strip: {line:?}"
            );
        }
        if let Some(gate) = test_module_gate(&text) {
            let lines: Vec<&str> = text.lines().collect();
            let rest: Vec<(usize, &str)> = lines
                .iter()
                .copied()
                .enumerate()
                .skip(gate + 1)
                .filter(|(_, l)| !l.trim().is_empty() && !l.starts_with("#["))
                .collect();
            let (open, declaration) = rest.first().copied().expect("the gate declares a module");
            let last = rest.last().map(|(i, _)| *i).expect("a non-empty file");
            let end = if declaration.ends_with(';') {
                open
            } else {
                rest.iter()
                    .skip(1)
                    .find(|(_, l)| l.starts_with('}'))
                    .map_or_else(|| panic!("the test module in {path} closes"), |(i, _)| *i)
            };
            assert_eq!(
                end,
                last,
                "{path}: code follows the test module at line {}, and the cut would skip it",
                end + 2
            );
        }
        texts.push((*path, text));
    }
    let canonical = sources_canonical(texts.iter().map(|(p, t)| (*p, t.as_str())));
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        decoder_sources_sha256(),
        "the binary's stamped digest is not the tree's: build.rs read other files"
    );
    assert_eq!(texts.len(), DECODER_SOURCES.len());
}

/// `(channel, decoder)` for every `Check { .. }` literal in `src/probe.rs`, in order: the
/// `Decoder` variant, and the predicate function a predicate variant names or the `detect`
/// function a code variant names on a later line.
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
        "detectors not defined once under src/decode/, or defined in src/probe.rs: {misplaced:?}"
    );
}
