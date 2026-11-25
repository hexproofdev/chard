// SPDX-License-Identifier: BSD-3-Clause

//! What `run.decoders_sha256` is taken over: the register of this crate's source files, each
//! either read as code that decides what a report says about a check or set aside with the
//! reason it decides nothing there, and the strip that reads a file as its code alone.

/// The files whose code decides what a report says about a check, by path from the
/// manifest directory.
pub const DECODER_SOURCES: &[&str] = &[
    "src/predicate/mod.rs",
    "src/predicate/elf_static.rs",
    "src/predicate/macro_channel.rs",
    "src/decode/mod.rs",
    "src/decode/common.rs",
    "src/decode/diag.rs",
    "src/decode/runtime.rs",
    "src/elf.rs",
    "src/elf/code.rs",
    "src/elf/entry.rs",
    "src/elf/reloc_names.rs",
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

/// The files the fingerprint does not read, each with the reason nothing in it decides
/// what a report `measure` writes says about a check.
pub const NOT_DECODER_SOURCES: &[(&str, &str)] = &[
    (
        "src/dataset.rs",
        "reads published reports to decide whether they may be compared",
    ),
    (
        "src/decode/common_tests.rs",
        "unit tests of src/decode/common.rs, compiled under cfg(test) alone",
    ),
    (
        "src/decode/diag_tests.rs",
        "unit tests of src/decode/diag.rs, compiled under cfg(test) alone",
    ),
    (
        "src/decode/runtime_tests.rs",
        "unit tests of src/decode/runtime.rs, compiled under cfg(test) alone",
    ),
    (
        "src/detect.rs",
        "replays a published report against this binary's decoders and prints the replay",
    ),
    (
        "src/digest.rs",
        "the SHA-256 every key and this fingerprint are taken with",
    ),
    (
        "src/error.rs",
        "the error envelope and the exit status of a command that failed",
    ),
    (
        "src/fingerprint.rs",
        "this register and the strip it reads by",
    ),
    (
        "src/fixture.rs",
        "replays recorded fixture evidence through the detectors for the test suite",
    ),
    (
        "src/lib.rs",
        "declares the modules; a module it gains is a file this register must classify",
    ),
    (
        "src/matrix.rs",
        "renders published reports as a cross-tabulation",
    ),
    (
        "src/table.rs",
        "renders published reports as a table; it measures nothing",
    ),
];

/// Whether the line at `at` opens the trailing test module: a top-level `#[cfg(test)]`
/// whose next line that is neither blank nor another attribute declares a module.
fn opens_test_module(lines: &[&str], at: usize) -> bool {
    if lines.get(at) != Some(&"#[cfg(test)]") {
        return false;
    }
    lines
        .iter()
        .skip(at.saturating_add(1))
        .find(|l| !l.trim().is_empty() && !l.starts_with("#["))
        .is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub(crate) mod "))
}

/// The index of the line [`decoder_code`] cuts `text` at: the first top-level `#[cfg(test)]`
/// that opens a module, or `None` where no line does and the whole file is read.
#[must_use]
pub fn test_module_gate(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    (0..lines.len()).find(|&at| opens_test_module(&lines, at))
}

/// A source file as the fingerprint reads it: the text before the top-level `#[cfg(test)]`
/// that opens its trailing test module, less every line whose first non-blank characters
/// are `//` and every blank line.
#[must_use]
pub fn decoder_code(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let end = test_module_gate(text).unwrap_or(lines.len());
    let mut code = String::new();
    for line in lines.iter().take(end) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        code.push_str(line);
        code.push('\n');
    }
    code
}

/// Append `part` to `canonical` framed by its length, so no two sequences of parts share a
/// canonical form.
pub fn frame(canonical: &mut String, part: &str) {
    canonical.push_str(&part.len().to_string());
    canonical.push(':');
    canonical.push_str(part);
    canonical.push('\n');
}

/// The canonical form the source digest is taken over: each `(path, text)` in the order
/// given, the path and then [`decoder_code`] of the text, each framed by its length.
#[must_use]
pub fn sources_canonical<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut canonical = String::new();
    for (path, text) in sources {
        frame(&mut canonical, path);
        frame(&mut canonical, &decoder_code(text));
    }
    canonical
}
