// SPDX-License-Identifier: BSD-3-Clause
//! The readers of what a compiler driver and a linker print about themselves, over arbitrary
//! text: the two `-###` listing readers (`compile_inputs::parse`, the compile commands' header
//! directories, macros, removals, targets and kin, and `link_inputs::parse`, the link's
//! inputs), the linker-selection reader of the same listing (`toolchain::link_line`), the
//! `-v` reader (`toolchain::parse_verbose`, the configure line and the configuration and specs
//! files), the `--version` banner and `.comment` readers (`toolchain::linker_kind`,
//! `toolchain::linker_line`), the `-fhardened` dump's diagnostic (`toolchain::
//! fhardened_diagnostic`) and the `-dumpmachine` reader (`toolchain::arch_of_triple`). The
//! text is the toolchain's (THREAT_MODEL.md, "The operator chose the toolchain"), so a
//! failure here is a defect in chard's reader and not an attack; but a listing reader that
//! reads a word from a line that is not a command, or from one command into another, compares
//! the measured build's inputs with inputs neither build had.
//!
//! The input is the text: the bytes decoded as UTF-8 lossily, as chard reads a driver's
//! output. Every reader reads all of it. Held for every input, without a model of the
//! spellings:
//!
//! - each reader returns without a panic, and returns the same reading twice;
//! - `compile_inputs::parse` reads each line alone: its reading of the text is the readings of
//!   the text's lines, each parsed alone, joined field by field in order, and it refuses the
//!   text with the first line's refusal that is not "no compile command", or with "no compile
//!   command" where every line refuses so. A line that is not a command (`link_inputs`' rule:
//!   one space, then a word) is refused alone as holding no compile command. What it reads
//!   is in its own vocabulary: every removal is a `REMOVALS` word, every header option a
//!   `HEADER_OPTIONS` word, every macro a `-D` or `-U` operation;
//! - `link_inputs::parse` reads command lines alone: the text and its command lines alone
//!   read the same, so driver chatter between them is never an input;
//! - `link_line` reads the last line that begins with a space and a quote or a slash, and no
//!   other: the text and that line alone read the same. What it hands `collect2` is
//!   `-fuse-ld=` and `--ld-path=` words, and the program a line runs is a path, never a bare
//!   name and never `collect2`;
//! - `parse_verbose` reads line by line: over two texts joined by a line feed its configure
//!   line is the second's where it has one and the first's otherwise, and its files are the
//!   first's then the second's; every file it names is non-empty and trimmed, and the
//!   configure line is trimmed;
//! - `linker_kind` names one of `gold`, `lld`, `mold`, `bfd` and `unknown`, the same for an
//!   ASCII banner in upper case; `linker_line`, asked of each line, names `lld` or `mold`
//!   with a version that is a word of that line, holding no white space;
//! - `fhardened_diagnostic` names a line exactly when one carries `-fhardened` or
//!   `-Whardened`, and the line it names is the first such, trimmed;
//! - `arch_of_triple` reads a triple's first component alone (the triple and the component
//!   alone read the same), and what it returns reads to itself.
//!
//! The seeds under `seeds/driver_text/` are the listings, banners and lines of the unit
//! tests beside each reader, which name no host.

#![no_main]

use chard::compile_inputs::{self, CompileInputs, HEADER_OPTIONS, REMOVALS};
use chard::link_inputs;
use chard::toolchain::{
    LinkLine, arch_of_triple, fhardened_diagnostic, link_line, linker_kind, linker_line,
    parse_verbose,
};
use libfuzzer_sys::fuzz_target;

const NO_COMPILE: &str = "the listing held no compile command";
const KINDS: [&str; 5] = ["gold", "lld", "mold", "bfd", "unknown"];

/// `link_inputs`' rule for a command line, restated: one space, then a character that is
/// not white space.
fn is_command(line: &str) -> bool {
    line.strip_prefix(' ')
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| !c.is_whitespace())
}

fn empty() -> CompileInputs {
    CompileInputs {
        programs: Vec::new(),
        headers: Vec::new(),
        macros: Vec::new(),
        removals: Vec::new(),
        targets: Vec::new(),
        sanitizers: Vec::new(),
        lto: Vec::new(),
        relocation: Vec::new(),
        exception_models: Vec::new(),
    }
}

fn append(into: &mut CompileInputs, from: CompileInputs) {
    into.programs.extend(from.programs);
    into.headers.extend(from.headers);
    into.macros.extend(from.macros);
    into.removals.extend(from.removals);
    into.targets.extend(from.targets);
    into.sanitizers.extend(from.sanitizers);
    into.lto.extend(from.lto);
    into.relocation.extend(from.relocation);
    into.exception_models.extend(from.exception_models);
}

fn check_compile_inputs(text: &str) {
    let read = compile_inputs::parse(text);
    assert_eq!(
        compile_inputs::parse(text),
        read,
        "a second reading differs"
    );
    let mut joined = empty();
    let mut refusal = None;
    for line in text.lines() {
        let alone = compile_inputs::parse(line);
        if !is_command(line) {
            assert_eq!(
                alone.as_ref().map(|_| ()),
                Err(&NO_COMPILE.to_owned()),
                "{line:?} is no command and read as {alone:?}"
            );
        }
        match alone {
            Ok(inputs) => append(&mut joined, inputs),
            Err(why) if why == NO_COMPILE => {}
            Err(why) => {
                refusal = Some(why);
                break;
            }
        }
    }
    let expected = match refusal {
        Some(why) => Err(why),
        None if joined.programs.is_empty() => Err(NO_COMPILE.to_owned()),
        None => Ok(joined),
    };
    assert_eq!(
        read, expected,
        "the listing is not read as its lines, each alone"
    );
    if let Ok(inputs) = &read {
        for word in &inputs.removals {
            assert!(REMOVALS.contains(&word.as_str()), "the removal {word:?}");
        }
        for (option, _) in &inputs.headers {
            assert!(
                HEADER_OPTIONS.contains(&option.as_str()),
                "the header option {option:?}"
            );
        }
        for word in &inputs.macros {
            assert!(
                word.starts_with("-D") || word.starts_with("-U"),
                "the macro operation {word:?}"
            );
        }
    }
}

fn check_link_inputs(text: &str) {
    let read = link_inputs::parse(text);
    assert_eq!(link_inputs::parse(text), read, "a second reading differs");
    let commands: Vec<&str> = text.lines().filter(|l| is_command(l)).collect();
    // A line keeping a carriage return would lose it to the line feed joining it.
    if commands.iter().any(|l| l.ends_with('\r')) {
        return;
    }
    assert_eq!(
        link_inputs::parse(&commands.join("\n")),
        read,
        "a line that is no command changed what the link reads"
    );
}

fn check_link_line(text: &str) {
    let read = link_line(text);
    assert_eq!(link_line(text), read, "a second reading differs");
    let last = text
        .lines()
        .filter(|l| l.starts_with(" \"") || l.starts_with(" /"))
        .next_back();
    assert_eq!(
        last.and_then(link_line),
        read,
        "a line other than the last link line changed the reading"
    );
    match &read {
        Some(LinkLine::Collect2(flags)) => {
            for flag in flags {
                assert!(
                    flag.starts_with("-fuse-ld=") || flag.starts_with("--ld-path="),
                    "collect2 is handed {flag:?}"
                );
            }
        }
        Some(LinkLine::Runs(program)) => {
            assert!(
                program.components().count() > 1,
                "the line runs {program:?}"
            );
            assert_ne!(
                program.file_name().and_then(|n| n.to_str()),
                Some("collect2"),
                "a collect2 line read as running collect2"
            );
        }
        None => {}
    }
}

fn check_verbose(text: &str) {
    let read = parse_verbose(text);
    assert_eq!(parse_verbose(text), read, "a second reading differs");
    let (configure, files) = &read;
    if let Some(line) = configure {
        assert_eq!(line.trim(), line, "the configure line is not trimmed");
    }
    for file in files {
        assert!(!file.is_empty(), "an empty configuration file");
        assert_eq!(file.trim(), file, "the file {file:?} is not trimmed");
    }
    // The first 16 splits at a line feed and the last.
    let splits: Vec<usize> = text.match_indices('\n').map(|(at, _)| at).collect();
    let last = splits.last().copied();
    for at in splits.into_iter().take(16).chain(last) {
        let (first, second) = (&text[..at], &text[at + 1..]);
        let (c1, f1) = parse_verbose(first);
        let (c2, f2) = parse_verbose(second);
        let joined = (c2.or(c1), [f1, f2].concat());
        assert_eq!(
            read, joined,
            "the text split at {at} reads otherwise than its halves"
        );
    }
}

fn check_linkers(text: &str) {
    let kind = linker_kind(text);
    assert_eq!(linker_kind(text), kind, "a second reading differs");
    assert!(KINDS.contains(&kind), "linker_kind named {kind:?}");
    if text.is_ascii() {
        assert_eq!(
            linker_kind(&text.to_ascii_uppercase()),
            kind,
            "the banner in upper case names another linker"
        );
    }
    for line in text.lines() {
        let read = linker_line(line);
        assert_eq!(linker_line(line), read, "a second reading differs");
        if let Some((kind, version)) = read {
            assert!(
                ["lld", "mold"].contains(&kind),
                "linker_line named {kind:?}"
            );
            assert!(!version.is_empty(), "an empty version from {line:?}");
            assert!(
                line.split_whitespace().any(|w| w == version),
                "the version {version:?} is not a word of {line:?}"
            );
        }
    }
}

fn check_fhardened(text: &str) {
    let read = fhardened_diagnostic(text);
    assert_eq!(fhardened_diagnostic(text), read, "a second reading differs");
    let first = text
        .lines()
        .find(|l| l.contains("-fhardened") || l.contains("-Whardened"))
        .map(|l| l.trim().to_owned());
    assert_eq!(
        read, first,
        "the diagnostic is not the first line naming the option"
    );
}

fn check_triple(text: &str) {
    for triple in text.lines().take(8) {
        let read = arch_of_triple(triple);
        assert_eq!(arch_of_triple(triple), read, "a second reading differs");
        let first = triple.split('-').next().unwrap_or("");
        assert_eq!(
            arch_of_triple(first),
            read,
            "{triple:?} reads otherwise than its first component"
        );
        if let Some(arch) = &read {
            assert_eq!(
                arch_of_triple(arch).as_ref(),
                Some(arch),
                "{arch:?} does not read to itself"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    check_compile_inputs(&text);
    check_link_inputs(&text);
    check_link_line(&text);
    check_verbose(&text);
    check_linkers(&text);
    check_fhardened(&text);
    check_triple(&text);
});
