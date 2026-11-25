// SPDX-License-Identifier: BSD-3-Clause

//! Each command's exit statuses, held to the sites in the source that return them.

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

/// The statuses each function of `src/main.rs` that makes one can return, with the
/// commands it serves. `2` reaches every command through `main`'s `error::emit`.
const EXPECTED: &[(&str, &[&str], &[&str])] = &[
    ("main", &["every command"], &["EXIT_FAILURE"]),
    (
        "refuse_usage",
        &["every command"],
        &["EXIT_OK", "EXIT_FAILURE"],
    ),
    (
        "dispatch",
        &["table", "matrix", "digest", "probes", "elf"],
        &["EXIT_OK"],
    ),
    ("detect_command", &["detect"], &["EXIT_OK", "EXIT_GATE"]),
    (
        "measure_command",
        &["measure"],
        // `2` here is a refusal or a failure, and the operator's `--execution` contradicted by
        // what chard observed.
        &[
            "EXIT_OK",
            "EXIT_GATE",
            "EXIT_MACHINE_LIMIT",
            "EXIT_FAILURE",
            "EXIT_CONTRADICTION",
        ],
    ),
];

/// The status each emitter in `src/error.rs` returns.
const EMITTERS: &[(&str, &str)] = &[
    ("error::emit(", "EXIT_FAILURE"),
    ("error::emit_contradiction(", "EXIT_CONTRADICTION"),
    ("error::emit_declaration_contradicted(", "EXIT_FAILURE"),
];

/// The `error::EXIT_` constants `Closed::status` returns: a site `ExitCode::from(closed.status())`
/// can return any of them. It is how `measure_command` exits with the status its closing line
/// names, and reading it here keeps that site as checked as one that names its constant.
fn closed_statuses(source: &str) -> BTreeSet<String> {
    let body = source
        .split("impl Closed {")
        .nth(1)
        .and_then(|rest| rest.split("const fn status(&self) -> u8 {").nth(1))
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("src/main.rs has Closed::status");
    let named: BTreeSet<String> = exit_words(body);
    assert!(
        !named.is_empty(),
        "Closed::status names no error::EXIT_ constant"
    );
    named
}

/// The `EXIT_` words of `text`.
fn exit_words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.starts_with("EXIT_"))
        .map(str::to_owned)
        .collect()
}

/// The text from `open` (just past an opening parenthesis) to its matching close.
fn balanced(text: &str) -> &str {
    let mut depth = 1usize;
    for (i, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[..i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced parentheses after an exit site");
}

/// `line`'s function name, when it declares one: `fn`, at any indentation, after any of the
/// visibility and qualifier words a declaration in this crate can carry.
fn declared_fn(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    for word in [
        "pub(crate) ",
        "pub(super) ",
        "pub ",
        "const ",
        "async ",
        "unsafe ",
    ] {
        rest = rest.strip_prefix(word).unwrap_or(rest);
    }
    let rest = rest.strip_prefix("fn ")?;
    rest.split(['(', '<']).next()
}

/// The name of the last function declared before `offset`.
fn enclosing_fn(source: &str, offset: usize) -> String {
    source[..offset]
        .lines()
        .rev()
        .find_map(declared_fn)
        .expect("an exit site inside a function")
        .to_owned()
}

/// Every exit status `src/main.rs` makes, by the function it is made in.
fn statuses_by_fn(source: &str) -> BTreeMap<String, BTreeSet<String>> {
    // The unit tests at the end assert on statuses; they make none.
    let source = source
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("the file");
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut sites = 0usize;
    for (offset, _) in source.match_indices("ExitCode::from(") {
        let body = balanced(&source[offset + "ExitCode::from(".len()..]);
        let function = enclosing_fn(source, offset);
        let named = if body.trim() == "closed.status()" {
            closed_statuses(source)
        } else {
            // `measure_command` makes its code from the ending's status alone, so the status
            // it exits with is the one its closing line names; a site there naming a constant
            // could exit with another.
            assert_ne!(
                function, "measure_command",
                "measure_command makes an exit code from {body}, not from closed.status()"
            );
            exit_words(body)
        };
        assert!(
            !named.is_empty(),
            "an ExitCode::from site in {} names no error::EXIT_ constant: {body}",
            enclosing_fn(source, offset)
        );
        found
            .entry(enclosing_fn(source, offset))
            .or_default()
            .extend(named);
        sites += 1;
    }
    for (emitter, status) in EMITTERS {
        for (offset, _) in source.match_indices(emitter) {
            found
                .entry(enclosing_fn(source, offset))
                .or_default()
                .insert((*status).to_owned());
            sites += 1;
        }
    }
    // The frame: the sites read and where each was attributed, so an empty scan cannot pass as
    // agreement and a misattribution can be read off the test's output.
    eprintln!("{sites} exit sites in src/main.rs: {found:?}");
    assert!(sites >= 10, "only {sites} exit sites found in src/main.rs");
    found
}

#[test]
fn each_command_returns_the_statuses_the_contract_gives_it_and_no_other() {
    let source = include_str!("../src/main.rs");
    let found = statuses_by_fn(source);
    let expected: BTreeMap<String, BTreeSet<String>> = EXPECTED
        .iter()
        .map(|(f, _, statuses)| {
            (
                (*f).to_owned(),
                statuses.iter().map(|s| (*s).to_owned()).collect(),
            )
        })
        .collect();
    assert_eq!(
        found, expected,
        "the exit statuses src/main.rs makes, by function, are not the table's"
    );
}

#[test]
fn only_measure_exits_3_and_only_through_its_envelope() {
    let source = include_str!("../src/main.rs");
    let found = statuses_by_fn(source);
    let threes: Vec<&String> = found
        .iter()
        .filter(|(_, statuses)| statuses.contains("EXIT_CONTRADICTION"))
        .map(|(f, _)| f)
        .collect();
    assert_eq!(
        threes,
        ["measure_command"],
        "exit 3 is chard's own contradiction alone"
    );
    assert!(
        !source.contains("ExitCode::from(error::EXIT_CONTRADICTION)"),
        "measure's exit 3 goes through error::emit_contradiction, which writes the envelope"
    );
    let error = include_str!("../src/error.rs");
    let uses = error.matches("EXIT_CONTRADICTION").count();
    let emitter = error
        .split("pub fn emit_contradiction(")
        .nth(1)
        .expect("error.rs has emit_contradiction");
    let emitter = emitter.split("\n}\n").next().expect("its body");
    assert!(
        emitter.contains("ExitCode::from(EXIT_CONTRADICTION)"),
        "emit_contradiction returns exit 3"
    );
    // And it writes the envelope its arguments describe (whose shape and hint
    // `tests/schema_conformance.rs` holds through `contradiction_envelope`), which
    // `measure_command` hands the count and the file `report::publish` kept, as `measure`
    // returned them.
    let words = |text: &str| text.split_whitespace().collect::<String>();
    assert!(
        words(emitter).contains(&words(
            "write_rendered(&contradiction_envelope(contradictions, quarantine));"
        )),
        "emit_contradiction writes the envelope for its own arguments"
    );
    assert!(
        words(source).contains(&words(
            "report::Publication::Refused { contradictions, quarantine, cause: \
             report::RefusalCause::Defect, } => { return Ok(Closed::Contradicted { \
             contradictions, quarantine, });"
        )) && words(source).contains(&words(
            "Closed::Contradicted { contradictions, quarantine, } => \
             error::emit_contradiction(*contradictions, quarantine.as_deref()),"
        )) && words(source).contains(&words(
            "Self::Contradicted { .. } => error::EXIT_CONTRADICTION,"
        )),
        "measure hands emit_contradiction publish's count and quarantine, on a defect alone"
    );
    // The constant's definition, its doc's mentions and the emitter's return; nothing else.
    let outside_docs = error
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains("EXIT_CONTRADICTION"))
        .count();
    assert_eq!(
        outside_docs, 2,
        "EXIT_CONTRADICTION's code uses are not its definition and return ({uses} in all)"
    );
}

#[test]
fn the_statuses_are_the_numbers_the_contract_states() {
    use chard::error::{EXIT_CONTRADICTION, EXIT_FAILURE, EXIT_GATE, EXIT_MACHINE_LIMIT, EXIT_OK};
    assert_eq!(
        (
            EXIT_OK,
            EXIT_GATE,
            EXIT_FAILURE,
            EXIT_CONTRADICTION,
            EXIT_MACHINE_LIMIT
        ),
        (0, 1, 2, 3, 4)
    );
}

#[test]
fn measure_has_one_caller_and_it_closes_every_run() {
    let source = include_str!("../src/main.rs");
    let source = source
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("the file");
    let calls: Vec<String> = source
        .match_indices("measure(args, &mut ending)")
        .map(|(offset, _)| enclosing_fn(source, offset))
        .collect();
    assert_eq!(
        calls,
        ["measure_command"],
        "measure is called from: {calls:?}"
    );
    let body = source
        .split("fn measure_command(")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("measure_command's body");
    let matched = body.find("let code = match &closed").expect("the match");
    assert!(
        !body.contains("let status"),
        "measure_command binds no status of its own; it exits with closed.status()"
    );
    let closed = body
        .find("error::note(&closing_line(&closed, closed.status(), &ending));")
        .expect("the closing line");
    // The panic hook goes in before the run, so a panic in it closes with its own line; no
    // test can make chard panic, so a hand reproduction is its witness.
    let hooked = body.find("close_a_panic();").expect("the panic hook");
    let run = body.find("measure(args, &mut ending)").expect("the run");
    assert!(
        hooked < run,
        "measure_command installs the panic hook before the run"
    );
    assert!(
        matched < closed && body[closed..].trim_end().ends_with("code"),
        "measure_command writes the closing line after the status, then returns the status"
    );
}
