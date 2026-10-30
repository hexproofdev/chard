// SPDX-License-Identifier: BSD-3-Clause

//! Each command's exit statuses, held to the sites in the source that return them.
//!
//! The CLI's contract (`CONTRACT` in `src/main.rs`) gives every status one meaning, and the
//! meaning is what a caller routes on: `1` a gate the caller can act on with the document
//! written, `3` a defect in chard to report. A `detect` that returned `3` for a report that
//! disagrees with its replay would carry the first meaning on the second's code, and without a
//! test saying which statuses a command can return the overload would stand in the contract's
//! own words. This test reads every site in `src/main.rs` that makes an exit status (an
//! `ExitCode::from`, `error::emit`, `error::emit_contradiction`), attributes it to the
//! function it sits in, and compares the statuses each function can return with the table
//! below; `src/error.rs` is read for the status each of its two emitters returns. A new
//! site, or a status at a site the table does not list for that function, fails here and is
//! named. Like `tests/untyped_errors.rs`, a text scan: a tripwire held to the source, not a
//! proof about every path, and the end-to-end statuses are `tests/detect_cli.rs`'s
//! (`detect`'s `1`), `tests/fake_driver.rs`'s (`measure`'s `0` and `1`) and
//! `tests/error_classes.rs`'s (`2`).

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
        // what chard observed. `measure` itself makes none: it says how the run ended, and
        // `measure_command` makes the status and the closing line from that one value.
        &["EXIT_OK", "EXIT_GATE", "EXIT_FAILURE", "EXIT_CONTRADICTION"],
    ),
];

/// The status each emitter in `src/error.rs` returns.
const EMITTERS: &[(&str, &str)] = &[
    ("error::emit(", "EXIT_FAILURE"),
    ("error::emit_contradiction(", "EXIT_CONTRADICTION"),
    ("error::emit_declaration_contradicted(", "EXIT_FAILURE"),
];

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
        let named: BTreeSet<String> = body
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| w.starts_with("EXIT_"))
            .map(str::to_owned)
            .collect();
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
        "the exit statuses src/main.rs makes, by function, are not the table's; a new status \
         at a site is a change to the CLI's contract (CONTRACT), and goes there first"
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
    // returned them. A text scan: no run reaches a contradiction short of a defect in chard,
    // so the write itself is witnessed only by injected-defect reproductions made by hand.
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
            "Closed::Contradicted { contradictions, quarantine, } => ( \
             error::emit_contradiction(*contradictions, quarantine.as_deref()), \
             error::EXIT_CONTRADICTION, ),"
        )),
        "measure hands emit_contradiction the count and the quarantine publish kept, and only \
         for a refusal whose cause is chard's own"
    );
    // The constant's definition, its doc's mentions and the emitter's return; nothing else.
    let outside_docs = error
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains("EXIT_CONTRADICTION"))
        .count();
    assert_eq!(
        outside_docs, 2,
        "src/error.rs uses EXIT_CONTRADICTION in code only where it is defined and where \
         emit_contradiction returns it ({uses} mentions in all)"
    );
}

#[test]
fn the_statuses_are_the_numbers_the_contract_states() {
    use chard::error::{EXIT_CONTRADICTION, EXIT_FAILURE, EXIT_GATE, EXIT_OK};
    assert_eq!(
        (EXIT_OK, EXIT_GATE, EXIT_FAILURE, EXIT_CONTRADICTION),
        (0, 1, 2, 3)
    );
}

/// `measure` has one caller, `measure_command`, which writes the closing line after the
/// match that makes the status, so no status `measure` ends on is returned without it. A
/// text scan, beside `tests/fake_driver.rs`'s end-to-end runs of each path a run can end on.
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
    let matched = body
        .find("let (code, status) = match &closed")
        .expect("the match");
    let closed = body
        .find("error::note(&closing_line(&closed, status, &ending));")
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
        "measure_command writes the closing line after the status is made, and returns that \
         status next"
    );
}
