// SPDX-License-Identifier: BSD-3-Clause

//! The compiler-diagnostic decoders against stderr drawn from a grammar of what gcc and
//! clang print.
//!
//! Two decoders read a compiler's stderr as text. The compiler-diag detectors find the
//! line carrying the diagnostic's wording and read its severity from that line
//! (`probe::diag_severity_of`); the rejection rule finds a line saying a tool does not
//! know a flag and naming one chard supplied (`measure::flag_rejection`). Each has unit
//! tests on stderr someone captured or wrote. What neither had was a stream nobody wrote:
//! the diagnostic between two unrelated errors, behind a gcc `In function` header, under
//! a work directory named for the check, quoted with U+2018/U+2019 or with apostrophes,
//! tagged `[-Wfoo]`, `[-Werror=foo]`, `[-Werror,-Wfoo]` or not at all. This file draws
//! such streams from a seed (`tests/seeded`) and holds each decoder's verdict to the
//! rule its doc comment states, computed here from the grammar's own record of what it
//! wrote, never from the decoder.
//!
//! The diagnostic wordings are the ones the replay corpus (`tests/fixtures/detectors.json`)
//! recorded from real builds, gcc 10 through 16 and clang 10 through 23, and the
//! detectors' own doc comments for the three the corpus has no line of; the rejection
//! wordings are the ones `measure::flag_rejection` lists, in the shapes gcc, clang, GNU
//! ld, lld and Apple's ld print them. Streams are color-free: `compile` builds with the
//! diagnostic language pinned and no terminal.

use std::collections::{BTreeMap, BTreeSet};

mod seeded;

use chard::compile::BuildRecord;
use chard::measure::{control_flag_rejection, profile_flag_refusal, profile_flag_refusals};
use chard::probe::{CORPUS, Channel, Check, Evidence, Outcome};

/// How a check reads its diagnostic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reads {
    /// Present at whatever severity the diagnostic's own line carries.
    Presence,
    /// Present only when the diagnostic's own line is an error.
    Severity,
}

/// One compiler-diag check: its reading, the option its tag names, and the wordings each
/// compiler gives the diagnostic, with `{q}` and `{Q}` for the opening and closing quote.
struct Diag {
    id: &'static str,
    reads: Reads,
    option: &'static str,
    gcc: &'static [&'static str],
    clang: &'static [&'static str],
}

const DIAGS: &[Diag] = &[
    Diag {
        id: "warn-all",
        reads: Reads::Presence,
        option: "unused-label",
        gcc: &["label {q}chard_wall_dead_label{Q} defined but not used"],
        clang: &["unused label {q}chard_wall_dead_label{Q}"],
    },
    Diag {
        id: "warn-extra",
        reads: Reads::Presence,
        option: "sign-compare",
        gcc: &[
            "comparison of integer expressions of different signedness: {q}int{Q} and \
             {q}unsigned int{Q}",
        ],
        clang: &["comparison of integers of different signs: {q}int{Q} and {q}unsigned int{Q}"],
    },
    Diag {
        id: "format-mismatch-warned",
        reads: Reads::Presence,
        option: "format=",
        gcc: &[
            "format {q}%d{Q} expects argument of type {q}int{Q}, but argument 2 has type \
             {q}long long int{Q}",
        ],
        clang: &["format specifies type {q}int{Q} but the argument has type {q}long long{Q}"],
    },
    Diag {
        id: "format-nonliteral-warned",
        reads: Reads::Presence,
        option: "format-nonliteral",
        gcc: &["format not a string literal, argument types not checked"],
        clang: &["format string is not a string literal"],
    },
    Diag {
        id: "conversion-warns-on-narrowing",
        reads: Reads::Presence,
        option: "conversion",
        gcc: &["conversion from {q}int{Q} to {q}char{Q} may change value"],
        clang: &["implicit conversion loses integer precision: {q}volatile int{Q} to {q}char{Q}"],
    },
    Diag {
        id: "sign-conversion-warns-on-signedness-change",
        reads: Reads::Presence,
        option: "sign-conversion",
        gcc: &["conversion to {q}unsigned int{Q} from {q}int{Q} may change the sign of the result"],
        clang: &[
            "implicit conversion changes signedness: {q}volatile int{Q} to {q}unsigned int{Q}",
        ],
    },
    Diag {
        id: "implicit-fallthrough-warned",
        reads: Reads::Presence,
        option: "implicit-fallthrough",
        gcc: &["this statement may fall through"],
        clang: &["unannotated fall-through between switch labels"],
    },
    Diag {
        id: "trampolines-warned",
        reads: Reads::Presence,
        option: "trampolines",
        gcc: &["trampoline generated for nested function {q}chard_nested{Q}"],
        clang: &[],
    },
    Diag {
        id: "bidi-chars-any",
        reads: Reads::Presence,
        option: "bidi-chars=",
        gcc: &["found problematic Unicode character {q}U+202E (RIGHT-TO-LEFT OVERRIDE){Q}"],
        clang: &[],
    },
    Diag {
        id: "hardened-downgrade-warned",
        reads: Reads::Presence,
        option: "hardened",
        gcc: &[
            "{q}-fstack-protector-strong{Q} is not enabled by {q}-fhardened{Q} because it \
             was specified on the command line",
        ],
        clang: &[],
    },
    Diag {
        id: "format-security-is-error",
        reads: Reads::Severity,
        option: "format-security",
        gcc: &["format not a string literal and no format arguments"],
        clang: &["format string is not a string literal (potentially insecure)"],
    },
    Diag {
        id: "implicit-function-declaration-is-error",
        reads: Reads::Severity,
        option: "implicit-function-declaration",
        gcc: &["implicit declaration of function {q}chard_probe_target{Q}"],
        clang: &[
            "call to undeclared function {q}chard_probe_target{Q}; ISO C99 and later do not \
             support implicit function declarations",
            "implicit declaration of function {q}chard_probe_target{Q} is invalid in C99",
        ],
    },
    Diag {
        id: "implicit-int-is-error",
        reads: Reads::Severity,
        option: "implicit-int",
        gcc: &["type defaults to {q}int{Q} in declaration of {q}chard_implicit_int_value{Q}"],
        clang: &[
            "type specifier missing, defaults to {q}int{Q}",
            "type specifier missing, defaults to {q}int{Q}; ISO C99 and later do not \
             support implicit int",
        ],
    },
    Diag {
        id: "incompatible-pointer-types-is-error",
        reads: Reads::Severity,
        option: "incompatible-pointer-types",
        gcc: &["assignment to {q}int *{Q} from incompatible pointer type {q}char *{Q}"],
        clang: &["incompatible pointer types assigning to {q}int *{Q} from {q}char *{Q}"],
    },
    Diag {
        id: "int-conversion-is-error",
        reads: Reads::Severity,
        option: "int-conversion",
        gcc: &[
            "initialization of {q}int *{Q} from {q}int{Q} makes pointer from integer without a cast",
        ],
        clang: &[
            "incompatible integer to pointer conversion initializing {q}int *{Q} with an \
             expression of type {q}int{Q}",
        ],
    },
];

/// Quote pairs a compiler uses in the C locale and in a UTF-8 one. gcc uses both;
/// clang only the apostrophe.
const GCC_QUOTES: &[(&str, &str)] = &[("'", "'"), ("\u{2018}", "\u{2019}")];
const CLANG_QUOTES: &[(&str, &str)] = &[("'", "'")];

/// Lines no check's wording appears in, each with whether it is an error: the canary's
/// neighbours, a failed link, an unrelated flag complaint.
const DISTRACTORS: &[(&str, bool)] = &[
    (
        "{path}:12:5: warning: {q}retain{Q} attribute ignored [-Wattributes]",
        false,
    ),
    (
        "clang: error: linker command failed with exit code 1 (use -v to see invocation)",
        true,
    ),
    ("collect2: error: ld returned 1 exit status", true),
    (
        "/usr/bin/ld: cannot find -lnosuchlib: No such file or directory",
        true,
    ),
    (
        "clang: warning: argument unused during compilation: {q}-fstack-clash-protection{Q} \
         [-Wunused-command-line-argument]",
        false,
    ),
    (
        "warning: unknown warning option {q}-Wtrampolines{Q}; did you mean \
         {q}-Wtrampoline{Q}? [-Wunknown-warning-option]",
        false,
    ),
    (
        "{path}:40:3: error: use of undeclared identifier {q}chard_nested{Q}",
        true,
    ),
];

/// Work directories, including one named for the check, which is how a needle short
/// enough to sit in a path once matched a gcc `In function` header.
const WORKDIRS: &[&str] = &["/tmp/chard-w", "/var/tmp/work dir", "/tmp/chard/{id}", "."];

/// What the grammar wrote into one stream, which is what the expected verdict is
/// computed from.
#[derive(Debug)]
struct Written {
    stderr: String,
    exit_status: i32,
    /// The severity the check's own diagnostic line carries, if the line was written.
    target: Option<&'static str>,
    canary: bool,
}

fn fill(template: &str, q: (&str, &str), path: &str) -> String {
    template
        .replace("{q}", q.0)
        .replace("{Q}", q.1)
        .replace("{path}", path)
}

/// The `[...]` tag after a diagnostic, in one of the spellings each compiler uses.
fn tag(rng: &mut seeded::Rng, gcc: bool, option: &str, error: bool) -> String {
    match rng.below(4) {
        0 => String::new(),
        1 if error && gcc => format!(" [-Werror={option}]"),
        1 if error => format!(" [-Werror,-W{option}]"),
        _ => format!(" [-W{option}]"),
    }
}

/// The source and caret lines under a diagnostic, in gcc's numbered layout or the
/// older bare one clang still prints.
fn excerpt(rng: &mut seeded::Rng, out: &mut Vec<String>) {
    if rng.chance(1, 2) {
        out.push("   57 |     chard_statement();".to_owned());
        out.push("      |     ^~~~~~~~~~~~~~~".to_owned());
    } else {
        out.push("    chard_statement();".to_owned());
        out.push("    ^".to_owned());
    }
}

fn write_stream(rng: &mut seeded::Rng, diag: &Diag) -> Written {
    let gcc = diag.clang.is_empty() || rng.chance(1, 2);
    let q = *rng.pick(if gcc { GCC_QUOTES } else { CLANG_QUOTES });
    let workdir = rng.pick(WORKDIRS).replace("{id}", diag.id);
    let path = format!("{workdir}/{}.c", diag.id.replace('-', "_"));
    let mut lines: Vec<String> = Vec::new();
    let mut error = false;

    let mut blocks: Vec<u8> = Vec::new();
    let target = rng
        .chance(2, 3)
        .then(|| if rng.chance(1, 2) { "error" } else { "warning" });
    if target.is_some() {
        blocks.push(0);
    }
    let canary = rng.chance(3, 4);
    if canary {
        blocks.push(1);
    }
    let distractors = usize::try_from(rng.below(3)).expect("below 3");
    blocks.extend(std::iter::repeat_n(2, distractors));
    // Any order: the canary before the diagnostic, a link error before both.
    for i in (1..blocks.len()).rev() {
        blocks.swap(i, rng.index(i + 1));
    }

    if gcc && rng.chance(1, 2) {
        lines.push(fill("{path}: In function {q}main{Q}:", q, &path));
    }
    for block in blocks {
        match block {
            0 => {
                let severity = target.expect("block 0 is written only with a target");
                let wording = rng.pick(if gcc { diag.gcc } else { diag.clang });
                let message = fill(wording, q, &path);
                let tag = tag(rng, gcc, diag.option, severity == "error");
                lines.push(format!("{path}:57:5: {severity}: {message}{tag}"));
                excerpt(rng, &mut lines);
                error |= severity == "error";
            }
            1 => {
                lines.push(fill(
                    "{path}:61:9: warning: unused variable {q}chard_canary_unused{Q} \
                     [-Wunused-variable]",
                    q,
                    &path,
                ));
                excerpt(rng, &mut lines);
            }
            _ => {
                let (template, is_error) = *rng.pick(DISTRACTORS);
                lines.push(fill(template, q, &path));
                error |= is_error;
            }
        }
    }
    if !gcc && !lines.is_empty() && rng.chance(1, 2) {
        lines.push("2 warnings generated.".to_owned());
    }
    Written {
        stderr: lines.join("\n") + "\n",
        exit_status: i32::from(error),
        target,
        canary,
    }
}

/// The verdict the detectors' doc comments promise for what was written.
fn expected(diag: &Diag, w: &Written) -> (Outcome, Option<&'static str>) {
    let Some(level) = w.target else {
        // Silence is absence only over a canary and a clean exit.
        return if w.canary && w.exit_status == 0 {
            (Outcome::Absent, None)
        } else {
            (Outcome::Indeterminate, None)
        };
    };
    match diag.reads {
        Reads::Presence => (Outcome::Present, Some(level)),
        Reads::Severity if level == "error" => (Outcome::Present, Some("error")),
        Reads::Severity => (Outcome::Absent, None),
    }
}

fn record(stderr: String, exit_status: i32) -> BuildRecord {
    BuildRecord {
        argv: Vec::new(),
        dropped_flags: Vec::new(),
        exit_status,
        stdout: String::new(),
        stderr,
        duration_ms: 0,
        artifact_sha256: None,
        stdout_sha256: None,
        stdout_unterminated: false,
    }
}

fn check(id: &str) -> &'static Check {
    CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} is not in the corpus"))
}

/// Every compiler-diag detector reads a drawn stream as its doc comment says.
///
/// The rule, in the detectors' own terms: the diagnostic's line decides, and its severity
/// is the one on that line, never one elsewhere in the stream; a presence check is
/// present at that severity, a severity check only at `error`; with no diagnostic line,
/// the canary missing or the build failed is `indeterminate`, and silence over a canary
/// and a clean exit is `absent`. Each verdict is counted per check and per cell of that
/// rule, and a default-sized run must reach every cell for every check.
#[test]
fn compiler_diag_detectors_read_drawn_streams_as_documented() {
    let (seed, from_env) = seeded::seed();
    let cases = seeded::cases(4000);
    let listed: BTreeSet<&str> = DIAGS.iter().map(|d| d.id).collect();
    let in_corpus: BTreeSet<&str> = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| {
            c.channel() == Channel::CompilerDiag
                && !matches!(c.id, "no-copy-dt-needed" | "pic-shared-link")
        })
        .map(|c| c.id)
        .collect();
    assert_eq!(
        listed, in_corpus,
        "every compiler-diag check that reads a diagnostic has a grammar here, and no other \
         (no-copy-dt-needed and pic-shared-link read a link, not a diagnostic)"
    );

    let macros = BTreeMap::new();
    let mut cells: BTreeMap<(&str, String), usize> = BTreeMap::new();
    for case in 0..cases {
        let mut rng = seeded::Rng::for_case(seed, case);
        let diag = rng.pick(DIAGS);
        let written = write_stream(&mut rng, diag);
        let build = record(written.stderr.clone(), written.exit_status);
        let detection = check(diag.id)
            .decode(&Evidence {
                macros: &macros,
                elf: None,
                build: Some(&build),
                run: None,
                workdir: None,
            })
            .detection;
        let want = expected(diag, &written);
        let got = (detection.outcome, detection.level.as_deref());
        assert!(
            got == want,
            "{}: expected {want:?}, the detector read {got:?} ({}).\nwritten: {written:#?}\n\
             observed: {}",
            diag.id,
            seeded::replay(seed, case),
            detection.observed
        );
        *cells
            .entry((diag.id, format!("{:?}/{:?}", want.0, want.1)))
            .or_insert(0) += 1;
    }
    seeded::announce(
        "compiler-diag grammar",
        seed,
        from_env,
        cases,
        &format!("{} (check, verdict) cells reached", cells.len()),
    );
    if cases >= 4000 {
        for diag in DIAGS {
            let reached: Vec<&String> = cells
                .keys()
                .filter(|(id, _)| *id == diag.id)
                .map(|(_, cell)| cell)
                .collect();
            let floor = match diag.reads {
                Reads::Presence => 4, // present/error, present/warning, absent, indeterminate
                Reads::Severity => 3, // present/error, absent, indeterminate
            };
            assert!(
                reached.len() >= floor,
                "{} reached only {reached:?} ({})",
                diag.id,
                seeded::replay(seed, 0)
            );
        }
    }
}

// --- flag rejection -------------------------------------------------------------------

/// Flags a control supplies, as written; `-Wl,` ones reach the linker as their pieces.
const FLAGS: &[&str] = &[
    "-Wtrampolines",
    "-Whardened",
    "-fstrict-flex-arrays=3",
    "-fstack-clash-protection",
    "-ftrivial-auto-var-init=zero",
    "-fhardened",
    "-mbranch-protection=standard",
    "-fcf-protection=full",
    "-Wbidi-chars=any",
    "-Wl,--no-copy-dt-needed-entries",
    "-Wl,--as-needed",
];

/// How a tool names `flag`: a linker names the pieces of a `-Wl,` flag.
fn spelled(flag: &'static str, linker: bool) -> &'static str {
    match flag.strip_prefix("-Wl,") {
        Some(rest) if linker => rest,
        _ => flag,
    }
}

/// One rejection shape: the tool, whether it is a linker, and the sentence with `{f}` for
/// the rejected flag and `{s}` for a suggestion.
const REJECTIONS: &[(&str, bool, &str)] = &[
    (
        "gcc",
        false,
        "error: unrecognized command-line option {q}{f}{Q}",
    ),
    (
        "gcc",
        false,
        "error: unrecognized command line option {q}{f}{Q}; did you mean {q}{s}{Q}?",
    ),
    (
        "cc1",
        false,
        "warning: unrecognized command-line option {q}{f}{Q} may have been intended to \
         silence earlier diagnostics",
    ),
    ("clang", false, "error: unknown argument: {q}{f}{Q}"),
    (
        "clang-22",
        false,
        "error: unknown argument {q}{f}{Q}; did you mean {q}{s}{Q}?",
    ),
    (
        "",
        false,
        "warning: unknown warning option {q}{f}{Q}; did you mean {q}{s}{Q}? [-Wunknown-warning-option]",
    ),
    (
        "clang",
        false,
        "error: unsupported option {q}{f}{Q} for target {q}x86_64-unknown-linux-gnu{Q}",
    ),
    (
        "clang",
        false,
        "error: {q}{f}{Q} hasn't been enabled; enable it at your own peril for benchmarking \
         purpose only with {q}-enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang{Q}",
    ),
    ("/usr/bin/ld", true, "unrecognized option {q}{f}{Q}"),
    ("ld.lld", true, "error: unknown argument {q}{f}{Q}"),
    ("ld", true, "unknown options: {f} "),
];

/// Lines naming a supplied flag without rejecting it, and rejecting nothing supplied.
const NOT_REJECTIONS: &[&str] = &[
    "clang: warning: argument unused during compilation: {q}{f}{Q} [-Wunused-command-line-argument]",
    "gcc: note: {q}{f}{Q} was given on the command line",
    "/usr/bin/ld: warning: {q}{f}{Q} ignored",
];

const QUOTES: &[(&str, &str)] = &[("'", "'"), ("\u{2018}", "\u{2019}"), ("\"", "\""), ("", "")];

/// One drawn stream, and the line and flag the rule must name, if any.
struct Rejection {
    supplied: Vec<&'static str>,
    stderr: String,
    /// `(tool, rejected spelling, line)` of the first line that rejects a supplied flag.
    expect: Option<(&'static str, &'static str, String)>,
    /// The same of the first such line the tool stopped on: one whose sentence opens with
    /// no `warning:`, which is the line a profile flag's refusal reads.
    refusal: Option<(&'static str, &'static str, String)>,
    /// Every such line's `(tool, spelling, line)`, each tool and spelling once, in order:
    /// what `measure::profile_flag_refusals` reads.
    refusals: Vec<(&'static str, &'static str, String)>,
}

fn draw_rejection(rng: &mut seeded::Rng) -> Rejection {
    let mut supplied: Vec<&'static str> = (0..=rng.below(3)).map(|_| *rng.pick(FLAGS)).collect();
    supplied.sort_unstable();
    supplied.dedup();
    let mut lines = Vec::new();
    let mut expect = None;
    let mut refusal = None;
    let mut refusals: Vec<(&'static str, &'static str, String)> = Vec::new();
    for _ in 0..=rng.below(3) {
        let q = *rng.pick(QUOTES);
        if rng.chance(1, 4) {
            let f = *rng.pick(&supplied);
            lines.push(fill(rng.pick::<&str>(NOT_REJECTIONS), q, "").replace("{f}", f));
            continue;
        }
        let (tool, linker, sentence) = *rng.pick(REJECTIONS);
        // The rejected flag: supplied half the time, otherwise one the control did not
        // pass; the suggestion is any flag, supplied or not.
        let flag = if rng.chance(1, 2) {
            *rng.pick(&supplied)
        } else {
            *rng.pick(FLAGS)
        };
        let suggestion = spelled(rng.pick::<&str>(FLAGS), linker);
        let named = spelled(flag, linker);
        let body = fill(sentence, q, "")
            .replace("{f}", named)
            .replace("{s}", suggestion);
        let line = if tool.is_empty() {
            body
        } else {
            format!("{tool}: {body}")
        };
        let supplied_spellings: BTreeSet<&str> =
            supplied.iter().map(|f| spelled(f, linker)).collect();
        if expect.is_none() && supplied_spellings.contains(named) {
            expect = Some((tool, named, line.clone()));
        }
        if refusal.is_none()
            && supplied_spellings.contains(named)
            && !sentence.starts_with("warning:")
        {
            refusal = Some((tool, named, line.clone()));
        }
        if supplied_spellings.contains(named)
            && !sentence.starts_with("warning:")
            && !refusals.iter().any(|(t, f, _)| *t == tool && *f == named)
        {
            refusals.push((tool, named, line.clone()));
        }
        lines.push(line);
    }
    Rejection {
        supplied,
        stderr: lines.join("\n") + "\n",
        expect,
        refusal,
        refusals,
    }
}

/// The rejection rule names the first line that rejects a supplied flag, and the flag,
/// over drawn streams; and it names nothing when no line does.
///
/// Held here: a line that names a supplied flag without a rejection phrase is not one; a
/// rejection of a flag the control did not supply is not one, even when the tool's
/// suggestion is a flag it did supply; every quote a tool puts around the flag, and the
/// sentence punctuation after it, is trimmed; a linker's spelling of a `-Wl,` flag is
/// matched. The tool is held to the line's own prefix where the line has one, and to
/// `the toolchain` where the line opens with its severity, as clang's frontend prints
/// `warning: unknown warning option`.
#[test]
fn flag_rejection_names_the_first_line_rejecting_a_supplied_flag() {
    let (seed, from_env) = seeded::seed();
    let cases = seeded::cases(4000);
    let (mut named, mut silent) = (0usize, 0usize);
    for case in 0..cases {
        let mut rng = seeded::Rng::for_case(seed, case);
        let drawn = draw_rejection(&mut rng);
        let build = record(drawn.stderr.clone(), 1);
        let got = control_flag_rejection(&build, &drawn.supplied);
        let context = || {
            format!(
                "({})\nsupplied: {:?}\nstderr:\n{}",
                seeded::replay(seed, case),
                drawn.supplied,
                drawn.stderr
            )
        };
        match (&drawn.expect, &got) {
            (None, None) => silent += 1,
            (Some((tool, flag, line)), Some(said)) => {
                assert!(
                    said.ends_with(&format!("does not know {flag}: {}", line.trim())),
                    "named the wrong flag or line: {said} {}",
                    context()
                );
                let tool = if tool.is_empty() {
                    "the toolchain"
                } else {
                    tool
                };
                assert!(
                    said.starts_with(&format!("{tool} does not know")),
                    "{said} {}",
                    context()
                );
                named += 1;
            }
            (want, got) => panic!("expected {want:?}, got {got:?} {}", context()),
        }
    }
    seeded::announce(
        "flag-rejection grammar",
        seed,
        from_env,
        cases,
        &format!("{named} streams named a rejection, {silent} named none"),
    );
    assert!(
        named > 0 && silent > 0,
        "both outcomes must be drawn: {named} named, {silent} silent"
    );
}

/// A profile flag's refusal names the first line the tool stopped on that rejects a
/// supplied flag, and carries that line's tool and flag as its fields, over the same drawn
/// streams with the flags as a profile's; and it names nothing when no such line is drawn.
///
/// The fields name the refusal a cell's `build_rejection` publishes, and the first entry of
/// `measure::profile_flag_refusals`, which `report::profile_flag_rejections` groups a run's
/// cells by, one `profile-flag-rejected` diagnostic per tool and flag; a tool or flag read
/// wrong here is a refused flag counted under the wrong name. The
/// expectation is the grammar's own record: the tool it wrote (`the toolchain` where the
/// line opens with its severity), the one spelling it wrote, and the line.
#[test]
fn profile_flag_refusal_carries_the_tool_and_flag_of_the_first_refusal() {
    let (seed, from_env) = seeded::seed();
    let cases = seeded::cases(4000);
    let (mut named, mut silent) = (0usize, 0usize);
    for case in 0..cases {
        let mut rng = seeded::Rng::for_case(seed, case);
        let drawn = draw_rejection(&mut rng);
        let (cflags, ldflags): (Vec<&str>, Vec<&str>) =
            drawn.supplied.iter().partition(|f| !f.starts_with("-Wl,"));
        let profile = chard::report::Profile {
            id: "explicit".to_owned(),
            flags_source: "user".to_owned(),
            cflags: cflags.iter().map(|f| (*f).to_owned()).collect(),
            cxxflags: Vec::new(),
            ldflags: ldflags.iter().map(|f| (*f).to_owned()).collect(),
            toolchain_note: None,
            compiler_environment: chard::compile::CompilerEnvironment::of_this_run(),
        };
        let got = profile_flag_refusal(&record(drawn.stderr.clone(), 1), &profile);
        let context = || {
            format!(
                "({})\nsupplied: {:?}\nstderr:\n{}",
                seeded::replay(seed, case),
                drawn.supplied,
                drawn.stderr
            )
        };
        match (&drawn.refusal, &got) {
            (None, None) => silent += 1,
            (Some((tool, flag, line)), Some(refusal)) => {
                let tool = if tool.is_empty() {
                    "the toolchain"
                } else {
                    tool
                };
                assert_eq!(refusal.tool, tool, "{}", context());
                assert_eq!(refusal.flags, [*flag], "{}", context());
                assert_eq!(refusal.line, line.trim(), "{}", context());
                assert_eq!(
                    refusal.sentence,
                    format!(
                        "{tool} rejected {flag}, supplied by the profile not by this check: {}",
                        line.trim()
                    ),
                    "{}",
                    context()
                );
                named += 1;
            }
            (want, got) => panic!("expected {want:?}, got {got:?} {}", context()),
        }
    }
    seeded::announce(
        "profile-refusal grammar",
        seed,
        from_env,
        cases,
        &format!("{named} streams named a refusal, {silent} named none"),
    );
    assert!(
        named > 0 && silent > 0,
        "both outcomes must be drawn: {named} named, {silent} silent"
    );
}

/// Every profile flag a build's tools refused is read, each tool and flag once, on the
/// first line that refused it, in order, over the same drawn streams; the first entry is
/// the refusal a cell's `build_rejection` names. `report::profile_flag_rejections` counts a
/// run by this reader, so a refusal it skips is a rejected flag named nowhere, which is
/// what reading only the first line did to a build refusing two flags.
#[test]
fn profile_flag_refusals_reads_every_refusal_line() {
    let (seed, from_env) = seeded::seed();
    let cases = seeded::cases(4000);
    let (mut several, mut one, mut none) = (0usize, 0usize, 0usize);
    for case in 0..cases {
        let mut rng = seeded::Rng::for_case(seed, case);
        let drawn = draw_rejection(&mut rng);
        let (cflags, ldflags): (Vec<&str>, Vec<&str>) =
            drawn.supplied.iter().partition(|f| !f.starts_with("-Wl,"));
        let profile = chard::report::Profile {
            id: "explicit".to_owned(),
            flags_source: "user".to_owned(),
            cflags: cflags.iter().map(|f| (*f).to_owned()).collect(),
            cxxflags: Vec::new(),
            ldflags: ldflags.iter().map(|f| (*f).to_owned()).collect(),
            toolchain_note: None,
            compiler_environment: chard::compile::CompilerEnvironment::of_this_run(),
        };
        let build = record(drawn.stderr.clone(), 1);
        let got: Vec<(String, String, String)> = profile_flag_refusals(&build, &profile)
            .into_iter()
            .map(|r| (r.tool, r.flag, r.line))
            .collect();
        let want: Vec<(String, String, String)> = drawn
            .refusals
            .iter()
            .map(|(tool, flag, line)| {
                let tool = if tool.is_empty() {
                    "the toolchain"
                } else {
                    tool
                };
                (tool.to_owned(), (*flag).to_owned(), line.trim().to_owned())
            })
            .collect();
        let context = || {
            format!(
                "({})\nsupplied: {:?}\nstderr:\n{}",
                seeded::replay(seed, case),
                drawn.supplied,
                drawn.stderr
            )
        };
        assert_eq!(got, want, "{}", context());
        let first = profile_flag_refusal(&build, &profile);
        assert_eq!(
            got.first().map(|(t, _, l)| (t.clone(), l.clone())),
            first.map(|r| (r.tool, r.line)),
            "the first refusal is the cell's {}",
            context()
        );
        match got.len() {
            0 => none += 1,
            1 => one += 1,
            _ => several += 1,
        }
    }
    seeded::announce(
        "profile-refusals grammar",
        seed,
        from_env,
        cases,
        &format!("{several} streams refused several flags, {one} one, {none} none"),
    );
    assert!(
        several > 0 && one > 0 && none > 0,
        "every outcome must be drawn: {several} several, {one} one, {none} none"
    );
}
