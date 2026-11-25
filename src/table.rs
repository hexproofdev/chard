// SPDX-License-Identifier: BSD-3-Clause

//! Rendering reports as a table a person can read: separate reports, such as what a bare
//! `cc` gives and what the distribution's own packages get, side by side.

use std::collections::{BTreeMap, BTreeSet};

use std::fmt::Write as _;

use anyhow::Result;
use serde_json::Value;

use crate::matrix::Repeated;
use crate::probe::{self, Levels};
use crate::report::{Verdict, family};

/// The width `chard table` wraps its prose at unless `--width` says otherwise.
pub const DEFAULT_WIDTH: usize = 80;

/// A verdict, the level where the check reported one, and the ask the check grades it
/// against where it grades one.
type Reading = (String, Option<String>, Option<String>);
/// Accumulator: protection family and column, to every reading seen for it.
type Readings = BTreeMap<(String, Column), BTreeSet<Reading>>;

/// The checks that ask about one level of their row's mechanism, by check id, each with the
/// level word it asks about: their `off` says the mechanism is not at that level, not that
/// it is absent, and their `on` says it is at that level.
const ONE_LEVEL_CHECKS: &[(&str, &str)] = &[
    ("auto-var-init-pattern", "pattern"),
    ("fortify-enforced-dynamic", "3"),
];

/// Protection family and column, to the [`ONE_LEVEL_CHECKS`] `on` and `off` readings held for
/// the cell, each with the level word it states or denies.
type OneLevel = BTreeMap<(String, Column), Vec<(&'static str, Reading)>>;

/// An observation's reading: `verdict` in protection terms, its `level`, and its ask,
/// scrubbed like the level, since both are a foreign report's strings.
fn reading_of(cell: &Value, verdict: &str, level: Option<&str>) -> Reading {
    let ask = cell
        .get("recommended_level")
        .and_then(Value::as_str)
        .map(scrub);
    (verdict.to_owned(), level.map(ToOwned::to_owned), ask)
}

/// How a withheld line names its cell: the row, and the check's flag beside it where the
/// flag says more than the row. A flag that is its row, or begins with it and a qualifier
/// (`-fstrict-flex-arrays (enforced under _FORTIFY_SOURCE>=2)` in the `-fstrict-flex-arrays`
/// row), names the cell alone.
fn withheld_label(w: &Withheld) -> (&str, Option<&str>) {
    if crate::report::unqualified(&w.check) == w.row {
        (&w.check, None)
    } else {
        (&w.row, Some(&w.check))
    }
}

/// The level word a [`ONE_LEVEL_CHECKS`] check asks about, `None` for any other check.
fn level_asked(check: &str) -> Option<&'static str> {
    ONE_LEVEL_CHECKS
        .iter()
        .find(|(id, _)| *id == check)
        .map(|(_, word)| *word)
}

/// The level word an observation's `verdict` (in protection terms) states or denies: a
/// [`ONE_LEVEL_CHECKS`] check's `on` or `off`. `None` for every other reading.
fn one_level_word(cell: &Value, verdict: &str) -> Option<&'static str> {
    let check = cell.get("check").and_then(Value::as_str)?;
    matches!(verdict, "on" | "off")
        .then(|| level_asked(check))
        .flatten()
}

/// Each held [`ONE_LEVEL_CHECKS`] reading into its cell's readings, the `on`s first.
fn settle_one_level(acc: &mut Readings, held: OneLevel) {
    for (key, held) in held {
        let readings = acc.entry(key).or_default();
        // [`one_level_word`] holds `on` and `off` alone: the `on`s state, the `off`s deny.
        let (states, denials): (Vec<_>, Vec<_>) =
            held.into_iter().partition(|(_, (v, _, _))| v == "on");
        let asks: BTreeSet<String> = readings
            .iter()
            .filter(|(v, l, _)| is_present(v) && l.is_some())
            .filter_map(|(_, _, ask)| ask.clone())
            .collect();
        let scale = (asks.len() == 1).then(|| asks.into_iter().next()).flatten();
        for (word, reading) in states {
            readings.insert(match &scale {
                Some(ask) => (reading.0, Some(word.to_owned()), Some(ask.clone())),
                None => reading,
            });
        }
        for (word, reading) in denials {
            let at_another_level = readings
                .iter()
                .any(|(v, l, _)| is_present(v) && l.as_deref().is_some_and(|l| l != word));
            if !at_another_level {
                readings.insert(reading);
            }
        }
    }
}

/// Whether an observation is a `partial` at a level [`crate::report::OPT_IN_LEVELS`] names: a
/// level whose rule reaches only code that opts in, which no probe's code does, so the
/// readings of what the probe built say nothing against it. The report's corroboration reads
/// the same list the same way, so the table and the report agree on what disagrees.
fn at_opt_in_level(cell: &Value, verdict: &str, level: Option<&str>) -> bool {
    let check = cell.get("check").and_then(Value::as_str);
    is_short(verdict)
        && check
            .zip(level)
            .is_some_and(|pair| crate::report::OPT_IN_LEVELS.contains(&pair))
}

/// The `off` readings out of every cell [`at_opt_in_level`] marked: under
/// `-fstack-protector-explicit` `canary-emitted` and `ssp-level-emitted` read `off` (no probe
/// function is marked `stack_protect`) beside `ssp-level` `partial` at `explicit`, all three
/// right, and the cell shows `explicit`.
fn settle_opt_in(acc: &mut Readings, cells: &BTreeSet<(String, Column)>) {
    for key in cells {
        if let Some(readings) = acc.get_mut(key) {
            readings.retain(|(v, _, _)| v != "off");
        }
    }
}

/// Every reading of every cell as [`collect`] reads them, until each cell's are all in.
#[derive(Default)]
struct Accumulator {
    /// Family and column, to the (verdict, level, ask) readings seen, kept unrendered so a
    /// difference in granularity is not mistaken for a difference in outcome.
    readings: Readings,
    /// The `on` and `off` readings of [`ONE_LEVEL_CHECKS`], held until every other reading
    /// of their cell is in, with the word each one states or denies.
    one_level: OneLevel,
    /// The cells holding a `partial` at a level that reaches only code which opts in.
    opt_in: BTreeSet<(String, Column)>,
}

impl Accumulator {
    /// One observation's reading, `verdict` in protection terms, into the cell `key`.
    fn file(&mut self, cell: &Value, verdict: &str, level: Option<&str>, key: (String, Column)) {
        let reading = reading_of(cell, verdict, level);
        if at_opt_in_level(cell, verdict, level) {
            self.opt_in.insert(key.clone());
        }
        match one_level_word(cell, verdict) {
            Some(word) => self.one_level.entry(key).or_default().push((word, reading)),
            None => drop(self.readings.entry(key).or_default().insert(reading)),
        }
    }

    /// Every cell's readings, the held ones settled: [`settle_one_level`], then
    /// [`settle_opt_in`].
    fn settled(mut self) -> Readings {
        settle_one_level(&mut self.readings, self.one_level);
        settle_opt_in(&mut self.readings, &self.opt_in);
        self.readings
    }
}

/// One column: a configuration measured under one profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Column {
    distro: String,
    release: String,
    compiler: String,
    compiler_version: String,
    libc: String,
    profile: String,
    /// The image the measurement ran in, and the architecture the toolchain built for
    /// (`toolchain.target.arch`, marked where its witnesses contradict it: `matrix::arch_of`,
    /// as the matrix's key reads it).
    image: String,
    arch: String,
    /// The machine the run had, `env::machine_of` over the report, as `matrix`'s key carries it:
    /// two machines' reports of one image label are two columns, not one whose `bti-enforced`
    /// reads `on` and `?` at once.
    machine: String,
    /// Where the measurement ran (`environment.execution.mode`) and how chard knows
    /// (`environment.execution.mode_evidence.basis`, or [`crate::matrix::UNPUBLISHED_BASIS`]
    /// for a report that carries none).
    execution: String,
    execution_basis: String,
}

/// The axes of a [`Column`], in the order a refusal or a replacement note names them: the
/// order of `matrix`'s key, whose fields these are, except that `libc` is the implementation
/// alone where the matrix's carries its version too.
const COLUMN_AXES: [&str; 11] = [
    "distro",
    "release",
    "compiler",
    "compiler_version",
    "libc",
    "arch",
    "machine",
    "profile",
    "execution",
    "execution_basis",
    "image",
];

impl Column {
    fn axis(&self, name: &str) -> &str {
        match name {
            "distro" => &self.distro,
            "release" => &self.release,
            "compiler" => &self.compiler,
            "compiler_version" => &self.compiler_version,
            "libc" => &self.libc,
            "arch" => &self.arch,
            "machine" => &self.machine,
            "profile" => &self.profile,
            "execution" => &self.execution,
            "execution_basis" => &self.execution_basis,
            "image" => &self.image,
            _ => "",
        }
    }

    /// Every axis and its value, the empty ones as `(none)`: the configuration as a
    /// refusal or a replacement note names it.
    fn describe(&self) -> String {
        COLUMN_AXES
            .iter()
            .map(|a| match self.axis(a) {
                "" => format!("{a} (none)"),
                v => format!("{a} {v}"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn config(&self) -> String {
        format!(
            "{} {} {} {}",
            self.distro, self.release, self.compiler, self.compiler_version
        )
    }

    /// What the profile means to a reader, rather than what it is called.
    fn context(&self) -> String {
        profile_context(&self.profile)
    }
}

/// [`Column::context`] of a `profile.id`: the profile's own reading, then the `+env:` suffix
/// as written where the run had `--env` pairs, so two columns that differ only in their pairs
/// keep the reading and still differ in the header. The pairs themselves are in the reports'
/// `profile.compiler_environment.set`.
fn profile_context(id: &str) -> String {
    let (profile, env) = match id.split_once("+env:") {
        Some((profile, digest)) => (profile, Some(digest)),
        None => (id, None),
    };
    let reading = {
        match profile {
            "bare" => "bare cc",
            // Named for what it measures: the compiler's own defaults under the
            // optimization fortify needs, beside `bare cc` for the
            // compiler-default-gated question.
            "bare-optimized" => "bare cc -O2",
            // A profile this build cannot produce, kept as a decoder for archived
            // reports, which can carry `distro-buildflags`: without the arm a column
            // header would show the raw profile string rather than what it measured.
            "distro-buildflags" => "packages",
            "openssf-tldr" => "guide",
            other => other,
        }
    };
    match env {
        Some(digest) => format!("{reading} +env:{digest}"),
        None => reading.to_owned(),
    }
}

/// Replace control characters with `?`, one for one.
pub(crate) fn scrub(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_format_character(c) || matches!(c, '\u{2028}' | '\u{2029}') {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// `scrub` line by line: within each line every character `scrub` replaces becomes `?`
/// (a tab and a carriage return among them), and the newlines between lines stay. For text
/// whose lines are its layout and which quotes what the operator typed, as clap's help and
/// refusals do.
pub fn scrub_lines(s: &str) -> String {
    s.split('\n').map(scrub).collect::<Vec<_>>().join("\n")
}

/// Is `c` of Unicode general category `Cf` (format), as Unicode 17.0 assigns it?
fn is_format_character(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// `s` as markdown text: a pipe would end a table cell, a backtick open a code span, a
/// backslash escape what follows it, and a `<` open an HTML tag a renderer may honour, so
/// each is escaped. Applied in [`markdown`] to the report strings in the table and in the
/// lists beside it.
fn md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '|' | '`' => {
                out.push('\\');
                out.push(c);
            }
            // A character reference (`&#x202E;`) would decode to what `scrub` removed.
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            _ => out.push(c),
        }
    }
    out
}

/// `s`, chard's own markdown with report strings inside it, with what would turn a report
/// string into markup escaped: `&` and `<` (a character reference, a tag) and `|`. Backticks
/// stay, since chard's own code spans are made of them.
fn md_prose(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '|' => out.push_str("\\|"),
            _ => out.push(c),
        }
    }
    out
}

/// `s` as a markdown code span, where it can be one: a backtick inside would end the span, so
/// such a string is written as escaped text instead. A pipe is escaped either way, which a
/// GitHub table cell reads as a pipe inside a code span too.
fn md_code(s: &str) -> String {
    if s.contains('`') {
        md(s)
    } else {
        format!("`{}`", s.replace('|', "\\|"))
    }
}

/// `s` as a code span in both renderers: fenced by one backtick more than the longest run of
/// them inside it, and padded where it starts or ends with one (the `CommonMark` rule), so a report
/// word ends no span early. A code span decodes no reference and no escape, so nothing else in
/// it is markup.
fn span(s: &str) -> String {
    let mut longest = 0_usize;
    let mut run = 0_usize;
    for c in s.chars() {
        run = if c == '`' { run.saturating_add(1) } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest.saturating_add(1));
    let pad = if s.starts_with('`') || s.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{s}{pad}{fence}")
}

fn text(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    scrub(cur.as_str().unwrap_or(""))
}

/// How directly a protection was observed, as one character.
fn evidence_mark(channels: &BTreeSet<String>) -> char {
    for (channel, mark) in DIRECTNESS {
        if channels.contains(channel) {
            return mark;
        }
    }
    '.'
}

/// The channels a verdict can rest on, most direct first, each with its letter.
const DIRECTNESS: [(&str, char); 4] = [
    ("runtime", 'x'),
    ("elf-static", 'a'),
    ("compiler-diag", 'd'),
    ("macro", 'm'),
];

/// Each row's letter: the least direct of the letters its columns earned, so the one letter
/// beside the row name holds for every cell on the row that carries a verdict. A column where
/// no reading of the row stands earns no letter and lowers no other; a row where none stands
/// anywhere has none, since no letter can say what a withheld cell rests on.
fn row_marks(channels: &BTreeMap<(String, Column), BTreeSet<String>>) -> BTreeMap<String, char> {
    // `.`, an unknown channel, ranks below every letter: it is not promoted by a column
    // that earned a stronger one.
    let rank = |mark: char| {
        DIRECTNESS
            .iter()
            .position(|&(_, m)| m == mark)
            .unwrap_or(DIRECTNESS.len())
    };
    let mut marks: BTreeMap<String, char> = BTreeMap::new();
    for ((row, _), set) in channels {
        let mark = evidence_mark(set);
        marks
            .entry(row.clone())
            .and_modify(|m| {
                if rank(mark) > rank(*m) {
                    *m = mark;
                }
            })
            .or_insert(mark);
    }
    marks
}

/// Whether `level` can stand in a cell for `verdict` without being read as something else:
/// not blank, not carrying `/` or a leading `!` (a split no checks made), and not a glyph
/// unless it is the verdict's own word (relro's `partial` under `partial`). [`render`] and
/// the level split in [`one_cell`] both ask it.
fn shown_as_level(verdict: &str, level: &str) -> bool {
    !level.trim().is_empty()
        && !level.contains('/')
        && !level.starts_with('!')
        && (level == verdict || !glyphs("protection").iter().any(|(g, _)| *g == level))
}

/// Collapse a verdict and level into what belongs in a cell.
fn render(verdict: &str, level: Option<&str>) -> String {
    // Both arms scrub `level`, a foreign report's string.
    let level = level.filter(|l| shown_as_level(verdict, l));
    match verdict {
        "on" => level.map_or_else(|| "on".to_owned(), scrub),
        "partial" => level.map_or_else(|| "partial".to_owned(), scrub),
        "off" => "--".to_owned(),
        // Both are earned limitations with a gating rule behind them: the toolchain lacks
        // the mechanism, or the question has no referent in what was measured.
        "unsupported" | "not-applicable" => "n/a".to_owned(),
        // Both mean the same thing to a reader: no verdict was earned.
        "probe-invalid" | "indeterminate" => "?".to_owned(),
        "build-failed" | "run-failed" => "err".to_owned(),
        other => scrub(other),
    }
}

struct Table {
    /// What the row axis is, so a reader knows whether they are looking at flags
    /// or at the defects those flags bear on.
    heading: &'static str,
    columns: Vec<Column>,
    rows: Vec<String>,
    cells: BTreeMap<(String, Column), String>,
    /// Caveats that travel with the table (a mixed dataset, a revision that corresponds to
    /// no commit), rendered into the output because a warning on stderr is lost when the
    /// output is redirected.
    notes: Vec<String>,
    /// The flags each column's report listed, so a cell absent from an older corpus
    /// can be told from one the distribution declined to enable.
    corpus_flags: BTreeMap<Column, BTreeSet<String>>,
    /// The evidence mark per row, from the readings that stand ([`row_marks`]): one
    /// letter beside the row name that holds for every column with a verdict. A row with no
    /// standing reading in any column has no entry.
    evidence: BTreeMap<String, char>,
    /// Whether the inputs came from more than one probe corpus.
    corpora_differ: bool,
    /// Why each withheld cell was withheld, one [`Withheld`] line each.
    withheld: Vec<Withheld>,
    /// The flags each column's profile passed, spelled for a reader; absent where the
    /// profile passed none. A column header names the profile (`explicit:f9cc1a78b5e6`,
    /// `guide`), which identifies the flags without saying what they were.
    flags: BTreeMap<Column, String>,
    /// What each column measures: its digest's `profile.meaning` ([`profile_meaning`]);
    /// absent where the digest carries none ([`MEANING_UNSTATED`]).
    meanings: BTreeMap<Column, String>,
    /// The columns whose report names a probe corpus other than this build's, or none: the
    /// level sentences come from this build's corpus, so the Levels section names these
    /// columns, where a word may have meant something else.
    other_corpus: BTreeSet<Column>,
    /// The width prose under the grid wraps at; `0` does not wrap. The grid itself is not
    /// wrapped: a row broken across lines stops being a row.
    width: usize,
    /// Each column's `profile-flag-rejected` diagnostics, in the report's order: a flag
    /// the toolchain refused withholds every cell it reached, so it is printed before the
    /// grid, where a reader meets it before the `err` cells it explains.
    rejections: Vec<(Column, String)>,
}

/// Whether an observation's `verdict` (`raw`, before the polarity turn) and `gating`
/// make it an earned limitation, by the rule the report's `coverage.withholding` uses: the
/// class written in `gating.premise`, else this build's table's for `gating.rule`.
fn is_earned(cell: &Value, raw: &str) -> bool {
    use crate::report::gating_rule::{Premise, premise_on_read};
    let gating = cell.get("gating");
    let rule = gating.and_then(|g| g.get("rule")).and_then(Value::as_str);
    let written = gating
        .and_then(|g| g.get("premise"))
        .and_then(Value::as_str)
        .and_then(Premise::from_name);
    Verdict::from_name(raw).is_some_and(|v| {
        crate::report::Standing::of(v, premise_on_read(rule, written))
            == crate::report::Standing::EarnedLimitation
    })
}

/// One withheld cell's line under the table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Withheld {
    column: Column,
    /// The row the cell is in, as the grid names it ([`family`] of the check's flag), so
    /// the line names what a reader sees in the grid: `-Wl,-z,pack-relative-relocs` is
    /// the `relative-relocs` row.
    row: String,
    /// The check's own flag, printed beside the row where the two differ, since one row
    /// collects several checks and a reason belongs to one of them.
    check: String,
    glyph: &'static str,
    reason: String,
    /// Whether the cell is an earned limitation ([`crate::report::Standing`]), listed under
    /// [`SECTIONS`]' first heading; otherwise chard withheld its answer.
    earned: bool,
}

/// The two lists under the table, earned limitations first: the same split, by the same
/// rule, as the report's `coverage.withholding`, so an architecture the target lacks does
/// not read as something chard failed to measure.
const SECTIONS: [(bool, &str); 2] = [(true, "Limitations, and why"), (false, "Withheld, and why")];

/// Each report's `profile-flag-rejected` messages, under its column, in file and then
/// diagnostic order.
fn rejections(reports: &[(String, Value)]) -> Vec<(Column, String)> {
    let mut out = Vec::new();
    for (_, report) in reports {
        let Some(diagnostics) = report.get("diagnostics").and_then(Value::as_array) else {
            continue;
        };
        for d in diagnostics {
            if d.get("context").and_then(Value::as_str)
                == Some(crate::report::PROFILE_FLAG_REJECTED)
            {
                out.push((column_of(report), text(d, &["message"])));
            }
        }
    }
    out
}

/// The rejected profile flags above the grid, one line per column and flag, with the
/// column's heading where the table has more than one; empty where no report has one.
fn rejection_lines(t: &Table, headings: &[String]) -> Vec<String> {
    let multi = t.columns.len() > 1;
    t.rejections
        .iter()
        .map(|(column, message)| {
            let heading = t
                .columns
                .iter()
                .position(|c| c == column)
                .and_then(|i| headings.get(i))
                .filter(|_| multi);
            match heading {
                Some(h) => format!("{h}: {message}"),
                None => message.clone(),
            }
        })
        .collect()
}

/// The column identifying this report, shared by both views.
fn column_of(report: &Value) -> Column {
    Column {
        distro: text(report, &["environment", "distro", "id"]),
        release: text(report, &["environment", "distro", "version_id"]),
        compiler: text(report, &["toolchain", "kind"]),
        compiler_version: text(report, &["toolchain", "version"]),
        libc: text(report, &["environment", "libc", "impl"]),
        profile: text(report, &["profile", "id"]),
        image: text(report, &["environment", "execution", "image"]),
        arch: crate::matrix::arch_of(report),
        machine: crate::env::machine_of(report),
        execution: text(report, &["environment", "execution", "mode"]),
        execution_basis: match text(
            report,
            &["environment", "execution", "mode_evidence", "basis"],
        ) {
            basis if basis.is_empty() => crate::matrix::UNPUBLISHED_BASIS.to_owned(),
            basis => basis,
        },
    }
}

/// Column headings, with whatever it takes to tell them apart.
fn headings(columns: &[Column]) -> Vec<String> {
    let plain: Vec<String> = columns
        .iter()
        .map(|c| format!("{} — {}", c.config(), c.context()))
        .collect();
    columns
        .iter()
        .zip(plain.iter())
        .map(|(c, base)| {
            let shared = plain.iter().filter(|p| *p == base).count() > 1;
            if !shared {
                return base.clone();
            }
            let mut extra: Vec<&str> = Vec::new();
            if !c.image.is_empty() {
                extra.push(&c.image);
            }
            if !c.arch.is_empty() {
                extra.push(&c.arch);
            }
            // Named only where a column of the same heading ran on another machine.
            if columns
                .iter()
                .zip(plain.iter())
                .any(|(other, p)| p == base && other.machine != c.machine)
            {
                extra.push(&c.machine);
            }
            // Named only where a column of the same heading ran elsewhere or on another
            // basis, so a table of one provenance keeps its headings.
            let mode = if c.execution.is_empty() {
                "mode unpublished"
            } else {
                c.execution.as_str()
            };
            let provenance = format!("{mode} on {}", c.execution_basis);
            let varies = columns.iter().zip(plain.iter()).any(|(other, p)| {
                p == base
                    && (other.execution != c.execution
                        || other.execution_basis != c.execution_basis)
            });
            if varies {
                extra.push(&provenance);
            }
            if extra.is_empty() {
                base.clone()
            } else {
                format!("{base} [{}]", extra.join(" "))
            }
        })
        .collect()
}

/// One defect row's cell, from the report's own `defect_coverage` entry: what both the grid
/// and a replacement note ([`defect_replacement`]) read, so the note names a row exactly where
/// the grid would draw it differently.
fn defect_cell(entry: &Value) -> String {
    let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
    // Whether the report's own evidence for this defect was complete: one glyph for
    // `not-mitigated` over partly-withheld checks and over checks that all answered would
    // read a partly-measured defect as a measured absence.
    let bearing = entry
        .get("from_checks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    // Answered: a protection check's three verdicts, and a request's or marking's own keys
    // (`report::defect_coverage`), which answer what they observe and move no status.
    let decided: u64 = entry
        .get("verdict_counts")
        .and_then(Value::as_object)
        .map_or(0, |c| {
            c.iter()
                .filter(|(k, _)| {
                    crate::report::RollupKey::from_name(k)
                        .is_some_and(crate::report::RollupKey::answers)
                })
                .filter_map(|(_, v)| v.as_u64())
                .sum()
        });
    let bearing = u64::try_from(bearing).unwrap_or(u64::MAX);
    let partly_withheld = bearing > 0 && decided < bearing;
    match status {
        "mitigated" => "yes".to_owned(),
        // Deliberately not collapsed into `yes`: partial RELRO and full
        // RELRO must not print the same cell, since the difference is
        // exactly what the packaging buys.
        "partial" => "part".to_owned(),
        // `--?` where some bearing check was withheld.
        "not-mitigated" if partly_withheld => "--?".to_owned(),
        "not-mitigated" => "--".to_owned(),
        // `unknown` is what `defect_coverage` emits and what the schema enumerates.
        "" | "unknown" => "?".to_owned(),
        other => scrub(other),
    }
}

/// Rows are defect classes rather than flags: what is protected, not what is set.
fn collect_defects(reports: &[(String, Value)]) -> Result<Table> {
    let mut columns: BTreeSet<Column> = BTreeSet::new();
    let mut rows: BTreeSet<String> = BTreeSet::new();
    let mut cells: BTreeMap<(String, Column), String> = BTreeMap::new();
    let mut corpus_flags: BTreeMap<Column, BTreeSet<String>> = BTreeMap::new();

    for (name, report) in reports {
        let Some(coverage) = report.get("defect_coverage").and_then(Value::as_object) else {
            return Err(crate::dataset::not_a_report(name, "it carries no defect_coverage").into());
        };
        let column = column_of(report);
        columns.insert(column.clone());
        corpus_flags.insert(column.clone(), crate::dataset::flags_of(report));
        for (defect, entry) in coverage {
            rows.insert(defect.clone());
            cells.insert((defect.clone(), column.clone()), defect_cell(entry));
        }
    }

    Ok(Table {
        heading: "defect",
        columns: columns.into_iter().collect(),
        rows: in_row_order(rows),
        cells,
        flags: column_flags(reports),
        meanings: column_meanings(reports),
        other_corpus: BTreeSet::new(),
        width: DEFAULT_WIDTH,
        notes: Vec::new(),
        // A defect row aggregates protections measured through different channels, so no
        // single mark describes it, and none is invented.
        evidence: BTreeMap::new(),
        corpus_flags,
        withheld: Vec::new(),
        corpora_differ: false,
        rejections: rejections(reports),
    })
}

fn collect(reports: &[(String, Value)]) -> Result<Table> {
    let mut columns: BTreeSet<Column> = BTreeSet::new();
    let mut rows: BTreeSet<String> = BTreeSet::new();
    let mut withheld: Vec<Withheld> = Vec::new();
    let mut acc = Accumulator::default();
    let mut corpus_flags: BTreeMap<Column, BTreeSet<String>> = BTreeMap::new();
    let mut channels: BTreeMap<(String, Column), BTreeSet<String>> = BTreeMap::new();

    for (name, report) in reports {
        let Some(observations) = report.get("observations").and_then(Value::as_array) else {
            return Err(crate::dataset::not_a_report(name, "it carries no observations").into());
        };
        let column = column_of(report);
        columns.insert(column.clone());
        corpus_flags.insert(column.clone(), crate::dataset::flags_of(report));

        // One observation per flag, held by `probe::tests::every_check_has_a_distinct_flag`;
        // the `matrix` rollup would re-key this list one to one, so it is not read.
        for cell in observations {
            let Some(flag) = cell.get("flag").and_then(Value::as_str) else {
                continue;
            };
            let fam = family(flag);
            rows.insert(fam.clone());
            let raw = cell.get("verdict").and_then(Value::as_str).unwrap_or("");
            // In protection terms, not verdict terms: for a `weaken` flag the two are
            // opposites, and the row axis is headed `protection`.
            let weakens = cell.get("polarity").and_then(Value::as_str) == Some("weaken");
            let polarity = if weakens {
                probe::Polarity::Weaken
            } else {
                probe::Polarity::Harden
            };
            let verdict = Verdict::from_name(raw).map_or(raw, |v| {
                crate::report::protection_term(probe::Observes::Protection, polarity, v).as_str()
            });
            let level = cell.get("level").and_then(Value::as_str);
            // Only a reading that stands says what its row rests on (no `cet x` over an
            // `indeterminate` `shadow-stack-enforced`).
            if Verdict::from_name(raw).is_some_and(Verdict::is_measurement) {
                let channel = cell.get("channel").and_then(Value::as_str).unwrap_or("");
                channels
                    .entry((fam.clone(), column.clone()))
                    .or_default()
                    .insert(scrub(channel));
            }
            // The reason, while the observation is in hand.
            let glyph = match verdict {
                "unsupported" | "not-applicable" => Some("n/a"),
                "probe-invalid" | "indeterminate" => Some("?"),
                "build-failed" | "run-failed" => Some("err"),
                _ => None,
            };
            if let Some(glyph) = glyph {
                // `Option` all the way through: a report with no reason for a withheld
                // cell contributes no line, and an empty-string default could not tell
                // absent from present and blank.
                let gating_reason = cell
                    .get("gating")
                    .and_then(|g| g.get("reason"))
                    .and_then(Value::as_str);
                let observed = cell
                    .get("evidence")
                    .and_then(|e| e.get("observed"))
                    .and_then(Value::as_str);
                let reason = match verdict {
                    "unsupported" | "not-applicable" => gating_reason,
                    "build-failed" => cell.get("build_rejection").and_then(Value::as_str),
                    // `level-outside-check-scale` and `macro-supplied-by-profile` withhold
                    // an `indeterminate` by rule, and the rule's sentence is the reason;
                    // `observed` is what the detector saw before the rule spoke.
                    "indeterminate" => gating_reason.or(observed),
                    _ => observed,
                };
                // One rule for every verdict here, and it is this filter: a withheld cell
                // contributes a line only where the report says why.
                if let Some(reason) = reason.filter(|r| !r.trim().is_empty()) {
                    withheld.push(Withheld {
                        column: column.clone(),
                        row: scrub(&fam),
                        check: scrub(flag),
                        glyph,
                        reason: scrub(reason),
                        earned: is_earned(cell, raw),
                    });
                }
            }

            acc.file(cell, verdict, level, (fam, column.clone()));
        }
    }
    let cells = acc
        .settled()
        .into_iter()
        .map(|(k, seen)| {
            let rendered = one_cell(&seen);
            (k, rendered)
        })
        .collect();

    Ok(Table {
        heading: "protection",
        columns: columns.into_iter().collect(),
        rows: in_row_order(rows),
        cells,
        withheld: in_grid_order(withheld),
        flags: column_flags(reports),
        meanings: column_meanings(reports),
        other_corpus: other_corpus(reports),
        width: DEFAULT_WIDTH,
        notes: Vec::new(),
        evidence: row_marks(&channels),
        corpus_flags,
        corpora_differ: false,
        rejections: rejections(reports),
    })
}

/// One cell, from every reading the family collected in that column.
fn one_cell(seen: &BTreeSet<Reading>) -> String {
    // Conflict about presence is an `off` beside a present reading, not a difference in how
    // finely or against what a check reports it: `-fstack-protector-strong`'s level `strong`
    // beside the artifact check's plain `on`, or an ungraded `on` beside a graded `partial`,
    // all say present, and a conflict there would cry wolf on every multi-channel family.
    let measured: BTreeSet<&str> = seen
        .iter()
        .filter(|(v, _, _)| matches!(v.as_str(), "on" | "off" | "partial"))
        .map(|(v, _, _)| v.as_str())
        .collect();

    if measured.len() > 1 && measured.contains("off") {
        let mut names: Vec<&str> = measured.into_iter().collect();
        names.sort_unstable();
        return format!("!{}", names.join("/"));
    }
    if measured.is_empty() {
        // Nothing was measured; report the shared non-measurement rather
        // than inventing agreement.
        let mut others: Vec<&str> = seen.iter().map(|(v, _, _)| v.as_str()).collect();
        others.sort_unstable();
        others.dedup();
        return others
            .first()
            .map_or_else(|| ".".to_owned(), |v| render(v, None));
    }
    if measured.contains("off") {
        return render("off", None);
    }

    // Present from here on.
    let verdict = if measured.contains("partial") {
        "partial"
    } else {
        "on"
    };
    let present = |(v, _, _): &&Reading| is_present(v);
    let cell_is_short = is_short(verdict);
    // Two readings graded against one ask read one scale, and different words there are a
    // disagreement about the level, shown as one about presence is:
    // `!all/unsafe-frame` for the stack protector under clang's `-fsanitize=safe-stack`
    // (the macro reading `all`, the object `unsafe-frame`, clang 22.1.8, 2026-10-08), where
    // showing `all` would contradict the report's own corroboration.
    let mut by_ask: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (level, ask) in seen
        .iter()
        .filter(present)
        .filter_map(|(_, level, ask)| level.as_deref().zip(ask.as_deref()))
    {
        by_ask.entry(ask).or_default().insert(level);
    }
    let split: BTreeSet<&str> = by_ask
        .values()
        .filter(|words| words.len() > 1)
        .flatten()
        .copied()
        .collect();
    if !split.is_empty() {
        // A word that could not stand alone in a cell cannot stand in a split either
        // (`!n/a/strong` would read as three words).
        if split.iter().all(|w| shown_as_level(verdict, w)) {
            let words: Vec<String> = split.into_iter().map(scrub).collect();
            return format!("!{}", words.join("/"));
        }
        return render(verdict, None);
    }
    // Among checks that carry a level, a graded reading's word wins (fortify's `3` over a
    // bare `on`) and the rest tie-break in the set's own order, not by a ranking, which
    // would put vocabularies that share no scale on one ladder: the pie family's cell holds
    // `pie` beside `__PIE__`'s `2`, and with `pie` ungraded shows `2`.
    let best = seen
        .iter()
        .filter(present)
        .filter_map(|(v, l, ask)| {
            l.as_deref()
                .map(|l| (!is_short(v), ask.is_none(), l, v.as_str()))
        })
        .min_by_key(|&(at_ask, ungraded, l, _)| (at_ask, ungraded, l));
    match best {
        // The best reading is `on` while the cell is short only where no `partial` names a level.
        Some((_, _, level, v)) if shown_as_level(v, level) && is_short(v) == cell_is_short => {
            render(v, Some(level))
        }
        _ => render(verdict, None),
    }
}

/// Whether a verdict (in protection terms) finds the protection present: `on` or `partial`.
fn is_present(verdict: &str) -> bool {
    matches!(verdict, "on" | "partial")
}

/// Whether a verdict finds the protection present short of the level its check asks for.
fn is_short(verdict: &str) -> bool {
    verdict == "partial"
}

/// What belongs in a cell, distinguishing three kinds of nothing.
fn cell_for(t: &Table, row: &str, col: &Column) -> String {
    if let Some(cell) = t.cells.get(&(row.to_owned(), col.clone())) {
        return cell.clone();
    }
    if !t.corpora_differ {
        return ".".to_owned();
    }
    let known_elsewhere = t
        .corpus_flags
        .values()
        .any(|flags| flags.iter().any(|f| family(f) == row));
    let in_this_corpus = t
        .corpus_flags
        .get(col)
        .is_some_and(|flags| flags.iter().any(|f| family(f) == row));
    if known_elsewhere && !in_this_corpus {
        return "~".to_owned();
    }
    ".".to_owned()
}

/// Render as GitHub-flavoured markdown.
fn markdown(t: &Table) -> String {
    let mut out = String::new();
    let rejected = rejection_lines(t, &headings(&t.columns));
    if !rejected.is_empty() {
        out.push_str("**Profile flags the toolchain rejected**\n\n");
        for line in &rejected {
            crate::error::best_effort(writeln!(out, "- {}", md(line)));
        }
        out.push('\n');
    }
    crate::error::best_effort(write!(out, "| {} |", t.heading));
    for h in headings(&t.columns) {
        crate::error::best_effort(write!(out, " {} |", md(&h)));
    }
    out.push_str("\n|---|");
    for _ in &t.columns {
        out.push_str("---|");
    }
    out.push('\n');
    for row in &t.rows {
        crate::error::best_effort(write!(out, "| {} |", md_code(&row_label(t, row))));
        for c in &t.columns {
            crate::error::best_effort(write!(out, " {} |", md(&cell_for(t, row, c))));
        }
        out.push('\n');
    }
    for paragraph in legend(t.heading).split("\n\n") {
        out.push('\n');
        out.push_str(paragraph);
        out.push('\n');
    }
    let levels = level_lines(t);
    if !levels.is_empty() {
        out.push_str("\n**Levels in this table**\n\n");
        crate::error::best_effort(writeln!(
            out,
            "{}\n",
            levels_provenance(
                t,
                &headings(&t.columns)
                    .iter()
                    .map(|h| md(h))
                    .collect::<Vec<_>>()
            )
        ));
        for (row, words, gloss) in &levels {
            let rows: Vec<String> = row.iter().map(|r| md_code(r)).collect();
            crate::error::best_effort(writeln!(out, "- {} {words}: {gloss}", rows.join(", ")));
        }
    }
    if !t.columns.is_empty() {
        crate::error::best_effort(write!(out, "\n**{FLAGS_HEADING}**\n\n"));
        for (column, heading) in t.columns.iter().zip(headings(&t.columns)) {
            let flags = t.flags.get(column).map_or("none", String::as_str);
            crate::error::best_effort(writeln!(out, "- {}: {}", md(&heading), md(flags)));
            // The digest's sentence, which the read held to the one this build derives: chard's
            // own words with their code spans, scrubbed, so `md_prose` and not `md`.
            crate::error::best_effort(writeln!(
                out,
                "  - measures: {}",
                md_prose(meaning_of(t, column))
            ));
        }
        crate::error::best_effort(write!(out, "\n{MEANING_FIELDS}\n"));
    }
    for (earned, title) in SECTIONS {
        if !t.withheld.iter().any(|w| w.earned == earned) {
            continue;
        }
        crate::error::best_effort(write!(out, "\n**{title}**\n\n"));
        let multi = t.columns.len() > 1;
        for (column, heading) in t.columns.iter().zip(headings(&t.columns)) {
            let mut lines = t
                .withheld
                .iter()
                .filter(|w| w.column == *column && w.earned == earned)
                .peekable();
            if lines.peek().is_none() {
                continue;
            }
            let indent = if multi {
                crate::error::best_effort(writeln!(out, "- {}", md(&heading)));
                "  "
            } else {
                ""
            };
            for w in lines {
                let name = match withheld_label(w) {
                    (row, Some(check)) => format!("{} ({})", md_code(row), md_code(check)),
                    (named, None) => md_code(named),
                };
                crate::error::best_effort(writeln!(
                    out,
                    "{indent}- {} {name}: {}",
                    md_code(w.glyph),
                    md(&w.reason)
                ));
            }
        }
    }
    // The notes are chard's own markdown, code spans included, around report strings
    // (`harness_revision`, a file name) that `scrub` has cleared of controls: a character
    // reference, a tag and a pipe are escaped, and the backticks are left to the spans.
    out.push_str(&md_prose(&notes(t)));
    out
}

/// The key to the glyphs, for whichever row axis is in use, as paragraphs separated by a
/// blank line; each renderer lays them out ([`plain`] wraps them at the table's width).
fn legend(heading: &str) -> String {
    let glyphs = glyphs(heading)
        .iter()
        .map(|(glyph, meaning)| format!("`{glyph}` {meaning}"))
        .collect::<Vec<_>>()
        .join(", ");
    let one_level = check_names(ONE_LEVEL_CHECKS);
    let opt_in = check_names(crate::report::OPT_IN_LEVELS);
    match heading {
        "defect" => format!("Legend: {glyphs}."),
        _ => format!(
            "Legend: a level where the check reports one (each level word in the table is \
             defined under \"Levels in this table\"), {glyphs}, `!a/b` checks within one \
             protection disagreed, about whether it is present (`!off/on`: one check read \
             `off` and another `on`) or, where checks on one graded scale read different \
             words, about its level (`!all/unsafe-frame`: the level the macro announced beside \
             the selection the object carries; `!1/3`: level 1 beside level 3, such as the level \
             requested beside the level in force). A check that finds it present at no level \
             does not disagree with one that names a level, except {one_level}, each asking \
             about one level alone, whose `on` is that level and whose `off` denies only that \
             level. An `off` beside a level that reaches only code which opts in ({opt_in}) is \
             no disagreement either, since no probe's code opts in: the cell shows that level. \
             Where several checks in one protection find it present, the \
             cell shows a level short of its ask first, then a graded check's level, and \
             otherwise the first in sorted order; where a check found it short at no level, \
             the cell is `partial`. Every `n/a`, `?` and \
             `err` whose report gives a reason is listed below the \
             table with that reason: an `n/a` its gating rule earns under \"Limitations, and \
             why\", where the measured system lacks the mechanism or the question does not \
             apply, and the rest under \"Withheld, and why\", where the check earned no \
             verdict. Rows are in alphabetical order of their names, ignoring \
             leading dashes and case.\n\nThe letter after each protection is what the verdict \
             rests on, most direct first: `x` the probe was run and the mitigation observed \
             to act or not to, `a` a property read from the compiled artifact, `d` the \
             compiler's own diagnostic, `m` a macro the compiler defined -- its claim about \
             itself, and `.` after a protection's name a channel this table does not name, or \
             none. A verdict is only as good as its letter, and `m` alone is the \
             compiler taking its own word for it. The letter is read from the checks whose \
             verdict stands (`on`, `off` or `partial`), never from an `n/a`, which rests on its \
             gating rule, or a withheld one. Where the columns differ it is the least direct \
             of theirs; a column with no verdict standing earns none and lowers no other, and a \
             protection with no verdict standing in any column carries none.\n\n\
             A row for a flag that weakens a protection (`polarity` `weaken` in the \
             report, such as `-Wl,-rpath`) reads in protection terms, so its cell is the \
             report's verdict inverted: `on` where the report says `off`, the flag's effect \
             being absent, which is the protected state, and `--` where it says `on`."
        ),
    }
}

/// A list of checks and level words as the legend names them, each check with its word, in
/// the list's order: [`ONE_LEVEL_CHECKS`] and [`crate::report::OPT_IN_LEVELS`].
fn check_names(list: &[(&str, &str)]) -> String {
    let names: Vec<String> = list
        .iter()
        .map(|(id, word)| format!("`{id}` (`{word}`)"))
        .collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => names.concat(),
    }
}

/// The fixed words a cell can show for a row axis, each with its meaning, in the order the
/// legend prints them. One list for the legend and for [`level_words`], which reads every
/// other word in a cell as a level; `every_word_a_cell_can_show_is_defined_beside_the_table`
/// holds the renderer to it by membership, so a glyph is defined here or not at all.
fn glyphs(heading: &str) -> &'static [(&'static str, &'static str)] {
    match heading {
        "defect" => &[
            (
                "yes",
                "every contributing check that observes protection is on and none was withheld",
            ),
            ("part", "some are"),
            ("--", "none is"),
            (
                "--?",
                "none of the checks that answered found one and not all of them answered",
            ),
            (
                "?",
                "no contributing check observed protection or its absence",
            ),
            (".", "not measured"),
            ("~", "not in that report's probe corpus"),
        ],
        _ => &[
            ("on", "present where the check reports no level"),
            (
                "partial",
                "present, short of the level the check is graded against",
            ),
            ("--", "off"),
            ("n/a", "the question does not apply here"),
            (
                "?",
                "withheld because the evidence did not support a verdict",
            ),
            ("err", "the probe failed to build or to run"),
            (".", "not measured"),
            ("~", "not in that report's probe corpus"),
        ],
    }
}

/// What the words of each level vocabulary in the corpus mean, for the levels under a table.
const LEVEL_GLOSSES: &[(Levels, Option<&str>, &str)] = &[
    (
        probe::SSP_LEVELS,
        None,
        "which functions the stack protector gave a canary.",
    ),
    (
        probe::FORTIFY_LEVELS,
        Some("fortify"),
        "the `_FORTIFY_SOURCE` level, a whole number such as `2` or `3`.",
    ),
    (
        probe::RELRO_LEVELS,
        None,
        "`partial` the read-only-after-relocation segment alone, `full` that segment with `BIND_NOW`.",
    ),
    (
        probe::FLEX_ARRAY_LEVELS,
        Some("-fstrict-flex-arrays"),
        "the `-fstrict-flex-arrays` level, a whole number from `1` to `3`, read from which \
         trailing-array spellings the compiler bounded.",
    ),
    (
        probe::CFI_COMPONENTS,
        None,
        "which control-flow-integrity components are present.",
    ),
    (
        probe::AUTO_VAR_FILL,
        None,
        "what uninitialized locals are filled with.",
    ),
    (
        probe::ZERO_CALL_USED_REGS,
        None,
        "which registers are cleared before a return.",
    ),
    (
        probe::DIAG_ERROR,
        None,
        "`error` the compiler rejected the construct as an error.",
    ),
    (
        probe::SHADOW_STACK_DEFAULT,
        None,
        "where the x86 shadow stack was enforced.",
    ),
    (
        probe::CODE_MODEL,
        None,
        "the value of `__PIE__` or `__PIC__`.",
    ),
    (
        probe::PIE_FLAVOUR,
        None,
        "`pie` the executable is position-independent.",
    ),
    (
        probe::SEARCH_PATH_KIND,
        None,
        "which search-path tag the object carries.",
    ),
    (
        probe::TEXTREL_WORD,
        None,
        "`textrel` the object carries text relocations.",
    ),
    (
        probe::DIAG_SEVERITY,
        None,
        "the severity on the diagnostic's own line.",
    ),
    (
        probe::PATTERN_FILL,
        None,
        "`pattern` uninitialized locals are filled with a repeated pattern.",
    ),
    (
        probe::LIBCPP_MODES,
        None,
        "libc++'s hardening mode, weakest first.",
    ),
    (
        probe::UBSAN_TRAP_INSN,
        None,
        "the trap instruction the sanitizer emitted.",
    ),
];

/// A level vocabulary's sentence under a table, for a check in `row`: its gloss from
/// [`LEVEL_GLOSSES`], then what the vocabulary itself says about grading. `None` for a
/// vocabulary with no entry, which `every_level_vocabulary_in_the_corpus_is_glossed` keeps
/// from happening in the corpus.
fn level_gloss(levels: &Levels, row: &str) -> Option<String> {
    let gloss = gloss_entry(levels, row)?;
    Some(match levels.recommended() {
        Some(ask) => format!("{gloss} Graded against `{ask}`."),
        None => format!("{gloss} Information beside the verdict."),
    })
}

/// The [`LEVEL_GLOSSES`] sentence for a vocabulary in `row`, without the grading clause.
fn gloss_entry(levels: &Levels, row: &str) -> Option<&'static str> {
    LEVEL_GLOSSES
        .iter()
        .find(|(known, only, _)| known == levels && only.is_none_or(|only| only == row))
        .map(|(_, _, gloss)| *gloss)
}

/// The sentence opening the Levels section: whose corpus the meanings are, and which columns
/// came from another. `headings` is the renderer's own spelling of the column headings.
fn levels_provenance(t: &Table, headings: &[String]) -> String {
    let others: Vec<&str> = t
        .columns
        .iter()
        .zip(headings)
        .filter(|(c, _)| t.other_corpus.contains(c))
        .map(|(_, h)| h.as_str())
        .collect();
    let mut sentence =
        "Each meaning is the one this build's probe corpus gives the word.".to_owned();
    if !others.is_empty() {
        crate::error::best_effort(write!(
            sentence,
            " These columns' reports name another probe corpus or none, where a word may have \
             meant something else: {}.",
            others.join("; ")
        ));
    }
    sentence
}

/// The level words a rendered cell carries, including each word of a level split
/// (`!all/unsafe-frame`): every word one of the row's vocabularies admits, and every other
/// word the legend's fixed glyphs (or, in a split, the verdict words) do not define.
fn level_words<'a>(cell: &'a str, admitted: &dyn Fn(&str) -> bool) -> Vec<&'a str> {
    let fixed = |word: &str| glyphs("protection").iter().any(|(glyph, _)| *glyph == word);
    match cell.strip_prefix('!') {
        // A split's words are verdicts (`!off/on`), which the legend's sentence on the
        // marker defines, or levels (`!all/unsafe-frame`).
        Some(split) => split
            .split('/')
            .filter(|w| admitted(w) || !matches!(*w, "on" | "off" | "partial"))
            .collect(),
        None if admitted(cell) || !fixed(cell) => vec![cell],
        None => Vec::new(),
    }
}

/// The "Levels in this table" lines: the rows whose cells show the same level words with the
/// same meaning, those words (each in backticks), and what they mean.
fn level_lines(t: &Table) -> Vec<(Vec<String>, String, String)> {
    if t.heading == "defect" {
        return Vec::new();
    }
    let mut lines: Vec<(Vec<String>, String, String)> = Vec::new();
    for row in &t.rows {
        let vocabularies: BTreeSet<Levels> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|check| family(check.flag) == *row)
            .map(|check| check.levels)
            .collect();
        let admitted = |word: &str| vocabularies.iter().any(|l| l.admits(word));
        let mut words: BTreeSet<&str> = BTreeSet::new();
        for column in &t.columns {
            if let Some(cell) = t.cells.get(&(row.clone(), column.clone())) {
                words.extend(level_words(cell, &admitted));
            }
        }
        if words.is_empty() {
            continue;
        }
        let mut glosses: Vec<String> = Vec::new();
        let mut undefined: Vec<&str> = Vec::new();
        for word in &words {
            let admitting: Vec<&Levels> = vocabularies.iter().filter(|l| l.admits(word)).collect();
            if admitting.is_empty() {
                undefined.push(word);
            }
            for levels in admitting {
                let gloss = level_gloss(levels, row)
                    .unwrap_or_else(|| "a level word of this row's check.".to_owned());
                if !glosses.contains(&gloss) {
                    glosses.push(gloss);
                }
            }
        }
        if !undefined.is_empty() {
            glosses.push(format!(
                "{} {} not a level this build's probe corpus defines for this row; the \
                 report's own observation is the only account of {}.",
                undefined
                    .iter()
                    .map(|w| span(w))
                    .collect::<Vec<_>>()
                    .join(", "),
                if undefined.len() == 1 { "is" } else { "are" },
                if undefined.len() == 1 { "it" } else { "them" },
            ));
        }
        let shown = words.iter().map(|w| span(w)).collect::<Vec<_>>().join(", ");
        let gloss = glosses.join(" ");
        match lines
            .iter_mut()
            .find(|(_, w, g)| *w == shown && *g == gloss)
        {
            Some((rows, _, _)) => rows.push(scrub(row)),
            None => lines.push((vec![scrub(row)], shown, gloss)),
        }
    }
    lines
}

/// [`profile_flags`] per column, for the columns whose profile passed any.
fn column_flags(reports: &[(String, Value)]) -> BTreeMap<Column, String> {
    reports
        .iter()
        .filter_map(|(_, report)| Some((column_of(report), profile_flags(report)?)))
        .collect()
}

/// The title of the block under the grid that gives, per column, the flags its profile
/// passed and what the column measures. Printed for every table, a `bare` one included, so
/// the table says that such a column is the compiler's defaults and not what a
/// distribution's package build gets.
const FLAGS_HEADING: &str = "Flags each column passed, and what it measures";

/// The line under that block that says where the fields its `measures:` sentences cite are
/// read: the table prints none of them, so the line names the fields and prints no value.
const MEANING_FIELDS: &str = "The other fields these sentences cite are not printed here.";

/// What a column says it measures where its report's digest carries no `profile.meaning`.
/// The read `chard table` makes refuses such a report before anything is drawn (a report with
/// no digest, or one whose digest disagrees with its fields), so this is a guard for a caller
/// that draws a table from reports read some other way, and no published report reaches it.
const MEANING_UNSTATED: &str = "not stated: the report's digest carries no `profile.meaning`";

/// [`profile_meaning`] per column, for the columns whose report carries one.
fn column_meanings(reports: &[(String, Value)]) -> BTreeMap<Column, String> {
    reports
        .iter()
        .filter_map(|(_, report)| Some((column_of(report), profile_meaning(report)?)))
        .collect()
}

/// A column's meaning, or [`MEANING_UNSTATED`].
fn meaning_of<'a>(t: &'a Table, column: &Column) -> &'a str {
    t.meanings
        .get(column)
        .map_or(MEANING_UNSTATED, String::as_str)
}

/// What a report's column measures: its digest's `profile.meaning`, scrubbed as every report
/// string is. The read the table makes refuses a report whose stored sentence is not the one
/// [`crate::report::digest::meaning`] derives from its `profile.flags_source`,
/// `toolchain.config_files` and `profile.id` (the `digest-disagrees-with-report` rule), so the
/// sentence printed is the one this build derives. `None` where the digest carries none.
fn profile_meaning(report: &Value) -> Option<String> {
    let meaning = report
        .get("digest")?
        .get("profile")?
        .get("meaning")?
        .as_str()?;
    Some(scrub(meaning))
}

/// The columns whose report names a probe corpus other than this build's, or none.
fn other_corpus(reports: &[(String, Value)]) -> BTreeSet<Column> {
    let this = probe::corpus_sha256();
    reports
        .iter()
        .filter(|(_, report)| text(report, &["run", "probe_corpus_sha256"]) != this)
        .map(|(_, report)| column_of(report))
        .collect()
}

/// The flags a report's profile passed, as `cflags: ...; ldflags: ...`, scrubbed: a
/// foreign report's strings. `None` where every list is absent or empty, as under `bare`.
fn profile_flags(report: &Value) -> Option<String> {
    let profile = report.get("profile")?;
    let parts: Vec<String> = ["cflags", "cxxflags", "ldflags"]
        .into_iter()
        .filter_map(|key| {
            let flags: Vec<String> = profile
                .get(key)?
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .map(scrub)
                .collect();
            (!flags.is_empty()).then(|| format!("{key}: {}", flags.join(" ")))
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// The order rows are printed in: alphabetical by name with leading dashes dropped and case
/// folded, then by the name as written, so the order is total. Byte order would group rows
/// by how their flag is spelled (`--param`, `-D`, `-f`, then `cet`) rather than by name.
fn row_key(row: &str) -> (String, &str) {
    (row.trim_start_matches('-').to_lowercase(), row)
}

/// Withheld lines in the grid's order, column by column and row by row, rather than in the
/// order the reports were given and their observations listed.
fn in_grid_order(mut withheld: Vec<Withheld>) -> Vec<Withheld> {
    withheld.sort_by(|a, b| {
        (&a.column, row_key(&a.row), &a.check).cmp(&(&b.column, row_key(&b.row), &b.check))
    });
    withheld
}

/// Rows in [`row_key`] order.
fn in_row_order(rows: BTreeSet<String>) -> Vec<String> {
    let mut rows: Vec<String> = rows.into_iter().collect();
    rows.sort_by(|a, b| row_key(a).cmp(&row_key(b)));
    rows
}

/// `text` as lines no wider than `width` characters where its words allow, the first line
/// starting with `first` and the rest with `rest`. A word longer than the line is kept
/// whole on a line of its own rather than broken. `width` 0 does not wrap. Runs of
/// whitespace in `text` collapse to one space.
fn wrap(text: &str, width: usize, first: &str, rest: &str) -> String {
    let mut out = String::new();
    let mut line = String::from(first);
    let mut bare = true;
    for word in text.split_whitespace() {
        let fits = line
            .chars()
            .count()
            .saturating_add(1)
            .saturating_add(word.chars().count())
            <= width;
        if !bare && width > 0 && !fits {
            out.push_str(&line);
            out.push('\n');
            line = String::from(rest);
            bare = true;
        }
        if !bare {
            line.push(' ');
        }
        line.push_str(word);
        bare = false;
    }
    out.push_str(&line);
    out.push('\n');
    out
}

/// Why each withheld cell was withheld, under the table, grouped by column in the grid's
/// order and named by the row the cell is in.
fn withheld_reasons(t: &Table) -> String {
    let mut out = String::new();
    let multi = t.columns.len() > 1;
    for (earned, title) in SECTIONS {
        if !t.withheld.iter().any(|w| w.earned == earned) {
            continue;
        }
        out.push('\n');
        out.push_str(title);
        out.push_str(":\n");
        for (column, heading) in t.columns.iter().zip(plain_headings(&t.columns)) {
            let mut lines = t
                .withheld
                .iter()
                .filter(|w| w.column == *column && w.earned == earned)
                .peekable();
            if lines.peek().is_none() {
                continue;
            }
            let indent = if multi {
                out.push_str(&wrap(&format!("{heading}:"), t.width, "  ", "    "));
                "    "
            } else {
                "  "
            };
            for w in lines {
                let name = match withheld_label(w) {
                    (row, Some(check)) => format!("{row} ({check})"),
                    (named, None) => named.to_owned(),
                };
                let head = format!("{indent}{:<4} ", w.glyph);
                let hang = " ".repeat(head.chars().count());
                out.push_str(&wrap(&name, t.width, &head, &hang));
                out.push_str(&wrap(&w.reason, t.width, &hang, &hang));
            }
        }
    }
    out
}

/// Caveats that travel with the table: rendered into the output, since a warning left on
/// stderr does not survive the table's paste into an issue or a report.
fn notes(t: &Table) -> String {
    if t.notes.is_empty() {
        return String::new();
    }
    let mut out = String::from("\n");
    for note in &t.notes {
        // Scrubbed here rather than at each push site: a note carries a foreign report's
        // dataset-identity strings (`harness_revision`, `probe_corpus_sha256`) by several
        // routes, and the render is the one chokepoint a later route cannot bypass.
        out.push_str(&wrap(&scrub(note), t.width, "!! ", "   "));
    }
    out
}

/// The row label: the protection name, scrubbed, carrying its evidence mark where it has
/// one.
fn row_label(t: &Table, row: &str) -> String {
    let row = scrub(row);
    match t.evidence.get(&row) {
        Some(mark) => format!("{row} {mark}"),
        None => row,
    }
}

/// `s` left-aligned in `width` characters, the padding `{:<width$}` gives.
fn padded(s: &str, width: usize) -> String {
    let mut out = String::from(s);
    out.extend(std::iter::repeat_n(
        ' ',
        width.saturating_sub(s.chars().count()),
    ));
    out
}

/// [`headings`] as the plain renderer prints them.
fn plain_headings(columns: &[Column]) -> Vec<String> {
    headings(columns)
        .into_iter()
        .map(|h| h.replace(" — ", " "))
        .collect()
}

/// Render as aligned plain text: the rejected profile flags, the grid, then the legend, the
/// levels, the flags each column passed, the withheld reasons and the notes, each wrapped at
/// the table's width.
fn plain(t: &Table) -> String {
    let width = |s: &str| s.chars().count();
    let row_width = t
        .rows
        .iter()
        .map(|r| width(&row_label(t, r)))
        .max()
        .unwrap_or(10)
        .max(10);
    let headers = plain_headings(&t.columns);
    let col_widths: Vec<usize> = headers.iter().map(|h| width(h).max(8)).collect();
    let rule: usize = col_widths
        .iter()
        .map(|w| w.saturating_add(2))
        .sum::<usize>()
        .saturating_add(row_width);

    let mut out = String::new();
    let rejected = rejection_lines(t, &headers);
    if !rejected.is_empty() {
        out.push_str("Profile flags the toolchain rejected:\n");
        for line in &rejected {
            out.push_str(&wrap(line, t.width, "!! ", "   "));
        }
        out.push('\n');
    }
    crate::error::best_effort(write!(out, "{}", padded(t.heading, row_width)));
    for (h, w) in headers.iter().zip(&col_widths) {
        crate::error::best_effort(write!(out, "  {}", padded(h, *w)));
    }
    out.push('\n');
    out.push_str(&"-".repeat(rule));
    out.push('\n');
    for row in &t.rows {
        let label = row_label(t, row);
        crate::error::best_effort(write!(out, "{}", padded(&label, row_width)));
        for (c, w) in t.columns.iter().zip(&col_widths) {
            crate::error::best_effort(write!(out, "  {}", padded(&cell_for(t, row, c), *w)));
        }
        out.push('\n');
    }
    for paragraph in legend(t.heading).split("\n\n") {
        out.push('\n');
        out.push_str(&wrap(paragraph, t.width, "", ""));
    }
    let levels = level_lines(t);
    if !levels.is_empty() {
        out.push_str("\nLevels in this table:\n");
        out.push_str(&wrap(&levels_provenance(t, &headers), t.width, "  ", "  "));
        for (row, words, gloss) in &levels {
            out.push_str(&wrap(
                &format!("{} {words}: {gloss}", row.join(", ")),
                t.width,
                "  ",
                "    ",
            ));
        }
    }
    if !t.columns.is_empty() {
        out.push('\n');
        out.push_str(&wrap(&format!("{FLAGS_HEADING}:"), t.width, "", ""));
        for (column, heading) in t.columns.iter().zip(&headers) {
            let flags = t.flags.get(column).map_or("none", String::as_str);
            out.push_str(&wrap(&format!("{heading}:"), t.width, "  ", "    "));
            out.push_str(&wrap(flags, t.width, "    ", "    "));
            out.push_str(&wrap(
                &format!("measures: {}", meaning_of(t, column)),
                t.width,
                "    ",
                "      ",
            ));
        }
        out.push('\n');
        out.push_str(&wrap(MEANING_FIELDS, t.width, "  ", "  "));
    }
    out.push_str(&withheld_reasons(t));
    out.push_str(&notes(t));
    out
}

/// The forms a table is rendered in, which `chard table --format` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A grid for a terminal, its notes wrapped at the width given.
    Text,
    /// A Markdown table, not wrapped.
    Markdown,
}

/// What [`one_per_column`] gives: the reports a table is drawn from, one per column, and the
/// notes that say which replaced which.
type OnePerColumn = (Vec<(String, Value)>, Vec<String>);

/// One report per column, and the notes that say which replaced which.
fn one_per_column(
    reports: &[(String, Value)],
    by_defect: bool,
    repeated: Repeated,
) -> Result<OnePerColumn> {
    let mut kept: Vec<(String, Value)> = Vec::new();
    let mut at: BTreeMap<Column, usize> = BTreeMap::new();
    let mut repeats = Vec::new();
    let mut notes = Vec::new();
    for entry in reports {
        let (name, report) = entry;
        if !report.get("observations").is_some_and(Value::is_array) {
            return Err(crate::dataset::not_a_report(name, "it carries no observations").into());
        }
        if by_defect && !report.get("defect_coverage").is_some_and(Value::is_object) {
            return Err(crate::dataset::not_a_report(name, "it carries no defect_coverage").into());
        }
        let column = column_of(report);
        let Some(was) = at.get(&column).and_then(|&i| kept.get_mut(i)) else {
            at.insert(column, kept.len());
            kept.push(entry.clone());
            continue;
        };
        match repeated {
            Repeated::Refuse => {
                repeats.push(format!("{name} repeats {} ({})", was.0, column.describe()));
            }
            Repeated::Replace => {
                let mut note =
                    crate::matrix::replacement_of(was, entry, &column.describe(), "column");
                if by_defect {
                    note = format!("{note}. {}", defect_replacement(was, entry));
                }
                notes.push(note);
                *was = entry.clone();
            }
        }
    }
    if !repeats.is_empty() {
        return Err(crate::error::UserError::with_hint(
            format!(
                "these reports repeat a configuration: a table column holds one report, and two \
                 reports alike on every axis of its key ({}; libc is the implementation alone) \
                 are one column. The key holds no probe selection, compiler wrapper or chard \
                 revision, so two runs that differ only there key alike:\n  {}",
                COLUMN_AXES.join(", "),
                repeats.join("\n  ")
            ),
            "leave out all but one report of each configuration, or pass --replace-repeated",
        )
        .into());
    }
    Ok((kept, notes))
}

/// What the by-defect view adds to a replacement note where `now` replaces `was`: every defect
/// class both carry whose cell the grid draws differently ([`defect_cell`], so `--` against
/// `--?` is named where the status alone reads `not-mitigated` twice), every class only `was`
/// carries, which leaves the column with it, and every class only `now` carries, which joins
/// it. Keyed on the class as the report spells it, as the grid's rows are, and scrubbed only
/// where printed.
fn defect_replacement(was: &(String, Value), now: &(String, Value)) -> String {
    let statuses = |(_, report): &(String, Value)| -> BTreeMap<String, String> {
        report
            .get("defect_coverage")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(class, entry)| (class.clone(), defect_cell(entry)))
            .collect()
    };
    let (before, after) = (statuses(was), statuses(now));
    let (e, l) = (&was.0, &now.0);
    let differ: Vec<String> = before
        .iter()
        .filter_map(|(class, b)| {
            let a = after.get(class)?;
            (a != b).then(|| format!("`{}` `{b}` in {e} and `{a}` in {l}", scrub(class)))
        })
        .collect();
    let mut parts = vec![if differ.is_empty() {
        "The grid draws every defect class both carry alike for the two".to_owned()
    } else {
        format!(
            "{} defect class(es) both carry are drawn differently: {}",
            differ.len(),
            differ.join("; ")
        )
    }];
    let only = |one: &BTreeMap<String, String>, other: &BTreeMap<String, String>| {
        one.keys()
            .filter(|class| !other.contains_key(*class))
            .map(|class| format!("`{}`", scrub(class)))
            .collect::<Vec<_>>()
    };
    let left = only(&before, &after);
    if !left.is_empty() {
        parts.push(format!(
            "{} defect class(es) only {e} carries leave the column with it: {}",
            left.len(),
            left.join(", ")
        ));
    }
    let joined = only(&after, &before);
    if !joined.is_empty() {
        parts.push(format!(
            "{} defect class(es) only {l} carries join the column: {}",
            joined.len(),
            joined.join(", ")
        ));
    }
    parts.join(". ")
}

/// Render report files as a table, by protection or by the defects they bear on, refusing a
/// repeated configuration ([`Repeated::Refuse`]): [`render_reports`] takes the choice.
///
/// # Errors
///
/// Errors when a file cannot be read or parsed, is not a chard report, belongs to a
/// different dataset than the others without `allow_mixed`, or repeats another's
/// configuration.
pub fn render_files(
    paths: &[std::path::PathBuf],
    format: Format,
    by_defect: bool,
    allow_mixed: bool,
    width: usize,
) -> Result<String> {
    let reports = crate::dataset::read_reports(paths)?;
    render_reports(
        &reports,
        format,
        by_defect,
        allow_mixed,
        Repeated::Refuse,
        width,
    )
}

/// [`render_files`] over reports already read: `main` reads them first
/// (`dataset::read_reports`) and sets an earlier `-o` output aside between the two, so a
/// path the operator mistyped leaves it untouched and a set refused here does not.
///
/// # Errors
///
/// A set that is not one dataset without `allow_mixed`, one that repeats a configuration
/// under [`Repeated::Refuse`] (`one_per_column`), or one holding a report
/// `dataset::refuse_self_contradicted` names.
pub fn render_reports(
    reports: &[(String, Value)],
    format: Format,
    by_defect: bool,
    allow_mixed: bool,
    repeated: Repeated,
    width: usize,
) -> Result<String> {
    let identity = crate::dataset::Identity::of(reports);
    let conflicts = identity.conflicts();
    if !conflicts.is_empty() && !allow_mixed {
        // A UserError, not a bail: a mismatched input set is the operator's invocation to
        // correct, not a chard defect, and a caller branches on the envelope's `code`.
        return Err(crate::error::UserError::with_hint(
            format!(
                "these reports are not one dataset, so a table of them would compare \
                 incomparable columns:\n  {}",
                conflicts.join("\n  ")
            ),
            "pass --allow-mixed to render anyway",
        )
        .into());
    }

    // The shape and the repeats first, so a file that is no report is refused as that; then
    // the contradiction check over every input, the replaced ones too, before anything is
    // rendered.
    let (columns, replaced) = one_per_column(reports, by_defect, repeated)?;
    crate::dataset::refuse_self_contradicted(reports)?;
    let moved = crate::dataset::moved_rule_notes(reports);
    // From here the table is drawn from one report per column, and the full set is out of
    // reach: a grid read from it would pool a repeat again.
    let reports = columns.as_slice();
    let mut table = if by_defect {
        collect_defects(reports)?
    } else {
        collect(reports)?
    };
    // Carried into the render, not printed to stderr, so the caveat travels with the table
    // when its output is redirected or pasted.
    table.corpora_differ = identity.corpora.len() > 1;
    table.width = width;
    table.notes = conflicts
        .into_iter()
        .map(|c| format!("MIXED DATASET: {c}"))
        .chain(identity.cautions())
        .chain(moved)
        .chain(replaced)
        .collect();

    Ok(match format {
        Format::Markdown => markdown(&table),
        Format::Text => plain(&table),
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn scrub_lines_keeps_the_lines_and_nothing_else_that_controls() {
        assert_eq!(
            scrub_lines("a\u{1b}[1m\nb\tc\r\n\u{9b}31m\u{202e}\n"),
            "a?[1m\nb?c?\n?31m?\n"
        );
        assert_eq!(scrub_lines(""), "");
    }

    #[test]
    fn a_verdict_says_what_it_rests_on() {
        let set =
            |cs: &[&str]| -> BTreeSet<String> { cs.iter().map(|c| (*c).to_owned()).collect() };
        assert_eq!(evidence_mark(&set(&["runtime"])), 'x');
        assert_eq!(evidence_mark(&set(&["elf-static"])), 'a');
        assert_eq!(evidence_mark(&set(&["compiler-diag"])), 'd');
        assert_eq!(evidence_mark(&set(&["macro"])), 'm');
        // Most direct wins, in every pairing and regardless of insertion order.
        assert_eq!(evidence_mark(&set(&["macro", "runtime"])), 'x');
        assert_eq!(evidence_mark(&set(&["runtime", "macro"])), 'x');
        assert_eq!(evidence_mark(&set(&["macro", "elf-static"])), 'a');
        assert_eq!(evidence_mark(&set(&["compiler-diag", "macro"])), 'd');
        // An unknown channel is not silently promoted to a strong one.
        assert_eq!(evidence_mark(&set(&["something-new"])), '.');
        assert_eq!(evidence_mark(&BTreeSet::new()), '.');
    }

    /// A report of `cells`, each `(flag, verdict, channel)`, under `profile`.
    fn channelled(profile: &str, cells: &[(&str, &str, &str)]) -> Value {
        let flat: Vec<(&str, &str, Option<&str>)> =
            cells.iter().map(|&(f, v, _)| (f, v, None)).collect();
        let mut r = report("fedora", profile, &flat);
        for (obs, &(_, _, channel)) in r["observations"]
            .as_array_mut()
            .expect("observations")
            .iter_mut()
            .zip(cells)
        {
            obs["channel"] = json!(channel);
        }
        r
    }

    /// The row letters `collect` gives `reports`.
    fn marks_of(reports: &[(&str, Value)]) -> BTreeMap<String, char> {
        let reports: Vec<(String, Value)> = reports
            .iter()
            .map(|(n, r)| ((*n).to_owned(), r.clone()))
            .collect();
        collect(&reports).expect("collects").evidence
    }

    #[test]
    fn a_withheld_reading_lends_its_row_no_letter() {
        let cet = |runtime: &str, artifact: &str| {
            channelled(
                "bare",
                &[
                    (
                        "-fcf-protection=full (shadow stack enforced)",
                        runtime,
                        "runtime",
                    ),
                    (
                        "-fcf-protection=full (artifact markings)",
                        artifact,
                        "elf-static",
                    ),
                ],
            )
        };
        // Every verdict under the runtime channel, beside an artifact `off`: the three that
        // stand are named here rather than asked of `is_measurement`, so the test does not
        // move with it.
        let standing = [Verdict::On, Verdict::Off, Verdict::Partial];
        for verdict in Verdict::ALL {
            let marks = marks_of(&[("r.json", cet(verdict.as_str(), "off"))]);
            let want = if standing.contains(verdict) { 'x' } else { 'a' };
            assert_eq!(marks.get("cet"), Some(&want), "{verdict:?}");
        }
        // A word outside the vocabulary, or none, is no verdict and lends nothing either.
        for word in ["maybe", ""] {
            let marks = marks_of(&[("r.json", cet(word, "off"))]);
            assert_eq!(marks.get("cet"), Some(&'a'), "{word:?}");
        }
        // Nothing stands: no letter, and the row is still a row.
        let reports = vec![("r.json".to_owned(), cet("indeterminate", "unsupported"))];
        let table = collect(&reports).expect("collects");
        assert!(table.evidence.is_empty(), "{:?}", table.evidence);
        assert_eq!(table.rows, ["cet"]);
        assert_eq!(row_label(&table, "cet"), "cet");
    }

    #[test]
    fn a_row_s_letter_holds_for_every_column() {
        type Make<'a> = &'a dyn Fn(&str) -> Value;
        let fortify = |profile: &str, runtime: &str, macro_verdict: &str| {
            channelled(
                profile,
                &[
                    ("-D_FORTIFY_SOURCE=3", runtime, "runtime"),
                    ("-D_FORTIFY_SOURCE", macro_verdict, "macro"),
                ],
            )
        };
        let ran = |profile: &str| fortify(profile, "on", "on");
        let macro_only = |profile: &str| fortify(profile, "indeterminate", "on");
        let silent = |profile: &str| fortify(profile, "indeterminate", "unsupported");
        // A standing reading on a channel the table does not name, and one on none.
        let unnamed =
            |profile: &str| channelled(profile, &[("-D_FORTIFY_SOURCE=3", "on", "something-new")]);
        let unchannelled = |profile: &str| {
            let mut r = fortify(profile, "on", "unsupported");
            r["observations"][0]
                .as_object_mut()
                .expect("an observation")
                .remove("channel");
            r
        };
        let cases: [(Make, Make, Option<char>); 6] = [
            (&ran, &macro_only, Some('m')),
            // A column with nothing standing earns no letter and lowers no other.
            (&ran, &silent, Some('x')),
            // `.` is less direct than every letter.
            (&ran, &unnamed, Some('.')),
            (&ran, &unchannelled, Some('.')),
            (&macro_only, &unnamed, Some('.')),
            (&macro_only, &unchannelled, Some('.')),
        ];
        for (n, (strong, weak, want)) in cases.iter().enumerate() {
            for (first, second) in [("bare", "openssf-tldr"), ("openssf-tldr", "bare")] {
                let marks = marks_of(&[("a.json", strong(first)), ("b.json", weak(second))]);
                assert_eq!(
                    marks.get("fortify"),
                    want.as_ref(),
                    "case {n}, {first} first"
                );
            }
        }
    }

    #[test]
    fn a_weaken_row_takes_its_letter_from_its_standing_readings() {
        let rpath = |verdict: &str| {
            let mut r = channelled("bare", &[("-Wl,-rpath", verdict, "elf-static")]);
            r["observations"][0]["polarity"] = json!("weaken");
            r
        };
        assert_eq!(
            marks_of(&[("r.json", rpath("off"))]).get("rpath"),
            Some(&'a')
        );
        assert_eq!(
            marks_of(&[("r.json", rpath("on"))]).get("rpath"),
            Some(&'a')
        );
        assert_eq!(
            marks_of(&[("r.json", rpath("indeterminate"))]).get("rpath"),
            None
        );
    }

    #[test]
    fn a_crafted_row_name_cannot_reach_the_terminal_either() {
        let esc = char::from(0x1b);
        let hostile = format!("{esc}]0;PWNED{esc}[31mzzzz-not-a-known-flag");
        let mut report = report("fedora", "bare", &[("-fPIE", "on", Some("2"))]);
        report["observations"]
            .as_array_mut()
            .expect("observations")
            .push(serde_json::json!({
                "flag": &hostile,
                "verdict": "on",
                "polarity": "harden",
                "channel": "macro",
            }));

        let table = collect(&[("r.json".to_owned(), report)]).expect("collects");
        for (name, rendered) in [("plain", plain(&table)), ("markdown", markdown(&table))] {
            assert!(
                !rendered.contains(esc),
                "{name} let a raw ESC through a row label"
            );
            assert!(
                rendered.contains("?]0;PWNED?[31mzzzz"),
                "{name} should render the row inert and visible, not drop it:\n{rendered}"
            );
        }
    }

    #[test]
    fn a_field_wider_than_the_formatters_width_limit_renders() {
        let long = "x".repeat(70_000);
        let mut r = report(&long, "bare", &[(long.as_str(), "on", Some(long.as_str()))]);
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .push(json!({"flag": &long, "verdict": "probe-invalid"}));
        let table = collect(&[("r.json".to_owned(), r)]).expect("collects");
        let rendered = plain(&table);
        assert!(
            rendered.contains(&long),
            "the long field is rendered, not dropped"
        );
        let _: String = markdown(&table);
    }

    #[test]
    fn a_crafted_level_cannot_reach_the_terminal_either() {
        let esc = char::from(0x1b);
        assert_eq!(render("on", Some(&format!("{esc}[31m3"))), "?[31m3");
        assert_eq!(render("partial", Some(&format!("{esc}]0;X"))), "?]0;X");
        // The no-level path is a fixed literal and must stay one.
        assert_eq!(render("on", None), "on");
        assert_eq!(render("partial", None), "partial");
    }

    #[test]
    fn the_mark_is_rendered_and_does_not_break_alignment() {
        let report = report("fedora", "bare", &[("-fPIE", "on", Some("2"))]);
        let mut table = collect(&[("r.json".to_owned(), report)]).expect("collects");
        let row = table.rows[0].clone();
        table.evidence.insert(row.clone(), 'x');

        let md = markdown(&table);
        assert!(
            md.contains(&format!("`{row} x`")),
            "markdown carries the mark:\n{md}"
        );

        let txt = plain(&table);
        let body: Vec<&str> = txt.lines().filter(|l| l.starts_with(&row)).collect();
        assert!(!body.is_empty(), "row missing from plain output:\n{txt}");
        assert!(
            body[0].contains(&format!("{row} x")),
            "plain carries the mark"
        );
        // The header and the row must still agree on where column one ends.
        let header = txt.lines().next().expect("a header");
        assert!(
            header.len() >= row.len() + 2,
            "the row label column must be at least as wide as its widest label"
        );

        // And the legend must explain it, or the letter is noise.
        let key = key_of(&txt);
        assert!(
            key.contains("`x` the probe was run and the mitigation observed to act or not to"),
            "legend explains x"
        );
        assert!(key.contains("`m` a macro"), "legend explains m");
        assert!(
            key.contains(
                "`.` after a protection's name a channel this table does not name, or none"
            ),
            "legend explains ."
        );
        // Where the letter comes from, and where none is earned.
        for sentence in [
            "The letter is read from the checks whose verdict stands (`on`, `off` or \
             `partial`), never from an `n/a`",
            "Where the columns differ it is the least direct of theirs",
            "a column with no verdict standing earns none and lowers no other",
            "a protection with no verdict standing in any column carries none",
        ] {
            assert!(key.contains(sentence), "legend says {sentence:?}:\n{key}");
        }
    }

    #[test]
    fn a_crafted_report_cannot_reach_the_terminal_control_channel() {
        let esc = char::from(0x1b);
        let payload = format!("{esc}[31mFAKE{esc}[0m");
        assert_eq!(
            scrub(&payload),
            "?[31mFAKE?[0m",
            "one char in, one char out"
        );
        // Width is preserved, which is what keeps `plain`'s column alignment honest.
        assert_eq!(scrub(&payload).chars().count(), payload.chars().count());
        // A newline would end the row and fabricate table lines, so it goes too.
        assert_eq!(scrub("a\nb"), "a?b");
        assert_eq!(scrub("a\tb"), "a?b");
        // Ordinary text, including non-ASCII, is untouched.
        assert_eq!(
            scrub("gcc 13.2.0 (Debian 13.2.0-25) — ok"),
            "gcc 13.2.0 (Debian 13.2.0-25) — ok"
        );
        // And the ingestion path uses it.
        let v = serde_json::json!({"toolchain": {"version": payload}});
        assert_eq!(text(&v, &["toolchain", "version"]), "?[31mFAKE?[0m");
    }
    use super::*;
    use crate::report::{digest, flags_source};
    use serde_json::json;

    /// A report whose observations carry `recommended_level` where the fourth element
    /// names one, which is how a report declares a check graded.
    fn graded_report(
        distro: &str,
        profile: &str,
        cells: &[(&str, &str, Option<&str>, Option<&str>)],
    ) -> Value {
        let mut value = report(
            distro,
            profile,
            &cells
                .iter()
                .map(|(flag, verdict, level, _)| (*flag, *verdict, *level))
                .collect::<Vec<_>>(),
        );
        let observations = value["observations"]
            .as_array_mut()
            .expect("report() builds an observation array");
        for (obs, (_, _, _, recommended)) in observations.iter_mut().zip(cells) {
            if let Some(r) = recommended {
                obs["recommended_level"] = json!(r);
            }
        }
        value
    }

    fn report(distro: &str, profile: &str, cells: &[(&str, &str, Option<&str>)]) -> Value {
        let observations: Vec<Value> = cells
            .iter()
            .map(|(flag, verdict, level)| {
                let mut c = serde_json::Map::new();
                c.insert("flag".into(), json!(flag));
                c.insert("verdict".into(), json!(verdict));
                if let Some(l) = level {
                    c.insert("level".into(), json!(l));
                }
                Value::Object(c)
            })
            .collect();
        json!({
            "environment": {"distro": {"id": distro, "version_id": "1"},
                            "libc": {"impl": "glibc"}, "kernel": {"arch": "x86_64"},
                            "execution": {"mode": "host"}},
            "toolchain": {"kind": "gcc", "version": "16", "target": {"arch": "x86_64"}},
            "profile": {"id": profile},
            "observations": Value::Array(observations),
        })
    }

    #[test]
    fn a_default_and_an_asserted_report_of_one_configuration_are_two_columns() {
        let cells = [
            ("-fPIE", "on", Some("2")),
            ("-fstack-protector-strong", "on", None),
        ];
        let with_basis = |basis: &str| {
            let mut r = report("fedora", "bare", &cells);
            r["environment"]["execution"]["mode_evidence"] = json!({"basis": basis});
            r
        };
        let default = ("default.json".to_owned(), with_basis("assumed-host"));
        let asserted = (
            "asserted.json".to_owned(),
            with_basis("asserted-but-unobservable"),
        );
        for reports in [
            [default.clone(), asserted.clone()],
            [asserted.clone(), default.clone()],
        ] {
            let t = collect(&reports).expect("collects");
            assert_eq!(t.columns.len(), 2, "two provenances, two columns");
            let h = headings(&t.columns);
            assert!(
                h.iter().any(|h| h.ends_with(" host on assumed-host]"))
                    && h.iter()
                        .any(|h| h.ends_with(" host on asserted-but-unobservable]")),
                "{h:?}"
            );
            let rendered = markdown(&t);
            assert!(rendered.contains("host on assumed-host"), "{rendered}");
        }
        // A report carrying no basis is its own provenance, named as matrix names it.
        let mut unpublished = report("fedora", "bare", &cells);
        unpublished["environment"]["execution"]
            .as_object_mut()
            .expect("execution")
            .remove("mode_evidence");
        let t =
            collect(&[default.clone(), ("old.json".to_owned(), unpublished)]).expect("collects");
        assert_eq!(t.columns.len(), 2);
        assert!(
            headings(&t.columns)
                .iter()
                .any(|h| h.contains(crate::matrix::UNPUBLISHED_BASIS)),
            "{:?}",
            headings(&t.columns)
        );
        // One provenance across a heading's columns: the bracket names what differs (the
        // architecture) and not the provenance both share.
        let mut modeless = with_basis("assumed-host");
        modeless["environment"]["execution"]
            .as_object_mut()
            .expect("execution")
            .remove("mode");
        let t =
            collect(&[default.clone(), ("modeless.json".to_owned(), modeless)]).expect("collects");
        assert!(
            headings(&t.columns)
                .iter()
                .any(|h| h.ends_with(" mode unpublished on assumed-host]")),
            "{:?}",
            headings(&t.columns)
        );
        // A run whose own witnesses contradict its architecture is a column of its own, and
        // its heading says so.
        let mut wrapped = with_basis("assumed-host");
        wrapped["toolchain"]["target"]["macros"] = json!({"agreement": "disagrees"});
        let t =
            collect(&[default.clone(), ("wrapped.json".to_owned(), wrapped)]).expect("collects");
        assert_eq!(t.columns.len(), 2);
        assert!(
            headings(&t.columns)
                .iter()
                .any(|h| h.contains("x86_64 (contradicted)")),
            "{:?}",
            headings(&t.columns)
        );
        let mut arm = with_basis("assumed-host");
        arm["toolchain"]["target"]["arch"] = json!("aarch64");
        let t = collect(&[default, ("arm.json".to_owned(), arm)]).expect("collects");
        let h = headings(&t.columns);
        assert_eq!(h.len(), 2);
        assert!(
            h.iter().all(|h| h.contains('[') && !h.contains(" on ")),
            "{h:?}"
        );
    }

    #[test]
    fn report_strings_reach_a_markdown_table_escaped() {
        let rlo = char::from_u32(0x202E).expect("U+202E");
        let zwsp = char::from_u32(0x200B).expect("U+200B");
        let flag = format!("-fx|`y`{rlo}z");
        let mut r = report(
            "fedora",
            &format!("bare|`<b>`{zwsp}"),
            &[(&flag, "on", None)],
        );
        r["toolchain"]["version"] = json!("16|1\\");
        // A level is a report string too, and so is a reference that would decode to an
        // override.
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .push(json!({"flag": "-fPIE", "verdict": "on", "level": "2|x&#x202E;"}));
        let out = markdown(&collect(&[("r.json".to_owned(), r)]).expect("collects"));
        assert!(!out.contains(rlo) && !out.contains(zwsp), "{out}");
        // A reference survives only inside a code span, which decodes none.
        assert!(
            !outside_code_spans(&out).contains("&#x202E;"),
            "a character reference reached markup: {out}"
        );
        assert!(
            out.contains("`2|x&#x202E;`"),
            "the levels list shows the report's word in a code span: {out}"
        );
        for line in out
            .lines()
            .filter(|l| l.starts_with('|') && !l.starts_with("|---"))
        {
            // Every unescaped pipe is a cell border: the header has two cells and every row
            // two, so three borders a line.
            let borders = line
                .char_indices()
                .filter(|(i, c)| *c == '|' && (*i == 0 || line.as_bytes()[i - 1] != b'\\'))
                .count();
            assert_eq!(borders, 3, "a report string added a cell: {line}");
        }
        assert!(out.contains("&lt;b>"), "{out}");
        assert!(
            !out.contains("`y`"),
            "a backtick in a report string opened a span: {out}"
        );
        assert_eq!(scrub(&format!("a{rlo}b{zwsp}c")), "a?b?c");
        // One code point from each arm of the format-character list, and the two separators.
        for cp in [
            0x00AD, 0x0600, 0x061C, 0x06DD, 0x070F, 0x0890, 0x08E2, 0x180E, 0x200B, 0x202A, 0x2060,
            0x2066, 0xFEFF, 0xFFF9, 0x110BD, 0x110CD, 0x13430, 0x1BCA0, 0x1D173, 0xE0001, 0xE0020,
            0x2028, 0x2029,
        ] {
            let c = char::from_u32(cp).expect("a scalar value");
            assert_eq!(scrub(&c.to_string()), "?", "U+{cp:04X}");
        }
        assert_eq!(
            scrub("\u{00AC}\u{2027}\u{E0080}"),
            "\u{00AC}\u{2027}\u{E0080}"
        );
    }

    /// `s` with every code span removed: what a markdown renderer reads as markup.
    fn outside_code_spans(s: &str) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(start) = rest.find('`') {
            out.push_str(&rest[..start]);
            let fence = rest[start..].chars().take_while(|c| *c == '`').count();
            let after = &rest[start + fence..];
            if let Some(end) = after.find(&"`".repeat(fence)) {
                rest = &after[end + fence..];
            } else {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn a_report_word_is_a_code_span_whatever_it_holds() {
        assert_eq!(span("2"), "`2`");
        assert_eq!(span("a`b"), "``a`b``");
        assert_eq!(span("`x"), "`` `x ``");
        assert_eq!(
            outside_code_spans(&format!("- {}: x", span("a``b<i>"))),
            "- : x"
        );
    }

    #[test]
    fn a_rejected_profile_flag_prints_before_the_grid() {
        let esc = char::from(0x1b);
        let message = format!(
            "a flag the operator supplied is rejected: cc1 refused -fno-such-flag{esc}[31m in 1"
        );
        let mut rejecting = report(
            "fedora",
            "explicit:0123",
            &[("-fPIE", "build-failed", None)],
        );
        rejecting["diagnostics"] = json!([
            {"severity": "warning", "message": "unrelated", "context": "toolchain.target"},
            {"severity": "warning", "message": message, "context": "profile-flag-rejected"},
        ]);
        let clean = report("debian", "bare", &[("-fPIE", "on", Some("2"))]);
        let scrubbed =
            "a flag the operator supplied is rejected: cc1 refused -fno-such-flag?[31m in 1";

        let one = collect(&[("r.json".to_owned(), rejecting.clone())]).expect("collects");
        let two = collect(&[
            ("c.json".to_owned(), clean.clone()),
            ("r.json".to_owned(), rejecting),
        ])
        .expect("collects");
        for (name, rendered, grid) in [
            ("plain", plain(&one), "protection"),
            ("markdown", markdown(&one), "| protection |"),
            ("plain, two columns", plain(&two), "protection"),
            ("markdown, two columns", markdown(&two), "| protection |"),
        ] {
            assert!(!rendered.contains(esc), "{name}: {rendered}");
            assert!(!rendered.contains("unrelated"), "{name}: {rendered}");
            let flat = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
            let at = flat
                .find(scrubbed)
                .unwrap_or_else(|| panic!("{name}: {rendered}"));
            let grid_at = flat
                .find(grid)
                .unwrap_or_else(|| panic!("{name}: {rendered}"));
            assert!(
                at < grid_at,
                "{name}: the rejection is printed first:\n{rendered}"
            );
        }
        let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let fedora = two
            .columns
            .iter()
            .position(|c| c.distro == "fedora")
            .expect("the rejecting column");
        for (name, rendered, heading, mark) in [
            (
                "plain",
                plain(&two),
                plain_headings(&two.columns)[fedora].clone(),
                "!!",
            ),
            (
                "markdown",
                markdown(&two),
                headings(&two.columns)[fedora].clone(),
                "-",
            ),
        ] {
            assert!(
                flat(&rendered).contains(&format!("{mark} {}: {scrubbed}", flat(&heading))),
                "{name}: two columns name the column the rejection belongs to:\n{rendered}"
            );
        }
        for (name, rendered, mark) in [
            ("plain", plain(&one), "!!"),
            ("markdown", markdown(&one), "-"),
        ] {
            assert!(
                flat(&rendered).contains(&format!("{mark} {scrubbed}")),
                "{name}: one column names no heading before the rejection:\n{rendered}"
            );
        }

        let none = collect(&[("c.json".to_owned(), clean)]).expect("collects");
        for rendered in [plain(&none), markdown(&none)] {
            assert!(!rendered.contains("rejected"), "{rendered}");
        }
    }

    #[test]
    fn a_heading_is_disambiguated_only_where_it_would_otherwise_collide() {
        let column = |image: &str, arch: &str| Column {
            distro: "gentoo".to_owned(),
            release: "2.18".to_owned(),
            compiler: "gcc".to_owned(),
            compiler_version: "15.3.0".to_owned(),
            libc: "glibc".to_owned(),
            profile: "bare".to_owned(),
            image: image.to_owned(),
            arch: arch.to_owned(),
            machine: "features:none".to_owned(),
            execution: "host".to_owned(),
            execution_basis: "measured".to_owned(),
        };

        // One column: nothing to tell apart, so nothing is added.
        let alone = headings(&[column("gentoo-hardened", "x86_64")]);
        assert_eq!(alone.len(), 1);
        assert!(
            !alone[0].contains('['),
            "a single column needs no disambiguator: {}",
            alone[0]
        );

        // Two columns agreeing on the configuration and differing by image: both get it.
        let by_image = headings(&[
            column("gentoo-hardened", "x86_64"),
            column("gentoo-default", "x86_64"),
        ]);
        assert!(by_image[0].contains("gentoo-hardened"), "{}", by_image[0]);
        assert!(by_image[1].contains("gentoo-default"), "{}", by_image[1]);
        assert_ne!(
            by_image[0], by_image[1],
            "two specimens that measured differently must not share a heading"
        );

        // Differing by architecture instead: the same rule, the other field.
        let by_arch = headings(&[column("", "x86_64"), column("", "aarch64")]);
        assert!(by_arch[0].contains("x86_64"), "{}", by_arch[0]);
        assert!(by_arch[1].contains("aarch64"), "{}", by_arch[1]);

        // Columns whose configurations already differ are left alone.
        let mut other = column("gentoo-hardened", "x86_64");
        other.compiler = "clang".to_owned();
        let distinct = headings(&[column("gentoo-default", "x86_64"), other]);
        assert!(
            distinct.iter().all(|h| !h.contains('[')),
            "distinguishable configurations get no disambiguator: {distinct:?}"
        );

        // And where the configuration collides with nothing to tell them apart by, the
        // heading is the configuration rather than an empty bracket.
        let no_discriminator = headings(&[column("", ""), column("", "")]);
        assert!(
            no_discriminator.iter().all(|h| !h.contains('[')),
            "{no_discriminator:?}"
        );
    }

    #[test]
    fn each_withheld_verdict_renders_its_own_glyph_and_its_own_reason() {
        let withheld_for = |obs: Value| {
            let mut r = report("fedora", "bare", &[]);
            r["observations"]
                .as_array_mut()
                .expect("observations")
                .push(obs);
            collect(&[("r".to_owned(), r)])
                .expect("a report with one observation renders")
                .withheld
        };
        let one = |obs: Value| -> Option<(String, String)> {
            withheld_for(obs)
                .first()
                .map(|w| (w.glyph.to_owned(), w.reason.clone()))
        };

        assert_eq!(
            one(json!({"flag": "-f", "verdict": "unsupported",
                       "gating": {"reason": "this libc has no such mechanism"}})),
            Some((
                "n/a".to_owned(),
                "this libc has no such mechanism".to_owned()
            )),
            "a toolchain that lacks the mechanism explains itself through its gating"
        );
        assert_eq!(
            one(json!({"flag": "-f", "verdict": "not-applicable",
                       "gating": {"reason": "libc++ keeps its assertions elsewhere"}})),
            Some((
                "n/a".to_owned(),
                "libc++ keeps its assertions elsewhere".to_owned()
            )),
            "a question with no referent here explains itself through its gating too"
        );
        assert_eq!(render("not-applicable", None), "n/a");
        for verdict in ["probe-invalid", "indeterminate"] {
            assert_eq!(
                one(json!({"flag": "-f", "verdict": verdict,
                           "evidence": {"observed": "both arms agreed"}})),
                Some(("?".to_owned(), "both arms agreed".to_owned())),
                "`{verdict}` is chard unable to tell, and says so from the detector"
            );
        }
        assert_eq!(
            one(json!({"flag": "-f", "verdict": "build-failed",
                       "build_rejection": "cc: unknown option"})),
            Some(("err".to_owned(), "cc: unknown option".to_owned())),
            "a build that failed on the profile's flags names the flag it failed on"
        );

        // A bare `build-failed` contributes no line: "the build failed" is what the cell
        // already says, and a row repeating it is noise.
        assert!(
            withheld_for(json!({"flag": "-f", "verdict": "build-failed"})).is_empty(),
            "no rejection recorded is nothing to add"
        );
        // Nor does a measured verdict, whatever else it carries.
        for verdict in ["on", "off", "partial"] {
            assert!(
                withheld_for(json!({"flag": "-f", "verdict": verdict,
                                    "evidence": {"observed": "seen"}}))
                .is_empty(),
                "`{verdict}` is a measurement, not a withholding"
            );
        }
        // And a withheld verdict whose reason is absent or empty contributes nothing
        // rather than a blank line.
        assert!(
            withheld_for(json!({"flag": "-f", "verdict": "unsupported"})).is_empty(),
            "a withheld cell with no reason has honestly nothing to say"
        );
        assert!(
            withheld_for(json!({"flag": "-f", "verdict": "unsupported",
                                "gating": {"reason": ""}}))
            .is_empty(),
            "a withheld cell whose reason is empty has nothing to say"
        );
    }

    #[test]
    fn the_rwx_segment_row_is_named_for_the_protection() {
        let cell = |verdict: &str| {
            let mut r = report("fedora", "bare", &[]);
            let obs = r["observations"].as_array_mut().expect("observations");
            obs.push(json!({"flag": "-Wl,-N", "verdict": verdict, "polarity": "weaken"}));
            let t = collect(&[("r".to_owned(), r)]).expect("table");
            assert!(
                t.rows.iter().all(|row| row != "-Wl,-N"),
                "the adverse spelling is no row of its own"
            );
            cell_for(&t, "no-rwx-segment", &t.columns[0])
        };
        assert_eq!(cell("off"), "on", "no RWX segment is the protected state");
        assert_eq!(cell("on"), "--", "an RWX segment is the adverse finding");
        for spelled in ["-Wl,-N", "-Wl,--omagic", "-Wl,-omagic"] {
            assert_eq!(family(spelled), "no-rwx-segment", "{spelled}");
        }
        assert!(
            family("-Wl,-n") != "no-rwx-segment" && family("-Wl,-no-as-needed") != "no-rwx-segment",
            "--nmagic and the -Wl,-no- flags keep rows of their own"
        );
    }

    /// `rpath-absent` and `textrel-absent` are `weaken` checks: their flags are discouraged, so
    /// `verdict: off` means the adverse thing was not found. Rendered raw, its `--` would tell
    /// a reader they were unprotected by the measurement that says they are protected;
    /// `report::defect_coverage` inverts it the same way.

    #[test]
    fn a_discouraged_flag_that_is_absent_reads_as_protection() {
        let mut r = report("fedora", "bare", &[]);
        let obs = r["observations"].as_array_mut().expect("observations");
        obs.push(json!({"flag": "-Wl,-rpath", "verdict": "off", "polarity": "weaken"}));
        obs.push(
            json!({"flag": "-fPIC (no text relocations)", "verdict": "on",
                        "polarity": "weaken"}),
        );
        // A harden flag in the same table must be untouched by the inversion.
        obs.push(json!({"flag": "-fstack-protector-strong", "verdict": "off",
                        "polarity": "harden"}));

        let t = collect(&[("r".to_owned(), r)]).expect("table");
        let col = &t.columns[0];
        assert_eq!(
            cell_for(&t, "rpath", col),
            "on",
            "no DT_RPATH is the protected state, and `--` said the opposite"
        );
        assert_eq!(
            cell_for(&t, "-fPIC (no text relocations)", col),
            "--",
            "text relocations present is the adverse finding"
        );
        assert_eq!(
            cell_for(&t, "stack-protector", col),
            "--",
            "a harden flag keeps its sense"
        );
    }

    #[test]
    fn defect_view_reports_status_and_withholds_rather_than_claiming_mitigation() {
        let mut r = report("fedora", "bare", &[]);
        // The statuses `defect_coverage` emits, which the schema also enumerates: a renderer
        // test has to speak the producer's vocabulary or it tests nothing.
        r["defect_coverage"] = json!({
            "got-overwrite":              {"status": "mitigated"},
            "stack-buffer-overflow":      {"status": "not-mitigated",
                                           "from_checks": ["a", "b"],
                                           "verdict_counts": {"off": 2}},
            "heap-buffer-overflow":       {"status": "not-mitigated",
                                           "from_checks": ["a", "b"],
                                           "verdict_counts": {"off": 1, "probe-invalid": 1}},
            "uninitialized-read":         {"status": "unknown"},
            "return-oriented-programming": {"status": "partial"},
        });
        let t = collect_defects(&[("r".to_owned(), r)]).expect("defect table");
        assert_eq!(t.heading, "defect");
        let col = &t.columns[0];
        assert_eq!(cell_for(&t, "got-overwrite", col), "yes");
        // Every bearing check answered and none found a protection.
        assert_eq!(cell_for(&t, "stack-buffer-overflow", col), "--");
        // One of two bearing checks was withheld, so "none is on" is not the whole story.
        assert_eq!(cell_for(&t, "heap-buffer-overflow", col), "--?");
        // Not `--`: a withheld verdict is not evidence of absent mitigation.
        assert_eq!(cell_for(&t, "uninitialized-read", col), "?");
        // And not `yes`: partial RELRO and full RELRO must not print the same cell.
        assert_eq!(cell_for(&t, "return-oriented-programming", col), "part");
    }

    #[test]
    fn every_glyph_the_defect_view_emits_is_in_its_legend() {
        let key = legend("defect");
        for glyph in ["yes", "part", "--?", "--", "?", ".", "~"] {
            assert!(
                key.contains(&format!("`{glyph}`")),
                "glyph `{glyph}` is emitted and not explained: {key}"
            );
        }
        let protections = legend("protection");
        for glyph in ["on", "partial", "--", "n/a", "?", "err", ".", "~", "!a/b"] {
            assert!(
                protections.contains(&format!("`{glyph}`")),
                "glyph `{glyph}` is emitted and not explained: {protections}"
            );
        }
    }

    #[test]
    fn a_flag_outside_a_report_s_corpus_is_not_rendered_as_unmeasured() {
        let old = report("ubuntu", "bare", &[("-fPIE", "on", None)]);
        let new = report(
            "alpine",
            "bare",
            &[("-fPIE", "on", None), ("-fnew-check", "off", None)],
        );
        let mut t =
            collect(&[("old".to_owned(), old), ("new".to_owned(), new)]).expect("table builds");

        let old_col = t
            .columns
            .iter()
            .find(|c| c.distro == "ubuntu")
            .expect("ubuntu column")
            .clone();

        // Rows are protection families, not raw flags.
        let new_row = family("-fnew-check");
        let shared_row = family("-fPIE");

        // Same dataset: the flag is simply not measured in that report.
        assert_eq!(cell_for(&t, &new_row, &old_col), ".");

        // Different corpora: it was never in that report's corpus to measure.
        t.corpora_differ = true;
        assert_eq!(cell_for(&t, &new_row, &old_col), "~");
        // And a flag both corpora carry is untouched by the gate.
        assert_eq!(cell_for(&t, &shared_row, &old_col), "on");
    }

    #[test]
    fn defect_view_rejects_a_report_without_the_defect_map() {
        let r = report("fedora", "bare", &[("-fPIE", "on", None)]);
        assert!(collect_defects(&[("r".to_owned(), r)]).is_err());
    }

    #[test]
    fn checks_in_one_family_collapse_to_one_row() {
        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[
                    ("-fstack-protector-strong", "on", Some("strong")),
                    ("-fstack-protector-strong (emitted)", "on", None),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(t.rows.len(), 1);
        assert_eq!(t.rows[0], "stack-protector");
    }

    #[test]
    fn disagreement_within_a_family_is_shown_not_averaged() {
        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[
                    ("-fstack-protector-strong", "on", Some("strong")),
                    ("-fstack-protector-strong (emitted)", "off", None),
                ],
            ),
        )])
        .expect("collected");
        let col = t.columns.first().expect("one column").clone();
        let cell = t
            .cells
            .get(&("stack-protector".to_owned(), col))
            .expect("cell");
        assert!(
            cell.starts_with('!'),
            "expected a conflict marker, got {cell}"
        );
    }

    #[test]
    fn a_withheld_check_does_not_manufacture_a_conflict() {
        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[
                    ("-D_FORTIFY_SOURCE", "on", Some("3")),
                    ("-D_FORTIFY_SOURCE (enforced)", "probe-invalid", None),
                ],
            ),
        )])
        .expect("collected");
        let col = t.columns.first().expect("one column").clone();
        assert_eq!(
            t.cells
                .get(&("fortify".to_owned(), col))
                .map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn the_two_contexts_are_named_for_what_they_mean() {
        let t = collect(&[
            (
                "a".to_owned(),
                report("fedora", "bare", &[("-fPIE", "off", None)]),
            ),
            (
                "b".to_owned(),
                report("fedora", "distro-buildflags", &[("-fPIE", "on", Some("2"))]),
            ),
        ])
        .expect("collected");
        let contexts: Vec<String> = t.columns.iter().map(Column::context).collect();
        assert!(contexts.iter().any(|c| c == "bare cc"));
        assert!(contexts.iter().any(|c| c == "packages"));
        let md = markdown(&t);
        assert!(md.contains("bare cc"));
        assert!(md.contains("packages"));
    }

    #[test]
    fn the_legend_states_which_level_a_shared_cell_shows() {
        let key = legend("protection");
        assert!(
            key.contains(
                "a level short of its ask first, then a graded check's level, and otherwise the \
                 first in sorted order; where a check found it short at no level, the cell is \
                 `partial`"
            ),
            "{key}"
        );
        // A reading at no level does not disagree, and the checks whose `on` is a level though
        // they report none are named, each with its word, from the list the rule reads.
        assert!(
            key.contains(
                "A check that finds it present at no level does not disagree with one that \
                 names a level, except "
            ) && key.contains(
                "`!1/3`: level 1 beside level 3, such as the level requested beside the level in \
                 force"
            ) && key.contains(
                "each asking about one level alone, whose `on` is that level and whose `off` \
                 denies only that level"
            ) && key.contains("is no disagreement either, since no probe's code opts in"),
            "{key}"
        );
        for (id, word) in ONE_LEVEL_CHECKS.iter().chain(crate::report::OPT_IN_LEVELS) {
            assert!(key.contains(&format!("`{id}` (`{word}`)")), "{id}: {key}");
        }
        // Three names join as a list does, the last after `and`.
        assert_eq!(
            check_names(&[("a", "1"), ("b", "2"), ("c", "3")]),
            "`a` (`1`), `b` (`2`) and `c` (`3`)"
        );
        assert_eq!(check_names(&[("a", "1")]), "`a` (`1`)");
        assert!(
            key.contains("where checks on one graded scale read different words, about its level")
                && key.contains("`!all/unsafe-frame`"),
            "{key}"
        );
    }

    #[test]
    fn a_level_split_within_one_ask_shows_both_words() {
        let cell = |t: &Table, family: &str| {
            let col = t.columns.first().expect("one column").clone();
            t.cells.get(&(family.to_owned(), col)).cloned()
        };
        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "explicit",
                &[
                    (
                        "-fstack-protector-strong",
                        "on",
                        Some("all"),
                        Some("strong"),
                    ),
                    (
                        "-fstack-protector-strong (level emitted)",
                        "on",
                        Some("unsafe-frame"),
                        Some("strong"),
                    ),
                    ("-fstack-protector-strong (emitted)", "on", None, None),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(
            cell(&t, "stack-protector").as_deref(),
            Some("!all/unsafe-frame"),
            "the macro's rung and the object's word are both shown"
        );
        let md = markdown(&t);
        assert!(md.contains("!all/unsafe-frame"), "{md}");

        // One word on both graded readers: the word.
        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[
                    (
                        "-fstack-protector-strong",
                        "on",
                        Some("strong"),
                        Some("strong"),
                    ),
                    (
                        "-fstack-protector-strong (level emitted)",
                        "on",
                        Some("strong"),
                        Some("strong"),
                    ),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(cell(&t, "stack-protector").as_deref(), Some("strong"));

        // A graded word beside an ungraded one is not compared: the graded word.
        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[
                    ("-pie", "on", Some("pie"), Some("pie")),
                    ("-fPIE", "on", Some("2"), None),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(cell(&t, "pie").as_deref(), Some("pie"));

        // Two asks are two scales: not compared, and no marker.
        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[
                    ("-fcf-protection=full", "on", Some("full"), Some("full")),
                    (
                        "-fcf-protection=full (shadow stack enforced)",
                        "on",
                        Some("default"),
                        Some("default"),
                    ),
                ],
            ),
        )])
        .expect("collected");
        let c = cell(&t, "cet").expect("cell");
        assert!(!c.starts_with('!'), "two asks are not one scale: {c}");
    }

    /// An observation of the corpus check `id` as `measure` writes one: its id, flag,
    /// polarity and channel from the corpus, its ask where it grades one, and the verdict
    /// and level given.
    fn observed(id: &str, verdict: &str, level: Option<&str>) -> Value {
        let check = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check {id} in the corpus"));
        let mut o = json!({
            "check": id,
            "flag": check.flag,
            "verdict": verdict,
            "polarity": check.polarity,
            "channel": check.channel(),
        });
        if let Some(level) = level {
            o["level"] = json!(level);
        }
        if let Some(ask) = check.recommended_level() {
            o["recommended_level"] = json!(ask);
        }
        o
    }

    /// `observations` as one report's table, and its rendered grid row for each of `rows`
    /// beside the cell, after asserting the rendering shows the cell.
    fn rendered_rows(observations: Vec<Value>, rows: &[&str]) -> Vec<(String, String)> {
        let mut r = report("wolfi", "bare", &[]);
        r["observations"] = Value::Array(observations);
        let t = collect(&[("r.json".to_owned(), r)]).expect("table builds");
        let column = t.columns.first().expect("one column").clone();
        let shown = plain(&t);
        rows.iter()
            .map(|row| {
                let cell = cell_for(&t, row, &column);
                let line = shown
                    .lines()
                    .find(|l| l.split("  ").next() == Some(row_label(&t, row).as_str()))
                    .unwrap_or_else(|| panic!("no rendered row {row}:\n{shown}"));
                assert!(
                    line.trim_end().ends_with(&format!(" {cell}")),
                    "row {row} renders {line:?}, not its cell {cell}"
                );
                (line.to_owned(), cell)
            })
            .collect()
    }

    #[test]
    fn fortify_3_without_strict_flex_arrays_is_no_disagreement() {
        let mut observations: Vec<Value> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.id.starts_with("fortify-"))
            .map(|c| observed(c.id, "on", c.recommended_level().map(|_| "3")))
            .collect();
        assert_eq!(observations.len(), 7, "the seven fortify checks");
        observations.push(observed("strict-flex-arrays", "off", None));
        observations.push(observed("strict-flex-arrays-enforced", "off", None));
        let rows = rendered_rows(observations, &["fortify", "-fstrict-flex-arrays"]);
        let cells: Vec<&str> = rows.iter().map(|(_, cell)| cell.as_str()).collect();
        assert_eq!(cells, ["3", "--"], "{rows:?}");
        for (line, _) in &rows {
            assert!(!line.contains('!'), "a disagreement rendered: {line}");
        }
        // Every fortify check withheld, as on Wolfi's gcc 13 wrapper: the fortify row is
        // withheld too, not read from the flex check's `off`.
        let mut observations: Vec<Value> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.id.starts_with("fortify-"))
            .map(|c| observed(c.id, "probe-invalid", None))
            .collect();
        observations.push(observed("strict-flex-arrays-enforced", "off", None));
        let rows = rendered_rows(observations, &["fortify", "-fstrict-flex-arrays"]);
        let cells: Vec<&str> = rows.iter().map(|(_, cell)| cell.as_str()).collect();
        assert_eq!(cells, ["?", "--"], "{rows:?}");
    }

    #[test]
    fn a_zero_fill_with_the_pattern_check_off_is_the_level_zero() {
        let row = |active: Option<(&str, Option<&str>)>, pattern: &str| {
            let mut observations = Vec::new();
            if let Some((verdict, level)) = active {
                observations.push(observed("auto-var-init-active", verdict, level));
            }
            observations.push(observed("auto-var-init-pattern", pattern, None));
            rendered_rows(observations, &["auto-var-init"]).remove(0)
        };
        let (line, cell) = row(Some(("on", Some("zero"))), "off");
        assert_eq!(cell, "zero");
        assert!(!line.contains('!'), "a disagreement rendered: {line}");
        // A pattern fill is `partial` against the ask of `zero`, and the pattern check's
        // `off` beside it is a real disagreement.
        assert_eq!(
            row(Some(("partial", Some("pattern"))), "off").1,
            "!off/partial"
        );
        assert_eq!(row(Some(("on", None)), "off").1, "!off/on");
        // A `partial` at another level stands for presence as an `on` does: a crafted word,
        // since the corpus's own scale grades `zero` as the ask.
        let (line, _) = row(Some(("partial", Some("odd"))), "off");
        assert!(!line.contains('!'), "a disagreement rendered: {line}");
        // A withheld reading names no presence, whatever level it carries: the `off` stays.
        assert_eq!(row(Some(("indeterminate", Some("zero"))), "off").1, "--");
        assert_eq!(row(Some(("off", None)), "off").1, "--");
        assert_eq!(row(None, "off").1, "--");
        // The pattern check's `on` beside an `off` is a conflict about presence.
        assert_eq!(row(Some(("off", None)), "on").1, "!off/on");
    }

    /// The cell `row` renders for one report of the corpus checks `readings` (id, verdict,
    /// level), after asserting the grid line carries `!` exactly where the cell does.
    fn row_cell(readings: &[(&str, &str, Option<&str>)], row: &str) -> String {
        let observations = readings
            .iter()
            .map(|(id, verdict, level)| observed(id, verdict, *level))
            .collect();
        let (line, cell) = rendered_rows(observations, &[row]).remove(0);
        assert_eq!(line.contains('!'), cell.starts_with('!'), "{line}");
        cell
    }

    /// Fortify as Ubuntu 14.04 to 22.04's gcc bare-optimized measures it in a sweep: the
    /// graded checks `partial` at `2`, the checks that report no level `on`.
    const FORTIFY_AT_2: [(&str, &str, Option<&str>); 6] = [
        ("fortify-requested", "partial", Some("2")),
        ("fortify-effective", "partial", Some("2")),
        ("fortify-printf-flag", "partial", Some("2")),
        ("fortify-enforced-known", "on", None),
        ("fortify-level-ge-2-subobject", "on", None),
        ("fortify-level-ge-2-percent-n", "on", None),
    ];

    /// [`FORTIFY_AT_2`] with fortify-enforced-dynamic read `verdict`, as fortify's cell.
    fn fortify_at_2_with_dynamic(verdict: &str) -> String {
        let mut readings = FORTIFY_AT_2.to_vec();
        readings.push(("fortify-enforced-dynamic", verdict, None));
        row_cell(&readings, "fortify")
    }

    #[test]
    fn readings_that_agree_on_presence_print_one_level() {
        // An ungraded `on` beside graded readings at one level below the ask: OpenBSD amd64's
        // cet, Ubuntu 14.04 to 22.04 gcc bare-optimized's fortify, Ubuntu 14.04's protector.
        let cet = [
            ("cet-macro", "partial", Some("branch")),
            ("cet-marked-object", "partial", Some("branch")),
            ("cet-endbr-emitted", "on", None),
            ("cet-marked", "partial", Some("branch")),
            ("shadow-stack-enforced", "probe-invalid", None),
        ];
        assert_eq!(row_cell(&cet, "cet"), "branch");
        // Two scales, the markings at their ask and the shadow stack short of its own: the
        // reading short of its ask, as Fedora 44's guide build measures cet.
        let guide_cet = [
            ("cet-macro", "on", Some("full")),
            ("cet-marked-object", "on", Some("full")),
            ("cet-endbr-emitted", "on", None),
            ("cet-marked", "on", Some("full")),
            ("shadow-stack-enforced", "partial", Some("opt-in")),
        ];
        assert_eq!(row_cell(&guide_cet, "cet"), "opt-in");
        assert_eq!(fortify_at_2_with_dynamic("unsupported"), "2");
        let protector = [
            ("ssp-level", "unsupported", None),
            ("canary-emitted", "on", None),
            ("ssp-level-emitted", "partial", Some("basic")),
        ];
        assert_eq!(row_cell(&protector, "stack-protector"), "basic");
        // fortify-enforced-dynamic's `off` says level 3's mechanism is absent: beside level 2
        // it agrees (Gentoo's default profile).
        assert_eq!(fortify_at_2_with_dynamic("off"), "2");
        // A pattern fill read both ways agrees.
        let pattern_fill = [
            ("auto-var-init-active", "partial", Some("pattern")),
            ("auto-var-init-pattern", "on", Some("pattern")),
        ];
        assert_eq!(row_cell(&pattern_fill, "auto-var-init"), "pattern");
        // Every reading present at no level, one short of its ask: `partial`.
        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[
                    ("-D_FORTIFY_SOURCE", "partial", None, Some("3")),
                    ("-D_FORTIFY_SOURCE (enforced)", "on", None, None),
                ],
            ),
        )])
        .expect("collected");
        let col = t.columns.first().expect("one column").clone();
        assert_eq!(
            t.cells
                .get(&("fortify".to_owned(), col))
                .map(String::as_str),
            Some("partial")
        );
    }

    #[test]
    fn a_split_of_levels_prints_both_and_an_off_beside_presence_is_a_conflict() {
        // fortify-enforced-dynamic's `off` beside levels 1 and 2 leaves the split standing
        // (Alpine 3.24 and edge bare-optimized).
        let alpine = [
            ("fortify-requested", "partial", Some("2")),
            ("fortify-effective", "partial", Some("1")),
            ("fortify-enforced-known", "on", None),
            ("fortify-enforced-dynamic", "off", None),
        ];
        assert_eq!(row_cell(&alpine, "fortify"), "!1/2");
        // The request beside the level in force (Alpine, Chimera and FreeBSD under
        // openssf-tldr), and OpenBSD's markings.
        let fortify_1_3 = [
            ("fortify-requested", "on", Some("3")),
            ("fortify-effective", "partial", Some("1")),
            ("fortify-enforced-known", "on", None),
            ("fortify-enforced-dynamic", "on", None),
        ];
        assert_eq!(row_cell(&fortify_1_3, "fortify"), "!1/3");
        let cet_split = [
            ("cet-macro", "on", Some("full")),
            ("cet-marked-object", "on", Some("full")),
            ("cet-endbr-emitted", "on", None),
            ("cet-marked", "partial", Some("branch")),
        ];
        assert_eq!(row_cell(&cet_split, "cet"), "!branch/full");
        // A one-level check's `on` is its word on the row's scale: the pattern check beside a
        // zero fill, and fortify-enforced-dynamic beside level 2.
        let zero_and_pattern = [
            ("auto-var-init-active", "on", Some("zero")),
            ("auto-var-init-pattern", "on", Some("pattern")),
        ];
        assert_eq!(
            row_cell(&zero_and_pattern, "auto-var-init"),
            "!pattern/zero"
        );
        assert_eq!(fortify_at_2_with_dynamic("on"), "!2/3");
        let ungraded = [
            ("fortify-enforced-known", "on", None),
            ("fortify-enforced-dynamic", "on", None),
        ];
        assert_eq!(row_cell(&ungraded, "fortify"), "on");
        // The controls.
        let mut known_off = FORTIFY_AT_2.to_vec();
        known_off[3] = ("fortify-enforced-known", "off", None);
        assert_eq!(row_cell(&known_off, "fortify"), "!off/on/partial");
        let at_3 = [
            ("fortify-requested", "on", Some("3")),
            ("fortify-enforced-dynamic", "off", None),
        ];
        assert_eq!(row_cell(&at_3, "fortify"), "!off/on");
        let known = [
            ("fortify-enforced-known", "on", None),
            ("fortify-enforced-dynamic", "off", None),
        ];
        assert_eq!(row_cell(&known, "fortify"), "!off/on");
    }

    #[test]
    fn a_reading_short_of_its_ask_is_not_hidden_and_a_lone_one_level_on_is_as_written() {
        let cell = |cells: &[(&str, &str, Option<&str>, Option<&str>)]| {
            let t = collect(&[("a".to_owned(), graded_report("fedora", "bare", cells))])
                .expect("collected");
            let col = t.columns.first().expect("one column").clone();
            t.cells
                .get(&("fortify".to_owned(), col))
                .cloned()
                .expect("a fortify cell")
        };
        let at_3 = ("-D_FORTIFY_SOURCE", "on", Some("3"), Some("3"));
        let short_at_no_level = (
            "_FORTIFY_SOURCE (level in force)",
            "partial",
            None,
            Some("3"),
        );
        assert_eq!(cell(&[at_3, short_at_no_level]), "partial");
        let ungraded_short = ("-D_FORTIFY_SOURCE (enforced)", "partial", Some("2"), None);
        assert_eq!(cell(&[at_3, ungraded_short]), "2");
        // The pattern check `on` beside a withheld zero-fill check: `pattern`, as written.
        let lone_pattern = [
            ("auto-var-init-active", "indeterminate", None),
            ("auto-var-init-pattern", "on", Some("pattern")),
        ];
        assert_eq!(row_cell(&lone_pattern, "auto-var-init"), "pattern");
        // Two asks in one fortify cell: the dynamic check's `on` is not placed on either, so
        // no split is drawn from it, and the cell shows a graded level.
        let mut observations: Vec<Value> = [
            ("fortify-requested", "on", Some("3")),
            ("fortify-effective", "on", Some("2")),
            ("fortify-enforced-dynamic", "on", None),
        ]
        .iter()
        .map(|(id, verdict, level)| observed(id, verdict, *level))
        .collect();
        observations[1]["recommended_level"] = json!("2");
        let (_, two_asks) = rendered_rows(observations, &["fortify"]).remove(0);
        assert_eq!(two_asks, "2");
        let all_off: Vec<_> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.id.starts_with("fortify-"))
            .map(|c| (c.id, "off", None))
            .collect();
        assert_eq!(row_cell(&all_off, "fortify"), "--");
    }

    #[test]
    fn an_off_beside_an_opt_in_level_is_no_disagreement_and_an_ask_alone_is_no_scale() {
        let explicit = [
            ("ssp-level", "partial", Some("explicit")),
            ("canary-emitted", "off", None),
            ("ssp-level-emitted", "off", None),
        ];
        assert_eq!(row_cell(&explicit, "stack-protector"), "explicit");
        let basic = [
            ("ssp-level", "partial", Some("basic")),
            ("canary-emitted", "off", None),
        ];
        assert_eq!(row_cell(&basic, "stack-protector"), "!off/partial");
        // An `explicit` from another check than the list names is not the opt-in rule.
        let emitted = [
            ("ssp-level-emitted", "partial", Some("explicit")),
            ("canary-emitted", "off", None),
        ];
        assert_eq!(row_cell(&emitted, "stack-protector"), "!off/partial");
        // fortify graded at 2, an `on` with an ask of its own but no level, and the dynamic
        // check `on`: one scale, so `!2/3`.
        let mut observations: Vec<Value> = [
            ("fortify-requested", "partial", Some("2")),
            ("fortify-enforced-known", "on", None),
            ("fortify-enforced-dynamic", "on", None),
        ]
        .iter()
        .map(|(id, verdict, level)| observed(id, verdict, *level))
        .collect();
        observations[1]["recommended_level"] = json!("x");
        let (_, cell) = rendered_rows(observations, &["fortify"]).remove(0);
        assert_eq!(cell, "!2/3");
    }

    #[test]
    fn the_bang_marks_exactly_a_disagreement_over_every_small_set_of_readings() {
        let mut domain: Vec<Reading> = Vec::new();
        for v in ["on", "partial", "off", "unsupported"] {
            for l in [None, Some("1"), Some("3"), Some("a/b")] {
                for a in [None, Some("3"), Some("full")] {
                    domain.push((v.to_owned(), l.map(str::to_owned), a.map(str::to_owned)));
                }
            }
        }
        let mut sets: Vec<BTreeSet<Reading>> = Vec::new();
        for i in 0..domain.len() {
            for j in i..domain.len() {
                for k in j..domain.len() {
                    sets.push(
                        [&domain[i], &domain[j], &domain[k]]
                            .into_iter()
                            .cloned()
                            .collect(),
                    );
                }
            }
        }
        let (mut agreeing, mut off_alone) = (0_usize, 0_usize);
        for seen in &sets {
            let present: Vec<&Reading> = seen
                .iter()
                .filter(|(v, _, _)| v == "on" || v == "partial")
                .collect();
            let absent = seen.iter().any(|(v, _, _)| v == "off");
            let mut by_ask: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
            for (_, l, a) in &present {
                if let (Some(l), Some(a)) = (l, a) {
                    by_ask.entry(a.as_str()).or_default().insert(l.as_str());
                }
            }
            let split: BTreeSet<&str> = by_ask
                .values()
                .filter(|w| w.len() > 1)
                .flatten()
                .copied()
                .collect();
            let shown_split = !split.is_empty() && !split.contains("a/b");
            let disagree = (absent && !present.is_empty()) || (!absent && shown_split);
            let cell = one_cell(seen);
            assert_eq!(cell.starts_with('!'), disagree, "{seen:?} -> {cell}");
            if disagree {
                continue;
            }
            if absent {
                assert_eq!(cell, "--", "{seen:?}");
                off_alone += 1;
                continue;
            }
            if present.is_empty() {
                continue;
            }
            let short = present.iter().any(|(v, _, _)| v == "partial");
            let named = |verdict: &str| -> BTreeSet<&str> {
                present
                    .iter()
                    .filter(|(v, _, _)| verdict.is_empty() || v == verdict)
                    .filter_map(|(_, l, _)| l.as_deref())
                    .collect()
            };
            if short {
                assert!(
                    cell == "partial" || named("partial").contains(cell.as_str()),
                    "a short reading hidden: {seen:?} -> {cell}"
                );
            } else {
                assert!(
                    cell == "on" || named("").contains(cell.as_str()),
                    "{seen:?} -> {cell}"
                );
            }
            agreeing += 1;
        }
        // Counted, so a domain that shrank cannot pass: 48 readings, the multisets of three,
        // and the sets that agree on a present protection and those holding an `off` alone.
        assert_eq!(domain.len(), 48);
        assert_eq!(sets.len(), 48 * 49 * 50 / 6);
        assert_eq!(
            (agreeing, off_alone),
            (7808, 2236),
            "{agreeing} {off_alone}"
        );
    }

    #[test]
    fn a_withheld_line_names_a_qualified_flag_once() {
        let withheld = |id: &str| {
            let mut o = observed(id, "indeterminate", None);
            o["evidence"] = json!({"observed": "the reason"});
            o
        };
        let mut r = report("wolfi", "bare", &[]);
        r["observations"] = json!([
            withheld("strict-flex-arrays-enforced"),
            withheld("trapv-helper-called")
        ]);
        let t = collect(&[("r.json".to_owned(), r)]).expect("table builds");
        let shown = plain(&t);
        assert!(
            shown.contains("-fstrict-flex-arrays (enforced under _FORTIFY_SOURCE>=2)"),
            "{shown}"
        );
        assert!(!shown.contains("-fstrict-flex-arrays (-fstrict"), "{shown}");
        assert!(shown.contains("trapv (-ftrapv (libgcc helper))"), "{shown}");
        let md = markdown(&t);
        assert!(
            md.contains("`-fstrict-flex-arrays (enforced under _FORTIFY_SOURCE>=2)`:"),
            "{md}"
        );
        assert!(md.contains("`trapv` (`-ftrapv (libgcc helper)`)"), "{md}");
        // A flag that only extends its row's text, with no qualifier, keeps the row beside it.
        let line = |row: &str, check: &str| Withheld {
            column: t.columns.first().expect("one column").clone(),
            row: row.to_owned(),
            check: check.to_owned(),
            glyph: "?",
            reason: String::new(),
            earned: false,
        };
        assert_eq!(
            withheld_label(&line("-fpic", "-fpic-x")),
            ("-fpic", Some("-fpic-x"))
        );
        assert_eq!(withheld_label(&line("-fpic", "-fpic")), ("-fpic", None));
    }

    #[test]
    fn one_level_checks_ask_about_a_word_their_row_grades() {
        assert!(
            !ONE_LEVEL_CHECKS.is_empty(),
            "the one-level checks are not empty, so the loop below checks something"
        );
        let checks = || probe::CORPUS.iter().flat_map(|p| p.checks);
        for (id, word) in ONE_LEVEL_CHECKS {
            let check = checks()
                .find(|c| c.id == *id)
                .unwrap_or_else(|| panic!("{id}: not a check in the corpus"));
            let words = check.levels.words();
            assert!(words.is_empty() || words == [*word], "{id}: {words:?}");
            assert!(check.levels.grade().is_none(), "{id} grades a level itself");
            assert_eq!(level_asked(id), Some(*word));
            // The probe's positive arm selects the word: its `on` is that level, which the
            // rule reads it as, and a check whose probe is another level's mechanism (the
            // level-2 rungs) cannot be listed at `3`.
            assert!(
                shown_as_level("on", word),
                "{id}: `{word}` cannot stand in a cell"
            );
            let selects = format!("={word}");
            assert!(
                check.positive.iter().any(|f| f.ends_with(&selects)),
                "{id}: no positive flag selects `{word}`: {:?}",
                check.positive
            );
            let row = family(check.flag);
            let graders: Vec<_> = checks()
                .filter(|c| c.id != *id && family(c.flag) == row)
                .filter(|c| c.levels.grade().is_some())
                .collect();
            assert!(
                !graders.is_empty(),
                "{id}: no check in row {row} grades a level"
            );
            for c in &graders {
                assert!(c.levels.admits(word), "{}: does not admit `{word}`", c.id);
            }
            let asks: BTreeSet<_> = graders.iter().map(|c| c.recommended_level()).collect();
            assert_eq!(asks.len(), 1, "{id}: row {row} grades against {asks:?}");
        }
        assert_eq!(level_asked("auto-var-init-active"), None);
        assert_eq!(level_asked("fortify-enforced-known"), None);
    }

    #[test]
    fn a_qualifier_does_not_key_a_check_s_row() {
        let checks = || probe::CORPUS.iter().flat_map(|p| p.checks);
        let fortify: Vec<&str> = checks()
            .filter(|c| family(c.flag) == "fortify")
            .map(|c| c.id)
            .collect();
        assert_eq!(fortify.len(), 7, "{fortify:?}");
        assert!(
            fortify.iter().all(|id| id.starts_with("fortify-")),
            "{fortify:?}"
        );
        let enforced = checks()
            .find(|c| c.id == "strict-flex-arrays-enforced")
            .expect("in the corpus");
        assert!(
            enforced.flag.contains("_FORTIFY_SOURCE"),
            "{}",
            enforced.flag
        );
        assert_eq!(family(enforced.flag), "-fstrict-flex-arrays");
        assert_eq!(family("-fstrict-flex-arrays"), "-fstrict-flex-arrays");
        assert_eq!(family("-fno-strict-flex-arrays"), "-fno-strict-flex-arrays");
        assert_eq!(
            family("-fnew-check (under -fstack-protector-strong)"),
            "-fnew-check (under -fstack-protector-strong)"
        );
    }

    #[test]
    fn one_ask_names_one_scale_within_a_family() {
        let mut by_family_ask: BTreeMap<(String, &str), BTreeSet<String>> = BTreeMap::new();
        let mut graded = 0usize;
        for check in probe::CORPUS.iter().flat_map(|p| p.checks) {
            let Some(grade) = check.levels.grade() else {
                continue;
            };
            graded += 1;
            by_family_ask
                .entry((family(check.flag), grade.recommended))
                .or_default()
                .insert(format!("{:?}", grade.scale));
        }
        assert!(graded >= 20, "the corpus carries graded checks: {graded}");
        for ((fam, ask), scales) in &by_family_ask {
            assert_eq!(
                scales.len(),
                1,
                "family {fam}: the ask `{ask}` names {} scales: {scales:?}",
                scales.len()
            );
        }
        assert!(
            by_family_ask.keys().filter(|(fam, _)| fam == "cet").count() >= 2,
            "the cet family carries two asks: {:?}",
            by_family_ask.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn differing_granularity_is_not_a_conflict() {
        let cell = |t: &Table, family: &str| {
            let col = t.columns.first().expect("one column").clone();
            t.cells.get(&(family.to_owned(), col)).cloned()
        };
        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[
                    ("-fstack-protector-strong", "on", Some("strong")),
                    ("-fstack-protector-strong (emitted)", "on", None),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(
            cell(&t, "stack-protector").as_deref(),
            Some("strong"),
            "the more specific level is the useful statement"
        );

        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[("-pie", "on", Some("pie")), ("-fPIE", "on", Some("2"))],
            ),
        )])
        .expect("collected");
        assert_eq!(
            cell(&t, "pie").as_deref(),
            Some("2"),
            "two ungraded levels: the first in sorted order"
        );

        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[
                    ("-pie", "on", Some("pie"), Some("pie")),
                    ("-fPIE", "on", Some("2"), None),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(
            cell(&t, "pie").as_deref(),
            Some("pie"),
            "a reading the report declares graded wins over one it does not"
        );

        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[
                    ("-D_FORTIFY_SOURCE", "on", Some("3"), Some("3")),
                    (
                        "_FORTIFY_SOURCE (level in force)",
                        "on",
                        Some("3"),
                        Some("3"),
                    ),
                    ("-D_FORTIFY_SOURCE (runtime)", "on", None, None),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(
            cell(&t, "fortify").as_deref(),
            Some("3"),
            "two graded readings agreeing on a word show it"
        );
    }

    #[test]
    fn a_non_report_is_rejected() {
        assert!(collect(&[("x".to_owned(), json!({}))]).is_err());
    }

    #[test]
    fn a_profile_with_env_pairs_keeps_its_reading_in_the_header() {
        assert_eq!(profile_context("bare"), "bare cc");
        assert_eq!(
            profile_context("bare+env:0123456789ab"),
            "bare cc +env:0123456789ab"
        );
        assert_eq!(
            profile_context("openssf-tldr+env:0123456789ab"),
            "guide +env:0123456789ab"
        );
        assert_eq!(
            profile_context("explicit:abc+env:0123456789ab"),
            "explicit:abc +env:0123456789ab"
        );
    }

    /// The legend under a plain table: everything after the grid, where every word a cell
    /// shows must be defined, with the wrapping undone (runs of whitespace as one space).
    fn key_of(rendered: &str) -> String {
        rendered
            .split_once("\nLegend:")
            .map_or("", |(_, key)| key)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn every_level_vocabulary_in_the_corpus_is_glossed() {
        let mut checked = 0usize;
        for check in probe::CORPUS.iter().flat_map(|p| p.checks) {
            if check.levels == Levels::None {
                continue;
            }
            let row = family(check.flag);
            assert!(
                gloss_entry(&check.levels, &row).is_some(),
                "{}: its level vocabulary has no gloss",
                check.id
            );
            level_gloss(&check.levels, &row).expect("glossed");
            checked += 1;
        }
        assert!(
            checked >= 25,
            "the corpus carries levelled checks: {checked}"
        );
    }

    #[test]
    fn the_legend_names_the_weaken_inversion_by_a_flag_the_corpus_weakens() {
        let key = legend("protection");
        let example = key
            .split("such as `")
            .nth(1)
            .and_then(|rest| rest.split('`').next())
            .expect("the legend names an example flag");
        assert!(
            probe::CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .any(|c| c.flag == example && c.polarity == probe::Polarity::Weaken),
            "{example} is not a weaken check's flag"
        );
        assert!(
            key.contains("weakens a protection (`polarity` `weaken`")
                && key.contains("`on` where the report says `off`"),
            "{key}"
        );
    }

    #[test]
    fn every_word_a_cell_can_show_is_defined_beside_the_table() {
        const VERDICTS: [&str; 9] = [
            "on",
            "off",
            "partial",
            "unsupported",
            "not-applicable",
            "indeterminate",
            "probe-invalid",
            "build-failed",
            "run-failed",
        ];
        let mut cases: Vec<Value> = Vec::new();
        for check in probe::CORPUS.iter().flat_map(|p| p.checks) {
            for verdict in VERDICTS {
                cases.push(json!({"flag": check.flag, "verdict": verdict}));
            }
            let numeric = ["1", "2", "3", "4"];
            let words = if check.levels.words().is_empty() && check.levels != Levels::None {
                &numeric[..]
            } else {
                check.levels.words()
            };
            for word in words.iter().chain(check.levels.ungraded()) {
                for verdict in ["on", "partial"] {
                    let mut obs = json!({"flag": check.flag, "verdict": verdict, "level": word});
                    if let Some(ask) = check.levels.recommended() {
                        obs["recommended_level"] = json!(ask);
                    }
                    cases.push(obs);
                }
            }
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut fed = 0usize;
        for obs in &cases {
            let mut r = report("fedora", "bare", &[]);
            r["observations"]
                .as_array_mut()
                .expect("observations")
                .push(obs.clone());
            let t = collect(&[("r".to_owned(), r)]).expect("collects");
            assert_eq!(t.cells.len(), 1, "{obs} yields one cell");
            for ((row, _), cell) in &t.cells {
                seen.extend(defined(&t, row, cell, obs));
            }
            fed += 1;
        }
        assert_eq!(fed, cases.len(), "every case was rendered");
        // The cases reached the vocabulary they were meant to.
        for word in [
            "on",
            "partial",
            "--",
            "n/a",
            "?",
            "err",
            "strong",
            "unsafe-frame",
            "3",
            "full",
            "warning",
            "error",
            "2",
            "gpr",
            "default",
        ] {
            assert!(seen.contains(word), "no case showed `{word}`: {seen:?}");
        }
        // A conflict cell's words are defined too.
        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[
                    ("-fstack-protector-strong", "on", Some("strong")),
                    ("-fstack-protector-strong (emitted)", "off", None),
                ],
            ),
        )])
        .expect("collected");
        let ((row, _), cell) = t.cells.iter().next().expect("a cell");
        assert_eq!(cell, "!off/on");
        assert_eq!(
            defined(&t, row, cell, &json!("conflict")),
            vec!["off", "on"]
        );
    }

    /// The words of `cell`, asserting the text under `t` defines each; a gloss's grading clause
    /// does not count, since it names the word without saying what it means.
    fn defined(t: &Table, row: &str, cell: &str, case: &Value) -> Vec<String> {
        let key = key_of(&plain(t));
        let lines = level_lines(t);
        let admitted = |word: &str| {
            probe::CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .filter(|check| family(check.flag) == row)
                .any(|check| check.levels.admits(word))
        };
        let (words, split): (Vec<&str>, bool) = match cell.strip_prefix('!') {
            Some(split) => (split.split('/').collect(), true),
            None => (vec![cell], false),
        };
        for word in &words {
            // A glyph is defined where the key carries its sentence, read from the output.
            let glyph = (!split)
                .then(|| glyphs(t.heading).iter().find(|(g, _)| g == word))
                .flatten();
            if let Some((g, meaning)) = glyph {
                assert!(
                    key.contains(&format!("`{g}` {meaning}")),
                    "`{word}` (from {case}) is a glyph the key does not define: {key}"
                );
            }
            let verdict = split && matches!(*word, "on" | "off" | "partial");
            if verdict {
                assert!(
                    key.contains("`!off/on`: one check read `off` and another `on`"),
                    "{key}"
                );
            }
            // A word the row's vocabulary admits is a level, whatever else it spells.
            if (glyph.is_some() || verdict) && !admitted(word) {
                continue;
            }
            let quoted = format!("`{word}`");
            let line = lines
                .iter()
                .find(|(rows, shown, _)| {
                    rows.iter().any(|r| r == row) && shown.split(", ").any(|w| w == quoted)
                })
                .unwrap_or_else(|| panic!("`{word}` (from {case}) has no level line: {key}"));
            let meaning = line.2.replace(&format!("Graded against {quoted}."), "");
            assert!(
                !meaning.contains("not a level this build"),
                "`{word}` (from {case}) is a corpus word the build calls undefined"
            );
        }
        words.into_iter().map(ToOwned::to_owned).collect()
    }

    #[test]
    fn a_level_spelled_as_a_glyph_is_defined_as_a_level() {
        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[("-Wl,-z,relro", "partial", Some("partial"), Some("full"))],
            ),
        )])
        .expect("collected");
        assert_eq!(t.rows, vec!["relro".to_owned()]);
        let lines = level_lines(&t);
        assert!(
            lines
                .iter()
                .any(|(rows, shown, gloss)| rows == &["relro".to_owned()]
                    && shown == "`partial`"
                    && gloss.contains("`partial` the read-only-after-relocation segment alone")),
            "{lines:?}"
        );
        assert!(
            key_of(&plain(&t))
                .contains("`partial` present, short of the level the check is graded against")
        );
    }

    #[test]
    fn a_run_that_failed_lists_its_reason() {
        let mut r = report("fedora", "bare", &[]);
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .push(
                json!({"flag": "-fstack-clash-protection", "verdict": "run-failed",
                         "evidence": {"observed": "the probe was killed by SIGKILL"}}),
            );
        let t = collect(&[("r".to_owned(), r)]).expect("collects");
        assert_eq!(t.cells.values().next().map(String::as_str), Some("err"));
        let w = t.withheld.first().expect("a withheld line");
        assert_eq!(
            (w.glyph, w.reason.as_str()),
            ("err", "the probe was killed by SIGKILL")
        );
        // A reason of whitespace alone is no reason.
        let mut r = report("fedora", "bare", &[]);
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .push(json!({"flag": "-f", "verdict": "probe-invalid",
                         "evidence": {"observed": "   "}}));
        assert!(
            collect(&[("r".to_owned(), r)])
                .expect("t")
                .withheld
                .is_empty(),
            "an observation whose evidence is blank withholds no cell"
        );
    }

    #[test]
    fn a_level_that_reads_as_a_glyph_or_a_split_is_not_shown() {
        for level in ["--", "?", "n/a", "a/b", "!x", "  ", "err", "~"] {
            assert_eq!(render("on", Some(level)), "on", "level {level:?}");
            assert_eq!(render("partial", Some(level)), "partial", "level {level:?}");
        }
        assert_eq!(render("partial", Some("partial")), "partial");
        assert_eq!(render("on", Some("strong")), "strong");
        // The same words cannot reach a cell through a level split.
        let t = collect(&[(
            "a".to_owned(),
            graded_report(
                "fedora",
                "bare",
                &[
                    (
                        "-fstack-protector-strong",
                        "on",
                        Some("n/a"),
                        Some("strong"),
                    ),
                    (
                        "-fstack-protector-strong (level emitted)",
                        "on",
                        Some("strong"),
                        Some("strong"),
                    ),
                ],
            ),
        )])
        .expect("collected");
        assert_eq!(t.cells.values().next().map(String::as_str), Some("on"));
    }

    #[test]
    fn the_levels_name_columns_from_another_corpus() {
        let mut own = report("fedora", "bare", &[("-fPIE", "on", Some("2"))]);
        own["run"] = json!({"probe_corpus_sha256": probe::corpus_sha256()});
        let other = report("alpine", "bare", &[("-fPIE", "on", Some("2"))]);
        let t = collect(&[("a".to_owned(), own), ("b".to_owned(), other)]).expect("t");
        let key = key_of(&plain(&t));
        assert!(
            key.contains("this build's probe corpus gives the word"),
            "{key}"
        );
        assert!(key.contains("another probe corpus or none"), "{key}");
        assert!(key.contains("alpine 1 gcc 16 bare cc."), "{key}");
        assert!(!key.contains("fedora 1 gcc 16 bare cc."), "{key}");
    }

    #[test]
    fn every_word_the_defect_view_shows_is_defined_beside_it() {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (status, checks) in [
            ("mitigated", json!({})),
            ("partial", json!({})),
            (
                "not-mitigated",
                json!({"from_checks": ["a"], "verdict_counts": {"off": 1}}),
            ),
            (
                "not-mitigated",
                json!({"from_checks": ["a", "b"], "verdict_counts": {"off": 1}}),
            ),
            ("unknown", json!({})),
            // A request's `off` answered: `--`, not `--?`.
            (
                "not-mitigated",
                json!({"from_checks": ["a", "b"], "verdict_counts": {"off": 1, "not-requested": 1}}),
            ),
            // Markings alone, every one answered: `?` with nothing withheld.
            (
                "unknown",
                json!({"from_checks": ["a", "b"], "verdict_counts": {"marked": 1, "not-marked": 1}}),
            ),
        ] {
            let mut r = report("fedora", "bare", &[]);
            let mut entry = checks;
            entry["status"] = json!(status);
            r["defect_coverage"] = json!({ "got-overwrite": entry });
            let t = collect_defects(&[("r".to_owned(), r)]).expect("a defect table");
            for ((row, _), cell) in &t.cells {
                seen.extend(defined(&t, row, cell, &json!(status)));
            }
        }
        for word in ["yes", "part", "--", "--?", "?"] {
            assert!(seen.contains(word), "no case showed `{word}`: {seen:?}");
        }
        // The two cases by name: a request or marking key is answered.
        assert_eq!(
            defect_cell(
                &json!({"status": "not-mitigated", "from_checks": ["a", "b"],
                "verdict_counts": {"off": 1, "not-requested": 1}})
            ),
            "--"
        );
        assert_eq!(
            defect_cell(
                &json!({"status": "not-mitigated", "from_checks": ["a", "b", "c"],
                "verdict_counts": {"off": 1, "not-requested": 1}})
            ),
            "--?"
        );
        assert_eq!(
            defect_cell(&json!({"status": "unknown", "from_checks": ["a", "b"],
                "verdict_counts": {"marked": 1, "not-marked": 1}})),
            "?"
        );
    }

    #[test]
    fn a_level_word_the_corpus_does_not_define_is_named_as_such() {
        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[("-fstack-protector-strong", "on", Some("galactic"))],
            ),
        )])
        .expect("collected");
        let rendered = plain(&t);
        assert!(
            key_of(&rendered).contains("`galactic` is not a level this build's probe corpus"),
            "{rendered}"
        );
    }

    #[test]
    fn a_withheld_reason_is_whole_wrapped_and_named_by_its_row() {
        let reason: String = (0..90)
            .map(|i| format!("word{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(reason.len() > 400);
        let mut r = report("fedora", "bare", &[]);
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .push(
                json!({"flag": "-Wl,-z,pack-relative-relocs", "verdict": "not-applicable",
                         "gating": {"reason": &reason}}),
            );
        let mut t = collect(&[("r".to_owned(), r)]).expect("collects");
        assert_eq!(t.rows, vec!["relative-relocs".to_owned()]);
        for width in [40, 80, 200] {
            t.width = width;
            let rendered = plain(&t);
            let below = rendered
                .split_once("Withheld, and why:\n")
                .map(|(_, w)| w)
                .expect("a withheld section");
            let words: Vec<&str> = below.split_whitespace().collect();
            let joined = words.join(" ");
            assert!(
                joined.starts_with("n/a relative-relocs (-Wl,-z,pack-relative-relocs)"),
                "{below}"
            );
            assert!(
                joined.contains(&reason),
                "width {width}: the reason was cut:\n{below}"
            );
            for line in rendered.lines().skip_while(|l| !l.starts_with("Legend:")) {
                assert!(
                    line.chars().count() <= width,
                    "width {width}: a line of {} columns: {line}",
                    line.chars().count()
                );
            }
        }
        // Width 0 does not wrap: the reason is one line.
        t.width = 0;
        let rendered = plain(&t);
        assert!(rendered.lines().any(|l| l.trim() == reason), "{rendered}");
        // Markdown carries the row and the check and leaves wrapping to the reader's renderer.
        let md = markdown(&t);
        assert!(
            md.contains(&format!(
                "- `n/a` `relative-relocs` (`-Wl,-z,pack-relative-relocs`): {reason}"
            )),
            "{md}"
        );
    }

    #[test]
    fn earned_limitations_are_listed_apart_from_withholdings() {
        let mut r = report("fedora", "bare", &[]);
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .extend([
                json!({"flag": "-mbranch-protection=standard", "verdict": "unsupported",
                       "gating": {"rule": "arch-gated", "reason": "not on x86_64"}}),
                json!({"flag": "-fhardened", "verdict": "unsupported",
                       "gating": {"rule": "cpu-lacks-shadow-stack", "reason": "misfiled"}}),
                json!({"flag": "-fcf-protection=full", "verdict": "indeterminate",
                       "gating": {"rule": "cpu-lacks-shadow-stack", "reason": "no CET CPU"}}),
            ]);
        let t = collect(&[("r".to_owned(), r)]).expect("collects");
        let rendered = plain(&t);
        let (_, after) = rendered
            .split_once("Limitations, and why:\n")
            .expect("a limitations list");
        let (limitations, withheld) = after
            .split_once("Withheld, and why:\n")
            .expect("a withheld list after it");
        assert!(limitations.contains("not on x86_64"), "{rendered}");
        assert!(!limitations.contains("no CET CPU") && !limitations.contains("misfiled"));
        assert!(
            withheld.contains("no CET CPU") && withheld.contains("misfiled"),
            "an unsupported no rule earns is chard's, not the target's: {rendered}"
        );
        let md = markdown(&t);
        let (_, after) = md
            .split_once("**Limitations, and why**")
            .expect("a limitations list");
        let (limitations, withheld) = after
            .split_once("**Withheld, and why**")
            .expect("a withheld list after it");
        assert!(limitations.contains("not on x86_64") && withheld.contains("no CET CPU"));
    }

    #[test]
    fn the_written_class_decides_the_list() {
        let listed = |premise: Option<&str>| {
            let mut gating = json!({"rule": "cpu-lacks-shadow-stack", "reason": "written"});
            if let Some(premise) = premise {
                gating["premise"] = json!(premise);
            }
            let mut r = report("fedora", "bare", &[]);
            r["observations"]
                .as_array_mut()
                .expect("observations")
                .push(json!({"flag": "-fhardened", "verdict": "unsupported", "gating": gating}));
            let rendered = plain(&collect(&[("r".to_owned(), r)]).expect("collects"));
            let (_, after) = rendered
                .split_once("Limitations, and why:\n")
                .unwrap_or(("", ""));
            let limitations = after.split("Withheld, and why:\n").next().unwrap_or("");
            limitations.contains("written")
        };
        assert!(listed(Some("toolchain-fact")));
        assert!(!listed(None));
        assert!(!listed(Some("instrument-limitation")));
    }

    #[test]
    fn withheld_lines_name_their_column_by_its_heading() {
        let withheld = |profile: &str| {
            let mut r = report("fedora", profile, &[]);
            r["observations"]
                .as_array_mut()
                .expect("observations")
                .push(json!({"flag": "-Whardened", "verdict": "probe-invalid",
                             "evidence": {"observed": format!("seen under {profile}")}}));
            r
        };
        let t = collect(&[
            ("a".to_owned(), withheld("bare")),
            ("b".to_owned(), withheld("openssf-tldr")),
        ])
        .expect("collects");
        let rendered = plain(&t);
        let below = rendered
            .split_once("Withheld, and why:\n")
            .map(|(_, w)| w)
            .expect("a withheld section");
        let bare = below
            .find("fedora 1 gcc 16 bare cc:")
            .expect("bare heading");
        let guide = below.find("fedora 1 gcc 16 guide:").expect("guide heading");
        let under_bare = below.find("seen under bare").expect("bare reason");
        let under_guide = below.find("seen under openssf-tldr").expect("guide reason");
        assert!(
            bare < under_bare && under_bare < guide && guide < under_guide,
            "{below}"
        );
    }

    #[test]
    fn a_column_that_passed_flags_shows_them() {
        let flags: Vec<String> = (0..30).map(|i| format!("-fflag-number-{i}")).collect();
        let mut explicit = report("fedora", "explicit:0123456789ab", &[("-fPIE", "on", None)]);
        explicit["profile"]["cflags"] = json!(flags);
        explicit["profile"]["ldflags"] = json!(["-Wl,-z,now"]);
        let mut bare = report("fedora", "bare", &[("-fPIE", "on", None)]);
        bare["profile"]["cflags"] = json!([]);
        let t = collect(&[("a".to_owned(), explicit), ("b".to_owned(), bare)]).expect("t");
        let rendered = plain(&t);
        let listed = rendered
            .split_once(&format!("{FLAGS_HEADING}:\n"))
            .map(|(_, f)| f)
            .expect("a flags section");
        assert!(
            listed.contains("fedora 1 gcc 16 explicit:0123456789ab:"),
            "{listed}"
        );
        let words = listed.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains("fedora 1 gcc 16 bare cc: none"),
            "a column that passed no flags says so: {listed}"
        );
        assert!(
            words.contains(&format!("cflags: {}; ldflags: -Wl,-z,now", flags.join(" "))),
            "{listed}"
        );
        assert!(rendered.lines().skip(3).all(|l| l.chars().count() <= 80));
        assert!(markdown(&t).contains(&format!("**{FLAGS_HEADING}**")));

        // The defect view lists them too.
        let mut explicit = report("fedora", "explicit:0123456789ab", &[]);
        explicit["profile"]["cflags"] = json!(["-fPIE"]);
        explicit["defect_coverage"] = json!({"got-overwrite": {"status": "mitigated"}});
        let t = collect_defects(&[("a".to_owned(), explicit)]).expect("a defect table");
        assert!(
            plain(&t).contains(&format!("{FLAGS_HEADING}:")),
            "{}",
            plain(&t)
        );
    }

    /// A report shaped as `measure` writes its digest's profile block, for a test table.
    fn with_meaning(mut r: Value, source: &str) -> Value {
        let meaning = digest::meaning(source, false, false).expect("a source");
        r["profile"]["flags_source"] = json!(source);
        r["digest"] = json!({"profile": {"meaning": meaning}});
        r
    }

    #[test]
    fn every_column_says_what_it_measures() {
        let cell = [("-fPIE", "on", None)];
        let bare = with_meaning(report("fedora", "bare", &cell), flags_source::NONE);
        let mut optimized = with_meaning(
            report("fedora", "bare-optimized", &cell),
            flags_source::ENABLING_CONDITION,
        );
        optimized["profile"]["cflags"] = json!(["-O2"]);
        let unstated = report("fedora", "distro-buildflags", &cell);
        let meaning = |source| digest::meaning(source, false, false).expect("a source");
        let (none, enabling) = (
            meaning(flags_source::NONE),
            meaning(flags_source::ENABLING_CONDITION),
        );
        assert!(enabling.contains("compiled-in defaults") && enabling.contains("package"));

        let alone = collect(&[("a".to_owned(), bare.clone())]).expect("t");
        let words = |s: String| s.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words(plain(&alone)).contains(&format!(
                "{FLAGS_HEADING}: fedora 1 gcc 16 bare cc: none measures: {none}"
            )),
            "a bare table alone: {}",
            plain(&alone)
        );

        let t = collect(&[
            ("a".to_owned(), bare),
            ("b".to_owned(), optimized),
            ("c".to_owned(), unstated),
        ])
        .expect("t");
        let text = words(plain(&t));
        assert!(MEANING_UNSTATED.starts_with("not stated"));
        for line in [
            format!("fedora 1 gcc 16 bare cc: none measures: {none}"),
            format!("fedora 1 gcc 16 bare cc -O2: cflags: -O2 measures: {enabling}"),
            format!("fedora 1 gcc 16 packages: none measures: {MEANING_UNSTATED}"),
        ] {
            assert!(text.contains(&line), "{line}\n{}", plain(&t));
        }
        assert!(plain(&t).lines().skip(3).all(|l| l.chars().count() <= 80));
        let md = markdown(&t);
        for (heading, sentence) in [
            ("bare cc: none", none.as_str()),
            ("bare cc -O2: cflags: -O2", enabling.as_str()),
            ("packages: none", MEANING_UNSTATED),
        ] {
            assert_eq!(
                md.matches(&format!("{heading}\n  - measures: {sentence}\n"))
                    .count(),
                1,
                "{md}"
            );
        }
    }

    #[test]
    fn the_meaning_block_says_where_its_cited_fields_are_read() {
        assert!(!MEANING_FIELDS.contains("  "));
        let words = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let pointer = words(MEANING_FIELDS);
        let mut user = with_meaning(
            report("fedora", "explicit:0123456789ab", &[("-fPIE", "on", None)]),
            flags_source::USER,
        );
        user["profile"]["cflags"] = json!(["-fPIE"]);
        user["profile"]["compiler_environment"] = json!({"set": {"CC_PIN": "pinned-value"}});
        user["toolchain"]["config_files"] = json!(["/etc/clang/x.cfg"]);
        user["observations"]
            .as_array_mut()
            .expect("observations")
            .push(json!({"flag": "-Whardened", "verdict": "probe-invalid",
                         "evidence": {"observed": "seen under explicit"},
                         "build": {"argv": ["cc", "-dropped-flag"],
                                   "dropped_flags": ["-dropped-flag"]}}));
        let sentence = digest::meaning(flags_source::USER, false, false).expect("user");
        let bare = with_meaning(report("fedora", "bare", &[]), flags_source::NONE);
        let mut defects = bare.clone();
        defects["defect_coverage"] = json!({"got-overwrite": {"status": "mitigated"}});
        let tables = [
            collect(&[("a".to_owned(), user), ("b".to_owned(), bare)]).expect("t"),
            collect_defects(&[("a".to_owned(), defects)]).expect("a defect table"),
        ];
        for t in &tables {
            for rendered in [plain(t), markdown(t)] {
                let text = words(&rendered);
                assert_eq!(text.matches(&pointer).count(), 1, "{rendered}");
                let (block, after) = text.split_once(&pointer).expect("the pointer");
                assert!(block.contains("measures: "), "{rendered}");
                assert!(!after.contains("measures: "), "{rendered}");
                for value in ["/etc/clang/x.cfg", "pinned-value", "-dropped-flag"] {
                    assert!(!rendered.contains(value), "{value}: {rendered}");
                }
            }
            assert!(markdown(t).contains(&format!("\n\n{MEANING_FIELDS}\n")));
            assert!(plain(t).contains("\n\n  The other fields these sentences cite"));
            assert!(plain(t).lines().skip(3).all(|l| l.chars().count() <= 80));
        }
        // The section after the block follows the pointer, in both formats.
        for rendered in [plain(&tables[0]), markdown(&tables[0])] {
            let text = words(&rendered);
            let withheld = text.rfind("Withheld, and why").expect("a withheld section");
            assert!(
                text.find(&pointer).expect("the pointer") < withheld,
                "{rendered}"
            );
        }
        assert!(words(&plain(&tables[0])).contains(&format!("measures: {sentence}")));
        assert!(markdown(&tables[0]).contains(&format!("\n  - measures: {sentence}\n")));
    }

    #[test]
    fn the_defect_view_says_what_a_column_measures_and_scrubs_it() {
        let mut bare = with_meaning(report("fedora", "bare", &[]), flags_source::NONE);
        bare["defect_coverage"] = json!({"got-overwrite": {"status": "mitigated"}});
        let none = digest::meaning(flags_source::NONE, false, false).expect("a source");
        let t = collect_defects(&[("a".to_owned(), bare.clone())]).expect("a defect table");
        let words = plain(&t).split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            words.contains(&format!("bare cc: none measures: {none}")),
            "{}",
            plain(&t)
        );
        assert!(
            markdown(&t).contains(&format!("\n  - measures: {none}\n")),
            "{}",
            markdown(&t)
        );
        bare["digest"]["profile"]["meaning"] = json!("defaults\u{1b}]0;owned\u{7}");
        let t = collect_defects(&[("a".to_owned(), bare)]).expect("a defect table");
        assert!(
            plain(&t).contains("measures: defaults?]0;owned?"),
            "{}",
            plain(&t)
        );
        assert!(!plain(&t).contains('\u{1b}') && !markdown(&t).contains('\u{1b}'));
    }

    #[test]
    fn rows_sort_by_name_ignoring_dashes_and_case() {
        let t = collect(&[(
            "a".to_owned(),
            report(
                "fedora",
                "bare",
                &[
                    ("-Wall", "on", None),
                    ("--param ssp-buffer-size=4", "on", None),
                    ("-fPIE", "on", None),
                    ("-D_GLIBCXX_ASSERTIONS", "on", None),
                    ("-fcf-protection=full", "on", None),
                ],
            ),
        )])
        .expect("collected");
        let names: Vec<String> = t.rows.iter().map(|r| row_key(r).0).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "{:?}", t.rows);
        assert_eq!(
            t.rows.first().map(String::as_str),
            Some("cet"),
            "{:?}",
            t.rows
        );
        assert_eq!(
            t.rows.last().map(String::as_str),
            Some("-Wall"),
            "{:?}",
            t.rows
        );
        assert!(legend("protection").contains("ignoring leading dashes and case"));
    }

    #[test]
    fn wrap_keeps_every_word_and_breaks_only_between_them() {
        let text = "aa bbb cccc dddddddddddddddddddddddddd e";
        let wrapped = wrap(text, 10, "> ", "  ");
        assert_eq!(
            wrapped,
            "> aa bbb\n  cccc\n  dddddddddddddddddddddddddd\n  e\n"
        );
        assert_eq!(wrap(text, 0, "> ", "  "), format!("> {text}\n"));
        assert_eq!(wrap("", 10, "> ", "  "), "> \n");
        // A line exactly `width` wide is kept on one line.
        assert_eq!(wrap("ab cd", 5, "", ""), "ab cd\n");
        assert_eq!(wrap("ab cde", 5, "", ""), "ab\ncde\n");
    }

    #[test]
    fn a_defect_one_report_lacks_reads_unmeasured_where_corpora_differ() {
        let mut fedora = report("fedora", "bare", &[("-fPIE", "on", None)]);
        fedora["defect_coverage"] = json!({"got-overwrite": {"status": "mitigated"}});
        let mut alpine = report("alpine", "bare", &[("-fPIE", "on", None)]);
        alpine["defect_coverage"] = json!({
            "got-overwrite": {"status": "mitigated"},
            "uninitialized-read": {"status": "unknown"},
        });
        let mut t = collect_defects(&[("f".to_owned(), fedora), ("a".to_owned(), alpine)])
            .expect("defect table");
        t.corpora_differ = true;
        let fedora = t
            .columns
            .iter()
            .find(|c| c.distro == "fedora")
            .expect("fedora column")
            .clone();
        assert_eq!(cell_for(&t, "uninitialized-read", &fedora), ".");
    }

    #[test]
    fn a_table_with_no_rejected_flag_prints_no_rejection_header() {
        let t = collect(&[(
            "r".to_owned(),
            report("fedora", "bare", &[("-fPIE", "on", None)]),
        )])
        .expect("collects");
        assert!(!markdown(&t).contains("**Profile flags the toolchain rejected**"));
    }

    #[test]
    fn withheld_lines_sit_under_their_own_column_s_heading_where_there_are_two() {
        let mut fedora = report("fedora", "bare", &[]);
        fedora["observations"]
            .as_array_mut()
            .expect("observations")
            .push(json!({"flag": "-fx", "verdict": "unsupported",
                         "gating": {"reason": "no such mechanism here"}}));
        let line = "- `n/a` `-fx`: no such mechanism here";
        let alone = markdown(&collect(&[("f".to_owned(), fedora.clone())]).expect("collects"));
        assert!(alone.contains(&format!("\n{line}\n")), "{alone}");
        let alpine = report("alpine", "bare", &[("-fx", "on", None)]);
        let both = markdown(
            &collect(&[("f".to_owned(), fedora), ("a".to_owned(), alpine)]).expect("collects"),
        );
        assert_eq!(both.matches(&format!("\n  {line}\n")).count(), 1, "{both}");
        assert!(!both.contains(&format!("\n{line}\n")), "{both}");
    }

    #[test]
    fn level_lines_group_rows_by_their_words_and_meaning_together() {
        let t = collect(&[(
            "r".to_owned(),
            report(
                "fedora",
                "bare",
                &[
                    ("-Werror=implicit-int", "on", Some("error")),
                    ("-Werror=int-conversion", "on", Some("error")),
                    ("-Wl,-z,relro -Wl,-z,now", "on", Some("full")),
                    ("-fcf-protection=full", "on", Some("full")),
                ],
            ),
        )])
        .expect("collects");
        let lines = level_lines(&t);
        let rows_of = |word: &str| {
            lines
                .iter()
                .filter(|(_, words, _)| words.contains(word))
                .map(|(rows, _, _)| rows.len())
                .collect::<Vec<_>>()
        };
        assert_eq!(rows_of("error"), [2], "{lines:?}");
        assert_eq!(rows_of("full"), [1, 1], "{lines:?}");
    }

    #[test]
    fn a_row_s_own_gloss_is_that_row_s_alone() {
        assert!(
            gloss_entry(&probe::FLEX_ARRAY_LEVELS, "-fstrict-flex-arrays")
                .is_some_and(|g| g.starts_with("the `-fstrict-flex-arrays` level"))
        );
        assert_eq!(
            gloss_entry(&probe::FLEX_ARRAY_LEVELS, "-fsome-other-row"),
            None
        );
    }

    #[test]
    fn the_notes_escape_markup_and_keep_code_spans() {
        assert_eq!(md_prose("a & b < c | d `e`"), "a &amp; b &lt; c \\| d `e`");
    }

    #[test]
    fn the_defect_view_s_legend_is_its_glyphs() {
        let defect = legend("defect");
        assert!(
            defect.starts_with("Legend: `") && !defect.contains("Levels in this table"),
            "{defect}"
        );
    }

    #[test]
    fn a_split_cell_shows_its_level_words_and_its_admitted_verdict_words() {
        let admits_all = |w: &str| w == "all";
        assert_eq!(
            level_words("!all/unsafe-frame", &admits_all),
            ["all", "unsafe-frame"]
        );
        assert!(
            level_words("!off/on", &admits_all).is_empty(),
            "a negated level list naming no admitted word yields none: {:?}",
            level_words("!off/on", &admits_all)
        );
        let admits_partial = |w: &str| w == "partial";
        assert_eq!(
            level_words("!partial/unsafe-frame", &admits_partial),
            ["partial", "unsafe-frame"]
        );
        assert_eq!(
            level_words("!partial/unsafe-frame", &admits_all),
            ["unsafe-frame"]
        );
    }

    /// The repeated-run shape ([`one_per_column`]): a full run, then a run of fewer checks of the
    /// same configuration through a wrapper adding `-no-pie`, which withholds the two checks
    /// the full run read `off` and `n/a`, and a report of another configuration, each with a
    /// `defect_coverage`.
    fn full_nopie_and_other() -> [(String, Value); 3] {
        let with_defects = |mut r: Value, status: &str| {
            r["defect_coverage"] = json!({"code-reuse": {"status": status}});
            r
        };
        let mut nopie = report(
            "fedora",
            "bare",
            &[
                ("-pie", "probe-invalid", None),
                ("-Wl,-z,pack-relative-relocs", "probe-invalid", None),
                ("-fstack-clash-protection", "on", None),
            ],
        );
        for obs in nopie["observations"].as_array_mut().expect("observations") {
            if obs["verdict"] == "probe-invalid" {
                obs["evidence"] = json!({"observed": "the forced-on arm linked no PIE"});
            }
        }
        let full = report(
            "fedora",
            "bare",
            &[
                ("-pie", "off", None),
                ("-Wl,-z,pack-relative-relocs", "not-applicable", None),
                ("-fstack-clash-protection", "on", None),
                ("-fstack-protector-strong", "on", Some("strong")),
            ],
        );
        let other = report("fedora", "explicit", &[("-pie", "on", None)]);
        [
            ("full.json".to_owned(), with_defects(full, "not-mitigated")),
            ("nopie.json".to_owned(), with_defects(nopie, "unknown")),
            ("other.json".to_owned(), with_defects(other, "mitigated")),
        ]
    }

    /// The configuration of [`full_nopie_and_other`]'s repeated pair, as a refusal and a note
    /// name it: every axis, the empty one too.
    const BARE: &str = "distro fedora, release 1, compiler gcc, compiler_version 16, libc \
                        glibc, arch x86_64, machine unread, profile bare, execution host, \
                        execution_basis unpublished, image (none)";

    /// The table `reports` give, by protection or by defect, without its notes.
    fn drawn(reports: &[(String, Value)], by_defect: bool) -> String {
        let t = if by_defect {
            collect_defects(reports)
        } else {
            collect(reports)
        };
        plain(&t.expect("collected"))
    }

    #[test]
    fn a_repeated_configuration_is_refused_in_either_view() {
        let [full, nopie, other] = full_nopie_and_other();
        // What the pool showed: the standing reading alone, the withheld one only below.
        let pooled = drawn(&[full.clone(), nopie.clone()], false);
        let pie = pooled
            .lines()
            .find(|l| l.starts_with("pie"))
            .expect("the pie row");
        assert!(pie.trim_end().ends_with("--"), "{pooled}");
        for by_defect in [false, true] {
            for set in [
                [full.clone(), other.clone(), nopie.clone()],
                [nopie.clone(), other.clone(), full.clone()],
            ] {
                let refused = one_per_column(&set, by_defect, Repeated::Refuse)
                    .expect_err("a repeated configuration");
                let user = refused
                    .downcast_ref::<crate::error::UserError>()
                    .expect("the caller's input to fix");
                let (first, repeat) = (&set[0].0, &set[2].0);
                assert!(
                    user.message
                        .contains(&format!("{repeat} repeats {first} ({BARE})"))
                        && user.message.contains(&format!(
                            "every axis of its key ({}; libc is the implementation alone)",
                            COLUMN_AXES.join(", ")
                        ))
                        && user.message.contains("The key holds no probe selection")
                        && !user.message.contains("other.json"),
                    "{}",
                    user.message
                );
                assert!(
                    user.hint
                        .as_deref()
                        .is_some_and(|h| h.contains("--replace-repeated")),
                    "{:?}",
                    user.hint
                );
            }
        }
        // Three of one configuration: each repeat named against the first.
        let third = ("third.json".to_owned(), full.1.clone());
        let refused = one_per_column(
            &[nopie.clone(), full.clone(), third],
            false,
            Repeated::Refuse,
        )
        .expect_err("three of one configuration");
        let refused = format!("{refused:#}");
        assert!(
            refused.contains("full.json repeats nopie.json")
                && refused.contains("third.json repeats nopie.json"),
            "{refused}"
        );
        // A document that is no report is refused as that, not as a repeat, in either view.
        let mut shapeless = full.clone();
        shapeless.1["defect_coverage"] = json!([]);
        let refused = one_per_column(&[full.clone(), shapeless], true, Repeated::Refuse)
            .expect_err("no defect map");
        assert!(
            format!("{refused:#}").contains("it carries no defect_coverage"),
            "{refused:#}"
        );
        for by_defect in [false, true] {
            let mut listless = full.clone();
            listless.1["observations"] = json!({});
            let refused = one_per_column(&[full.clone(), listless], by_defect, Repeated::Replace)
                .expect_err("no observations");
            assert!(
                format!("{refused:#}").contains("it carries no observations"),
                "{refused:#}"
            );
        }
        // Distinct configurations: every report, in order, and no note.
        let (kept, notes) = one_per_column(&[full.clone(), other.clone()], false, Repeated::Refuse)
            .expect("two configurations");
        assert_eq!(kept, [full, other]);
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn a_repeated_configuration_is_replaced_whole_never_pooled() {
        let [full, nopie, other] = full_nopie_and_other();
        for by_defect in [false, true] {
            for (earlier, later) in [(&full, &nopie), (&nopie, &full)] {
                let (kept, notes) = one_per_column(
                    &[earlier.clone(), other.clone(), later.clone()],
                    by_defect,
                    Repeated::Replace,
                )
                .expect("replaced");
                assert_eq!(
                    drawn(&kept, by_defect),
                    drawn(&[later.clone(), other.clone()], by_defect),
                    "{}'s column whole",
                    later.0
                );
                let (e, l) = (earlier.0.as_str(), later.0.as_str());
                let [note] = notes.as_slice() else {
                    panic!("one note names the repeat: {notes:?}");
                };
                let read = |name: &str, flag: &str| match (name, flag) {
                    ("full.json", "-pie") => "off",
                    ("full.json", _) => "not-applicable",
                    _ => "probe-invalid",
                };
                assert!(
                    note.starts_with(&format!(
                        "{l} repeats the configuration of {e} ({BARE}) and replaces its whole \
                         column, nothing of {e} kept"
                    )) && note.contains("2 flag(s) both carry read differently"),
                    "{note}"
                );
                for flag in ["-pie", "-Wl,-z,pack-relative-relocs"] {
                    let said = format!(
                        "`{flag}` {} in {e} and {} in {l}",
                        read(e, flag),
                        read(l, flag)
                    );
                    assert!(note.contains(&said), "{said}: {note}");
                }
                assert!(
                    !note.contains("`-fstack-clash-protection`"),
                    "read alike: {note}"
                );
                let (said, unsaid) = (
                    "1 flag(s) only full.json carries leave the column with it: \
                     `-fstack-protector-strong`",
                    "1 flag(s) only full.json carries join the column: \
                     `-fstack-protector-strong`",
                );
                let (said, unsaid) = if e == "full.json" {
                    (said, unsaid)
                } else {
                    (unsaid, said)
                };
                assert!(
                    note.contains(said) && !note.contains(unsaid),
                    "{said}: {note}"
                );
                // The by-defect view names the defect row that moved, which the flags alone
                // do not; the protection view says nothing of defect classes.
                let status = |name: &str| {
                    if name == "full.json" { "--" } else { "?" }
                };
                let moved = format!(
                    "1 defect class(es) both carry are drawn differently: `code-reuse` `{}` in \
                     {e} and `{}` in {l}",
                    status(e),
                    status(l)
                );
                if by_defect {
                    assert!(note.contains(&moved), "{moved}: {note}");
                } else {
                    assert!(!note.contains("defect class"), "{note}");
                }
            }
        }
        // The `pie` cell is the later report's word: withheld after the wrapper run, `--`
        // after the full one.
        let pie = |reports: &[(String, Value)]| {
            let (kept, _) = one_per_column(reports, false, Repeated::Replace).expect("replaced");
            let t = collect(&kept).expect("collected");
            t.cells
                .iter()
                .find(|((row, _), _)| row == "pie")
                .map(|(_, cell)| cell.clone())
                .expect("the pie cell")
        };
        assert_eq!(pie(&[full.clone(), nopie.clone()]), "?");
        assert_eq!(pie(&[nopie.clone(), full.clone()]), "--");

        // Distinct configurations: the same reports either way, and no note.
        let pair = [full.clone(), other.clone()];
        let refusing = one_per_column(&pair, false, Repeated::Refuse).expect("two");
        let replacing = one_per_column(&pair, false, Repeated::Replace).expect("two");
        assert_eq!(refusing, replacing);
        assert!(replacing.1.is_empty(), "{:?}", replacing.1);
    }

    #[test]
    fn every_column_field_is_an_axis_the_refusal_names() {
        let column = Column {
            distro: "distro".into(),
            release: "release".into(),
            compiler: "compiler".into(),
            compiler_version: "compiler_version".into(),
            libc: "libc".into(),
            profile: "profile".into(),
            image: "image".into(),
            arch: "arch".into(),
            machine: "machine".into(),
            execution: "execution".into(),
            execution_basis: "execution_basis".into(),
        };
        // Exhaustive, so a field added to `Column` fails to compile here until it is counted.
        let Column {
            distro,
            release,
            compiler,
            compiler_version,
            libc,
            profile,
            image,
            arch,
            machine,
            execution,
            execution_basis,
        } = &column;
        let fields = [
            distro,
            release,
            compiler,
            compiler_version,
            libc,
            profile,
            image,
            arch,
            machine,
            execution,
            execution_basis,
        ];
        assert_eq!(COLUMN_AXES.len(), fields.len());
        // A column is keyed as a matrix cell is: an axis the matrix gains and the table does not
        // pools two of the matrix's cells into one column.
        assert_eq!(COLUMN_AXES.as_slice(), crate::matrix::AXES);
        let distinct: BTreeSet<&str> = COLUMN_AXES.iter().copied().collect();
        assert_eq!(distinct.len(), COLUMN_AXES.len(), "an axis named twice");
        for axis in COLUMN_AXES {
            assert_eq!(
                column.axis(axis),
                axis,
                "the `{axis}` arm reads its own field"
            );
        }
        let described = column.describe();
        assert!(!described.contains("(none)"), "{described}");
        assert_eq!(
            described,
            COLUMN_AXES
                .iter()
                .map(|a| format!("{a} {a}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    #[test]
    fn a_libc_version_alone_is_one_column_and_two_matrix_cells() {
        let [full, ..] = full_nopie_and_other();
        let versioned = |name: &str, version: &str| {
            let mut r = full.1.clone();
            r["environment"]["libc"]["version"] = json!(version);
            (name.to_owned(), r)
        };
        let pair = [versioned("old.json", "2.39"), versioned("new.json", "2.43")];
        let refused = one_per_column(&pair, false, Repeated::Refuse).expect_err("one column");
        assert!(
            format!("{refused:#}").contains("new.json repeats old.json (distro fedora"),
            "{refused:#}"
        );
        let m = crate::matrix::build(&pair).expect("two cells");
        assert_eq!(m.cells.len(), 2, "{:?}", m.cells);
    }

    #[test]
    fn a_replacement_names_defect_classes_and_chains() {
        let [full, nopie, _] = full_nopie_and_other();
        // A defect class only one report carries, and one both read alike, in the by-defect
        // view.
        let mut wider = nopie.clone();
        wider.1["defect_coverage"]["info-leak"] = json!({"status": "mitigated"});
        let (_, notes) =
            one_per_column(&[full.clone(), wider], true, Repeated::Replace).expect("replaced");
        assert!(
            notes[0].contains(
                "1 defect class(es) only nopie.json carries join the column: `info-leak`"
            ),
            "{notes:?}"
        );
        // Reversed, the class only the earlier report carried leaves the column with it.
        let mut wider = nopie.clone();
        wider.1["defect_coverage"]["info-leak"] = json!({"status": "mitigated"});
        let (_, notes) =
            one_per_column(&[wider, full.clone()], true, Repeated::Replace).expect("replaced");
        assert!(
            notes[0].contains(
                "1 defect class(es) only nopie.json carries leave the column with it: `info-leak`"
            ),
            "{notes:?}"
        );
        // The status alone reads `not-mitigated` twice, but one report's bearing checks were
        // partly withheld, so the grid draws `--?` beside `--`: the note names it.
        let partly = |name: &str, counts: Value| {
            let mut r = full.clone();
            r.0 = name.to_owned();
            r.1["defect_coverage"] = json!({"code-reuse": {
                "status": "not-mitigated", "from_checks": ["-pie", "-fPIE"],
                "verdict_counts": counts}});
            r
        };
        let answered = partly("answered.json", json!({"off": 2}));
        let withheld = partly("withheld.json", json!({"off": 1, "probe-invalid": 1}));
        let (_, notes) =
            one_per_column(&[answered, withheld], true, Repeated::Replace).expect("replaced");
        assert!(
            notes[0].contains(
                "1 defect class(es) both carry are drawn differently: `code-reuse` `--` in \
                 answered.json and `--?` in withheld.json"
            ),
            "{notes:?}"
        );
        let (_, notes) = one_per_column(&[full.clone(), full.clone()], true, Repeated::Replace)
            .expect("replaced");
        assert!(
            notes[0].contains("The grid draws every defect class both carry alike for the two"),
            "{notes:?}"
        );
        // Three of one configuration replace in turn.
        let third = ("third.json".to_owned(), full.1.clone());
        let (kept, notes) = one_per_column(
            &[full.clone(), nopie.clone(), third.clone()],
            false,
            Repeated::Replace,
        )
        .expect("replaced twice");
        assert_eq!(kept, [third]);
        let [second, last] = notes.as_slice() else {
            panic!("two notes name the repeats: {notes:?}");
        };
        assert!(
            second.starts_with("nopie.json repeats the configuration of full.json"),
            "{second}"
        );
        assert!(
            last.starts_with("third.json repeats the configuration of nopie.json")
                && last.contains("`-pie` probe-invalid in nopie.json and off in third.json"),
            "{last}"
        );
    }
}
