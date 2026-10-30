// SPDX-License-Identifier: BSD-3-Clause

//! Every assumption the code ships is written down, with what would retire it.
//!
//! The check lives here rather than in a module's own tests because its subject is a
//! *document*. This is the shape the project keeps rediscovering: a rule written down once,
//! relied on afterwards, and checked by nobody. The assumption register was a markdown table
//! maintained beside the binary, so an assumption added in `src/` reached a published report
//! without ever reaching the table.
//!
//! The register is in `THREAT_MODEL.md`, beside the non-goals, which is where a reader needs it,
//! since both answer "what does this tool not establish?"

use std::collections::BTreeSet;
use std::path::PathBuf;

fn threat_model() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("THREAT_MODEL.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The assumption register's section of `THREAT_MODEL.md`, from its heading to the next
/// heading of any level.
fn register_section(text: &str) -> &str {
    // Bounded at the next heading. Unbounded, this took everything to EOF and swallowed
    // "What is explicitly not defended" and "Reporting", so an id appearing anywhere later
    // in the file satisfied the check.
    let after = text
        .split_once("\n### The assumption register\n")
        .expect("THREAT_MODEL.md carries the assumption register")
        .1;
    after.find("\n#").map_or(after, |end| &after[..end])
}

/// Every assumption the code ships has a register entry naming what would retire it.
#[test]
fn every_shipped_assumption_is_in_the_register() {
    let text = threat_model();
    let section = register_section(&text);

    assert!(
        !chard::report::ASSUMPTIONS.is_empty(),
        "an empty register is not a milestone. Every entry left this list by being measured or \
         by having its code deleted, and those are different events — if the count really has \
         reached zero, delete this test rather than letting it pass vacuously"
    );

    for assumption in chard::report::ASSUMPTIONS {
        // The table ROW, not the bare id. `contains(id)` was satisfied by the HTML anchor
        // alone (the anchor contains the id as a substring), so a heading with no
        // statement, no site and no retirement condition passed both this and the anchor
        // test below. Demonstrated by mutating the file to exactly that and watching both
        // assertions hold.
        let row = section
            .lines()
            .find(|l| l.starts_with('|') && l.contains(assumption.id))
            .unwrap_or_else(|| {
                panic!(
                    "`{}` ships in the binary and has no table row in the assumption \
                     register, so nothing states what observation would retire it",
                    assumption.id
                )
            });
        // `| <anchor>statement | site | retired by |`: four pipes, three cells, none empty.
        let cells: Vec<&str> = row
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        assert!(
            cells.len() == 3 && cells.iter().all(|c| !c.is_empty()),
            "`{}`'s register row must carry a statement, a site and a retirement condition; \
             got {} cell(s): {:?}",
            assumption.id,
            cells.len(),
            cells
        );
        assert!(
            cells[2].len() > 10,
            "`{}`'s retirement condition is `{}`, which states no observation that would \
             discharge it",
            assumption.id,
            cells[2]
        );
        assert!(
            !assumption.retired_by.is_empty(),
            "`{}` has a register entry with no retirement condition, which is an assumption \
             recorded rather than one that can ever be discharged",
            assumption.id
        );
    }
}

/// The text of one register copy, set to the form the other is compared in: the first
/// character's case and one trailing full stop are dropped, since `report::ASSUMPTIONS` holds
/// each entry as a clause ("a non-musl libc that defines one") and the table as a sentence
/// ("A non-musl libc that defines one."). Leading and trailing whitespace is trimmed too;
/// nothing else is normalised. A Rust string's line
/// continuation is resolved by the compiler before this sees the text, so a continuation that
/// lost the space before its `\` joins two words and fails here; a table row is one Markdown
/// line, so the table has no continuation to undo.
fn register_text(text: &str) -> String {
    let text = text.trim();
    let text = text.strip_suffix('.').unwrap_or(text);
    let mut chars = text.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_lowercase().chain(chars).collect())
}

/// Every entry in `report::ASSUMPTIONS` and its `THREAT_MODEL.md` row say the same thing in
/// the statement, the retirement condition and the site. The site is compared with its
/// backticks dropped, since the table sets every path in code and the entry only the check ids.
///
/// The register lives twice, and the test above holds only that each entry has a row with
/// three non-empty cells. A row's statement cell is never empty, because the anchor opens it.
/// So this test holds each entry's fields non-empty, since two copies equally empty would
/// otherwise pass. The row is found by its anchor, `<a id="ID"></a>` at the start of the
/// statement cell, and must be the only one: an id is matched whole, not as a substring of
/// another row.
#[test]
fn every_register_entry_reads_the_same_in_both_copies() {
    let text = threat_model();
    let section = register_section(&text);
    let mut differences = Vec::new();
    for assumption in chard::report::ASSUMPTIONS {
        let anchor = format!("<a id=\"{}\"></a>", assumption.id);
        let rows: Vec<&str> = section
            .lines()
            .filter(|l| l.starts_with('|') && l.contains(&anchor))
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "`{}` must have exactly one register row carrying its anchor; found {rows:?}",
            assumption.id
        );
        let cells: Vec<&str> = rows[0]
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        let [statement, site, retired_by] = cells[..] else {
            panic!("`{}`'s row has {} cells", assumption.id, cells.len())
        };
        let statement = statement.strip_prefix(&anchor).unwrap_or_else(|| {
            panic!(
                "`{}`'s anchor does not open its statement cell",
                assumption.id
            )
        });
        let unticked = |s: &str| s.replace('`', "");
        for (field, entry, row) in [
            (
                "statement",
                register_text(assumption.statement),
                register_text(statement),
            ),
            (
                "retired_by",
                register_text(assumption.retired_by),
                register_text(retired_by),
            ),
            ("site", unticked(assumption.site), unticked(site)),
        ] {
            assert!(
                !entry.is_empty(),
                "`{}`'s {field} is empty in report::ASSUMPTIONS",
                assumption.id
            );
            if entry != row {
                differences.push(format!(
                    "`{}` {field}:\n  report::ASSUMPTIONS: {entry}\n  THREAT_MODEL.md:     {row}",
                    assumption.id
                ));
            }
        }
    }
    assert!(
        differences.is_empty(),
        "the assumption register's two copies differ; make them say the same thing:\n{}",
        differences.join("\n")
    );
}

/// The probe environment `THREAT_MODEL.md` describes is the one `run::execute` sets.
///
/// The same subject as the register: a document making a claim about the code, held against
/// the code. The claim is that a probe receives exactly the pinned variables and that the run
/// record carries them, so the document must name every pin and the field. A pin added in
/// `src/run.rs` without a sentence here is the table-beside-the-binary shape this file's
/// header describes.
#[test]
fn the_threat_model_names_the_probe_environment_the_code_sets() {
    let text = threat_model();
    assert!(
        !chard::run::PROBE_ENVIRONMENT.is_empty(),
        "an empty probe environment would make this test compare nothing; if `LC_ALL` has \
         really gone, delete the test rather than let it pass vacuously"
    );
    for (name, value) in chard::run::PROBE_ENVIRONMENT {
        let spelled = format!("`{name}={value}`");
        assert!(
            text.contains(&spelled),
            "every probe receives {spelled} and THREAT_MODEL.md does not say so"
        );
    }
    // A probe's own pins (`probe::Probe::run_environment`) reach its runs beside the list
    // above, so the document names each beside the probe that declares it, in the same
    // paragraph. A pin added to a probe without a sentence here is the same shape as one
    // added to the list.
    let paragraph = text
        .split_once("**Environmental perturbation of a measurement.**")
        .expect("THREAT_MODEL.md carries the environmental-perturbation paragraph")
        .1
        .split_once("\n\n")
        .map_or("", |(p, _)| p);
    for probe in chard::probe::CORPUS {
        for (name, value) in probe.run_environment {
            let spelled = format!("`{name}={value}`");
            let named = format!("`{}`", probe.id);
            assert!(
                paragraph.contains(&spelled) && paragraph.contains(&named),
                "probe `{}` runs with {spelled} and THREAT_MODEL.md's environmental-perturbation \
                 paragraph does not name the pin beside the probe",
                probe.id
            );
        }
    }
    assert!(
        text.contains("`environment`"),
        "THREAT_MODEL.md does not name the run record field that carries the probe's environment"
    );
}

/// The compiler environment `THREAT_MODEL.md` describes is the one `compile::invoke` sets.
///
/// The probe-environment test above has a sibling claim for the compiler, and until
/// 2026-09-28 nothing held it: the document's list named nine variables while the code
/// removed fourteen, so a reader of the threat model saw a narrower defence than the one
/// shipped, and the next variable added to the code had no reason to reach the prose. Since
/// 2026-10-11 the compiler sentence carries two lists, each read as a set of backticked names
/// and compared in both directions: the parenthesised list after "passes from its own (" with
/// `compile::COMPILER_ENV_PASSED`, which is what reaches the driver beside the pins, and the
/// one after "were it passed (" with `compile::COMPILER_ENV_NAMED`, so an entry added on
/// either side alone fails here. Each pin in `compile::COMPILER_ENV_PINNED` must appear in
/// the same sentences as `NAME=value`.
#[test]
fn the_threat_model_names_the_compiler_environment_the_code_sets() {
    use std::collections::BTreeSet;

    let compiler = compiler_sentences();
    let list_after = |marker: &str| -> BTreeSet<&str> {
        let list = compiler
            .split_once(marker)
            .and_then(|(_, rest)| rest.split_once(')'))
            .unwrap_or_else(|| panic!("the compiler sentence carries a list as `{marker}...)`"))
            .0;
        list.split('`').skip(1).step_by(2).collect()
    };
    for (marker, code, name) in [
        (
            "passes from its own (",
            chard::compile::COMPILER_ENV_PASSED,
            "COMPILER_ENV_PASSED",
        ),
        (
            "were it passed (",
            chard::compile::COMPILER_ENV_NAMED,
            "COMPILER_ENV_NAMED",
        ),
    ] {
        let documented = list_after(marker);
        let set: BTreeSet<&str> = code.iter().copied().collect();
        assert!(
            !set.is_empty(),
            "an empty `compile::{name}` would make this test compare nothing; if every \
             variable has really gone, delete the comparison rather than let it pass vacuously"
        );
        assert_eq!(
            set.len(),
            code.len(),
            "`compile::{name}` names a variable twice"
        );
        let undocumented: Vec<&&str> = set.difference(&documented).collect();
        assert!(
            undocumented.is_empty(),
            "`compile::{name}` holds {undocumented:?} and THREAT_MODEL.md's list does not say so"
        );
        let unimplemented: Vec<&&str> = documented.difference(&set).collect();
        assert!(
            unimplemented.is_empty(),
            "THREAT_MODEL.md's list names {unimplemented:?} and `compile::{name}` does not"
        );
    }

    assert!(
        !chard::compile::COMPILER_ENV_PINNED.is_empty(),
        "an empty pin list would make this check compare nothing; if `LC_ALL` has really \
         gone, delete the check rather than let it pass vacuously"
    );
    for (name, value) in chard::compile::COMPILER_ENV_PINNED {
        let spelled = format!("`{name}={value}`");
        assert!(
            compiler.contains(&spelled),
            "every compiler invocation receives {spelled} and THREAT_MODEL.md's compiler \
             sentence does not say so"
        );
    }
}

/// The paths `THREAT_MODEL.md` says a report carries as written are the ones `--normalize`
/// replaces.
///
/// The sentence lists the options whose values `run.invocation` publishes as the operator
/// wrote them, and `report::INVOCATION_PATH_OPTIONS` is the list `normalized_invocation`
/// replaces. Read as a set of backticked spellings between "so the values of" and "are
/// published as written" and compared in both directions, so a path-valued option added to
/// the code alone, or to the sentence alone, fails here.
#[test]
fn the_threat_model_names_the_invocation_paths_a_report_carries() {
    use std::collections::BTreeSet;

    let text = threat_model();
    let paragraph = text
        .split_once("**A report names the paths it was given.**")
        .expect("THREAT_MODEL.md carries the paragraph on the paths a report names")
        .1
        .split_once(
            "

",
        )
        .map_or("", |(p, _)| p)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let documented: BTreeSet<&str> = paragraph
        .split_once("so the values of ")
        .and_then(|(_, rest)| rest.split_once(" are published as written"))
        .expect(
            "the paragraph lists the options as `so the values of ... are published as written`",
        )
        .0
        .split('`')
        .skip(1)
        .step_by(2)
        .collect();
    let code: BTreeSet<&str> = chard::report::INVOCATION_PATH_OPTIONS
        .iter()
        .copied()
        .collect();
    assert!(
        !code.is_empty(),
        "an empty `report::INVOCATION_PATH_OPTIONS` would make this test compare nothing"
    );
    assert_eq!(
        code, documented,
        "`report::INVOCATION_PATH_OPTIONS` and THREAT_MODEL.md's list of the paths a report \
         carries as written disagree"
    );
    assert!(
        paragraph.contains("`run.invocation`") && paragraph.contains("`argv[0]`"),
        "the paragraph names the field and what it keeps of `argv[0]`"
    );
}

/// The compiler's sentences of `THREAT_MODEL.md`'s environmental-perturbation paragraph,
/// whitespace collapsed so a marker the paragraph's wrapping splits across two lines is
/// still found. They end where the probe's begin.
fn compiler_sentences() -> String {
    let text = threat_model();
    let paragraph = text
        .split_once("**Environmental perturbation of a measurement.**")
        .expect("THREAT_MODEL.md carries the environmental-perturbation paragraph")
        .1;
    paragraph
        .split_once("A probe runs")
        .expect("the paragraph describes the probe environment after the compiler's")
        .0
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The compiler sentences say how a toolchain's configuration is given (`--env`) and where
/// the report publishes the environment, and the field they name is the one a serialized
/// profile carries; they say `--env` refuses a passed or pinned name, which
/// `compile::compiler_environment_additions` is held to for each such name here.
#[test]
fn the_threat_model_says_how_the_compiler_environment_is_given_and_published() {
    let compiler = compiler_sentences();
    // The environment is published, under the field the document names.
    assert!(
        compiler.contains("`profile.compiler_environment`")
            && compiler.contains("`--env NAME=VALUE`"),
        "THREAT_MODEL.md's compiler sentences do not say how a configuration is given and \
         where the report publishes the environment"
    );
    let profile = chard::report::Profile {
        id: "bare".to_owned(),
        flags_source: "none".to_owned(),
        cflags: Vec::new(),
        cxxflags: Vec::new(),
        ldflags: Vec::new(),
        toolchain_note: None,
        compiler_environment: chard::compile::CompilerEnvironment::under(
            &chard::compile::EnvPairs::default(),
        ),
    };
    let published = serde_json::to_value(&profile).expect("a profile serializes");
    assert!(
        published.get("compiler_environment").is_some(),
        "THREAT_MODEL.md names `profile.compiler_environment` and a profile publishes no such \
         field: {published}"
    );
    // A pair naming a passed or pinned variable is refused, as the sentences say.
    assert!(compiler.contains("`--env` refuses a name chard passes or pins"));
    for name in chard::compile::COMPILER_ENV_PASSED.iter().chain(
        chard::compile::COMPILER_ENV_PINNED
            .iter()
            .map(|(name, _)| name),
    ) {
        assert!(
            chard::compile::compiler_environment_additions(&[format!("{name}=x")]).is_err(),
            "THREAT_MODEL.md says --env refuses {name} and it is accepted"
        );
    }
}

/// Each id is citable: `#need-macros-identify-musl` resolves to an anchor.
///
/// A bolded id renders as bold text and links to nothing, so a citation to it fails silently.
/// The predecessor of this test caught exactly that in a register of fifteen ids.
#[test]
fn every_shipped_assumption_id_has_an_anchor() {
    let text = threat_model();
    for assumption in chard::report::ASSUMPTIONS {
        let anchor = format!("<a id=\"{}\"></a>", assumption.id);
        assert!(
            text.contains(&anchor),
            "`{}` has no HTML anchor, so `THREAT_MODEL.md#{}` resolves to nothing and a \
             citation to it cannot be followed",
            assumption.id,
            assumption.id
        );
    }
}

/// Every row of the register's table is an assumption the code ships, and the table holds as
/// many rows as `report::ASSUMPTIONS` holds entries.
///
/// The converse of `every_shipped_assumption_is_in_the_register`, which reads code to table:
/// a row whose `report::ASSUMPTIONS` entry was deleted stayed in the table, and the register
/// overstated what the binary assumes. The table is the first run of lines opening with `|`
/// after leading whitespace. Outside that run the section carries no `|` and no `<a id=`: a
/// GFM row needs neither the leading pipe nor column zero, so a row written ` | ...` or
/// `<a id="x"></a>a | b | c` renders in the table and would otherwise pass uncounted. The six
/// assumptions that left the register are prose below the table, so a second table there
/// fails this test rather than escaping the count. The section must end at the heading that
/// follows it in the file, so a `#` line inside it cannot cut the table short unseen. That pin
/// names the heading literally, so renaming `## What is explicitly not defended` fails this test
/// even though nothing is wrong: wanted, because a pin that followed any heading could not tell
/// a rename from a `#` line inserted into the section, and the rename costs one edit here.
/// The line after the table's last row must be blank or the section's end: under GFM a table
/// ends only at a blank line or another block, so a non-blank line there is a lazy
/// continuation, a one-cell row carrying neither `|` nor `<a id=`.
#[test]
fn every_register_row_is_a_shipped_assumption() {
    use std::collections::BTreeSet;

    let text = threat_model();
    let section = register_section(&text);
    // `register_section` returns a slice of `text`, so its end is an offset into the file;
    // what follows it opens with the newline before the heading that bounded it.
    let section_end = section.as_ptr() as usize - text.as_ptr() as usize + section.len();
    let next_heading = text[section_end..].lines().nth(1).unwrap_or("end of file");
    assert_eq!(
        next_heading, "## What is explicitly not defended",
        "the assumption register's section ends at a heading other than the one after it in \
         the file, so a line inside it starting with `#` cut it short and rows beyond the cut \
         would go unread"
    );
    let lines: Vec<&str> = section.lines().collect();
    let in_table = |l: &str| l.trim_start().starts_with('|');
    let start = lines
        .iter()
        .position(|l| in_table(l))
        .expect("the assumption register's section carries a table");
    let end = start + lines[start..].iter().take_while(|l| in_table(l)).count();
    // GFM ends a table only at a blank line or the start of another block (spec example
    // 201): any other line after the last row is a lazy continuation, rendered as a one-cell
    // row with no `|` and no anchor, which the guard below would not see. Blank means spaces
    // and tabs alone, as CommonMark counts it: `str::trim` also strips a no-break space, and
    // a line holding only one is a lazy continuation row too.
    let after_table = lines.get(end).copied().unwrap_or("");
    assert!(
        after_table.trim_matches([' ', '\t']).is_empty(),
        "the line after the assumption register's table is not blank, so GFM renders it as a \
         lazy continuation row of the table that this test would not count: {after_table:?}"
    );
    let table = &lines[start..end];
    let elsewhere: Vec<&str> = lines[..start]
        .iter()
        .chain(&lines[end..])
        .copied()
        .filter(|l| l.contains('|') || l.contains("<a id="))
        .collect();
    assert!(
        elsewhere.is_empty(),
        "the assumption register's section carries {} line(s) with `|` or `<a id=` outside its \
         table, which GitHub may render as rows and this test would not count: {elsewhere:?}",
        elsewhere.len()
    );
    assert_eq!(
        table.get(..2),
        Some(&["| assumption | site | retired by |", "|---|---|---|"][..]),
        "the register's table opens with its header and separator rows"
    );

    // `| <a id="ID"></a>statement | site | retired by |`: the anchor opens every row.
    let ids: Vec<&str> = table[2..]
        .iter()
        .map(|row| {
            row.trim_start()
                .strip_prefix("| <a id=\"")
                .and_then(|rest| rest.split_once("\"></a>"))
                .unwrap_or_else(|| panic!("a register row opens with no anchor: {row}"))
                .0
        })
        .collect();
    eprintln!(
        "### The assumption register: {} section lines ending before `{next_heading}`, {} rows \
         from `{}` to `{}`, against {} entries in report::ASSUMPTIONS",
        lines.len(),
        ids.len(),
        ids.first().unwrap_or(&"none"),
        ids.last().unwrap_or(&"none"),
        chard::report::ASSUMPTIONS.len()
    );
    assert!(
        !ids.is_empty(),
        "the register's table has no rows, so this test compares nothing; \
         every_shipped_assumption_is_in_the_register says what an empty register means"
    );

    let shipped: BTreeSet<&str> = chard::report::ASSUMPTIONS.iter().map(|a| a.id).collect();
    let orphans: Vec<&&str> = ids.iter().filter(|id| !shipped.contains(**id)).collect();
    assert!(
        orphans.is_empty(),
        "the register's table has rows for {orphans:?}, which `report::ASSUMPTIONS` does not \
         ship; an assumption that leaves the code leaves the table for the prose below it"
    );
    let distinct: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        ids.len(),
        "the register's table has two rows for one id"
    );
    assert_eq!(
        ids.len(),
        chard::report::ASSUMPTIONS.len(),
        "the register's table has {} rows and `report::ASSUMPTIONS` {} entries",
        ids.len(),
        chard::report::ASSUMPTIONS.len()
    );
}

/// The fault reporter's paragraph in `THREAT_MODEL.md`, whitespace collapsed.
fn fault_reporter_paragraph(text: &str) -> String {
    text.split_once("**A probe's account of how it died.**")
        .expect("THREAT_MODEL.md carries the fault reporter's paragraph")
        .1
        .split_once("\n\n")
        .map_or("", |(p, _)| p)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The backticked names in the parenthesised list after `marker`.
fn listed_after<'a>(paragraph: &'a str, marker: &str) -> BTreeSet<&'a str> {
    paragraph
        .split_once(marker)
        .and_then(|(_, rest)| rest.split_once(')'))
        .unwrap_or_else(|| panic!("the paragraph carries a list as `{marker}...)`"))
        .0
        .split('`')
        .skip(1)
        .step_by(2)
        .collect()
}

/// The fault reporter's paragraph names the line, the signals, the architectures and the
/// probes the code has.
///
/// The prefix and fields are compared with the string literals the handler in
/// `probes/chard_selfreport.h` writes and with `run::FaultReport::FIELDS`, which `parse`
/// requires exactly; the signals with the handler's `sigaction` calls; the architectures with
/// the guard the handler is compiled under, every term of which must parse; and the probes that
/// opt in with the corpus, by their source. A flag spelling the macro cannot be tied to a probe
/// id here, so any file under `src/` but `src/run.rs` that spells it fails. Each set is
/// compared in both directions.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one comparison per list the paragraph names, read in the paragraph's order"
)]
fn the_threat_model_names_the_fault_reporter_the_code_has() {
    use chard::run::FaultReport;

    let text = threat_model();
    let paragraph = fault_reporter_paragraph(&text);
    let prefix = FaultReport::PREFIX.trim_end();
    let header = chard::probe::SELFREPORT_HEADER;
    let block = header
        .split_once("#if defined(CHARD_WANT_FAULT_REPORT)\n")
        .expect("probes/chard_selfreport.h carries the fault reporter")
        .1;

    // The handler's literals: the prefix opens the first one that names a field, and every
    // `name=` token in them is a field the line carries.
    let handler = block
        .split_once("static void chard_fault_handler(")
        .and_then(|(_, rest)| rest.split_once("\n}\n"))
        .expect("probes/chard_selfreport.h defines chard_fault_handler")
        .0;
    let literals: Vec<&str> = handler.split('"').skip(1).step_by(2).collect();
    let first = literals
        .iter()
        .find(|l| l.contains('='))
        .expect("the handler writes a field");
    assert!(
        first.starts_with(FaultReport::PREFIX),
        "the handler's line opens with {first:?}, and `FaultReport::PREFIX` is {:?}",
        FaultReport::PREFIX
    );
    let written: BTreeSet<&str> = literals
        .iter()
        .flat_map(|l| l.split_whitespace())
        .filter_map(|token| token.split_once('=').map(|(name, _)| name))
        .collect();
    let parsed: BTreeSet<&str> = FaultReport::FIELDS.iter().copied().collect();
    assert!(
        FaultReport::FIELDS.is_sorted() && parsed.len() == FaultReport::FIELDS.len(),
        "`FaultReport::FIELDS` must be sorted and distinct, the order `parse` collects keys in"
    );
    assert_eq!(
        written, parsed,
        "the handler writes {written:?} and `FaultReport::parse` requires {parsed:?}"
    );
    let documented = listed_after(&paragraph, &format!("`{prefix}` followed by its fields ("));
    assert_eq!(
        documented, parsed,
        "THREAT_MODEL.md lists {documented:?} and `FaultReport::parse` requires {parsed:?}"
    );

    // The signals the handler installs itself for.
    let caught: BTreeSet<&str> = block
        .split("sigaction(")
        .skip(1)
        .filter_map(|call| call.split_once(", &sa, NULL)").map(|(signal, _)| signal))
        .collect();
    let named = listed_after(&paragraph, ") catches (");
    assert!(
        !caught.is_empty(),
        "the handler installs itself for no signal"
    );
    assert_eq!(
        named, caught,
        "THREAT_MODEL.md lists {named:?} and the handler catches {caught:?}"
    );

    // The architectures: the guard on the line after the opt-in, `__linux__` aside.
    let guard = block.lines().next().unwrap_or_default();
    assert!(
        guard.starts_with("#if defined(__linux__) && ("),
        "the reporter is guarded by Linux and a list of architectures: {guard}"
    );
    let terms: Vec<&str> = guard
        .split("defined(")
        .skip(1)
        .map(|rest| rest.split_once(')').map_or(rest, |(term, _)| term))
        .collect();
    for term in &terms {
        assert!(
            term.len() > 4 && term.starts_with("__") && term.ends_with("__"),
            "the reporter's guard tests `{term}`, which this test cannot read as an architecture"
        );
    }
    let built: BTreeSet<&str> = terms
        .iter()
        .map(|term| term.trim_matches('_'))
        .filter(|arch| *arch != "linux")
        .collect();
    let stated: BTreeSet<&str> = paragraph
        .split_once("on Linux (")
        .and_then(|(_, rest)| rest.split_once(')'))
        .expect("the paragraph names the architectures as `on Linux (...)`")
        .0
        .split(", ")
        .flat_map(|part| part.split(" and "))
        .collect();
    assert!(
        !built.is_empty(),
        "the reporter's guard names no architecture"
    );
    assert_eq!(
        stated, built,
        "THREAT_MODEL.md says the reporter runs on {stated:?} and it is built for {built:?}"
    );

    // The probes that opt in: by their source, or by a flag spelled anywhere in `src/` other
    // than `src/run.rs`, which reads the line and names the macro in its documentation.
    let opted: Vec<&str> = chard::probe::CORPUS
        .iter()
        .filter(|probe| probe.source.contains("CHARD_WANT_FAULT_REPORT"))
        .map(|probe| probe.id)
        .collect();
    let mut spelled = Vec::new();
    let mut pending = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if !path.ends_with("src/run.rs")
                && std::fs::read_to_string(&path)
                    .is_ok_and(|source| source.contains("CHARD_WANT_FAULT_REPORT"))
            {
                spelled.push(path.display().to_string());
            }
        }
    }
    assert!(
        spelled.is_empty(),
        "{spelled:?} spell the fault reporter's macro, which opts a probe in by a flag this test \
         cannot tie to a probe id; opt in by the probe's source, or teach this test the flag"
    );
    if paragraph.contains("No probe in the corpus opts in yet") {
        assert!(
            opted.is_empty(),
            "THREAT_MODEL.md says no probe opts in to the fault reporter, and {opted:?} do"
        );
    }
    for id in &opted {
        assert!(
            paragraph.contains(&format!("`{id}`")),
            "probe `{id}` opts in to the fault reporter and THREAT_MODEL.md's paragraph does \
             not name it"
        );
    }
}

/// A run record whose stderr is `stderr` and whose death is `signal`.
fn fault_record(signal: Option<&str>, stderr: &str) -> chard::run::RunRecord {
    chard::run::RunRecord {
        argv: vec!["probe".to_owned()],
        exit_status: if signal.is_some() { -1 } else { 0 },
        signal: signal.map(ToOwned::to_owned),
        stdout: String::new(),
        stderr: stderr.to_owned(),
        timed_out: false,
        deadline_ms: None,
        output_error: None,
        output_truncated: false,
        duration_ms: 1,
        environment: None,
    }
}

/// The rules the fault reporter's paragraph says a report is read by are the ones
/// `RunRecord` applies.
///
/// Each rule is checked on lines of the reporter's shape. "Never adds trap credit" is checked
/// over every line the enumeration below spells (signals 1 to 31, each `si_code` the reporter
/// was measured writing, each architecture, and words and ESR values of every class) under
/// every death the line could be read for, rather than over examples.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one block per read rule the paragraph states, read in the paragraph's order"
)]
fn the_threat_model_states_the_rules_a_fault_report_is_read_by() {
    use chard::run::{Fault, FaultReport};

    let text = threat_model();
    let paragraph = fault_reporter_paragraph(&text);
    let prefix = FaultReport::PREFIX.trim_end();
    let record = fault_record;

    // Lines of the reporter's shape, from the measured lines in `src/run.rs`.
    let bti = "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xbd74c4c00a5c addr=0xbd74c4c00a5c word=0xd28000e0 esr=none at-target=yes";
    let pac = "chard-fault-v1 signal=4 code=2 sent=no arch=aarch64 pc=0xb95168ec0cdc addr=0xb95168ec0cdc word=0xd50323bf esr=0x72000000 at-target=undeclared";
    let unread = bti.replace("word=0xd28000e0", "word=none");

    // The bare signal: `SIGILL` and `SIGTRAP` are traps and nothing else is.
    assert!(paragraph.contains("the bare signal (`SIGILL` or `SIGTRAP`)"));
    for (death, trap) in [
        (Some("SIGILL"), true),
        (Some("SIGTRAP"), true),
        (Some("SIGSEGV"), false),
        (Some("SIGBUS"), false),
        (Some("SIGABRT"), false),
        (Some("SIGFPE"), false),
        (None, false),
    ] {
        assert_eq!(
            record(death, "").trapped(),
            trap,
            "{death:?} without a report"
        );
    }

    // Only whole: the line as written reads, and without any one field, or with a field
    // unknown, repeated or malformed, it does not.
    assert!(paragraph.contains("A report is read only whole"));
    assert!(record(Some("SIGILL"), bti).fault_report().is_some());
    for field in FaultReport::FIELDS {
        let cut: Vec<&str> = bti
            .split(' ')
            .filter(|token| !token.starts_with(&format!("{field}=")))
            .collect();
        assert!(
            record(Some("SIGILL"), &cut.join(" ")).fault().is_none(),
            "a report without `{field}` is read"
        );
    }
    for broken in [
        format!("{bti} extra=1"),
        bti.replace("signal=4", "signal=4 signal=4"),
        bti.replace("word=0xd28000e0", "word=d28000e0"),
    ] {
        assert!(
            record(Some("SIGILL"), &broken).fault().is_none(),
            "a report with a field unknown, repeated or malformed is read: {broken}"
        );
    }

    // Only the last line, and a malformed last line is not passed over for an earlier one.
    assert!(paragraph.contains(&format!("only from the last `{prefix}` line")));
    assert_eq!(
        record(Some("SIGILL"), &format!("{pac}\n{bti}\n")).fault(),
        Some(Fault::BtiFault)
    );
    assert_eq!(
        record(Some("SIGILL"), &format!("{bti}\n{pac}\n")).fault(),
        Some(Fault::PacFailure)
    );
    assert_eq!(
        record(Some("SIGILL"), &format!("{bti}\n{bti} extra=1\n")).fault(),
        None,
        "an earlier report was read in place of a malformed last line"
    );

    // Only about the recorded death.
    assert!(paragraph.contains("only when its signal is the signal the run record says"));
    assert_eq!(record(Some("SIGTRAP"), bti).fault(), None);
    assert_eq!(record(None, bti).fault(), None);

    // Removes trap credit, never adds it: a record carrying a report is a trap only where the
    // same record without one is, for every line spelled here under every death.
    assert!(paragraph.contains("a report can remove trap credit and never add it"));
    let deaths: [(i32, &str); 6] = [
        (4, "SIGILL"),
        (5, "SIGTRAP"),
        (6, "SIGABRT"),
        (7, "SIGBUS"),
        (8, "SIGFPE"),
        (11, "SIGSEGV"),
    ];
    let words = [
        "none",
        "0x0",
        "0xd4207d00",
        "0xd28000e0",
        "0xd50323bf",
        "0x0b0f",
        "0xb90f67",
        "0xcc",
    ];
    let esrs = ["none", "0x72000000", "0x36000002", "0x92000044"];
    let mut classes = BTreeSet::new();
    let (mut lines, mut removed) = (0_usize, 0_usize);
    for signal in 1..=31 {
        for code in [-6, -1, 0, 1, 2, 3, 128] {
            for arch in ["aarch64", "x86_64", "x86"] {
                for word in words {
                    for esr in esrs {
                        for at in ["yes", "no", "undeclared"] {
                            let sent = if code <= 0 { "yes" } else { "no" };
                            let line = format!(
                                "chard-fault-v1 signal={signal} code={code} sent={sent} arch={arch} \
                                 pc=0x1000 addr=0x1000 word={word} esr={esr} at-target={at}\n"
                            );
                            lines += 1;
                            for (number, name) in deaths {
                                let bare = record(Some(name), "").trapped();
                                let with = record(Some(name), &line);
                                assert!(
                                    bare || !with.trapped(),
                                    "a report added trap credit under {name}: {line}"
                                );
                                removed += usize::from(bare && !with.trapped());
                                if number == signal {
                                    let fault = with.fault();
                                    assert!(fault.is_some(), "a well-formed line is read: {line}");
                                    classes.insert(format!("{fault:?}"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(lines > 0 && removed > 0, "the enumeration compared nothing");
    assert_eq!(
        classes.len(),
        Fault::ALL.len(),
        "the enumeration reaches every class, so the rule is checked on each: {classes:?}"
    );

    // Missing and undecided are distinct from a trap and from each other, and are what an
    // opting check reads through `RunRecord::fault`.
    assert!(
        paragraph.contains("reads `RunRecord::fault` instead")
            && paragraph.contains("a missing report")
            && paragraph.contains("`Fault::Undetermined`")
            && paragraph.contains("must withhold the reading")
    );
    let missing = record(Some("SIGILL"), "");
    assert_eq!(missing.fault(), None);
    let undecided = record(Some("SIGILL"), &unread);
    assert_eq!(undecided.fault(), Some(Fault::Undetermined));
    assert!(
        !undecided.trapped(),
        "an undecided report is credited as a trap"
    );
}

/// `diag-stream-is-text-unless-recognised` names the checks that read a linker line beside a
/// recognised structured stream, and those are exactly the checks in `DIAG_NEEDLES_EXEMPT`,
/// in the register's statement and in `THREAT_MODEL.md`'s row alike. A check moved into or out
/// of the exemption without the sentence would make the entry false about which checks it
/// withholds. That `DIAG_NEEDLES` holds every other compiler-diag check, so the statement's
/// "the checks in `DIAG_NEEDLES`" is the rest, is
/// `probe::tests::every_compiler_diag_check_is_in_the_needle_table_or_exempt_from_it`.
///
/// `every_register_entry_reads_the_same_in_both_copies` holds the two copies to each other,
/// and two copies equally wrong pass it. This test stays beside it because it holds the
/// sentence to the code, `DIAG_NEEDLES_EXEMPT`, which no comparison of the copies can do.
#[test]
fn the_diag_stream_entry_names_the_checks_exempt_from_it() {
    const ID: &str = "diag-stream-is-text-unless-recognised";
    let diag: BTreeSet<&str> = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .filter(|c| c.channel() == chard::probe::Channel::CompilerDiag)
        .map(|c| c.id)
        .collect();
    let exempt: BTreeSet<&str> = chard::probe::DIAG_NEEDLES_EXEMPT
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert!(!exempt.is_empty(), "the exemption list is empty");
    // The compiler-diag check ids a sentence names in backticks.
    let named = |sentence: &str| -> BTreeSet<String> {
        sentence
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|word| diag.contains(word))
            .map(str::to_owned)
            .collect()
    };
    let want: BTreeSet<String> = exempt.iter().map(|id| (*id).to_owned()).collect();

    let entry = chard::report::ASSUMPTIONS
        .iter()
        .find(|a| a.id == ID)
        .expect("the diag-stream entry ships");
    let text = threat_model();
    let row = register_section(&text)
        .lines()
        .find(|l| l.starts_with('|') && l.contains(&format!("<a id=\"{ID}\"></a>")))
        .expect("the diag-stream entry has a register row");
    let statement = row
        .trim_matches('|')
        .split('|')
        .next()
        .expect("the row has a statement cell");
    for (place, sentence) in [
        ("report::ASSUMPTIONS", entry.statement),
        ("THREAT_MODEL.md", statement),
    ] {
        eprintln!(
            "{place}: names {:?}; DIAG_NEEDLES_EXEMPT {exempt:?}",
            named(sentence)
        );
        assert_eq!(
            named(sentence),
            want,
            "{place}'s statement of {ID} names other compiler-diag checks than \
             DIAG_NEEDLES_EXEMPT holds"
        );
        for list in ["`DIAG_NEEDLES`", "`DIAG_NEEDLES_EXEMPT`"] {
            assert!(
                sentence.contains(list),
                "{place}'s statement of {ID} does not point at {list}"
            );
        }
    }
}

/// `self-report-absent-withholds-the-macro-channel` names one object probe with a
/// macro-channel check, `exceptions`, as the probe whose `-c` object under `-flto` holds its
/// section as LTO IR (gcc's slim object) or as bitcode the reader refuses (clang's). A second
/// such probe would make that sentence false, so the set is held here.
#[test]
fn the_register_names_every_macro_channel_object_probe() {
    let object_macro: Vec<&str> = chard::probe::CORPUS
        .iter()
        .filter(|p| p.link_mode == chard::probe::LinkMode::Object)
        .filter(|p| {
            p.checks
                .iter()
                .any(|c| c.channel() == chard::probe::Channel::Macro)
        })
        .map(|p| p.id)
        .collect();
    assert_eq!(
        object_macro,
        ["exceptions"],
        "the register entry self-report-absent-withholds-the-macro-channel names `exceptions` \
         as the one object probe with a macro-channel check"
    );
}

/// The paragraphs of the `///` block directly above the first line of `text` that starts,
/// once trimmed, with `item`, each joined into one line; a bare `///` separates two. Empty
/// where no doc comment sits there. Panics where no line starts so, since a renamed item
/// would otherwise leave a doc check reading nothing.
fn doc_above(text: &str, item: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with(item))
        .unwrap_or_else(|| panic!("no line starts with `{item}`"));
    let mut doc: Vec<&str> = lines[..at]
        .iter()
        .rev()
        .take_while(|l| l.trim_start().starts_with("///"))
        .map(|l| l.trim_start().trim_start_matches("///").trim())
        .collect();
    doc.reverse();
    doc.split(|l| l.is_empty())
        .filter(|p| !p.is_empty())
        .map(|p| p.join(" "))
        .collect()
}

/// The link classifier leaves one case open, an interpreter-less `ET_DYN` with neither marker,
/// and lld 10.0.0 under `-static-pie -Wl,-z,rodynamic` writes it (measured on Ubuntu 20.04
/// x86_64, 2026-10-26). `every-static-pie-carries-a-marker` is retired by mechanism:
/// `report::link_mode_limitation` withholds a reading of the classification over an
/// executable link's artifact that classifies as a shared object. So the entry does not ship,
/// the register carries no row for it, and each doc comment that describes the case
/// names the gate in the same paragraph: `elf::LinkKind::StaticPie`'s, `SharedObject`'s and
/// the precondition table's. DESIGN.md's paragraph on the `as-needed` row names it too; this
/// test does not read DESIGN.md, which `scripts/merge-gate.sh`'s document map would then have
/// to list for this target.
#[test]
fn the_unmarked_static_pie_is_withheld_where_the_case_is_described() {
    const RETIRED: &str = "every-static-pie-carries-a-marker";
    const GATE: &str = "link_mode_limitation";
    const LONG: &str = "neither `DF_1_PIE` nor `DT_DEBUG`";
    assert!(
        !chard::report::ASSUMPTIONS.iter().any(|a| a.id == RETIRED),
        "{RETIRED} is retired and still ships in report::ASSUMPTIONS"
    );
    let text = threat_model();
    assert!(
        !register_section(&text).contains(RETIRED),
        "{RETIRED} is retired and the register still names it"
    );
    let elf = include_str!("../src/elf.rs");
    let report = include_str!("../src/report.rs");
    assert!(
        report.contains(&format!("pub fn {GATE}(")),
        "the gate {GATE} is not in src/report.rs"
    );
    let sites: [(&str, Vec<String>, &str); 3] = [
        (
            "src/elf.rs, LinkKind::StaticPie",
            doc_above(elf, "StaticPie { df_1_pie: bool, dt_debug: bool },"),
            "carrying neither marker",
        ),
        (
            "src/elf.rs, LinkKind::SharedObject",
            doc_above(elf, "SharedObject,"),
            LONG,
        ),
        (
            "src/report.rs, ARTIFACT_PRECONDITIONS",
            doc_above(report, "const ARTIFACT_PRECONDITIONS:"),
            LONG,
        ),
    ];
    let mut checked = 0;
    for (place, paragraphs, case) in &sites {
        assert!(!paragraphs.is_empty(), "{place}: no doc comment to read");
        let describing: Vec<&String> = paragraphs.iter().filter(|p| p.contains(case)).collect();
        eprintln!(
            "{place}: {} paragraph(s), {} describe the case",
            paragraphs.len(),
            describing.len()
        );
        assert!(
            !describing.is_empty(),
            "{place}: no paragraph describes the unmarked case (`{case}`)"
        );
        for paragraph in describing {
            assert!(
                paragraph.contains(GATE),
                "{place}: a paragraph describes the unmarked static PIE and does not name \
                 {GATE}: {paragraph}"
            );
            assert!(
                !paragraph.contains(RETIRED),
                "{place}: a paragraph still cites the retired {RETIRED}: {paragraph}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, sites.len());
}

/// The assumptions that name a crafted ELF the reader reads in full but reads differently
/// from the loader or binutils `readelf`. Each is an item the crafted-ELF row of the attacker
/// table does not defend.
const LOADER_DIFFERENTIALS: [&str; 7] = [
    "property-note-name-size-is-four",
    "property-word-lies-in-its-descriptor",
    "feature-word-is-four-bytes",
    "dynamic-symbol-names-carry-no-version",
    "address-reached-tables-lie-in-the-file-image",
    "note-segments-align-to-four-or-eight",
    "one-property-note-per-object",
];

/// The register entries sited in the ELF reader that are not such a misreading, each with why.
/// An entry whose site names `elf::` is one or the other, so a reading added to the register
/// is listed in the row or excluded here by name, with a reason.
const READER_ASSUMPTIONS_NOT_MISREADINGS: [(&str, &str); 3] = [
    (
        "dt-debug-marks-only-executable-output",
        "what linkers write on a shared object, not a reading of a crafted file",
    ),
    (
        "separate-code-reads-the-linked-layout",
        "the layout a linker chose, read as linked",
    ),
    (
        "landing-pad-sits-at-the-symbol",
        "where a compiler places a landing pad, read as compiled",
    ),
];

/// The sentences of the crafted-ELF row this test holds, each whole: the bold lead that says
/// the misreadings are not stopped, that such a file can publish a wrong verdict, that the
/// list is of the readings measured so far, that a reading not named is no evidence of a
/// refusal, and that a toolchain's own output is read the same way.
const CRAFTED_ELF_ROW_SENTENCES: [&str; 5] = [
    "**a crash and an unfinished table; the misreadings named below are not stopped.**",
    "a check read from such a file can publish a wrong verdict",
    "The register below names the readings of that kind measured so far",
    "That a reading is not named there is no evidence that the reader refuses it",
    "These readings hold for any ELF chard reads, a toolchain's own output included",
];

/// Words that would make the crafted-ELF row claim a refusal, matched without case. The row
/// says none of them; a sentence that did would claim what the register says is not shown.
/// A claim worded otherwise passes this list, and the sentences above are what hold the row.
const CRAFTED_ELF_ROW_REFUSAL_WORDS: [&str; 6] = [
    "cannot",
    "can not",
    "can't",
    "never",
    "unable",
    "impossible",
];

/// The targets of the ``[`id`](#id)`` links in `cell`, in order, each held to a label that is
/// its own target.
fn register_links(cell: &str) -> Vec<&str> {
    let mut linked = Vec::new();
    for piece in cell.split("[`").skip(1) {
        let (label, rest) = piece
            .split_once("`](#")
            .unwrap_or_else(|| panic!("a link in the crafted-ELF row has no target: {piece}"));
        let (target, _) = rest
            .split_once(')')
            .unwrap_or_else(|| panic!("a link in the crafted-ELF row is not closed: {rest}"));
        assert_eq!(
            label, target,
            "the crafted-ELF row labels a link to {target} as {label}"
        );
        linked.push(target);
    }
    linked
}

/// The crafted-ELF row says what its defences cover and links, item by item, to the register
/// entries for what they do not: each entry in [`LOADER_DIFFERENTIALS`] ships, the row's last
/// cell links to every one under its own name and to nothing else, and every shipped entry
/// whose site names `elf::` is listed or excluded by name, with a reason, in
/// [`READER_ASSUMPTIONS_NOT_MISREADINGS`]. The cell keeps [`CRAFTED_ELF_ROW_SENTENCES`] and
/// says none of [`CRAFTED_ELF_ROW_REFUSAL_WORDS`]. What it does not hold: that each entry's
/// statement is true of the reader, which its retirement condition's crafted fixture will.
#[test]
fn the_crafted_elf_row_links_each_misreading_it_does_not_defend() {
    let text = threat_model();
    let shipped: BTreeSet<&str> = chard::report::ASSUMPTIONS.iter().map(|a| a.id).collect();
    for id in LOADER_DIFFERENTIALS {
        assert!(
            shipped.contains(id),
            "{id} does not ship in report::ASSUMPTIONS"
        );
    }
    let listed: BTreeSet<&str> = LOADER_DIFFERENTIALS.into_iter().collect();
    let excluded: BTreeSet<&str> = READER_ASSUMPTIONS_NOT_MISREADINGS
        .iter()
        .map(|(id, _)| *id)
        .collect();
    for (id, reason) in READER_ASSUMPTIONS_NOT_MISREADINGS {
        assert!(shipped.contains(id), "{id} is excluded and does not ship");
        assert!(!listed.contains(id), "{id} is both listed and excluded");
        assert!(!reason.trim().is_empty(), "{id} is excluded with no reason");
    }
    let reader_sited: BTreeSet<&str> = chard::report::ASSUMPTIONS
        .iter()
        .filter(|a| a.site.contains("elf::"))
        .map(|a| a.id)
        .collect();
    let accounted: BTreeSet<&str> = listed.union(&excluded).copied().collect();
    assert_eq!(
        reader_sited, accounted,
        "the register entries sited in the ELF reader are {reader_sited:?}, and the listed and \
         excluded ones {accounted:?}"
    );
    let rows: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("| A crafted ELF file |"))
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "THREAT_MODEL.md has {} crafted-ELF rows",
        rows.len()
    );
    let cells: Vec<&str> = rows[0]
        .trim()
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .collect();
    assert_eq!(
        cells.len(),
        3,
        "the crafted-ELF row has {} cells",
        cells.len()
    );
    let defences = cells[2];
    let linked = register_links(defences);
    assert_eq!(
        defences.matches("](#").count(),
        linked.len(),
        "the crafted-ELF row carries a link that is not a register entry's own: {defences}"
    );
    let linked_set: BTreeSet<&str> = linked.iter().copied().collect();
    eprintln!(
        "crafted-ELF row: {} register link(s), {} distinct, {} listed misreading(s), {} \
         excluded, {} reader-sited entries",
        linked.len(),
        linked_set.len(),
        listed.len(),
        excluded.len(),
        reader_sited.len()
    );
    assert_eq!(
        linked.len(),
        linked_set.len(),
        "the crafted-ELF row links one entry twice"
    );
    assert_eq!(
        linked_set, listed,
        "the crafted-ELF row links {linked_set:?} and the listed misreadings are {listed:?}"
    );
    assert!(
        defences.starts_with(CRAFTED_ELF_ROW_SENTENCES[0]),
        "the crafted-ELF row does not open with its bold lead: {defences}"
    );
    for sentence in CRAFTED_ELF_ROW_SENTENCES {
        assert!(
            defences.contains(sentence),
            "the crafted-ELF row does not say `{sentence}`: {defences}"
        );
    }
    let lower = defences.to_lowercase();
    for word in CRAFTED_ELF_ROW_REFUSAL_WORDS {
        assert!(
            !lower.contains(word),
            "the crafted-ELF row says `{word}`, which would claim a refusal the register does \
             not show: {defences}"
        );
    }
}

/// The ids leading the bullets of the re-run list under "What a reader checks of a report it
/// did not write": from the sentence that introduces the list to "What still reads as
/// written". A bullet that leads with no backticked id yields an empty name, which no rule
/// has, so the comparison below names it.
fn reread_list(text: &str) -> Vec<&str> {
    let list = text
        .split_once("\n### What a reader checks of a report it did not write\n")
        .expect("THREAT_MODEL.md carries the reader's section")
        .1
        .split_once("They are, by id:\n")
        .expect("the reader's section introduces the re-run list as `They are, by id:`")
        .1
        .split_once("\nWhat still reads as written:")
        .expect("the re-run list ends where `What still reads as written:` begins")
        .0;
    list.lines()
        .filter_map(|l| l.strip_prefix("- "))
        .map(|bullet| {
            bullet
                .strip_prefix('`')
                .and_then(|rest| rest.split_once("`:"))
                .map_or("", |(id, _)| id)
        })
        .collect()
}

/// The re-run list names every rule of `report::REREAD_RULES`, once each, and no other, so the
/// list is complete by construction rather than a selection a reader cannot tell is one.
#[test]
fn the_reread_list_names_every_rule_reread_on_read() {
    let text = threat_model();
    let listed = reread_list(&text);
    let set: BTreeSet<&str> = listed.iter().copied().collect();
    assert_eq!(
        listed.len(),
        set.len(),
        "the re-run list names a rule twice: {listed:?}"
    );
    let rules: BTreeSet<&str> = chard::report::REREAD_RULES.iter().copied().collect();
    assert_eq!(
        set, rules,
        "the re-run list in THREAT_MODEL.md and report::REREAD_RULES differ (an empty name is a \
         bullet that leads with no `id`:)"
    );
}

/// The extraction above reads what it is given: a list naming a rule twice and a bullet
/// with no leading id each read differently from a whole list. A rule missing from the
/// list is the comparison's case, not the extraction's.
#[test]
fn the_reread_list_reader_sees_a_missing_doubled_or_unnamed_bullet() {
    let wrap = |bullets: &str| {
        format!(
            "\n### What a reader checks of a report it did not write\n\nThey are, by id:\n\n\
             {bullets}\nWhat still reads as written:\n"
        )
    };
    let whole = wrap("- `a-rule`: one.\n- `b-rule`: two,\n  continued.\n");
    assert_eq!(reread_list(&whole), ["a-rule", "b-rule"]);
    let doubled = wrap("- `a-rule`: one.\n- `a-rule`: again.\n");
    assert_eq!(reread_list(&doubled), ["a-rule", "a-rule"]);
    let unnamed = wrap("- `a-rule`: one.\n- A rule with no id.\n");
    assert_eq!(reread_list(&unnamed), ["a-rule", ""]);
}
