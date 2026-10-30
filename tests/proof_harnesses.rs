// SPDX-License-Identifier: BSD-3-Clause

//! `proofs/README.md` says what `make kani` proves and what is held by a test over its whole
//! domain instead. This holds the document to the code, in three parts:
//!
//! 1. Every `.rs` file under `proofs/` is included by one `#[path = "../proofs/<file>"]`
//!    module in a file of `src/`, whose attributes, above the path and below it to its `mod`
//!    line, are `#[cfg(kani)]` exactly and no other `#[cfg]`, and the path resolves to that
//!    file. A harness file nothing includes is a proof `make kani` never runs, and a green run
//!    over the rest reads as covering it. No file of `src/` writes `kani::proof` itself.
//! 2. The README's harness table names every `#[kani::proof]` function under its file and no
//!    other, so a harness added, renamed or dropped moves the table in the same change.
//! 3. The tests the README's "held by" rows name are [`HELD_BY`], each a `#[test]` function
//!    of the file the row names that the suite runs (no `#[ignore]`, no `#[cfg]`), so a
//!    renamed or ignored test cannot leave a row pointing at nothing.
//!
//! These read text, so a harness written in a shape they do not parse is refused rather than
//! passed where they can see it. What they cannot see (an include inside a module nothing
//! compiles, a harness in a block comment) `scripts/kani-gate.sh` holds at run time: `make
//! kani` fails unless the harnesses the checker verified are, by name, the harnesses declared
//! under `proofs/`.
//!
//! The three are ratchets (tests/ratchets.txt): a change to the README alone runs the reduced
//! gate, which runs them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const README: &str = "proofs/README.md";

/// The tests the README's "held by" rows name, as (file, test), which part 3 holds equal to
/// the rows: a row dropped from the table fails here, and a test dropped from here fails
/// against the table.
const HELD_BY: [(&str, &str); 5] = [
    (
        "src/report.rs",
        "the_recount_agrees_with_the_rollup_on_every_polarity_word_and_verdict",
    ),
    (
        "src/report.rs",
        "weaken_polarity_counts_absence_as_protection",
    ),
    (
        "tests/inert_flags.rs",
        "every_graded_or_optimization_gated_check_names_its_inert_form_or_a_reason",
    ),
    ("src/mechanism.rs", "the_table_is_total_and_well_formed"),
    (
        "src/mechanism.rs",
        "the_decision_of_every_gated_check_on_every_architecture_is_the_one_named",
    ),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Whether `name` has the extension `rs`, exactly: the tree's paths are case-sensitive.
fn is_rust_source(name: &str) -> bool {
    Path::new(name).extension().is_some_and(|e| e == "rs")
}

/// The `.rs` files under `proofs/`, by file name. The directory holds harness files and the
/// README and nothing else. A directory there fails, since this reads one level and a
/// harness below it would be outside every hold here. Any other entry fails too, since no
/// hold reads it and no build compiles it.
fn harness_files() -> BTreeSet<String> {
    let dir = root().join("proofs");
    let entries =
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    entries
        .filter_map(|entry| {
            let entry = entry.expect("a directory entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                !entry.path().is_dir(),
                "proofs/{name} is a directory, which this hold does not walk"
            );
            if name == "README.md" {
                return None;
            }
            assert!(
                is_rust_source(&name),
                "proofs/{name} is neither a harness file nor the README, so nothing here \
                 reads it and nothing compiles it"
            );
            Some(name)
        })
        .collect()
}

/// How many times `kani::proof` is written in `text` with its spaces and line breaks taken
/// out: every spelling of the attribute, which the exact `#[kani::proof]` reader must have
/// parsed every one of. Prose naming the attribute counts too, and fails loudly.
fn proof_attribute_mentions(text: &str) -> usize {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    compact.matches("kani::proof").count()
}

/// Every `.rs` file under `src/`, walked, in path order.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.to_str().is_some_and(is_rust_source) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&root().join("src"), &mut out);
    out.sort();
    out
}

/// The net count of `[` over `]` in `line`, for an attribute that continues past it.
fn bracket_depth(line: &str) -> i32 {
    line.chars()
        .map(|c| match c {
            '[' => 1,
            ']' => -1,
            _ => 0,
        })
        .sum()
}

/// The attributes of `text`, each joined across the lines it spans, and the functions
/// declared under them: the name after a `fn` whose run of attributes holds `attribute`. A
/// run is the attributes above the `fn`, in any order, with comment lines between them. A
/// function whose run also holds `#[ignore]` or any `#[cfg]` is left out, whichever comes
/// first: a test the suite does not run, or runs only somewhere, holds nothing.
fn functions_under(text: &str, attribute: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut attributes: Vec<String> = Vec::new();
    let mut open: Option<(String, i32)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some((mut joined, mut depth)) = open.take() {
            joined.push(' ');
            joined.push_str(line);
            depth += bracket_depth(line);
            if depth > 0 {
                open = Some((joined, depth));
            } else {
                attributes.push(joined);
            }
            continue;
        }
        if line.starts_with("#[") {
            let depth = bracket_depth(line);
            if depth > 0 {
                open = Some((line.to_owned(), depth));
            } else {
                attributes.push(line.to_owned());
            }
            continue;
        }
        if line.starts_with("//") || line.is_empty() {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("fn ")
            .or_else(|| line.split_once(" fn ").map(|(_, r)| r))
        {
            let wanted = attributes.iter().any(|a| a == attribute);
            let conditional = attributes
                .iter()
                .any(|a| a.starts_with("#[ignore") || a.starts_with("#[cfg"));
            if wanted && !conditional {
                let name = rest.split('(').next().unwrap_or(rest);
                out.insert(name.trim().to_owned());
            }
        }
        attributes.clear();
    }
    out
}

/// One `#[path = "../proofs/<file>"]` include of a source file: the file it names; whether
/// the attributes of its run, above the path line and below it to the `mod` line, are
/// `#[cfg(kani)]` exactly and no other `#[cfg]`; whether a `mod` line follows; and whether
/// the path, resolved from the including file's directory as rustc resolves it for a file
/// module, is that file under `proofs/`.
struct Include {
    file: String,
    gated: bool,
    declares: bool,
    resolves: bool,
}

/// The proof includes of the source file at `source`. The look-back and look-ahead read
/// attribute lines alone, so a comment naming `cfg(kani)` beside a bare include is not its
/// gate.
fn proof_includes(source: &Path) -> Vec<Include> {
    let text = read(source);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let is_attribute_or_comment = |l: &str| l.starts_with("#[") || l.starts_with("//");
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(path) = line
            .strip_prefix("#[path = \"")
            .and_then(|rest| rest.strip_suffix("\"]"))
        else {
            continue;
        };
        let Some(file) = path.strip_prefix("../proofs/") else {
            continue;
        };
        let above = lines[..i]
            .iter()
            .rev()
            .take_while(|l| is_attribute_or_comment(l));
        let below = lines[i + 1..]
            .iter()
            .take_while(|l| is_attribute_or_comment(l));
        let attributes: Vec<&str> = above
            .chain(below)
            .filter(|l| l.starts_with("#["))
            .copied()
            .collect();
        let gated = attributes.contains(&"#[cfg(kani)]")
            && attributes.iter().filter(|a| a.starts_with("#[cfg")).count() == 1;
        let declares = lines[i + 1..]
            .iter()
            .find(|l| !is_attribute_or_comment(l) && !l.is_empty())
            .is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub mod "));
        let resolves = source
            .parent()
            .map(|dir| dir.join(path))
            .and_then(|p| p.canonicalize().ok())
            .is_some_and(|p| {
                root()
                    .join("proofs")
                    .join(file)
                    .canonicalize()
                    .is_ok_and(|want| want == p)
            });
        out.push(Include {
            file: file.to_owned(),
            gated,
            declares,
            resolves,
        });
    }
    out
}

/// A `## ` section of the README, from its heading to the next heading of that level.
fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let marker = format!("\n## {heading}\n");
    let (_, after) = text
        .split_once(&marker)
        .unwrap_or_else(|| panic!("{README} has no section {heading:?}"));
    after.find("\n## ").map_or(after, |end| &after[..end])
}

/// The rows of the one table in `section`, whose header cells are `columns` and whose
/// second line is the rule: each row's cells, trimmed.
fn table_rows(section: &str, columns: &[&str]) -> Vec<Vec<String>> {
    let cells = |line: &str| -> Vec<String> {
        line.trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().to_owned())
            .collect()
    };
    let mut lines = section.lines().filter(|line| line.starts_with('|'));
    let header = lines.next().map(cells).unwrap_or_default();
    assert_eq!(header, columns, "{README}: the table's header row");
    let rule = lines.next().unwrap_or_default();
    assert!(
        rule.starts_with("|---"),
        "{README}: the line after the header is not the rule: {rule:?}"
    );
    lines.map(cells).collect()
}

/// The backticked spans of a cell, in order.
fn code_spans(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The problems of one source file's proof includes, and of a proof attribute written there.
fn include_problems(source: &Path, files: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    let shown = source
        .strip_prefix(root())
        .unwrap_or(source)
        .display()
        .to_string();
    let mut problems = Vec::new();
    let mut included = Vec::new();
    if proof_attribute_mentions(&read(source)) > 0 {
        problems.push(format!(
            "{shown} writes `kani::proof`, which belongs under proofs/, where the harness \
             table and the kani gate read it"
        ));
    }
    for include in proof_includes(source) {
        let file = include.file;
        if !include.gated {
            problems.push(format!(
                "{shown} includes proofs/{file} without exactly `#[cfg(kani)]` as its one \
                 `#[cfg]`, so an ordinary build compiles the harness, or no build does"
            ));
        }
        if !include.declares {
            problems.push(format!(
                "{shown} includes proofs/{file} with no `mod` line after the path"
            ));
        }
        if !include.resolves {
            problems.push(format!(
                "{shown} includes proofs/{file} by a path that does not resolve to it \
                 from that file's directory, as rustc resolves `#[path]`"
            ));
        }
        if !files.contains(&file) {
            problems.push(format!(
                "{shown} includes proofs/{file}, which does not exist"
            ));
        }
        included.push(file);
    }
    (problems, included)
}

/// Every harness file is included once, from one file of `src/`, under `#[cfg(kani)]`
/// exactly, by a path that resolves to it, with its `mod` line; every such include names a
/// harness file; and no file of `src/` writes a proof attribute itself.
#[test]
fn every_harness_file_is_included_under_cfg_kani_and_every_include_names_one() {
    let files = harness_files();
    assert!(!files.is_empty(), "proofs/ holds no harness file");
    let mut included: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut problems = Vec::new();
    for source in source_files() {
        let (found, files_here) = include_problems(&source, &files);
        problems.extend(found);
        for file in files_here {
            included
                .entry(file)
                .or_default()
                .push(source.display().to_string());
        }
    }
    for file in &files {
        match included.get(file).map(Vec::as_slice) {
            None => problems.push(format!(
                "proofs/{file} is included by no file of src/, so `make kani` never runs it"
            )),
            Some([_]) => {}
            Some(many) => problems.push(format!(
                "proofs/{file} is included {} times: {many:?}",
                many.len()
            )),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The README's harness table names every `#[kani::proof]` function of `proofs/` under its
/// file, says what each proves, and names no other.
#[test]
fn the_readme_names_every_harness_under_its_file_and_no_other() {
    let text = read(&root().join(README));
    let rows = table_rows(
        section(&text, "What the harnesses prove"),
        &["file", "harness", "what it proves"],
    );
    let mut named = BTreeSet::new();
    for row in rows {
        let [file, harness, proves] = row.as_slice() else {
            panic!("a harness row of another width: {row:?}");
        };
        let (Some(file), Some(harness)) = (
            code_spans(file).into_iter().next(),
            code_spans(harness).into_iter().next(),
        ) else {
            panic!("a harness row without its file or harness in backticks: {row:?}");
        };
        assert!(!proves.is_empty(), "{harness}: a row that says nothing");
        assert!(
            named.insert((file.clone(), harness.clone())),
            "{file} {harness}: named twice"
        );
    }
    let mut declared = BTreeSet::new();
    for file in harness_files() {
        let text = read(&root().join("proofs").join(&file));
        let harnesses = functions_under(&text, "#[kani::proof]");
        // A proof attribute spelled another way (`#[cfg_attr(kani, kani::proof)]`, split
        // over lines, or on the line of its `fn`), or a harness under a `#[cfg]`, is one
        // this reader did not see and a row it cannot hold: it fails here rather than
        // passing as a file with fewer harnesses.
        assert_eq!(
            proof_attribute_mentions(&text),
            harnesses.len(),
            "proofs/{file}: `kani::proof` is written somewhere the reader of `#[kani::proof]` \
             lines did not parse as a harness"
        );
        for harness in harnesses {
            declared.insert((file.clone(), harness));
        }
    }
    assert!(
        !declared.is_empty(),
        "proofs/ declares no #[kani::proof] function"
    );
    assert_eq!(
        named, declared,
        "the README's harness rows (left) against the #[kani::proof] functions (right)"
    );
}

/// The README's "held by" rows name the tests of [`HELD_BY`], each a `#[test]` function the
/// suite runs in the file the row names, and no row names a test outside the list.
#[test]
fn every_test_the_readme_says_holds_a_property_exists_where_it_says() {
    assert!(
        !HELD_BY.is_empty(),
        "HELD_BY names no test, so this holds nothing"
    );
    let text = read(&root().join(README));
    let rows = table_rows(
        section(&text, "What is held by a test over its whole domain"),
        &["property", "domain", "held by"],
    );
    let mut named = BTreeSet::new();
    let mut problems = Vec::new();
    for row in rows {
        let [property, _domain, held_by] = row.as_slice() else {
            panic!("a property row of another width: {row:?}");
        };
        let mut file: Option<String> = None;
        let mut tests = 0_usize;
        for span in code_spans(held_by) {
            if is_rust_source(&span) {
                file = Some(span);
                continue;
            }
            let Some(path) = &file else {
                problems.push(format!("{property}: `{span}` names no file before it"));
                continue;
            };
            named.insert((path.clone(), span));
            tests += 1;
        }
        if tests == 0 {
            problems.push(format!("{property}: held by no test"));
        }
    }
    let expected: BTreeSet<(String, String)> = HELD_BY
        .iter()
        .map(|(file, test)| ((*file).to_owned(), (*test).to_owned()))
        .collect();
    assert_eq!(
        named, expected,
        "the README's held-by rows (left) against HELD_BY (right)"
    );
    let mut tests_of: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (file, test) in HELD_BY {
        let tests = tests_of
            .entry(file)
            .or_insert_with(|| functions_under(&read(&root().join(file)), "#[test]"));
        if !tests.contains(test) {
            problems.push(format!(
                "{file} has no #[test] fn {test} the suite runs unconditionally"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
