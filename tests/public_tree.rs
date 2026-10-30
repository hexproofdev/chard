// SPDX-License-Identifier: BSD-3-Clause
//! No tracked file names the private evidence repository or a session directory in it, and
//! no file of the release tree names a plan handle.
//!
//! The record each change is measured into is kept outside this repository, as the ledger
//! and the evidence are (CLAUDE.md), and the tree does not name it or point into it. This reads
//! every tracked file for the repository's hyphenated name in any ASCII case and for
//! `sessions/` followed by a `YYYY-MM-DD` date, one line at a time, and fails naming each line
//! that holds one. The name is built here from two halves, so this file does not hold it
//! either. What it does not catch: the name wrapped across a line break, and the name joined
//! by an underscore or a space, which the shadow-stack probe's buffer-size identifier and
//! ordinary prose share. The second test holds the shapes it does catch, and its near misses.
//!
//! A plan handle is a ledger prefix, a hyphen and digits, in any ASCII case; an item branch
//! name spells one too. A handle points a reader at a ledger the release does not carry. So a
//! document or a comment says its frame (toolchain, profile, host and date) or its reason in
//! its own words instead. The third test reads every tracked file of the release tree and fails
//! naming each line that holds a handle. The release tree is every tracked file but the CI
//! workflows under `.forgejo/workflows/` and `tests/merge_gate.rs`, which name the merge
//! queue's `item/<handle>` branches. The development branch tracks both. The published tree
//! is made from that branch without them, so nothing is skipped there. The test accepts
//! both sides tracked or both absent, and fails when one side is tracked without the other.
//! The fourth test holds the shapes the rule catches and its near misses. The prefixes are
//! kept here as a list, so this file holds no handle either.
//!
//! A commit of this repository's history is the other pointer the release does not carry.
//! The tree says what chard does, never what it did (CLAUDE.md): a measurement keeps its
//! toolchain, profile, host and date, and names no revision. The fifth test reads every
//! tracked file of the release tree for the shape of an abbreviated commit name, a run of
//! seven to twelve lowercase hex digits standing as a word, asks git in one batch which of
//! them name a commit, and fails naming each file and token that does. On a clone whose
//! history is the one publication commit nothing resolves, so the rule holds on the
//! development branch, where the history is. What it does not catch: a commit named by a
//! longer run or by its date alone. What it can mistake: a fragment of a digest that happens
//! to be a prefix of some commit, which a longer quotation of the digest settles. The sixth
//! test holds the shape rule over planted text.
//!
//! Outside a repository, as in an unpacked crate archive, the tracked files are every file
//! below the manifest directory but `target/`, the same set, and the commit test has no
//! history to ask, so it holds its scan alone and says so.
//!
//! All six tests are ratchets (tests/ratchets.txt). Every merge gate runs them first, the
//! reduced phase set of a document-only diff included (scripts/merge-gate.sh).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod common;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Tracked files, by `git ls-files` in the repository root. Outside a repository, as in an
/// unpacked crate archive, every file below the manifest directory but `target/`: a crate
/// archive holds the tracked files and nothing else, so the two sets are one.
fn tracked() -> Option<Vec<String>> {
    if let Some(out) = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root())
        .output()
        .ok()
        .filter(|out| out.status.success())
    {
        return Some(
            String::from_utf8_lossy(&out.stdout)
                .split('\0')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect(),
        );
    }
    let mut files = walked(&root(), &root()).ok()?;
    files.sort();
    Some(files)
}

/// Every file below `dir`, relative to `root` with `/` separators, skipping `target/` and
/// `.git/` at the root.
fn walked(root: &Path, dir: &Path) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            if dir == root && (name == "target" || name == ".git") {
                continue;
            }
            out.extend(walked(root, &path)?);
        } else {
            let rel = path.strip_prefix(root).expect("below the root");
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(out)
}

/// Whether the manifest directory is inside a git repository, which is where a commit name
/// can be resolved.
fn in_repository() -> bool {
    Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(root())
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Whether `line`, lowercased, holds `sessions/` followed by a `YYYY-MM-DD` date.
fn names_a_session(line: &[u8]) -> bool {
    const PREFIX: &[u8] = b"sessions/";
    line.windows(PREFIX.len() + 10)
        .any(|w| w.starts_with(PREFIX) && is_date(&w[PREFIX.len()..]))
}

/// Whether `d` is ten bytes of the shape `dddd-dd-dd`.
fn is_date(d: &[u8]) -> bool {
    d.len() == 10
        && d.iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

/// The lines of `bytes` that name the repository or a session in it, as `path:line: text`.
fn hits(path: &str, bytes: &[u8]) -> Vec<String> {
    let name = format!("{}-{}", "chard", "witness");
    let mut out = Vec::new();
    for (n, line) in bytes.split(|b| *b == b'\n').enumerate() {
        let lower = line.to_ascii_lowercase();
        let named = lower.windows(name.len()).any(|w| w == name.as_bytes());
        if named || names_a_session(&lower) {
            out.push(format!(
                "{path}:{}: {}",
                n + 1,
                String::from_utf8_lossy(line).trim()
            ));
        }
    }
    out
}

#[test]
fn no_tracked_file_names_the_private_evidence_repository() {
    let Some(files) = tracked() else {
        common::refuse(
            "git cannot list the tracked files",
            "that no tracked file names the private evidence repository",
        );
        return;
    };
    // Fewer than this is a listing that went wrong, not a tree: the tree holds hundreds.
    assert!(
        files.len() >= 100,
        "git listed {} tracked files",
        files.len()
    );
    let mut found = Vec::new();
    for path in &files {
        let bytes = std::fs::read(root().join(path))
            .unwrap_or_else(|e| panic!("reading tracked file {path}: {e}"));
        found.extend(hits(path, &bytes));
    }
    assert!(
        found.is_empty(),
        "tracked text names the private evidence repository or a session in it; say what the \
         record showed in the text's own words instead:\n{}",
        found.join("\n")
    );
}

/// The rule over planted lines, so a matcher that finds nothing cannot pass on a clean tree:
/// each shape it names is found, in any case, and each near miss is not.
#[test]
fn the_rule_finds_each_shape_it_names_and_not_its_near_misses() {
    let name = format!("{}-{}", "chard", "witness");
    let session = format!("{}/{}", "sessions", "2026-10-18");
    let found = [
        format!("/// (the {name} record, F1)"),
        format!("see {} here", name.to_ascii_uppercase()),
        format!("`{session}/audit`"),
        format!("{}/x", session.to_ascii_uppercase()),
    ];
    for line in &found {
        assert_eq!(hits("f", line.as_bytes()).len(), 1, "{line:?} is not found");
    }
    let missed = [
        "#define CHARD_WITNESS_SIZE 8192".to_owned(),
        "a chard witness is a reader".to_owned(),
        format!("{}/2026-1-02/", "sessions"),
        format!("{}/20261018/", "sessions"),
        "sessions/<date>/".to_owned(),
    ];
    for line in &missed {
        assert!(hits("f", line.as_bytes()).is_empty(), "{line:?} is found");
    }
    let text = format!("one\n{}\nthree\n", found[0]);
    assert_eq!(hits("p", text.as_bytes()), [format!("p:2: {}", found[0])]);
}

/// The ledger's prefixes. A handle is one of them, a hyphen and at least one digit, with no
/// letter, digit or underscore before it, in any ASCII case.
const PLAN_PREFIXES: [&str; 19] = [
    "COR", "ASR", "CLI", "DOC", "RSK", "OPS", "WH", "FLT", "DAT", "TGT", "ENF", "CON", "ARC",
    "CMP", "REV", "MRK", "SQ", "DIF", "D",
];

/// The tracked paths the handle test skips: the CI workflows and the test that holds them,
/// which name the merge queue's `item/<handle>` branches.
fn outside_the_release(path: &str) -> bool {
    path.starts_with(".forgejo/workflows/") || path == "tests/merge_gate.rs"
}

/// Whether `line` holds a plan handle.
fn names_a_handle(line: &[u8]) -> bool {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (0..line.len()).any(|at| {
        (at == 0 || !word(line[at - 1]))
            && PLAN_PREFIXES.iter().any(|prefix| {
                let end = at + prefix.len();
                line.len() > end + 1
                    && line[at..end].eq_ignore_ascii_case(prefix.as_bytes())
                    && line[end] == b'-'
                    && line[end + 1].is_ascii_digit()
            })
    })
}

/// The lines of `bytes` that name a plan handle, as `path:line: text`.
fn handle_hits(path: &str, bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == b'\n')
        .enumerate()
        .filter(|(_, line)| names_a_handle(line))
        .map(|(n, line)| format!("{path}:{}: {}", n + 1, String::from_utf8_lossy(line).trim()))
        .collect()
}

#[test]
fn no_file_of_the_release_tree_names_a_plan_handle() {
    let Some(files) = tracked() else {
        common::refuse(
            "git cannot list the tracked files",
            "that no file of the release tree names a plan handle",
        );
        return;
    };
    assert!(
        files.len() >= 100,
        "git listed {} tracked files",
        files.len()
    );
    let (outside, release): (Vec<&String>, Vec<&String>) =
        files.iter().partition(|p| outside_the_release(p));
    // The skipped paths are the workflows and their test and nothing else. Both are tracked
    // on the development branch. Both are absent from the published tree, made from that
    // branch without them, so nothing is skipped there. One side tracked without the other
    // fails below; any workflow file counts as the workflows' side. What this file cannot
    // tell apart: a branch that lost both looks the same here as the published tree, and a
    // tree meant for publication that kept both is accepted here as the branch is. The cut,
    // outside this tree, is what removes them.
    assert!(
        outside
            .iter()
            .all(|p| p.starts_with(".forgejo/workflows/") || *p == "tests/merge_gate.rs"),
        "the handle test skips more than the CI workflows and their test: {outside:?}"
    );
    let workflows_tracked = outside.iter().any(|p| p.starts_with(".forgejo/workflows/"));
    let gate_test_tracked = outside.iter().any(|p| *p == "tests/merge_gate.rs");
    assert!(
        workflows_tracked == gate_test_tracked,
        "a workflow under .forgejo/workflows/ is tracked without tests/merge_gate.rs, or the \
         reverse; the test accepts both sides or neither; tracked: {outside:?}"
    );
    assert!(
        release.len() >= 100,
        "the release tree is {} files of {} tracked",
        release.len(),
        files.len()
    );
    let mut fed = 0usize;
    let mut found = Vec::new();
    for path in &release {
        let bytes = std::fs::read(root().join(path))
            .unwrap_or_else(|e| panic!("reading tracked file {path}: {e}"));
        fed += 1;
        found.extend(handle_hits(path, &bytes));
    }
    // A file that cannot be read panicked above, so every release file was fed. The count is
    // printed for a run with `--nocapture` and named in the failure message below.
    eprintln!(
        "public_tree: read {fed} release files for plan handles, of {} tracked; skipped {}: \
         {outside:?}",
        files.len(),
        outside.len()
    );
    assert!(
        found.is_empty(),
        "{} lines of the {fed} release files read name a plan handle; say the frame \
         (toolchain, profile, host and date) or the reason in the text's own words instead:\n{}",
        found.len(),
        found.join("\n")
    );
}

/// The handle rule over planted lines, so a matcher that finds nothing cannot pass on a clean
/// tree: each shape is found, every prefix in either case, and each near miss is not.
#[test]
fn the_handle_rule_finds_each_shape_and_not_its_near_misses() {
    for prefix in PLAN_PREFIXES {
        for line in [
            format!("({prefix}-7)"),
            format!("until {}-12's review", prefix.to_ascii_lowercase()),
            format!("{prefix}-301"),
        ] {
            assert_eq!(
                handle_hits("f", line.as_bytes()).len(),
                1,
                "{line:?} is not found"
            );
        }
    }
    let found = [
        format!("the item/{}-18 tree", "tgt"),
        format!("/// ({}-37, 2026-10-20)", "COR"),
        format!("\"note\": \"added by {}-78: the arm\"", "COR"),
    ];
    for line in &found {
        assert_eq!(
            handle_hits("f", line.as_bytes()).len(),
            1,
            "{line:?} is not found"
        );
    }
    let missed = [
        "x86-64",
        "SHA-256 and UTF-8",
        "-D_FORTIFY_SOURCE=2",
        "CORE-1",
        "ACOR-7",
        "COR-x",
        "git rev-parse",
        "_D-1",
        "2COR-7",
        "4D-1",
        "D-",
        "x86_64-linux-gnu-gcc-13",
    ];
    for line in missed {
        assert!(
            handle_hits("f", line.as_bytes()).is_empty(),
            "{line:?} is found"
        );
    }
    let text = format!("one\n{}\nthree\n", found[1]);
    assert_eq!(
        handle_hits("p", text.as_bytes()),
        [format!("p:2: {}", found[1])]
    );
}

/// The maximal runs of lowercase hex digits in `bytes` that stand as a word, seven to twelve
/// long: the shape of an abbreviated commit name. A longer run (a digest, a flags hash) and
/// a run inside a word are not candidates.
fn commit_shaped(bytes: &[u8]) -> Vec<String> {
    let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        if !word(bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && hex(bytes[at]) {
            at += 1;
        }
        let run = at - start;
        while at < bytes.len() && word(bytes[at]) {
            at += 1;
        }
        let whole_word = at - start == run;
        if whole_word && (7..=12).contains(&run) {
            out.push(String::from_utf8_lossy(&bytes[start..start + run]).into_owned());
        }
    }
    out
}

/// Which of `tokens` name a commit of this repository, by one `git cat-file --batch-check`
/// over `<token>^{commit}`, which narrows a prefix shared with other objects to commits:
/// each hit with what git resolved it to. `None` when git cannot answer.
fn commits_among(tokens: &BTreeSet<String>) -> Option<BTreeMap<String, String>> {
    let mut child = Command::new("git")
        .args(["cat-file", "--batch-check"])
        .current_dir(root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let queries: Vec<String> = tokens.iter().map(|t| format!("{t}^{{commit}}\n")).collect();
    // Written on a thread: git answers as it reads, and a batch larger than a pipe would
    // otherwise wait on this side writing while that side waits on this side reading.
    let writer = std::thread::spawn(move || {
        for q in queries {
            if stdin.write_all(q.as_bytes()).is_err() {
                return false;
            }
        }
        true
    });
    let out = child.wait_with_output().ok()?;
    if !writer.join().ok()? || !out.status.success() {
        return None;
    }
    let answers = String::from_utf8_lossy(&out.stdout);
    let answers: Vec<&str> = answers.lines().collect();
    (answers.len() == tokens.len()).then(|| {
        answers
            .iter()
            .zip(tokens)
            .filter_map(|(line, token)| {
                let mut fields = line.split(' ');
                let first = fields.next()?;
                match fields.next()? {
                    "commit" => Some((token.clone(), first.to_owned())),
                    "ambiguous" => Some((token.clone(), "more than one commit".to_owned())),
                    _ => None,
                }
            })
            .collect()
    })
}

#[test]
fn no_file_of_the_release_tree_names_a_commit_of_this_repository() {
    let Some(files) = tracked() else {
        common::refuse(
            "git cannot list the tracked files",
            "that no file of the release tree names a commit of this repository",
        );
        return;
    };
    let release: Vec<&String> = files.iter().filter(|p| !outside_the_release(p)).collect();
    assert!(
        release.len() >= 100,
        "the release tree is {} files of {} tracked",
        release.len(),
        files.len()
    );
    let mut fed = 0usize;
    let mut tokens = BTreeSet::new();
    let mut sites: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in &release {
        let bytes = std::fs::read(root().join(path))
            .unwrap_or_else(|e| panic!("reading tracked file {path}: {e}"));
        fed += 1;
        for (n, line) in bytes.split(|b| *b == b'\n').enumerate() {
            for token in commit_shaped(line) {
                sites
                    .entry(token.clone())
                    .or_default()
                    .push(format!("{path}:{}", n + 1));
                tokens.insert(token);
            }
        }
    }
    // Outside a repository there is no history to ask: the scan holds alone, and the counts
    // below say how much was scanned. Inside one, git answers or the test refuses.
    let named = if in_repository() {
        let Some(named) = commits_among(&tokens) else {
            common::refuse(
                "git cannot resolve object names",
                "that no file of the release tree names a commit of this repository",
            );
            return;
        };
        named
    } else {
        eprintln!(
            "public_tree: no repository here; the commit-shaped tokens resolve against nothing"
        );
        BTreeMap::new()
    };
    // Every release file was fed (a file that cannot be read panicked above), and every
    // commit-shaped token was asked about: the counts are printed for a run with
    // `--nocapture` and named in the failure below.
    eprintln!(
        "public_tree: read {fed} release files for commit names; {} commit-shaped tokens \
         asked of git, {} name a commit",
        tokens.len(),
        named.len()
    );
    let found: Vec<String> = named
        .iter()
        .map(|(token, commit)| format!("{token} ({commit}): {}", sites[token].join(", ")))
        .collect();
    assert!(
        found.is_empty(),
        "{} tokens in the {fed} release files read name a commit of this repository; the \
         tree says what chard does, never what it did: keep the measurement's toolchain, \
         profile, host and date and drop the revision, or say the reason in the text's own \
         words:\n{}",
        found.len(),
        found.join("\n")
    );
}

/// The commit-name shape over planted text, so a matcher that finds nothing cannot pass on a
/// clean tree: each shape is found, and each near miss is not.
#[test]
fn the_commit_rule_finds_each_shape_and_not_its_near_misses() {
    let found = [
        ("at chard 1a2b3c4 on Fedora", vec!["1a2b3c4"]),
        ("(before 0123456789ab)", vec!["0123456789ab"]),
        ("fixed at deadbeef.", vec!["deadbeef"]),
        ("two: 1234567 and abcdef0", vec!["1234567", "abcdef0"]),
        ("`c0ffee1`", vec!["c0ffee1"]),
    ];
    for (line, want) in &found {
        assert_eq!(&commit_shaped(line.as_bytes()), want, "{line:?}");
    }
    let missed = [
        "123456",
        "0123456789abc",
        "sha256:3f73339bf0d3d64081cac3f6d9fdafc6dd4cef2b9c49e0a09f91e97cb0eb139a",
        "DEADBEEF",
        "1a2b3c4g",
        "x1a2b3c4",
        "1a2b3c4_5",
        "0x7ffff7dd",
        "2026-10-30",
    ];
    for line in missed {
        assert!(
            commit_shaped(line.as_bytes()).is_empty(),
            "{line:?} is found: {:?}",
            commit_shaped(line.as_bytes())
        );
    }
}
