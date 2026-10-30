// SPDX-License-Identifier: BSD-3-Clause

//! `scripts/leak-gate.sh` over throwaway repositories whose findings are known.
//!
//! The gate is the boundary a push crosses, and the merge-gate job runs it with the CI host's
//! private list (`--patterns`) and a tracked list of accepted findings. So what
//! it calls a finding, an accepted one, a stale acceptance and a local-only match is held
//! here, each in a repository built for it, with git's global and system configuration kept
//! out (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM`) so the developer's own cannot decide it.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

const GATE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/leak-gate.sh");

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test Author")
        .env("GIT_AUTHOR_EMAIL", "author@example.org")
        .env("GIT_COMMITTER_NAME", "Test Author")
        .env("GIT_COMMITTER_EMAIL", "author@example.org")
        .output()
        .expect("running git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn tools_present(verifies: &str) -> bool {
    for tool in ["bash", "git"] {
        if Command::new(tool).arg("--version").output().is_err() {
            common::refuse(
                &format!("no {tool} on PATH to run scripts/leak-gate.sh"),
                verifies,
            );
            return false;
        }
    }
    true
}

/// A repository with the gate in `scripts/` and one committed file.
fn repo(work: &common::Work, tag: &str) -> PathBuf {
    let dir = work.dir().join(tag);
    std::fs::create_dir_all(dir.join("scripts")).expect("the repository");
    git(&dir, &["init", "-q", "-b", "main"]);
    std::fs::copy(GATE, dir.join("scripts/leak-gate.sh")).expect("the gate");
    std::fs::write(dir.join("README"), "a file\n").expect("a file");
    git(&dir, &["add", "README", "scripts/leak-gate.sh"]);
    git(&dir, &["commit", "-q", "-m", "first"]);
    dir
}

fn commit(dir: &Path, path: &str, text: &str, message: &str, force: bool) {
    let file = dir.join(path);
    std::fs::create_dir_all(file.parent().expect("a parent")).expect("the directory");
    std::fs::write(&file, text).expect("the file");
    let mut add = vec!["add"];
    if force {
        add.push("-f");
    }
    add.push(path);
    git(dir, &add);
    git(dir, &["commit", "-q", "-m", message]);
}

fn accept(dir: &Path, lines: &[String]) {
    std::fs::write(
        dir.join("scripts/leak-gate.accepted"),
        lines.join("\n") + "\n",
    )
    .expect("the accepted list");
}

struct Run {
    status: Option<i32>,
    out: String,
}

fn gate(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new("bash")
        .arg(dir.join("scripts/leak-gate.sh"))
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("running the gate");
    Run {
        status: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// Every `key:` line the gate printed, sorted.
fn keys(r: &Run) -> Vec<String> {
    let mut keys: Vec<String> = r
        .out
        .lines()
        .filter_map(|l| l.trim().strip_prefix("key: "))
        .map(str::to_owned)
        .collect();
    keys.sort();
    keys
}

/// The one `key:` line the gate printed.
fn key(r: &Run) -> String {
    let keys: Vec<&str> = r
        .out
        .lines()
        .filter_map(|l| l.trim().strip_prefix("key: "))
        .collect();
    assert_eq!(keys.len(), 1, "{}", r.out);
    keys[0].to_owned()
}

#[test]
fn a_clean_history_passes_and_a_bad_invocation_exits_2() {
    if !tools_present("that the leak gate passes a clean history") {
        return;
    }
    let work = common::Work::new("leakgate", "clean");
    let dir = repo(&work, "clean");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(
        r.out
            .contains("leak gate passed; private patterns: not scanned"),
        "{}",
        r.out
    );
    assert_eq!(gate(&dir, &["--bogus"]).status, Some(2));
    assert_eq!(gate(&dir, &["--patterns"]).status, Some(2));

    // A list asked for and absent fails, where a missing default list only skips.
    let r = gate(&dir, &["--patterns", "no-such-list"]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(r.out.contains("which does not exist"), "{}", r.out);
}

#[test]
fn a_shallow_clone_is_refused_because_its_history_is_not_there() {
    if !tools_present("that the leak gate refuses a shallow clone") {
        return;
    }
    let work = common::Work::new("leakgate", "shallow");
    let dir = repo(&work, "origin");
    commit(&dir, "second", "two\n", "second", false);
    let shallow = work.dir().join("shallow");
    let url = format!("file://{}", dir.display());
    git(
        work.dir(),
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &url,
            shallow.to_str().expect("a path"),
        ],
    );
    let r = gate(&shallow, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("FAIL  leak gate: this clone is shallow"),
        "{}",
        r.out
    );
    // The same history whole passes.
    assert_eq!(gate(&dir, &[]).status, Some(0));
}

#[test]
fn a_message_finding_fails_until_accepted_and_a_stale_acceptance_fails() {
    if !tools_present("that the leak gate accepts a listed message and refuses a stale line") {
        return;
    }
    let work = common::Work::new("leakgate", "message");
    let dir = repo(&work, "message");
    let first = git(&dir, &["rev-parse", "HEAD"]);
    let patterns = work.dir().join("private-list");
    std::fs::write(&patterns, "word zebrahost\n").expect("the list");
    let p = patterns.to_str().expect("a path");
    commit(&dir, "notes", "notes\n", "measured on zebrahost", false);

    let r = gate(&dir, &["--patterns", p]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains("FAIL  messages: 1 commit(s) match 'private word 1'"),
        "{}",
        r.out
    );
    assert!(
        !r.out.contains("zebrahost"),
        "the gate names a pattern by number: {}",
        r.out
    );
    let found = key(&r);
    let sha = git(&dir, &["rev-parse", "HEAD"]);
    assert_eq!(found, format!("message {sha} private word 1"));

    accept(&dir, std::slice::from_ref(&found));
    let r = gate(&dir, &["--patterns", p]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(
        r.out
            .contains("accept messages: 1 commit(s) match 'private word 1'"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("1 finding(s) accepted by scripts/leak-gate.accepted"),
        "{}",
        r.out
    );

    // A line for an object this clone holds that matches nothing is stale; one for an object
    // it lacks is noted and not checked.
    let stale = format!("message {first} private word 1");
    let absent = format!("message {} private word 1", "0".repeat(40));
    accept(&dir, &[found.clone(), stale.clone()]);
    let r = gate(&dir, &["--patterns", p]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains(&format!("FAIL  accepted: '{stale}' matches no finding")),
        "{}",
        r.out
    );
    accept(&dir, &[found, absent.clone()]);
    let r = gate(&dir, &["--patterns", p]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(
        r.out.contains(&format!(
            "accepted: '{absent}' names an object this clone does not hold"
        )),
        "{}",
        r.out
    );

    // A line the gate does not understand fails rather than being skipped.
    accept(&dir, &["message not-an-id private word 1".to_owned()]);
    let r = gate(&dir, &["--patterns", p]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("the second field is not a full object id"),
        "{}",
        r.out
    );
}

#[test]
fn an_ignored_path_and_a_reachable_blob_are_findings_and_an_unreachable_one_is_local() {
    if !tools_present("that the leak gate keys path and content findings by object") {
        return;
    }
    let work = common::Work::new("leakgate", "objects");

    let dir = repo(&work, "ignored");
    commit(&dir, ".gitignore", "secret/\n", "ignore secret", false);
    commit(&dir, "secret/notes", "notes\n", "add notes", true);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    // The directory and the file under it are both ignored paths, each its own object.
    assert!(
        r.out.contains(
            "FAIL  ref-reachable: 2 object(s) under ignored paths not accepted (2 ignored path(s) \
             over 6)"
        ),
        "{}",
        r.out
    );
    let keys = keys(&r);
    let blob = git(&dir, &["rev-parse", "HEAD:secret/notes"]);
    let tree = git(&dir, &["rev-parse", "HEAD:secret"]);
    let mut expected = vec![
        format!("ignored-path {blob}"),
        format!("ignored-path {tree}"),
    ];
    expected.sort();
    assert_eq!(keys, expected);
    accept(&dir, &keys[..1]);
    let r = gate(&dir, &[]);
    assert_eq!(
        r.status,
        Some(1),
        "one of two accepted still fails: {}",
        r.out
    );
    accept(&dir, &keys);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(
        r.out.contains("every object under them accepted"),
        "{}",
        r.out
    );

    let dir = repo(&work, "content");
    let home = format!("{}alice/build\n", "/ho".to_owned() + "me/");
    commit(&dir, "log", &home, "a log", false);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    let found = key(&r);
    let blob = git(&dir, &["rev-parse", "HEAD:log"]);
    assert_eq!(found, format!("content {blob} /home/"));
    accept(&dir, &[found]);
    assert_eq!(gate(&dir, &[]).status, Some(0));

    // A blob no ref reaches is reported as local-only and does not fail the gate.
    let dir = repo(&work, "unreachable");
    std::fs::write(dir.join("loose"), &home).expect("a loose file");
    git(&dir, &["hash-object", "-w", "loose"]);
    std::fs::remove_file(dir.join("loose")).expect("removing it");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(
        r.out
            .contains("local-only (unreachable): 1 blob(s) match '/home/'"),
        "{}",
        r.out
    );
}

#[test]
fn an_unexercised_vector_is_named_and_a_relative_list_is_read() {
    if !tools_present("that the leak gate names a vector it could not exercise") {
        return;
    }
    let work = common::Work::new("leakgate", "vectors");
    let dir = repo(&work, "vectors");
    git(&dir, &["reflog", "expire", "--expire=now", "--all"]);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(r.out.contains("; not exercised: reflog\n"), "{}", r.out);

    // A list named relative to where the gate is run from, here the repository's parent.
    std::fs::write(work.dir().join("relative-list"), "word zebrahost\n").expect("the list");
    let out = Command::new("bash")
        .arg(dir.join("scripts/leak-gate.sh"))
        .args(["--patterns", "relative-list"])
        .current_dir(work.dir())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("running the gate");
    let out = String::from_utf8_lossy(&out.stdout);
    assert!(out.contains("private patterns: 1 from "), "{out}");

    // An identity cannot be accepted: the line is not one the list understands.
    accept(
        &dir,
        &[format!("identity {} private word 1", "a".repeat(40))],
    );
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains("is not 'ignored-path ID', 'content ID LABEL' or 'message ID LABEL'"),
        "{}",
        r.out
    );
}

#[test]
fn a_partial_clone_and_a_replaced_commit_do_not_hide_history() {
    if !tools_present("that the leak gate scans the history a push carries") {
        return;
    }
    let work = common::Work::new("leakgate", "graph");
    let dir = repo(&work, "origin");
    git(&dir, &["config", "uploadpack.allowFilter", "true"]);
    let partial = work.dir().join("partial");
    let url = format!("file://{}", dir.display());
    git(
        work.dir(),
        &[
            "clone",
            "-q",
            "--filter=blob:none",
            "--no-checkout",
            &url,
            partial.to_str().expect("a path"),
        ],
    );
    std::fs::create_dir_all(partial.join("scripts")).expect("scripts");
    std::fs::copy(GATE, partial.join("scripts/leak-gate.sh")).expect("the gate");
    let r = gate(&partial, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("FAIL  leak gate: this is a partial clone"),
        "{}",
        r.out
    );

    // A commit whose message leaks, replaced by a clean one: a push sends the original.
    let patterns = work.dir().join("list");
    std::fs::write(&patterns, "word zebrahost\n").expect("the list");
    let p = patterns.to_str().expect("a path");
    commit(&dir, "notes", "notes\n", "measured on zebrahost", false);
    let leaked = git(&dir, &["rev-parse", "HEAD"]);
    let tree = git(&dir, &["rev-parse", "HEAD^{tree}"]);
    let parent = git(&dir, &["rev-parse", "HEAD^"]);
    let out = Command::new("git")
        .current_dir(&dir)
        .args(["commit-tree", &tree, "-p", &parent, "-m", "measured"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test Author")
        .env("GIT_AUTHOR_EMAIL", "author@example.org")
        .env("GIT_COMMITTER_NAME", "Test Author")
        .env("GIT_COMMITTER_EMAIL", "author@example.org")
        .output()
        .expect("commit-tree");
    let clean = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    git(&dir, &["replace", &leaked, &clean]);
    let r = gate(&dir, &["--patterns", p]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains(&format!("key: message {leaked} private word 1")),
        "{}",
        r.out
    );
}

#[test]
fn a_missing_object_and_a_graft_file_fail_the_gate() {
    if !tools_present("that the leak gate fails on a store missing an object or a graft file") {
        return;
    }
    let work = common::Work::new("leakgate", "store");
    let dir = repo(&work, "missing");
    commit(&dir, "data", "data\n", "data", false);
    let blob = git(&dir, &["rev-parse", "HEAD:data"]);
    std::fs::remove_file(dir.join(".git/objects").join(&blob[..2]).join(&blob[2..]))
        .expect("removing the loose blob");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("FAIL  ref-reachable: git rev-list failed")
            || r.out.contains("not in this object store"),
        "{}",
        r.out
    );

    let dir = repo(&work, "grafted");
    let head = git(&dir, &["rev-parse", "HEAD"]);
    std::fs::write(dir.join(".git/info/grafts"), format!("{head}\n")).expect("a graft file");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains("FAIL  leak gate: this repository has a graft file"),
        "{}",
        r.out
    );
}

#[test]
fn an_ignored_path_outside_ascii_is_keyed() {
    if !tools_present("that the leak gate keys an ignored path git would quote") {
        return;
    }
    let work = common::Work::new("leakgate", "quoted");
    let dir = repo(&work, "quoted");
    commit(&dir, ".gitignore", "secret/\n", "ignore secret", false);
    commit(
        &dir,
        "secret/naïve \"notes\".txt",
        "notes\n",
        "add notes",
        true,
    );
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(!r.out.contains("could not be keyed"), "{}", r.out);
    let blob = git(&dir, &["rev-parse", "HEAD:secret/naïve \"notes\".txt"]);
    assert!(
        r.out.contains(&format!("key: ignored-path {blob}")),
        "{}",
        r.out
    );
}

#[test]
fn a_home_name_that_opens_outside_ascii_is_a_name_not_a_bare_root() {
    if !tools_present("that the leak gate reads a non-ASCII name after a home root") {
        return;
    }
    let work = common::Work::new("leakgate", "homename");
    let dir = repo(&work, "homename");
    // Split so this source file does not itself hold the path it tests.
    let path = format!("{}émile/build\n", "/ho".to_owned() + "me/");
    commit(&dir, "log", &path, "a log", false);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    let blob = git(&dir, &["rev-parse", "HEAD:log"]);
    assert_eq!(key(&r), format!("content {blob} /home/"));
}

#[test]
fn each_match_is_keyed_to_the_blob_it_is_in() {
    if !tools_present("that the leak gate maps a match in a many-blob stream to its blob") {
        return;
    }
    let work = common::Work::new("leakgate", "mapping");
    let dir = repo(&work, "mapping");
    let home = "/ho".to_owned() + "me/";
    // Blobs around the leaks, an empty one among them, so an offset an off-by-one shifted
    // would land in a neighbour; the first leak is the first bytes of its blob, the second
    // the last bytes of a blob with no trailing newline.
    // Long enough that every later offset has more digits than the first blob's, so offsets
    // compared as strings would order wrongly.
    commit(&dir, "a", &"before\n".repeat(400), "a", false);
    commit(&dir, "empty", "", "empty", false);
    commit(
        &dir,
        "first",
        &format!("{home}alice/build\nmore\n"),
        "first",
        false,
    );
    commit(&dir, "middle", "between\n", "middle", false);
    commit(&dir, "last", &format!("text then {home}bob"), "last", false);
    commit(&dir, "z", "after\n", "z", false);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    let mut expected = vec![
        format!("content {} /home/", git(&dir, &["rev-parse", "HEAD:first"])),
        format!("content {} /home/", git(&dir, &["rev-parse", "HEAD:last"])),
    ];
    expected.sort();
    assert_eq!(keys(&r), expected);
}

/// Executable shims in a directory of their own, each `(name, script body)`. A body runs under
/// bash with `$REAL` set to run the real tool: PATH with the shim directory taken out.
fn shims(work: &common::Work, tag: &str, tools: &[(&str, String)]) -> PathBuf {
    let dir = work.dir().join(tag);
    std::fs::create_dir_all(&dir).expect("the shim directory");
    for (tool, body) in tools {
        let path = dir.join(tool);
        let text = format!(
            "#!/usr/bin/env bash\nREAL=\"env PATH=${{PATH#{}:}} {tool}\"\n{body}",
            dir.display()
        );
        std::fs::write(&path, text).expect("a shim");
        let mut mode = std::fs::metadata(&path).expect("the shim").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
        std::fs::set_permissions(&path, mode).expect("the shim's mode");
    }
    dir
}

/// The gate with `shim` first on PATH; its run and its stderr.
fn gate_under(dir: &Path, shim: &Path, args: &[&str]) -> (Run, String) {
    let path = format!(
        "{}:{}",
        shim.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("bash")
        .arg(dir.join("scripts/leak-gate.sh"))
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("running the gate");
    let run = Run {
        status: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
    };
    (run, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// `wc`, `grep` and `sed` shaped as BSD's: `wc` pads each count with spaces (seven columns
/// after a space here), as a macOS run shows, and `sed` refuses `-z`, as macOS's
/// does; `grep` refuses it too, standing for any grep without GNU's NUL-separated mode.
fn bsd_shaped_tools(work: &common::Work) -> PathBuf {
    let wc = "out=$($REAL \"$@\") || exit $?\n\
              printf '%s\\n' \"$out\" | while read -r n rest; do printf ' %7d%s\\n' \"$n\" \"${rest:+ $rest}\"; done\n"
        .to_owned();
    let refuse_z = "for a in \"$@\"; do case $a in --*) ;; -*z*) echo \"$0: illegal option -- z\" >&2; exit 2 ;; esac; done\n\
                    exec $REAL \"$@\"\n"
        .to_owned();
    // The `-z` tools are named in one string, not as quoted words: tests/merge_gate.rs reads a
    // quoted grep as a test that searches the tracked tree, which this one does not.
    let mut tools = vec![("wc", wc)];
    tools.extend("grep sed".split(' ').map(|t| (t, refuse_z.clone())));
    shims(work, "bsd-shaped", &tools)
}

#[test]
fn the_gate_reads_alike_under_bsd_shaped_tools() {
    if !tools_present("that the leak gate gives one verdict under GNU and BSD-shaped tools") {
        return;
    }
    let work = common::Work::new("leakgate", "bsd-shaped");
    let dir = repo(&work, "bsd-shaped");
    let home = "/ho".to_owned() + "me/";
    let patterns = work.dir().join("private-list");
    std::fs::write(&patterns, "word zebrahost\n").expect("the list");
    let p = patterns.to_str().expect("a path");
    // Message findings in a subject, in a body's third line, in a message with no final
    // newline and in the newest commit (the stream's first record), with clean commits and an
    // empty message between, so a line mapped to the wrong record lands on a neighbour; and
    // one content finding.
    commit(
        &dir,
        "a",
        "a\n",
        &format!("subject names {home}alice"),
        false,
    );
    commit(&dir, "b", "b\n", "clean", false);
    git(
        &dir,
        &[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "clean subject",
            "-m",
            "one\ntwo\nmeasured on zebrahost",
        ],
    );
    commit(&dir, "c", "c\n", "clean again", false);
    git(
        &dir,
        &[
            "commit",
            "-q",
            "--allow-empty",
            "--cleanup=verbatim",
            "-m",
            &format!("no final newline {home}carol"),
        ],
    );
    git(
        &dir,
        &[
            "commit",
            "-q",
            "--allow-empty",
            "--allow-empty-message",
            "-m",
            "",
        ],
    );
    commit(
        &dir,
        "log",
        &format!("built in {home}dave\n"),
        "newest, on zebrahost",
        false,
    );
    let sha = |rev: &str| git(&dir, &["rev-parse", rev]);
    let mut expected = vec![
        format!("message {} /home/", sha("HEAD~6")),
        format!("message {} private word 1", sha("HEAD~4")),
        format!("message {} /home/", sha("HEAD~2")),
        format!("message {} private word 1", sha("HEAD")),
        format!("content {} /home/", sha("HEAD:log")),
    ];
    expected.sort();

    let plain = gate(&dir, &["--patterns", p]);
    assert_eq!(plain.status, Some(1), "{}", plain.out);
    assert_eq!(keys(&plain), expected, "{}", plain.out);

    let (shaped, stderr) = gate_under(&dir, &bsd_shaped_tools(&work), &["--patterns", p]);
    assert_eq!(
        (shaped.status, &shaped.out),
        (plain.status, &plain.out),
        "the gate under BSD-shaped tools: {stderr}"
    );
}

#[test]
fn the_message_stream_is_read_to_its_last_record_and_a_count_that_is_not_a_number_fails() {
    if !tools_present("that the leak gate fails where its message records or a count do not add up")
    {
        return;
    }
    let work = common::Work::new("leakgate", "short");
    let dir = repo(&work, "short");
    commit(&dir, "b", "b\n", "second", false);

    // A git whose NUL-separated message stream is rewritten: its records, all but the last
    // as git wrote them, then `last` given the last record.
    let git_with = |last: &str| {
        format!(
            "case \" $* \" in *' log '*' -z '*)\n\
             mapfile -d '' -t recs < <($REAL \"$@\"); n=${{#recs[@]}}\n\
             printf '%s\\0' \"${{recs[@]:0:n-1}}\"; {last}\n\
             exit ;; esac\nexec $REAL \"$@\"\n"
        )
    };

    // A stream one record short of the commits git lists.
    let (r, stderr) = gate_under(
        &dir,
        &shims(&work, "short-git", &[("git", git_with(":"))]),
        &[],
    );
    assert_eq!(r.status, Some(1), "{}{stderr}", r.out);
    assert!(
        r.out.contains(
            "FAIL  messages: 1 message record(s) read for 2 commits listed, so which messages \
             were scanned is unknown"
        ),
        "{}{stderr}",
        r.out
    );

    // A last record without its NUL is still read.
    let unterminated = git_with("printf '%s' \"${recs[n-1]}\"");
    let (r, stderr) = gate_under(
        &dir,
        &shims(&work, "unterminated-git", &[("git", unterminated)]),
        &[],
    );
    assert_eq!(r.status, Some(0), "{}{stderr}", r.out);
    assert!(
        r.out
            .contains("ok    messages: 0 commits match '/Users/', over 2 commits"),
        "{}{stderr}",
        r.out
    );

    // A wc that prints something other than a count.
    let garbled = "printf 'n/a\\n'\n".to_owned();
    let (r, stderr) = gate_under(&dir, &shims(&work, "garbled-wc", &[("wc", garbled)]), &[]);
    assert_eq!(r.status, Some(1), "{}{stderr}", r.out);
    assert!(
        r.out
            .contains("is 'n/a', not a number, so what was counted is unknown"),
        "{}{stderr}",
        r.out
    );
}

#[test]
fn a_permitted_home_passes_and_one_unpermitted_name_beside_it_fails() {
    if !tools_present("that the leak gate forgives permitted home names and only them") {
        return;
    }
    let work = common::Work::new("leakgate", "permitted");
    let home = "/ho".to_owned() + "me/";
    let dir = repo(&work, "permitted");
    commit(
        &dir,
        "guest",
        &format!("{home}chard/probe.c\nunder {home} nobody\n"),
        "guest",
        false,
    );
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(r.out.contains("only as permitted values"), "{}", r.out);

    let dir = repo(&work, "mixed");
    commit(
        &dir,
        "mixed",
        &format!("{home}chard/probe.c\n{home}carol/x\n"),
        "mixed",
        false,
    );
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    let blob = git(&dir, &["rev-parse", "HEAD:mixed"]);
    assert_eq!(key(&r), format!("content {blob} /home/"));
}

#[test]
fn a_blob_that_cannot_be_read_fails_the_content_scan() {
    if !tools_present("that the leak gate fails on a blob it cannot read whole") {
        return;
    }
    let work = common::Work::new("leakgate", "corrupt");
    let dir = repo(&work, "corrupt");
    commit(&dir, "data", "data\n", "data", false);
    let blob = git(&dir, &["rev-parse", "HEAD:data"]);
    // Present but not readable: rev-list walks trees and does not inflate blobs, and git
    // lists the object with the type `missing` and exits 0, which a gate reading only the
    // exit status would pass; the refusal of any record that is not a readable type finds it.
    let loose = dir.join(".git/objects").join(&blob[..2]).join(&blob[2..]);
    let mut mode = std::fs::metadata(&loose)
        .expect("the loose blob")
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    mode.set_readonly(false);
    std::fs::set_permissions(&loose, mode).expect("writable");
    std::fs::write(&loose, b"not zlib").expect("corrupting it");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains("FAIL  leak gate: 1 object(s) in the store could not be read"),
        "{}",
        r.out
    );
}

#[test]
fn a_size_table_short_of_a_blob_fails_the_content_scan() {
    if !tools_present("that the leak gate fails when git sizes fewer blobs than it was asked") {
        return;
    }
    let work = common::Work::new("leakgate", "sizes");
    let dir = repo(&work, "sizes");
    commit(&dir, "data", "data\n", "data", false);
    // A git that drops the last line of the size table and is otherwise the real one.
    let real = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .expect("which git")
            .stdout,
    )
    .expect("a path");
    let bin = work.dir().join("bin");
    std::fs::create_dir_all(&bin).expect("the bin directory");
    common::executable(
        &bin.join("git"),
        &format!(
            "#!/bin/sh\ncase \"$*\" in *objectsize*) '{}' \"$@\" | sed '$d' ;; *) exec '{}' \"$@\" ;; esac\n",
            real.trim(),
            real.trim()
        ),
    );
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").expect("PATH"));
    let out = Command::new("bash")
        .arg(dir.join("scripts/leak-gate.sh"))
        .current_dir(&dir)
        .env("PATH", path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("running the gate");
    let out = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.contains(
            "FAIL  content: a blob to scan is not in the store as a blob, or was not sized"
        ),
        "{out}"
    );
}

#[test]
fn an_accepted_private_line_is_not_stale_where_no_list_is_loaded() {
    if !tools_present(
        "that the leak gate passes a checkout with no list beside a private acceptance",
    ) {
        return;
    }
    let work = common::Work::new("leakgate", "nolist");
    let dir = repo(&work, "nolist");
    commit(&dir, "notes", "notes\n", "measured on zebrahost", false);
    let sha = git(&dir, &["rev-parse", "HEAD"]);
    accept(&dir, &[format!("message {sha} private word 1")]);
    // With the list the line is used; without it, it is noted and the gate still passes.
    let patterns = work.dir().join("list");
    std::fs::write(&patterns, "word zebrahost\n").expect("the list");
    let r = gate(&dir, &["--patterns", patterns.to_str().expect("a path")]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(
        r.out
            .contains("names a private pattern this run did not load, so it is not checked here"),
        "{}",
        r.out
    );
    // A line for a private pattern the list does load, and that matches nothing, is stale.
    std::fs::write(&patterns, "word zebrahost\nword other\n").expect("the list");
    accept(
        &dir,
        &[
            format!("message {sha} private word 1"),
            format!("message {sha} private word 2"),
        ],
    );
    let r = gate(&dir, &["--patterns", patterns.to_str().expect("a path")]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("private word 2' matches no finding"),
        "{}",
        r.out
    );
}

/// A `git` in a shim directory that runs one call as the real one, so its output is written,
/// and then exits 128, as a git that fails partway would; every other call runs as the real
/// one. `call` is a shell `case` pattern over the arguments, each padded with a space.
fn failing_git(work: &common::Work, tag: &str, call: &str) -> PathBuf {
    let body =
        format!("case \" $* \" in {call}) $REAL \"$@\"; exit 128 ;; esac\nexec $REAL \"$@\"\n");
    shims(work, tag, &[("git", body)])
}

/// The reflog vector's `git check-ignore` failing fails the gate, where a count of its output
/// read as "0 ignored paths". The failing call is the one without `-z`; the ref vector's calls
/// carry `-z`, and pass. The reflog holds an ignored path the refs do not, so the failing call
/// prints a line before it fails.
#[test]
fn a_reflog_ignore_check_that_fails_fails_the_gate() {
    if !tools_present("that the leak gate fails where its reflog ignore check fails") {
        return;
    }
    let work = common::Work::new("leakgate", "reflog-fault");
    let dir = repo(&work, "reflog-fault");
    commit(
        &dir,
        ".gitignore",
        "secret.txt\n",
        "ignore secret.txt",
        false,
    );
    commit(&dir, "secret.txt", "s\n", "an ignored file, forced", true);
    git(&dir, &["reset", "-q", "--hard", "HEAD~1"]);
    let shim = failing_git(
        &work,
        "reflog-fault-git",
        "*' check-ignore --stdin --no-index '*",
    );
    let (r, stderr) = gate_under(&dir, &shim, &[]);
    assert_eq!(r.status, Some(1), "{}{stderr}", r.out);
    assert!(
        r.out
            .contains("FAIL  local-only (reflog): git check-ignore failed (exit 128)"),
        "{}",
        r.out
    );
    assert!(
        !r.out.contains("local-only (reflog): 0 ignored"),
        "{}",
        r.out
    );
    assert!(
        !r.out.contains("FAIL  ref-reachable"),
        "the ref vector failed instead: {}",
        r.out
    );
}

/// The reflog listing failing fails the gate, where it read as an empty reflog ("expired, or
/// a fresh clone").
#[test]
fn a_reflog_listing_that_fails_fails_the_gate() {
    if !tools_present("that the leak gate fails where its reflog listing fails") {
        return;
    }
    let work = common::Work::new("leakgate", "reflog-list-fault");
    let dir = repo(&work, "reflog-list-fault");
    let shim = failing_git(&work, "reflog-list-git", "*' rev-list '*' --reflog '*");
    let (r, stderr) = gate_under(&dir, &shim, &[]);
    assert_eq!(r.status, Some(1), "{}{stderr}", r.out);
    assert!(
        r.out
            .contains("FAIL  local-only (reflog): git rev-list --reflog failed (exit 128)"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("no reflog to scan"), "{}", r.out);
}

/// `info/exclude` the gate cannot read fails it, where `grep -c`'s count read as "0 rules".
/// The fault is a `grep` that exits 2 for that file, so the arm runs as root too. A repository
/// with no exclude file has no rule, and passes.
#[test]
fn an_exclude_file_that_cannot_be_read_fails_the_gate_and_an_absent_one_is_no_rule() {
    if !tools_present("that the leak gate fails where it cannot read info/exclude") {
        return;
    }
    let work = common::Work::new("leakgate", "exclude-fault");
    let dir = repo(&work, "exclude-fault");
    let exclude = dir.join(".git/info/exclude");
    std::fs::create_dir_all(exclude.parent().expect("a parent")).expect("the info directory");
    std::fs::write(&exclude, "# no rule\n").expect("an exclude file");
    let grep =
        "case \" $* \" in *' .git/info/exclude ') echo 0; exit 2 ;; esac\nexec $REAL \"$@\"\n"
            .to_owned();
    // The tool is named from one string, not as a quoted word: tests/merge_gate.rs reads a
    // quoted grep as a test that searches the tracked tree, which this one does not.
    let tool = "grep for the exclude file"
        .split(' ')
        .next()
        .expect("a name");
    let shim = shims(&work, "exclude-fault-grep", &[(tool, grep)]);
    let (r, stderr) = gate_under(&dir, &shim, &[]);
    assert_eq!(r.status, Some(1), "{}{stderr}", r.out);
    assert!(
        r.out
            .contains("FAIL  info/exclude: .git/info/exclude could not be read (grep exit 2)"),
        "{}",
        r.out
    );

    std::fs::remove_file(&exclude).expect("removing the exclude file");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(r.out.contains("ok    info/exclude: 0 rules"), "{}", r.out);
    std::fs::remove_dir(exclude.parent().expect("a parent")).expect("removing info/");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(0), "no info directory: {}", r.out);
    assert!(r.out.contains("ok    info/exclude: 0 rules"), "{}", r.out);
}

/// An exclude file behind a path that is not a searchable directory is not read as absent:
/// there `[ -e ]` is false for a file that is there, and its rules would have read as none.
/// `info` as a file runs everywhere; `info` at mode 000 needs a process that is not root.
#[test]
fn an_exclude_file_behind_an_unsearchable_directory_fails_the_gate() {
    if !tools_present("that the leak gate fails where it cannot tell whether info/exclude exists") {
        return;
    }
    let work = common::Work::new("leakgate", "exclude-hidden");
    let dir = repo(&work, "exclude-hidden");
    let info = dir.join(".git/info");
    // `info` a file: the nearest existing path above the exclude file is not a directory. This
    // arm runs as root too.
    let _ = std::fs::remove_dir_all(&info);
    std::fs::write(&info, "not a directory\n").expect("info as a file");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "info a file: {}", r.out);
    assert!(
        r.out.contains(
            "FAIL  info/exclude: whether .git/info/exclude exists cannot be told (.git/info is not a directory that can be searched)"
        ),
        "info a file: {}",
        r.out
    );
    std::fs::remove_file(&info).expect("removing it");
    std::fs::create_dir_all(&info).expect("the info directory");
    std::fs::write(info.join("exclude"), "secret-dir/\n").expect("an exclude rule");
    let mode = |m| {
        std::fs::set_permissions(
            &info,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(m),
        )
    };
    mode(0o000).expect("making info/ unsearchable");
    let searchable = info.join("exclude").exists();
    let r = gate(&dir, &[]);
    mode(0o755).expect("making it searchable again");
    if searchable {
        common::capability_gap(
            "an exclude file behind an unsearchable directory fails the gate",
            "this process searches a directory of mode 000 (it runs as root)",
        );
        return;
    }
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains(
            "FAIL  info/exclude: whether .git/info/exclude exists cannot be told (.git/info is not a directory that can be searched)"
        ),
        "{}",
        r.out
    );
    assert!(!r.out.contains("ok    info/exclude: 0 rules"), "{}", r.out);
}

/// A blob holding NUL bytes is scanned as text: the content scan's `grep -a` is what reads
/// it, and without `-a` this blob's home path passed the gate.
#[test]
fn a_blob_holding_nul_bytes_is_scanned_as_text() {
    if !tools_present("that the leak gate scans a blob holding NUL bytes") {
        return;
    }
    let work = common::Work::new("leakgate", "nul-blob");
    let dir = repo(&work, "nul-blob");
    let home = "/ho".to_owned() + "me/";
    commit(
        &dir,
        "swap.bin",
        &format!("bin\0\0data {home}alice\0end\n"),
        "an editor's swap file",
        false,
    );
    let blob = git(&dir, &["rev-parse", "HEAD:swap.bin"]);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert_eq!(
        keys(&r),
        vec![format!("content {blob} /home/")],
        "{}",
        r.out
    );
}

/// A commit message with bytes outside UTF-8 is found by the message scan. It reaches the scan
/// as UTF-8, so this test cannot hold the message scan's `-a` (see the comment there).
#[test]
fn a_message_with_bytes_outside_utf8_is_found() {
    if !tools_present("that the leak gate scans a message with bytes outside UTF-8") {
        return;
    }
    let work = common::Work::new("leakgate", "eight-bit-message");
    let dir = repo(&work, "eight-bit-message");
    let message = work.dir().join("message");
    let mut text = b"subject \xff\xfe ".to_vec();
    text.extend_from_slice(("/ho".to_owned() + "me/carol\n").as_bytes());
    std::fs::write(&message, text).expect("the message");
    let path = message.to_str().expect("a UTF-8 path");
    git(&dir, &["commit", "-q", "--allow-empty", "-F", path]);
    let commit = git(&dir, &["rev-parse", "HEAD"]);
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert_eq!(
        keys(&r),
        vec![format!("message {commit} /home/")],
        "{}",
        r.out
    );
}

/// `scripts/test-ledger.sh` prints the same lines under BSD-shaped tools as under the host's,
/// for a ledger with gaps and skips and for one with neither: its counts are numbers, not
/// `wc`'s padded text, and a kind with no line counts 0.
#[test]
fn the_test_ledger_reads_alike_under_bsd_shaped_tools() {
    if !tools_present("that the test ledger prints one text under GNU and BSD-shaped tools") {
        return;
    }
    let work = common::Work::new("leakgate", "ledger-bsd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/test-ledger.sh");
    let shim = bsd_shaped_tools(&work);
    let shaped_path = format!(
        "{}:{}",
        shim.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let ledgers = [
        (
            "some",
            "gap\tsome_test\tan arm\ngap\tsome_test\tanother arm\nskipped\tsome_binary\tno cc\n\
             count\tsome_binary\tinert_flags: 3 rows of 3\n",
            "1 ledger file(s); 2 arm(s) not exercised on this host, 1 test(s) skipped",
        ),
        (
            "none",
            "count\tsome_binary\tinert_flags: 3 rows of 3\n",
            "1 ledger file(s); 0 arm(s) not exercised on this host, 0 test(s) skipped",
        ),
    ];
    for (name, rows, summary) in ledgers {
        let ledger = work.dir().join(name);
        std::fs::create_dir_all(&ledger).expect("the ledger directory");
        std::fs::write(ledger.join("one.tsv"), rows).expect("a ledger file");
        let run = |path: Option<&str>| {
            let mut command = Command::new("bash");
            command.arg(script).arg(&ledger);
            if let Some(path) = path {
                command.env("PATH", path);
            }
            let out = command.output().expect("running the test ledger");
            (
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
            )
        };
        let plain = run(None);
        assert_eq!(plain.0, Some(0), "{name}: {}", plain.1);
        assert!(plain.1.contains(summary), "{name}: {}", plain.1);
        assert_eq!(
            run(Some(&shaped_path)),
            plain,
            "{name}: under BSD-shaped tools"
        );
    }
}

/// A fixed pattern holding `|`, `&` or a backslash is refused by name, wherever it is in the
/// list: the message scan writes the pattern into a sed script as its label, where each of
/// them means something.
#[test]
fn a_fixed_pattern_the_message_label_cannot_carry_is_refused() {
    if !tools_present("that the leak gate refuses a fixed pattern its sed label cannot carry") {
        return;
    }
    let work = common::Work::new("leakgate", "pattern-guard");
    let list = "PATH_PATTERNS=(\n  '/home/'\n  '/Users/'\n)\n";
    for (i, pattern) in ["/srv|x/", "/srv&x/", "/srv\\x/"].into_iter().enumerate() {
        let first = format!("PATH_PATTERNS=(\n  '{pattern}'\n  '/home/'\n  '/Users/'\n)\n");
        let middle = format!("PATH_PATTERNS=(\n  '/home/'\n  '{pattern}'\n  '/Users/'\n)\n");
        let last = format!("PATH_PATTERNS=(\n  '/home/'\n  '/Users/'\n  '{pattern}'\n)\n");
        for (place, replaced) in [("first", first), ("middle", middle), ("last", last)] {
            let dir = repo(&work, &format!("pattern-guard-{i}-{place}"));
            let script = dir.join("scripts/leak-gate.sh");
            let text = std::fs::read_to_string(&script).expect("the gate");
            assert_eq!(text.matches(list).count(), 1, "the fixed list");
            std::fs::write(&script, text.replace(list, &replaced)).expect("the gate, edited");
            let r = gate(&dir, &[]);
            assert_eq!(r.status, Some(1), "{pattern} {place}: {}", r.out);
            assert!(
                r.out.contains(&format!(
                    "FAIL  fixed pattern '{pattern}' contains |, & or a backslash"
                )),
                "{pattern} {place}: {}",
                r.out
            );
        }
    }
}

/// A rule in `info/exclude` fails the gate, run from the main checkout and from a linked
/// worktree, where `.git` is a file and `--git-path` names the repository's exclude file.
#[test]
fn an_exclude_rule_fails_the_gate_from_the_main_checkout_and_a_linked_worktree() {
    if !tools_present("that the leak gate fails on an info/exclude rule from any worktree") {
        return;
    }
    let work = common::Work::new("leakgate", "exclude-rule");
    let dir = repo(&work, "exclude-rule");
    let info = dir.join(".git/info");
    std::fs::create_dir_all(&info).expect("the info directory");
    std::fs::write(info.join("exclude"), "# a comment\n\nsecret-dir/\n").expect("an exclude rule");
    let r = gate(&dir, &[]);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("FAIL  info/exclude has 1 rule(s)"),
        "{}",
        r.out
    );

    let linked = work.dir().join("exclude-rule-linked");
    let path = linked.to_str().expect("a UTF-8 path");
    git(&dir, &["worktree", "add", "-q", "--detach", path]);
    let r = gate(&linked, &[]);
    assert_eq!(r.status, Some(1), "linked: {}", r.out);
    assert!(
        r.out.contains("FAIL  info/exclude has 1 rule(s)"),
        "linked: {}",
        r.out
    );
}
