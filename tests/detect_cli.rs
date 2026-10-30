// SPDX-License-Identifier: BSD-3-Clause

//! `chard detect` through the built binary: the replay of a real report, a tampered copy,
//! the three single-reading inputs, and the refusals.
//!
//! Every invocation of `detect` here runs with an environment emptied but for `PATH`,
//! which is the one variable chard reads (`CLAUDE.md`, hard constraints); a result that
//! depended on anything else in the test's environment would differ here from a caller's.
//!
//! The report is measured once per binary with the host's `cc` under `bare`, and every
//! macro and `elf-static` check the corpus lists is replayed from it. On a Mach-O host the
//! `elf-static` checks carry no reading and close at `expected: 0`, and the tests that need
//! an ELF artifact from the measurement announce the gap; the checked-in objects under
//! `tests/fixtures/elf/` exercise `--artifact` on every host.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::Value;

mod common;

fn chard_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("chard")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `chard` with `args`, its environment emptied but for `PATH`.
fn chard(args: &[&str]) -> Output {
    let mut command = Command::new(chard_binary());
    command.env_clear().args(args);
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command.output().expect("spawning chard")
}

/// The JSON object `output` printed, and its exit code.
/// `detect`'s status for a reading that disagrees with its replay: a tripped gate
/// (`error::EXIT_GATE`), never `3`, which is chard's own contradiction alone.
const DISAGREES: i32 = 1;

fn json_of(output: &Output) -> (i32, Value) {
    let text = String::from_utf8_lossy(&output.stdout);
    let value = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!(
            "chard's stdout was not one JSON object ({e}):\n{text}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (
        output.status.code().expect("chard exited, not killed"),
        value,
    )
}

fn detect(check: &str, flag: &str, path: &Path, extra: &[&str]) -> (i32, Value) {
    let path = path.to_str().expect("a UTF-8 path");
    let mut args = vec!["detect", check, flag, path];
    args.extend_from_slice(extra);
    json_of(&chard(&args))
}

fn ready(verifies: &str) -> bool {
    common::require_binary(&chard_binary(), verifies)
}

/// The corpus as `chard probes` lists it: every check id with its channel.
fn checks() -> Vec<(String, String)> {
    let (code, listing) = json_of(&chard(&["probes"]));
    assert_eq!(code, 0);
    let out: Vec<(String, String)> = listing["probes"]
        .as_array()
        .expect("probes")
        .iter()
        .flat_map(|p| p["checks"].as_array().expect("checks").iter())
        .map(|c| {
            (
                c["id"].as_str().expect("id").to_owned(),
                c["channel"].as_str().expect("channel").to_owned(),
            )
        })
        .collect();
    assert!(out.len() >= 26, "the listing reached {} checks", out.len());
    out
}

/// `chard probes` publishes `run_basis` on every runtime decoder and on nothing else, and
/// `shadow-stack-enforced` and `stack-clash-guard-page` are the checks whose reading rests
/// on the machine.
///
/// `report::emulation_limitation` withholds on that field, and the listing is how a reader
/// learns which runtime checks it covers; nothing else read it, so the listing could lose or
/// mislabel it with every test passing.
#[test]
fn the_listing_names_each_runtime_checks_run_basis() {
    let (code, listing) = json_of(&chard(&["probes"]));
    assert_eq!(code, 0);
    let mut runtime = 0;
    let mut machine = Vec::new();
    for c in listing["probes"]
        .as_array()
        .expect("probes")
        .iter()
        .flat_map(|p| p["checks"].as_array().expect("checks").iter())
    {
        let id = c["id"].as_str().expect("id");
        let basis = c["decoder"].get("run_basis");
        if c["channel"] != "runtime" {
            assert!(
                basis.is_none(),
                "{id} is not a runtime check and lists {basis:?}"
            );
            continue;
        }
        runtime += 1;
        match basis.and_then(Value::as_str) {
            Some("program") => {}
            Some("machine") => machine.push(id.to_owned()),
            other => panic!("runtime check {id} lists run_basis {other:?}"),
        }
    }
    assert!(runtime > 1, "the listing named {runtime} runtime check(s)");
    assert_eq!(
        machine,
        [
            "noexecstack-enforced",
            "shadow-stack-enforced",
            "stack-clash-guard-page"
        ]
    );
}

/// Every macro and `elf-static` check id: the ones a report publishes readings for.
fn predicate_checks() -> Vec<String> {
    checks()
        .into_iter()
        .filter(|(_, channel)| channel == "macro" || channel == "elf-static")
        .map(|(id, _)| id)
        .collect()
}

/// One `bare` measurement, kept with its work directory for the whole binary. The
/// directory is a [`common::SharedWork`]. It stays after the binary ends, and the next run
/// that measures removes it.
struct Measured {
    work: common::SharedWork,
    report: PathBuf,
    value: Value,
}

fn measured() -> Option<&'static Measured> {
    static CELL: OnceLock<Measured> = OnceLock::new();
    if !(ready("that a real report replays through `chard detect`")
        && common::require_cc("that a real report replays through `chard detect`"))
    {
        return None;
    }
    Some(CELL.get_or_init(|| {
        let work = common::Work::shared("detect", "report");
        let report = work.path("report.json");
        let output = Command::new(chard_binary())
            .arg("measure")
            .arg("--workdir")
            .arg(work.path("work"))
            .arg("--output")
            .arg(&report)
            .output()
            .expect("spawning chard measure");
        assert_eq!(
            output.status.code(),
            Some(0),
            "measure failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = std::fs::read_to_string(&report).expect("the report was written");
        let value: Value = serde_json::from_str(&text).expect("the report is JSON");
        assert!(value.get("error").is_none(), "{}", value["error"]);
        Measured {
            work,
            report,
            value,
        }
    }))
}

/// A child process killed and reaped when the test ends, however it ends.
struct Reaped(std::process::Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The pid of a process that has run and been reaped.
fn ended_pid() -> u32 {
    let mut child = Command::new("true").spawn().expect("spawning true");
    let pid = child.id();
    child.wait().expect("waiting for true");
    pid
}

/// A directory at `path` holding a file and a directory with a file in it.
fn full_dir(path: &Path) -> PathBuf {
    std::fs::create_dir_all(path.join("work")).expect("making a directory");
    std::fs::write(path.join("report.json"), "{}").expect("writing into it");
    std::fs::write(path.join("work").join("a.o"), "").expect("writing into it");
    path.to_owned()
}

/// [`common::remove_stale`] with `kill -0` removes ended runs' directories with what they
/// hold, every one of them.
///
/// It keeps:
/// - a live process's directory, and does not end that process;
/// - this process's directory;
/// - a symlink and a file named for an ended run;
/// - a name whose pid has a sign or a leading zero;
/// - a directory with another tag.
#[test]
fn ended_runs_shared_directories_are_removed_and_the_rest_kept() {
    let base = common::Work::new("detect", "stale");
    let (gone, gone_too) = (ended_pid(), ended_pid());
    let (as_link, as_file) = (ended_pid(), ended_pid());
    let mut live = Reaped(
        Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawning sleep"),
    );
    let name = |pid: &dyn std::fmt::Display| base.path(&format!("chard-detect-report-{pid}"));
    let mut stale = vec![full_dir(&name(&gone)), full_dir(&name(&gone_too))];
    stale.sort();
    let target = full_dir(&base.path("elsewhere"));
    std::os::unix::fs::symlink(&target, name(&as_link)).expect("making a symlink");
    let kept = [
        full_dir(&name(&live.0.id())),
        full_dir(&name(&std::process::id())),
        full_dir(&name(&format!("0{gone}"))),
        full_dir(&name(&format!("+{gone}"))),
        full_dir(&base.path(&format!("chard-detect-other-{gone}"))),
        base.write(&format!("chard-detect-report-{as_file}"), ""),
        name(&as_link),
        target,
    ];
    let owner = common::owner_of(base.dir());
    let mut removed =
        common::remove_stale(base.dir(), "detect", "report", owner, common::process_alive)
            .expect("kill can be run");
    removed.sort();
    // A signal is delivered and acted on after `kill` returns, so the child is watched for a
    // while rather than polled once.
    for _ in 0..10 {
        assert!(
            live.0.try_wait().expect("polling sleep").is_none(),
            "the live process was signalled"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(removed, stale);
    for path in &stale {
        assert!(
            path.symlink_metadata().is_err(),
            "{} is still there",
            path.display()
        );
    }
    for path in &kept {
        assert!(
            path.symlink_metadata().is_ok(),
            "{} was removed",
            path.display()
        );
    }
}

/// [`common::remove_stale`] keeps this process's directory even where every process reads
/// as ended. Where liveness cannot be told, it removes nothing and says why.
#[test]
fn remove_stale_keeps_its_own_directory_and_removes_nothing_it_cannot_judge() {
    let base = common::Work::new("detect", "judged");
    let name = |pid: u32| base.path(&format!("chard-detect-report-{pid}"));
    let own = full_dir(&name(std::process::id()));
    let other = full_dir(&name(std::process::id().wrapping_add(1)));
    let owner = common::owner_of(base.dir());

    let foreign = common::remove_stale(
        base.dir(),
        "detect",
        "report",
        owner.wrapping_add(1),
        |_| Some(false),
    );
    assert_eq!(foreign, Ok(vec![]), "another user's directory was removed");

    let unjudged = common::remove_stale(base.dir(), "detect", "report", owner, |_| None);
    assert!(unjudged.is_err(), "{unjudged:?}");
    assert!(
        own.is_dir() && other.is_dir(),
        "a directory was removed unjudged"
    );

    // A directory this user cannot empty: the removal fails, and it is not listed as removed.
    let locked = full_dir(&name(std::process::id().wrapping_add(2)));
    let mode = |m| {
        std::fs::set_permissions(
            locked.join("work"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(m),
        )
    };
    mode(0o500).expect("making a directory read-only");
    let removed = common::remove_stale(base.dir(), "detect", "report", owner, |_| Some(false));
    let locked_kept = locked.join("work").is_dir();
    mode(0o700).expect("making it writable again");
    let mut removed = removed.expect("liveness was told");
    removed.sort();
    if owner == 0 {
        common::capability_gap(
            "a directory that cannot be removed is not listed as removed",
            "running as root, a read-only directory is removed all the same",
        );
        let mut want = vec![other.clone(), locked.clone()];
        want.sort();
        assert_eq!(removed, want);
    } else {
        assert_eq!(removed, vec![other.clone()]);
        assert!(locked_kept, "the read-only directory was removed");
    }
    assert!(own.is_dir(), "this process's directory was removed");
}

/// [`common::Work::shared`] makes its directory under the name [`common::Work::under`]
/// gives, empty even where an ended run left one under this pid, and removes an ended run's
/// directory with the same prefix and tag.
#[test]
fn a_shared_work_removes_an_ended_runs_directory() {
    // Built aside and moved in whole: another run of this test may sweep at any moment.
    let aside = common::Work::new("detect", "sweep-aside");
    let stale = std::env::temp_dir().join(format!("chard-detect-sweep-{}", ended_pid()));
    std::fs::rename(full_dir(&aside.path("stale")), &stale).expect("moving it into place");
    let left =
        full_dir(&std::env::temp_dir().join(format!("chard-detect-sweep-{}", std::process::id())));
    let work = common::Work::shared("detect", "sweep");
    assert!(
        std::fs::read_dir(work.dir())
            .expect("listing it")
            .next()
            .is_none(),
        "the directory left under this pid was reused with what it held"
    );
    assert_eq!(work.dir(), left);
    assert!(
        stale.symlink_metadata().is_err(),
        "{} is still there",
        stale.display()
    );
    assert_eq!(
        work.dir(),
        std::env::temp_dir().join(format!("chard-detect-sweep-{}", std::process::id()))
    );
    assert!(work.dir().is_dir(), "the shared directory was not made");
}

/// The `decoded` readings `report` publishes for `check`, by site.
fn readings(report: &Value, check: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for o in report["observations"].as_array().expect("observations") {
        if o["check"] != check {
            continue;
        }
        if let Some(d) = o["evidence"].get("decoded") {
            out.push(d.clone());
        }
        for arm in ["positive", "negative", "regime_negative"] {
            if let Some(d) = o
                .get("controls")
                .and_then(|c| c.get(arm))
                .and_then(|a| a.get("decoded"))
            {
                out.push(d.clone());
            }
        }
    }
    out
}

fn assert_closes(what: &str, got: &Value) {
    let expected = got["expected"].as_u64().expect("expected");
    let replayed = got["replayed"].as_u64().expect("replayed");
    let skipped = got["not_replayable"]
        .as_array()
        .expect("not_replayable")
        .len() as u64;
    assert_eq!(
        expected,
        replayed + skipped,
        "{what}: expected is not replayed + not_replayable:\n{got:#}"
    );
    assert_eq!(
        replayed,
        got["replays"].as_array().expect("replays").len() as u64,
        "{what}: replayed is not the replays listed"
    );
}

#[test]
fn every_reading_of_a_real_report_replays_and_the_counts_close() {
    let Some(m) = measured() else { return };
    let mut replayed = 0u64;
    let mut followed = 0u64;
    let mut restated = 0usize;
    let ids = predicate_checks();
    for check in &ids {
        let (code, got) = detect(check, "--evidence", &m.report, &[]);
        assert_eq!(code, 0, "{check}:\n{got:#}");
        assert_eq!(got["kind"], "replay");
        assert_eq!(got["run_id"], m.value["run"]["id"]);
        assert_eq!(got["inputs_sha256"], m.value["run"]["inputs_sha256"]);
        assert_closes(check, &got);
        assert!(got["observations"].as_u64() > Some(0), "{check}: {got:#}");
        for r in got["replays"].as_array().expect("replays") {
            assert_eq!(r["agrees"], true, "{check}: {r:#}");
            assert_eq!(r["clause"], r["published"]["clause"]);
        }
        for r in got["restated"].as_array().expect("restated") {
            assert_eq!(r["agrees"], true, "{check}: {r:#}");
        }
        restated += got["restated"].as_array().expect("restated").len();
        let expected = got["expected"].as_u64().expect("expected");
        assert_eq!(
            expected,
            readings(&m.value, check).len() as u64,
            "{check}: a consistent report owes a reading at every site that publishes one"
        );
        replayed += got["replayed"].as_u64().expect("replayed");
        followed += got["not_replayable"]
            .as_array()
            .expect("not_replayable")
            .iter()
            .filter(|n| n["reason"] == "unkept-c-int-follow")
            .count() as u64;
    }
    // The report's own replay counted the same readings the loop did, check by check.
    let own = &m.value["consistency"]["replay"];
    assert_eq!(own["unresolved"], 0, "{own}");
    assert_eq!(own["replayed"].as_u64(), Some(replayed), "{own}");
    assert_eq!(own["readings"].as_u64(), Some(replayed + followed), "{own}");
    assert!(
        replayed > 0,
        "no reading was replayed over {} checks",
        ids.len()
    );
    assert!(restated > 0, "no stated outcome or verdict was restated");
    eprintln!(
        "{replayed} readings replayed and {restated} stated values restated over {} checks",
        ids.len()
    );
}

/// One hand edit to a report document.
type Edit = fn(&mut Value);

/// A replay reads the readings, the predicates and the facts, and no kernel field: a report
/// without `environment.kernel.ownership` and one with it, or
/// `is_host_kernel`, edited replay as the report does. Those fields are `table`'s and
/// `matrix`'s to hold, which refuse the edits (`report::reread_contradictions`).
#[test]
fn the_kernel_fields_do_not_reach_a_replay() {
    let Some(m) = measured() else { return };
    let check = predicate_checks()
        .into_iter()
        .find(|c| !readings(&m.value, c).is_empty())
        .expect("some check carries a reading");
    let (code, honest) = detect(&check, "--evidence", &m.report, &[]);
    assert_eq!(code, 0, "{honest:#}");
    let edits: [(&str, Edit); 3] = [
        ("older", |r| {
            r["environment"]["kernel"]
                .as_object_mut()
                .expect("a kernel object")
                .remove("ownership");
        }),
        ("ownership-edited", |r| {
            r["environment"]["kernel"]["ownership"] = "borrowed".into();
        }),
        ("is-host-kernel-edited", |r| {
            r["environment"]["kernel"]["is_host_kernel"] = true.into();
        }),
    ];
    let mut fed = 0;
    for (name, edit) in edits {
        let mut report = m.value.clone();
        edit(&mut report);
        let path = m.work.path(&format!("{name}.json"));
        std::fs::write(&path, serde_json::to_vec(&report).expect("serializes")).expect("written");
        let (code, got) = detect(&check, "--evidence", &path, &[]);
        fed += 1;
        assert_eq!(code, 0, "{name}: {got:#}");
        assert_eq!(got, honest, "{name}: the replay moved");
    }
    assert_eq!(fed, 3);
}

#[test]
fn one_arm_replays_alone() {
    let Some(m) = measured() else { return };
    let check = predicate_checks()
        .into_iter()
        .find(|c| !readings(&m.value, c).is_empty())
        .expect("some check carries a reading");
    let (_, all) = detect(&check, "--evidence", &m.report, &[]);
    let mut sum = 0;
    for arm in ["measured", "positive", "negative", "regime"] {
        let (code, got) = detect(&check, "--evidence", &m.report, &["--arm", arm]);
        assert_eq!(code, 0, "{got:#}");
        assert_closes(arm, &got);
        for r in got["replays"].as_array().expect("replays") {
            assert_eq!(r["arm"], arm);
        }
        sum += got["expected"].as_u64().expect("expected");
    }
    assert_eq!(Some(sum), all["expected"].as_u64());
}

/// `report` with `edit` applied, written beside it.
fn tampered(m: &Measured, name: &str, edit: impl FnOnce(&mut Value)) -> PathBuf {
    let mut copy = m.value.clone();
    edit(&mut copy);
    let path = m.work.path(name);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&copy).expect("serializes"),
    )
    .expect("writing the copy");
    path
}

/// The first check with a measured reading, and that reading.
fn first_measured_reading(report: &Value) -> (String, usize, Value) {
    report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .enumerate()
        .find_map(|(i, o)| {
            let d = o["evidence"].get("decoded")?;
            Some((o["check"].as_str()?.to_owned(), i, d.clone()))
        })
        .expect("some observation carries a measured reading")
}

#[test]
fn a_flipped_outcome_exits_1() {
    let Some(m) = measured() else { return };
    let (check, index, decoded) = first_measured_reading(&m.value);
    let flipped = if decoded["outcome"] == "absent" {
        "present"
    } else {
        "absent"
    };
    let path = tampered(m, "flipped.json", |r| {
        r["observations"][index]["evidence"]["decoded"]["outcome"] = flipped.into();
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{got:#}");
    assert_closes("flipped", &got);
    assert!(
        got["replays"]
            .as_array()
            .expect("replays")
            .iter()
            .any(|r| r["agrees"] == false && r["arm"] == "measured"),
        "{got:#}"
    );
}

/// Each macro `detect` read with a value in its replay of a measured reading, with the
/// store key the reading names.
fn defined_reads(got: &Value) -> Vec<(String, String)> {
    got["replays"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["arm"] == "measured")
        .flat_map(|r| {
            let key = r["facts_key"].as_str().unwrap_or_default().to_owned();
            r["reads"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(k, v)| k.starts_with("macros.") && !v.is_null())
                .map(move |(k, _)| (k.trim_start_matches("macros.").to_owned(), key.clone()))
        })
        .collect()
}

#[test]
fn one_changed_fact_exits_1() {
    let Some(m) = measured() else { return };
    // A reading that read a defined macro: renaming that macro in the store entry by one
    // byte leaves it undefined, and a clause that read it no longer holds. Not every read
    // decides its reading, so candidates are tried until one moves; none may be refused.
    let mut tried = Vec::new();
    for check in predicate_checks() {
        let (_, got) = detect(&check, "--evidence", &m.report, &["--arm", "measured"]);
        for (name, key) in defined_reads(&got) {
            let renamed = format!("{}X{}", &name[..2], &name[3..]);
            let path = tampered(m, "fact.json", |r| {
                let entry = &mut r["facts"][&key];
                let text = serde_json::to_string(entry).expect("serializes");
                *entry = serde_json::from_str(&text.replace(&name, &renamed)).expect("JSON");
            });
            let (code, got) = detect(&check, "--evidence", &path, &["--arm", "measured"]);
            assert!(code == 0 || code == DISAGREES, "{check}: {got:#}");
            tried.push(format!("{check}: {name}"));
            if code == DISAGREES {
                assert_closes(&check, &got);
                eprintln!("renaming {name} in facts[{key}] moved {check}'s reading");
                return;
            }
        }
    }
    panic!("no one-byte change to a read macro moved a reading; tried {tried:?}");
}

#[test]
fn a_reading_without_its_predicate_is_unusable_input_and_a_check_without_readings_closes_at_zero() {
    let Some(m) = measured() else { return };
    let path = tampered(m, "nodecoders.json", |r| {
        r.as_object_mut().expect("object").remove("decoders");
    });
    let mut unread = 0;
    for check in predicate_checks() {
        let (code, got) = detect(&check, "--evidence", &path, &[]);
        if readings(&m.value, &check).is_empty() {
            unread += 1;
            assert_eq!(code, 0, "{check}: {got:#}");
            assert_eq!(got["expected"], 0);
            assert_eq!(got["replayed"], 0);
        } else {
            assert_eq!(code, 2, "{check}: {got:#}");
            assert_eq!(got["error"]["operation"], "detect");
            assert!(
                got["error"]["message"]
                    .as_str()
                    .is_some_and(|s| s.contains("decoders")),
                "{got:#}"
            );
        }
    }
    eprintln!("{unread} checks carry no reading and closed at zero");
}

#[test]
fn a_store_entry_reads_as_the_report_read_it() {
    let Some(m) = measured() else { return };
    let mut compared = 0;
    for check in predicate_checks() {
        for decoded in readings(&m.value, &check) {
            // An elf-static reading naming a separate macro source is read with both; a
            // lone entry carries one.
            if decoded.get("macros").is_some() {
                continue;
            }
            let key = decoded["facts"].as_str().expect("facts");
            // An `elf-delta` names its base, which a lone entry does not carry.
            if m.value["facts"][key]["kind"] == "elf-delta" {
                continue;
            }
            let path = m.work.path(&format!("entry-{key}.json"));
            std::fs::write(&path, m.value["facts"][key].to_string()).expect("writing");
            let (code, got) = detect(&check, "--evidence", &path, &[]);
            assert_eq!(code, 0, "{check} over facts[{key}]: {got:#}");
            assert_eq!(got["kind"], "detection");
            assert_eq!(got["input"], "store-entry");
            assert_eq!(
                got["clause"], decoded["clause"],
                "{check} over facts[{key}]"
            );
            assert_eq!(
                got["outcome"], decoded["outcome"],
                "{check} over facts[{key}]"
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "no reading was compared with its store entry");
}

/// Every file under `dir`, recursively, by SHA-256.
fn files_by_digest(dir: &Path, out: &mut BTreeMap<String, PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("reading the work directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            files_by_digest(&path, out);
        } else if let Some(digest) = chard::digest::sha256_file(&path) {
            out.entry(digest).or_insert(path);
        }
    }
}

#[test]
fn a_retained_artifact_decodes_to_the_measured_reading() {
    let Some(m) = measured() else { return };
    if !common::ELF_HOST {
        common::capability_gap(
            "detect --artifact over the measurement's own artifacts",
            "this host's cc builds Mach-O, which the ELF reader refuses",
        );
        return;
    }
    let mut files = BTreeMap::new();
    files_by_digest(&m.work.path("work"), &mut files);
    let mut compared = 0;
    for check in predicate_checks() {
        for o in m.value["observations"].as_array().expect("observations") {
            let Some(decoded) = o["evidence"].get("decoded").filter(|_| o["check"] == check) else {
                continue;
            };
            let key = decoded["facts"].as_str().expect("facts");
            // The artifact is the macro source only where the reading says so.
            let entry = &m.value["facts"][key];
            if entry["kind"] != "elf" || decoded.get("macros").is_some_and(|k| k != key) {
                continue;
            }
            let artifact = files
                .get(key)
                .unwrap_or_else(|| panic!("{check}: no retained file has digest {key}"));
            let (code, got) = detect(&check, "--artifact", artifact, &[]);
            assert_eq!(code, 0, "{check}: {got:#}");
            assert_eq!(got["facts_key"], key, "{check}");
            assert_eq!(got["clause"], decoded["clause"], "{check}");
            assert_eq!(got["outcome"], decoded["outcome"], "{check}");
            assert_eq!(
                got["level"],
                decoded.get("level").cloned().unwrap_or(Value::Null)
            );
            compared += 1;
        }
    }
    assert!(
        compared > 0,
        "no measured reading was compared with its artifact"
    );
    eprintln!("{compared} measured readings reproduced from their retained artifacts");
}

fn elf_fixtures() -> Vec<PathBuf> {
    let dir = repo_root().join("tests/fixtures/elf");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("the fixture directory")
        .map(|e| e.expect("an entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "elf"))
        .collect();
    out.sort();
    assert_eq!(out.len(), common::ELF_FIXTURE_COUNT);
    out
}

#[test]
fn chard_elf_output_and_the_artifact_give_one_detection() {
    if !ready("that `chard elf` output and `--artifact` read one object alike") {
        return;
    }
    let work = common::Work::new("detect", "elfout");
    let ids = predicate_checks();
    let mut compared = 0;
    for object in elf_fixtures() {
        let output = chard(&["elf", object.to_str().expect("UTF-8")]);
        assert_eq!(output.status.code(), Some(0));
        let facts = work.path("facts.json");
        std::fs::write(&facts, &output.stdout).expect("writing");
        for check in &ids {
            let (a, from_facts) = detect(check, "--evidence", &facts, &[]);
            let (b, from_artifact) = detect(check, "--artifact", &object, &[]);
            assert_eq!((a, b), (0, 0), "{check} over {}", object.display());
            assert_eq!(from_facts["input"], "elf-facts");
            assert_eq!(from_artifact["input"], "artifact");
            for field in ["clause", "outcome", "level", "observed", "reads", "decoder"] {
                assert_eq!(
                    from_facts.get(field),
                    from_artifact.get(field),
                    "{check} over {}: {field}",
                    object.display()
                );
            }
            assert_eq!(
                from_artifact["facts_key"].as_str(),
                chard::digest::sha256_file(&object).as_deref()
            );
            compared += 1;
        }
    }
    assert_eq!(compared, ids.len() * common::ELF_FIXTURE_COUNT);
}

#[test]
fn artifact_reads_a_checked_in_object() {
    if !ready("that `--artifact` reads a checked-in object") {
        return;
    }
    let dir = repo_root().join("tests/fixtures/elf");
    let (code, got) = detect(
        "relro",
        "--artifact",
        &dir.join("elf64-le-x86_64-exec-relro-lazy.elf"),
        &[],
    );
    assert_eq!(code, 0, "{got:#}");
    assert_eq!(got["kind"], "detection");
    assert_eq!(got["proof"], true);
    assert_eq!(got["outcome"], "present");
    assert_eq!(got["level"], "partial");
    let (code, got) = detect(
        "pie",
        "--artifact",
        &dir.join("elf64-le-x86_64-static-pie-relr.elf"),
        &[],
    );
    assert_eq!(code, 0, "{got:#}");
    assert_eq!(got["outcome"], "present");
    assert_eq!(got["reads"]["elf.static_pie"], true);
    // No `.chard.report` in a synthetic object: a predicate that needs macros has no
    // source, which is a reserved clause and never `absent`.
    let (code, got) = detect(
        "ssp-level",
        "--artifact",
        &dir.join("elf64-le-x86_64-exec-relro-lazy.elf"),
        &[],
    );
    assert_eq!(code, 0, "{got:#}");
    assert_eq!(got["clause"], "@no-source:macros");
    assert_eq!(got["outcome"], "indeterminate");
}

#[test]
fn a_tracked_fixture_per_channel_reproduces_its_expectation() {
    if !ready("that a tracked fixture reproduces its expectation through `chard detect`") {
        return;
    }
    let channels: BTreeMap<String, String> = checks().into_iter().collect();
    let text = std::fs::read_to_string(repo_root().join("tests/fixtures/detectors.json"))
        .expect("the fixture corpus");
    let fixtures: Vec<Value> = serde_json::from_str(&text).expect("JSON");
    let work = common::Work::new("detect", "fixtures");
    let mut seen = BTreeMap::new();
    for fixture in &fixtures {
        let check = fixture["check"].as_str().expect("check");
        let Some(channel) = channels.get(check) else {
            continue;
        };
        if seen.contains_key(channel) {
            continue;
        }
        let path = work.path(&format!("{channel}.json"));
        std::fs::write(&path, fixture.to_string()).expect("writing");
        let (code, got) = detect(check, "--evidence", &path, &[]);
        assert_eq!(code, 0, "{check} ({channel}): {got:#}");
        assert_eq!(got["input"], "record");
        assert_eq!(got["outcome"], fixture["expected"], "{check}");
        assert_eq!(
            got.get("level").cloned().unwrap_or(Value::Null),
            fixture
                .get("expected_level")
                .cloned()
                .unwrap_or(Value::Null),
            "{check}"
        );
        assert_eq!(got["agrees"], true);
        let predicate = channel == "macro" || channel == "elf-static";
        assert_eq!(got["proof"], predicate, "{check} ({channel})");
        assert_eq!(
            got["decoder"]["kind"],
            if predicate { "predicate" } else { "code" }
        );
        seen.insert(channel.clone(), check.to_owned());
    }
    assert_eq!(
        seen.keys().map(String::as_str).collect::<Vec<_>>(),
        ["compiler-diag", "elf-static", "macro", "runtime"],
        "{seen:?}"
    );
}

/// The README's sample report, read as the library reads it.
fn sample() -> Value {
    let path = repo_root().join("tests/fixtures/sample-report.json");
    let text = std::fs::read_to_string(&path).expect("the sample fixture reads");
    serde_json::from_str(&text).expect("the sample fixture is JSON")
}

fn check(id: &str) -> &'static chard::probe::Check {
    chard::detect::check_by_id(id).expect("a corpus check")
}

fn replay_of(report: &Value, id: &str) -> chard::detect::Replay {
    chard::detect::replay_report(report, check(id), None).expect("the report replays")
}

/// The sample report's observation of `id`.
fn observation_of<'a>(report: &'a mut Value, id: &str) -> &'a mut Value {
    report["observations"]
        .as_array_mut()
        .expect("observations")
        .iter_mut()
        .find(|o| o["check"] == id)
        .expect("the sample observes the check")
}

/// What [`chard::detect::decode_evidence`] decodes `value` to, as a detection.
fn detected(value: &Value, id: &str) -> chard::detect::Detected {
    match chard::detect::decode_evidence(value, check(id), None).expect("the evidence decodes") {
        chard::detect::Output::Detected(d) => d,
        chard::detect::Output::Replay(_) => panic!("{value} decoded as a report"),
    }
}

/// A replay's counts close where every owed reading was replayed or named, and a count
/// edited apart from the lists it counts does not.
#[test]
fn a_replay_closes_only_where_its_counts_are_its_lists() {
    let mut replay = replay_of(&sample(), "ssp-level");
    assert!(replay.closes() && replay.agrees(), "{replay:?}");
    replay.expected += 1;
    assert!(!replay.closes() && !replay.agrees());
    replay.replayed += 1;
    assert!(
        !replay.closes(),
        "replayed no longer counts the replays listed"
    );
}

/// A measured verdict's restatement carries the level its reading licenses, and an arm's
/// outcome carries none.
#[test]
fn a_restated_verdict_carries_its_level_and_an_arm_outcome_none() {
    let replay = replay_of(&sample(), "relro");
    let verdict = replay
        .restated
        .iter()
        .find(|r| r.arm == "measured" && r.field == "verdict")
        .expect("the measured verdict is restated");
    assert_eq!(
        (verdict.stated.as_deref(), verdict.restated_level.as_deref()),
        (Some("partial"), Some("partial")),
        "{verdict:?}"
    );
    let outcomes: Vec<_> = replay
        .restated
        .iter()
        .filter(|r| r.field == "outcome")
        .collect();
    assert!(
        !outcomes.is_empty() && outcomes.iter().all(|r| r.restated_level.is_none()),
        "{outcomes:?}"
    );
}

/// A regime arm the profile does not owe, published and reading `absent`, leaves a
/// measured verdict earned by its triple.
#[test]
fn an_unowed_regime_arm_reading_absent_leaves_the_verdict_earned() {
    let mut report = sample();
    let o = observation_of(&mut report, "relro");
    let negative = o["controls"]["negative"].clone();
    o["controls"]["regime_negative"] = negative;
    let replay = replay_of(&report, "relro");
    let earned = replay
        .restated
        .iter()
        .find(|r| r.arm == "measured" && r.field == "controls")
        .expect("the triple restates the measured verdict");
    assert!(earned.agrees, "{earned:?}");
}

/// Every replayed site restates its reading's `facts` key as bound, and a key moved to
/// another entry is restated as unbound and not also as bound.
#[test]
fn a_facts_key_is_restated_as_bound_only_where_it_is() {
    let report = sample();
    let replay = replay_of(&report, "ssp-level");
    for arm in ["measured", "positive", "negative"] {
        assert!(
            replay
                .restated
                .iter()
                .any(|r| r.arm == arm && r.field == "facts" && r.agrees),
            "{arm}: {:?}",
            replay.restated
        );
    }
    let mut moved = report;
    let o = observation_of(&mut moved, "ssp-level");
    let measured = o["evidence"]["decoded"]["facts"].clone();
    o["controls"]["positive"]["decoded"]["facts"] = measured;
    let replay = replay_of(&moved, "ssp-level");
    let facts: Vec<_> = replay
        .restated
        .iter()
        .filter(|r| r.arm == "positive" && r.field == "facts")
        .collect();
    assert!(
        !facts.is_empty() && facts.iter().all(|r| !r.agrees),
        "{facts:?}"
    );
}

/// A code-decoded arm whose build record was cut is not replayed, whatever its run record
/// holds.
#[test]
fn an_arm_whose_build_record_was_cut_is_not_replayed() {
    let id = "implicit-int-is-error";
    let mut report = sample();
    let o = observation_of(&mut report, id);
    let build = &mut o["controls"]["positive"]["build"];
    let stderr = build["stderr"].as_str().unwrap_or_default().to_owned();
    build["stderr"] = format!("[9 {}]{stderr}", chard::probe::CUT_MARKER).into();
    let replay = replay_of(&report, id);
    assert!(
        replay
            .not_replayable
            .iter()
            .any(|n| n.arm == "positive" && n.reason == "record-cut"),
        "{:?}",
        replay.not_replayable
    );
}

/// An arm of a check whose decoder reads the artifact, with no store entry under its
/// artifact, is named as not replayable rather than replayed over no facts.
#[test]
fn an_arm_of_a_listed_check_without_its_artifact_is_not_replayed() {
    let Some(m) = measured() else { return };
    let id = chard::detect::READS_UNSTORED_ARTIFACT[0];
    let mut report = m.value.clone();
    let Some(key) = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .find(|o| o["check"] == id)
        .and_then(|o| o["controls"]["positive"]["build"]["artifact_sha256"].as_str())
        .map(ToOwned::to_owned)
    else {
        common::capability_gap(
            "a listed check's arm without its artifact",
            "the measured report built no triple for it, so no arm names an artifact",
        );
        return;
    };
    report["facts"]
        .as_object_mut()
        .expect("facts")
        .remove(&key)
        .expect("the arm's artifact is stored");
    let replay = replay_of(&report, id);
    assert!(
        replay
            .not_replayable
            .iter()
            .any(|n| n.arm == "positive" && n.reason == "code-decoder"),
        "{replay:?}"
    );
}

/// A record's expectation is its outcome and its level together.
#[test]
fn a_record_is_held_to_its_expected_level_as_well_as_its_outcome() {
    let record = |level: &str| {
        serde_json::json!({
            "check": "ssp-level",
            "expected": "present",
            "expected_level": level,
            "macros": {"__SSP_STRONG__": "2"},
        })
    };
    assert_eq!(detected(&record("strong"), "ssp-level").agrees, Some(true));
    assert_eq!(detected(&record("all"), "ssp-level").agrees, Some(false));
}

/// A `macro-dump` entry cut by this build's own filter reads a name the filter keeps and
/// the entry lacks as undefined; cut by another filter, the name is unknown.
#[test]
fn a_dump_entry_is_read_through_the_filter_it_names() {
    let entry = |filter: &str| {
        serde_json::json!({
            "kind": "macro-dump",
            "defines": 1,
            "macros_filter": filter,
            "macros": {},
        })
    };
    let own = chard::report::evidence_filters().macros.sha256;
    assert_eq!(
        detected(&entry(&own), "optimization-enabled").outcome,
        "absent"
    );
    assert_ne!(
        detected(&entry(&"0".repeat(64)), "optimization-enabled").outcome,
        "absent"
    );
}

/// An object whose values carry a machine and no ELF class is not `chard elf` output, and
/// is refused as no evidence chard reads.
#[test]
fn values_with_a_machine_alone_are_not_elf_output() {
    let Err(refused) = chard::detect::decode_evidence(
        &serde_json::json!({"a.out": {"machine": "x86_64"}}),
        check("pie"),
        None,
    ) else {
        panic!("an object of machines alone decoded");
    };
    assert!(
        refused
            .message
            .starts_with("the evidence is not a report, a store entry"),
        "{}",
        refused.message
    );
}

#[test]
fn a_record_whose_expectation_the_decoder_misses_exits_1() {
    if !ready("that a record's unmet expectation exits 1") {
        return;
    }
    let work = common::Work::new("detect", "misses");
    let path = work.write(
        "record.json",
        r#"{"check":"ssp-level","expected":"absent","macros":{"__SSP_STRONG__":"2"}}"#,
    );
    let (code, got) = detect("ssp-level", "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{got:#}");
    assert_eq!(got["outcome"], "present");
    assert_eq!(got["agrees"], false);
}

/// A code-decoded check replays through this binary's decoder over the records its sites
/// publish, and every replay of a real report agrees.
///
/// Counted under `not_replayable` as `code-decoder`, every such reading would let an edited
/// runtime or compiler-diag arm exit 0. What stays
/// unreplayed is a record an excerpt budget cut (`record-cut`), and an arm of a check whose
/// decoder reads an artifact the store does not keep (`detect::READS_UNSTORED_ARTIFACT`).
#[test]
fn every_code_decoded_reading_of_a_real_report_replays_and_agrees() {
    let Some(m) = measured() else { return };
    let code_checks: Vec<String> = checks()
        .into_iter()
        .filter(|(id, channel)| {
            (channel == "runtime" || channel == "compiler-diag")
                && m.value["observations"].as_array().is_some_and(|os| {
                    os.iter()
                        .any(|o| o["check"] == *id && o.get("controls").is_some())
                })
        })
        .map(|(id, _)| id)
        .collect();
    assert!(
        !code_checks.is_empty(),
        "no code-decoded check built its triple"
    );
    let mut replayed = 0u64;
    for check in &code_checks {
        let (code, got) = detect(check, "--evidence", &m.report, &[]);
        assert_eq!(code, 0, "{check}: {got:#}");
        assert_eq!(got["decoder"]["kind"], "code");
        assert_closes(check, &got);
        for r in got["replays"].as_array().expect("replays") {
            assert_eq!(r["agrees"], true, "{check}: {r:#}");
        }
        for r in got["restated"].as_array().expect("restated") {
            assert_eq!(r["agrees"], true, "{check}: {r:#}");
        }
        let listed = chard::detect::READS_UNSTORED_ARTIFACT.contains(&check.as_str());
        for n in got["not_replayable"].as_array().expect("not_replayable") {
            assert!(
                n["reason"] == "record-cut"
                    || (listed && n["reason"] == "code-decoder" && n["arm"] != "measured"),
                "{check}: {n}"
            );
        }
        replayed += got["replayed"].as_u64().expect("replayed");
    }
    assert!(replayed > 0, "no code-decoded reading was replayed");
}

/// A measured `on` or `off` of a code-decoded check, swapped for the other beside an intact
/// triple, disagrees with its replay and exits 1.
///
/// The triple alone cannot catch it: `earned` holds a measured verdict to a discriminating
/// triple, and both `on` and `off` stand beside one. Without the replay of a code decoder's
/// reading, this edit would exit 0.
#[test]
fn a_swapped_code_decoded_verdict_exits_1() {
    let Some(m) = measured() else { return };
    let (check, index, verdict) = m.value["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .enumerate()
        .find_map(|(i, o)| {
            let channel = o["channel"].as_str()?;
            let verdict = o["verdict"].as_str()?;
            ((channel == "runtime" || channel == "compiler-diag")
                && (verdict == "on" || verdict == "off")
                && o["controls"]["discriminating"] == true)
                .then(|| (o["check"].as_str().map(ToOwned::to_owned), i, verdict))
                .and_then(|(c, i, v)| Some((c?, i, v.to_owned())))
        })
        .expect("some code-decoded check publishes a measured on or off beside its triple");
    let path = tampered(m, "code-swapped.json", |r| {
        let o = &mut r["observations"][index];
        o["verdict"] = if verdict == "on" { "off" } else { "on" }.into();
        if let Some(obj) = o.as_object_mut() {
            obj.remove("level");
        }
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| r["agrees"] == false && r["field"] == "verdict"),
        "{got:#}"
    );
}

#[test]
fn a_report_without_the_check_is_refused_rather_than_closed_at_zero() {
    let Some(m) = measured() else { return };
    let check = predicate_checks()
        .into_iter()
        .find(|c| !readings(&m.value, c).is_empty())
        .expect("some check carries a reading");
    let path = tampered(m, "stripped.json", |r| {
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .retain(|o| o["check"] != check.as_str());
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, 2, "{check}: {got:#}");
    assert_eq!(got["error"]["operation"], "detect");
    assert!(
        got["error"]["message"]
            .as_str()
            .is_some_and(|s| s.contains("no observation")),
        "{got:#}"
    );
}

/// [`first_site`], or `None` where no observation has the site.
fn first_site_opt<T>(
    report: &Value,
    pick: impl Fn(&Value) -> Option<T>,
) -> Option<(String, usize, T)> {
    report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .enumerate()
        .find_map(|(i, o)| Some((o["check"].as_str()?.to_owned(), i, pick(o)?)))
}

/// The first observation for which `pick` returns a value,
/// with its check, index and that value.
fn first_site<T>(report: &Value, pick: impl Fn(&Value) -> Option<T>) -> (String, usize, T) {
    report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .enumerate()
        .find_map(|(i, o)| Some((o["check"].as_str()?.to_owned(), i, pick(o)?)))
        .expect("some observation has the site")
}

#[test]
fn a_verdict_its_reading_does_not_license_exits_1() {
    let Some(m) = measured() else { return };
    // The reading stays as published and replays; only the verdict beside it moves.
    let (check, index, verdict) = first_site(&m.value, |o| {
        o.get("evidence")?.get("decoded")?;
        if o.get("gating").is_some_and(|g| !g.is_null()) {
            return None;
        }
        let v = o["verdict"].as_str()?;
        matches!(v, "on" | "off" | "partial").then(|| v.to_owned())
    });
    let moved = if verdict == "off" { "on" } else { "off" };
    let path = tampered(m, "verdict.json", |r| {
        let o = r["observations"][index].as_object_mut().expect("object");
        o.insert("verdict".to_owned(), moved.into());
        o.remove("level");
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["replays"]
            .as_array()
            .expect("replays")
            .iter()
            .all(|r| r["agrees"] == true),
        "the readings themselves are untouched: {got:#}"
    );
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| { r["field"] == "verdict" && r["stated"] == moved && r["agrees"] == false }),
        "{got:#}"
    );
}

#[test]
fn a_verdict_its_reading_does_not_license_exits_1_beside_an_added_gating() {
    let Some(m) = measured() else { return };
    // No gating premise publishes a measurement, so a `gating` added beside a moved
    // verdict does not take the verdict out of restatement.
    let (check, index, verdict) = first_site(&m.value, |o| {
        o.get("evidence")?.get("decoded")?;
        let v = o["verdict"].as_str()?;
        matches!(v, "on" | "off" | "partial").then(|| v.to_owned())
    });
    let moved = if verdict == "off" { "on" } else { "off" };
    let path = tampered(m, "verdict-gated.json", |r| {
        let o = r["observations"][index].as_object_mut().expect("object");
        o.insert("verdict".to_owned(), moved.into());
        o.insert("gating".to_owned(), serde_json::json!({}));
        o.remove("level");
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| { r["field"] == "verdict" && r["stated"] == moved && r["agrees"] == false }),
        "{got:#}"
    );
}

#[test]
fn an_arm_outcome_its_reading_does_not_give_exits_1() {
    let Some(m) = measured() else { return };
    let (check, index, (arm, outcome)) = first_site(&m.value, |o| {
        ["positive", "negative", "regime_negative"]
            .into_iter()
            .find_map(|arm| {
                let a = o.get("controls")?.get(arm)?;
                a.get("decoded")?;
                Some((arm, a["outcome"].as_str()?.to_owned()))
            })
    });
    let flipped = if outcome == "absent" {
        "present"
    } else {
        "absent"
    };
    let path = tampered(m, "arm.json", |r| {
        r["observations"][index]["controls"][arm]["outcome"] = flipped.into();
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| { r["field"] == "outcome" && r["stated"] == flipped && r["agrees"] == false }),
        "{got:#}"
    );
}

/// Whether `got` restates some value at `field` and disagrees.
fn restated_disagrees(got: &Value, field: &str) -> bool {
    got["restated"]
        .as_array()
        .expect("restated")
        .iter()
        .any(|r| r["field"] == field && r["agrees"] == false)
}

/// The verdict a measured reading of `outcome` licenses on an ungraded check.
fn licensed(outcome: &str) -> Option<&'static str> {
    match outcome {
        "absent" => Some("off"),
        "present" => Some("on"),
        _ => None,
    }
}

#[test]
fn a_verdict_its_triple_did_not_earn_exits_1() {
    let Some(m) = measured() else { return };
    // A `probe-invalid` moved to the verdict its measured reading licenses: the reading
    // replays and the verdict restates against it, and only the triple withheld it.
    let withheld = first_site_opt(&m.value, |o| {
        let d = o.get("evidence")?.get("decoded")?;
        (o["verdict"] == "probe-invalid" && d.get("level").is_none())
            .then(|| licensed(d["outcome"].as_str()?))
            .flatten()
    });
    let (check, path, moved) = if let Some((check, index, moved)) = withheld {
        let path = tampered(m, "unearned.json", |r| {
            r["observations"][index]["verdict"] = moved.into();
        });
        (check, path, moved.to_owned())
    } else {
        // No such cell on this host: a discriminating `off` or `on` whose triple is
        // published as withheld instead.
        let (check, index, verdict) = first_site(&m.value, |o| {
            o.get("evidence")?.get("decoded")?;
            let v = o["verdict"].as_str()?;
            (matches!(v, "on" | "off") && o.get("controls").is_some()).then(|| v.to_owned())
        });
        eprintln!("no withheld predicate cell with a licensing reading; flipping {check}'s triple");
        let path = tampered(m, "unearned.json", |r| {
            let c = r["observations"][index]["controls"]
                .as_object_mut()
                .expect("controls");
            c.insert("discriminating".to_owned(), false.into());
            c.insert("withheld_because".to_owned(), "positive-silent".into());
        });
        (check, path, verdict)
    };
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["replays"]
            .as_array()
            .expect("replays")
            .iter()
            .all(|r| r["agrees"] == true),
        "the readings themselves are untouched: {got:#}"
    );
    assert!(
        !restated_disagrees(&got, "verdict"),
        "the reading licenses the verdict: {got:#}"
    );
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| {
                r["field"] == "controls"
                    && r["stated"] == moved.as_str()
                    && r["restated"] == "probe-invalid"
                    && r["agrees"] == false
            }),
        "{got:#}"
    );
}

#[test]
fn a_measured_verdict_with_its_triple_deleted_exits_1() {
    let Some(m) = measured() else { return };
    let (check, index, ()) = first_site(&m.value, |o| {
        o.get("evidence")?.get("decoded")?;
        (matches!(o["verdict"].as_str()?, "on" | "off" | "partial") && o.get("controls").is_some())
            .then_some(())
    });
    let path = tampered(m, "untripled.json", |r| {
        r["observations"][index]
            .as_object_mut()
            .expect("object")
            .remove("controls");
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| {
                r["field"] == "controls" && r["restated"].is_null() && r["agrees"] == false
            }),
        "{got:#}"
    );
}

#[test]
fn a_measured_reading_moved_to_another_builds_facts_exits_1() {
    let Some(m) = measured() else { return };
    // The negative arm's own reading, published as the measured build's with the `off` it
    // licenses: it replays, and the verdict restates against it. A cell whose measured
    // build and negative arm read the same bytes (one dump digest) is passed over, since
    // there the two keys are one.
    let (check, index, negative) = first_site(&m.value, |o| {
        let measured = o.get("evidence")?.get("decoded")?;
        let neg = o.get("controls")?.get("negative")?.get("decoded")?;
        (matches!(o["verdict"].as_str()?, "on" | "off" | "partial")
            && neg["outcome"] == "absent"
            && neg.get("level").is_none()
            && neg["facts"] != measured["facts"])
            .then(|| neg.clone())
    });
    let path = tampered(m, "displaced.json", |r| {
        let o = r["observations"][index].as_object_mut().expect("object");
        o.insert("verdict".to_owned(), "off".into());
        o.remove("level");
        o.get_mut("evidence")
            .and_then(Value::as_object_mut)
            .expect("evidence")
            .insert("decoded".to_owned(), negative.clone());
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["replays"]
            .as_array()
            .expect("replays")
            .iter()
            .all(|r| r["agrees"] == true),
        "the moved reading replays over the facts it names: {got:#}"
    );
    assert!(!restated_disagrees(&got, "verdict"), "{got:#}");
    assert!(restated_disagrees(&got, "facts"), "{got:#}");
}

#[test]
fn a_code_decoded_verdict_with_its_triple_deleted_exits_1() {
    let Some(m) = measured() else { return };
    // The triple needs no reading, so a code decoder's measured verdict is held to it too.
    let code: Vec<String> = checks()
        .into_iter()
        .filter(|(_, channel)| channel == "runtime" || channel == "compiler-diag")
        .map(|(id, _)| id)
        .collect();
    let (check, index, ()) = first_site(&m.value, |o| {
        (code.iter().any(|c| o["check"] == c.as_str())
            && matches!(o["verdict"].as_str()?, "on" | "off" | "partial")
            && o.get("controls").is_some())
        .then_some(())
    });
    let path = tampered(m, "untripled-code.json", |r| {
        r["observations"][index]
            .as_object_mut()
            .expect("object")
            .remove("controls");
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert_eq!(got["decoder"]["kind"], "code", "{got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| {
                r["field"] == "controls" && r["restated"].is_null() && r["agrees"] == false
            }),
        "{got:#}"
    );
}

#[test]
fn a_verdict_beside_a_reading_the_replay_cannot_rederive_exits_1() {
    let Some(m) = measured() else { return };
    // A libc++ mode reached through a macro name outside the published filter: the
    // measured reading stops at `unkept-c-int-follow`, so nothing verifies it, and an
    // `off` moved beside a reading forged to license it is not certified as agreeing.
    let check = "cxx-hardening-requested";
    let Some((_, index, key)) = first_site_opt(&m.value, |o| {
        if o["check"] != check {
            return None;
        }
        let d = o.get("evidence")?.get("decoded")?;
        d.get("macros")
            .is_none()
            .then(|| d["facts"].as_str().map(ToOwned::to_owned))?
    }) else {
        eprintln!("skipping: no measured {check} reading in this report");
        return;
    };
    if m.value["facts"][&key]["kind"] != "macro-dump" {
        eprintln!("skipping: {check}'s measured reading does not read a macro dump");
        return;
    }
    let path = tampered(m, "unkept.json", |r| {
        let macros = r["facts"][&key]["macros"]
            .as_object_mut()
            .expect("a macro-dump entry carries its macros");
        macros.insert("_LIBCPP_VERSION".to_owned(), "210000".into());
        macros.insert("_LIBCPP_HARDENING_MODE".to_owned(), "VENDOR_MODE".into());
        let o = r["observations"][index].as_object_mut().expect("object");
        o.insert("verdict".to_owned(), "off".into());
        o.remove("level");
        let d = o
            .get_mut("evidence")
            .and_then(|e| e.get_mut("decoded"))
            .and_then(Value::as_object_mut)
            .expect("decoded");
        d.insert("clause".to_owned(), "libcxx-none".into());
        d.insert("outcome".to_owned(), "absent".into());
        d.remove("level");
    });
    let (code, got) = detect(check, "--evidence", &path, &["--arm", "measured"]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["not_replayable"]
            .as_array()
            .expect("not_replayable")
            .iter()
            .any(|n| n["reason"] == "unkept-c-int-follow"),
        "{got:#}"
    );
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| {
                r["field"] == "verdict"
                    && r["stated"] == "off"
                    && r["restated"].is_null()
                    && r["agrees"] == false
            }),
        "{got:#}"
    );
}

/// Removes `decoded` from the sites `arms` names (`evidence` for the measured build) on
/// every observation of `check`.
fn strip_readings(r: &mut Value, check: &str, arms: &[&str]) {
    for o in r["observations"].as_array_mut().expect("observations") {
        if o["check"] != check {
            continue;
        }
        for arm in arms {
            let holder = if *arm == "evidence" {
                o.get_mut("evidence")
            } else {
                o.get_mut("controls").and_then(|c| c.get_mut(*arm))
            };
            if let Some(h) = holder.and_then(Value::as_object_mut) {
                h.remove("decoded");
            }
        }
    }
}

#[test]
fn a_reading_stripped_from_a_site_that_owes_one_exits_1_and_is_never_a_clean_zero() {
    let Some(m) = measured() else { return };
    let check = predicate_checks()
        .into_iter()
        .find(|c| {
            m.value["observations"]
                .as_array()
                .expect("observations")
                .iter()
                .any(|o| {
                    o["check"] == c.as_str() && o["controls"]["negative"].get("decoded").is_some()
                })
        })
        .expect("some check carries an arm reading");
    let all = ["evidence", "positive", "negative", "regime_negative"];
    for (name, arms) in [
        ("measured", &all[..1]),
        ("negative", &all[2..3]),
        ("every", &all[..]),
    ] {
        let path = tampered(m, &format!("stripped-{name}.json"), |r| {
            strip_readings(r, &check, arms);
        });
        let (code, got) = detect(&check, "--evidence", &path, &[]);
        assert_eq!(code, DISAGREES, "{check}, {name}: {got:#}");
        assert_closes(name, &got);
        assert!(
            got["expected"].as_u64().expect("expected") > 0,
            "{check}, {name}: a stripped report is not a clean zero: {got:#}"
        );
        let absent: Vec<&Value> = got["not_replayable"]
            .as_array()
            .expect("not_replayable")
            .iter()
            .filter(|n| n["reason"] == "reading-absent")
            .collect();
        assert!(!absent.is_empty(), "{check}, {name}: {got:#}");
        if name == "every" {
            assert_eq!(got["replayed"], 0, "{got:#}");
            assert_eq!(
                absent.len() as u64,
                got["expected"].as_u64().expect("expected"),
                "every owed site is named absent: {got:#}"
            );
        }
    }
}

#[test]
fn chard_elf_output_over_an_object_named_like_a_record_member_reads_as_elf_output() {
    if !ready("that `chard elf` output is recognised whatever its path is named") {
        return;
    }
    let work = common::Work::new("detect", "elfnamed");
    let object = repo_root().join("tests/fixtures/elf/elf64-le-x86_64-exec-relro-lazy.elf");
    let output = chard(&["elf", object.to_str().expect("UTF-8")]);
    assert_eq!(output.status.code(), Some(0));
    let listing: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let facts = listing
        .as_object()
        .and_then(|m| m.values().next())
        .expect("one object")
        .clone();
    for name in ["run", "build", "elf", "macros", "kind"] {
        let path = work.write(
            &format!("{name}.json"),
            &serde_json::json!({ name: facts }).to_string(),
        );
        let (code, got) = detect("relro", "--evidence", &path, &[]);
        assert_eq!(code, 0, "{name}: {got:#}");
        assert_eq!(got["input"], "elf-facts", "{name}");
        assert_eq!(got["level"], "partial", "{name}");
    }
}

/// The checks whose declaration asks for a regime-matched negative arm
/// (`Regime::Arm`), which `chard probes` does not list.
const REGIME_CHECKS: &[&str] = &["auto-var-init-active", "auto-var-init-pattern"];

#[test]
fn a_regime_arm_the_profile_owes_is_owed_whether_or_not_it_is_published() {
    let Some(m) = measured() else { return };
    let listed = checks();
    for id in REGIME_CHECKS {
        assert!(
            listed.iter().any(|(c, _)| c == id),
            "{id} is not in the corpus"
        );
    }
    // A `bare` report owes no regime arm, so its triples publish none. Under a profile
    // that adds a flag the same triple owes one, and without it the measured verdict is
    // unearned: the shape of a regime arm deleted from a report measured under a profile.
    let (check, _, verdict) = first_site(&m.value, |o| {
        let v = o["verdict"].as_str()?;
        (REGIME_CHECKS.iter().any(|c| o["check"] == *c)
            && matches!(v, "on" | "off" | "partial")
            && o.get("controls")?.get("regime_negative").is_none())
        .then(|| v.to_owned())
    });
    let (code, got) = detect(&check, "--evidence", &m.report, &[]);
    assert_eq!(
        code, 0,
        "{check} under the profile it was measured with: {got:#}"
    );
    let path = tampered(m, "regime-owed.json", |r| {
        r["profile"]["cflags"] = serde_json::json!(["-O2"]);
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| {
                r["field"] == "controls"
                    && r["stated"] == verdict.as_str()
                    && r["restated"] == "probe-invalid"
                    && r["agrees"] == false
            }),
        "{got:#}"
    );
}

/// The first measured cell beside a discriminating triple, ungated, with its check,
/// index and verdict.
fn first_discriminating_measurement(report: &Value) -> (String, usize, String) {
    first_site(report, |o| {
        let v = o["verdict"].as_str()?;
        (matches!(v, "on" | "off" | "partial")
            && o.get("controls")?.get("discriminating")? == true
            && o.get("gating").is_none_or(Value::is_null))
        .then(|| v.to_owned())
    })
}

#[test]
fn a_measurement_relabelled_probe_invalid_beside_its_discriminating_triple_exits_1() {
    let Some(m) = measured() else { return };
    // A discriminating triple reaches `decide`'s verdict arm, and nothing later writes
    // `probe-invalid`: the report's rule `verdict-unearned-by-controls` refuses the pair,
    // and the replay restates it.
    let (check, index, _) = first_discriminating_measurement(&m.value);
    let path = tampered(m, "relabelled-invalid.json", |r| {
        let o = r["observations"][index].as_object_mut().expect("object");
        o.insert("verdict".to_owned(), "probe-invalid".into());
        o.remove("level");
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, DISAGREES, "{check}: {got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .any(|r| {
                r["field"] == "controls"
                    && r["stated"] == "probe-invalid"
                    && r["restated"].is_null()
                    && r["agrees"] == false
            }),
        "{got:#}"
    );
}

#[test]
fn a_measurement_relabelled_indeterminate_is_not_restated_against_its_triple() {
    let Some(m) = measured() else { return };
    // `indeterminate` beside a discriminating triple is what the fortify ratchet's
    // withholding and a gating rule leave, and a replay re-derives neither, so the
    // relabel is outside what `chard detect` restates: the limit the module documentation,
    // DESIGN.md and THREAT_MODEL.md name. The test pins the limit, so a change that
    // closes it changes this test with the documents.
    let (check, index, _) = first_discriminating_measurement(&m.value);
    let path = tampered(m, "relabelled-indeterminate.json", |r| {
        let o = r["observations"][index].as_object_mut().expect("object");
        o.insert("verdict".to_owned(), "indeterminate".into());
        o.remove("level");
    });
    let (code, got) = detect(&check, "--evidence", &path, &[]);
    assert_eq!(code, 0, "{check}: {got:#}");
    assert!(
        got["restated"]
            .as_array()
            .expect("restated")
            .iter()
            .all(|r| r["stated"] != "indeterminate"),
        "{got:#}"
    );
}

/// A `--normalize` report replays. `report::VOLATILE_READINGS` masks the stack-clash
/// probe's `dist=` after the decoder read it and keeps `ratio_pct` so that
/// `chard detect --evidence` still has a reading to replay; a decoder that needs the masked
/// digits turns every arm `indeterminate` against a published `off`/`present`/`absent`
/// and exits 1. Measured that way on 2026-10-05 (Fedora 44 x86_64, gcc 16.1.1, default stack
/// limit) with a decoder that recomputes the ratio from `dist`.
#[test]
fn a_normalized_stack_clash_report_replays() {
    let verifies = "that a normalized stack-clash report replays through `chard detect`";
    if !(ready(verifies) && common::require_cc(verifies)) {
        return;
    }
    let work = common::Work::new("detect", "normalized");
    let report = work.path("report.json");
    let output = Command::new(chard_binary())
        .args(["measure", "--profile", "bare", "--normalize"])
        .args(["--probe", "stack-clash"])
        .arg("--workdir")
        .arg(work.path("work"))
        .arg("--output")
        .arg(&report)
        .output()
        .expect("spawning chard measure");
    assert_eq!(
        output.status.code(),
        Some(0),
        "measure failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&report).expect("the report was written");
    let masked = format!("SCPRT dist={}", chard::report::NORMALIZED_READING);
    if !text.contains(&masked) {
        common::capability_gap(
            "normalized stack-clash replay",
            "no arm printed a stack-clash distance on this host, so nothing was masked",
        );
        return;
    }
    let (code, got) = detect("stack-clash-guard-page", "--evidence", &report, &[]);
    assert_eq!(code, 0, "{got:#}");
    assert_closes("normalized", &got);
    let replays = got["replays"].as_array().expect("replays");
    // The measured build and at least both control arms, each replayed rather than set
    // aside.
    let expected = got["expected"].as_u64().expect("expected");
    assert!(expected >= 3, "{got:#}");
    assert_eq!(
        replays.len() as u64,
        expected,
        "every published reading replays: {got:#}"
    );
    for r in replays {
        assert_eq!(r["agrees"], true, "{r:#}");
    }
    // The mask must be read, not merely survived: a run whose every arm withheld would
    // agree with nothing decided.
    let decided = replays
        .iter()
        .filter(|r| r["published"]["outcome"] != "indeterminate")
        .count();
    assert!(decided > 0, "no replayed arm decided anything: {got:#}");
}

/// The half of [`a_chard_document_that_is_not_a_report_is_refused_by_name`] that needs no
/// measurement, so a host with no C compiler still runs it: the probe listing and an error
/// envelope are refused as not a report, and `chard elf` output whose one path is named
/// `chard_schema` is read as `elf` output, a detection, since its value is facts and not a
/// version string.
#[test]
fn chard_documents_needing_no_measurement_are_told_apart_from_a_report() {
    if !ready("that --evidence tells chard's other documents from a report") {
        return;
    }
    let work = common::Work::new("detect", "documents-unmeasured");
    let (code, listing) = json_of(&chard(&["probes"]));
    assert_eq!(code, 0);
    let (code, envelope) = json_of(&chard(&["table", "/nonexistent/chard-detect-test"]));
    assert_eq!(code, 2);
    for (label, document) in [("probe listing", listing), ("error envelope", envelope)] {
        assert!(
            document["chard_schema"].is_string(),
            "{label}: {document:#}"
        );
        let path = work.path(&format!("{}.json", label.replace(' ', "-")));
        std::fs::write(&path, serde_json::to_string(&document).expect("serialize")).expect("write");
        let (code, got) = detect("relro", "--evidence", &path, &[]);
        assert_eq!(code, 2, "{label}: {got:#}");
        assert_eq!(got["error"]["code"], "USER_INPUT", "{label}: {got:#}");
        assert!(
            got["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("not a report")),
            "{label}: {got:#}"
        );
    }
    let fixture = elf_fixtures().into_iter().next().expect("an ELF fixture");
    let fixture = fixture.to_str().expect("a UTF-8 path");
    let (code, elf) = json_of(&chard(&["elf", fixture]));
    assert_eq!(code, 0, "{elf:#}");
    let facts = elf
        .as_object()
        .and_then(|m| m.values().next())
        .expect("one path's facts");
    let renamed = work.path("elf-named-chard_schema.json");
    std::fs::write(
        &renamed,
        serde_json::json!({ "chard_schema": facts }).to_string(),
    )
    .expect("write");
    let (code, got) = detect("relro", "--evidence", &renamed, &[]);
    assert_eq!(code, 0, "{got:#}");
    assert_eq!(got["kind"], "detection", "{got:#}");
}

/// Every JSON document chard writes but `elf`'s carries `chard_schema`, so that key does not
/// tell a report apart. Each of chard's other documents, as chard wrote it, is refused as not a
/// report (exit 2, `USER_INPUT`), never replayed as a report that lost its readings: a replay of
/// a real report (whose `observations` is a count, which a sniff for the key alone takes for a
/// report), a detection, a matrix, the probe listing and an error envelope. What tells a report
/// apart is an `observations` list beside the version.
#[test]
fn a_chard_document_that_is_not_a_report_is_refused_by_name() {
    let Some(m) = measured() else {
        return;
    };
    let work = common::Work::new("detect", "documents");
    let (check, ..) = first_measured_reading(&m.value);
    let replay = detect(&check, "--evidence", &m.report, &[]).1;
    assert_eq!(replay["kind"], "replay", "{replay:#}");
    assert!(replay["observations"].is_u64(), "{replay:#}");
    let fixture = elf_fixtures().into_iter().next().expect("an ELF fixture");
    let detection = detect(&check, "--artifact", &fixture, &[]).1;
    assert_eq!(detection["kind"], "detection", "{detection:#}");
    let report = m.report.to_str().expect("a UTF-8 path");
    let (code, matrix) = json_of(&chard(&["matrix", report]));
    assert_eq!(code, 0, "{matrix:#}");
    for (label, document) in [
        ("replay", replay),
        ("detection", detection),
        ("matrix", matrix),
    ] {
        assert!(
            document["chard_schema"].is_string(),
            "{label}: {document:#}"
        );
        let path = work.path(&format!("{}.json", label.replace(' ', "-")));
        std::fs::write(&path, serde_json::to_string(&document).expect("serialize")).expect("write");
        let (code, got) = detect(&check, "--evidence", &path, &[]);
        assert_eq!(code, 2, "{label}: {got:#}");
        assert_eq!(got["error"]["code"], "USER_INPUT", "{label}: {got:#}");
        assert!(
            got["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("not a report")),
            "{label}: {got:#}"
        );
    }
}
