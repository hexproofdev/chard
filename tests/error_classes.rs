// SPDX-License-Identifier: BSD-3-Clause

//! What the envelope's `code` says for each kind of failure, through the built binary.

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

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

mod common;

use common::chard_binary;

/// The envelope one failing invocation printed.
struct Envelope {
    code: String,
    operation: String,
    message: String,
    hint: Option<String>,
}

/// Run `chard` with `args` and read the envelope, asserting the contract around it: exit
/// `2`, one JSON object on stdout and nothing else there.
fn envelope_of(output: &std::process::Output) -> Envelope {
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a failure exits 2; stdout was:\n{text}"
    );
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's stdout was not one JSON object ({e}):\n{text}"));
    let error = parsed
        .get("error")
        .unwrap_or_else(|| panic!("stdout carried no envelope:\n{text}"));
    let field = |name: &str| error.get(name).and_then(Value::as_str).map(str::to_owned);
    Envelope {
        code: field("code").expect("an envelope carries a code"),
        operation: field("operation").expect("an envelope carries an operation"),
        message: field("message").expect("an envelope carries a message"),
        hint: field("hint"),
    }
}

fn output_of(args: &[&OsStr]) -> std::process::Output {
    Command::new(chard_binary())
        .args(args)
        .output()
        .expect("spawning chard")
}

fn run(args: &[&OsStr]) -> Envelope {
    envelope_of(&output_of(args))
}

/// The facts `chard elf` printed for its one argument, under the key the path was given
/// as, asserting the contract around them: exit `0` and one JSON object on stdout.
fn facts_of(output: &std::process::Output, key: &Path) -> Value {
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a read that succeeded exits 0; stdout was:\n{text}\nstderr was:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's stdout was not one JSON object ({e}):\n{text}"));
    parsed
        .get(key.display().to_string())
        .cloned()
        .unwrap_or_else(|| panic!("no facts under {}:\n{text}", key.display()))
}

fn elf(path: &Path) -> Envelope {
    run(&[OsStr::new("elf"), path.as_os_str()])
}

fn ready(verifies: &str) -> bool {
    common::require_binary(&chard_binary(), verifies)
}

/// Sixteen bytes or more, so the reader gets past the identification and refuses the
/// magic; a shorter file is refused as too short, which is the next test's case.
const TEXT: &str = "127.0.0.1 localhost\n";

#[test]
fn elf_on_a_text_file_is_the_callers_input() {
    if !ready("that a non-ELF file handed to `chard elf` is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "text");
    let path = work.write("hosts", TEXT);
    let got = elf(&path);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("not an ELF file"), "{}", got.message);
    assert!(
        got.hint.as_deref().is_some_and(|h| h.contains("chard elf")),
        "{:?}",
        got.hint
    );
}

#[test]
fn elf_on_an_empty_file_is_the_callers_input() {
    if !ready("that an empty file handed to `chard elf` is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "empty");
    let path = work.write("empty", "");
    let got = elf(&path);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("too short"), "{}", got.message);
}

#[test]
fn elf_on_a_directory_is_the_callers_input() {
    if !ready("that a directory handed to `chard elf` is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "dir");
    let got = elf(work.dir());
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.message.contains("not a regular file") && got.message.contains("directory"),
        "{}",
        got.message
    );
    assert!(
        got.hint.as_deref().is_some_and(|h| h.contains("chard elf")),
        "{:?}",
        got.hint
    );
}

/// Wait at most ten seconds for `child`. The cases this serves feed an object down a
/// pipe, and a child that never exits would turn the assertion into silence, which is the
/// outcome the discipline refuses.
fn output_within_ten_seconds(mut child: std::process::Child, what: &str) -> std::process::Output {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if child.try_wait().expect("polling chard").is_some() {
            return child.wait_with_output().expect("collecting chard's output");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{what} blocked for ten seconds (the child is left to the harness)"
        );
        #[expect(
            clippy::disallowed_methods,
            reason = "the wait is on a child's exit, which std offers no timed wait for: try_wait \
                      between sleeps, under the ten-second deadline, is the bounded wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn elf_on_a_fifo_carrying_an_object_reads_it() {
    if !ready("that an object fed down a FIFO is read by `chard elf`") {
        return;
    }
    let work = common::Work::new("errorclasses", "fifo");
    let fifo = work.path("fifo");
    let made = Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|status| status.success()) {
        common::capability_gap(
            "`chard elf` reading an object from a FIFO",
            "this host has no mkfifo to make one with",
        );
        return;
    }
    let object = fixture_object();
    let bytes = std::fs::read(&object).expect("read the fixture");
    let child = Command::new(chard_binary())
        .arg("elf")
        .arg(&fifo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning chard");
    // The writer's `open` pairs with chard's, and its `write_all` ends when chard has read
    // the bytes or has gone.
    let feed = {
        let fifo = fifo.clone();
        std::thread::spawn(move || -> std::io::Result<()> {
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo)?
                .write_all(&bytes)
        })
    };
    let output = output_within_ten_seconds(child, "chard elf on a FIFO with a writer");
    let from_pipe = facts_of(&output, &fifo);
    let from_file = facts_of(
        &output_of(&[OsStr::new("elf"), object.as_os_str()]),
        &object,
    );
    assert_eq!(from_pipe, from_file, "the pipe carried the same object");
    feed.join()
        .expect("the writer thread")
        .expect("feeding the FIFO");
}

#[test]
fn elf_on_stdin_from_a_pipe_reads_it() {
    if !ready("that an object piped to `chard elf /dev/stdin` is read") {
        return;
    }
    let object = fixture_object();
    let bytes = std::fs::read(&object).expect("read the fixture");
    let mut child = Command::new(chard_binary())
        .arg("elf")
        .arg("/dev/stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning chard");
    let mut stdin = child.stdin.take().expect("a piped stdin");
    // A chard that refused the pipe read nothing, and the write then ends with `EPIPE`
    // rather than blocking; the facts assertion names the envelope first.
    let feed = std::thread::spawn(move || {
        use std::io::Write as _;
        let fed = stdin.write_all(&bytes);
        drop(stdin);
        fed
    });
    let output = output_within_ten_seconds(child, "chard elf /dev/stdin behind a pipe");
    let from_pipe = facts_of(&output, Path::new("/dev/stdin"));
    let from_file = facts_of(
        &output_of(&[OsStr::new("elf"), object.as_os_str()]),
        &object,
    );
    assert_eq!(from_pipe, from_file, "the pipe carried the same object");
    feed.join()
        .expect("the writer thread")
        .expect("feeding stdin");
}

#[test]
fn elf_on_a_missing_path_is_the_callers_input() {
    if !ready("that a missing path handed to `chard elf` is the caller's to fix") {
        return;
    }
    let got = elf(Path::new("/nonexistent/chard-error-classes/x"));
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.hint.as_deref().is_some_and(|h| h.contains("path")),
        "{:?}",
        got.hint
    );
}

#[test]
fn elf_above_the_size_cap_is_the_callers_input() {
    if !ready("that an object above the size cap is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "cap");
    let path = work.path("big");
    let f = std::fs::File::create(&path).expect("create the oversize file");
    f.set_len(512 * 1024 * 1024 + 1).expect("extend sparsely");
    drop(f);
    let got = elf(&path);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("cap"), "{}", got.message);
}

#[test]
fn elf_on_a_truncated_header_names_the_readelf_cross_check() {
    if !ready("that a truncated object is the caller's, with the cross-check in the hint") {
        return;
    }
    let work = common::Work::new("errorclasses", "truncated");
    let path = work.path("cut");
    let mut bytes = b"\x7fELF\x02\x01\x01".to_vec();
    bytes.resize(20, 0);
    std::fs::write(&path, bytes).expect("write the truncated header");
    let got = elf(&path);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.hint.as_deref().is_some_and(|h| h.contains("cut")),
        "{:?}",
        got.hint
    );
}

#[test]
fn elf_on_an_unreadable_file_is_permission() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that a file the caller cannot read is a permission problem") {
        return;
    }
    let work = common::Work::new("errorclasses", "unreadable");
    let path = work.write("locked", TEXT);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    if std::fs::read(&path).is_ok() {
        common::capability_gap(
            "PERMISSION from `chard elf` on a mode-000 file",
            "this process reads the file anyway, so the mode stops nothing here",
        );
        return;
    }
    let got = elf(&path);
    assert_eq!(got.code, "PERMISSION", "{}", got.message);
    assert!(got.message.contains("locked"), "{}", got.message);
}

#[test]
fn measure_into_an_unwritable_work_directory_is_permission() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that a work directory the caller cannot create in is a permission problem") {
        return;
    }
    let work = common::Work::new("errorclasses", "readonly");
    let parent = work.path("ro");
    std::fs::create_dir(&parent).expect("create the parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).expect("chmod 500");
    if std::fs::create_dir(parent.join("probe")).is_ok() {
        common::capability_gap(
            "PERMISSION from `chard measure` into a mode-500 directory",
            "this process creates inside it anyway, so the mode stops nothing here",
        );
        return;
    }
    let got = run(&[
        OsStr::new("measure"),
        OsStr::new("--cc"),
        OsStr::new("/nonexistent/chard-test-compiler"),
        OsStr::new("--workdir"),
        parent.join("w").as_os_str(),
    ]);
    assert_eq!(got.code, "PERMISSION", "{}", got.message);
    assert!(got.message.contains("work directory"), "{}", got.message);
}

#[test]
fn measure_into_an_existing_unwritable_work_directory_names_the_file_chard_could_not_write() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that a work directory chard cannot write into names the file it could not") {
        return;
    }
    let work = common::Work::new("errorclasses", "ro-workdir");
    let cc = work.write("cc", SHIM);
    std::fs::set_permissions(&cc, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
    let workdir = work.path("w");
    std::fs::create_dir(&workdir).expect("create the work directory");
    std::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o500)).expect("chmod 500");
    if std::fs::write(workdir.join("probe"), "").is_ok() {
        common::capability_gap(
            "PERMISSION from `chard measure` writing into a mode-500 work directory",
            "this process writes into it anyway, so the mode stops nothing here",
        );
        return;
    }
    let output = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&cc)
            .arg("--workdir")
            .arg(&workdir);
        cmd
    });
    let got = envelope_of(&output);
    assert_eq!(got.code, "PERMISSION", "{}", got.message);
    assert!(
        got.message.contains("claiming the work directory"),
        "{}",
        got.message
    );
    assert!(
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains(".chard-measure.")),
        "{:?}",
        got.hint
    );
    std::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o700)).expect("chmod 700");
}

#[test]
fn measure_with_a_cc_that_cannot_be_executed_is_the_callers_input() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that a --cc with no execute bit is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "mode644");
    let cc = work.write("cc", TEXT);
    std::fs::set_permissions(&cc, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
    let got = run(&[
        OsStr::new("measure"),
        OsStr::new("--cc"),
        cc.as_os_str(),
        OsStr::new("--workdir"),
        work.path("w").as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.message.contains("not an executable file") && got.message.contains("mode644"),
        "the message names the path and the requirement: {}",
        got.message
    );
    assert!(
        got.hint.as_deref().is_some_and(|h| h.contains("--cc")),
        "{:?}",
        got.hint
    );
}

#[test]
fn measure_into_a_work_directory_that_is_a_file_is_the_callers_input() {
    if !ready("that a --workdir naming an existing file is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "workdir-file");
    let file = work.write("text", TEXT);
    let got = run(&[
        OsStr::new("measure"),
        OsStr::new("--cc"),
        OsStr::new("/nonexistent/chard-test-compiler"),
        OsStr::new("--workdir"),
        file.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("work directory"), "{}", got.message);
    assert!(
        got.hint.as_deref().is_some_and(|h| h.contains("directory")),
        "{:?}",
        got.hint
    );
}

/// The work directory claims in `dir`, none where it cannot be listed.
fn claims_in(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.expect("an entry").path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with(".chard-measure."))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A fixture script's shell loop that runs while `condition` holds, bounded twice: it exits
/// 1 once `work` is gone or once the script's poll count `n` reaches `GATE_POLLS`. `n` is set
/// once, by [`gated_wait`], and every loop in one script counts on it, so all of a script's
/// waits together last at most `GATE_POLLS` polls. An unbounded wait here would outlive its
/// test: the test kills the run that started the driver and the directory is removed, and the
/// driver polls for ever for a file that cannot appear. `Work`'s drop fails a test that leaves
/// such a process; the bound is what keeps one from being left.
fn bounded_wait(condition: &str, work: &Path) -> String {
    format!(
        "while {condition}; do\n  [ -d '{}' ] && [ $n -lt {GATE_POLLS} ] || exit 1\n  \
         n=$((n + 1)); sleep 0.05\ndone",
        work.display()
    )
}

/// The start of a fixture script that waits for `gate` to exist: [`bounded_wait`], with the
/// script's poll count set.
fn gated_wait(gate: &Path, work: &Path) -> String {
    format!(
        "n=0\n{}",
        bounded_wait(&format!("[ ! -e '{}' ]", gate.display()), work)
    )
}

/// How many 50ms polls a fixture script makes in all before it gives up: at least 30s, three
/// times the 10s the tests that use it allow for the run to make its claim.
const GATE_POLLS: u32 = 600;

#[test]
fn measure_in_a_work_directory_another_run_holds_is_transient() {
    if !ready("that a second measure in a busy work directory is refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "busy-workdir");
    let gate = work.path("gate");
    common::removed(std::fs::remove_file(&gate), &gate);
    let shared = work.path("shared");
    common::removed(std::fs::remove_dir_all(&shared), &shared);
    let held = common::executable(
        &work.path("held-cc"),
        &format!(
            "[ $# -eq 0 ] && exit 0\n{}\n{}\nexit 1",
            gated_wait(&gate, work.dir()),
            bounded_wait("kill -0 $PPID 2>/dev/null", work.dir())
        ),
    );
    let claims = || claims_in(&shared);
    let mut holder = Command::new(chard_binary())
        .arg("measure")
        .args(["-o", "-"])
        .arg("--cc")
        .arg(&held)
        .arg("--workdir")
        .arg(&shared)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning the holding run");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while claims().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the holding run made no claim within 10s"
        );
        #[expect(
            clippy::disallowed_methods,
            reason = "the condition is a claim appearing in the work directory, which nothing here \
                      can wait on: listing it between sleeps, under the 10 s deadline, is the wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let missing = OsStr::new("/nonexistent/chard-test-compiler");
    let second = run(&[
        OsStr::new("measure"),
        OsStr::new("--cc"),
        missing,
        OsStr::new("--workdir"),
        shared.as_os_str(),
    ]);
    let held_claims = claims();
    std::fs::write(&gate, "").expect("opening the gate");
    holder.kill().expect("killing the holding run");
    holder.wait().expect("reaping the holding run");
    assert_eq!(
        held_claims.len(),
        1,
        "the refused run removed its own claim: {held_claims:?}"
    );
    if !Path::new("/proc/self/stat").exists() {
        // No /proc: the holder cannot be judged live or gone, so the refusal is the
        // caller's, naming the file to remove.
        assert_eq!(second.code, "USER_INPUT", "{}", second.message);
        assert!(
            second.hint.as_deref().is_some_and(|h| h.contains("remove")),
            "{:?}",
            second.hint
        );
        common::capability_gap(
            "a live run's claim is judged live and a killed run's judged gone",
            "this system has no /proc, so every other run's claim is refused as unjudged",
        );
        return;
    }
    assert_eq!(second.code, "TRANSIENT", "{}", second.message);
    assert_eq!(second.operation, "measure");
    assert!(
        second.message.contains(&format!("process {}", holder.id())),
        "{}",
        second.message
    );

    // The killed run's claim, kept to plant again below.
    let stale = held_claims[0].clone();
    let third_output = output_of(&[
        OsStr::new("measure"),
        OsStr::new("--cc"),
        missing,
        OsStr::new("--workdir"),
        shared.as_os_str(),
    ]);
    let third = envelope_of(&third_output);
    assert_eq!(third.code, "USER_INPUT", "{}", third.message);
    let noted = String::from_utf8_lossy(&third_output.stderr);
    assert!(
        noted.contains("a claim left by a run whose process is gone"),
        "the removal is noted: {noted}"
    );
    assert!(
        claims().is_empty(),
        "the killed run's claim was removed: {:?}",
        claims()
    );

    a_gone_claim_that_cannot_be_removed_is_said(&shared, &stale, missing);
}

/// The killed run's claim planted again as a directory, which `remove_file` refuses: the
/// claim is judged gone by its name, and the failure to remove it is said.
fn a_gone_claim_that_cannot_be_removed_is_said(shared: &Path, stale: &Path, missing: &OsStr) {
    std::fs::create_dir(stale).expect("planting the claim as a directory");
    std::fs::write(stale.join("held"), "").expect("a file inside it");
    let fourth_output = output_of(&[
        OsStr::new("measure"),
        OsStr::new("--cc"),
        missing,
        OsStr::new("--workdir"),
        shared.as_os_str(),
    ]);
    let noted = String::from_utf8_lossy(&fourth_output.stderr);
    std::fs::remove_dir_all(stale).expect("removing the planted directory");
    assert!(
        noted.contains("a claim left by a run that is gone")
            && noted.contains("could not be removed"),
        "{noted}"
    );
}

#[test]
fn measure_whose_claim_was_removed_mid_run_publishes_nothing() {
    let verifies = "that a run whose work directory claim was removed publishes nothing";
    if !(ready(verifies) && common::require_cc(verifies)) {
        return;
    }
    let work = common::Work::new("errorclasses", "claim-removed");
    let gate = work.path("gate");
    common::removed(std::fs::remove_file(&gate), &gate);
    let shared = work.path("shared");
    common::removed(std::fs::remove_dir_all(&shared), &shared);
    let report = work.path("report.json");
    common::removed(std::fs::remove_file(&report), &report);
    let real = Command::new("sh")
        .args(["-c", "command -v cc"])
        .output()
        .expect("sh is available");
    let real = String::from_utf8_lossy(&real.stdout).trim().to_owned();
    assert!(
        !real.is_empty(),
        "`require_cc` said a C compiler is present"
    );
    let gated = common::executable(
        &work.path("fakecc"),
        &format!(
            "[ $# -eq 0 ] && exit 0\n{}\nexec '{real}' \"$@\"",
            gated_wait(&gate, work.dir())
        ),
    );
    let claims = || claims_in(&shared);
    let run = Command::new(chard_binary())
        .args(["measure", "--profile", "bare", "--probe", "link-defaults"])
        .arg("--cc")
        .arg(&gated)
        .arg("--workdir")
        .arg(&shared)
        .arg("--output")
        .arg(&report)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the run");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while claims().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the run made no claim within 10s"
        );
        #[expect(
            clippy::disallowed_methods,
            reason = "the condition is a claim appearing in the work directory, which nothing here \
                      can wait on: listing it between sleeps, under the 10 s deadline, is the wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for claim in claims() {
        std::fs::remove_file(&claim).expect("removing the run's claim");
    }
    std::fs::write(&gate, "").expect("opening the gate");
    let output = run.wait_with_output().expect("waiting for the run");
    let got = envelope_of(&output);
    assert_eq!(got.code, "TRANSIENT", "{}", got.message);
    assert!(
        got.message.contains("was removed while it measured"),
        "{}",
        got.message
    );
    // The claim was already gone when the run let it go, which is no claim stuck.
    let noted = String::from_utf8_lossy(&output.stderr);
    assert!(!noted.contains("could not be removed"), "{noted}");
    assert!(
        !report.exists(),
        "a run that lost its claim published a report"
    );
}

/// Wait at most `within` for `child` to exit. Past it, kill it here and return `None`: a
/// test waiting on a fixture the check under test should have killed must not hang when the
/// check fails, and must clean up before it asserts anything.
fn exit_within(
    child: &mut std::process::Child,
    within: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().expect("polling the fixture") {
            return Some(status);
        }
        if std::time::Instant::now() >= deadline {
            chard::error::best_effort(child.kill());
            chard::error::best_effort(child.wait());
            return None;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the wait is on a child's exit, which std offers no timed wait for: try_wait \
                      between sleeps, under the caller's bound, is the bounded wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// The children of process `pid`, read from `/proc` directly, so a test can clean up a
/// fixture's descendants without trusting the check it is testing to have found them.
fn children_of(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Is process `pid` gone (or a zombie, which runs nothing)? Wait at most 5s for it; past
/// that, kill it so the failing test leaves nothing, and say no.
fn gone_or_killed(pid: u32) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok();
        // The state is the field after the parenthesised command name.
        let zombie = state
            .as_deref()
            .and_then(|s| s.rsplit_once(") "))
            .is_some_and(|(_, rest)| rest.starts_with('Z'));
        if state.is_none() || zombie {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            chard::error::best_effort(
                Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status(),
            );
            return false;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the condition is a process that is not this one's child leaving /proc, which \
                      nothing here can wait on: reading its stat between sleeps, up to 5 s, is the \
                      wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// The check `Work`'s drop makes, shown to fail on each of its two channels, for `work`.
fn a_leak_fails_its_test(work: common::Work, verifies: &str) {
    use std::os::unix::process::ExitStatusExt as _;
    let script = common::executable(
        &work.path("forever"),
        &format!(
            "[ $# -eq 0 ] && exit 0\n(cd '{}' && exec sleep 3600)",
            work.dir().display()
        ),
    );
    let mut left = Command::new(&script)
        .arg("left")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning the fixture");
    if let Err(why) = work.leftover_processes() {
        chard::error::best_effort(left.kill());
        chard::error::best_effort(left.wait());
        common::capability_gap(verifies, &why);
        return;
    }
    // Read now, while the shell is alive and still its parent, so every path below can kill
    // the sleep without relying on the check under test to have seen it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut descendants = children_of(left.id());
    while descendants.is_empty() && std::time::Instant::now() < deadline {
        #[expect(
            clippy::disallowed_methods,
            reason = "the condition is the shell's child appearing in /proc, which nothing here \
                      can wait on: reading the shell's children between sleeps, up to 5 s, is the \
                      wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
        descendants = children_of(left.id());
    }
    let (shell, sleep) = loop {
        let seen = work
            .leftover_processes()
            .expect("the processes were visible a moment ago");
        let shell = seen.iter().find(|l| l.pid == left.id()).cloned();
        let sleep = seen
            .iter()
            .find(|l| l.command.starts_with("sleep "))
            .cloned();
        if let (Some(shell), Some(sleep)) = (shell, sleep) {
            break (shell, sleep);
        }
        if std::time::Instant::now() >= deadline {
            chard::error::best_effort(left.kill());
            chard::error::best_effort(left.wait());
            for pid in seen
                .iter()
                .map(|l| l.pid)
                .chain(descendants.iter().copied())
            {
                gone_or_killed(pid);
            }
            panic!("the shell and its sleep were not both seen within 5s: {seen:?}");
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the condition is the shell and its sleep both naming the directory in /proc, \
                      which nothing here can wait on: reading the leftovers between sleeps, up to \
                      5 s, is the wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(work)));
    // Reaped and confirmed gone before anything is asserted, so no outcome leaves them.
    let status = exit_within(&mut left, std::time::Duration::from_secs(5));
    let sleep_gone = gone_or_killed(sleep.pid);
    for pid in descendants {
        gone_or_killed(pid);
    }
    assert!(
        shell.by_args && !shell.by_cwd,
        "the shell was to be seen by its arguments alone: {shell:?}"
    );
    assert!(
        sleep.by_cwd && !sleep.by_args,
        "the sleep was to be seen by its working directory alone: {sleep:?}"
    );
    let why = dropped.expect_err("a process left running did not fail the test");
    let why = why.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(why.contains("outlived the test"), "{why}");
    assert!(why.contains(&format!("\n  {}: ", shell.pid)), "{why}");
    assert!(
        why.contains(&format!("\n  {}: sleep 3600", sleep.pid)),
        "{why}"
    );
    assert!(why.ends_with("all were killed"), "{why}");
    let status = status.expect("the shell was still running 5s after the drop; killed it here");
    assert_eq!(
        status.signal(),
        Some(9),
        "the shell was not killed: {status:?}"
    );
    assert!(sleep_gone, "the sleep {} outlived the drop", sleep.pid);
}

#[test]
fn a_process_left_in_a_work_directory_fails_its_test() {
    a_leak_fails_its_test(
        common::Work::new("errorclasses", "leftover"),
        "a process left in a work directory fails its test",
    );
}

#[test]
fn a_process_left_in_a_work_directory_reached_through_a_symlink_fails_its_test() {
    let base = common::Work::new("errorclasses", "symlinked-base");
    let real = base.path("real");
    std::fs::create_dir(&real).expect("creating the real directory");
    let link = base.path("link");
    std::os::unix::fs::symlink(&real, &link).expect("linking to it");
    a_leak_fails_its_test(
        common::Work::under(&link, "errorclasses", "symlinked"),
        "a process left in a work directory reached through a symlink fails its test",
    );
}

#[test]
fn a_process_in_a_sibling_directory_is_not_a_leftover() {
    let work = common::Work::new("errorclasses", "sibling");
    let sibling = PathBuf::from(format!("{}3", work.dir().display()));
    std::fs::create_dir_all(&sibling).expect("creating the sibling");
    let script = common::executable(
        &sibling.join("forever"),
        "[ $# -eq 0 ] && exit 0\nsleep 3600",
    );
    let mut beside = Command::new(&script)
        .arg("beside")
        .current_dir(&sibling)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning the sibling's fixture");
    // Seen at all only once the shell has run its script and started its sleep.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let sleep = loop {
        let child = children_of(beside.id()).first().copied();
        if let Some(pid) = child {
            break Some(pid);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the condition is the sibling shell's child appearing in /proc, which nothing \
                      here can wait on: reading the shell's children between sleeps, up to 5 s, is \
                      the wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let listed = work.leftover_processes();
    chard::error::best_effort(beside.kill());
    chard::error::best_effort(beside.wait());
    if let Some(pid) = sleep {
        chard::error::best_effort(
            Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status(),
        );
    }
    let sleep_gone = sleep.is_none_or(gone_or_killed);
    common::removed(std::fs::remove_dir_all(&sibling), &sibling);
    let listed = match listed {
        Ok(listed) => listed,
        Err(why) => {
            common::capability_gap("a sibling directory's process is not a leftover", &why);
            return;
        }
    };
    let sleep = sleep.expect("the sibling's shell started its sleep within 5s");
    assert!(
        !listed
            .iter()
            .any(|l| l.pid == beside.id() || l.pid == sleep),
        "a process in {} was taken for {}'s: {listed:?}",
        sibling.display(),
        work.dir().display()
    );
    assert!(sleep_gone, "the sibling's sleep {sleep} outlived the test");
}

/// A driver that answers the interrogation `toolchain::detect` makes and nothing more: a
/// version banner, and a macro dump naming gcc so the kind resolves. No compile is
/// reached, because the profile is resolved before any probe is built and the profile
/// this invocation names is unusable without `--flags`.
const SHIM: &str = r#"#!/bin/sh
case " $* " in
  *' --version '*) echo 'shim 1.0' ;;
  *' -dM '*) printf '#define __GNUC__ 14\n#define __GNUC_MINOR__ 2\n#define __GNUC_PATCHLEVEL__ 0\n' ;;
esac
exit 0
"#;

#[test]
fn measure_with_explicit_profile_and_no_flags_is_configuration() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that an explicit profile with no flags is the invocation's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "configuration");
    let cc = work.write("cc", SHIM);
    std::fs::set_permissions(&cc, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
    let output = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&cc)
            .arg("--profile")
            .arg("explicit")
            .arg("--workdir")
            .arg(work.path("w"));
        cmd
    });
    let got = envelope_of(&output);
    assert_eq!(got.code, "CONFIGURATION", "{}", got.message);
    assert!(got.message.contains("--flags"), "{}", got.message);
}

#[test]
fn measure_with_a_cc_the_kernel_cannot_load_is_the_callers_input() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that a --cc the kernel has no loader for is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "noexec");
    let cc = work.write("cc", TEXT);
    std::fs::set_permissions(&cc, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
    let output = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&cc)
            .arg("--workdir")
            .arg(work.path("w"));
        cmd
    });
    let got = envelope_of(&output);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    if cfg!(target_os = "linux") {
        assert!(
            got.message.contains("os error 8"),
            "ENOEXEC reaches the message: {}",
            got.message
        );
    } else {
        common::capability_gap(
            "ENOEXEC from `chard measure --cc` on a shebang-less file",
            "this host runs the file through sh instead of refusing it at exec",
        );
    }
}

/// A socket bound under the work directory, or the announced gap when the host cannot
/// bind one there: a socket path is capped near a hundred bytes, and the temp directory
/// can take most of that.
fn bound_socket(work: &common::Work) -> Option<(std::os::unix::net::UnixListener, PathBuf)> {
    let path = work.path("s");
    match std::os::unix::net::UnixListener::bind(&path) {
        Ok(listener) => Some((listener, path)),
        Err(e) => {
            common::capability_gap(
                "USER_INPUT from a socket handed to `chard table` or `chard matrix`",
                &format!("this host could not bind one at {}: {e}", path.display()),
            );
            None
        }
    }
}

#[test]
fn table_on_a_socket_is_the_callers_input() {
    if !ready("that a socket handed to `chard table` is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "table-socket");
    let Some((_listener, sock)) = bound_socket(&work) else {
        return;
    };
    let got = run(&[OsStr::new("table"), sock.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("it is a socket"), "{}", got.message);
}

#[test]
fn matrix_on_a_socket_is_the_callers_input() {
    if !ready("that a socket handed to `chard matrix` is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "matrix-socket");
    let Some((_listener, sock)) = bound_socket(&work) else {
        return;
    };
    let got = run(&[OsStr::new("matrix"), sock.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("it is a socket"), "{}", got.message);
}

#[test]
fn table_on_a_text_file_is_the_callers_input() {
    if !ready("that a non-JSON file handed to `chard table` is the caller's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "table-text");
    let path = work.write("hosts", TEXT);
    let got = run(&[OsStr::new("table"), path.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.message.contains("hosts") && got.message.contains("JSON"),
        "{}",
        got.message
    );
    assert!(
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains("chard measure -o")),
        "{:?}",
        got.hint
    );
}

/// An ELF object handed to `table` is the fixture the reader's own tests use, and it is
/// not UTF-8: the parser refuses it as JSON, where a `read_to_string` refused it first
/// with `InvalidData`, which the envelope could only report as chard's own.
fn fixture_object() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/elf/elf64-le-x86_64-exec-relro-lazy.elf")
}

#[test]
fn table_on_a_binary_file_is_the_callers_input() {
    if !ready("that an object handed to `chard table` is the caller's to fix") {
        return;
    }
    let path = fixture_object();
    let got = run(&[OsStr::new("table"), path.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.message.contains("relro-lazy.elf") && got.message.contains("JSON"),
        "{}",
        got.message
    );
    assert!(
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains("chard measure -o")),
        "{:?}",
        got.hint
    );
}

#[test]
fn matrix_on_a_binary_file_is_the_callers_input() {
    if !ready("that an object handed to `chard matrix` is the caller's to fix") {
        return;
    }
    let path = fixture_object();
    let got = run(&[OsStr::new("matrix"), path.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.message.contains("relro-lazy.elf") && got.message.contains("JSON"),
        "{}",
        got.message
    );
}

/// A report as chard 0.1.0 wrote one, as far as a reader of this version reads it before
/// refusing: `chard_schema` 1 in the report and in its digest, an observations list,
/// predicates in `chard-predicate/1`, and the `run.decoders_sha256` that release published.
fn a_0_1_0_report() -> Value {
    let release = chard::dataset::PUBLISHED_REPORT_VERSIONS
        .iter()
        .find(|published| published.version == "1")
        .expect("version 1 is a published one");
    serde_json::json!({
        "chard_schema": "1",
        "digest": {"chard_schema": "1"},
        "observations": [],
        "decoders": {"language": "chard-predicate/1"},
        "run": {"decoders_sha256": release.decoders_sha256},
    })
}

#[test]
fn a_report_chard_0_1_0_published_is_refused_naming_that_release() {
    if !ready("that a report at `chard_schema` 1 is refused naming chard 0.1.0") {
        return;
    }
    assert_ne!(chard::report::SCHEMA_VERSION, "1");
    let report = a_0_1_0_report();
    let work = common::Work::new("errorclasses", "sample-0.1.0");
    let path = work.write("as-written.json", &report.to_string());
    let mut later = report.clone();
    later["run"]["decoders_sha256"] = "ab".repeat(32).into();
    let later = work.write("later.json", &later.to_string());
    let mut unnamed = report.clone();
    unnamed["run"]
        .as_object_mut()
        .expect("0.1.0's sample carries a run")
        .remove("decoders_sha256");
    let unnamed = work.write("unnamed.json", &unnamed.to_string());
    let mut relabelled = report.clone();
    relabelled["chard_schema"] = chard::report::SCHEMA_VERSION.into();
    relabelled["digest"]["chard_schema"] = chard::report::SCHEMA_VERSION.into();
    let relabelled = work.write("relabelled.json", &relabelled.to_string());

    let mut read = 0;
    for command in [
        &["table"][..],
        &["matrix"],
        &["digest"],
        &["detect", "fortify-requested", "--evidence"],
    ] {
        for (file, _, _) in [
            (&path, "read this one with chard 0.1.0", "development build"),
            (
                &later,
                "chard 0.1.0 did not write this report as it stands",
                "read this one with chard 0.1.0",
            ),
            (
                &unnamed,
                "carries no `run.decoders_sha256` to say which",
                "read this one with chard 0.1.0",
            ),
        ] {
            let mut args: Vec<&OsStr> = command.iter().map(OsStr::new).collect();
            args.push(file.as_os_str());
            let got = run(&args);
            read += 1;
            assert_eq!(got.code, "USER_INPUT", "{command:?}: {}", got.message);
            assert!(
                got.message.contains("carries `chard_schema` \"1\","),
                "{command:?}: {}",
                got.message
            );
            assert!(got.hint.is_some(), "the refusal carries a hint");
        }
        if command[0] != "detect" {
            let mut args: Vec<&OsStr> = command.iter().map(OsStr::new).collect();
            args.push(relabelled.as_os_str());
            let got = run(&args);
            read += 1;
            assert_eq!(got.code, "USER_INPUT", "{command:?}: {}", got.message);
            assert!(
                got.message
                    .contains("`decoders.language` \"chard-predicate/1\""),
                "{command:?}: {}",
                got.message
            );
        }
    }
    assert_eq!(
        read, 15,
        "three files through four readers, the relabelled one through three"
    );
}

#[test]
fn table_on_an_object_that_is_no_report_is_the_callers_input() {
    if !ready("that a JSON file that is no report handed to `chard table` is the caller's") {
        return;
    }
    let work = common::Work::new("errorclasses", "table-empty");
    // An empty object is refused at the read, for the version it does not carry.
    let empty = work.write("empty.json", "{}");
    let got = run(&[OsStr::new("table"), empty.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("no `chard_schema`"), "{}", got.message);
    // One that carries the version, an empty `observations` list and a digest passes the
    // read and is refused by the renderer for the field it reads.
    let path = work.write(
        "versioned.json",
        &format!(
            r#"{{"chard_schema": "{}", "observations": [], "digest": {{}}}}"#,
            chard::report::SCHEMA_VERSION
        ),
    );
    let got = run(&[OsStr::new("table"), path.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("observations"), "{}", got.message);
    // The defect-keyed table reads a different field, and refuses the same way.
    let got = run(&[
        OsStr::new("table"),
        OsStr::new("--by-defect"),
        path.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("defect_coverage"), "{}", got.message);
}

#[test]
fn matrix_on_an_object_that_is_no_report_is_the_callers_input() {
    if !ready("that a JSON file that is no report handed to `chard matrix` is the caller's") {
        return;
    }
    let work = common::Work::new("errorclasses", "matrix-empty");
    let mut fed = 0;
    for (name, body) in [
        ("empty.json", "{}"),
        ("versioned.json", r#"{"chard_schema": "1", "digest": {}}"#),
    ] {
        let path = work.write(name, body);
        let got = run(&[OsStr::new("matrix"), path.as_os_str()]);
        fed += 1;
        assert_eq!(got.code, "USER_INPUT", "{name}: {}", got.message);
        assert!(
            got.hint
                .as_deref()
                .is_some_and(|h| h.contains("chard measure -o")),
            "{name}: {:?}",
            got.hint
        );
    }
    assert_eq!(fed, 2, "the version refusal and the renderer's");
}

/// The sentence a replacement writes where the two reports read every flag alike.
const ALIKE: &str = "The two read every flag both carry alike, verdict, polarity and gating rule";

#[test]
fn a_repeated_configuration_is_refused_unless_replaced() {
    if !ready("that `chard matrix` refuses a repeated configuration unless replacing") {
        return;
    }
    let work = common::Work::new("errorclasses", "repeated-configuration");
    let first = work.write("first.json", &minimal_report("[]"));
    let again = work.write("again.json", &minimal_report("[]"));
    let got = run(&[OsStr::new("matrix"), first.as_os_str(), again.as_os_str()]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    let (first_name, again_name) = (first.display().to_string(), again.display().to_string());
    assert!(
        got.message
            .contains(&format!("{again_name} repeats {first_name} (")),
        "{}",
        got.message
    );
    assert!(
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains("--replace-repeated")),
        "{:?}",
        got.hint
    );

    let output = output_of(&[
        OsStr::new("matrix"),
        OsStr::new("--replace-repeated"),
        first.as_os_str(),
        again.as_os_str(),
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{text}");
    let matrix: Value = serde_json::from_str(&text).expect("a matrix");
    assert_eq!(matrix["cells"].as_array().map(Vec::len), Some(1), "{text}");
    assert_eq!(matrix["inputs"], 2, "{text}");
    let said = format!("{again_name} repeats the configuration of {first_name} (");
    assert!(
        matrix["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| {
                w.as_str()
                    .is_some_and(|w| w.starts_with(&said) && w.contains(ALIKE))
            })),
        "{text}"
    );
}

#[test]
fn table_refuses_a_repeated_configuration_unless_replaced() {
    if !ready("that `chard table` refuses a repeated configuration unless replacing") {
        return;
    }
    let work = common::Work::new("errorclasses", "table-repeated-configuration");
    let first = work.write("first.json", &minimal_report("[]"));
    let again = work.write("again.json", &minimal_report("[]"));
    let (first_name, again_name) = (first.display().to_string(), again.display().to_string());
    let got = run(&[OsStr::new("table"), first.as_os_str(), again.as_os_str()]);
    assert_eq!(got.operation, "table");
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.message.contains(&format!(
            "{again_name} repeats {first_name} (distro (none), "
        )) && got.message.contains(
            "every axis of its key (distro, release, compiler, compiler_version, libc, \
                     arch, machine, profile, execution, execution_basis, image; libc is the \
                     implementation alone)"
        ),
        "{}",
        got.message
    );
    assert!(
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains("--replace-repeated")),
        "{:?}",
        got.hint
    );

    let output = output_of(&[
        OsStr::new("table"),
        OsStr::new("--width"),
        OsStr::new("0"),
        OsStr::new("--replace-repeated"),
        first.as_os_str(),
        again.as_os_str(),
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{text}");
    let alone = output_of(&[
        OsStr::new("table"),
        OsStr::new("--width"),
        OsStr::new("0"),
        again.as_os_str(),
    ]);
    let alone = String::from_utf8_lossy(&alone.stdout);
    let note =
        format!("!! {again_name} repeats the configuration of {first_name} (distro (none), ");
    let (_, noted) = text.split_once(&note).expect("the replacement is noted");
    assert!(noted.contains(ALIKE), "{text}");
    let grid = |t: &str| t.split_once("\nLegend:").map(|(g, _)| g.to_owned());
    assert_eq!(
        grid(&text),
        grid(&alone),
        "the column is the later report's alone"
    );
    assert_eq!(grid(&text).map(|g| g.matches("bare cc").count()), Some(1));

    // Two reports of one configuration that read `-pie` differently: in either order and
    // either form, the rendered column is the later report's word, where a pool of the two
    // reads `!off/on`, and the note names the flag that moved.
    let on = work.write("on.json", &minimal_report_reading("on", "[]"));
    let off = work.write("off.json", &minimal_report_reading("off", "[]"));
    let mut fed = 0;
    for (earlier, later, word) in [(&on, &off, "--"), (&off, &on, "on")] {
        for form in ["text", "markdown"] {
            let output = output_of(&[
                OsStr::new("table"),
                OsStr::new("--format"),
                OsStr::new(form),
                OsStr::new("--width"),
                OsStr::new("0"),
                OsStr::new("--replace-repeated"),
                earlier.as_os_str(),
                later.as_os_str(),
            ]);
            fed += 1;
            let text = String::from_utf8_lossy(&output.stdout);
            assert_eq!(output.status.code(), Some(0), "{text}");
            let row = text
                .lines()
                .find(|l| l.trim_start_matches(['|', ' ', '`']).starts_with("pie"))
                .unwrap_or_default();
            assert!(
                row.split(['|', ' '])
                    .any(|cell| cell.trim_matches('`') == word)
                    && !row.contains("!off/on"),
                "{form}, {} later: {row}\n{text}",
                later.display()
            );
            let moved = format!(
                "`-pie` {} in {} and {} in {}",
                if word == "on" { "off" } else { "on" },
                earlier.display(),
                if word == "on" { "on" } else { "off" },
                later.display()
            );
            let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(flat.contains(&moved), "{form}: {moved}\n{text}");
        }
    }
    assert_eq!(fed, 4, "both orders in both forms");
}

/// The smallest document `table` and `matrix` render: one observation, the `coverage`
/// tally of it, and its `consistency` block, with `contradictions` as given.
fn minimal_report(contradictions: &str) -> String {
    minimal_report_reading("on", contradictions)
}

/// [`minimal_report`] with its one observation reading `verdict`, a measured one.
fn minimal_report_reading(verdict: &str, contradictions: &str) -> String {
    published(serde_json::from_str(&format!(
        r#"{{"environment": {{"kernel": {{"is_host_kernel": false, "ownership": "unsettled"}}, "execution": {{"mode": "host", "mode_evidence": {{"basis": "assumed-host"}}}}}},
"observations": [{{"check": "pie", "flag": "-pie", "verdict": "{verdict}"}}],
"coverage": {{"checks_attempted": 1, "corpus_checks_total": 1, "verdict_counts": {{"{verdict}": 1}}, "all_verdicts_published": true,
 "withholding": {{"published": 1, "earned_limitations": {{"count": 0, "no_named_cause": 0}}, "instrument_withholdings": {{"count": 0, "no_named_cause": 0}}}}}},
"composites": [], "consistency": {{"contradictions": {contradictions}}}}}"#
    )).expect("the minimal report is JSON"))
}

/// `report` as `measure` publishes it, as far as a reader holds it before any rule: at the
/// `chard_schema` this chard writes, with the fields the digest is made from filled where the
/// hand-built document leaves them out (the run's identity, the toolchain and profile, the
/// coverage the tally does not need, each observation's polarity, `observes`, channel and
/// evidence), and
/// the digest derived from the document as it stands, after any edit, so that the rule an
/// edit breaks is the one the reader names. Every reader refuses a report of another version or
/// without a digest before any rule runs; a key the document carries is
/// kept, a published report's digest among them.
fn published(report: Value) -> String {
    serde_json::to_string(&publish(report)).expect("json")
}

/// [`published`] as a value, for an edit made after publication: one to a field the digest
/// is made from, which the reader's re-run of the digest rule is then to name.
fn publish(mut report: Value) -> Value {
    use serde_json::json;
    fn fill(at: &mut Value, key: &str, value: Value) {
        if let Some(map) = at.as_object_mut() {
            map.entry(key).or_insert(value);
        }
    }
    let unmeasured = "0".repeat(64);
    fill(
        &mut report,
        "chard_schema",
        json!(chard::report::SCHEMA_VERSION),
    );
    fill(
        &mut report,
        "run",
        json!({"id": "hand-built", "harness_version": chard::report::HARNESS_VERSION,
               "probe_corpus_sha256": unmeasured, "decoders_sha256": unmeasured}),
    );
    fill(&mut report, "toolchain", json!({"id": "hand-built"}));
    fill(
        &mut report,
        "profile",
        json!({"id": "bare", "flags_source": "none", "cflags": []}),
    );
    // The triples that discriminated, as `measure` counts them: held on read to each
    // observation's `controls.discriminating`, which a hand-built observation leaves out.
    let valid = report
        .get("observations")
        .and_then(Value::as_array)
        .map_or(0, |observations| {
            observations
                .iter()
                .filter(|o| o["controls"]["discriminating"].as_bool() == Some(true))
                .count()
        });
    if let Some(coverage) = report.get_mut("coverage") {
        let attempted = coverage["checks_attempted"].clone();
        fill(coverage, "checks_expected", attempted);
        fill(coverage, "checks_valid", json!(valid));
        fill(coverage, "all_checks_attempted", json!(true));
    }
    if let Some(observations) = report.get_mut("observations").and_then(Value::as_array_mut) {
        for observation in observations {
            fill(observation, "polarity", json!("harden"));
            fill(observation, "observes", json!("protection"));
            fill(observation, "channel", json!("elf-static"));
            fill(observation, "evidence", json!({}));
        }
    }
    if report.get("digest").is_none() {
        // The status word `measure` writes beside the list, with the rule it applied: the
        // digest is held to the word, and a word beside no rule is refused on its own.
        let consistency = &mut report["consistency"];
        let listed = consistency["contradictions"].as_array().map_or(0, Vec::len);
        let derived = if listed == 0 {
            "consistent"
        } else {
            "contradicted"
        };
        fill(consistency, "status", json!(derived));
        fill(
            consistency,
            "rules_applied",
            json!(["digest-disagrees-with-report"]),
        );
        let status = consistency["status"].as_str().unwrap_or(derived).to_owned();
        let digest = chard::report::digest::derive(&report, &status)
            .expect("a hand-built report the digest can be made from");
        fill(
            &mut report,
            "digest",
            serde_json::to_value(digest).expect("the digest serializes"),
        );
    }
    report
}

#[test]
fn a_report_without_observes_is_refused_by_every_reader() {
    if !ready("that every reader refuses a report without observes") {
        return;
    }
    let work = common::Work::new("errorclasses", "no-observes");
    let honest: Value = serde_json::from_str(&minimal_report("[]")).expect("JSON");
    assert_ne!(
        honest["run"]["probe_corpus_sha256"],
        chard::probe::corpus_sha256(),
        "the hand-built report is of another corpus"
    );
    let mut older = honest.clone();
    older["observations"][0]
        .as_object_mut()
        .expect("an observation")
        .remove("observes");
    let digest = chard::report::digest::derive(&older, "consistent").expect("derives");
    older["digest"] = serde_json::to_value(digest).expect("the digest serializes");
    let mut read = 0;
    for (name, report, refused) in [("honest", &honest, false), ("older", &older, true)] {
        let path = work.write(&format!("{name}.json"), &report.to_string());
        for command in ["table", "matrix", "digest"] {
            let output = output_of(&[OsStr::new(command), path.as_os_str()]);
            read += 1;
            if refused {
                let got = envelope_of(&output);
                assert_eq!(got.code, "USER_INPUT", "{name} {command}: {}", got.message);
                assert!(
                    got.message.contains("its observations carry no `observes`"),
                    "{name} {command}: {}",
                    got.message
                );
                let hint = got.hint.unwrap_or_default();
                assert!(
                    hint.contains("in a shape this revision does not write")
                        && hint.contains("read it with the chard its `run.harness_revision` names")
                        && hint.contains("run `chard measure` again with this build")
                        && !hint.contains("bug report"),
                    "{name} {command}: {hint}"
                );
            } else {
                assert_eq!(
                    output.status.code(),
                    Some(0),
                    "{name} {command}: {output:?}"
                );
            }
        }
    }
    assert_eq!(read, 6, "two reports through three readers");
}

/// A report `chard measure` writes here under `bare` with `cc`, with `args` added: a report of
/// this corpus, whose `run.invocation` is the one this test gave.
fn measured_here(work: &common::Work, name: &str, args: &[&str]) -> Value {
    let path = work.path(name);
    let output = Command::new(chard_binary())
        .args(["measure", "--profile", "bare", "-o"])
        .arg(&path)
        .args(args)
        .output()
        .expect("spawning chard measure");
    assert_eq!(
        output.status.code(),
        Some(0),
        "measure {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the report reads"))
            .expect("the report is JSON");
    assert_eq!(
        report["run"]["probe_corpus_sha256"],
        chard::probe::corpus_sha256(),
        "the measured report is of this corpus"
    );
    report
}

/// `report` with its digest made again over the document as it stands, as a forger who edits
/// the fields under it would make it.
fn redigested(mut report: Value) -> Value {
    let status = report["consistency"]["status"]
        .as_str()
        .expect("a measured report has a status")
        .to_owned();
    let digest = chard::report::digest::derive(&report, &status).expect("the digest derives");
    report["digest"] = serde_json::to_value(digest).expect("the digest serializes");
    report
}

/// An observation of `report` that no block but the observation list and the digest names,
/// bearing no defect, measured `on` or `off` with no gating, and whose triple discriminated:
/// one a forger can delete or copy with `coverage` alone moved to match. Its id is returned
/// beside its index.
fn self_contained(report: &Value, besides: &[&str]) -> (usize, String) {
    let mut rest = report.clone();
    let rest = rest.as_object_mut().expect("a report");
    rest.remove("observations");
    rest.remove("digest");
    let elsewhere = Value::Object(rest.clone()).to_string();
    report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .enumerate()
        .find_map(|(i, o)| {
            let id = o["check"].as_str()?;
            let measured = matches!(o["verdict"].as_str(), Some("on" | "off"));
            let bare = o.get("defects").is_none() && o.get("gating").is_none();
            let valid = o["controls"]["discriminating"].as_bool() == Some(true);
            let unnamed = !elsewhere.contains(&format!("\"{id}\""));
            (measured && bare && valid && unnamed && !besides.contains(&id))
                .then(|| (i, id.to_owned()))
        })
        .expect("the corpus has a self-contained check measured here")
}

/// `coverage` moved by `by` observations measured `verdict` with a triple that discriminated:
/// the counts, the tally and the published set, as `measure` would have counted them.
fn shift_coverage(report: &mut Value, verdict: &str, by: i64) {
    let coverage = &mut report["coverage"];
    for key in ["checks_attempted", "checks_expected", "checks_valid"] {
        let n = coverage[key].as_i64().expect("a count");
        coverage[key] = (n + by).into();
    }
    let tally = coverage["verdict_counts"][verdict].as_i64().unwrap_or(0);
    coverage["verdict_counts"][verdict] = (tally + by).into();
    let published = coverage["withholding"]["published"]
        .as_i64()
        .expect("a count");
    coverage["withholding"]["published"] = (published + by).into();
}

/// `whole` with a defect taken from one observation and given to another reading alike in
/// protection terms, the rollup's bearing checks rewritten, so its counts and status stand.
fn defect_moved(whole: &Value) -> Value {
    let mut report = whole.clone();
    let observations = report["observations"].as_array().expect("observations");
    let term = |o: &Value| {
        (
            o["verdict"].as_str().map(str::to_owned),
            o["polarity"].as_str().map(str::to_owned),
            o["observes"].as_str().map(str::to_owned),
        )
    };
    let (from, to, defect) = observations
        .iter()
        .enumerate()
        .find_map(|(i, o)| {
            let defect = o["defects"].as_array()?.first()?.as_str()?.to_owned();
            let j = observations.iter().position(|other| {
                other["check"] != o["check"]
                    && term(other) == term(o)
                    && !other["defects"]
                        .as_array()
                        .is_some_and(|d| d.iter().any(|x| x == defect.as_str()))
            })?;
            Some((i, j, defect))
        })
        .expect("two observations reading alike, one declaring a defect the other does not");
    let from_id = report["observations"][from]["check"].clone();
    let to_id = report["observations"][to]["check"].clone();
    let declared = report["observations"][from]["defects"]
        .as_array_mut()
        .expect("defects");
    declared.retain(|d| d != defect.as_str());
    if declared.is_empty() {
        report["observations"][from]
            .as_object_mut()
            .expect("an observation")
            .remove("defects");
    }
    let target = report["observations"][to]
        .as_object_mut()
        .expect("an observation");
    let defects = target
        .entry("defects")
        .or_insert_with(|| Value::Array(Vec::new()));
    defects
        .as_array_mut()
        .expect("defects")
        .push(defect.as_str().into());
    // The bearing checks in observation order, as `defect_coverage` lists them.
    let bearing: Vec<Value> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| {
            o["defects"]
                .as_array()
                .is_some_and(|d| d.iter().any(|x| x == defect.as_str()))
        })
        .map(|o| o["check"].clone())
        .collect();
    assert!(bearing.contains(&to_id) && !bearing.contains(&from_id));
    report["defect_coverage"][&defect]["from_checks"] = Value::Array(bearing);
    report
}

/// `whole` with the flag of observation `kept` exchanged with that of one reading otherwise.
fn flags_exchanged(whole: &Value, kept: usize) -> Value {
    let mut report = whole.clone();
    let observations = report["observations"].as_array().expect("observations");
    let other = observations
        .iter()
        .position(|o| o["verdict"] != observations[kept]["verdict"])
        .expect("an observation reading otherwise");
    let a = report["observations"][kept]["flag"].clone();
    let b = report["observations"][other]["flag"].clone();
    report["observations"][kept]["flag"] = b;
    report["observations"][other]["flag"] = a;
    report
}

/// One edit of [`a_report_of_this_corpus_is_held_to_the_corpus_on_read`]: its name, its rule,
/// the claim of the statement it breaks, the unedited report and the edited one.
type ThisCorpusEdit = (&'static str, &'static str, String, Value, Value);

/// The ten edits of [`a_report_of_this_corpus_is_held_to_the_corpus_on_read`], over `whole`
/// (a run of the whole corpus) and `narrowed` (a run of `probe` alone, which holds the check at
/// `kept`), with `added` the index in `whole` of a check outside `probe`.
fn this_corpus_edits(
    whole: &Value,
    narrowed: &Value,
    probe: &str,
    (kept, kept_id): (usize, &str),
    (added, added_id): (usize, &str),
) -> Vec<ThisCorpusEdit> {
    const COVERAGE: &str = "coverage-disagrees-with-observations";
    const DEFECT: &str = "defect-status-disagrees-with-bearing-checks";
    let kept_verdict = whole["observations"][kept]["verdict"]
        .as_str()
        .expect("a verdict")
        .to_owned();

    let mut edited: Vec<ThisCorpusEdit> = Vec::new();
    edited.push((
        "defect-moved",
        DEFECT,
        "].defects = ".to_owned(),
        whole.clone(),
        defect_moved(whole),
    ));
    {
        let mut report = whole.clone();
        report["observations"]
            .as_array_mut()
            .expect("observations")
            .remove(kept);
        shift_coverage(&mut report, &kept_verdict, -1);
        report["coverage"]["all_checks_attempted"] = false.into();
        report["coverage"]["all_verdicts_published"] = false.into();
        edited.push((
            "observation-deleted",
            COVERAGE,
            format!("no observation carries {kept_id}, and coverage.checks_missing omits it"),
            whole.clone(),
            report,
        ));
    }
    {
        let mut report = whole.clone();
        let copy = report["observations"][kept].clone();
        report["observations"]
            .as_array_mut()
            .expect("observations")
            .push(copy);
        shift_coverage(&mut report, &kept_verdict, 1);
        edited.push((
            "observation-repeated",
            COVERAGE,
            format!("repeated: {kept_id} x2"),
            whole.clone(),
            report,
        ));
    }
    {
        let mut report = whole.clone();
        report["run"]
            .as_object_mut()
            .expect("run")
            .remove("invocation");
        edited.push((
            "invocation-removed",
            COVERAGE,
            "run.invocation is absent".to_owned(),
            whole.clone(),
            report,
        ));
    }
    edited.extend(narrowed_edits(whole, narrowed, probe, (added, added_id)));
    {
        let mut report = whole.clone();
        let written = report["observations"][kept]["channel"].clone();
        let other = if written == "runtime" {
            "elf-static"
        } else {
            "runtime"
        };
        report["observations"][kept]["channel"] = other.into();
        edited.push((
            "channel-edited",
            COVERAGE,
            format!("observations[{kept_id}].channel = {other}"),
            whole.clone(),
            report,
        ));
    }
    edited.push((
        "flags-exchanged",
        COVERAGE,
        "].flag = ".to_owned(),
        whole.clone(),
        flags_exchanged(whole, kept),
    ));

    edited
}

/// The four edits of [`this_corpus_edits`] made to the narrowed run: an observation of the
/// check at `added` in `whole` added, unnamed and named unexpected, the total lowered, and the
/// `--probe` value replaced.
fn narrowed_edits(
    whole: &Value,
    narrowed: &Value,
    probe: &str,
    (added, added_id): (usize, &str),
) -> Vec<ThisCorpusEdit> {
    const COVERAGE: &str = "coverage-disagrees-with-observations";
    let added_report = |named: bool| {
        let mut report = narrowed.clone();
        let observation = whole["observations"][added].clone();
        let verdict = observation["verdict"]
            .as_str()
            .expect("a verdict")
            .to_owned();
        report["observations"]
            .as_array_mut()
            .expect("observations")
            .push(observation);
        shift_coverage(&mut report, &verdict, 1);
        if named {
            report["coverage"]["checks_unexpected"] = serde_json::json!([added_id]);
        }
        report
    };
    let mut edited: Vec<ThisCorpusEdit> = Vec::new();
    edited.push((
        "observation-added",
        COVERAGE,
        format!("run.invocation does not select {added_id}"),
        narrowed.clone(),
        added_report(false),
    ));
    edited.push((
        "added-named-unexpected",
        COVERAGE,
        format!("coverage.checks_unexpected names {added_id}"),
        narrowed.clone(),
        added_report(true),
    ));
    {
        let mut report = narrowed.clone();
        report["coverage"]["corpus_checks_total"] = report["coverage"]["checks_expected"].clone();
        report["coverage"]["all_checks_attempted"] = true.into();
        report["coverage"]["all_verdicts_published"] = true.into();
        edited.push((
            "total-lowered",
            COVERAGE,
            "coverage.corpus_checks_total = ".to_owned(),
            narrowed.clone(),
            report,
        ));
    }
    {
        let mut report = narrowed.clone();
        let invocation = report["run"]["invocation"]
            .as_array_mut()
            .expect("an invocation");
        let at = invocation
            .iter()
            .position(|w| w == probe)
            .expect("the --probe value");
        invocation[at] = "no-such-probe".into();
        edited.push((
            "probe-unknown",
            COVERAGE,
            "this corpus has no such probe".to_owned(),
            narrowed.clone(),
            report,
        ));
    }
    edited
}

#[test]
fn a_report_of_this_corpus_is_held_to_the_corpus_on_read() {
    if !ready("that a report of this corpus is held to the corpus on read")
        || !common::require_cc("that a report of this corpus is held to the corpus on read")
    {
        return;
    }
    let work = common::Work::new("errorclasses", "this-corpus");
    let whole = measured_here(&work, "whole.json", &[]);
    let (kept, kept_id) = self_contained(&whole, &[]);
    let probe = chard::probe::CORPUS
        .iter()
        .find(|p| p.checks.iter().any(|c| c.id == kept_id))
        .expect("the check's probe");
    assert_eq!(probe.checks.len(), 1, "{kept_id}'s probe holds it alone");
    let narrowed = measured_here(&work, "narrowed.json", &["--probe", probe.id]);
    let (added, added_id) = self_contained(&whole, &[&kept_id]);
    assert!(
        probe.checks.iter().all(|c| c.id != added_id),
        "{added_id} is outside the narrowed run's selection"
    );
    let edited = this_corpus_edits(
        &whole,
        &narrowed,
        probe.id,
        (kept, &kept_id),
        (added, &added_id),
    );
    let mut fed = 0;
    for (name, rule, claim, honest, report) in &edited {
        assert_ne!(honest, report, "{name} edits the document");
        let honest_path = work.write(&format!("{name}-honest.json"), &honest.to_string());
        let file = format!("{name}.json");
        let path = work.write(&file, &redigested(report.clone()).to_string());
        for command in ["table", "matrix", "digest"] {
            let control = output_of(&[OsStr::new(command), honest_path.as_os_str()]);
            assert_eq!(
                control.status.code(),
                Some(0),
                "{name} {command} over the unedited report: {control:?}"
            );
            let got = envelope_of(&output_of(&[OsStr::new(command), path.as_os_str()]));
            fed += 1;
            assert_eq!(got.code, "USER_INPUT", "{name} {command}: {}", got.message);
            assert!(
                got.message.contains(&file)
                    && got.message.contains(rule)
                    && got.message.contains(claim.as_str()),
                "{name} {command}: the refusal names the report, the rule and `{claim}`: {}",
                got.message
            );
        }
    }
    assert_eq!(fed, 30, "ten edits through three readers");
}

#[test]
fn every_reader_refuses_another_version_and_a_missing_digest_without_a_compiler() {
    if !ready("that every reader refuses another chard_schema and a missing digest") {
        return;
    }
    let work = common::Work::new("errorclasses", "schema-and-digest");
    let honest: Value = serde_json::from_str(&minimal_report("[]")).expect("JSON");
    let path = work.write("honest.json", &honest.to_string());
    let mut read = 0;
    for command in ["table", "matrix", "digest"] {
        let output = output_of(&[OsStr::new(command), path.as_os_str()]);
        read += 1;
        assert_eq!(output.status.code(), Some(0), "{command}: {output:?}");
    }
    assert_eq!(read, 3, "the control through three readers");

    let reads = format!("`chard_schema` \"{}\"", chard::report::SCHEMA_VERSION);
    let shapes: [(&str, Edit, &str); 3] = [
        (
            "v99",
            |r| r["chard_schema"] = "99".into(),
            "carries `chard_schema` \"99\"",
        ),
        (
            "absent",
            |r| {
                r.as_object_mut().expect("object").remove("chard_schema");
            },
            "carries no `chard_schema`",
        ),
        (
            "object-no-observations",
            |r| {
                r["chard_schema"] = serde_json::json!({});
                r.as_object_mut().expect("object").remove("observations");
            },
            "carries `chard_schema` {}",
        ),
    ];
    let mut refused = 0;
    for (name, edit, carries) in shapes {
        let mut forged = honest.clone();
        edit(&mut forged);
        let path = work.write(&format!("{name}.json"), &forged.to_string());
        for args in [
            &["table"][..],
            &["matrix"][..],
            &["digest"][..],
            &["detect", "pie", "--evidence"][..],
        ] {
            let mut all: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
            all.push(path.as_os_str());
            let got = run(&all);
            refused += 1;
            assert_eq!(got.code, "USER_INPUT", "{name} {args:?}: {}", got.message);
            assert!(
                got.message.contains(carries) && got.message.contains(&reads),
                "{name} {args:?}: {}",
                got.message
            );
        }
    }
    assert_eq!(refused, 12, "three shapes through four readers");

    let mut older = honest.clone();
    older.as_object_mut().expect("object").remove("digest");
    let path = work.write("no-digest.json", &older.to_string());
    let mut kept = 0;
    for command in ["table", "matrix", "digest"] {
        let earlier = work.write(&format!("{command}.out"), "an earlier output\n");
        let got = run(&[
            OsStr::new(command),
            OsStr::new("-o"),
            earlier.as_os_str(),
            path.as_os_str(),
        ]);
        kept += 1;
        assert!(
            got.message.contains("carries no `digest`"),
            "{command}: {}",
            got.message
        );
        assert_eq!(
            std::fs::read_to_string(&earlier).expect("the earlier output"),
            "an earlier output\n",
            "{command}"
        );
        assert!(
            !work.path(&format!("{command}.out.previous")).exists(),
            "{command} set the earlier output aside"
        );
    }
    assert_eq!(kept, 3, "three readers given an earlier output");
}

#[test]
fn a_matrix_handed_to_table_is_not_a_report_and_not_a_lost_digest() {
    if !ready("that a matrix handed to `table` is named as not a report") {
        return;
    }
    let work = common::Work::new("errorclasses", "matrix-to-table");
    let report = work.write("report.json", &minimal_report("[]"));
    let matrix = work.path("matrix.json");
    let made = output_of(&[
        OsStr::new("matrix"),
        OsStr::new("-o"),
        matrix.as_os_str(),
        report.as_os_str(),
    ]);
    assert_eq!(made.status.code(), Some(0), "{made:?}");
    let got = run(&[OsStr::new("table"), matrix.as_os_str()]);
    assert!(
        got.message.contains("is not a chard measurement report")
            && !got.message.contains("`digest`"),
        "a matrix is named as not a report: {}",
        got.message
    );
}

/// The `environment` a run on the default writes, as far as the reread's kernel rule reads it.
fn environment_on_the_default() -> Value {
    serde_json::json!({
        "kernel": {"is_host_kernel": false, "ownership": "unsettled"},
        "execution": {"mode": "host", "mode_evidence": {"basis": "assumed-host"}},
    })
}

/// One contradiction for [`minimal_report`]: a report that parses and is refused on its
/// content, after the earlier output is set aside, where a missing path is refused before.
const CONTRADICTION: &str = r#"[{"rule": "r", "property": "p", "claims": [], "detail": "d"}]"#;

#[test]
fn table_and_matrix_refuse_a_report_that_contradicts_itself() {
    if !ready("that `table` and `matrix` refuse a report that contradicts itself") {
        return;
    }
    let work = common::Work::new("errorclasses", "contradicted-content");
    let clean = work.write("clean.json", &minimal_report("[]"));
    let flagged = work.write(
        "flagged.json",
        &minimal_report(r#"[{"rule": "r", "property": "p", "claims": [], "detail": "d"}]"#),
    );
    // The control: the same document with an empty list renders, so the refusal below
    // is the contradiction's and not the fixture's shape.
    for command in ["table", "matrix"] {
        let output = output_of(&[OsStr::new(command), clean.as_os_str()]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command} over a consistent report: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let mut fed = 0;
    for (command, reversed) in [
        ("table", false),
        ("table", true),
        ("matrix", false),
        ("matrix", true),
    ] {
        let out = work.path(&format!("{command}-{reversed}.out"));
        // The two are one configuration, which `matrix` and `table` refuse
        // before they read a contradiction; replacing the repeat, each still refuses the
        // contradiction, whichever of the two the cell or column keeps.
        let mut args = vec![OsStr::new(command), OsStr::new("--replace-repeated")];
        let (first, second) = if reversed {
            (&flagged, &clean)
        } else {
            (&clean, &flagged)
        };
        args.extend([
            OsStr::new("-o"),
            out.as_os_str(),
            first.as_os_str(),
            second.as_os_str(),
        ]);
        let got = run(&args);
        fed += 1;
        assert_eq!(got.operation, command);
        assert_eq!(got.code, "USER_INPUT", "{}", got.message);
        assert!(
            got.message.contains("flagged.json") && got.message.contains("1 contradiction"),
            "the refusal names the report and what it says of itself: {}",
            got.message
        );
        assert!(
            !out.exists(),
            "{command} wrote {} over a refused set",
            out.display()
        );
    }
    assert_eq!(fed, 4, "both renderers were exercised, each in both orders");
}

/// A document whose derived fields agree with its observations under the four rules
/// `table` and `matrix` re-run on read: `fortify-effective` at level 2 beside the four
/// rungs of glibc's level 2 and a ratchet deriving 2 from them, one defect class borne by
/// an `on` and an `off` and so `partial`, one withheld check, and a `coverage` tally of
/// the six verdicts.
fn derived_report() -> Value {
    serde_json::json!({
        "environment": environment_on_the_default(),
        "observations": [
            {"check": "fortify-effective", "flag": "-D_FORTIFY_SOURCE", "verdict": "on",
             "level": "2", "defects": ["heap-buffer-overflow"]},
            {"check": "fortify-enforced-known", "flag": "-D_FORTIFY_SOURCE=1",
             "verdict": "on"},
            {"check": "fortify-level-ge-2-subobject", "flag": "-D_FORTIFY_SOURCE=2",
             "verdict": "on"},
            {"check": "fortify-level-ge-2-percent-n", "flag": "-D_FORTIFY_SOURCE=2",
             "verdict": "on"},
            {"check": "fortify-enforced-dynamic", "flag": "-D_FORTIFY_SOURCE=3",
             "verdict": "off", "defects": ["heap-buffer-overflow"]},
            {"check": "pie", "flag": "-pie", "verdict": "probe-invalid"},
        ],
        "fortify_ratchet": {"implied_level": "2", "whole_object_level": "2",
                            "dynamic_bounds": false,
                            "rungs": [
                                {"check": "fortify-enforced-known", "fires_at_level": "1",
                                 "verdict": "on"},
                                {"check": "fortify-level-ge-2-subobject",
                                 "fires_at_level": "2", "verdict": "on"},
                                {"check": "fortify-level-ge-2-percent-n",
                                 "fires_at_level": "2", "verdict": "on"},
                                {"check": "fortify-enforced-dynamic", "fires_at_level": "3",
                                 "verdict": "off"},
                            ],
                            "monotone": true, "implementation": "glibc"},
        "defect_coverage": {"heap-buffer-overflow": {
            "defect": {"id": "heap-buffer-overflow", "summary": "s"},
            "status": "partial", "complete": true,
            "from_checks": ["fortify-effective", "fortify-enforced-dynamic"],
            "verdict_counts": {"on": 1, "off": 1}}},
        "coverage": {"checks_attempted": 6, "corpus_checks_total": 6,
                     "verdict_counts": {"on": 4, "off": 1, "probe-invalid": 1},
                     "all_verdicts_published": false,
                     "withholding": {"published": 5,
                                     "earned_limitations": {"count": 0, "no_named_cause": 0},
                                     "instrument_withholdings": {
                                         "count": 1, "by_verdict": {"probe-invalid": 1},
                                         "no_named_cause": 1}}},
        "composites": [],
        "consistency": {"contradictions": []},
    })
}

/// One hand edit to a report document.
type Edit = fn(&mut Value);

/// The three renderings a derived field reaches a reader through.
const RENDERINGS: [&[&str]; 3] = [&["table"], &["table", "--by-defect"], &["matrix"]];

fn render(args: &[&str], path: &Path) -> std::process::Output {
    let mut all: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    all.push(path.as_os_str());
    output_of(&all)
}

#[test]
fn table_and_matrix_refuse_a_derived_field_edited_alone() {
    if !ready("that `table` and `matrix` re-run the derived-field rules on read") {
        return;
    }
    let work = common::Work::new("errorclasses", "derived-edit");
    let honest = work.write("honest.json", &published(derived_report()));
    // The control: the document unedited renders through every rendering, so each
    // refusal below is the edit's and not the fixture's shape.
    for args in RENDERINGS {
        let output = render(args, &honest);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?} over the honest document: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let edits: [(&str, &str, Edit); 4] = [
        (
            "status",
            "defect-status-disagrees-with-bearing-checks",
            |r| r["defect_coverage"]["heap-buffer-overflow"]["status"] = "mitigated".into(),
        ),
        ("level", "derived-fortify-level-exceeds-measured", |r| {
            r["fortify_ratchet"]["implied_level"] = "3".into();
        }),
        ("axes", "dynamic-bounds-without-whole-object-bounds", |r| {
            r["fortify_ratchet"]["dynamic_bounds"] = true.into();
            r["fortify_ratchet"]["whole_object_level"] = "0".into();
        }),
        (
            "withholding",
            "withholding-disagrees-with-verdict-counts",
            |r| r["coverage"]["withholding"]["published"] = 3.into(),
        ),
    ];
    let mut fed = 0;
    for (name, rule, edit) in edits {
        let mut report = derived_report();
        edit(&mut report);
        let file = format!("{name}.json");
        let path = work.write(&file, &published(report.clone()));
        for args in RENDERINGS {
            let output = render(args, &path);
            fed += 1;
            let got = envelope_of(&output);
            assert_eq!(got.code, "USER_INPUT", "{name} {args:?}: {}", got.message);
            assert!(
                got.message.contains(&file) && got.message.contains(rule),
                "{name} {args:?}: the refusal names the report and the rule: {}",
                got.message
            );
        }
    }
    assert_eq!(fed, 12, "four edits through three renderings");
}

#[test]
fn table_and_matrix_refuse_the_derived_edits_the_first_reread_passed() {
    const LEVEL: &str = "derived-fortify-level-exceeds-measured";
    const DEFECT: &str = "defect-status-disagrees-with-bearing-checks";
    const WITHHOLDING: &str = "withholding-disagrees-with-verdict-counts";
    if !ready("that `table` and `matrix` refuse the derived edits the first re-read passed") {
        return;
    }
    let work = common::Work::new("errorclasses", "derived-holes");
    let honest = work.write("honest.json", &published(derived_report()));
    for args in RENDERINGS {
        let output = render(args, &honest);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?} over the honest document: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let edits: [(&str, &str, Edit); 11] = [
        ("level-word", LEVEL, |r| {
            r["fortify_ratchet"]["implied_level"] = "two".into();
        }),
        ("level-lowered", LEVEL, |r| {
            r["fortify_ratchet"]["implied_level"] = "1".into();
        }),
        ("level-and-axis-lowered", LEVEL, |r| {
            r["fortify_ratchet"]["implied_level"] = "1".into();
            r["fortify_ratchet"]["whole_object_level"] = "1".into();
        }),
        ("ratchet-deleted", LEVEL, |r| {
            r.as_object_mut()
                .expect("a report")
                .remove("fortify_ratchet");
        }),
        ("rung-deleted", LEVEL, |r| {
            r["fortify_ratchet"]["rungs"]
                .as_array_mut()
                .expect("rungs")
                .remove(3);
        }),
        ("defect-entry-deleted", DEFECT, |r| {
            r["defect_coverage"] = serde_json::json!({});
        }),
        ("defect-check-deleted", DEFECT, |r| {
            let entry = &mut r["defect_coverage"]["heap-buffer-overflow"];
            entry["from_checks"] = serde_json::json!(["fortify-effective"]);
            entry["verdict_counts"] = serde_json::json!({"on": 1});
            entry["status"] = "mitigated".into();
        }),
        ("by-verdict-relabelled", WITHHOLDING, |r| {
            r["coverage"]["withholding"]["instrument_withholdings"]["by_verdict"] =
                serde_json::json!({"indeterminate": 1});
        }),
        ("verdict-counts-unknown-key", WITHHOLDING, |r| {
            r["coverage"]["verdict_counts"]["mitigated-probably"] = 2.into();
        }),
        ("effective-level-word", LEVEL, |r| {
            r["observations"][0]["level"] = "two".into();
        }),
        // `complete` edited apart from its counts, everything else as written.
        ("defect-complete-flipped", DEFECT, |r| {
            let entry = &mut r["defect_coverage"]["heap-buffer-overflow"];
            let was = entry["complete"].as_bool().expect("a published complete");
            entry["complete"] = (!was).into();
        }),
    ];
    let mut fed = 0;
    for (name, rule, edit) in edits {
        let mut report = derived_report();
        edit(&mut report);
        assert_ne!(report, derived_report(), "{name} edits the document");
        let file = format!("{name}.json");
        let path = work.write(&file, &published(report.clone()));
        for args in RENDERINGS {
            let output = render(args, &path);
            fed += 1;
            let got = envelope_of(&output);
            assert_eq!(got.code, "USER_INPUT", "{name} {args:?}: {}", got.message);
            assert!(
                got.message.contains(&file) && got.message.contains(rule),
                "{name} {args:?}: the refusal names the report and the rule: {}",
                got.message
            );
        }
    }
    assert_eq!(fed, 33, "eleven edits through three renderings");
    // `digest` re-reads too: the `complete` edit, refused there.
    let flipped = work.path("defect-complete-flipped.json");
    let got = envelope_of(&render(&["digest"], &flipped));
    assert_eq!(got.code, "USER_INPUT", "digest: {}", got.message);
    assert!(
        got.message.contains(DEFECT) && got.message.contains(".complete ="),
        "digest: {}",
        got.message
    );
}

#[test]
fn table_and_matrix_refuse_a_tally_relabelled_with_its_sum_kept() {
    const COVERAGE: &str = "coverage-disagrees-with-observations";
    const DEFECT: &str = "defect-status-disagrees-with-bearing-checks";
    if !ready("that `table` and `matrix` refuse a tally relabelled with its sum kept") {
        return;
    }
    let work = common::Work::new("errorclasses", "tally-relabelled");
    let honest = work.write("honest.json", &published(derived_report()));
    for args in RENDERINGS {
        let output = render(args, &honest);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?} over the honest document: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let edits: [(&str, &str, Edit); 4] = [
        ("tally-off-to-on", COVERAGE, |r| {
            r["coverage"]["verdict_counts"] = serde_json::json!({"on": 5, "probe-invalid": 1});
        }),
        // With the withholding block moved to match, so only the recount sees it.
        ("tally-withheld-to-on", COVERAGE, |r| {
            r["coverage"]["verdict_counts"] = serde_json::json!({"on": 5, "off": 1});
            r["coverage"]["withholding"] = serde_json::json!({"published": 6,
                "earned_limitations": {"count": 0, "no_named_cause": 0}, "instrument_withholdings": {"count": 0, "no_named_cause": 0}});
            r["coverage"]["all_verdicts_published"] = true.into();
        }),
        ("rollup-off-to-withheld", DEFECT, |r| {
            r["defect_coverage"]["heap-buffer-overflow"]["verdict_counts"] =
                serde_json::json!({"on": 1, "indeterminate": 1});
        }),
        ("rollup-on-off-exchanged", DEFECT, |r| {
            let entry = &mut r["defect_coverage"]["heap-buffer-overflow"];
            entry["verdict_counts"] = serde_json::json!({"on": 2});
            entry["status"] = "mitigated".into();
        }),
    ];
    let mut fed = 0;
    for (name, rule, edit) in edits {
        let mut report = derived_report();
        edit(&mut report);
        assert_ne!(report, derived_report(), "{name} edits the document");
        let file = format!("{name}.json");
        let path = work.write(&file, &published(report.clone()));
        for args in RENDERINGS {
            let output = render(args, &path);
            fed += 1;
            let got = envelope_of(&output);
            assert_eq!(got.code, "USER_INPUT", "{name} {args:?}: {}", got.message);
            assert!(
                got.message.contains(&file) && got.message.contains(rule),
                "{name} {args:?}: the refusal names the report and the rule: {}",
                got.message
            );
        }
    }
    assert_eq!(fed, 12, "four edits through three renderings");
    // `digest` re-reads too: the exchange, refused there.
    let exchanged = work.path("rollup-on-off-exchanged.json");
    let got = envelope_of(&render(&["digest"], &exchanged));
    assert_eq!(got.code, "USER_INPUT", "digest: {}", got.message);
    assert!(got.message.contains(DEFECT), "digest: {}", got.message);
}

/// What `measure` omits when it has nothing to say reads as absent, an empty rollup
/// reads as one, and a member no rule reads is not the reader's to refuse. Nothing to
/// say is the observations' state, not the block's: a rollup or a ratchet removed from beside the
/// observations it summarises is a contradiction
/// (`table_and_matrix_refuse_the_derived_edits_the_first_reread_passed`), so these take the
/// observations' defects, or the rungs, away with it.
fn readable_omissions() -> [(&'static str, Edit); 4] {
    [
        ("no-dc", |r| {
            r.as_object_mut()
                .expect("a report")
                .remove("defect_coverage");
            for o in r["observations"].as_array_mut().expect("observations") {
                o.as_object_mut().expect("an observation").remove("defects");
            }
        }),
        ("empty-dc", |r| {
            r["defect_coverage"] = serde_json::json!({});
            for o in r["observations"].as_array_mut().expect("observations") {
                o.as_object_mut().expect("an observation").remove("defects");
            }
        }),
        ("no-ratchet", |r| {
            r.as_object_mut()
                .expect("a report")
                .remove("fortify_ratchet");
            // The one rung bearing on the defect goes with its count, and the rollup
            // over the one check left is `mitigated`.
            r["observations"]
                .as_array_mut()
                .expect("observations")
                .retain(|o| {
                    !o["check"]
                        .as_str()
                        .is_some_and(|c| c.starts_with("fortify-") && c != "fortify-effective")
                });
            r["coverage"] = serde_json::json!({
                    "checks_attempted": 2, "corpus_checks_total": 2,
                    "verdict_counts": {"on": 1, "probe-invalid": 1},
                    "all_verdicts_published": false,
                    "withholding": {"published": 1,
                                    "earned_limitations": {"count": 0, "no_named_cause": 0},
                                    "instrument_withholdings": {
                                        "count": 1, "by_verdict": {"probe-invalid": 1},
                                        "no_named_cause": 1}}});
            let entry = &mut r["defect_coverage"]["heap-buffer-overflow"];
            entry["from_checks"] = serde_json::json!(["fortify-effective"]);
            entry["verdict_counts"] = serde_json::json!({"on": 1});
            entry["status"] = "mitigated".into();
        }),
        ("extra-member", |r| {
            r["defect_coverage"]["heap-buffer-overflow"]["not_counted"] = 0.into();
        }),
    ]
}

#[test]
fn table_and_matrix_refuse_a_derived_subtree_they_cannot_read() {
    if !ready("that `table` and `matrix` refuse a derived subtree they cannot read") {
        return;
    }
    let work = common::Work::new("errorclasses", "derived-unreadable");
    let unreadable: [(&str, &str, Edit); 8] = [
        ("dc-null", "defect_coverage", |r| {
            r["defect_coverage"] = Value::Null;
        }),
        ("dc-array", "defect_coverage", |r| {
            r["defect_coverage"] = serde_json::json!([]);
        }),
        ("dc-status-number", "defect_coverage", |r| {
            r["defect_coverage"]["heap-buffer-overflow"]["status"] = 7.into();
        }),
        ("dc-no-counts", "defect_coverage", |r| {
            r["defect_coverage"]["heap-buffer-overflow"]
                .as_object_mut()
                .expect("an entry")
                .remove("verdict_counts");
        }),
        ("ratchet-null", "fortify_ratchet", |r| {
            r["fortify_ratchet"] = Value::Null;
        }),
        ("ratchet-bounds-string", "fortify_ratchet", |r| {
            r["fortify_ratchet"]["dynamic_bounds"] = "yes".into();
        }),
        ("no-coverage", "coverage", |r| {
            r.as_object_mut().expect("a report").remove("coverage");
        }),
        ("no-withholding", "coverage", |r| {
            r["coverage"]
                .as_object_mut()
                .expect("coverage")
                .remove("withholding");
        }),
    ];
    let mut fed = 0;
    for (name, field, edit) in unreadable {
        // Published first and edited after, as an editor of a published report edits it:
        // `coverage` removed leaves no digest to derive from the document.
        let mut report = publish(derived_report());
        edit(&mut report);
        let file = format!("{name}.json");
        let path = work.write(&file, &serde_json::to_string(&report).expect("json"));
        for command in ["table", "matrix"] {
            let got = run(&[OsStr::new(command), path.as_os_str()]);
            fed += 1;
            assert_eq!(got.code, "USER_INPUT", "{name} {command}: {}", got.message);
            // A line of its own, not the digest rule's: the report is published before the
            // edit, so removing `coverage` is named by `digest-disagrees-with-report` too,
            // and that line alone must not pass for the subtree's refusal.
            assert!(
                got.message.lines().any(|line| line.contains(&file)
                    && line.contains(&format!("`{field}`"))
                    && !line.contains("digest-disagrees-with-report")),
                "{name} {command}: the refusal names the report and the field: {}",
                got.message
            );
        }
    }
    assert_eq!(fed, 16, "eight shapes through two renderers");

    let readable = readable_omissions();
    let mut rendered = 0;
    for (name, edit) in readable {
        let mut report = derived_report();
        edit(&mut report);
        let path = work.write(&format!("{name}.json"), &published(report));
        for command in ["table", "matrix"] {
            let output = output_of(&[OsStr::new(command), path.as_os_str()]);
            rendered += 1;
            assert_eq!(
                output.status.code(),
                Some(0),
                "{name} {command}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
    assert_eq!(rendered, 8, "four shapes through two renderers");
}

#[test]
fn a_report_measure_publishes_passes_the_reread() {
    if !ready("that a published report passes the rules re-run on read")
        || !common::require_cc("that a published report passes the rules re-run on read")
    {
        return;
    }
    let work = common::Work::new("errorclasses", "reread-roundtrip");
    let profiles = ["bare", "bare-optimized", "openssf-tldr"];
    let mut fed = 0;
    // The three measurements are independent, each in its own work directory, and each is a
    // chain of child processes run one after another, so they run at once: this test took
    // 70 s of the suite in series, nearly all of it waiting on children.
    let running: Vec<_> = profiles
        .iter()
        .map(|profile| {
            Command::new(chard_binary())
                .arg("measure")
                .args(["-o", "-"])
                .arg("--profile")
                .arg(profile)
                .arg("--workdir")
                .arg(work.path(&format!("w-{profile}")))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawning chard")
        })
        .collect();
    for (profile, child) in profiles.into_iter().zip(running) {
        let output = child.wait_with_output().expect("waiting for chard");
        // A full-corpus measurement exits 0 with a reader; closed_pipe measures two probes.
        assert_eq!(
            output.status.code(),
            Some(0),
            "{profile}: measure of the whole corpus; stderr was:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("a report");
        assert!(
            report.get("error").is_none(),
            "{profile}: {}",
            report["error"]
        );
        let reread = chard::report::reread_contradictions(&report);
        assert!(
            reread.is_empty(),
            "{profile}: a published report fails the reread: {reread:?}"
        );
        let path = work.write(
            &format!("{profile}.json"),
            &serde_json::to_string(&report).expect("json"),
        );
        for args in RENDERINGS {
            let rendered = render(args, &path);
            assert_eq!(
                rendered.status.code(),
                Some(0),
                "{profile} {args:?}: {}",
                String::from_utf8_lossy(&rendered.stdout)
            );
        }
        fed += 1;
    }
    assert_eq!(fed, profiles.len());
}

#[test]
fn table_and_matrix_refuse_a_file_named_as_unpublished() {
    if !ready("that `table` and `matrix` refuse a quarantined or set-aside report by name") {
        return;
    }
    let work = common::Work::new("errorclasses", "unpublished-name");
    let body = minimal_report("[]");
    let mut fed = 0;
    for (name, says) in [
        ("r.json.contradicted", "quarantine"),
        ("r.json.previous", "set aside"),
        ("r.json.partial", "temporary file"),
        ("r.json.partial.4242.0", "temporary file"),
    ] {
        let path = work.write(name, &body);
        for command in ["table", "matrix"] {
            let got = run(&[OsStr::new(command), path.as_os_str()]);
            fed += 1;
            assert_eq!(got.code, "USER_INPUT", "{command} {name}: {}", got.message);
            assert!(
                got.message.contains(name) && got.message.contains(says),
                "{command} {name}: {}",
                got.message
            );
        }
    }
    assert_eq!(fed, 8, "four names through two renderers");
}

#[test]
fn a_measure_that_fails_leaves_no_earlier_report_at_the_output() {
    if !ready("that a failed `measure` leaves no earlier report at the requested path") {
        return;
    }
    let work = common::Work::new("errorclasses", "stale-output");
    let missing = work.path("no-such-cc");
    let earlier = minimal_report("[]");
    let cases: [(&str, Vec<&OsStr>, &str); 1] = [(
        "missing-cc",
        vec![OsStr::new("--cc"), missing.as_os_str()],
        "USER_INPUT",
    )];
    let mut fed = 0;
    for (name, args, class) in &cases {
        let output_path = work.write(&format!("{name}.json"), &earlier);
        let previous = work.path(&format!("{name}.json.previous"));
        let output = common::output_waiting_out_etxtbsy(|| {
            let mut cmd = Command::new(chard_binary());
            cmd.arg("measure")
                .arg("--workdir")
                .arg(work.path(&format!("w-{name}")))
                .arg("-o")
                .arg(&output_path)
                .args(args);
            cmd
        });
        fed += 1;
        let got = envelope_of(&output);
        assert_eq!(got.code, *class, "{name}: {}", got.message);
        assert!(
            !output_path.exists(),
            "{name}: the earlier report is still at {} after a run that published nothing",
            output_path.display()
        );
        assert_eq!(
            std::fs::read_to_string(&previous).ok().as_deref(),
            Some(earlier.as_str()),
            "{name}: the earlier report is kept, unchanged, at {}",
            previous.display()
        );
    }
    assert_eq!(fed, cases.len());
}

/// The usage errors `a_usage_error_leaves_the_earlier_output_untouched` feeds: each as its
/// command and arguments, over files `work` holds, with the error class expected.
#[expect(
    clippy::too_many_lines,
    reason = "one row per usage error, each spelled out so a reader sees the invocation; \
              splitting the table would split the one list the test counts"
)]
fn usage_errors(
    work: &common::Work,
    earlier: &str,
) -> Vec<(&'static str, Vec<OsString>, &'static str)> {
    let os = |s: &str| OsString::from(s);
    let missing = work.path("missing.json").into_os_string();
    let not_json = work.write("not-json.json", "{").into_os_string();
    let set_aside = work.write("stale.json.previous", earlier).into_os_string();
    let quarantine = work
        .write("stale.json.contradicted", earlier)
        .into_os_string();
    let no_attestation = work.path("no-attestation.json").into_os_string();
    let a_file = work.write("a-file", "not a directory\n").into_os_string();
    let report = work.write("report.json", earlier).into_os_string();
    vec![
        (
            "measure-unknown-option",
            vec![os("measure"), os("--no-such-option")],
            "USER_INPUT",
        ),
        (
            "table-format-it-does-not-take",
            vec![os("table"), os("--format"), os("json"), report],
            "USER_INPUT",
        ),
        (
            "measure-unknown-probe",
            vec![os("measure"), os("--probe"), os("no-such-probe")],
            "USER_INPUT",
        ),
        (
            "measure-unknown-probe-beside-a-known-one",
            vec![
                os("measure"),
                os("--probe"),
                os("no-plt"),
                os("--probe"),
                os("no-such-probe"),
            ],
            "USER_INPUT",
        ),
        (
            "measure-empty-probe-id",
            vec![os("measure"), os("--probe"), os("")],
            "USER_INPUT",
        ),
        (
            "measure-explicit-response-file",
            vec![
                os("measure"),
                os("--profile"),
                os("explicit"),
                os("--flags"),
                os("-O2 @/nonexistent/chard-flags.rsp"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-explicit-x32-in-cxxflags",
            vec![
                os("measure"),
                os("--profile"),
                os("explicit"),
                os("--flags"),
                os("-O2"),
                os("--cxxflags"),
                os("-O2 -mx32"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-explicit-runtime-removal",
            vec![
                os("measure"),
                os("--profile"),
                os("explicit"),
                os("--flags"),
                os("-O2 -nostdlib"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-explicit-relative-path-in-ldflags",
            vec![
                os("measure"),
                os("--profile"),
                os("explicit"),
                os("--flags"),
                os("-O2"),
                os("--ldflags"),
                os("-Wl,-L,lib"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-explicit-relative-input-in-ldflags",
            vec![
                os("measure"),
                os("--profile"),
                os("explicit"),
                os("--flags"),
                os("-O2"),
                os("--ldflags"),
                os("rwx_segment.c"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-probe-twice",
            vec![
                os("measure"),
                os("--probe"),
                os("no-plt"),
                os("--probe"),
                os("no-plt"),
            ],
            "USER_INPUT",
        ),
        (
            "measure-explicit-no-flags",
            vec![os("measure"), os("--profile"), os("explicit")],
            "CONFIGURATION",
        ),
        (
            "measure-bare-with-flags",
            vec![
                os("measure"),
                os("--profile"),
                os("bare"),
                os("--flags"),
                os("-O2"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-bare-optimized-with-cxxflags",
            vec![
                os("measure"),
                os("--profile"),
                os("bare-optimized"),
                os("--cxxflags"),
                os("-D_GLIBCXX_ASSERTIONS"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-openssf-tldr-with-ldflags",
            vec![
                os("measure"),
                os("--profile"),
                os("openssf-tldr"),
                os("--ldflags"),
                os("-Wl,-z,now"),
            ],
            "CONFIGURATION",
        ),
        (
            "measure-missing-attestation",
            vec![os("measure"), os("--image-attestation"), no_attestation],
            "USER_INPUT",
        ),
        (
            "measure-workdir-is-a-file",
            vec![os("measure"), os("--workdir"), a_file],
            "USER_INPUT",
        ),
        (
            "table-missing-input",
            vec![os("table"), missing.clone()],
            "USER_INPUT",
        ),
        (
            "matrix-missing-input",
            vec![os("matrix"), missing],
            "USER_INPUT",
        ),
        ("table-not-json", vec![os("table"), not_json], "USER_INPUT"),
        (
            "table-set-aside-input",
            vec![os("table"), set_aside],
            "USER_INPUT",
        ),
        (
            "matrix-quarantine-input",
            vec![os("matrix"), quarantine],
            "USER_INPUT",
        ),
    ]
}

#[test]
fn a_usage_error_leaves_the_earlier_output_untouched() {
    if !ready("that a usage error leaves the earlier output untouched") {
        return;
    }
    let work = common::Work::new("errorclasses", "usage-untouched");
    let earlier = minimal_report("[]");
    let cases = usage_errors(&work, &earlier);
    let mut fed = 0;
    for (name, args, class) in &cases {
        let output_path = work.write(&format!("{name}.out"), &earlier);
        let previous = work.path(&format!("{name}.out.previous"));
        let workdir = work.path(&format!("w-{name}"));
        let mut full: Vec<&OsStr> = vec![args[0].as_os_str()];
        if args[0] == "measure" && !args.iter().any(|a| a == "--workdir") {
            full.extend([OsStr::new("--workdir"), workdir.as_os_str()]);
        }
        full.extend([OsStr::new("-o"), output_path.as_os_str()]);
        full.extend(args.iter().skip(1).map(OsString::as_os_str));
        let got = run(&full);
        fed += 1;
        assert_eq!(got.code, *class, "{name}: {}", got.message);
        assert_eq!(
            std::fs::read_to_string(&output_path).ok().as_deref(),
            Some(earlier.as_str()),
            "{name}: the earlier output at {} is not as it was",
            output_path.display()
        );
        assert!(
            !previous.exists(),
            "{name}: a usage error set the earlier output aside as {}",
            previous.display()
        );
        assert!(
            !workdir.exists(),
            "{name}: a usage error made the work directory {}",
            workdir.display()
        );
    }
    assert_eq!(fed, cases.len());
}

/// One row of `an_unusable_output_is_refused_before_anything_is_built`: its name, the
/// command and arguments before `-o`, the output, the class, words only its hint carries,
/// and whether an earlier output is there to stay as it was.
type UnusableOutput = (
    &'static str,
    Vec<OsString>,
    PathBuf,
    &'static str,
    &'static str,
    bool,
);

/// Print the longest name the scratch filesystem takes to the real stderr, past the test
/// harness's capture, so a passing run's log says which length its name rows ran at: 255
/// where the lookup of an over-long sibling refuses, less (fuse-overlayfs holds 251) where
/// the trial of its length does.
fn announce_name_max(test: &str, name_max: usize) {
    use std::io::Write as _;
    let mut stderr = std::io::stderr().lock();
    chard::error::best_effort(
        writeln!(
            stderr,
            "\nchard: {test}: names in the scratch directory hold {name_max} bytes"
        )
        .and_then(|()| stderr.flush()),
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the shapes, the two that need a mode the host may not honour, and the six \
              assertions each case is held to, read as one table and one loop"
)]
fn an_unusable_output_is_refused_before_anything_is_built() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that an unusable -o is refused before the run builds anything") {
        return;
    }
    let work = common::Work::new("errorclasses", "unusable-output");
    let earlier = minimal_report("[]");
    let a_file = work.write("a-file", "not a directory\n");
    let a_directory = work.path("a-directory");
    std::fs::create_dir(&a_directory).expect("mkdir");
    let dangling = work.path("dangling.json");
    std::os::unix::fs::symlink("/nonexistent/chard-test-dir/out.json", &dangling)
        .expect("a dangling link");
    let report = work.write("report.json", &earlier);
    // A directory that takes no new file, holding an earlier output that cannot be written
    // either: neither of publication's two routes is open.
    let read_only = work.path("read-only");
    std::fs::create_dir(&read_only).expect("mkdir");
    let locked = read_only.join("out.json");
    std::fs::write(&locked, &earlier).expect("the earlier output");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o444)).expect("chmod");
    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let mode_holds = std::fs::write(read_only.join("probe"), "").is_err()
        && std::fs::OpenOptions::new()
            .write(true)
            .open(&locked)
            .is_err();

    let name_max = common::longest_name(work.dir());
    announce_name_max(
        "an_unusable_output_is_refused_before_anything_is_built",
        name_max,
    );
    let measure = |name: &str| -> Vec<OsString> {
        [
            "measure".into(),
            "--cc".into(),
            "/nonexistent/chard-test-compiler".into(),
            "--workdir".into(),
            work.path(&format!("w-{name}")).into_os_string(),
        ]
        .into()
    };
    let mut cases: Vec<UnusableOutput> = vec![
        (
            "missing-directory",
            measure("missing-directory"),
            work.path("no-such-directory/out.json"),
            "USER_INPUT",
            "first",
            false,
        ),
        (
            "a-directory",
            measure("a-directory"),
            a_directory.clone(),
            "USER_INPUT",
            "inside",
            false,
        ),
        (
            "through-a-file",
            measure("through-a-file"),
            a_file.join("out.json"),
            "USER_INPUT",
            "slash",
            false,
        ),
        (
            "trailing-slash",
            measure("trailing-slash"),
            work.path("no-such-file/"),
            "USER_INPUT",
            "slash",
            false,
        ),
        (
            // Five bytes under the longest name this filesystem takes fits;
            // `<output>.contradicted`, which publication removes before it writes, does not,
            // nor `.previous`.
            "name-too-long-for-its-siblings",
            measure("name-too-long-for-its-siblings"),
            work.path(&format!("{}.json", "r".repeat(name_max - 10))),
            "USER_INPUT",
            "shorter",
            false,
        ),
        (
            "dangling-link",
            measure("dangling-link"),
            dangling.clone(),
            "USER_INPUT",
            "point the link",
            false,
        ),
        (
            "table-missing-directory",
            vec!["table".into(), report.clone().into_os_string()],
            work.path("no-such-directory/table.txt"),
            "USER_INPUT",
            "first",
            false,
        ),
    ];
    if mode_holds {
        cases.push((
            "read-only-directory",
            measure("read-only-directory"),
            locked.clone(),
            "PERMISSION",
            "this user",
            true,
        ));
        cases.push((
            "read-only-directory-no-file",
            measure("read-only-directory-no-file"),
            read_only.join("new.json"),
            "PERMISSION",
            "this user",
            false,
        ));
    } else {
        common::capability_gap(
            "PERMISSION for an -o in a mode-555 directory, over a mode-444 file and over none",
            "this process writes there anyway, so the modes stop nothing here",
        );
    }
    let mut fed = 0;
    for (name, before, output_path, class, _, has_earlier) in &cases {
        let mut args: Vec<&OsStr> = before.iter().map(OsString::as_os_str).collect();
        args.extend([OsStr::new("-o"), output_path.as_os_str()]);
        let got = run(&args);
        fed += 1;
        assert_eq!(
            got.code, *class,
            "{name} (names here hold {name_max} bytes): {}",
            got.message
        );
        assert!(
            got.message.contains(&output_path.display().to_string()),
            "{name}: the refusal names the output: {}",
            got.message
        );
        let workdir = work.path(&format!("w-{name}"));
        assert!(
            !workdir.exists(),
            "{name}: the work directory {} was made before the refusal",
            workdir.display()
        );
        if *has_earlier {
            assert_eq!(
                std::fs::read_to_string(output_path).ok().as_deref(),
                Some(earlier.as_str()),
                "{name}: the earlier output is not as it was"
            );
        }
        let mut previous = output_path.clone().into_os_string();
        previous.push(".previous");
        assert!(
            !Path::new(&previous).exists(),
            "{name}: the refusal set an earlier output aside"
        );
    }
    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(fed, cases.len());
    assert_eq!(fed, if mode_holds { 9 } else { 7 });
}

#[test]
fn a_usable_output_is_not_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that a usable -o is not refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "usable-output");
    let existing = work.path("existing");
    std::fs::create_dir(&existing).expect("mkdir");
    let dangling = work.path("dangling.json");
    std::os::unix::fs::symlink(existing.join("target.json"), &dangling).expect("a link");
    let fifo = work.path("fifo");
    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|s| s.success());
    // A directory that takes no new file, over a writable earlier output: publication
    // writes it in place.
    let read_only = work.path("read-only");
    std::fs::create_dir(&read_only).expect("mkdir");
    let writable = read_only.join("out.json");
    std::fs::write(&writable, "earlier").expect("the earlier output");
    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let mode_holds = std::fs::write(read_only.join("probe"), "").is_err();

    // As long as the filesystem lets `<output>.contradicted` be: the name and its
    // `.contradicted` and `.previous` siblings fit.
    let name_max = common::longest_name(work.dir());
    announce_name_max("a_usable_output_is_not_refused", name_max);
    let only_temporary_too_long = work.path(&format!("{}.json", "r".repeat(name_max - 18)));
    let mut cases: Vec<(&str, PathBuf)> = vec![
        ("dangling-link-in-an-existing-directory", dangling.clone()),
        (
            "name-too-long-for-the-temporary-file",
            only_temporary_too_long.clone(),
        ),
        ("dev-null", PathBuf::from("/dev/null")),
    ];
    if made {
        cases.push(("fifo", fifo.clone()));
    } else {
        common::capability_gap("a FIFO at -o", "mkfifo did not make one here");
    }
    if mode_holds {
        cases.push(("read-only-directory-over-a-writable-file", writable.clone()));
    } else {
        common::capability_gap(
            "an -o in a mode-555 directory over a writable file",
            "this process writes there anyway, so the mode stops nothing here",
        );
    }
    let mut fed = 0;
    for (name, output_path) in &cases {
        let workdir = work.path(&format!("w-{name}"));
        let got = run(&[
            OsStr::new("measure"),
            OsStr::new("--cc"),
            OsStr::new("/nonexistent/chard-test-compiler"),
            OsStr::new("--workdir"),
            workdir.as_os_str(),
            OsStr::new("-o"),
            output_path.as_os_str(),
        ]);
        fed += 1;
        assert!(
            got.code == "USER_INPUT" && got.message.contains("chard-test-compiler"),
            "{name} (names here hold {name_max} bytes): not the compiler's USER_INPUT: {} ({:?})",
            got.message,
            got.hint
        );
        assert!(
            workdir.exists(),
            "{name}: the run did not go on to make its work directory"
        );
    }
    assert!(
        !existing.join("target.json").exists(),
        "the check left a file at the dangling link's target"
    );
    assert!(
        !only_temporary_too_long.exists(),
        "the check left the file it created to try the in-place route"
    );
    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(fed, cases.len());
    assert_eq!(fed, 3 + usize::from(made) + usize::from(mode_holds));
}

#[test]
fn measure_with_flags_beside_the_default_profile_is_configuration() {
    if !ready("that --flags beside a built-in profile is the invocation's to fix") {
        return;
    }
    let work = common::Work::new("errorclasses", "flags-beside-bare");
    let workdir = work.path("w");
    let got = run(&[
        OsStr::new("measure"),
        OsStr::new("--cc"),
        OsStr::new("/nonexistent/chard-test-compiler"),
        OsStr::new("--workdir"),
        workdir.as_os_str(),
        OsStr::new("--flags"),
        OsStr::new("-O2"),
    ]);
    assert_eq!(got.code, "CONFIGURATION", "{}", got.message);
    assert!(
        got.message.contains("--profile explicit")
            && got.message.contains("--profile bare ")
            && got.message.contains("reads none of --flags;"),
        "{}",
        got.message
    );
    assert!(
        !workdir.exists(),
        "a refused invocation made {}",
        workdir.display()
    );
}

#[test]
fn measure_with_a_zero_timeout_is_refused() {
    if !ready("that --timeout 0 is refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "zero-timeout");
    let earlier = minimal_report("[]");
    let output_path = work.write("r.json", &earlier);
    let workdir = work.path("w");
    let output = output_of(&[
        OsStr::new("measure"),
        OsStr::new("--timeout"),
        OsStr::new("0"),
        OsStr::new("--workdir"),
        workdir.as_os_str(),
        OsStr::new("-o"),
        output_path.as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let got = envelope_of(&output);
    assert_eq!(
        (got.code.as_str(), got.operation.as_str()),
        ("USER_INPUT", "measure"),
        "{}",
        got.message
    );
    assert!(got.message.contains("--timeout"), "{}", got.message);
    assert!(stderr.contains("--timeout"), "stderr was:\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(&output_path).ok().as_deref(),
        Some(earlier.as_str())
    );
    assert!(!work.path("r.json.previous").exists());
    assert!(!workdir.exists());
}

#[test]
fn an_allowance_the_gate_cannot_take_is_refused_with_its_reason() {
    if !ready("that an allowance the gate cannot take is refused with its reason") {
        return;
    }
    let work = common::Work::new("errorclasses", "allowance");
    let report = work.path("r.json");
    for (args, said) in [
        (
            vec!["measure", "--allow", "no-check-on-target"],
            "--fail-on-missing",
        ),
        (
            vec![
                "measure",
                "--fail-on-missing",
                "--allow",
                "arch-outside-table",
            ],
            "gating.rule arch-outside-table has no allowance",
        ),
        (
            vec![
                "measure",
                "--fail-on-missing",
                "--allow",
                "machine-lacks-bti",
            ],
            "it is a machine limit",
        ),
    ] {
        let mut argv: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        argv.extend([OsStr::new("-o"), report.as_os_str()]);
        let output = output_of(&argv);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let got = envelope_of(&output);
        assert_eq!(got.code, "USER_INPUT", "{args:?}: {}", got.message);
        assert_eq!(got.operation, "measure", "{args:?}");
        assert!(stderr.contains(said), "{args:?}: {stderr}");
        assert!(!report.exists(), "{args:?}: a refused run wrote a report");
    }
}

#[test]
fn a_command_line_clap_refuses_reaches_the_envelope() {
    if !ready("that a command line clap refuses reaches the envelope") {
        return;
    }
    let work = common::Work::new("errorclasses", "clap-refusal");
    let report = work.write("report.json", &minimal_report("[]"));
    let cases: [(&str, Vec<&OsStr>, &str); 8] = [
        (
            "unknown-option",
            vec![OsStr::new("measure"), OsStr::new("--no-such-option")],
            "measure",
        ),
        (
            "option-before-the-command",
            vec![OsStr::new("--no-such-option"), OsStr::new("elf")],
            "chard",
        ),
        (
            "table-format-it-does-not-take",
            vec![
                OsStr::new("table"),
                OsStr::new("--format"),
                OsStr::new("json"),
                report.as_os_str(),
            ],
            "table",
        ),
        (
            "probes-format-it-does-not-take",
            vec![
                OsStr::new("probes"),
                OsStr::new("--format"),
                OsStr::new("markdown"),
            ],
            "probes",
        ),
        (
            "missing-required-argument",
            vec![OsStr::new("table")],
            "table",
        ),
        (
            "missing-value",
            vec![
                OsStr::new("detect"),
                OsStr::new("pie"),
                OsStr::new("--evidence"),
            ],
            "detect",
        ),
        ("no-command", vec![], "chard"),
        (
            "unknown-command",
            vec![OsStr::new("no-such-command")],
            "chard",
        ),
    ];
    let mut fed = 0;
    for (name, args, operation) in &cases {
        let output = output_of(args);
        let got = envelope_of(&output);
        fed += 1;
        assert_eq!(got.code, "USER_INPUT", "{name}: {}", got.message);
        assert_eq!(got.operation, *operation, "{name}: {}", got.message);
        let help = if *operation == "chard" {
            "`chard --help`".to_owned()
        } else {
            format!("`chard {operation} --help`")
        };
        assert!(
            got.hint.as_deref().is_some_and(|h| h.contains(&help)),
            "{name}: the hint {:?} does not name {help}",
            got.hint
        );
        assert!(
            !got.message.is_empty() && !got.message.starts_with("error:"),
            "{name}: {}",
            got.message
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Usage:") || stderr.contains("try '--help'"),
            "{name}: clap's text is not on stderr:\n{stderr}"
        );
    }
    assert_eq!(fed, cases.len());

    // The envelope's message is clap's whole first block, so a missing argument is named
    // there as on stderr, not cut at the line that introduces it.
    let got = run(&[OsStr::new("table")]);
    assert!(
        got.message.contains("<REPORTS>"),
        "the missing argument is not named: {}",
        got.message
    );
}

#[test]
fn help_and_version_print_text_and_exit_0() {
    if !ready("that --help and --version print text and exit 0") {
        return;
    }
    let controls: [&[&str]; 3] = [&["--help"], &["--version"], &["measure", "--help"]];
    for args in controls {
        let os: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let output = output_of(&os);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: stdout was:\n{stdout}"
        );
        assert!(
            stdout.starts_with("chard ") || stdout.contains("Usage: chard"),
            "{args:?}: {stdout}"
        );
        assert!(
            serde_json::from_str::<Value>(&stdout).is_err(),
            "{args:?} printed JSON"
        );
        assert!(output.stderr.is_empty(), "{args:?} wrote to stderr");
    }
}

#[test]
fn no_escape_reaches_either_stream_from_a_colour_variable_or_the_command_line() {
    use std::os::unix::ffi::OsStringExt as _;
    const COLOUR: [&str; 6] = [
        "NO_COLOR",
        "CLICOLOR",
        "CLICOLOR_FORCE",
        "TERM",
        "COLORTERM",
        "CI",
    ];
    const COLOUR_CRATES: [&str; 3] = ["anstream", "anstyle-query", "colorchoice"];
    let lock = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
        .expect("Cargo.lock");
    for name in COLOUR_CRATES {
        assert!(
            !lock.contains(&format!("name = \"{name}\"")),
            "Cargo.lock holds {name}, through which clap's `color` reads the colour variables"
        );
    }
    if !ready("that no escape reaches either stream from a colour variable or an argument") {
        return;
    }
    let forced: &[(&str, &str)] = &[
        ("CLICOLOR_FORCE", "1"),
        ("CLICOLOR", "1"),
        ("TERM", "xterm-256color"),
        ("COLORTERM", "truecolor"),
        ("CI", "true"),
    ];
    let settings: [&[(&str, &str)]; 2] = [&[], forced];
    let word = |s: &str| OsString::from(s);
    let not_utf8 = OsString::from_vec(b"--x\xff\x1b[1m".to_vec());
    // The arguments, the exit status, and what the quote reads as once scrubbed.
    let lines: [(Vec<OsString>, i32, Option<&str>); 8] = [
        (vec![word("--help")], 0, None),
        (vec![word("measure"), word("--help")], 0, None),
        (
            vec![word("measure"), word("--cxxflag"), word("-O2")],
            2,
            Some("a similar argument exists: '--cxxflags'"),
        ),
        (vec![], 2, None),
        (
            vec![word("measure"), word("--x\u{1b}[31mred")],
            2,
            Some("--x?[31mred"),
        ),
        (
            vec![
                word("probes"),
                word("--format"),
                word("\u{1b}]0;title\u{7}"),
            ],
            2,
            Some("?]0;title?"),
        ),
        (
            vec![word("measure"), word("--x\u{9b}31m")],
            2,
            Some("--x?31m"),
        ),
        (vec![word("measure"), not_utf8], 2, Some("?[1m")),
    ];
    let mut fed = 0;
    for setting in settings {
        for (args, status, quote) in &lines {
            let mut cmd = Command::new(chard_binary());
            cmd.args(args);
            for name in COLOUR {
                cmd.env_remove(name);
            }
            cmd.envs(setting.iter().copied());
            let output = cmd.output().expect("spawning chard");
            fed += 1;
            let case = format!("{setting:?} {args:?}");
            holds_no_control_character(&case, &output, *status, *quote);
        }
    }
    assert_eq!(fed, settings.len() * lines.len());
    assert_eq!(fed, 16);
}

/// One run of `no_escape_reaches_either_stream_from_a_colour_variable_or_the_command_line`:
/// its exit status, no control character but a newline on either stream, a help that kept
/// its lines or an envelope whose message carries none, and the scrubbed quote on stderr.
fn holds_no_control_character(
    case: &str,
    output: &std::process::Output,
    status: i32,
    quote: Option<&str>,
) {
    assert_eq!(output.status.code(), Some(status), "{case}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{case}: a control character on {stream}:\n{text:?}"
        );
    }
    if status == 0 {
        assert!(
            stdout.lines().count() > 3 && stdout.contains("\nUsage: chard"),
            "{case}: the help lost its lines:\n{stdout}"
        );
    } else {
        let got = envelope_of(output);
        assert!(
            !got.message.chars().any(char::is_control),
            "{case}: a control character in the envelope: {:?}",
            got.message
        );
    }
    if let Some(quote) = quote {
        assert!(
            stderr.contains(quote),
            "{case}: stderr does not carry {quote:?}:\n{stderr}"
        );
    }
}

#[test]
fn every_inspecting_command_writes_its_document_to_dash_o() {
    if !ready("that probes, elf and detect write their document to -o") {
        return;
    }
    let work = common::Work::new("errorclasses", "inspect-output");
    let object =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/elf32-le-i386-pie.elf");
    let cases: [(&str, Vec<&OsStr>); 4] = [
        ("probes-json", vec![OsStr::new("probes")]),
        (
            "probes-text",
            vec![
                OsStr::new("probes"),
                OsStr::new("--format"),
                OsStr::new("text"),
            ],
        ),
        ("elf", vec![OsStr::new("elf"), object.as_os_str()]),
        (
            "detect",
            vec![
                OsStr::new("detect"),
                OsStr::new("pie"),
                OsStr::new("--artifact"),
                object.as_os_str(),
            ],
        ),
    ];
    let mut fed = 0;
    for (name, args) in &cases {
        let direct = output_of(args);
        assert_eq!(direct.status.code(), Some(0), "{name} without -o");
        assert!(!direct.stdout.is_empty(), "{name} printed nothing");
        let out = work.write(&format!("{name}.out"), "an earlier document\n");
        let mut with_output = args.clone();
        with_output.extend([OsStr::new("-o"), out.as_os_str()]);
        let written = output_of(&with_output);
        fed += 1;
        assert_eq!(
            written.status.code(),
            Some(0),
            "{name} -o: {}",
            String::from_utf8_lossy(&written.stderr)
        );
        assert!(written.stdout.is_empty(), "{name} -o printed on stdout");
        assert_eq!(
            std::fs::read(&out).ok(),
            Some(direct.stdout.clone()),
            "{name}: -o and stdout differ"
        );
        assert!(
            !work.path(&format!("{name}.out.previous")).exists(),
            "{name}: the set-aside was kept"
        );
    }
    assert_eq!(fed, cases.len());
}

#[test]
fn chard_without_a_command_says_it_takes_one() {
    if !ready("that chard with no command says it takes one") {
        return;
    }
    let got = run(&[]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert_eq!(got.message, "chard takes a command");
}

#[test]
fn a_bare_output_beside_a_bare_input_is_refused_and_two_directories_are_not() {
    if !ready("that a bare -o whose set-aside is a bare input is refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "bare-input");
    let object = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/elf32-le-i386-pie.elf"),
    )
    .expect("the fixture");
    std::fs::write(work.path("a.out.previous"), &object).expect("an input");
    let refused = Command::new(chard_binary())
        .args(["elf", "a.out.previous", "-o", "a.out"])
        .current_dir(work.dir())
        .output()
        .expect("spawning chard");
    let got = envelope_of(&refused);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.message.contains("is a name chard replaces or removes"),
        "{}",
        got.message
    );
    assert_eq!(
        std::fs::read(work.path("a.out.previous")).ok(),
        Some(object.clone()),
        "the input is untouched"
    );

    std::fs::create_dir(work.path("a")).expect("mkdir");
    std::fs::create_dir(work.path("b")).expect("mkdir");
    std::fs::write(work.path("a/x.previous"), &object).expect("an input");
    let written = Command::new(chard_binary())
        .args(["elf", "a/x.previous", "-o", "b/x"])
        .current_dir(work.dir())
        .output()
        .expect("spawning chard");
    assert_eq!(
        written.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&written.stdout),
        String::from_utf8_lossy(&written.stderr)
    );
    assert!(work.path("b/x").exists());
    assert_eq!(std::fs::read(work.path("a/x.previous")).ok(), Some(object));
}

#[test]
fn a_bare_output_name_is_published_in_the_working_directory_without_a_note() {
    if !ready("that a bare -o name is published in the working directory") {
        return;
    }
    let work = common::Work::new("errorclasses", "bare-output");
    let direct = output_of(&[OsStr::new("probes")]);
    assert_eq!(direct.status.code(), Some(0), "probes without -o");
    let written = Command::new(chard_binary())
        .args(["probes", "-o", "listing.json"])
        .current_dir(work.dir())
        .output()
        .expect("spawning chard");
    let stderr = String::from_utf8_lossy(&written.stderr);
    assert_eq!(written.status.code(), Some(0), "{stderr}");
    assert!(written.stdout.is_empty(), "-o printed on stdout");
    assert_eq!(
        std::fs::read(work.path("listing.json")).ok(),
        Some(direct.stdout),
        "-o and stdout differ"
    );
    assert!(
        stderr.lines().count() == 1 && stderr.contains("written to listing.json"),
        "{stderr}"
    );
}

/// One row of `an_output_that_is_an_input_is_refused`: its name, the arguments, the input that
/// must survive and its bytes, and words the refusal names.
type OutputIsInput = (&'static str, Vec<OsString>, PathBuf, Vec<u8>, &'static str);

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row per shape, each spelled out so a reader sees the invocation; splitting \
              the table would split the one list the test counts"
)]
fn an_output_that_is_an_input_is_refused() {
    if !ready("that an -o naming an input is refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "output-is-input");
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/elf32-le-i386-pie.elf");
    let object = std::fs::read(&fixture).expect("the fixture");
    let report = minimal_report("[]").into_bytes();
    // `chard elf`'s output, which `detect --evidence` reads as a detection's input.
    let facts = output_of(&[OsStr::new("elf"), fixture.as_os_str()]).stdout;
    assert!(!facts.is_empty(), "chard elf printed no facts");
    let os = |p: &Path| p.as_os_str().to_owned();
    let put = |name: &str, bytes: &[u8]| {
        let path = work.path(name);
        std::fs::write(&path, bytes).expect("an input");
        path
    };
    let mut rows: Vec<OutputIsInput> = Vec::new();
    for command in ["table", "matrix"] {
        let input = put(&format!("{command}.json"), &report);
        rows.push((
            command,
            vec![command.into(), os(&input), "-o".into(), os(&input)],
            input,
            report.clone(),
            "is the input",
        ));
    }
    let first = put("first.json", &report);
    let second = put("second.json", &report);
    rows.push((
        "table-second-input",
        vec![
            "table".into(),
            os(&first),
            os(&second),
            "-o".into(),
            os(&second),
        ],
        second,
        report.clone(),
        "is the input",
    ));
    let input = put("elf.elf", &object);
    rows.push((
        "elf",
        vec!["elf".into(), os(&input), "-o".into(), os(&input)],
        input,
        object.clone(),
        "is the input",
    ));
    let input = put("hard.elf", &object);
    let link = work.path("hard-link.elf");
    std::fs::hard_link(&input, &link).expect("a hard link");
    rows.push((
        "elf-hard-link",
        vec!["elf".into(), os(&input), "-o".into(), os(&link)],
        input,
        object.clone(),
        "is the input",
    ));
    let input = put("symbolic.elf", &object);
    let link = work.path("symbolic-link.elf");
    std::os::unix::fs::symlink(&input, &link).expect("a symbolic link");
    rows.push((
        "elf-symbolic-link",
        vec!["elf".into(), os(&input), "-o".into(), os(&link)],
        input,
        object.clone(),
        "is the input",
    ));
    let input = put("spelled.elf", &object);
    let spelled = work.path(".").join("spelled.elf");
    rows.push((
        "elf-second-spelling",
        vec!["elf".into(), os(&input), "-o".into(), os(&spelled)],
        input,
        object.clone(),
        "is the input",
    ));
    let output = put("set-aside.out", b"an earlier document\n");
    let input = put("set-aside.out.previous", &object);
    rows.push((
        "elf-input-is-the-set-aside",
        vec!["elf".into(), os(&input), "-o".into(), os(&output)],
        input,
        object.clone(),
        "a name chard replaces or removes when it writes",
    ));
    let output = work.path("quarantine.out");
    let input = put("quarantine.out.contradicted", &facts);
    rows.push((
        "detect-input-is-the-quarantine",
        vec![
            "detect".into(),
            "pie".into(),
            "--evidence".into(),
            os(&input),
            "-o".into(),
            os(&output),
        ],
        input,
        facts.clone(),
        "a name chard replaces or removes when it writes",
    ));
    let output = work.path("partial.out");
    let input = put("partial.out.partial", &object);
    rows.push((
        "elf-input-is-a-temporary-name",
        vec!["elf".into(), os(&input), "-o".into(), os(&output)],
        input,
        object.clone(),
        "a name chard replaces or removes when it writes",
    ));
    let output = put("aliased.out", b"an earlier document\n");
    let target = put("aliased.out.previous", &object);
    let alias = work.path("alias.elf");
    std::os::unix::fs::symlink(&target, &alias).expect("a symbolic link");
    rows.push((
        "elf-input-links-to-the-set-aside",
        vec!["elf".into(), os(&alias), "-o".into(), os(&output)],
        alias,
        object.clone(),
        "a name chard replaces or removes when it writes",
    ));
    let ahead = work.path("ahead");
    std::fs::create_dir(&ahead).expect("a directory");
    let dangling = work.path("dangling.out");
    std::os::unix::fs::symlink(ahead.join("end.json"), &dangling).expect("a dangling link");
    let input = put("ahead/end.json.previous", &object);
    rows.push((
        "elf-input-beside-a-dangling-link",
        vec!["elf".into(), os(&input), "-o".into(), os(&dangling)],
        input,
        object.clone(),
        "a name chard replaces or removes when it writes",
    ));
    let input = put("evidence.json", &facts);
    rows.push((
        "detect-evidence",
        vec![
            "detect".into(),
            "pie".into(),
            "--evidence".into(),
            os(&input),
            "-o".into(),
            os(&input),
        ],
        input,
        facts.clone(),
        "is the input",
    ));
    let input = put("artifact.elf", &object);
    rows.push((
        "detect-artifact",
        vec![
            "detect".into(),
            "pie".into(),
            "--artifact".into(),
            os(&input),
            "-o".into(),
            os(&input),
        ],
        input,
        object.clone(),
        "is the input",
    ));
    let mut fed = 0;
    for (name, args, input, bytes, words) in &rows {
        let args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
        let got = run(&args);
        fed += 1;
        assert_eq!(got.code, "USER_INPUT", "{name}: {}", got.message);
        assert!(got.message.contains(words), "{name}: {}", got.message);
        assert_eq!(
            std::fs::read(input).ok().as_ref(),
            Some(bytes),
            "{name}: the input was changed"
        );
        // Refused before the set-aside: no `.previous` was made beside `-o`, unless that
        // name is the input itself.
        let output = args.last().expect("-o and its path close each row");
        let mut previous = output.to_os_string();
        previous.push(".previous");
        assert!(
            !Path::new(&previous).exists()
                || std::fs::canonicalize(&previous).ok() == std::fs::canonicalize(input).ok(),
            "{name}: -o was set aside before the refusal"
        );
    }
    assert_eq!(fed, rows.len());
    assert_eq!(fed, 14, "the rows were counted");
}

#[test]
fn a_table_or_matrix_that_fails_leaves_no_earlier_output() {
    if !ready("that a failed `table` or `matrix` leaves no earlier output at -o") {
        return;
    }
    let work = common::Work::new("errorclasses", "stale-render");
    let refused = work.write("contradicted.json", &minimal_report(CONTRADICTION));
    let mut fed = 0;
    for command in ["table", "matrix"] {
        let out = work.write(&format!("{command}.out"), "an earlier rendering\n");
        let got = run(&[
            OsStr::new(command),
            OsStr::new("-o"),
            out.as_os_str(),
            refused.as_os_str(),
        ]);
        fed += 1;
        assert_eq!(got.code, "USER_INPUT", "{}", got.message);
        assert!(!out.exists(), "{command}: {} survived", out.display());
        let previous = work.path(&format!("{command}.out.previous"));
        assert_eq!(
            std::fs::read_to_string(&previous).ok().as_deref(),
            Some("an earlier rendering\n"),
            "{command}: the earlier output is kept at {}",
            previous.display()
        );
        // And a rendering that succeeds replaces it and removes what was set aside.
        let report = work.write(&format!("{command}.json"), &minimal_report("[]"));
        let output = output_of(&[
            OsStr::new(command),
            OsStr::new("-o"),
            out.as_os_str(),
            report.as_os_str(),
        ]);
        assert_eq!(output.status.code(), Some(0), "{command} over a report");
        assert!(
            out.exists() && !previous.exists(),
            "{command}: {previous:?}"
        );
    }
    assert_eq!(fed, 2);
}

#[test]
fn an_output_its_directory_will_not_release_is_emptied_not_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that an output its directory will not release is emptied, not refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "unreleased-output");
    let refused = work.write("contradicted.json", &minimal_report(CONTRADICTION));
    let report = work.write("report.json", &minimal_report("[]"));
    let locked = work.path("locked");
    std::fs::create_dir(&locked).expect("mkdir");
    // What the loop fed, against what the host let it feed: two commands, or none when
    // the mode stops nothing and the arm is announced as a capability gap.
    let mut fed = 0;
    let mut expected = 2;

    // Mode 555: the rename needs the directory, writing the file does not.
    for command in ["table", "matrix"] {
        let out = locked.join(format!("{command}.out"));
        std::fs::write(&out, "an earlier rendering\n").expect("an earlier rendering");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555))
            .expect("chmod 555");
        let probe = locked.join("probe");
        let holds = std::fs::rename(&out, &probe).is_err();
        if !holds {
            std::fs::rename(&probe, &out).expect("renaming the probe back to the output");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
                .expect("chmod 755");
            common::capability_gap(
                "an output in a mode-555 directory",
                "this process renames in it anyway, so the mode stops nothing here",
            );
            expected -= 2;
            break;
        }
        let got = run(&[
            OsStr::new(command),
            OsStr::new("-o"),
            out.as_os_str(),
            refused.as_os_str(),
        ]);
        fed += 1;
        assert_eq!(got.code, "USER_INPUT", "{command}: {}", got.message);
        assert_eq!(
            std::fs::read_to_string(&out)
                .expect("the output is still there")
                .as_str(),
            "",
            "{command}: a failed run left the earlier rendering at {}",
            out.display()
        );
        std::fs::write(&out, "an earlier rendering\n").expect("an earlier rendering");
        let output = output_of(&[
            OsStr::new(command),
            OsStr::new("-o"),
            out.as_os_str(),
            report.as_os_str(),
        ]);
        let written = std::fs::read_to_string(&out).expect("the output is still there");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 755");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command} over a report in a mode-555 directory: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !written.is_empty() && written != "an earlier rendering\n",
            "{command}: this run's output is at {}: {written:?}",
            out.display()
        );
        assert!(!locked.join(format!("{command}.out.previous")).exists());
        assert_eq!(
            common::temporary_files_beside(&locked.join(format!("{command}.out"))),
            Vec::<PathBuf>::new(),
            "{command}: a temporary file was left in the mode-555 directory"
        );
    }
    assert_eq!(
        fed, expected,
        "commands run against commands the host allowed"
    );
}

#[test]
fn a_bind_mounted_output_is_emptied_not_refused() {
    if !ready("that a bind-mounted output is emptied, not refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "bound-output");
    let refused = work.write("contradicted.json", &minimal_report(CONTRADICTION));
    let report = work.write("report.json", &minimal_report("[]"));
    let bound = work.write("bound.out", "an earlier rendering\n");
    let unshare = |args: &[&OsStr]| {
        Command::new("unshare")
            .args([
                "-rm",
                "sh",
                "-c",
                r#"mount --bind "$1" "$1" && shift && exec "$@""#,
                "sh",
            ])
            .arg(&bound)
            .arg(chard_binary())
            .args(args)
            .stdin(Stdio::null())
            .output()
    };
    match unshare(&[OsStr::new("probes")]) {
        Ok(o) if o.status.success() => {
            let output = unshare(&[
                OsStr::new("table"),
                OsStr::new("-o"),
                bound.as_os_str(),
                refused.as_os_str(),
            ])
            .expect("unshare ran once");
            let got = envelope_of(&output);
            assert_eq!(got.code, "USER_INPUT", "bind mount: {}", got.message);
            assert_eq!(
                std::fs::read_to_string(&bound).expect("bound").as_str(),
                "",
                "bind mount: a failed run left the earlier rendering in place"
            );
            assert_eq!(
                std::fs::read_to_string(work.path("bound.out.previous"))
                    .ok()
                    .as_deref(),
                Some("an earlier rendering\n"),
                "bind mount: the directory is writable, so the earlier contents are kept"
            );
            let output = unshare(&[
                OsStr::new("table"),
                OsStr::new("-o"),
                bound.as_os_str(),
                report.as_os_str(),
            ])
            .expect("unshare ran twice");
            assert_eq!(
                output.status.code(),
                Some(0),
                "bind mount, over a report: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(
                !std::fs::read_to_string(&bound).expect("bound").is_empty(),
                "the report reached the bind-mounted file"
            );
            assert!(!work.path("bound.out.previous").exists());
            // The directory takes the temporary file and the mount refuses the rename over
            // it (`EBUSY`), so this is the arm where one is made and must be removed.
            assert_eq!(
                common::temporary_files_beside(&work.path("bound.out")),
                Vec::<PathBuf>::new(),
                "bind mount: the temporary file the refused rename left is still there"
            );
        }
        _ => {
            common::capability_gap(
                "an output bind-mounted over itself",
                "`unshare -rm` with `mount --bind` is not available to this process",
            );
        }
    }
}

#[test]
fn a_symlinked_output_is_set_aside_at_its_target() {
    if !ready("that a symbolic link at -o has its target set aside and replaced") {
        return;
    }
    let work = common::Work::new("errorclasses", "linked-output");
    let refused = work.write("contradicted.json", &minimal_report(CONTRADICTION));
    let report = work.write("report.json", &minimal_report("[]"));
    let targets = work.path("t");
    std::fs::create_dir(&targets).expect("mkdir");
    let is_link = |p: &Path| {
        p.symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
    };
    let mut fed = 0;
    for command in ["table", "matrix"] {
        let target = targets.join(format!("{command}.out"));
        std::fs::write(&target, "an earlier rendering\n").expect("an earlier rendering");
        let link = work.path(&format!("{command}.link"));
        std::os::unix::fs::symlink(&target, &link).expect("a link");
        let got = run(&[
            OsStr::new(command),
            OsStr::new("-o"),
            link.as_os_str(),
            refused.as_os_str(),
        ]);
        fed += 1;
        assert_eq!(got.code, "USER_INPUT", "{command}: {}", got.message);
        assert!(
            !target.exists(),
            "{command}: a failed run left the earlier rendering at {}",
            target.display()
        );
        assert!(is_link(&link), "{command}: the link stays a link");
        let previous = targets.join(format!("{command}.out.previous"));
        assert_eq!(
            std::fs::read_to_string(&previous).ok().as_deref(),
            Some("an earlier rendering\n"),
            "{command}: the earlier rendering is kept beside the target"
        );
        let output = output_of(&[
            OsStr::new(command),
            OsStr::new("-o"),
            link.as_os_str(),
            report.as_os_str(),
        ]);
        fed += 1;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command} over a report: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            is_link(&link),
            "{command}: a publication leaves the link a link"
        );
        let written = std::fs::read_to_string(&target).expect("this run's output");
        assert!(
            !written.is_empty() && written != "an earlier rendering\n",
            "{command}: {written:?}"
        );
        let temporary = [
            targets.join(format!("{command}.out")),
            work.path(&format!("{command}.link")),
        ]
        .into_iter()
        .flat_map(|output| common::temporary_files_beside(&output));
        for leftover in [previous, work.path(&format!("{command}.link.previous"))]
            .into_iter()
            .chain(temporary)
        {
            assert!(
                !leftover.exists(),
                "{command}: {} remains",
                leftover.display()
            );
        }
    }
    assert_eq!(
        fed, 4,
        "a failing and a succeeding run through two renderers"
    );
}

#[test]
fn an_output_symlinked_to_a_stream_is_written_through() {
    if !ready("that a symbolic link at -o naming a stream is written through") {
        return;
    }
    let work = common::Work::new("errorclasses", "streamed-output");
    let report = work.write("report.json", &minimal_report("[]"));
    let mut fed = 0;
    for (command, shows) in [("table", "pie"), ("matrix", "\"-pie\"")] {
        let link = work.path(&format!("{command}.stdout"));
        std::os::unix::fs::symlink("/dev/stdout", &link).expect("a link to stdout");
        let output = output_of(&[
            OsStr::new(command),
            OsStr::new("-o"),
            link.as_os_str(),
            report.as_os_str(),
        ]);
        fed += 1;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{command}: {stdout}");
        assert!(stdout.contains(shows), "{command}: stdout was {stdout:?}");
        assert!(
            std::fs::read_link(&link).is_ok_and(|t| t == Path::new("/dev/stdout")),
            "{command}: the link still names /dev/stdout"
        );
        let stdout_link = work.path(&format!("{command}.stdout"));
        let previous = work.path(&format!("{command}.stdout.previous"));
        let made: Vec<_> = std::iter::once(previous)
            .filter(|p| p.exists())
            .chain(common::temporary_files_beside(&stdout_link))
            .collect();
        assert!(made.is_empty(), "{command}: {made:?} was made");
    }
    let redirected = work.write("redirected.out", "an earlier rendering\n");
    let held = std::fs::OpenOptions::new()
        .write(true)
        .open(&redirected)
        .expect("stdout for chard");
    let output = Command::new(chard_binary())
        .args([
            OsStr::new("table"),
            OsStr::new("-o"),
            OsStr::new("/dev/stdout"),
        ])
        .arg(&report)
        .stdout(held)
        .output()
        .expect("spawning chard");
    fed += 1;
    assert_eq!(output.status.code(), Some(0), "-o /dev/stdout into a file");
    let written = std::fs::read_to_string(&redirected).expect("the file stdout was");
    assert!(written.contains("pie"), "{written:?}");
    let made: Vec<_> = std::iter::once(work.path("redirected.out.previous"))
        .filter(|p| p.exists())
        .chain(common::temporary_files_beside(&redirected))
        .collect();
    assert!(made.is_empty(), "{made:?} was made");
    assert_eq!(fed, 3, "both renderers, and stdout redirected to a file");
}

/// A `chard detect` invocation that fails, asserting the envelope names the operation.
fn detect(args: &[&OsStr]) -> Envelope {
    let mut all = vec![OsStr::new("detect")];
    all.extend_from_slice(args);
    let got = run(&all);
    assert_eq!(got.operation, "detect", "{}", got.message);
    got
}

#[test]
fn detect_with_both_inputs_or_neither_is_the_callers_input() {
    if !ready("that `chard detect` refuses both --evidence and --artifact, and neither") {
        return;
    }
    let object = fixture_object();
    let got = detect(&[OsStr::new("pie")]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("exactly one"), "{}", got.message);
    let got = detect(&[
        OsStr::new("pie"),
        OsStr::new("--evidence"),
        object.as_os_str(),
        OsStr::new("--artifact"),
        object.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("exactly one"), "{}", got.message);
}

#[test]
fn detect_on_an_unknown_check_or_arm_is_the_callers_input() {
    if !ready("that `chard detect` names an unknown check and an unknown arm") {
        return;
    }
    let object = fixture_object();
    let got = detect(&[
        OsStr::new("no-such-check"),
        OsStr::new("--artifact"),
        object.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains("chard probes")),
        "{:?}",
        got.hint
    );
    let got = detect(&[
        OsStr::new("pie"),
        OsStr::new("--artifact"),
        object.as_os_str(),
        OsStr::new("--arm"),
        OsStr::new("sideways"),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("sideways"), "{}", got.message);
}

#[test]
fn detect_on_evidence_that_is_missing_or_no_evidence_is_the_callers_input() {
    if !ready("that `chard detect` names evidence it cannot read") {
        return;
    }
    let got = detect(&[
        OsStr::new("pie"),
        OsStr::new("--evidence"),
        OsStr::new("/nonexistent/chard-error-classes/r.json"),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("/nonexistent"), "{}", got.message);
    let work = common::Work::new("errorclasses", "detect");
    let text = work.write("hosts", TEXT);
    let got = detect(&[
        OsStr::new("pie"),
        OsStr::new("--evidence"),
        text.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("not JSON"), "{}", got.message);
    let empty = work.write("empty.json", "{}");
    let got = detect(&[
        OsStr::new("pie"),
        OsStr::new("--evidence"),
        empty.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("not a report"), "{}", got.message);
    let got = detect(&[
        OsStr::new("pie"),
        OsStr::new("--artifact"),
        text.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("not an ELF file"), "{}", got.message);
}

#[test]
fn detect_on_a_store_entry_of_an_unknown_kind_is_not_read_as_absent() {
    if !ready("that `chard detect` refuses a store entry kind it does not know") {
        return;
    }
    let work = common::Work::new("errorclasses", "detect-kind");
    let entry = work.write("entry.json", r#"{"kind":"elf-v2","elf":{}}"#);
    let got = detect(&[
        OsStr::new("pie"),
        OsStr::new("--evidence"),
        entry.as_os_str(),
    ]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert!(got.message.contains("not understood"), "{}", got.message);
}

#[test]
fn one_bad_input_gets_one_class_from_every_reader() {
    if !ready("that one bad input gets one error class from every reader") {
        return;
    }
    let work = common::Work::new("errorclasses", "one-class");
    let not_utf8 = work.path("not-utf8");
    std::fs::write(
        &not_utf8,
        [0x7f, b'E', b'L', b'F', 0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28],
    )
    .expect("writing the bytes");
    let inputs: Vec<(&str, PathBuf)> = vec![
        ("not UTF-8", not_utf8),
        ("text that is not JSON", work.write("text", TEXT)),
        ("an empty file", work.write("empty", "")),
        ("a directory", {
            let d = work.path("dir");
            std::fs::create_dir(&d).expect("mkdir");
            d
        }),
        ("a missing path", work.path("absent")),
        // A character device, which a read would never finish on were it `/dev/zero`.
        ("a character device", PathBuf::from("/dev/null")),
    ];
    let workdir = work.path("w");
    let workdir = workdir.to_str().expect("a UTF-8 work path");
    let readers: [&[&str]; 6] = [
        &["table"],
        &["matrix"],
        &["detect", "pie", "--evidence"],
        &["detect", "pie", "--artifact"],
        &["elf"],
        &["measure", "--workdir", workdir, "--image-attestation"],
    ];
    let mut fed = 0;
    for (shape, path) in &inputs {
        for reader in readers {
            let mut args: Vec<&OsStr> = reader.iter().map(OsStr::new).collect();
            args.push(path.as_os_str());
            let got = run(&args);
            fed += 1;
            assert_eq!(
                got.code,
                "USER_INPUT",
                "{} on {shape}: {}",
                reader.join(" "),
                got.message
            );
        }
    }
    // A literal, not the product of the two lists: a row dropped from either fails here.
    assert_eq!(fed, 36, "six readers by six inputs");
    // `/dev/null` reads as empty and so would be refused anyway; every reader refuses it by
    // its shape, before a read, which is what keeps `/dev/zero` from being read without
    // bound (to an allocation failure, `INTERNAL`, for `--image-attestation` at one point).
    for reader in readers {
        let mut args: Vec<&OsStr> = reader.iter().map(OsStr::new).collect();
        args.push(OsStr::new("/dev/null"));
        let got = run(&args);
        assert!(
            got.message.contains("a device"),
            "{} names the shape: {}",
            reader.join(" "),
            got.message
        );
    }

    // An unreadable file is a permission problem to every reader, `--image-attestation`
    // included, which wrapped every io error as `USER_INPUT`.
    let locked = work.write("locked", TEXT);
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 000");
    }
    if std::fs::read(&locked).is_ok() {
        common::capability_gap(
            "PERMISSION from every reader on a mode-000 file",
            "this process reads the file anyway, so the mode stops nothing here",
        );
        return;
    }
    let mut refused = 0;
    for reader in readers {
        let mut args: Vec<&OsStr> = reader.iter().map(OsStr::new).collect();
        args.push(locked.as_os_str());
        let got = run(&args);
        refused += 1;
        assert_eq!(
            got.code,
            "PERMISSION",
            "{}: {}",
            reader.join(" "),
            got.message
        );
    }
    assert_eq!(refused, 6, "six readers");
}

/// A driver whose macro dump fails, writing why to stderr, as a wrapper adding a flag the
/// compiler rejects does (gcc 4.8.4 under `-fstack-protector-strong` on Ubuntu 14.04)
/// and as a `CCACHE_PREFIX` naming a failing program does.
const REJECTING: &str = r#"#!/bin/sh
case " $* " in
  *' --version '*) echo 'shim 1.0' ;;
  *' -dM '*) echo "cc: error: unrecognized command-line option '-fstack-protector-strong'" >&2; echo "compilation terminated." >&2; exit 1 ;;
esac
exit 0
"#;

/// The same driver, writing more than the quote keeps: a multibyte line, an escape
/// sequence, and a line past the limit.
const VERBOSE: &str = r#"#!/bin/sh
case " $* " in
  *' --version '*) echo 'shim 1.0' ;;
  *' -dM '*) printf 'cc: erreur: option « -fbogus » inconnue \033[31mred\033[0m\n' >&2
             i=0; while [ $i -lt 100 ]; do printf 'noise %03d ' $i >&2; i=$((i+1)); done
             printf 'THE-TAIL\n' >&2; exit 4 ;;
esac
exit 0
"#;

/// The same driver, ended by a signal.
const KILLED: &str = r#"#!/bin/sh
case " $* " in
  *' --version '*) echo 'shim 1.0' ;;
  *' -dM '*) kill -SEGV $$ ;;
esac
exit 0
"#;

/// The same driver, saying nothing.
const SILENT: &str = r#"#!/bin/sh
case " $* " in
  *' --version '*) echo 'shim 1.0' ;;
  *' -dM '*) exit 1 ;;
esac
exit 0
"#;

#[test]
fn a_driver_that_defines_no_macro_is_refused_with_what_it_said() {
    use std::os::unix::fs::PermissionsExt as _;
    if !ready("that a driver defining no macro is refused with its stderr") {
        return;
    }
    let work = common::Work::new("errorclasses", "no-macros");
    for (name, script, said) in [
        (
            "verbose",
            VERBOSE,
            Some("cc: erreur: option « -fbogus » inconnue ?[31mred?[0m"),
        ),
        ("killed", KILLED, None),
        (
            "rejecting",
            REJECTING,
            Some(
                "its stderr read: cc: error: unrecognized command-line option '-fstack-protector-strong' | compilation terminated.",
            ),
        ),
        ("silent", SILENT, None),
    ] {
        let cc = work.write(name, script);
        std::fs::set_permissions(&cc, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
        let output = common::output_waiting_out_etxtbsy(|| {
            let mut cmd = Command::new(chard_binary());
            cmd.arg("measure")
                .args(["-o", "-"])
                .arg("--cc")
                .arg(&cc)
                .arg("--workdir")
                .arg(work.path(&format!("w-{name}")));
            cmd
        });
        let got = envelope_of(&output);
        assert_eq!(got.code, "USER_INPUT", "{name}: {}", got.message);
        assert!(
            got.message.contains("produced no predefined macros"),
            "{}",
            got.message
        );
        let ended = match name {
            "verbose" => "(exited 4)",
            "killed" => "(was killed by a signal)",
            _ => "(exited 1)",
        };
        assert!(got.message.contains(ended), "{name}: {}", got.message);
        if name == "verbose" {
            // Cut at the limit and marked, the tail past it not quoted, no ESC through.
            assert!(got.message.ends_with(" [...]"), "{}", got.message);
            assert!(!got.message.contains("THE-TAIL"), "{}", got.message);
            assert!(!got.message.contains('\u{1b}'), "{}", got.message);
        }
        if let Some(line) = said {
            assert!(got.message.contains(line), "{name}: {}", got.message);
        }
        let hint = got.hint.unwrap_or_default();
        assert!(hint.contains("env -i"), "{name}: the hint is kept: {hint}");
    }
}

/// A three-check document for
/// [`earned_limitations_and_instrument_withholdings_are_counted_and_listed_apart`]: `pie`
/// `on`, an architecture gate, and `third`, beside the coverage block given.
fn withholding_document(
    third: &Value,
    earned: &Value,
    instrument: &Value,
    complete: bool,
) -> Value {
    let verdict = third["verdict"].as_str().expect("a verdict").to_owned();
    serde_json::json!({
        "environment": environment_on_the_default(),
        "observations": [
            {"check": "pie", "flag": "-pie", "verdict": "on"},
            {"check": "branch-protection-macro", "flag": "-mbranch-protection=standard",
             "verdict": "unsupported",
             "gating": {"rule": "arch-gated", "reason": "an aarch64 mechanism"}},
            third,
        ],
        "coverage": {"checks_attempted": 3, "corpus_checks_total": 3,
                     "verdict_counts": if verdict == "unsupported" {
                         serde_json::json!({"on": 1, "unsupported": 2})
                     } else {
                         serde_json::json!({"on": 1, "unsupported": 1, verdict: 1})
                     },
                     "all_verdicts_published": complete,
                     "withholding": {"published": 1, "earned_limitations": earned,
                                     "instrument_withholdings": instrument}},
        "composites": [],
        "consistency": {"contradictions": []},
    })
}

#[test]
fn earned_limitations_and_instrument_withholdings_are_counted_and_listed_apart() {
    const WITHHOLDING: &str = "withholding-disagrees-with-verdict-counts";
    // `--by-defect` needs a `defect_coverage` block, which these documents do not carry.
    const PLAIN_RENDERINGS: [&[&str]; 2] = [&["table"], &["matrix"]];
    if !ready("that earned limitations and instrument withholdings are counted apart") {
        return;
    }
    let empty = serde_json::json!({"count": 0, "no_named_cause": 0});
    let earned_only = withholding_document(
        &serde_json::json!({"check": "zero-init-padding-bits",
                           "flag": "-fzero-init-padding-bits=all", "verdict": "unsupported",
                           "gating": {"rule": "flag-unknown-to-driver",
                                      "reason": "the driver does not know the flag"},
                           "controls": {"discriminating": false,
                                        "withheld_because": "positive-unevaluable"}}),
        &serde_json::json!({"count": 2, "by_verdict": {"unsupported": 2},
                           "by_rule": {"arch-gated": 1, "flag-unknown-to-driver": 1},
                           "no_named_cause": 0}),
        &empty,
        true,
    );
    let one_withheld = withholding_document(
        &serde_json::json!({"check": "shadow-stack-enforced", "flag": "-fcf-protection=return",
                           "verdict": "indeterminate",
                           "gating": {"rule": "cpu-lacks-shadow-stack",
                                      "reason": "the CPU does not enumerate shadow stack"},
                           "controls": {"discriminating": false,
                                        "withheld_because": "positive-indeterminate"}}),
        &serde_json::json!({"count": 1, "by_verdict": {"unsupported": 1},
                           "by_rule": {"arch-gated": 1}, "no_named_cause": 0}),
        &serde_json::json!({"count": 1, "by_verdict": {"indeterminate": 1},
                           "by_rule": {"cpu-lacks-shadow-stack": 1}, "no_named_cause": 0}),
        false,
    );
    let work = common::Work::new("errorclasses", "withholding-sets");
    let mut fed = 0;
    for (name, report, withheld_heading) in [
        ("earned-only", &earned_only, false),
        ("one-withheld", &one_withheld, true),
    ] {
        let path = work.write(&format!("{name}.json"), &published(report.clone()));
        for args in PLAIN_RENDERINGS {
            let output = render(args, &path);
            fed += 1;
            assert_eq!(
                output.status.code(),
                Some(0),
                "{name} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let table = String::from_utf8_lossy(&render(&["table"], &path).stdout).into_owned();
        let (_, after) = table
            .split_once("Limitations, and why:")
            .unwrap_or_else(|| panic!("{name}: a limitations list:\n{table}"));
        assert!(after.contains("an aarch64 mechanism"), "{table}");
        assert_eq!(
            table.contains("Withheld, and why:"),
            withheld_heading,
            "{name}: the withheld list stands only beside a withholding:\n{table}"
        );
    }

    // A reason relabelled inside the earned set: every sum, the tally and the flag agree,
    // and the rule still publishes `unsupported`, so only the recount from the
    // observations sees that the flag the driver did not know is now an architecture.
    let mut relabelled = earned_only;
    relabelled["coverage"]["withholding"]["earned_limitations"]["by_rule"] =
        serde_json::json!({"arch-gated": 2});
    let path = work.write("relabelled.json", &published(relabelled));
    for args in PLAIN_RENDERINGS {
        let output = render(args, &path);
        fed += 1;
        let got = envelope_of(&output);
        assert_eq!(
            got.code, "USER_INPUT",
            "relabelled {args:?}: {}",
            got.message
        );
        assert!(got.message.contains(WITHHOLDING), "{}", got.message);
    }
    assert_eq!(fed, 6, "two documents and one edit through two renderings");
}
