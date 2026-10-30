// SPDX-License-Identifier: BSD-3-Clause

//! What the envelope's `code` says for each kind of failure, through the built binary.
//!
//! The class is what a sweep across dozens of images branches on, and the ledger record
//! this file closes found it pointing the wrong way in both directions: a text file handed
//! to `chard elf` reported `INTERNAL`, which files a bug for a typo, and a file chard wrote
//! and lost reported `USER_INPUT`, which tells an operator to check a path they never
//! typed. The second direction is held at unit level in `src/error.rs`, since deleting the
//! work directory between chard creating it and chard writing into it is a race; this file
//! holds the first through the real binary, because the class is decided at the sole exit
//! point after every context layer `main` adds, and a unit test on `classify` cannot see a
//! `with_context` that erased the root.
//!
//! Each case names its input, a file written under `common::Work`, a checked-in fixture or
//! a path that does not exist, and asserts exit `2`, exactly one JSON object on stdout,
//! and the class. A command line clap's own parser refuses is one of them: its usage text
//! goes to stderr and its envelope to stdout (`a_command_line_clap_refuses_reaches_the_envelope`).
//! The `PERMISSION` cases do not
//! reproduce as root, where a mode of `000`, `500` or
//! `555` stops nothing; each checks from the test process whether the mode holds and
//! announces a capability gap rather than passing over an arm it could not exercise.
//!
//! Four of the five classes are reached here: `USER_INPUT`, `PERMISSION`, `CONFIGURATION`,
//! and `TRANSIENT` for a work directory another run holds. `TRANSIENT`'s io arm is a race
//! (`ETXTBSY`), and `INTERNAL` is a defect in chard
//! or a driver that hung on its own interrogation, which sits behind a bound too long for a
//! test; a socket handed to `table` or `matrix` was the one deterministic `INTERNAL` through
//! the binary, a wrong path misclassified, and it is refused from its metadata as the
//! caller's below. So `src/error.rs` pins those two at unit level in
//! `executable_file_busy_is_transient_on_either_path` and
//! `the_default_arm_catches_only_the_inventoried_internal_sites`. The positive controls,
//! that a run which succeeds prints a report and no envelope, are the existing
//! `measure_in_env` in `tests/fake_driver.rs` and `report_for` and
//! `a_matrix_conforms_to_its_schema` in `tests/schema_conformance.rs`, each of which
//! asserts the absence of an `error` key before reading the report.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// Refused from the metadata, before an open, as anything that is not a regular file is.
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
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// An object fed down a named FIFO is read to the same facts as the file it came from.
///
/// A FIFO's `len()` is 0 and its `open` blocks with no writer, and the change that typed
/// the reader's refusals first refused every FIFO from its metadata for the second
/// reason: that refused `chard elf <(...)` and `chard elf /dev/stdin` behind a pipe, both
/// of which read before, with a hint saying the bytes were not an object. The cap is held
/// on the bytes as they arrive instead, and the shapes no read serves (a directory, a
/// device, a socket) are the ones refused from the metadata.
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
    // the bytes or has gone. A chard that refused the FIFO leaves this thread in `open`;
    // the assertion below then fails on the envelope, with the thread left to the
    // process's exit.
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

/// The same object on `/dev/stdin` behind a pipe, which stats as a FIFO too and needs no
/// `mkfifo`: `cat probe | chard elf /dev/stdin` is the shell's shape of it.
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

/// Sparse, as `src/elf.rs`'s own cap test builds it: `set_len` writes no blocks, and the
/// file is refused from its metadata before it is opened.
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
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains("readelf -h") && h.contains("cut")),
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

/// `create_dir_all` runs before the probe selection and the toolchain interrogation, so
/// the `--cc` that names nothing never gets a turn.
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

/// The work directory exists and cannot be written into, so the first file chard
/// constructs under it, the run's claim on the directory (`measure::claim_workdir`), fails
/// with `EACCES` under its `HarnessPath` tag, and the hint names the file and both
/// operations a chard-owned path meets. Until the claim, that file was the macro-dump source
/// `toolchain::detect` asks for. The driver is the shim, so a refusal of the compiler cannot
/// come first should the claim ever move after it.
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
    assert!(
        got.hint
            .as_deref()
            .is_some_and(|h| h.contains("write or run") && h.contains("writable")),
        "{:?}",
        got.hint
    );
    std::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o700)).expect("chmod 700");
}

/// The `--cc` exists with no execute bit, and the envelope said `PERMISSION`: `chmod` on a
/// text file is the wrong action, and the caller is the one who can name a compiler. The
/// refusal is read from the metadata before any spawn, so no `ETXTBSY` wait is needed
/// here, and an `EACCES` the spawn itself reports on an executable mode (a `noexec`
/// mount) keeps `PERMISSION` for the filesystem's owner.
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

/// A `--workdir` that exists and is not a directory is refused from its metadata with the
/// invocation's other arguments, before the earlier output is set aside, not by
/// `create_dir_all` with `EEXIST` after the set-aside. The `--cc` that names
/// nothing never gets a turn, as above.
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

/// `TRANSIENT` through the binary: a second measure in a work directory a live run holds is
/// refused and leaves no claim of its own there, and a third, after the holder was killed, is
/// let in and removes the claim the killed run left.
///
/// The holder's driver waits on a gate file at its first invocation, so the holder is
/// inside `toolchain::detect` with its claim made for as long as the test needs. The test
/// opens the gate before it kills the holder, and the driver, once through the gate, waits
/// (on the same bound) for its parent to be gone before it exits: so the driver ends right after the
/// kill, and the holder never sees it exit, which would let the holder fail on its own and
/// remove its claim before the kill the third run's note depends on. The
/// second and third runs name a compiler that does not exist: that refusal comes after the
/// claim, so `USER_INPUT` for a missing compiler is what a run let in reads, and before
/// the claim existed it was what the second run read too.
#[test]
fn measure_in_a_work_directory_another_run_holds_is_transient() {
    if !ready("that a second measure in a busy work directory is refused") {
        return;
    }
    let work = common::Work::new("errorclasses", "busy-workdir");
    let gate = work.path("gate");
    let _ = std::fs::remove_file(&gate);
    let shared = work.path("shared");
    let _ = std::fs::remove_dir_all(&shared);
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

/// `TRANSIENT` through the binary: a run whose own claim was removed while it measured
/// publishes nothing.
///
/// The driver proxies to the host's `cc` once a gate file exists, so the run is held inside
/// `toolchain::detect` with its claim made while the test removes the claim, and then
/// measures and reaches publication. `measure::WorkdirClaim::confirm` is what refuses it;
/// without that call the run publishes its report and exits 0.
#[test]
fn measure_whose_claim_was_removed_mid_run_publishes_nothing() {
    let verifies = "that a run whose work directory claim was removed publishes nothing";
    if !(ready(verifies) && common::require_cc(verifies)) {
        return;
    }
    let work = common::Work::new("errorclasses", "claim-removed");
    let gate = work.path("gate");
    let _ = std::fs::remove_file(&gate);
    let shared = work.path("shared");
    let _ = std::fs::remove_dir_all(&shared);
    let report = work.path("report.json");
    let _ = std::fs::remove_file(&report);
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
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
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
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// The check `Work`'s drop makes, shown to fail on each of its two channels, for `work`.
///
/// The fixture's shell runs from `/`, so only its arguments (its script's path) name the
/// directory; the `sleep` it starts in a subshell that changed into the directory names
/// nothing there, so only its working directory does. Each is asserted found by its own
/// channel alone, so removing either channel from `Work::leftover_processes` fails this. The
/// drop must then fail, name both, report both killed, and have killed both; every wait on
/// the fixture is bounded, so a regression of the check fails here rather than hanging.
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
        let _ = left.kill();
        let _ = left.wait();
        common::capability_gap(verifies, why);
        return;
    }
    // Read now, while the shell is alive and still its parent, so every path below can kill
    // the sleep without relying on the check under test to have seen it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut descendants = children_of(left.id());
    while descendants.is_empty() && std::time::Instant::now() < deadline {
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
            let _ = left.kill();
            let _ = left.wait();
            for pid in seen
                .iter()
                .map(|l| l.pid)
                .chain(descendants.iter().copied())
            {
                gone_or_killed(pid);
            }
            panic!("the shell and its sleep were not both seen within 5s: {seen:?}");
        }
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

/// The same through a `TMPDIR` reached by a symlink: the kernel reports a working directory
/// resolved, so the `sleep` is found only if the resolved spelling is compared.
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

/// A process in a sibling directory sharing the work directory's name as a prefix
/// (`...-<pid>3` beside `...-<pid>`) is not this test's: neither its arguments nor its
/// working directory name the work directory.
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
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let listed = work.leftover_processes();
    let _ = beside.kill();
    let _ = beside.wait();
    if let Some(pid) = sleep {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    let sleep_gone = sleep.is_none_or(gone_or_killed);
    let _ = std::fs::remove_dir_all(&sibling);
    let listed = match listed {
        Ok(listed) => listed,
        Err(why) => {
            common::capability_gap("a sibling directory's process is not a leftover", why);
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

/// `CONFIGURATION` through the binary: an invocation that contradicts itself, refused
/// before any driver runs, not after a driver has answered. The shim is a
/// file this test wrote and chard execs, so the invocation waits out `ETXTBSY`.
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

/// A `+x` file with no shebang. Linux refuses it at `execve` with `ENOEXEC`, which no
/// `ErrorKind` names and which the envelope therefore reported as `INTERNAL`; Darwin runs
/// it through `sh` instead, so there the refusal arrives later, as a driver that defined no
/// macros, and the `ENOEXEC` arm is announced rather than asserted.
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

/// A socket has no bytes to read as a report, and a `read` on it answers with an errno
/// (`ENOTSUP` on Darwin, `ENXIO` on Linux) that no `ErrorKind` names, so `table` reported
/// `INTERNAL` for a wrong path. It is refused from its metadata as the caller's.
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
        r#"{"chard_schema": "1", "observations": [], "digest": {}}"#,
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

/// `chard matrix` refuses two reports of one configuration as the caller's input, naming the
/// repeat and the flag that allows it, and with `--replace-repeated` writes one cell and the
/// repeat in its warnings. The two reports are one document under two names, so the
/// cell is the same whichever is kept, and the warning says the two read every flag alike.
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
                w.as_str().is_some_and(|w| {
                    w.starts_with(&said)
                        && w.contains(
                            "The two read every flag both carry alike, verdict and polarity",
                        )
                })
            })),
        "{text}"
    );
}

/// `chard table` refuses two reports of one column's configuration as the caller's input,
/// naming the repeat, the key's axes and the flag that allows it, and with
/// `--replace-repeated` renders one column and the repeat among its notes, as
/// `matrix` does, rather than pooling the two into one column with exit 0 and no word of it.
/// The two reports are one document under two names, so the column is the same
/// whichever is kept, and the note says the two read every flag alike. The by-defect view's
/// refusal is `table`'s unit test's: this document carries no defect map.
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
                     arch, profile, execution, execution_basis, image; libc is the \
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
    assert!(
        noted.contains("The two read every flag both carry alike, verdict and polarity"),
        "{text}"
    );
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
///
/// `coverage` is in it because the renderers re-run
/// `withholding-disagrees-with-verdict-counts` on read and refuse a report with no
/// `coverage`, which every report `measure` writes carries. `coverage.checks_attempted` is
/// in it because the tally statements of `coverage-disagrees-with-observations` are re-run
/// on read too.
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
    if let Some(coverage) = report.get_mut("coverage") {
        let attempted = coverage["checks_attempted"].clone();
        fill(coverage, "checks_expected", attempted);
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

/// A report that carries no `observes` is refused by `table`, `matrix` and `digest` as the
/// shape of another chard's output, and the hint names the two ways on. The report is of
/// another corpus, carries no `observes`, counts its rollup with every bearing check as
/// protection and has its digest made over that. The same report with the field reads.
/// Without the refusal, the report without the field would read as consistent, with `table`,
/// `matrix` and `digest` exiting 0.
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

/// Every reader refuses a report of another `chard_schema`, and `table`, `matrix` and `digest`
/// one without its digest, with no compiler on the host: the hand-built report, published,
/// is read by the three as a control; a version of `"99"`, a version removed, and a version
/// retyped to an object with the `observations` list removed (which a sniff on `run` alone
/// would read as a record) are each refused by `table`, `matrix`, `digest` and `detect`, the
/// message naming what the file carries and the version this chard reads; the report with
/// its digest removed is refused by the three with an earlier `-o` output left as it was and
/// no `.previous`; and a matrix handed to `table` is named as not a report, not as a report
/// that lost its digest. `tests/fake_driver.rs` holds the same over a measured report.
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

/// A matrix handed to `table` is named as not a report, not as a report that lost its
/// digest: the read refuses a document with no `observations` list before it looks for the
/// digest, so chard's own other documents keep the renderers' sentence.
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

/// A report that states a contradiction of its own is refused by `table` and `matrix` as
/// the caller's input, and nothing is written to `-o`.
///
/// A renderer that rendered it, with a `CONTRADICTED` note under the table or in the
/// matrix's `warnings`, would exit 0, and `chard matrix ... -o m.json` would print "matrix
/// written" with one cell. `measure` quarantines such a report because a job ignores exit
/// codes and notes alike; a renderer that accepts it is the way back in.
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
///
/// The rungs are in it because the ratchet is held to its rung observations; a ratchet
/// over one rung with `rungs: []` is a shape `measure` never writes.
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

/// A report whose derived field was edited alone is refused by `table` and `matrix`,
/// naming the rule that the edit breaks.
///
/// A renderer that re-ran no consistency rule would render each of these edits with exit 0:
/// `table`, `table --by-defect` and `matrix` over a `defect_coverage` status set to
/// `mitigated` (`--by-defect` printing `yes` where the report says `part`), a
/// `fortify_ratchet.implied_level` above `fortify-effective`'s level, and
/// `dynamic_bounds: true` beside `whole_object_level: "0"`.
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

/// The derived-field edits a narrower re-read would pass are refused too, each naming its
/// rule.
///
/// Each would render with exit 0 through `table`, `table --by-defect` and `matrix` over a
/// published `openssf-tldr` report. A level that is not a number is skipped by
/// `.parse().ok()?`; a lowered `implied_level`, or one lowered with its axes, passes a rule
/// that is one-directional on purpose; a deleted ratchet, rung or `defect_coverage` entry
/// leaves nothing for a rule to read; a relabelled `by_verdict` keeps its sum; and an unknown
/// `verdict_counts` key is counted by neither total.
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
    let edits: [(&str, &str, Edit); 10] = [
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
    assert_eq!(fed, 30, "ten edits through three renderings");
}

/// A tally or a rollup edited between verdicts with its sum kept is refused by `table`
/// and `matrix`, naming the rule that the recount breaks.
///
/// Each of these would render with exit 0 were `coverage-disagrees-with-observations` to
/// compare only the tally's total, or not be re-run on read, and were the defect rollup's
/// counts read only by the status rule, which a status edited with them satisfies. The last
/// edit is the boundary: `on` and `off`
/// exchanged inside a rollup, with the status edited to match, still renders, since telling
/// the two apart needs polarity and the status rule does not read it.
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
    let edits: [(&str, &str, Edit); 3] = [
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
    assert_eq!(fed, 9, "three edits through three renderings");

    // The open shape, pinned so that closing it is a visible change to this test.
    let mut exchanged = derived_report();
    let entry = &mut exchanged["defect_coverage"]["heap-buffer-overflow"];
    entry["verdict_counts"] = serde_json::json!({"on": 2});
    entry["status"] = "mitigated".into();
    let path = work.write("rollup-on-off-exchanged.json", &published(exchanged));
    let mut open = 0;
    for args in RENDERINGS {
        let output = render(args, &path);
        open += 1;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: an on and off exchange inside a rollup is still read as written: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    assert_eq!(open, RENDERINGS.len());
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

/// A derived subtree the renderers cannot read as `measure` writes it is refused, naming
/// the field; one `measure` omits, or one carrying a member no rule reads, renders.
///
/// The refusal is the point: a rule that silently did not run over an edited subtree
/// would be a clean-looking pass.
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

/// Every report `measure` publishes passes the rules the renderers re-run, through the
/// library function and through `table`.
///
/// The guard on the read adapters: a field read back differently from how `measure`
/// holds it (an absent `level` against a null, an omitted `by_verdict`) would refuse
/// honest reports, and only a report chard itself wrote can show it does not. Measured
/// with the `cc` on `PATH`, under each built-in profile that needs no flags.
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
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
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

/// A file named as `measure` names a report it did not publish is refused by `table` and
/// `matrix` whatever it holds: `<output>.contradicted`, the quarantine,
/// `<output>.previous`, an earlier report a run set aside and has not replaced, and
/// `<output>.partial`, the temporary file a publication renames into place, which only a
/// run stopped between the write and the rename leaves. That file is named
/// `<output>.partial.<pid>.<n>`, and the refusal takes a name of that form too.
///
/// The content here is consistent on purpose. A quarantine edited to look clean and an
/// earlier report that is clean and stale both render, by content, as a measurement; their
/// names are chard's statement that neither is one. Without the refusal a `.contradicted` or
/// a `.partial` file would render byte for byte as the same report named `.json` does.
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

/// A `measure` that fails after its arguments were validated and before it publishes
/// leaves no earlier report at `-o`: the file is set aside, byte for byte, as
/// `<output>.previous`.
///
/// Without the set-aside this would exit 2 with the earlier report untouched at the requested
/// path, as would eight more cases, a signal among them. `publish` removes an earlier report only
/// when it refuses, and none of those reaches it. The compiler that is not there is refused when it
/// is run, after the set-aside; the cases refused before it, the invocation's own errors, are
/// `a_usage_error_leaves_the_earlier_output_untouched`'s.
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
#[allow(
    clippy::too_many_lines,
    reason = "one row per usage error, each spelled out so a reader sees the invocation; \
              splitting the table would split the one list the test counts"
)]
fn usage_errors(
    work: &common::Work,
    earlier: &str,
) -> Vec<(&'static str, Vec<std::ffi::OsString>, &'static str)> {
    let os = |s: &str| std::ffi::OsString::from(s);
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

/// A usage error is refused before the set-aside and touches nothing: the earlier report
/// or rendering stays at `-o` byte for byte, no `<output>.previous` is made, and `measure`
/// makes no work directory, so nothing was compiled, since every compile, the toolchain
/// interrogation's included, writes there. The explicit profile's own refusals (a response
/// file, an x32 selection, a runtime removal, a relative path) come before the set-aside and
/// the toolchain interrogation, and each of their rows here fails against the other ordering.
/// With the set-aside first, `measure --probe no-such-probe -o q.json` would exit 2 with
/// `q.json` moved to `q.json.previous` and a work directory made; a mistyped line is not a
/// run. `table` and `matrix` read and parse their inputs before the set-aside for the
/// same reason, so a missing path, a file that is not JSON and a file named as unpublished
/// leave the earlier rendering where it was.
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
        full.extend(args.iter().skip(1).map(std::ffi::OsString::as_os_str));
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
    Vec<std::ffi::OsString>,
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
    let _ = writeln!(
        stderr,
        "\nchard: {test}: names in the scratch directory hold {name_max} bytes"
    );
    let _ = stderr.flush();
}

/// An `-o` the run could never publish to is refused before anything is built, with a hint
/// for its shape, and leaves an earlier output where it was.
///
/// Found only when the report is first written, a missing directory, a directory chard
/// cannot write and a directory named as the output would let `measure` build and run every
/// probe and then exit 2, the missing directory with a hint about scripts and interpreters.
/// The driver named does not exist and the work
/// directory is a fresh path, so a refusal that came at publication, or anywhere after the
/// work directory is made, fails here on the work directory or on the class. `table`
/// shares the check through the same set-aside, and one row holds it there. Each row's
/// hint words are carried by no other shape's hint, so two hints swapped fail here.
/// `a_usable_output_is_not_refused` holds the other direction.
#[test]
#[allow(
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
    let measure = |name: &str| -> Vec<std::ffi::OsString> {
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
            // nor `.previous`. Sized from the filesystem: 250 bytes where names hold 255, and
            // fuse-overlayfs holds 251 and answers the lookup of a longer one "no such file".
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
    let mut hints: Vec<(&str, String)> = Vec::new();
    for (name, before, output_path, class, hint_word, has_earlier) in &cases {
        let mut args: Vec<&OsStr> = before.iter().map(std::ffi::OsString::as_os_str).collect();
        args.extend([OsStr::new("-o"), output_path.as_os_str()]);
        let got = run(&args);
        fed += 1;
        assert_eq!(
            got.code, *class,
            "{name} (names here hold {name_max} bytes): {}",
            got.message
        );
        let hint = got.hint.unwrap_or_default();
        hints.push((*hint_word, hint.clone()));
        assert!(
            hint.contains(hint_word) && !hint.contains("interpreter"),
            "{name} (names here hold {name_max} bytes): the hint does not fit the shape: \
             {hint:?} ({})",
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
    for (word, _) in &hints {
        for (other, hint) in &hints {
            assert!(
                other == word || !hint.contains(word),
                "{word:?} is in the hint for another shape too: {hint:?}"
            );
        }
    }
}

/// An `-o` publication can write is not refused: the check passes it and the run goes on,
/// here to the missing compiler it names, with its work directory made. Each row is a shape
/// a too-eager check refuses, among them a name the temporary file's suffix makes too long
/// and a directory whose next temporary names are all taken (that one is
/// `report::tests::the_output_check_takes_the_in_place_route`). A suite that held only
/// refusals would pass such a check.
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
    // `.contradicted` and `.previous` siblings fit. The temporary name `.partial.<pid>.<n>`
    // is 10 bytes and the digits of the pid and of n (one digit for the first try), so it
    // is longer than `.contradicted` (13) and refused only where the pid has three digits
    // or more; under a pid below 100 this row tests a usable name, not the temporary-only
    // overflow. Sized from the filesystem (242 bytes where names hold 255): a fixed 240 had
    // a `.contradicted` fuse-overlayfs, which holds 251, refuses.
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
            "{name} (names here hold {name_max} bytes): the output was refused, or the run \
             failed elsewhere: {} ({:?})",
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

/// `--flags` beside the default profile is refused through the binary with a message that
/// names the way to have it read, where a measurement of the compiler's defaults with `-O2`
/// named nowhere would read as a measurement of `-O2`. The driver named does not exist, so a
/// refusal that came after the toolchain interrogation would read `USER_INPUT` instead.
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

/// `--timeout 0` is refused by the parser, before anything is touched: exit 2, the envelope
/// on stdout as `USER_INPUT`, the argument named on stderr and in the envelope, and the
/// earlier report at `-o` as it was.
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

/// A command line clap refuses reaches the envelope as every other refusal does: exit 2,
/// one JSON object on stdout whose class is `USER_INPUT` and whose operation is the command
/// named, or `chard` where none is, a hint naming that command's `--help`, and clap's own
/// text on stderr. `Cli::parse` would exit 2 with stdout empty, so a caller branching on the
/// envelope would find nothing. The positive controls are
/// in `help_and_version_print_text_and_exit_0`.
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

/// The positive controls of `a_command_line_clap_refuses_reaches_the_envelope`: `--help`
/// and `--version`, which clap also reports as errors, print text on stdout, nothing on
/// stderr, and exit 0.
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

/// No escape reaches either stream from a colour variable or from the command line.
///
/// A colour variable: clap's `color` feature, off in `Cargo.toml`, reads `NO_COLOR`,
/// `CLICOLOR`, `CLICOLOR_FORCE`, `TERM`, `COLORTERM` and `CI` through `anstream`,
/// `anstyle-query` and `colorchoice`. With the feature, `CLICOLOR_FORCE=1` puts an escape on
/// `--help`'s stdout and on a refusal's stderr even into a pipe. `refuse_usage` writes clap's
/// rendered text itself, and two checks hold the feature off: the
/// lockfile check, and the quotes, which the feature's own stripping would leave without
/// the `?` the scrub puts in the escape's place. The forced rows fail if clap's own
/// printing comes back with the feature.
///
/// The command line: clap quotes a refused argument. With `color` it strips an escape
/// from the quote; without it, `refuse_usage` scrubs the text (`table::scrub_lines`), so a
/// crafted argument (an escape, a C1 control, bytes that are not UTF-8) reaches neither
/// stream nor the envelope's message as a control character, and the quote stays, scrubbed.
/// The help keeps its lines, and the refusal its "a similar argument exists" tip.
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

/// `probes`, `elf` and `detect` take `-o` as `measure`, `table` and `matrix` do: the
/// document written there is the one stdout carries without it, stdout is then empty, and an
/// earlier file at the path is set aside and removed.
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

/// `chard` with no command is the caller's to fix, and the envelope says so in words rather
/// than quoting clap's help.
#[test]
fn chard_without_a_command_says_it_takes_one() {
    if !ready("that chard with no command says it takes one") {
        return;
    }
    let got = run(&[]);
    assert_eq!(got.code, "USER_INPUT", "{}", got.message);
    assert_eq!(got.message, "chard takes a command");
}

/// An `-o` named bare is the file of that name in the working directory, as an input named
/// bare is: its set-aside `<output>.previous` there is the input of that name, so the run is
/// refused before the set-aside would replace it; and the same names in two directories are
/// two entries, so nothing is refused.
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

/// An `-o` named bare, with no directory in it, is published in the working directory with
/// nothing said but the note naming it: the directory searched for an earlier run's
/// temporary files and the one synced after the rename are `.`, not the empty parent the
/// name carries, which no directory call takes.
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
type OutputIsInput = (
    &'static str,
    Vec<std::ffi::OsString>,
    PathBuf,
    Vec<u8>,
    &'static str,
);

/// An `-o` that is one of the command's own inputs, or whose set-aside or quarantine name is
/// one, is refused as `USER_INPUT` and leaves the input as it was: the input is read before
/// the set-aside, so the set-aside and the document made from it would replace it. Unrefused,
/// `table r.json -o r.json` replaces the report with its table and exits 0, `elf` and `detect`
/// replace a binary or a report the same way, `elf x.previous -o x` exits 0 with `x.previous`
/// gone, and `elf x.partial -o x` removes the input with its cleanup. A hard link, a symbolic link
/// and a second spelling are the same file under another name.
#[test]
#[allow(
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
        let args: Vec<&OsStr> = args.iter().map(std::ffi::OsString::as_os_str).collect();
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

/// `table -o` and `matrix -o` over an input set that fails after its inputs were read leave
/// no earlier output at the path either: the set is judged after the set-aside. Until
/// 2026-10-05 an earlier table stayed at `-o` after an exit 2.
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

/// An output file whose directory refuses the rename `report::set_aside` tries is emptied
/// in place, not refused: a failed `table` or `matrix` leaves an empty file where the
/// earlier rendering was, and one that succeeds writes its output there with exit 0.
///
/// Two shapes refuse the rename while leaving the file writable: a mode-555 directory,
/// and a single file bind-mounted over itself, the shape `docker run -v
/// host/report.json:/out/report.json` produces, whose rename fails with `EBUSY`. A
/// `set_aside` that refused the run on either before it did anything would exit 2, under
/// `PERMISSION` and `INTERNAL` respectively, and leave the earlier output at the path. The
/// bind mount is made in a user and mount
/// namespace (`unshare -rm`) by the next test; a host without one announces the arm it
/// could not run. This one holds the mode-555 directory.
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
            let _ = std::fs::rename(&probe, &out);
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
            Vec::<std::path::PathBuf>::new(),
            "{command}: a temporary file was left in the mode-555 directory"
        );
    }
    assert_eq!(
        fed, expected,
        "commands run against commands the host allowed"
    );
}

/// The bind-mount half of the test above: a file bind-mounted over itself refuses the
/// rename with `EBUSY`, which classifies `INTERNAL`, and is emptied in place instead.
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
            assert!(!std::fs::read_to_string(&bound).expect("bound").is_empty());
            assert!(!work.path("bound.out.previous").exists());
            // The directory takes the temporary file and the mount refuses the rename over
            // it (`EBUSY`), so this is the arm where one is made and must be removed.
            assert_eq!(
                common::temporary_files_beside(&work.path("bound.out")),
                Vec::<std::path::PathBuf>::new(),
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

/// A symbolic link at `-o` naming a regular file is resolved: its target is set aside
/// and replaced, and the link stays a link naming this run's output.
///
/// A link written through and never set aside would leave, on a failed run, the target's
/// earlier contents where the link names them: `table -o out.json missing.json` with
/// `out.json` a link to a file holding an earlier rendering would exit 2 and leave that
/// rendering in place.
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

/// A symbolic link at `-o` naming a stream is written through, as `-o /dev/stdout` is: the
/// rendering arrives on stdout, exit 0, and nothing is renamed or made beside the link.
/// A guard on the policy: it fails if every link is resolved and replaced, since `/dev/stdout`
/// reaches `/proc/self/fd/1`, whose text is `pipe:[N]` and no path chard may rename over. The third
/// arm is stdout redirected to a regular file, where the link does reach one: it is still written
/// through, since renaming that file would split it from the descriptor the shell holds.
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

/// One bad input gets one error class, whichever subcommand reads it. A reader that read its
/// file with `read_to_string` would fail on a file that is not UTF-8 with `InvalidData` and
/// reach the envelope as `INTERNAL`, while a reader of bytes calls the same file
/// `USER_INPUT`. Every reader of
/// a file the operator names is fed every shape here, and the count of invocations is held
/// to the product of the two lists, so a reader dropped from the loop fails rather than
/// passing on nothing.
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

/// The refusal for a driver that defined no macro carries what the driver said on stderr,
/// and its exit status. It said only "it may not be a working C compiler", with the
/// driver's own line discarded, while the drivers that met it worked and had each rejected
/// one thing by name (2026-10-12). Where the driver said nothing, the refusal says
/// that, and keeps the guess. The hint naming the environment chard gives the compiler is
/// kept either way.
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
        match said {
            Some(line) => {
                assert!(got.message.contains(line), "{name}: {}", got.message);
                assert!(
                    !got.message.contains("may not be a working"),
                    "{}",
                    got.message
                );
            }
            None => assert!(
                got.message.contains("wrote nothing to stderr")
                    && got.message.contains("may not be a working C compiler"),
                "{name}: {}",
                got.message
            ),
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

/// A report whose only non-measurements are earned limitations, and one with an instrument
/// withholding: each is read by `table` and `matrix` as `measure` writes it, its reasons
/// listed under the heading of its own set, and an edit that moves the withholding into the
/// earned set, with the tally, the flag and every sum kept, is refused naming the rule.
///
/// `coverage.withholding` once counted both kinds as `withheld`, beside a
/// `percent_withheld`, and `table` listed both under "Withheld, and why".
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
