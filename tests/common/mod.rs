// SPDX-License-Identifier: BSD-3-Clause

//! What the test suite does when it cannot run a test here.
//!
//! Shared by every integration test that needs a C toolchain or a built `chard`,
//! because a skip rule that exists in two copies is a skip rule that will disagree
//! with itself.
//!
//! The rule: **declining to run is not a neutral outcome.** These tests are the only
//! thing standing behind claims that no human re-checks: that a report conforms to
//! its shipped schema, that a control triple discriminated before a verdict was
//! trusted. A test that reports `ok` having done none of that is the clean-looking
//! zero this project exists to refuse, and it was in the project's own gate.
//!
//! So the default is to fail. `CHARD_ALLOW_TEST_SKIP=1` opts out, for the one
//! legitimate case: a packaging environment with no C toolchain, where the operator
//! has decided the compile-dependent tests are out of scope.

// A `tests/common` module is compiled separately into every integration-test binary
// that declares it, so each binary sees the helpers the *other* binaries use as dead
// code. The alternative to this allow is splitting the rule into one module per
// consumer, which is the duplication this module exists to prevent.
#![allow(dead_code)]

pub mod schema;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// How many synthetic objects the catalogue in `tests/elf_builder` builds under
/// `tests/fixtures/elf/`. Two test binaries reconcile it against the directory,
/// `tests/elf_fixtures.rs` against the catalogue and `tests/schema_conformance.rs` against
/// the records it feeds to `$defs/elf_facts`, and integration tests are separate crates
/// that share a number only through a module both compile. A builder added to the
/// catalogue moves this one number.
pub const ELF_FIXTURE_COUNT: usize = 25;

/// How many tests have declined to run in this process.
static SKIPPED: AtomicUsize = AtomicUsize::new(0);

/// Did the operator opt into skipping?
pub fn skip_allowed() -> bool {
    std::env::var_os("CHARD_ALLOW_TEST_SKIP").is_some()
}

/// Refuse to pretend a test ran: panic, or (if the operator opted in) announce it
/// unmissably and let the caller return.
///
/// The skip is per test, never `std::process::exit(0)`. Exiting from inside a libtest thread
/// tears the whole harness down mid-run: every *other* test in the binary silently never
/// executes, libtest prints no `test result:` line at all, and cargo exits 0. With no compiler
/// on `PATH` that reads `running 3 tests` and then nothing, a green CI tick over zero tests.
/// One unrunnable test takes every other test in the binary with it, the containment defect
/// `measure::run_probe` guards against, in the harness rather than the product.
///
/// So the caller returns, libtest prints its result line, and the rest of the binary still
/// runs.
///
/// # Loudness
///
/// The announcement goes through [`std::io::stderr`] rather than `eprintln!`,
/// deliberately. libtest captures the `eprintln!` macro per test and replays it only
/// when that test *fails*, so a message written that way is invisible on a passing run without
/// `--nocapture`, which is exactly the run where it matters. The capture is a
/// thread-local consulted by the macro's formatting shim, not by the handle underneath
/// it, so writing the handle directly reaches the real file descriptor 2.
///
/// Reopening `/dev/stderr` would also bypass the capture, and it is wrong: each caller gets
/// its own description with its own file offset, so with tests running in parallel the
/// banners overwrite each other, and a four-character fragment of one warning can print in
/// place of another. `stderr().lock()` is a
/// process-wide lock and one `write_all` under it emits the banner whole.
///
/// # Panics
///
/// Panics unless `CHARD_ALLOW_TEST_SKIP` is set: that is the point.
pub fn refuse(reason: &str, verifies: &str) {
    assert!(
        skip_allowed(),
        "cannot run this test ({reason}).\n\
         It verifies {verifies}, so it fails rather than passing vacuously.\n\
         Set CHARD_ALLOW_TEST_SKIP=1 only if this machine genuinely cannot run it."
    );

    let n = SKIPPED.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let banner = format!(
        "\nchard: SKIPPED TEST #{n} — {reason}\n\
         chard:   this test verifies {verifies}, and that went unverified.\n\
         chard:   CHARD_ALLOW_TEST_SKIP is set, so this is not a failure. \
         A green run below does not mean this was checked.\n"
    );

    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(banner.as_bytes());
    let _ = stderr.flush();
    record("skipped", &format!("{reason}; it verifies {verifies}"));
}

/// The longest file name the filesystem holding `dir` creates, in bytes: names from 255
/// down are created in `dir` and removed until one is taken.
///
/// A test that sizes a name against the limit reads it here rather than assuming 255.
/// fuse-overlayfs, a rootless container's storage and the `/tmp` of the Ubuntu 24.04 image
/// CI's toolchain was measured in, holds 251 (2026-10-14), so a 240-byte name whose
/// `.contradicted` sibling fits 255 has a sibling that filesystem refuses.
///
/// # Panics
///
/// Where a create fails for any reason but the name's length, or no name of one byte is
/// taken: neither says how long a name may be.
pub fn longest_name(dir: &Path) -> usize {
    for length in (1..=255usize).rev() {
        let path = dir.join("n".repeat(length));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                drop(file);
                std::fs::remove_file(&path).expect("removing the name tried");
                return length;
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidFilename => {}
            Err(e) => panic!(
                "creating a {length}-byte name in {} failed for another reason than its \
                 length: {e}",
                dir.display()
            ),
        }
    }
    panic!("{} takes no name of one byte", dir.display());
}

/// Announce an arm that could not run because the *toolchain* lacks a capability.
///
/// Distinct from [`refuse`], and deliberately not gated on `CHARD_ALLOW_TEST_SKIP`: a
/// compiler that does not implement `-fcf-protection=full` is a property of the
/// compiler, legitimately variable between hosts, and demanding an opt-out for it would
/// train the operator to set the variable permanently, which would then also excuse the
/// skips that are not legitimate.
///
/// It still goes to the real stderr rather than `eprintln!`, for the reason [`refuse`]
/// does: a coverage reduction that is only visible under `--nocapture` is not visible.
pub fn capability_gap(arm: &str, why: &str) {
    let banner = format!("\nchard: arm not exercised — {arm}: {why}\n");
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(banner.as_bytes());
    let _ = stderr.flush();
    record("gap", &format!("{arm}: {why}"));
}

/// The directory every test binary of one build appends its unexercised arms to, read back
/// by `scripts/test-ledger.sh` after `make test`.
///
/// The banners above reach the terminal, interleaved with a few hundred `ok` lines across
/// thirty-odd binaries, and a green summary follows them: a reader who sees the summary and
/// not the banners reads every arm as run, the clean-looking zero inside the suite. The
/// ledger is the same announcements collected where one command can count and print them
/// after the run. `CARGO_TARGET_TMPDIR` is cargo's scratch directory for integration tests,
/// fixed at compile time, so no environment variable decides where the ledger goes.
pub const LEDGER_DIR: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/test-ledger");

/// Append one line to this process's ledger file: a kind, the test binary, and the text.
///
/// One file per process, named by the binary and the process id, so binaries never share
/// a file and a stale file from an earlier run is told from this one by `make test`
/// clearing the directory first. Each line is one `write_all` on a file opened for append,
/// so the threads of one binary cannot interleave within a line. A ledger that cannot be
/// written is said on stderr and not otherwise acted on: the banner already reached the
/// terminal, and `scripts/test-ledger.sh` fails a run whose ledger lacks the lines the
/// binaries that always write one owe it.
pub fn record(kind: &str, text: &str) {
    let binary = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown".to_owned());
    // cargo names an integration test binary `<test>-<hash>`; the ledger names the test.
    let test = binary
        .rsplit_once('-')
        .map_or(binary.as_str(), |(name, _)| name)
        .to_owned();
    let line = format!("{kind}\t{test}\t{}\n", text.replace(['\n', '\t'], " "));
    let file = Path::new(LEDGER_DIR).join(format!("{test}-{}.tsv", std::process::id()));
    let written = std::fs::create_dir_all(LEDGER_DIR).and_then(|()| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)?
            .write_all(line.as_bytes())
    });
    if let Err(e) = written {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "chard: the test ledger {} could not be written: {e}",
            file.display()
        );
    }
}

/// The compiler family a gate requires `cc` to be, from `CHARD_TEST_EXPECT_CC`, or `None`.
///
/// Rows that are inert only under one compiler family run only where `cc` is that family,
/// so on a gcc host every clang row is announced and the run still passes. `make
/// compiler-arms` points `cc` at the other family and sets this variable, and the driving
/// tests then fail unless the toolchain the reports name is that family and every row of it
/// ran. Without the variable a `cc` that resolved to the wrong compiler would pass that gate
/// with the rows announced again: Fedora's ccache shim picks the compiler from `argv[0]`, so
/// a `cc` symlink to the shim runs gcc. Read only by the tests; chard itself reads nothing
/// from the environment but `PATH`.
pub fn expected_compiler() -> Option<String> {
    std::env::var("CHARD_TEST_EXPECT_CC")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Does the host's `cc` emit ELF?
///
/// Several floors in this suite ("at least one measurement was examined", "at least one
/// elf-static check was measured") are correct on every host chard supports and false on
/// a Mach-O one, where the artifact channel has nothing to read. They are the guards that
/// stop a test passing having checked nothing, so they must not be relaxed on the basis of
/// the *result*; that is the clean-looking zero. Relaxing them on the basis of the *host*
/// is a different claim, and this constant is the one place it is made.
///
/// `cfg!` rather than `#[cfg]` so the surrounding code is compiled and type-checked on
/// every host, including the ones where the floor does not apply.
pub const ELF_HOST: bool = cfg!(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd"
));

/// A scratch directory that removes itself.
///
/// Three copies of this existed (`Workspace` in `elf_notes`, `Work` in
/// `measurement_loop` and `Work` in `schema_conformance`) identical but for the name
/// they gave the directory. That is the duplication this module's header objects to,
/// applied to cleanup rather than to skipping: three `Drop` impls are three chances to
/// leave a tree behind in `/tmp`, and only the one you are reading gets audited.
///
/// `prefix` names the test binary and `tag` the test, because the pid alone does not
/// separate two binaries of the same run.
///
/// # A process the test left behind fails the test
///
/// Dropping a `Work` also looks for processes the test left running: any process whose
/// arguments name the directory or a path under it, or whose working directory is in it.
/// One still there after [`LEFTOVER_GRACE`] is killed and the test fails, naming it and
/// saying whether the kill took. The directory carries this process's pid, so a concurrent
/// suite run's processes are not mistaken for this one's; a match is the directory followed
/// by `/` or by the end of an argument, so `...-busy-workdir-12` does not match another
/// run's `...-busy-workdir-123`. Both spellings of the directory are compared, the one
/// `TMPDIR` gave and the resolved one, because the kernel reports a working directory
/// resolved: under a `TMPDIR` reached through a symlink the given spelling alone matches no
/// working directory at all.
///
/// This is the check for a fixture that outlives its test. A fake driver that waits for a gate
/// file with no bound, whose `chard measure` the test kills and whose directory is removed,
/// polls for a file that cannot appear. A leaked process
/// is invisible to the run that leaked it, which exits 0, so the check sits where the test's
/// scratch is cleaned up, and every test that uses `Work` gets it without opting in. The
/// tests that show each channel discriminates are the `a_process_left_in_a_work_directory_*`
/// tests in `tests/error_classes.rs`.
///
/// What it does not see: a process that names the directory in neither its arguments nor its
/// working directory (a descendant that changed directory away and was started with no path
/// into it, or one holding only an open file there), and scratch a test makes outside `Work`.
/// A marker in the environment would not reach further, since chard runs its driver under a
/// cleared environment. Where `/proc` is absent or unreadable the processes cannot be seen,
/// and the check says so once per test binary through [`capability_gap`], naming which,
/// rather than passing as though it had looked.
pub struct Work {
    dir: PathBuf,
    /// `dir` with every symlink resolved, as `/proc/<pid>/cwd` reads back.
    resolved: PathBuf,
}

impl Work {
    pub fn new(prefix: &str, tag: &str) -> Self {
        Self::under(&std::env::temp_dir(), prefix, tag)
    }

    /// A `Work` under `base` in place of the temporary directory, for a test that needs the
    /// directory reached a particular way (through a symlink, say).
    pub fn under(base: &Path, prefix: &str, tag: &str) -> Self {
        let dir = base.join(format!("chard-{prefix}-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creating the work directory");
        let resolved = dir.canonicalize().expect("resolving the work directory");
        Self { dir, resolved }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, contents).expect("writing a source file");
        path
    }
}

/// A [`Work`] made by [`Work::shared`], the kind a test binary keeps in a `static` for all
/// its tests. A separate type, so a `static` written to hold one cannot be given a plain
/// [`Work`] by mistake.
///
/// Rust runs no destructor for a `static`, so the [`Drop`] of the `Work` inside never runs
/// and its directory outlives the binary. The next run that makes a `SharedWork` with the
/// same prefix and tag removes it. So after any number of runs the newest run's directory
/// stays. The directory of a run still going is kept too. A run that never makes its
/// `SharedWork` (one whose measurement is skipped) removes nothing.
pub struct SharedWork(Work);

impl SharedWork {
    pub fn dir(&self) -> &Path {
        self.0.dir()
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.path(name)
    }
}

impl Work {
    /// The [`SharedWork`] for `prefix` and `tag`, under the temporary directory.
    ///
    /// A directory already under this process's name was left by an ended run whose pid
    /// this one now has. It is removed, and a new empty one is made; where it cannot be
    /// emptied, the test panics rather than reuse what it holds. Then the directories of
    /// ended runs with the same prefix and tag are removed ([`remove_stale`], with
    /// [`process_alive`]). Where one of them needs judging and `kill` cannot be run, nothing
    /// more is removed and the gap is announced through [`capability_gap`].
    pub fn shared(prefix: &str, tag: &str) -> SharedWork {
        let base = std::env::temp_dir();
        let own = base.join(format!("chard-{prefix}-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&own);
        let work = Self::under(&base, prefix, tag);
        assert!(
            std::fs::read_dir(work.dir())
                .expect("listing the shared directory")
                .next()
                .is_none(),
            "{} was left by an ended run and could not be emptied",
            work.dir().display()
        );
        let owner = owner_of(work.dir());
        if let Err(why) = remove_stale(&base, prefix, tag, owner, process_alive) {
            capability_gap("an ended run's shared work directory is removed", why);
        }
        SharedWork(work)
    }
}

/// The user id that owns `path`.
pub fn owner_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(path)
        .expect("reading a directory's owner")
        .uid()
}

/// Removes the directories of ended runs from `base`, and returns the ones removed.
///
/// A directory is removed when all of these hold:
/// - its name is exactly the one [`Work::under`] gives for `prefix`, `tag` and a pid
///   (`chard-<prefix>-<tag>-<pid>`);
/// - it is a directory, not a symlink or a file;
/// - user `owner` owns it;
/// - the pid is not this process's;
/// - `alive` says the pid's process has ended.
///
/// A directory that cannot be removed is kept and named on stderr. Where `alive` cannot
/// tell (`None`), the walk stops and returns why, so nothing more is removed.
///
/// The owner check is there because `kill -0` fails for a process this user may not signal
/// as well as for one that has ended. This user may signal its own processes, so for this
/// user's directories a failure means the process has ended. Two cases remain:
/// - Where another process of this user now has the pid, the directory is kept. This errs
///   towards leaving one.
/// - A run of this user in another pid namespace that shares `base` reads as ended,
///   because `kill -0` cannot see it. Its directory can be removed while it runs.
pub fn remove_stale(
    base: &Path,
    prefix: &str,
    tag: &str,
    owner: u32,
    alive: impl Fn(u32) -> Option<bool>,
) -> Result<Vec<PathBuf>, &'static str> {
    let stem = format!("chard-{prefix}-{tag}-");
    let own = std::process::id();
    let mut removed = Vec::new();
    let entries = std::fs::read_dir(base).expect("listing the directory a shared Work is made in");
    for entry in entries {
        let entry = entry.expect("a directory entry");
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.strip_prefix(&stem)) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        if pid == own || name.to_str() != Some(&format!("{stem}{pid}")) {
            continue;
        }
        let path = entry.path();
        // One read for both checks: a concurrent run may remove the directory at any point.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || std::os::unix::fs::MetadataExt::uid(&meta) != owner {
            continue;
        }
        match alive(pid) {
            Some(true) => continue,
            Some(false) => {}
            None => return Err("`kill` could not be run, so no process can be told to have ended"),
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => removed.push(path),
            // A concurrent run removed it first.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                let mut stderr = std::io::stderr().lock();
                let _ = stderr.write_all(
                    format!(
                        "\nchard: an ended run's directory {} was not removed: {e}\n",
                        path.display()
                    )
                    .as_bytes(),
                );
            }
        }
    }
    Ok(removed)
}

/// Whether process `pid` is running, read by `kill -0`, or `None` where `kill` cannot be
/// run. `kill -0` also fails for a process this user may not signal, which therefore reads
/// as not running; [`remove_stale`] removes only this user's directories for that reason.
///
/// The `kill` program, because the crate denies `unsafe` and so has no binding to the call.
/// A lock held by the live run would be the better sign, but `File::lock` is newer than the
/// declared MSRV.
pub fn process_alive(pid: u32) -> Option<bool> {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
        .map(|s| s.success())
}

/// How long a dropped [`Work`] lets a process that names its directory finish on its own
/// before the test fails. A fixture released at the end of a test (a gate opened, its parent
/// killed, its directory removed) exits at its next poll, tens of milliseconds later.
pub const LEFTOVER_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// A live process a [`Work`] found naming its directory, and by which channel.
#[derive(Debug, Clone)]
pub struct Leftover {
    pub pid: u32,
    /// The command line, its arguments joined by spaces.
    pub command: String,
    /// An argument names the directory or a path under it.
    pub by_args: bool,
    /// The working directory is the directory or under it.
    pub by_cwd: bool,
}

/// Why this process cannot see other processes' command lines and working directories, or
/// `None` where it can: `/proc` must exist and this process's own `cmdline` and `cwd` entries
/// must read back, since those are the two channels [`Work::leftover_processes`] reads. A
/// procfs that lacks either (the BSDs' has no `self`) reads as unable, not as empty.
pub fn processes_unseen() -> Option<&'static str> {
    if !Path::new("/proc").exists() {
        return Some("this system has no /proc, so no test's leftover processes are seen");
    }
    let lists = std::fs::read_dir("/proc").is_ok();
    let cmdline = std::fs::read("/proc/self/cmdline").is_ok();
    let cwd = std::fs::read_link("/proc/self/cwd").is_ok();
    if lists && cmdline && cwd {
        None
    } else {
        Some(
            "/proc exists but cannot be listed, or this process's own cmdline or cwd entry \
             cannot be read from it, so no test's leftover processes are seen",
        )
    }
}

impl Work {
    /// The live processes, other than this one, that name this directory, or why they
    /// cannot be seen ([`processes_unseen`]).
    pub fn leftover_processes(&self) -> Result<Vec<Leftover>, &'static str> {
        if let Some(why) = processes_unseen() {
            return Err(why);
        }
        let entries = std::fs::read_dir("/proc").map_err(|_| "/proc stopped being listable")?;
        let given = self.dir.as_os_str().as_encoded_bytes();
        let resolved = self.resolved.as_os_str().as_encoded_bytes();
        let spellings = [given, resolved];
        let own = std::process::id();
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == own {
                continue;
            }
            // An entry that cannot be read is a process that exited after the listing, or
            // one belonging to another user. A fixture this test started is neither: it runs
            // as this user, and this process's own entries were just read. A zombie reads an
            // empty command line and no working directory: it runs nothing.
            let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let by_args = cmdline
                .split(|&b| b == 0)
                .any(|arg| spellings.iter().any(|dir| names(arg, dir)));
            let by_cwd = std::fs::read_link(entry.path().join("cwd")).is_ok_and(|cwd| {
                let cwd = cwd.as_os_str().as_encoded_bytes();
                // A removed directory reads back with this suffix.
                let cwd = cwd.strip_suffix(b" (deleted)").unwrap_or(cwd);
                spellings.iter().any(|dir| within(cwd, dir))
            });
            if by_args || by_cwd {
                let command = String::from_utf8_lossy(&cmdline).replace('\0', " ");
                found.push(Leftover {
                    pid,
                    command: command.trim_end().to_owned(),
                    by_args,
                    by_cwd,
                });
            }
        }
        Ok(found)
    }
}

/// Is `path` the directory `dir` or a path under it?
fn within(path: &[u8], dir: &[u8]) -> bool {
    path.starts_with(dir) && matches!(path.get(dir.len()), None | Some(b'/'))
}

/// Does `arg` name `dir` or a path under it? An occurrence counts where the next byte is a
/// `/` or the end of the argument, so a sibling sharing the prefix does not.
fn names(arg: &[u8], dir: &[u8]) -> bool {
    !dir.is_empty()
        && arg.windows(dir.len()).enumerate().any(|(at, window)| {
            window == dir && matches!(arg.get(at + dir.len()), None | Some(b'/'))
        })
}

impl Drop for Work {
    fn drop(&mut self) {
        // Removed first: a bounded fixture loop also ends when its directory goes.
        let _ = std::fs::remove_dir_all(&self.dir);
        let deadline = std::time::Instant::now() + LEFTOVER_GRACE;
        let left = loop {
            let left = match self.leftover_processes() {
                Ok(left) => left,
                Err(why) => {
                    static ANNOUNCED: std::sync::Once = std::sync::Once::new();
                    ANNOUNCED.call_once(|| {
                        capability_gap("a process a test leaves running fails the test", why);
                    });
                    return;
                }
            };
            if left.is_empty() || std::time::Instant::now() >= deadline {
                break left;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        if left.is_empty() {
            return;
        }
        // Killed whether or not this test then fails, so a failing test does not leak
        // either. `kill` the program, because the crate denies `unsafe` and so has no
        // binding to the call; whether it took is read back from `/proc`, not assumed.
        for leftover in &left {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &leftover.pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        // A process killed while writing into the directory can leave it behind.
        let _ = std::fs::remove_dir_all(&self.dir);
        let pids: Vec<u32> = left.iter().map(|l| l.pid).collect();
        let settle = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let survivors: Vec<u32> = loop {
            let still: Vec<u32> = self
                .leftover_processes()
                .unwrap_or_default()
                .into_iter()
                .map(|l| l.pid)
                .filter(|pid| pids.contains(pid))
                .collect();
            if still.is_empty() || std::time::Instant::now() >= settle {
                break still;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let listed: Vec<String> = left
            .iter()
            .map(|l| format!("{}: {}", l.pid, l.command))
            .collect();
        let outcome = if survivors.is_empty() {
            "all were killed".to_owned()
        } else {
            format!("still running after `kill -KILL`, not killed: {survivors:?}")
        };
        let message = format!(
            "{} process(es) naming {} outlived the test by {LEFTOVER_GRACE:?}:\n  {}\n{outcome}",
            left.len(),
            self.dir.display(),
            listed.join("\n  ")
        );
        if std::thread::panicking() {
            // The test is already failing; a second panic would abort the binary.
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(format!("\nchard: {message}\n").as_bytes());
        } else {
            panic!("{message}");
        }
    }
}

/// The temporary files a publication of `output` has left beside it: every entry of its
/// directory named `<output>.partial` or `<output>.partial.<...>`. chard names one
/// `<output>.partial.<pid>.<n>`, which a check of the fixed `<output>.partial`
/// alone would never see. A directory that cannot be listed fails the test rather than
/// reading as empty.
pub fn temporary_files_beside(output: &Path) -> Vec<PathBuf> {
    let directory = output.parent().expect("an output in a directory");
    let name = output.file_name().expect("an output with a name");
    let mut fixed = name.to_owned();
    fixed.push(".partial");
    let mut numbered = fixed.clone();
    numbered.push(".");
    let (fixed, numbered) = (fixed.as_encoded_bytes(), numbered.as_encoded_bytes());
    std::fs::read_dir(directory)
        .expect("listing the output's directory")
        .map(|e| e.expect("a directory entry").file_name())
        .filter(|n| {
            let n = n.as_encoded_bytes();
            n == fixed || n.starts_with(numbered)
        })
        .map(|n| directory.join(n))
        .collect()
}

/// Write `body` under a `#!/bin/sh` line at `path`, mark it executable, and wait until
/// the kernel will run it.
///
/// The wait is the point, and the reason a test that writes a program it will run goes
/// through this in place of `std::fs::write`. `cargo test` runs tests on threads of one
/// process, and a thread that forks between another thread's `open` and `close` inherits
/// the write descriptor; until that child reaches its own `exec`, the file is open for
/// writing somewhere and `execve` on it fails with `ETXTBSY`. A wrapper that chard then
/// cannot run reads as a driver that did not answer, which is a real failure of a test
/// doing nothing wrong. `Shims::script` in `src/toolchain.rs` records the measurement
/// (three of seven tests failing one per run on Fedora 44 aarch64) and the argument that
/// one successful spawn is enough: the descriptor can only be held by children that
/// existed while the file was open, so once one exec has succeeded no later one can be
/// refused.
///
/// The probe spawn runs the script with no arguments and ignores its exit status; only
/// the spawn error matters. A body that cannot cope with no arguments should begin by
/// handling that case.
pub fn executable(path: &Path, body: &str) -> PathBuf {
    // ETXTBSY is 26 on Linux and on Darwin alike. Any other error is left to the caller:
    // a script that cannot be run for another reason is a broken test, and waiting on
    // it would hide that.
    const ETXTBSY: i32 = 26;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("writing the script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("marking the script executable");
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match std::process::Command::new(path).output() {
            Ok(_) => break,
            Err(why) if why.raw_os_error() == Some(ETXTBSY) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{} stayed busy for 5s; a descriptor is held open for writing \
                     somewhere that never execs",
                    path.display()
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(why) => panic!("running the script {}: {why}", path.display()),
        }
    }
    path.to_path_buf()
}

/// Is there a C compiler to measure with?
///
/// The environment precondition every compile-dependent test shares. It was written
/// twice, and the two had already diverged: `schema_conformance` additionally checked
/// that `chard` was built, `measurement_loop` did not, which is the shape the header
/// above warns about: not a copy that is wrong, a copy that answers a different
/// question under the same name.
///
/// Returns `false` only when the operator opted into skipping; otherwise [`refuse`]
/// panics.
pub fn require_cc(verifies: &str) -> bool {
    if std::process::Command::new("cc")
        .arg("--version")
        .output()
        .is_err()
    {
        refuse("no C compiler on PATH", verifies);
        return false;
    }
    true
}

/// Was the binary under test actually built?
///
/// Kept separate from [`require_cc`] for the reason `schema_conformance` gives at
/// length: a single hatch cannot tell "this box has no compiler" from "chard is
/// broken", and the second would then wear the first's exemption.
pub fn require_binary(binary: &Path, verifies: &str) -> bool {
    if !binary.exists() {
        refuse(&format!("{} is not built", binary.display()), verifies);
        return false;
    }
    true
}

/// Run a command that execs a file the test just wrote, waiting out `ETXTBSY`.
///
/// `cargo test` runs tests on threads of one process, and a thread that forks between
/// another thread's `open` and `close` of a file inherits the write descriptor; until that
/// child reaches its own `exec`, an `execve` of the file fails with `ETXTBSY`. A test that
/// writes an executable and then has the built `chard` run it therefore sees a spurious
/// `Text file busy` one run in several, and `src/toolchain.rs`'s test shim already waits
/// the same window out for the shims it writes. This is the shared form for the case where
/// chard is the one spawning: the invocation is retried while chard's own output reports
/// the busy errno, and any other outcome ends the wait, because the descriptor can only be
/// held by children that already existed when the file was open. Past the deadline the
/// last output is returned as it stands, so the test that reads it fails on the busy
/// message rather than on a silence.
pub fn output_waiting_out_etxtbsy(
    build: impl Fn() -> std::process::Command,
) -> std::process::Output {
    // 26 on Linux and on Darwin alike; matched on the rendered errno because it arrives
    // inside chard's envelope, several layers above the `io::Error` that carried it.
    const ETXTBSY_RENDERED: &str = "os error 26";
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let output = build().output().expect("spawning the command");
        let busy = String::from_utf8_lossy(&output.stdout).contains(ETXTBSY_RENDERED);
        if !busy || std::time::Instant::now() >= deadline {
            return output;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Every `.rs` file under `src`, recursively, named by its path relative to `src` with
/// `/` separators and sorted by that name.
///
/// The source scans (`tests/discarded_failures.rs`, `tests/untyped_errors.rs`, the schema's
/// name check) read `src/` through this one walk. Each read the top level alone before it,
/// which left a module directory such as `src/predicate/` outside every ratchet with
/// nothing to say so.
pub fn rust_sources(src: &Path) -> Vec<(String, PathBuf)> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, PathBuf)>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("a UTF-8 file name")
                .to_owned();
            if path.is_dir() {
                walk(&path, &format!("{prefix}{name}/"), out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((format!("{prefix}{name}"), path));
            }
        }
    }
    let mut out = Vec::new();
    walk(src, "", &mut out);
    out.sort();
    out
}
