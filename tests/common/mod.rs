// SPDX-License-Identifier: BSD-3-Clause

//! What the test suite does when it cannot run a test here.

#![allow(
    dead_code,
    reason = "a tests/common module is compiled separately into every integration-test binary \
              that declares it, so each binary sees the helpers the other binaries use as dead \
              code; the alternative is one module per consumer, the duplication this module \
              exists to prevent"
)]

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
pub const ELF_FIXTURE_COUNT: usize = 26;

/// How many tests have declined to run in this process.
static SKIPPED: AtomicUsize = AtomicUsize::new(0);

/// Did the operator opt into skipping? Private: [`refuse`] is the one caller, so a skip always
/// prints its banner and writes its ledger row. This is the variable's one read in the suite.
fn skip_allowed() -> bool {
    std::env::var_os("CHARD_ALLOW_TEST_SKIP").is_some()
}

/// Refuse to pretend a test ran: panic, or (if the operator opted in) announce it
/// unmissably and let the caller return.
///
/// # Panics
///
/// Panics unless `CHARD_ALLOW_TEST_SKIP` is set: that is the point.
pub fn refuse(reason: &str, verifies: &str) {
    assert!(
        skip_allowed(),
        "cannot run this test ({reason}); it verifies {verifies}; see CHARD_ALLOW_TEST_SKIP"
    );

    let n = SKIPPED.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let banner = format!(
        "\nchard: SKIPPED TEST #{n} — {reason}\n\
         chard:   this test verifies {verifies}, and that went unverified.\n\
         chard:   CHARD_ALLOW_TEST_SKIP is set, so this is not a failure. \
         A green run below does not mean this was checked.\n"
    );

    write_banner(&banner);
    record("skipped", &format!("{reason}; it verifies {verifies}"));
}

/// Write a banner whole to the real stderr under its lock, as [`refuse`] says why. A banner
/// that cannot be written fails the test rather than leave a skip, a gap or a regeneration
/// unannounced, except while the thread is already panicking: that test is failing anyway,
/// and a second panic would abort the binary. Only these three go through here, the banners a
/// gate that reads a run's output or the ledger's reader stands on (`scripts/test-ledger.sh`);
/// a test's own note to stderr (a seed, a count it also asserts) is a log line, and keeps
/// `chard::error::best_effort`.
fn write_banner(banner: &str) {
    let mut stderr = std::io::stderr().lock();
    let written = stderr
        .write_all(banner.as_bytes())
        .and_then(|()| stderr.flush());
    if let Err(e) = written {
        assert!(
            std::thread::panicking(),
            "writing a banner to stderr: {e}; it said:{banner}"
        );
    }
}

/// The longest file name the filesystem holding `dir` creates, in bytes: names from 255
/// down are created in `dir` and removed until one is taken.
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
                "creating a {length}-byte name in {} failed, not on its length: {e}",
                dir.display()
            ),
        }
    }
    panic!("{} takes no name of one byte", dir.display());
}

/// Announce an arm that could not run because the *toolchain* lacks a capability.
pub fn capability_gap(arm: &str, why: &str) {
    write_banner(&format!("\nchard: arm not exercised — {arm}: {why}\n"));
    record("gap", &format!("{arm}: {why}"));
}

/// The directory every test binary of one build appends its unexercised arms to, read back
/// by `scripts/test-ledger.sh` after `make test`.
pub const LEDGER_DIR: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/test-ledger");

/// The test binary this process runs: what [`record`] names the ledger file by, and what a
/// test runs again to see what a helper prints in a process of its own. Not the chard binary,
/// which [`chard_binary`] finds.
pub fn this_test_binary() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// Append one line to this process's ledger file: a kind, the test binary, and the text.
pub fn record(kind: &str, text: &str) {
    let binary = this_test_binary()
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
        chard::error::best_effort(writeln!(
            stderr,
            "chard: the test ledger {} could not be written: {e}",
            file.display()
        ));
    }
}

/// The compiler family a gate requires `cc` to be, from `CHARD_TEST_EXPECT_CC`, or `None`.
pub fn expected_compiler() -> Option<String> {
    std::env::var("CHARD_TEST_EXPECT_CC")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Does the host's `cc` emit ELF?
pub const ELF_HOST: bool = cfg!(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd"
));

/// A scratch directory that removes itself.
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
    pub fn shared(prefix: &str, tag: &str) -> SharedWork {
        let base = std::env::temp_dir();
        let own = base.join(format!("chard-{prefix}-{tag}-{}", std::process::id()));
        removed(std::fs::remove_dir_all(&own), &own);
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
                chard::error::best_effort(
                    stderr.write_all(
                        format!(
                            "\nchard: an ended run's directory {} was not removed: {e}\n",
                            path.display()
                        )
                        .as_bytes(),
                    ),
                );
            }
        }
    }
    Ok(removed)
}

/// Whether process `pid` is running, read by `kill -0`, or `None` where `kill` cannot be
/// run. `kill -0` also fails for a process this user may not signal, which therefore reads
/// as not running; [`remove_stale`] removes only this user's directories for that reason.
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
    pub fn leftover_processes(&self) -> Result<Vec<Leftover>, String> {
        if let Some(why) = processes_unseen() {
            return Err(why.to_owned());
        }
        let entries =
            std::fs::read_dir("/proc").map_err(|e| format!("/proc stopped being listable: {e}"))?;
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
            // one belonging to another user.
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

/// Judges the removal of a test's own scratch path, the result of a `remove_dir_all` or a
/// `remove_file` of `path`: a path already gone is the state the cleanup wants, and any other
/// error fails the test, so a directory that will not empty is found by the test that left it
/// rather than read by the next. While the thread is already panicking the error is written
/// to stderr instead, since a second panic would abort the test binary.
#[track_caller]
pub fn removed(result: std::io::Result<()>, path: &Path) {
    let e = match result {
        Ok(()) => return,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => e,
    };
    let message = format!("removing {}: {e}", path.display());
    if std::thread::panicking() {
        let mut stderr = std::io::stderr().lock();
        chard::error::best_effort(writeln!(stderr, "\nchard: {message}"));
    } else {
        panic!("{message}");
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        // Removed first: a bounded fixture loop also ends when its directory goes.
        let first = std::fs::remove_dir_all(&self.dir);
        let deadline = std::time::Instant::now() + LEFTOVER_GRACE;
        let left = loop {
            let left = match self.leftover_processes() {
                Ok(left) => left,
                Err(why) => {
                    static ANNOUNCED: std::sync::Once = std::sync::Once::new();
                    removed(
                        first.or_else(|_| std::fs::remove_dir_all(&self.dir)),
                        &self.dir,
                    );
                    // After the removal, and forced: a banner that fails to write panics in
                    // the closure, which would otherwise leave the directory and poison the
                    // `Once` for every later drop, a panic while panicking among them.
                    ANNOUNCED.call_once_force(|_| {
                        capability_gap("a process a test leaves running fails the test", &why);
                    });
                    return;
                }
            };
            if left.is_empty() || std::time::Instant::now() >= deadline {
                break left;
            }
            #[expect(
                clippy::disallowed_methods,
                reason = "the condition is that no process names the directory, read from /proc, \
                          which offers nothing to wait on: re-reading it between sleeps, up to \
                          LEFTOVER_GRACE, is the wait"
            )]
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        if left.is_empty() {
            removed(
                first.or_else(|_| std::fs::remove_dir_all(&self.dir)),
                &self.dir,
            );
            return;
        }
        // Killed whether or not this test then fails, so a failing test does not leak
        // either.
        for leftover in &left {
            chard::error::best_effort(
                std::process::Command::new("kill")
                    .args(["-KILL", &leftover.pid.to_string()])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status(),
            );
        }
        // A process killed while writing into the directory can leave it behind.
        let second = match std::fs::remove_dir_all(&self.dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                format!("\nand the directory was not removed: {e}")
            }
            Ok(()) | Err(_) => String::new(),
        };
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
            #[expect(
                clippy::disallowed_methods,
                reason = "the condition is that the killed processes have left /proc, which offers \
                          nothing to wait on: re-reading it between sleeps, up to a second, is the \
                          wait"
            )]
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
            "{} process(es) naming {} outlived the test by {LEFTOVER_GRACE:?}:\n  {}\n{outcome}{second}",
            left.len(),
            self.dir.display(),
            listed.join("\n  ")
        );
        if std::thread::panicking() {
            // The test is already failing; a second panic would abort the binary.
            let mut stderr = std::io::stderr().lock();
            chard::error::best_effort(stderr.write_all(format!("\nchard: {message}\n").as_bytes()));
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
pub fn executable(path: &Path, body: &str) -> PathBuf {
    // ETXTBSY is 26 on Linux and on Darwin alike.
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
                    "{} stayed busy for 5s",
                    path.display()
                );
                #[expect(
                    clippy::disallowed_methods,
                    reason = "the condition is a sibling test's fork closing its copy of the write \
                              descriptor, which nothing here can wait on: retrying the exec \
                              between sleeps, under the 5 s deadline, is the wait"
                )]
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(why) => panic!("running the script {}: {why}", path.display()),
        }
    }
    path.to_path_buf()
}

/// Is there a C compiler to measure with?
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

/// The `chard` binary under test: the path cargo hands integration tests at compile time
/// (`CARGO_BIN_EXE_chard`), where it built the binary whatever the target directory or the
/// build-dir layout. A test binary's own path says neither: derived from `current_exe`, it
/// assumed the test binaries sit in `deps/` beside the binary, which cargo 1.101's build-dir
/// moved, and every test behind [`require_binary`] refused. No test derives the path another
/// way.
pub fn chard_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chard"))
}

/// Was the binary under test actually built?
pub fn require_binary(binary: &Path, verifies: &str) -> bool {
    if !binary.exists() {
        refuse(&format!("{} is not built", binary.display()), verifies);
        return false;
    }
    true
}

/// Run a command that execs a file the test just wrote, waiting out `ETXTBSY`.
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
        #[expect(
            clippy::disallowed_methods,
            reason = "the condition is a sibling test's fork closing its copy of the write \
                      descriptor, which nothing here can wait on: retrying the command between \
                      sleeps, under the 5 s deadline, is the wait"
        )]
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Every `.rs` file under `src`, recursively, named by its path relative to `src` with
/// `/` separators and sorted by that name.
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
