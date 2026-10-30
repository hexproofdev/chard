// SPDX-License-Identifier: BSD-3-Clause

//! Invoking the toolchain under test.
//!
//! Two operations, because two channels need different things from the compiler:
//! [`build`] produces an artifact for the `elf-static` and `runtime` channels,
//! and [`macro_dump`] preprocesses for the `macro` channel. Both record the full
//! argv verbatim so any verdict in a report can be re-derived by hand.
//!
//! For the `compiler-diag` channel the [`BuildRecord`] *is* the observable —
//! whether the compiler warned, errored, or said nothing at all leaves no trace
//! in any binary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::digest;

/// Headers preprocessed for the with-libc macro dump. `__GLIBC__` and
/// `__USE_FORTIFY_LEVEL` are defined by libc headers, not by the compiler, so a
/// bare `-dM -E` on empty input cannot see them — and `__USE_FORTIFY_LEVEL` is
/// the single most useful macro chard reads, because it is the level glibc
/// *actually settled on* rather than the one the command line asked for.
/// The synthetic translation unit whose macro dump identifies the C library.
///
/// `<features.h>` is glibc's and exists nowhere else, so including it unconditionally made
/// this file a **fatal error** on Darwin — `fatal error: 'features.h' file not found`, exit
/// 1 — and the macro channel there worked only because clang keeps preprocessing and dumps
/// its macros anyway. Measured on Apple clang 21: 3047 `#define` lines on stdout beside a
/// fatal error on stderr. Every macro-channel check on that platform rested on the driver
/// choosing to continue past an error it called fatal, and a future clang that stops
/// instead would have taken all of them down at once, silently.
///
/// The guard is nested rather than `defined(__has_include) && __has_include(...)`, because
/// a preprocessor without `__has_include` would expand the second operand of the `&&`
/// before short-circuiting and fail on the syntax.
///
/// Costs nothing where it is present: the dump is byte-identical with and without the
/// explicit include on gcc 16 / glibc, clang 22 / glibc and musl-gcc, because every glibc
/// header pulls `<features.h>` in for itself. The include earns its place by making the
/// dependency explicit, not by being the only path to `__GLIBC__`.
const LIBC_PROBE_HEADERS: &str = "#if defined(__has_include)\n\
                                  #  if __has_include(<features.h>)\n\
                                  #    include <features.h>\n\
                                  #  endif\n\
                                  #endif\n\
                                  #include <stdio.h>\n\
                                  #include <stdlib.h>\n\
                                  #include <string.h>\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    pub argv: Vec<String>,
    /// Profile flags the harness removed before invoking the driver, because they cannot
    /// coexist with this probe's output kind — `-pie` against `-shared`, and the rest of
    /// [`crate::probe::LinkMode::conflicts_with`].
    ///
    /// Empty for almost every build, and serialized only when it is not, but it must exist:
    /// without it `profile.cflags` names a flag list that some builds did not use, and a
    /// reader comparing the two has no way to tell a deliberate resolution from a harness
    /// bug. That is the same defect as appending a flag over a stated one (a report naming
    /// a flag list it did not measure), in the half that removes rather than adds.
    ///
    /// Recorded per build rather than on the profile because the conflict is a property of
    /// the probe's link mode: the same profile drops `-pie` for a shared-object probe and
    /// keeps it for every executable one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub dropped_flags: Vec<String>,
    pub exit_status: i32,
    pub stdout: String,
    pub stderr: String,
    /// The child's lifetime in whole milliseconds, measured to where it was reaped and
    /// not to where we finished reading its pipes. `0` means under a millisecond.
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    /// SHA-256 of the job's standard output with its lines sorted ([`dump_digest`]), set on a
    /// `-dM -E` dump record as the report publishes it, where `stdout` itself is replaced by a
    /// count of the defines.
    ///
    /// The digest is the key of the dump's `macro-dump` entry in the report's `facts` store,
    /// so the filtered macros a verdict was read from are named by the lines they were parsed
    /// out of. `None` on every other record, and on the record a detector reads, which still
    /// carries the dump itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_sha256: Option<String>,
    /// Whether the job's standard output ended partway through a line: text other than
    /// whitespace followed its last newline, or made up the whole output where it printed
    /// none. Set by [`invoke`] from the text it read, before `stdout` is stored with its
    /// trailing whitespace trimmed, which leaves no other trace of it. Serialized only where
    /// it is true.
    ///
    /// A `-dM -E` listing ends each define with a newline (measured over an empty unit and
    /// `<stdio.h>` with gcc 11, 12, 13, 14, 15 and 16 and clang 14, 18, 22 and 23 on Linux and
    /// Apple clang 21 on macOS), so a dump whose last line is unterminated was cut off, for
    /// example by a closed pipe, a signal, or a filesystem that filled. A driver whose whole
    /// listing lacked the final newline would have every dump read as failed (withheld,
    /// refused or named as below), never `off`. Its last line may be a define cut short, `#define __GLIBC_MINOR__ 4` from
    /// `43`, and the status says nothing of it: gcc 16.1.1's driver exits 0 when its `cc1` dies
    /// of a closed pipe under `-wrapper` with its stdout cut mid-line, and 1 when a signal kills
    /// the `cc1` (Fedora 44 x86_64). So [`Self::whole_stdout`] drops that line before a dump is
    /// parsed, and [`Self::dump_failure`] reads such a dump as failed whatever its status.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stdout_unterminated: bool,
}

/// How a job that recorded `exit_status` ended: `exited N`, or `was killed by a signal` for
/// the `-1` [`invoke`] records where the child has no exit code (a real `exit(-1)` reads 255
/// on Unix). [`BuildRecord::ended`] reads it, and so does a status kept apart from its record
/// (`toolchain::ProfileDump`'s), so the sentinel has one spelling wherever it is published.
#[must_use]
pub fn ended(exit_status: i32) -> String {
    if exit_status == -1 {
        "was killed by a signal".to_owned()
    } else {
        format!("exited {exit_status}")
    }
}

/// No published sentence spells a job's status by hand: every "exited N" goes through
/// [`ended`], so the `-1` sentinel is never "exited -1". A text scan, as
/// `tests/discarded_failures.rs` is, for the two spellings that bypass [`ended`].
/// `(exit {}` and not `exit {}`: chard's own exit code is a number, not a job's status.
#[cfg(test)]
#[test]
fn every_exit_status_is_spelled_by_ended() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![src.clone()];
    let mut scanned = 0;
    let mut offenders = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                scanned += 1;
                if path == src.join("compile.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("a source file");
                for (n, line) in text.lines().enumerate() {
                    if line.contains("exited {") || line.contains("(exit {}") {
                        offenders.push(format!("{}:{}", path.display(), n + 1));
                    }
                }
            }
        }
    }
    assert!(scanned > 20, "the scan read the tree: {scanned} files");
    assert!(
        offenders.is_empty(),
        "spell these through compile::ended: {offenders:?}"
    );
}

impl BuildRecord {
    pub fn succeeded(&self) -> bool {
        self.exit_status == 0
    }

    /// How the job ended, in [`ended`]'s words.
    #[must_use]
    pub fn ended(&self) -> String {
        ended(self.exit_status)
    }

    /// How a job that did not succeed ended ([`Self::ended`]) and the
    /// [`Self::first_stderr_line`] after a colon where there is one; `None` for a job that
    /// exited 0. A `-dM -E` dump is read through [`Self::dump_failure`], which adds the dump
    /// that exited 0 with its output cut off.
    #[must_use]
    pub fn failure(&self, workdir: Option<&Path>) -> Option<String> {
        if self.succeeded() {
            return None;
        }
        let excerpt = self
            .first_stderr_line(workdir)
            .map_or_else(String::new, |line| format!(": {line}"));
        Some(format!("{}{excerpt}", self.ended()))
    }

    /// Why a `-dM -E` dump is not read as a whole listing: its [`Self::failure`], or, for one
    /// that exited 0, its output cut off partway through a line ([`Self::stdout_unterminated`]);
    /// `None` for a dump that exited 0 with its last line ended.
    ///
    /// The one reading of "did this `-dM -E` dump fail" and of the sentence that says so:
    /// a variant's dump (`report::Variant::macro_dump_failure`) and the two `toolchain::detect`
    /// takes (the intrinsic one, refused, and the with-headers one, published as
    /// `libc_headers_error` and named in the libc's detection) all ask it, so the detection
    /// and the measurement cannot disagree about whether a dump failed. The dumps under the
    /// profile's flags publish their status and [`Self::stdout_unterminated`] whole, and
    /// `toolchain::ProfileMacroWitness` reads either as `dump-failed`, so a listing cut under a
    /// driver that exited on its own is never read as whole.
    #[must_use]
    pub fn dump_failure(&self, workdir: Option<&Path>) -> Option<String> {
        self.failure(workdir).or_else(|| {
            self.stdout_unterminated
                .then(|| format!("{} {CUT_OFF}", self.ended()))
        })
    }

    /// `stdout` without its last line where the job's output ended partway through it
    /// ([`Self::stdout_unterminated`]), and whole otherwise, whatever the status: what a dump
    /// is parsed from.
    ///
    /// Only the unterminated line goes. A reader that keyed on the status instead would go
    /// wrong both ways: a line cut under a driver that exited on its own would read as a
    /// define, and a whole last line a signal followed would be dropped. Dropping the last
    /// line of every failed dump would drop whichever define gcc's identifier-table order
    /// listed last, and a `__GLIBC__` listed last would read the library as `unknown`.
    #[must_use]
    pub fn whole_stdout(&self) -> &str {
        if self.stdout_unterminated {
            self.stdout.rsplit_once('\n').map_or("", |(whole, _)| whole)
        } else {
            &self.stdout
        }
    }

    /// The first non-empty line of stderr as the report publishes it, trimmed and cut
    /// at 200 characters.
    ///
    /// What a one-line reason quotes when it names a failed job: the compiler's first
    /// line is the fatal error, and a reader who needs more has the record itself. The
    /// line is rewritten for publication (`measure::publish_text`, against `workdir`)
    /// before it is cut, so the 200 characters are the same 200 under every `--workdir`.
    /// Cut first, a long work directory would spend the budget on a prefix the published
    /// reason does not carry. `None` for `workdir` is a
    /// record whose paths are already published.
    #[must_use]
    pub fn first_stderr_line(&self, workdir: Option<&Path>) -> Option<String> {
        self.stderr
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| {
                crate::measure::publish_text(line, workdir.unwrap_or(Path::new("")))
                    .chars()
                    .take(200)
                    .collect::<String>()
            })
    }

    /// A copy for publication, with every path under `workdir` made relative to it.
    ///
    /// The driver is invoked with absolute paths, because the operator's own flags are
    /// resolved against the operator's working directory and changing the child's
    /// directory would change their meaning; `-include foo.h` in a `--flags` list is
    /// the ordinary case. What is *recorded* is another matter. An absolute work
    /// directory in every `argv` and every diagnostic is host detail a published report
    /// has no use for, and it is what made two runs of one measurement differ in every
    /// build line. Relative to the work directory, `argv` is re-runnable from inside it
    /// and identical wherever it was produced.
    ///
    /// Applied to the copy the report carries and never to the record a detector reads,
    /// which stays as captured: see `measure::publish`.
    #[must_use]
    pub fn relative_to(&self, workdir: &Path) -> Self {
        Self {
            argv: self
                .argv
                .iter()
                .map(|arg| relativize(arg, workdir))
                .collect(),
            dropped_flags: self.dropped_flags.clone(),
            exit_status: self.exit_status,
            stdout: relativize(&self.stdout, workdir),
            stderr: relativize(&self.stderr, workdir),
            duration_ms: self.duration_ms,
            artifact_sha256: self.artifact_sha256.clone(),
            stdout_sha256: self.stdout_sha256.clone(),
            stdout_unterminated: self.stdout_unterminated,
        }
    }

    /// Case-insensitive search of compiler diagnostics — the observable for the
    /// `compiler-diag` channel.
    pub fn diagnostics_contain(&self, needle: &str) -> bool {
        self.stderr.to_lowercase().contains(&needle.to_lowercase())
    }
}

/// `text` with every path under `workdir` made relative to it.
///
/// `workdir/name` becomes `name` and a bare `workdir` becomes `.`, so `-o /work/probe`
/// reads `-o probe`, `-L/work` reads `-L.`, and a diagnostic's `/work/probe.c:3:5:`
/// reads `probe.c:3:5:`. Textual, and deliberately so: the callers hold argv entries,
/// compiler stderr and detector summaries, and the one thing they share is that the
/// work directory's absolute spelling appears in them verbatim.
///
/// Matched on whole path components. The spelling has to be followed by `/`, by the end
/// of the text, or by a character that cannot continue a component (whitespace, or the
/// punctuation a diagnostic or an option closes a path with), so a work directory
/// `/tmp/wd` leaves `/tmp/wd2/x.c` and `/tmp/wd.bak` as written. As a substring
/// replacement it rewrote the first to `.2/x.c`, in published argv and stderr alike,
/// which is evidence corrupted rather than trimmed.
#[must_use]
pub fn relativize(text: &str, workdir: &Path) -> String {
    let root = workdir.display().to_string();
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(root) {
        out.push_str(rest.get(..at).unwrap_or(""));
        let tail = rest.get(at.saturating_add(root.len())..).unwrap_or("");
        if let Some(under) = tail.strip_prefix('/') {
            // `workdir/name` reads `name`, and `workdir/` alone reads `.`.
            if under.is_empty() {
                out.push('.');
            }
            rest = under;
        } else if tail.chars().next().is_none_or(ends_component) {
            out.push('.');
            rest = tail;
        } else {
            // A longer path that shares the prefix is kept as written.
            out.push_str(root);
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// A character that cannot continue a path component: whitespace, or the punctuation
/// a diagnostic or an option closes a path with.
fn ends_component(c: char) -> bool {
    c.is_whitespace() || matches!(c, '/' | ':' | '\'' | '"' | ')' | ',' | ';' | '=' | '>')
}

/// How long any single toolchain or package-manager invocation may take.
///
/// `.output()` waits forever, and every measurement chard takes runs through here. A
/// compiler that wedges (a bad `-specs` file, an NFS stall, a package manager holding a
/// lock nobody will release) would hang the whole sweep with no diagnostic, and on an
/// 18-guest run the symptom is one lane that never returns.
///
/// 120 seconds is set against measurement rather than taste. Across the 5,204 compiler
/// and package-manager invocations of a sweep, the slowest was **451 ms**
/// (`clang++`), the p99 was 144 ms and the median 22 ms. So this is 266x the observed
/// maximum: far too loose to fire on a loaded box — which this one is, being shared —
/// and still a bound.
pub const INVOKE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the output threads once the child itself has been reaped.
///
/// `try_wait` returning a status means the *child* is gone, not that its pipes are
/// closed: anything that inherited the write end holds them open, and `join()` on a
/// reader parked in `read` carries no deadline of its own. So `INVOKE_TIMEOUT` did not
/// bound this function at all. Demonstrated, against this code: `sh -c 'sleep 30 & exit
/// 0'` under a 400 ms bound returned after 30.0 s, because the backgrounded `sleep` still
/// held stdout — 75x the bound the caller asked for. In the field the shape is a
/// compiler wrapper that leaves a server behind, `sccache` and `distcc` being the ones
/// that turn up as `CC` on a build host.
///
/// Charged separately rather than against what is left of `INVOKE_TIMEOUT`: a compile
/// that legitimately finishes at 119.9 s must not fail because there was no budget left
/// to read what it wrote. The call is then bounded by `INVOKE_TIMEOUT + DRAIN_GRACE`,
/// which is still a bound.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Read a child's pipe to the end, on a thread of its own.
///
/// A read error leaves whatever arrived before it. Partial output is still evidence and the
/// exit status is recorded separately, so there is nothing here to propagate.
fn drain<R: std::io::Read>(mut pipe: R) -> Vec<u8> {
    let mut buf = Vec::new();
    crate::error::best_effort(pipe.read_to_end(&mut buf));
    buf
}

/// The variables of chard's own environment a toolchain invocation is handed, when chard has
/// them: `PATH` alone.
///
/// Every toolchain invocation chard makes runs under a cleared environment holding these, the
/// run's `--env` pairs and [`COMPILER_ENV_PINNED`], and nothing else
/// ([`compiler_environment`], applied in [`invoke_with_timeout`], so probe builds, macro
/// dumps and the driver, linker and loader
/// probes all see the same environment). The probes run under a cleared environment too;
/// `run::PROBE_ENVIRONMENT` says why. `PATH` is passed because the drivers need it:
/// gcc finds `as` and `ld` through it (`gcc -print-prog-name=as` prints a bare `as`), clang
/// finds the linker through it, and a `ccache` masquerade directory finds the compiler behind
/// it through it. It is also the one variable chard reads itself, to resolve `--cc`.
///
/// Measured before the change, 2026-10-11: on Fedora 44 x86_64 `gcc` and `clang` (both
/// through `ccache` 4.12.3's masquerade directory) compile under `env -i` with `PATH`,
/// `LC_ALL=C` and `TERM=dumb`, `ccache` finding the same cache directory without `HOME`; on
/// arm64 macOS, Apple clang 21.0.0 from the Command Line Tools compiles, links and runs a C
/// program under `env -i` with `PATH` alone and compiles one with no variable at all, and
/// `-###` names the same triple, SDK version and `-isysroot` as with the shell's environment. Apple's `xcrun` shim reads
/// `DEVELOPER_DIR` (a value naming no directory fails the compile, exit 1); without it the
/// shim uses the developer directory `xcode-select` names. A host that chose its Xcode with
/// `DEVELOPER_DIR` names that Xcode's compiler as `--cc` instead.
///
/// The cost is a toolchain that cannot run without a variable: a compiler built against
/// libraries it finds only through `LD_LIBRARY_PATH`, as some module systems arrange, fails
/// every invocation. Measured 2026-10-11 on Fedora 44 x86_64 with a stand-in `gcc` that
/// exits 1 with the loader's message when `LD_LIBRARY_PATH` is unset, run under `measure
/// --profile bare` with it set: before the clear the report published as usual; after it
/// chard refuses the measurement (exit 2, "produced no predefined macros") and publishes no
/// report, and the refusal's hint spells this environment as an `env -i` command.
pub const COMPILER_ENV_PASSED: &[&str] = &["PATH"];

/// The environment every toolchain invocation receives, in the order it is applied:
/// [`COMPILER_ENV_PASSED`] as chard has them, then the run's `--env` pairs ([`ADDED`]), then
/// [`COMPILER_ENV_PINNED`].
///
/// A passed variable chard does not have is absent, not empty: an empty `PATH` and an unset
/// one are searched differently. A pair can name neither a passed variable nor a pin
/// ([`compiler_environment_additions`] refuses both), and the pins come last besides, so a
/// later entry replacing an earlier one never decides what a driver receives.
///
/// Reading it fixes the run's pairs ([`RunEnvironment::get`]).
pub fn compiler_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    compiler_environment_from(|name| std::env::var_os(name), ADDED.get())
}

/// `--env` pairs that passed [`compiler_environment_additions`], which is the only way to
/// make one with any pair in it: no name passed or pinned or given twice, every name
/// portable, no NUL and no relative path in a value, sorted by name. What reads the pairs
/// takes this type, so a pair that names a pin (which the published `set` would show as the
/// pin, and [`CompilerEnvironment::added`] would leave out of `profile.id`'s digest) cannot
/// reach it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvPairs(Vec<(String, String)>);

impl EnvPairs {
    /// The pairs, sorted by name.
    #[must_use]
    pub fn as_slice(&self) -> &[(String, String)] {
        &self.0
    }
}

/// [`compiler_environment`] with chard's own environment read through `lookup` and the
/// pairs given as `added`, so a test can hand it one that lacks a passed variable and pairs
/// of its own without setting the run's.
pub fn compiler_environment_from(
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    added: &EnvPairs,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    COMPILER_ENV_PASSED
        .iter()
        .filter_map(|name| lookup(name).map(|value| ((*name).into(), value)))
        .chain(
            added
                .as_slice()
                .iter()
                .map(|(name, value)| (name.into(), value.into())),
        )
        .chain(
            COMPILER_ENV_PINNED
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into())),
        )
        .collect()
}

/// The run's `--env` pairs: variables the operator wrote in the invocation, which every
/// toolchain invocation of the run receives ([`compiler_environment`]) and
/// `profile.compiler_environment` publishes with their values.
///
/// They are how a toolchain configured through its environment is measured as configured.
/// nixpkgs' cc-wrapper applies its hardening from `NIX_HARDENING_ENABLE`, and only for a
/// role nix-shell's setup hooks switch on (`NIX_CC_WRAPPER_TARGET_HOST_<triple>=1`, and
/// `NIX_BINTOOLS_WRAPPER_TARGET_HOST_<triple>=1` for the linker wrapper's `bindnow` and
/// `relro`); under the cleared environment alone it adds none. Measured 2026-10-12 on the
/// 26.05 release of the Nix distribution, x86_64, gcc 15.3.0 and clang 21.1.8 wrappers:
/// the `on` count under `bare` was 22 before the clear and 14 after; with those three pairs it is 22
/// again, every verdict and level of the six cells equal to the run before the clear, and
/// with `NIX_HARDENING_ENABLE` alone it stays 14. The value comes from the invocation and
/// never from chard's own environment, so the report and the command line that made it say
/// the same thing; chard still reads nothing of its environment but `PATH`.
///
/// `measure` sets them once, at the door, before the toolchain is first run. The first read
/// fixes the value, the empty list when nothing was set, so a set after any invocation has
/// read it is an error ([`RunEnvironment::set`]) rather than a run whose early invocations
/// and report saw another environment than its later ones.
static ADDED: RunEnvironment = RunEnvironment::new();

/// A list of pairs set at most once and fixed by its first read. [`ADDED`] is the one chard
/// uses; a test makes its own to show that a set after a read fails.
#[derive(Debug, Default)]
pub struct RunEnvironment(std::sync::OnceLock<EnvPairs>);

impl RunEnvironment {
    #[must_use]
    pub const fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }

    /// Set the pairs.
    ///
    /// # Errors
    ///
    /// When they were set before, or read before: a read fixes the empty list, and an
    /// invocation that ran under it has already been measured without these.
    pub fn set(&self, pairs: EnvPairs) -> Result<()> {
        self.0.set(pairs).map_err(|_refused| {
            anyhow::anyhow!(
                "the compiler environment's --env pairs were set after a toolchain invocation \
                 had read them, or set twice"
            )
        })
    }

    /// The pairs, none when none was set; fixed from the first call on.
    pub fn get(&self) -> &EnvPairs {
        self.0.get_or_init(EnvPairs::default)
    }
}

/// Set the run's `--env` pairs, as [`compiler_environment_additions`] returns them.
///
/// # Errors
///
/// [`RunEnvironment::set`]'s: called after a toolchain invocation, or twice.
pub fn add_to_compiler_environment(pairs: EnvPairs) -> Result<()> {
    ADDED.set(pairs)
}

/// Read `--env NAME=VALUE` arguments into the pairs [`add_to_compiler_environment`] takes,
/// sorted by name, refusing what the compiler's environment cannot honour as written.
///
/// Refused, every one named in a single error: an argument with no `=`; a name that is not
/// a portable shell name (a letter or `_`, then letters, digits and `_`), which is also what
/// keeps the published `env -i` spelling one word per name; a name chard passes
/// ([`COMPILER_ENV_PASSED`]) or pins ([`COMPILER_ENV_PINNED`]), since `PATH` comes from
/// chard's own environment and a pin is what the diagnostic channels read under; a name
/// given twice, whose value would be whichever came last; a NUL in a value, which no
/// environment can hold; and a value holding a relative path ([`relative_path_in_value`]),
/// for [`relative_path_arguments`]' reason: chard runs the toolchain in its own directory
/// for the interrogations and in the work directory for the builds, so one relative path
/// names two directories and one report describes two toolchains. An empty value is a
/// value, and is kept.
///
/// # Errors
///
/// A [`crate::error::ConfigError`] naming each refused argument and why.
pub fn compiler_environment_additions(args: &[String]) -> Result<EnvPairs> {
    let portable = |name: &str| {
        let mut chars = name.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let mut refused = Vec::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    for arg in args {
        let Some((name, value)) = arg.split_once('=') else {
            refused.push(format!("{arg:?} has no `=`; --env takes NAME=VALUE"));
            continue;
        };
        if !portable(name) {
            refused.push(format!(
                "{arg:?}: {name:?} is not a portable variable name (a letter or `_`, then \
                 letters, digits and `_`)"
            ));
        } else if COMPILER_ENV_PASSED.contains(&name) {
            refused.push(format!(
                "{arg:?}: {name} is passed to the compiler from chard's own environment"
            ));
        } else if COMPILER_ENV_PINNED
            .iter()
            .any(|(pinned, _)| *pinned == name)
        {
            refused.push(format!(
                "{arg:?}: {name} is pinned for every compiler invocation, because the \
                 compiler-diag channel reads its diagnostics under that value"
            ));
        } else if value.contains('\0') {
            refused.push(format!("{arg:?}: the value holds a NUL"));
        } else if let Some(found) = relative_path_in_value(value, Path::exists) {
            let path = found.argument;
            refused.push(match found.reading.note() {
                Some(note) => format!("{arg:?}: {path:?}, {note}"),
                None => format!(
                    "{arg:?}: {path:?} is a relative path, which the toolchain would read \
                     against chard's directory in some invocations and the work directory in \
                     others; write it absolute (a word that is not a path but names a file in \
                     chard's directory is read as one: run chard from another directory)"
                ),
            });
        } else if pairs.iter().any(|(given, _)| given == name) {
            refused.push(format!("{arg:?}: {name} is given more than once"));
        } else {
            pairs.push((name.to_owned(), value.to_owned()));
        }
    }
    if !refused.is_empty() {
        return Err(
            crate::error::ConfigError(format!("refusing --env: {}", refused.join("; "))).into(),
        );
    }
    pairs.sort();
    Ok(EnvPairs(pairs))
}

/// The first relative path in an `--env` value, with how it was read, or `None`.
///
/// A value is read as words (split on whitespace) for the flags a wrapper variable can carry,
/// held to [`relative_path_readings`], and as entries (split on `:` and whitespace) for the
/// path lists a search variable carries. An entry is a relative path where it is `.` or `..`,
/// holds a `/` without starting with one, or names something that `exists` in chard's
/// directory; an entry that begins with `-`, `=` or `$` is a flag, a sysroot path or a
/// reference, and is left to the word reading. Which variables a toolchain reads as paths is
/// the toolchain's own (`COMPILER_PATH`, `LIBRARY_PATH`, a wrapper's own), so the rule is on
/// the shape of the value and not on its name; a bare word that happens to name a file in
/// chard's directory is refused with it, and the refusal says so.
pub fn relative_path_in_value(value: &str, exists: impl Fn(&Path) -> bool) -> Option<RelativePath> {
    let words: Vec<String> = value.split_ascii_whitespace().map(str::to_owned).collect();
    if let Some(found) = relative_path_readings(&words).into_iter().next() {
        return Some(found);
    }
    value
        .split(|c: char| c == ':' || c.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty() && !entry.starts_with(['-', '=', '$']))
        .find(|entry| {
            let path = Path::new(entry);
            path.is_relative()
                && (*entry == "." || *entry == ".." || entry.contains('/') || exists(path))
        })
        .map(|entry| RelativePath {
            argument: entry.to_owned(),
            reading: PathReading::Relative,
        })
}

/// The environment the run's toolchain invocations received, as `profile.compiler_environment`
/// publishes it: built from the list [`compiler_environment`] hands every spawn, so the report
/// and the spawns read one value.
///
/// A passed variable is published by name, its value withheld: chard's `PATH` names the
/// operator's directories, and the report says the driver was handed it. A variable chard set
/// is published with its value: the pins are chard's, and the `--env` pairs are the operator's
/// own words from the invocation, so a reader re-running a measurement has every value it
/// needs except `PATH`. Every value is published as written, so none is a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompilerEnvironment {
    /// The [`COMPILER_ENV_PASSED`] names chard had and handed over.
    pub passed: Vec<String>,
    /// Every variable set to a value: the `--env` pairs and [`COMPILER_ENV_PINNED`].
    pub set: BTreeMap<String, String>,
    /// The `--env` pairs alone, kept as given rather than recovered from `set`.
    #[serde(skip)]
    added: EnvPairs,
}

impl CompilerEnvironment {
    /// The run's: [`compiler_environment`], which fixes the run's pairs.
    #[must_use]
    pub fn of_this_run() -> Self {
        Self::published(compiler_environment(), ADDED.get())
    }

    /// The environment a run with `added` as its pairs hands its toolchain, read from chard's
    /// own `PATH`; the run's own is [`CompilerEnvironment::of_this_run`].
    #[must_use]
    pub fn under(added: &EnvPairs) -> Self {
        Self::published(
            compiler_environment_from(|name| std::env::var_os(name), added),
            added,
        )
    }

    fn published(applied: Vec<(std::ffi::OsString, std::ffi::OsString)>, added: &EnvPairs) -> Self {
        let mut passed = Vec::new();
        let mut set = BTreeMap::new();
        for (name, value) in applied {
            let name = name.to_string_lossy().into_owned();
            if COMPILER_ENV_PASSED.contains(&name.as_str()) {
                passed.push(name);
            } else {
                set.insert(name, value.to_string_lossy().into_owned());
            }
        }
        Self {
            passed,
            set,
            added: added.clone(),
        }
    }

    /// The `--env` pairs, sorted by name.
    pub fn added(&self) -> impl Iterator<Item = (&str, &str)> {
        self.added
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

/// The variables named as moving a measurement were they passed to a toolchain, each with its
/// measurement or its argument, which the cleared environment keeps from it like any other.
///
/// [`compiler_environment`] decides what reaches the driver, and this decides nothing at
/// spawn. A list of variables to remove would pass through every variable nobody had found;
/// a cleared environment does not. This is the record of why the clear matters, entry by
/// entry, and the names `tests/fake_driver.rs` sets in chard's own environment and holds the
/// driver to receiving none of. `THREAT_MODEL.md` names each entry
/// and `tests/register.rs` holds the two together.
///
/// How the list was derived, so that a later toolchain can repeat it. The 2026-10-09 inventory read
/// the environment-variable names out of the programs themselves, on Fedora 44 x86_64: `strings`
/// over gcc 16.1.1's `gcc`, `cc1`, `cc1plus`, `collect2` and `lto-wrapper`, clang 22.1.8's
/// `clang-22`, `libclang-cpp.so.22.1` and `libLLVM.so.22.1`, and GNU binutils 2.46.1's `ld.bfd` and
/// `as`; plus a `getenv` logger preloaded under a compile and a link through each driver, which
/// names what is read on a plain build; plus the "Environment Variables Affecting GCC" node of that
/// gcc's manual. A name that was a candidate in any of the three was then set in front of the real
/// drivers and the difference sought in the driver's output, in the `-###` listing, in the object,
/// and in the report. Not done: no `ld.lld` or `ld.gold` was installed on that host, so neither was
/// read, and Apple's clang and `ld` were not read at all. The Darwin driver code is in the Linux
/// clang, so its variables were measured there under `--target=arm64-apple-darwin`, which says what
/// upstream's driver reads and not what Apple's fork adds.
///
/// - Changes the target or the code generated: `MACOSX_DEPLOYMENT_TARGET` and the four
///   other `*_DEPLOYMENT_TARGET` names, `RC_DEBUG_PREFIX_MAP`, `RC_DEBUG_OPTIONS`,
///   `GCC_COMPARE_DEBUG`, `SOURCE_DATE_EPOCH`, `LDEMULATION`, `GNUTARGET`.
/// - Changes diagnostic text or exit status, which the compiler-diag channel parses:
///   `GCC_EXTRA_DIAGNOSTIC_OUTPUT`, `GCC_URLS`, `EXPERIMENTAL_SARIF_SOCKET`,
///   `COLLECT_NO_DEMANGLE`, `FORCE_CLANG_DIAGNOSTICS_CRASH`, `CLANG_CRASH_DIAGNOSTICS_DIR`
///   and clang's `CC_PRINT_*` and `CC_LOG_DIAGNOSTICS` family.
/// - Changes where the driver looks or writes: `SDKROOT`, `LPATH`, `GCC_ROOT`,
///   `BINUTILS_ROOT`, `DEPENDENCIES_OUTPUT`, `SUNPRO_DEPENDENCIES`, `GCC_DIAGNOSTICS_LOG`,
///   `CLANG_MODULE_CACHE_PATH`.
/// - Read and measured inert on that host, so not removed, and listed as the record of
///   having looked: `NO_COLOR` (colour is off on a pipe), `MAKEFLAGS`, `GLIBCXX_TUNABLES`
///   (the compiler's own libstdc++ at run time), `HIP_PATH` and `ROCM_PATH` (HIP mode
///   only), `CLANG_TOOLCHAIN_PROGRAM_TIMEOUT`, `LLVM_OVERRIDE_PRODUCER`,
///   `LLVM_IGNORED_ENV_VAR`, `LIBCTF_DEBUG`, `AS_SECURE_LOG_FILE`, `G++_ROOT`, and
///   `COLLECT_GCC`, `COLLECT_GCC_OPTIONS`, `COLLECT_AS_OPTIONS` and `COLLECT_LTO_WRAPPER`,
///   which gcc sets for its own children and which ignored an inherited value. An inert
///   reading is a reading of one version: a later toolchain that honours one of these
///   moves it into a class above.
/// - Left to a neighbouring entry: `LD_STATS`, `LD_LIBRARY_PATH` and the other loader
///   variables, `OBJC_INCLUDE_PATH` (see the comment on `CPLUS_INCLUDE_PATH`), `PWD`
///   (a working directory is chard's own to set), and `DEVELOPER_DIR` and `TOOLCHAINS`,
///   which Apple's `xcrun` shim is expected to read and which no binary on the inventory
///   host contains, so they are unmeasured.
///
/// Every name in the last two classes is kept from the driver by the clear as well, as is
/// every name nobody has read. (`DEVELOPER_DIR` was measured on 2026-10-11; see
/// [`COMPILER_ENV_PASSED`].) The comments below say "removed" in the sense of the list's
/// first form.
pub const COMPILER_ENV_NAMED: &[&str] = &[
    // Refuse to inherit build configuration. A CFLAGS or CPATH in the
    // ambient environment silently changing what we measure is precisely the
    // class of error chard exists to detect, so we must not be subject to it.
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "C_INCLUDE_PATH",
    // The C++ sibling of `C_INCLUDE_PATH`. Measured 2026-10-05 on Fedora 44 x86_64
    // (gcc 16.1.1, clang 22.1.8): a C++ source including a header found only in a
    // directory this names built under `g++` and `clang++` with it set and failed
    // without it. `OBJC_INCLUDE_PATH` is left out, measured rather than forgotten: in the
    // same run a C source including the same header failed under both drivers with it
    // set, and only clang's Objective-C mode read it; chard compiles C and C++.
    "CPLUS_INCLUDE_PATH",
    "LIBRARY_PATH",
    // The linker reads this one and writes what it finds into the artifact as
    // `DT_RPATH`. `rpath-absent` then sees an RPATH in every arm, including the
    // negative control, so the triple cannot discriminate and the check publishes
    // `probe-invalid` — chard reporting its own instrument as broken because the
    // operator's shell had a variable set. Exported by module systems and by
    // hand-rolled toolchain environment scripts, so this is an ordinary host, not a
    // hostile one.
    "LD_RUN_PATH",
    // gcc's diagnostic colour palette. `TERM=dumb` and a piped stderr already keep
    // colour off; this removes the one variable that restyles it.
    "GCC_COLORS",
    // Both drivers put their temporary objects where this points, and a linker
    // warning names the object it is about, so the name reaches the captured stderr
    // and from there a control arm's `detail`. `measure::scrub_compiler_temp_names`
    // knows the roots the drivers use when nothing redirects them; an operator's
    // `TMPDIR` put the object outside those roots, and two normalized runs of one
    // measurement differed again on the one line the scrubber existed for. Removed
    // on the same reasoning as `CFLAGS`: an ambient variable deciding what a
    // published record says is the class of error this tool exists to detect.
    //
    // The three after it are the drivers' fallbacks when `TMPDIR` is unset, which
    // removing `TMPDIR` makes the case. Measured 2026-10-05 on Fedora 44 x86_64
    // (gcc 16.1.1, clang 22.1.8) with `TMPDIR` unset and each variable alone pointing
    // at a scratch directory: `-###` of a compile-and-link named temporary files in it
    // under `TMP` and `TEMP` for both drivers and under `TEMPDIR` for clang alone. With
    // all four removed both drivers fall back to `/tmp`, the root the scrubber knows.
    "TMPDIR",
    "TMP",
    "TEMP",
    "TEMPDIR",
    // The driver's own search path for the programs it runs. gcc searches
    // `COMPILER_PATH` for `cc1`, `as` and `collect2` before its installed directories,
    // and clang searches it for the linker. `GCC_EXEC_PREFIX` relocates gcc: it stands
    // in for the installed `/usr/lib/gcc/`, gcc derives its program directory from it
    // (`GCC_EXEC_PREFIX../../libexec/gcc/<triple>/<version>/`), stops looking in the
    // installed one, and passes `-iprefix GCC_EXEC_PREFIX<triple>/<version>/` to `cc1`.
    // Measured 2026-09-28 on Fedora 44 x86_64 (gcc 16.1.1, clang 22.1.8) and Fedora 44
    // aarch64 (gcc 16.2.1, clang 22.1.8) with planted stand-ins: under
    // `COMPILER_PATH`, `gcc -###` named the planted `cc1`, `as` and `collect2` and
    // `clang -###` the planted `ld`, and a real compile or link ran them. Under
    // `GCC_EXEC_PREFIX` with `cc1` planted at the derived program directory,
    // `gcc -###` and `-print-prog-name=cc1` named the planted `cc1` and a real compile
    // ran it; with the stand-ins planted at `GCC_EXEC_PREFIX<triple>/<version>/`
    // instead, `gcc -###` named a bare `cc1` and a real compile failed with `cannot
    // execute 'cc1'`, and a link under the relocated prefix failed with
    // `liblto_plugin.so not found`. clang 22.1.8 does not read `GCC_EXEC_PREFIX`:
    // `-###` differed only in temporary file names and a real link succeeded, so it
    // is here for gcc.
    "COMPILER_PATH",
    "GCC_EXEC_PREFIX",
    // clang skips its default configuration file when this is set. On both Fedora 44
    // hosts above, `clang -###` announced `Configuration file:
    // /etc/clang/<triple>-clang.cfg` without it and no configuration file with it, so
    // `toolchain.config_files` reads empty and a `bare` column's `flags_source` reads
    // `none` for a driver a file does configure. Fedora's file carries only
    // `--gcc-triple`, and the macro dump was the same with and without it (405 lines on
    // x86_64, 419 on aarch64); a distribution whose file carries a hardening flag would
    // lose that flag from the measurement.
    "CLANG_NO_DEFAULT_CONFIG",
    // clang rewrites its own command line from this before doing anything else. With
    // `+-fno-stack-protector` in it, clang 22.1.8 on both hosts printed `### Adding
    // argument -fno-stack-protector at end` and passed the flag to `-cc1`: the
    // `CFLAGS` argument at full strength, since it edits argv after chard wrote it.
    //
    // Not in this list, measured rather than forgotten: `CLANG_CONFIG_FILE_SYSTEM_DIR`
    // and `CLANG_CONFIG_FILE_USER_DIR` are CMake options fixed when clang is built, and
    // `CLANG_CONFIG_FILE` is not a name clang reads. None of the three strings is in
    // `clang-22` or `libclang-cpp.so.22.1` on either host above; the only `CLANG_CONFIG`
    // string there is `CLANG_CONFIG_PATH`. A directory of planted files named for
    // clang's own triple (`clang -print-target-triple`, `<triple>-clang.cfg`,
    // `<triple>.cfg` and `clang.cfg`, each defining a macro) did not load with any of
    // the four variables pointing at it or at its `<triple>-clang.cfg`: `clang -###`
    // announced only `/etc/clang/<triple>-clang.cfg` and the macro dump carried no
    // planted define.
    "CCC_OVERRIDE_OPTIONS",
    // The diagnostic language, pinned by `LC_ALL` in [`COMPILER_ENV_PINNED`]; these
    // three are removed so nothing outranks or supplements the pin.
    "LANG",
    "LANGUAGE",
    "LC_MESSAGES",
    // `$HOME`, because a file in it must not decide a distribution's verdict.
    //
    // chard states that rule and enforces it twice: the abuild query deliberately
    // sources `/etc/abuild.conf` and not `~/.abuild/abuild.conf`, the makepkg query
    // `/etc/makepkg.conf` and not `~/.makepkg.conf`, each with a comment saying
    // that a file in `$HOME` deciding a distro verdict is the failure this tool
    // exists to detect, and each with a test holding it. The rpm query goes through
    // this function and had no such guard: `rpm` reads `~/.rpmmacros` by itself, so
    // redefining `%build_cflags` there replaces Fedora's twenty-token flag list
    // with anything at all. Reproduced by planting one under a scratch `HOME` —
    // the query returned the planted string, and three checks then published `on`
    // with `discriminating: true` on a binary carrying none of those protections.
    //
    // Removed rather than redirected: `rpm --eval` and `gcc` both work without it
    // here, and pointing it at a directory invites something to write there. It is
    // scrubbed for probe compilation too, on the same reasoning as `CFLAGS` — an
    // ambient file changing what gets measured is the class of error chard exists
    // to detect, so chard must not be subject to it.
    //
    // No distribution query remains for this paragraph to describe, and `HOME` stays
    // removed on the last paragraph's argument alone. clang's
    // `CLANG_CONFIG_FILE_USER_DIR` build option names a per-user configuration
    // directory, which is where a home directory can reach a driver. Fedora 44's clang
    // 22.1.8 is built without one: `clang -v` names only the system directory
    // `/etc/clang/`, and with `HOME` or `XDG_CONFIG_HOME` pointing at a scratch
    // directory holding `.config/clang/` planted as in the "Not in this list"
    // paragraph above, neither `clang -###` nor the macro dump showed a planted
    // file on either Fedora 44 host.
    "HOME",
    // The Darwin deployment target. The Darwin driver takes the minimum macOS version from
    // this when no `-mmacosx-version-min=` and no versioned triple says otherwise, and the
    // version is part of the triple the compiler compiles for. Reproduced on Fedora 44
    // x86_64 with clang 22.1.8, whose Darwin driver is the upstream code Apple's is derived
    // from: `--target=arm64-apple-darwin25.0.0 -### -c` names `-triple
    // arm64-apple-macosx26.0.0` without the variable and `arm64-apple-macosx10.15.0` with
    // `MACOSX_DEPLOYMENT_TARGET=10.15`, and the macro dump follows
    // (`__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__` 260000 against 101500). The variable
    // is not read for the versionless `arm64-apple-macosx` triple. On Apple clang 21 (arm64
    // macOS) the same move was measured in the triple and in every
    // macro-dump digest of a report with no verdict moving: digests that differ between
    // two runs for a reason the report does not record. With the variable removed the target
    // is the toolchain's own default, and the macro dump `--emit-macros` publishes states it.
    //
    // The same code reads the other four. Under `--target=arm64-apple-darwin`,
    // `RC_DEBUG_PREFIX_MAP=a=b` added `-fdebug-prefix-map=a=b` to the `-cc1` line and
    // `RC_DEBUG_OPTIONS=1` added `-dwarf-debug-flags` carrying the whole command line;
    // rewriting debug info is code generation.
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
    "TVOS_DEPLOYMENT_TARGET",
    "WATCHOS_DEPLOYMENT_TARGET",
    "XROS_DEPLOYMENT_TARGET",
    "DRIVERKIT_DEPLOYMENT_TARGET",
    "RC_DEBUG_PREFIX_MAP",
    "RC_DEBUG_OPTIONS",
    // The SDK, which `-isysroot` also names. The string is in `libclang-cpp`, and Apple's
    // tools are expected to read it as well; it had no effect on the Linux driver, measured
    // (`-###` identical with and without it, for a Linux and an Apple triple). Removed on
    // the `CPATH` reasoning: an ambient path deciding which headers a measurement saw. The
    // cost falls on a Darwin host that relies on it: with no SDK found the compile fails,
    // which reads `build-failed` and not a verdict, and `--profile explicit --flags
    // "-isysroot SDK"` puts the SDK in the report. Not measured on Darwin.
    "SDKROOT",
    // gcc's `-fcompare-debug` through the environment. Measured: the `cc1` line gains
    // `-fcompare-debug=...`, a random seed and a `-fdump-final-insns=` file; the object
    // came out byte identical; a mismatch between the two compiles is a compile error.
    "GCC_COMPARE_DEBUG",
    // `fixits-v1` and `fixits-v2` add a `fix-it:` line to gcc's stderr (12 lines against 11
    // for an implicit `printf`), and the compiler-diag channel matches stderr text.
    "GCC_EXTRA_DIAGNOSTIC_OUTPUT",
    // gcc's hyperlinks in diagnostics. Measured to change nothing on a pipe, under
    // `TERM=dumb` or `xterm`, for `yes`, `st` and `bel`; it is removed on the text
    // argument above and not on an effect, since a gcc that honoured it on a pipe would
    // put escape sequences inside the strings the channel matches.
    "GCC_URLS",
    // gcc writes a trace of its diagnostics machinery to the path named. stderr is
    // unchanged; the effect is a file written where the operator pointed.
    "GCC_DIAGNOSTICS_LOG",
    // gcc 16 sends diagnostics to a SARIF socket. With a path that does not connect the
    // result is `cc1: fatal error: unable to connect to ...` and exit 1: a build failure
    // caused by the environment alone.
    "EXPERIMENTAL_SARIF_SOCKET",
    // GNU ld reads it, and `gcc` and `clang` both pass `-m` themselves, so a link through
    // either driver is unchanged (measured). `ld.bfd` run directly with
    // `LDEMULATION=elf_i386` refuses an x86_64 object: it selects the target. `GNUTARGET`
    // is the same class for BFD's input format and was inert through both drivers.
    "LDEMULATION",
    "GNUTARGET",
    // `COLLECT_NO_DEMANGLE=1` turns the linker's symbol demangling off: `undefined
    // reference to `f()'` becomes `undefined reference to `_Z1fv'`. Measured through `g++`.
    "COLLECT_NO_DEMANGLE",
    // The embedded build time. `__DATE__` and `__TIME__` read it in both drivers
    // (`Jan  1 1970 00:00:00` under `0`, measured). The intrinsic macro dump does not
    // contain them, so no digest moved in the 72-cell report. Removed because a variable
    // that changes what a compile embeds is configuration, whether or not a probe happens
    // to embed it. Pinning it, to make the probe objects reproducible, is a different
    // change and is not made here.
    "SOURCE_DATE_EPOCH",
    // gcc's driver reads these three as search roots. `GCC_ROOT` and `BINUTILS_ROOT`
    // changed the `COMPILER_PATH` that the `-###` listing prints and `LPATH` the
    // `LIBRARY_PATH` and the order in it: `COMPILER_PATH` and `LIBRARY_PATH` by other names.
    "LPATH",
    "GCC_ROOT",
    "BINUTILS_ROOT",
    // gcc's older dependency-output variables behave as `-MM` and `-MD` for every compile.
    // Measured on the 72-cell `bare` report with `DEPENDENCIES_OUTPUT` or
    // `SUNPRO_DEPENDENCIES` naming a file, on both drivers: ten cells moved from `off` (or
    // `unsupported`) to `build-failed`, and the file collected a dependency line for every
    // compile. Loud and not silent, which is the one thing in its favour.
    "DEPENDENCIES_OUTPUT",
    "SUNPRO_DEPENDENCIES",
    // clang's own reporting. The `CC_PRINT_*` and `CC_LOG_DIAGNOSTICS` family writes to
    // stderr when its `_FILE` companion is unset. Measured: `CC_PRINT_OPTIONS=1` put the
    // whole `-cc1` command line on stderr, `CC_LOG_DIAGNOSTICS=1` an XML plist,
    // `CC_PRINT_PROC_STAT=1` a timing line and `CC_PRINT_INTERNAL_STAT=1` a JSON block; in
    // a `measure` run `CC_PRINT_OPTIONS=1` changed 244 report fields and
    // `CC_PRINT_HEADERS=1`, which lists every included header, 139 (build stderr and the
    // details quoting it), with no verdict moving. The `_FILE`, `_FORMAT` and `_FILTERING`
    // companions are here on the strength of the family, not of an effect seen.
    "CC_PRINT_OPTIONS",
    "CC_PRINT_HEADERS",
    "CC_PRINT_HEADERS_FILE",
    "CC_PRINT_HEADERS_FORMAT",
    "CC_PRINT_HEADERS_FILTERING",
    "CC_LOG_DIAGNOSTICS",
    "CC_LOG_DIAGNOSTICS_FILE",
    "CC_PRINT_INTERNAL_STAT",
    "CC_PRINT_INTERNAL_STAT_FILE",
    "CC_PRINT_PROC_STAT",
    "CC_PRINT_PROC_STAT_FILE",
    // clang's crash handling. `FORCE_CLANG_DIAGNOSTICS_CRASH=1` makes every compile crash
    // and print the "PLEASE submit a bug report" text (measured). The directory names where
    // the reproducer is written, and the path is printed on stderr (measured).
    "FORCE_CLANG_DIAGNOSTICS_CRASH",
    "CLANG_CRASH_DIAGNOSTICS_DIR",
    // Where `-fmodules` keeps its cache, printed in the `-cc1` line (measured). No C probe
    // compiles with modules, so this is location only today.
    "CLANG_MODULE_CACHE_PATH",
];

/// The variables every compiler invocation receives with a fixed value.
///
/// `LC_ALL=C` pins the diagnostic language. The compiler-diag channel matches on
/// wording, and gcc ships translated diagnostics — `/usr/share/locale/*/LC_MESSAGES/gcc.mo`
/// is present on this very host — so an operator whose locale is set would get a
/// translated body and every wording match would silently fail, including the existing
/// implicit-function-declaration check. That reasoning was written for the driver probes
/// and applies with more force to probe builds, where the wording being matched is what
/// decides a check's verdict.
///
/// Honest scope: the translated case could not be reproduced here, because no
/// non-English locale is generated on this machine and gcc falls back to English. What
/// *is* reproducible is that the quoting style changes — `LC_ALL=C` yields 'main' while
/// `C.UTF-8` yields ‘main’ — which any matcher quoting an identifier would trip over.
/// Both risks cost one line to remove, and parsing another program's human-readable
/// output without pinning its language is a mistake regardless of whether this host can
/// demonstrate it.
///
/// `TERM=dumb`: colour escapes in captured diagnostics would break substring matching
/// for the compiler-diag channel.
pub const COMPILER_ENV_PINNED: &[(&str, &str)] = &[("LC_ALL", "C"), ("TERM", "dumb")];

fn invoke(program: &Path, args: &[String]) -> Result<BuildRecord> {
    invoke_with_timeout(program, args, None, INVOKE_TIMEOUT, DRAIN_GRACE)
}

/// The body, with both bounds as parameters so a test can prove each of them fires
/// without taking two minutes to do it.
///
/// `cwd` is the directory the child runs in, and `None` leaves it the caller's. With a
/// directory, a relative `program` is made absolute first and recorded that way:
/// `Command` leaves it unspecified whether a relative program is looked up before or
/// after the change of directory, and `run::execute` met the second reading.
fn invoke_with_timeout(
    program: &Path,
    args: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
    drain_grace: Duration,
) -> Result<BuildRecord> {
    let started = Instant::now();
    let absolute;
    let program = match cwd {
        Some(_) if program.is_relative() => {
            absolute = std::path::absolute(program)
                .with_context(|| format!("resolving {} to an absolute path", program.display()))?;
            absolute.as_path()
        }
        _ => program,
    };
    let mut command = Command::new(program);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .env_clear()
        .envs(compiler_environment())
        .spawn()
        .with_context(|| format!("running {}", program.display()))?;

    // Drained on their own threads rather than into files, which is where this departs from
    // `run::execute` and why: that function always has a work directory to put them in, and
    // `capture` is called from `toolchain`'s driver and linker probes, which have none. The
    // hazard it names is real either way — a child that fills a pipe blocks forever while we
    // poll `try_wait`, so nothing may wait on the child while a pipe is unread.
    // `Stdio::piped()` above is what makes these `Some`; an absent pipe here would mean the
    // spawn configuration and this code disagree, which is a bug rather than a runtime state.
    // Handled rather than unwrapped anyway, because a panic inside a sweep loses the lane.
    let (Some(out_pipe), Some(err_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        crate::error::best_effort(child.kill());
        anyhow::bail!("{}: stdout and stderr were not piped", program.display());
    };
    let out_reader = std::thread::spawn(move || drain(out_pipe));
    let err_reader = std::thread::spawn(move || drain(err_pipe));

    let status = loop {
        if let Some(status) = child.try_wait().context("waiting for the toolchain")? {
            break status;
        }
        if started.elapsed() >= timeout {
            // One more look before killing, for `run::execute`'s reason: the child may have
            // finished in the window between that `try_wait` and this comparison, and a real
            // status is worth more than one this branch would invent.
            if let Ok(Some(status)) = child.try_wait() {
                break status;
            }
            crate::error::best_effort(child.kill());
            crate::error::best_effort(child.wait());
            drop(out_reader);
            drop(err_reader);
            // An error, not a `BuildRecord`. A timed-out compile must never reach a detector:
            // `succeeded()` would be false and the `compiler-diag` channel reads a failed
            // compile as its *observable*, so a wedged toolchain would publish as "the
            // compiler rejected this" — a measurement, from a run that measured nothing. A
            // failure to observe has to stay a failure to observe.
            //
            // Untyped, and in `tests/untyped_errors.rs`'s inventory as such. It reaches the
            // envelope only through `toolchain::detect`, where the driver hung on its own
            // interrogation, and a driver that hangs on `--version` hangs again, so the
            // retry `TRANSIENT` promises is a class this failure has not earned; inside
            // the measurement loop it is contained as an unmeasured probe.
            anyhow::bail!(
                "{} did not finish within {}s: {}",
                program.display(),
                timeout.as_secs(),
                args.join(" ")
            );
        }
        crate::run::poll_sleep(started.elapsed());
    };
    // Before draining, not after: the reported duration is the child's lifetime, not the
    // child's lifetime plus our own bookkeeping.
    let ran_for = started.elapsed();

    // The child is gone; its pipes may not be. Wait for both readers under a bound of
    // their own, and treat a stream we could not read as a failure to observe rather than
    // as an observation — an unread stderr published as empty says "the compiler was
    // silent", which is a `compiler-diag` measurement we did not make. Same rule as the
    // timeout branch above, for the same reason.
    let drain_started = Instant::now();
    while !(out_reader.is_finished() && err_reader.is_finished()) {
        if drain_started.elapsed() >= drain_grace {
            anyhow::bail!(
                "{} exited but its output pipes were still held {:?} later, so its \
                 diagnostics could not be read: {}",
                program.display(),
                drain_grace,
                args.join(" ")
            );
        }
        crate::run::poll_sleep(drain_started.elapsed());
    }
    // `unwrap_or_default` here would substitute an empty stream for an unread one, which
    // is the same conversion the bail above refuses.
    let (Ok(stdout), Ok(stderr)) = (out_reader.join(), err_reader.join()) else {
        anyhow::bail!(
            "{}: an output reader panicked, so its diagnostics could not be read: {}",
            program.display(),
            args.join(" ")
        );
    };

    let mut argv = vec![program.display().to_string()];
    argv.extend(args.iter().cloned());

    let stdout = String::from_utf8_lossy(&stdout);
    // Read before the trim below removes the newline it looks for.
    let stdout_unterminated = ends_mid_line(&stdout);

    Ok(BuildRecord {
        argv,
        // Filled in by the caller that did the filtering; `invoke` cannot know what was
        // removed before it was handed `args`.
        dropped_flags: Vec::new(),
        exit_status: status.code().unwrap_or(-1),
        stdout: stdout.trim_end().to_owned(),
        stderr: String::from_utf8_lossy(&stderr).trim_end().to_owned(),
        duration_ms: ran_for.as_millis(),
        artifact_sha256: None,
        stdout_sha256: None,
        stdout_unterminated,
    })
}

/// Whether `output`, as read before any trim, ends partway through a line: text other than
/// whitespace follows its last newline, or makes up the whole of it where it has none.
/// Whitespace after the last newline is trimmed with that newline when `stdout` is stored, so
/// a last line of whitespace alone is no line a cut ended, and where this holds the trimmed
/// `stdout` keeps the newline before the cut line ([`BuildRecord::whole_stdout`]).
fn ends_mid_line(output: &str) -> bool {
    !output
        .rsplit_once('\n')
        .map_or(output, |(_, last)| last)
        .trim_end()
        .is_empty()
}

/// How [`BuildRecord::dump_failure`] says a dump that exited on its own was cut off, after
/// "exited N".
pub const CUT_OFF: &str = "with its output cut off partway through a line";

/// Run a program with exactly `args` and nothing appended.
///
/// Used to interrogate the toolchain (`--version`, `-dumpmachine`,
/// `-print-prog-name=ld`) and to ask a distro package manager who owns the
/// driver. Shares `invoke`'s environment scrubbing, so an interrogation cannot
/// be perturbed by ambient build variables either.
/// # Errors
///
/// Errors when the program cannot be spawned at all. A non-zero exit status is
/// not an error: it is recorded in the returned [`BuildRecord`].
pub fn capture(program: &Path, args: &[String]) -> Result<BuildRecord> {
    invoke(program, args)
}

/// Compile and link `source` into `out`, with `flags` inserted before it.
///
/// Flag order is deliberate: profile flags, then the variant's control flags,
/// then the source. Later flags win in both gcc and clang, so a control can
/// always override a profile default — which is what makes the positive and
/// negative controls trustworthy.
///
/// The driver runs in the source's directory and is handed the source by its file name
/// alone ([`in_place`]), so nothing the compiler derives from the name it was given
/// depends on where `--workdir` points. OpenBSD's clang names each RETGUARD cookie, and
/// the `.openbsd.randomdata.retguard.<n>` section it lives in, from a hash of the module
/// name and the function name, and the module name is the source path as given. Measured
/// 2026-10-01 on OpenBSD 7.9 amd64 (clang 19.1.7) over a two-function file in a 6- and a
/// 69-character directory: compiled by absolute path, the objects carried the cookies
/// `352`, `515` and `1104` in one and `764`, `1048` and `1910` in the other, and differed;
/// compiled from inside each directory by file name, both carried `2521`, `2588` and
/// `3502` and were byte-identical, as were the linked executables, with `-o` absolute or
/// relative. `-ffile-prefix-map`, `-fdebug-prefix-map` and `-fmacro-prefix-map` left each
/// object byte-identical to the absolute build, so a prefix map does not reach the name.
/// The same holds wherever a source name is compiled into the artifact as given, such as
/// a sanitizer's source locations. The output path stays absolute; `-o` is not read into
/// the module. A relative path in an explicit profile's flags would name a directory under
/// the work directory here and one under chard's own elsewhere, and `measure` refuses it
/// ([`relative_path_arguments`]).
/// # Errors
///
/// Errors when the compiler cannot be spawned. A failed *compilation* is
/// deliberately not an error — for the `compiler-diag` channel the failure is
/// the observable, so it is reported in the [`BuildRecord`] instead.
pub fn build(
    driver: &Path,
    flags: &[String],
    source: &Path,
    out: &Path,
    link_libs: &[&str],
) -> Result<BuildRecord> {
    let (cwd, source_arg) = in_place(source);
    let mut args: Vec<String> = Vec::new();
    args.extend(flags.iter().cloned());
    args.push("-o".to_owned());
    args.push(out.display().to_string());
    args.push(source_arg);
    // After the source, never before: GNU ld resolves libraries in command-line
    // order, so a `-l` ahead of the object that needs it contributes nothing — and
    // under `--as-needed` is dropped even when the symbol *is* used, which would make
    // the probe for that very flag report it active in both arms.
    args.extend(link_libs.iter().map(|s| (*s).to_owned()));

    // Clear the path first, so what is read afterwards can only be what this build
    // wrote. Without it a probe inherits whatever a previous run left at the same
    // name, and the work directory is reused by design — `--workdir` defaults into
    // the caller's CWD and is never cleaned, because it is retained as evidence.
    //
    // Measured with this removal taken out: `--profile openssf-tldr` then `--profile
    // explicit --flags -fsyntax-only` over one work directory. The second run compiles
    // nothing (`-fsyntax-only` writes no output file), exits 0, and publishes `pie`,
    // `relro` and `noexecstack` as `on` off the first run's binary, with the same
    // `artifact_sha256` in both reports and every control triple `discriminating`. A
    // fabricated `on` is the one outcome the control triple exists to make impossible,
    // and it gets there without a hostile compiler: two ordinary invocations in one
    // directory.
    //
    // `NotFound` is the expected case and not an error. Anything else — a directory in
    // the way, a permission problem — must not be swallowed, because it would leave
    // exactly the stale file this removal exists to prevent.
    match std::fs::remove_file(out) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e)
                .context(crate::error::HarnessPath(out.to_path_buf()))
                .context("clearing the previous artifact before building it");
        }
    }

    let mut record = invoke_with_timeout(driver, &args, cwd, INVOKE_TIMEOUT, DRAIN_GRACE)?;
    if record.succeeded() {
        // `None` here means the driver exited 0 and wrote nothing, which the
        // caller reads as "no artifact to inspect" rather than as a build failure —
        // the `compiler-diag` channel still has its observable either way.
        record.artifact_sha256 = digest::sha256_file(out);
    }
    Ok(record)
}

/// Driver options whose argument is a path the driver, or a tool it runs, opens relative
/// to its working directory: the argument either joined (`-Ifoo`, `--sysroot=foo`) or the
/// next word (`-I foo`, `--sysroot foo`). An option spelled with `--`, and
/// `-resource-dir`, joins its argument only after `=`, so `--config-user-dir=d` is not
/// `--config` with the argument `-user-dir=d`. One ending in `=` takes no next word.
/// clang's own `-isystem-after` and `-include-pch` ([`CLANG_LONGER`]) are read as clang
/// reads them, and as gcc reads them besides. [`relative_path_arguments`] reads them.
const PATH_OPTIONS: &[&str] = &[
    "-B",
    "--prefix",
    "-ccc-install-dir",
    "-L",
    "-I",
    "-F",
    "-isystem",
    "-isystem-after",
    "-stdlib++-isystem",
    "-iquote",
    "-idirafter",
    "-isysroot",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
    "-include",
    "-include-pch",
    "-imacros",
    "-resource-dir",
    "--sysroot",
    "--gcc-toolchain",
    "--gcc-install-dir",
    "--config",
    "--config-system-dir",
    "--config-user-dir",
    "-fprofile-use=",
    "-fprofile-instr-use=",
    "-fsanitize-ignorelist=",
    "-fsanitize-blacklist=",
];

/// Options whose argument is a name the driver searches for unless it contains a `/`,
/// joined only. A bare `-fuse-ld=lld` or `-specs=nosys.specs` names no directory.
const PATH_OR_NAME_OPTIONS: &[&str] = &["-fuse-ld=", "-specs=", "--specs="];

/// Whether `word`, as written or joined by `=`, is an option this reader names
/// ([`PATH_OPTIONS`], [`PATH_OR_NAME_OPTIONS`]), so that `toolchain::read`'s generic map
/// leaves it as written: clang's `--config=f` is a path to this reader and a spelling of no
/// selection table, and gcc's map of it to `-fconfig=f` would hide the file from the
/// refusal (clang 22.1.8 reads `--config=rel/c.cfg` and `--config rel/c.cfg`; gcc 16.1.1
/// refuses both; measured 2026-10-28 UTC on Fedora 44 x86_64 under `-###`).
pub(crate) fn names_a_path_option(word: &str) -> bool {
    let stem = word.strip_suffix('=').unwrap_or(word);
    PATH_OPTIONS
        .iter()
        .chain(PATH_OR_NAME_OPTIONS)
        .any(|option| option.trim_end_matches('=') == stem)
}

/// clang's options whose spelling begins with a shorter [`PATH_OPTIONS`] option, each with
/// that option. gcc knows neither and reads the word as the shorter option joined to the
/// rest, `-after` or `-pch` and whatever follows, a relative path wherever it stands:
/// measured 2026-10-28 on Fedora 44 x86_64 with `-v -E`, gcc 16.1.1 handed `cc1` `-isystem
/// -after` for `-isystem-after /usr/share` and `-isystem -after/usr/share` for
/// `-isystem-after/usr/share`, and ignored the nonexistent directory, and handed it `-include
/// -pch` for `-include-pch <file>` and failed on the missing `-pch`; clang 22.1.8 read each
/// as its own option and its value.
const CLANG_LONGER: [(&str, &str); 2] =
    [("-isystem-after", "-isystem"), ("-include-pch", "-include")];

/// GNU ld's options that name a file or directory it reads, or one the program it writes reads
/// at run time (the dynamic linker, the run-time search paths), with the path as the next item
/// (`-Wl,-L,dir`, `-Xlinker -L -Xlinker dir`), from `ld --help` (GNU ld 2.46.1; ld also takes
/// `--rpath` and `--rpath-link`, measured the same day by the RUNPATH `-Wl,--rpath,/opt/x`
/// wrote). Not here: the options that name what ld writes (`-o`, `-Map`, `--dependency-file`),
/// since a file written elsewhere changes nothing a probe reads; those that take a name ld or
/// the loader searches for ([`LINKER_PATH_OR_NAME_OPTIONS`]); and `--remap-inputs
/// PATTERN=FILE`, whose file is not read here.
const LINKER_PATH_OPTIONS: [&str; 23] = [
    "-L",
    "--library-path",
    "-T",
    "--script",
    "-dT",
    "--default-script",
    "-c",
    "--mri-script",
    "-I",
    "--dynamic-linker",
    "-R",
    "--just-symbols",
    "-Y",
    "-rpath",
    "--rpath",
    "-rpath-link",
    "--rpath-link",
    "--retain-symbols-file",
    "--remap-inputs-file",
    "--section-ordering-file",
    "--version-script",
    "--dynamic-list",
    "--export-dynamic-symbol-list",
];

/// GNU ld's options that take a path or a name, as the next item or, for the long ones, joined
/// after `=`: a plugin, an error-handling script, an audit library and a filter object, each
/// searched for where it names no directory, so a value is a path only where it holds a `/`,
/// as `-fuse-ld=`'s is ([`PATH_OR_NAME_OPTIONS`]). From `ld --help` (GNU ld 2.46.1).
const LINKER_PATH_OR_NAME_OPTIONS: [&str; 10] = [
    "-plugin",
    "--plugin",
    "--error-handling-script",
    "--audit",
    "-P",
    "--depaudit",
    "-f",
    "--auxiliary",
    "-F",
    "--filter",
];

/// GNU ld's options that take such a path joined: the long ones of [`LINKER_PATH_OPTIONS`]
/// after `=`, `--sysroot=`, which ld takes joined only, and the one-letter `-L`, `-T`, `-I`,
/// `-R` and `-Y` with the path after the letter (not `-c`, whose letter begins ld's
/// `-call_shared`).
const LINKER_PATH_JOINED: [&str; 22] = [
    "--library-path=",
    "--script=",
    "--default-script=",
    "--mri-script=",
    "--dynamic-linker=",
    "--just-symbols=",
    "-rpath=",
    "--rpath=",
    "-rpath-link=",
    "--rpath-link=",
    "--retain-symbols-file=",
    "--remap-inputs-file=",
    "--section-ordering-file=",
    "--version-script=",
    "--dynamic-list=",
    "--export-dynamic-symbol-list=",
    "--sysroot=",
    "-L",
    "-T",
    "-I",
    "-R",
    "-Y",
];

/// GNU ld's options that begin with `-T` and take an address, not a file, as the next item or
/// joined after `=` (`-Ttext 0x1000`, `-Ttext-segment=0x400000`), as `ld --help` lists them
/// (GNU ld 2.46.1).
const LINKER_ADDRESS_OPTIONS: [&str; 6] = [
    "-Tbss",
    "-Tdata",
    "-Ttext",
    "-Ttext-segment",
    "-Trodata-segment",
    "-Tldata-segment",
];

/// How [`relative_path_readings`] read an argument it returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathReading {
    /// The argument names a relative path as written.
    Relative,
    /// gcc reads the word as `option` joined to `value`, a relative path: clang's own
    /// `-isystem-after` or `-include-pch` ([`CLANG_LONGER`]), which gcc does not know.
    GccJoined {
        /// The shorter option gcc reads.
        option: &'static str,
        /// The rest of the word, which gcc reads as that option's path.
        value: String,
    },
    /// A path option handed to another tool with no path handed in the same word or the
    /// pair after it: the tool reads its path from a word handed later, which this reader
    /// does not pair with it, or the line hands it none.
    Unpaired,
}

impl PathReading {
    /// What a refusal says of an argument read so, beside the argument, and what to write
    /// instead; `None` for a relative path as written, which the refusal's own sentence covers.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        match self {
            Self::Relative => None,
            Self::GccJoined { option, value } => Some(format!(
                "which gcc reads as {option} with the relative path {value:?}; name a directory \
                 with -idirafter, which both drivers read, or leave the option out"
            )),
            Self::Unpaired => Some(
                "whose path is not handed in the same word or the pair after it, so the tool \
                 reads it from a later word or from none; hand the option and its path together"
                    .to_owned(),
            ),
        }
    }
}

/// One argument [`relative_path_readings`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativePath {
    /// The words the argument was read from, as written and joined by a space: one word, an
    /// option and its separate path, or the pairs that hand a tool an option and its path.
    pub argument: String,
    /// How it was read.
    pub reading: PathReading,
}

/// Who reads a list of words for the paths in it ([`relative_path_readings`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathReader {
    /// The driver: [`PATH_OPTIONS`] and [`PATH_OR_NAME_OPTIONS`], [`CLANG_LONGER`] as gcc
    /// reads them, and gcc's `-I-`, which is no path.
    Driver,
    /// The preprocessor, through `-Xpreprocessor` or `-Wp,`: gcc's `cc1` and clang's `-cc1`
    /// read the driver's header options as the driver does, [`CLANG_LONGER`] as gcc reads
    /// them; but clang's `-cc1` reads `-I-` as the directory `-`.
    Preprocessor,
    /// clang's driver for one architecture (`-Xarch_<arch>`): one word, a two-token option
    /// with no path, which clang refuses.
    Arch,
    /// The assembler, through `-Xassembler`, `--for-assembler` or `-Wa,`: GNU as's `-I`, the
    /// one option of its own that names a directory it reads (`.include`), joined or as the
    /// next item. Its `-L` keeps local symbols and names nothing.
    Assembler,
    /// Another tool (clang's `-cc1` through `-Xclang`, LLVM's option parser, an offload
    /// toolchain's driver), read with the driver's options as clang names them.
    Tool,
    /// A linker: [`LINKER_PATH_OPTIONS`] and [`LINKER_PATH_JOINED`], and not
    /// [`LINKER_ADDRESS_OPTIONS`].
    Linker,
}

/// Whether `path` names a path relative to the working directory: not empty, not read
/// against the sysroot (`=`, `$SYSROOT`), not absolute.
fn relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('=')
        && !path.starts_with("$SYSROOT")
        && Path::new(path).is_relative()
}

/// What a linker reads in `word`, with `next` the item after it ([`path_word`]'s linker arm).
fn linker_path_word(word: &str, next: Option<&str>) -> (usize, Option<PathReading>) {
    // A run-time path may begin with a dynamic string token the loader expands
    // (`$ORIGIN`, `$LIB`, `$PLATFORM`, braced or not), which names no directory here.
    let path =
        |path: &str| (relative(path) && !path.starts_with('$')).then_some(PathReading::Relative);
    let path_or_name = |value: &str| {
        if value.contains('/') {
            path(value)
        } else {
            None
        }
    };
    let unpaired = || (1, Some(PathReading::Unpaired));
    if LINKER_ADDRESS_OPTIONS.contains(&word) {
        return (if next.is_some() { 2 } else { 1 }, None);
    }
    if LINKER_PATH_OPTIONS.contains(&word) {
        return next.map_or_else(unpaired, |value| (2, path(value)));
    }
    if LINKER_PATH_OR_NAME_OPTIONS.contains(&word) {
        return next.map_or_else(unpaired, |value| (2, path_or_name(value)));
    }
    if LINKER_ADDRESS_OPTIONS.iter().any(|option| {
        word.strip_prefix(option)
            .is_some_and(|r| r.starts_with('='))
    }) {
        return (1, None);
    }
    if let Some(value) = LINKER_PATH_OR_NAME_OPTIONS
        .iter()
        .filter(|option| option.starts_with("--") || option.len() > 2)
        .find_map(|option| word.strip_prefix(option)?.strip_prefix('='))
    {
        return (1, path_or_name(value));
    }
    match LINKER_PATH_JOINED
        .iter()
        .find_map(|option| word.strip_prefix(option))
    {
        Some(joined) => (1, path(joined)),
        None => (1, None),
    }
}

/// What `reader` reads in `word`, with `next` the word after it in the list it reads: the
/// words it takes (one, or two where `next` is the option's separate path) and how it read a
/// relative path among them, if it did.
fn path_word(reader: PathReader, word: &str, next: Option<&str>) -> (usize, Option<PathReading>) {
    let found = |path: &str| relative(path).then_some(PathReading::Relative);
    let separate = || match next {
        Some(path) => (2, found(path)),
        None => match reader {
            PathReader::Driver | PathReader::Arch => (1, None),
            PathReader::Preprocessor
            | PathReader::Assembler
            | PathReader::Tool
            | PathReader::Linker => (1, Some(PathReading::Unpaired)),
        },
    };
    if let Some(file) = word.strip_prefix('@') {
        return (1, found(file));
    }
    if reader == PathReader::Assembler {
        return match word.strip_prefix("-I") {
            Some("") => separate(),
            Some(joined) => (1, found(joined)),
            None => (1, None),
        };
    }
    if reader == PathReader::Linker {
        return linker_path_word(word, next);
    }
    if let Some(value) = PATH_OR_NAME_OPTIONS
        .iter()
        .find_map(|option| word.strip_prefix(*option))
    {
        return (
            1,
            if value.contains('/') {
                found(value)
            } else {
                None
            },
        );
    }
    // gcc's `-specs file`, which it reads as `-specs=file` (so too `--specs file` and `--sp
    // file`, which `toolchain::read` hands here as `-specs`; measured 2026-10-28 UTC on
    // Fedora 44 x86_64 with gcc 16.1.1 under `-###`, each spelling's `COLLECT_GCC_OPTIONS`
    // carrying `-specs=rel/x.specs`): the file is a name the driver searches for unless it
    // contains a `/`, as the joined spelling is read.
    if reader == PathReader::Driver && word == "-specs" {
        return match next {
            Some(file) if file.contains('/') => (2, found(file)),
            Some(_) => (2, None),
            None => (1, None),
        };
    }
    if matches!(reader, PathReader::Driver | PathReader::Preprocessor)
        && let Some((option, value)) = CLANG_LONGER.iter().find_map(|(longer, shorter)| {
            word.starts_with(longer)
                .then(|| (*shorter, word.get(shorter.len()..).unwrap_or("")))
        })
    {
        // gcc's reading, of this word alone: the word after it is a driver word to gcc.
        let reading = PathReading::GccJoined {
            option,
            value: value.to_owned(),
        };
        return (1, Some(reading));
    }
    // The longest option a word begins with, so `-isystem` is not read as `-I`'s
    // neighbour and `-iwithprefixbefore` is not read as `-iwithprefix`.
    let Some((option, after)) = PATH_OPTIONS
        .iter()
        .filter_map(|option| Some((*option, word.strip_prefix(*option)?)))
        .max_by_key(|(option, _)| option.len())
    else {
        // A value-taking option that names no path takes the next word as its value, which
        // is no option of its own (`-u -B<dir>`, `-MF -L<dir>`; `toolchain::takes_a_value`).
        if reader == PathReader::Driver && crate::toolchain::takes_a_value(word) {
            return (if next.is_some() { 2 } else { 1 }, None);
        }
        return (1, None);
    };
    let joined = if option.ends_with('=') {
        after
    } else if option.starts_with("--") || option == "-resource-dir" {
        match after.strip_prefix('=') {
            Some(joined) => joined,
            None if after.is_empty() => "",
            None => return (1, None),
        }
    } else {
        after
    };
    if after.is_empty() && !option.ends_with('=') {
        separate()
    } else if reader == PathReader::Driver && option == "-I" && joined == "-" {
        // gcc's `-I-`, which splits the search list and names no directory; clang's driver
        // refuses it.
        (1, None)
    } else {
        (1, found(joined))
    }
}

/// Read `run`, the words a list hands one reader, each with the positions in `flags` of the
/// words it came from, and push each relative path with the words it came from, each set of
/// words once.
fn read_run(
    reader: PathReader,
    run: &[(&str, std::ops::Range<usize>)],
    flags: &[String],
    found: &mut Vec<RelativePath>,
) {
    let mut last: Option<std::collections::BTreeSet<usize>> = None;
    let mut j = 0;
    while let Some((word, _)) = run.get(j) {
        let next = run.get(j.saturating_add(1)).map(|(w, _)| *w);
        // gcc's `cc1` reads the driver's long spellings handed to it as the driver does
        // (`-Wp,--include=f`, `-Xpreprocessor --imacros=f`, `-Wp,--im,f` force the file in;
        // measured 2026-10-28 on Fedora 44 x86_64 with gcc 16.1.1 by `-dM -E`; clang's `-cc1`
        // refuses them), so the preprocessor's words are read as gcc reads them.
        let spelled = if matches!(reader, PathReader::Preprocessor | PathReader::Arch) {
            crate::toolchain::spelled_alone(word)
        } else {
            std::borrow::Cow::Borrowed(*word)
        };
        let (takes, reading) = path_word(reader, &spelled, next);
        let end = j.saturating_add(takes);
        // `takes` is two only where `next` is a word of the run; the word alone otherwise.
        if let Some(reading) = reading
            && let Some(taken) = run.get(j..end).or_else(|| run.get(j..j.saturating_add(1)))
        {
            let positions: std::collections::BTreeSet<usize> =
                taken.iter().flat_map(|(_, from)| from.clone()).collect();
            if last.as_ref() != Some(&positions) {
                let argument = positions
                    .iter()
                    .filter_map(|&k| flags.get(k).map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" ");
                found.push(RelativePath { argument, reading });
                last = Some(positions);
            }
        }
        j = end;
    }
}

/// The arguments in `flags` that hand the driver, or a tool it runs, a relative path, each
/// as written and with how it was read ([`relative_path_arguments`] says why each is
/// refused).
///
/// Each word is read by whoever reads it. The driver reads a [`PATH_OPTIONS`] option's
/// path, a [`PATH_OR_NAME_OPTIONS`] argument with a `/` in it and a response file (`@file`);
/// any other option that takes the next word as its value (`toolchain::takes_a_value`: `-u`,
/// `-MF`, `-o`, `-D`) takes it unread, so `-u -B<dir>` names no prefix.
/// A word that hands the next word to a tool (`toolchain::Handed`: `-Xlinker`,
/// `-Xpreprocessor`, `-Xclang`, ...) is passed over by the driver with that word, and the
/// words handed to one tool by adjacent pairs are read in order as that tool reads them: the
/// preprocessor and the other tools with the driver's options, the assembler with GNU as's
/// `-I`, a linker with GNU ld's ([`LINKER_PATH_OPTIONS`]). So `-Xpreprocessor -I
/// -Xpreprocessor /abs` is `cc1`'s `-I /abs`, which gcc 16.1.1 and clang 22.1.8 hand `cc1`
/// and `-cc1` for that line (measured 2026-10-28 on Fedora 44 x86_64 with `-v -E`), and not
/// the driver's `-I` with the relative path `-Xpreprocessor`; `-Xlinker -Bsymbolic` is ld's,
/// and no driver `-B`. `-Wl,<list>`, `-Wp,<list>` and `-Wa,<list>` hand their items to the
/// linker, the preprocessor and the assembler, and the joined spellings of
/// [`JOINED_PASS_THROUGH`] (`--for-linker=<word>`, `-Xclang=<word>`, ...) their one value,
/// each read within the word. A word handed to clang's driver for one architecture
/// (`-Xarch_<arch>`) is read as the driver's own word alone, a list within it included.
///
/// Where the drivers read a word apart, it is refused where either reads a relative path:
///
/// - clang's `-isystem-after` and `-include-pch`, which gcc reads as `-isystem` and
///   `-include` joined to a relative path ([`CLANG_LONGER`]), whatever follows;
/// - `-I -`: gcc reads it as `-I-`, and clang as the directory `-`, which its `-cc1` also
///   reads for `-I-` handed to it (the same measurement). gcc's `-I-` to the driver splits
///   the search list and names no directory, and clang refuses it, so it is no relative path.
///
/// A path option handed to a tool with no path in the same word or the pair after it
/// (`-Xlinker -L -O2 -Xlinker dir`, `-Wl,-L -Wl,dir`) reads its path from a later word, or
/// from none, which this reader does not pair, and is returned as [`PathReading::Unpaired`]:
/// a refusal of a line ld would read, taken so that no path goes unread.
///
/// An option missing from these lists is not caught: the spellings GCC and Clang accept
/// beyond them (unique-prefix abbreviations of the long options, `--include-directory` and
/// kin, `-iframework`, `-T`, `-ivfsoverlay`, the value-taking options whose value is a path,
/// which are read as values), the options that hand a tool its path joined to another word
/// (`--for-l=`, an abbreviation gcc may take), `cc1`'s own options through `-Xclang`
/// (`-internal-isystem`), and GNU ld's single-dash and abbreviated spellings of its long
/// options (`-library-path=`, `--lib=`). The linker's words are read as GNU ld reads them,
/// whichever linker `-fuse-ld=` names.
#[must_use]
pub fn relative_path_readings(flags: &[String]) -> Vec<RelativePath> {
    use crate::toolchain::{Handed, handed, read};
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(word) = flags.get(i) {
        let one = i.saturating_add(1);
        let two = i.saturating_add(2);
        let hand = handed(word);
        let reader = match hand {
            Handed::Driver => {
                if let Some((reader, items)) = handed_within(word) {
                    let run: Vec<_> = items.into_iter().map(|item| (item, i..one)).collect();
                    read_run(reader, &run, flags, &mut found);
                    i = one;
                } else {
                    // The word as gcc reads it (`--li` is `-L`, `--pref` is `-B`, `--machine
                    // 32` is `-m32` and spans the pair; `toolchain::read`), so the path
                    // options are read under every spelling gcc takes for them.
                    let read_as = read(word, flags.get(one).map(String::as_str));
                    let next = if read_as.joined() {
                        None
                    } else {
                        flags.get(one).map(String::as_str)
                    };
                    let (takes, reading) = path_word(PathReader::Driver, &read_as.word, next);
                    let end = i.saturating_add(takes.max(read_as.span()));
                    // `takes` is two only where `next` is a word; the word alone otherwise.
                    if let Some(reading) = reading
                        && let Some(words) = flags.get(i..end).or_else(|| flags.get(i..one))
                    {
                        let argument = words.join(" ");
                        found.push(RelativePath { argument, reading });
                    }
                    i = end;
                }
                continue;
            }
            Handed::Arch => {
                // The word clang applies for the architecture is read as the driver's own
                // word alone, a list or a joined hand-on within it included.
                if let Some(next) = flags.get(one) {
                    let (reader, items) =
                        handed_within(next).unwrap_or((PathReader::Arch, vec![next.as_str()]));
                    let run: Vec<_> = items.into_iter().map(|item| (item, i..two)).collect();
                    read_run(reader, &run, flags, &mut found);
                }
                i = two;
                continue;
            }
            Handed::Preprocessor => PathReader::Preprocessor,
            Handed::Assembler => PathReader::Assembler,
            Handed::Linker(_) => PathReader::Linker,
            Handed::Tool(_) => PathReader::Tool,
        };
        // The run of adjacent pairs that hand words to this tool.
        let mut run = Vec::new();
        let mut at = i;
        while let Some(w) = flags.get(at)
            && handed(w) == hand
            && let Some(next) = flags.get(at.saturating_add(1))
        {
            run.push((next.as_str(), at..at.saturating_add(2)));
            at = at.saturating_add(2);
        }
        read_run(reader, &run, flags, &mut found);
        i = if run.is_empty() { one } else { at };
    }
    found
}

/// The items `word` hands a tool within itself, and the reader of them: a `-Wl,`, `-Wp,` or
/// `-Wa,` list's items, split at commas, or the one value of a [`JOINED_PASS_THROUGH`]
/// spelling; `None` for any other word.
fn handed_within(word: &str) -> Option<(PathReader, Vec<&str>)> {
    if let Some((option, value)) = JOINED_PASS_THROUGH
        .iter()
        .find_map(|option| Some((*option, word.strip_prefix(option)?)))
    {
        let reader = match option {
            "--for-linker=" => PathReader::Linker,
            "--for-assembler=" => PathReader::Assembler,
            _ => PathReader::Tool,
        };
        return Some((reader, vec![value]));
    }
    [
        ("-Wl,", PathReader::Linker),
        ("-Wp,", PathReader::Preprocessor),
        ("-Wa,", PathReader::Assembler),
    ]
    .into_iter()
    .find_map(|(prefix, reader)| Some((reader, word.strip_prefix(prefix)?.split(',').collect())))
}

/// The arguments in `flags` that hand the driver, or a tool it runs, a relative path, each
/// as written, an option and its separate argument joined by a space
/// ([`relative_path_readings`] says how each word is read).
///
/// A path is relative to the directory the driver runs in, and chard runs it in more
/// than one: [`build`] and [`macro_dump`] run it in the work directory, while the
/// link-line and toolchain interrogations ([`capture`]) run it in chard's own. A `--flags
/// -Bmy-ld` written relative to where chard was started would reach the link-line capture
/// as that directory and every probe build as a directory under the work directory, which
/// does not exist, and the driver ignores a missing `-B`, `-L` or `-I` directory without a
/// word: one report would describe two toolchains and say nothing. `measure` refuses such
/// an argument, before the driver
/// sees it, and asks for the path made absolute, or for what the reading's note
/// ([`PathReading::note`]) names.
///
/// A path that begins with `=` or `$SYSROOT` is read against the sysroot, not the working
/// directory, and is not returned.
#[must_use]
pub fn relative_path_arguments(flags: &[String]) -> Vec<String> {
    relative_path_readings(flags)
        .into_iter()
        .map(|found| found.argument)
        .collect()
}

/// The options that hand their joined value, whole, to another tool: clang's `-Xclang=`
/// (to `-cc1`), `-Xclangas=` (to `-cc1as`), `-mllvm=` (to LLVM's option parser) and
/// `-Xthinlto-distributor=`, and `--for-linker=` and gcc's `--for-assembler=` (clang
/// 22.1.8 rejects the second). None of them splits at commas, so only a value that begins
/// with `@` is a response file. [`response_file_arguments`] says why each is refused.
const JOINED_PASS_THROUGH: [&str; 6] = [
    "-Xclang=",
    "-Xclangas=",
    "-mllvm=",
    "-Xthinlto-distributor=",
    "--for-linker=",
    "--for-assembler=",
];

/// The arguments in `flags` that hand a tool a response file: a word that begins with
/// `@`, which also covers the word after `-Xlinker`, `-Xpreprocessor`, `-Xassembler`,
/// `-Xclang`, `-mllvm` or `-Xarch_<arch>`; a `-Wl,`, `-Wp,` or `-Wa,` list with an item
/// that begins with `@`; and a [`JOINED_PASS_THROUGH`] option whose value begins with
/// `@`. Each comes back as written.
///
/// Every tool on the build's path expands one in place: the driver, and through the
/// pass-through spellings the preprocessor, the linker, and clang's `-cc1`. Measured
/// 2026-10-05 on Fedora 44 x86_64 with gcc 16.1.1, clang 22.1.8 and GNU ld 2.46.1: a file
/// holding `-DPLANTED=7` defined `PLANTED` in a `-dM -E` dump as `@file`, `-Wp,@file` and
/// `-Xpreprocessor @file` under both drivers, and as `-Xclang @file` under clang; one
/// holding `-m32` turned the dump to `__i386__`; one holding
/// `--defsym=planted_sym=0x1234` put the symbol in the linked program through `-Wl,@file`
/// and `-Xlinker @file` under both, and through `--for-linker=@file` under clang. The
/// joined spellings, measured the same day on the same host and toolchains:
/// under clang `-Xclang=@file` defined `PLANTED`, and with the file holding
/// `-triple i386-unknown-linux-gnu` wrote an i386 object; `-mllvm=@file` handed LLVM's
/// option parser the file's `-debug-pass=Structure`; `-Xclangas=@file` handed `-cc1as`
/// the file's words; and under gcc `--for-assembler=@file` holding `--defsym=asym=1` put
/// `asym` in the linked program. `-Xclang=-DX,@file` defined `X` as `,@file`: the joined
/// value is one word, unsplit. `-Xthinlto-distributor=` is listed unmeasured, because it
/// hands its value to a distributor program chard cannot read either.
///
/// chard reads the profile's flags to decide what each control arm carries (the target
/// and linker selection), which flags a shared-object link drops (`-pie`), whether a
/// macro the dump reports was forged by a `-D`, and where a relative path points, and
/// none of those readers sees inside the file. A `-m32` there reached the measured build
/// and no arm, so the triple validated each detector on another target than the cell
/// measured. `measure` refuses such an argument, before the driver sees it, and asks for
/// the flags written out.
///
/// Refused rather than expanded. Expanding is a read of a file the operator names, beside
/// the flag text, and it would have to reproduce each tool's own syntax (gcc's and GNU
/// ld's quoting, clang's, nested `@` inside the file, a missing file passed through as a
/// literal word) to read what the tool read; a difference between the two expansions is a
/// flag one side sees and the other does not, the hole this closes. The flags written out
/// on the command line are the same measurement, and they are recorded as `profile.cflags`
/// where a file's name would record nothing a reader can check.
///
/// A Darwin linker argument such as `-Wl,-rpath,@loader_path/lib` is refused too. GNU ld
/// expands a word that begins with `@` and names a file whether or not it is an option's
/// argument (in the same run, gcc's `-Wl,-rpath,@file` linked a `RUNPATH` of the file's
/// contents), so the spelling alone does not say what the linker will read.
#[must_use]
pub fn response_file_arguments(flags: &[String]) -> Vec<String> {
    flags
        .iter()
        .filter(|word| {
            word.starts_with('@')
                || JOINED_PASS_THROUGH.iter().any(|option| {
                    word.strip_prefix(*option)
                        .is_some_and(|value| value.starts_with('@'))
                })
                || ["-Wl,", "-Wp,", "-Wa,"].iter().any(|list| {
                    word.strip_prefix(*list)
                        .is_some_and(|items| items.split(',').any(|item| item.starts_with('@')))
                })
        })
        .cloned()
        .collect()
}

/// The directory to run the driver in and the spelling of `source` to hand it: the
/// source's parent and its file name, or no directory and the path as it is when either
/// is missing. [`build`] says why.
fn in_place(source: &Path) -> (Option<&Path>, String) {
    match (source.parent(), source.file_name()) {
        (Some(dir), Some(name)) if !dir.as_os_str().is_empty() => {
            (Some(dir), Path::new(name).display().to_string())
        }
        _ => (None, source.display().to_string()),
    }
}

/// The digest a `-dM -E` dump record publishes as `stdout_sha256`, and the key of its
/// `macro-dump` entry in the report's store: SHA-256 of the dump's lines sorted bytewise and
/// joined by newlines, with no newline after the last, a repeated line kept as many times as
/// it was printed. Lines are split as [`str::lines`] splits them, so a `\r` before a newline
/// is not part of a line; the record's output is trimmed at its end before it gets here. The
/// same value is `LC_ALL=C sort` over the dump with its final newline removed, then
/// `sha256sum`.
///
/// gcc lists its macros in the order of its identifier table, so a `-D` that enters a name in
/// that table can move other macros in the list with none of them changed. A digest of the
/// dump as printed would move with that order; this one moves only where a line does. The
/// macros parsed from a dump ([`parse_macros`]) are a sorted map, so nothing read from the
/// dump depends on the order either.
#[must_use]
pub fn dump_digest(stdout: &str) -> String {
    let mut lines: Vec<&str> = stdout.lines().collect();
    lines.sort_unstable();
    crate::digest::sha256_hex(lines.join("\n").as_bytes())
}

/// Preprocess with `-dM -E` and return the predefined macros.
///
/// `with_libc_headers` decides whether libc headers are pulled in first. Both
/// dumps are needed: the bare one shows what the *compiler* defines (so
/// `__SSP_STRONG__` reflects a compiler default), while the with-headers one
/// additionally shows what libc concluded (`__USE_FORTIFY_LEVEL`).
///
/// `lang` is the language of `driver`, and names the source `macros-<tag>.<suffix>`
/// ([`crate::probe::Lang::source_suffix`]), so the C++ driver is handed a C++ file and
/// does not warn that it is treating C input as C++. The two are passed apart and the
/// callers pair them: `measure::Gatherer::gather` takes both from the probe's language,
/// `toolchain` the C driver with C and the C++ driver with C++, each held by
/// `tests/macro_dump_digest.rs`. The driver `--cc` names is dumped as C whatever its name,
/// so a C++ driver given there under `-Werror` still fails its dump, a run whose macro
/// channel withholds with the dump's error, which is true of it.
///
/// # Errors
///
/// Errors when the throwaway source cannot be written to `work`, or when the
/// compiler cannot be spawned.
pub fn macro_dump(
    driver: &Path,
    lang: crate::probe::Lang,
    flags: &[String],
    with_libc_headers: bool,
    work: &Path,
    tag: &str,
) -> Result<(BTreeMap<String, String>, BuildRecord)> {
    // A real file rather than stdin: it keeps the invocation reproducible by
    // hand and leaves the exact input behind as evidence.
    let source = work.join(format!("macros-{tag}.{}", lang.source_suffix()));
    let body = if with_libc_headers {
        LIBC_PROBE_HEADERS
    } else {
        ""
    };
    // A path chard constructed under the work directory, and tagged so: a failure to
    // write it is never the caller's typo.
    std::fs::write(&source, body)
        .with_context(|| crate::error::HarnessPath(source.clone()))
        .context("writing the macro-dump source")?;

    let mut args: Vec<String> = Vec::new();
    args.extend(flags.iter().cloned());
    args.push("-dM".to_owned());
    args.push("-E".to_owned());
    // The driver runs in the work directory and is handed the file by its name alone, as
    // [`build`] does for a probe, and for a reason of the same kind. gcc lists its macros in
    // the order of its identifier table, and the path it was given is entered in that table:
    // a path whose hash collides with a macro's moves that macro to another slot, and the
    // dump lists it elsewhere. Measured 2026-10-09 on Fedora 44 x86_64 (gcc 16.1.1, libstdc++
    // 16): `g++ -dM -E` over one 7-line source copied into 60 directories and run by absolute
    // path wrote the same 1358 lines in 8 orders, 53 copies in one and 7 in seven others, each
    // differing from the first in the position of one line (`__FLT64X_HAS_INFINITY__`,
    // `__unix__`, `_PSTL_CONFIG_H` and others). Run from inside each directory by file name,
    // the 60 copies wrote one order. One source under 60 file names in one directory gave 7
    // other orders as well, so the spelling of the path decides it, and one path run 21000
    // times wrote one order, so it is not a race. The parsed map is sorted and never sees the
    // order. A digest of the dump's stdout as printed would move with `--workdir`, so the
    // published digest is over the sorted lines ([`dump_digest`]).
    let (cwd, source_arg) = in_place(&source);
    args.push(source_arg);

    let record = invoke_with_timeout(driver, &args, cwd, INVOKE_TIMEOUT, DRAIN_GRACE)?;
    // The lines the job ended: a define cut short is not a define (`BuildRecord::whole_stdout`).
    Ok((parse_macros(record.whole_stdout()), record))
}

/// Parse `#define NAME VALUE` lines. Function-like macros keep their parameter
/// list in the key, since `__has_builtin(x)` and a hypothetical object-like
/// `__has_builtin` are different definitions.
pub fn parse_macros(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("#define ") else {
            continue;
        };
        match rest.split_once(' ') {
            Some((name, value)) => {
                out.insert(name.to_owned(), value.trim().to_owned());
            }
            // Defined with no replacement list: record it as present-but-empty
            // rather than dropping it, because presence is the signal for
            // several macros (_GLIBCXX_ASSERTIONS among them).
            None => {
                out.insert(rest.to_owned(), String::new());
            }
        }
    }
    out
}

/// Locate the C++ driver matching a C driver, if one exists.
///
/// The driver name is treated as `-`-separated components and the one naming the
/// language is rewritten in place. Suffix or prefix matching is not enough: real
/// drivers carry a version suffix (`gcc-15`), a target triple prefix
/// (`x86_64-pc-linux-gnu-gcc`), or both, and every distribution that ships more
/// than one compiler major ships the suffixed form. Matching only bare `gcc` and
/// `*-gcc` would silently answer `None` for `gcc-15`. A miss withholds as `indeterminate`
/// under `no-driver`, whose premise is this lookup, rather than reporting the C++ check
/// as not-applicable, a property of the toolchain rather than of the lookup; a wrong miss
/// still costs every C++ cell its verdict.
pub fn cxx_driver_for(cc: &Path) -> Option<PathBuf> {
    let name = cc.file_name()?.to_str()?;
    let mut parts: Vec<&str> = name.split('-').collect();
    let mapped = parts.iter_mut().find_map(|part| match *part {
        "gcc" => Some((part, "g++")),
        "clang" => Some((part, "clang++")),
        "cc" => Some((part, "c++")),
        _ => None,
    });
    let (slot, replacement) = mapped?;
    *slot = replacement;
    sibling(cc, &parts.join("-"))
}

fn sibling(original: &Path, name: &str) -> Option<PathBuf> {
    let candidate = original.with_file_name(name);
    candidate.exists().then_some(candidate)
}

/// Write `body` under a `#!/bin/sh` line at `path`, mark it executable, and wait until the
/// kernel will actually run it. For this crate's unit tests; `tests/common`'s `executable`
/// is the integration tests' copy.
///
/// The wait is the point. `cargo test` runs these tests on threads of one process, and a
/// thread that forks between another thread's `open` and `close` inherits the write
/// descriptor; until that child reaches its own `exec`, the file is open for writing
/// somewhere and `execve` on it fails with `ETXTBSY`. `toolchain::detect_linker_on` reads
/// that as a driver that did not answer and returns `kind: "unknown"` with no path, which is
/// a real failure of a test that was doing nothing wrong. Measured on Fedora 44 aarch64:
/// three different tests of the seven sharing the toolchain shims failed this way across
/// five full runs, one per run, each passing when run alone; the fifth run named it,
/// `running /tmp/chard-linker-bare-75657/cc: Text file busy (os error 26)`. On 2026-10-01
/// `run::tests::a_probe_receives_the_pinned_environment_and_nothing_else`, which then wrote
/// its script with `std::fs::write` and ran it at once, failed the same way once in four
/// lib runs on Fedora 44 x86_64; it and
/// `tests::a_build_names_its_source_relative_to_the_directory_it_runs_in` write through
/// here.
///
/// One successful spawn is enough. The descriptor can only be held by children that
/// already existed when the file was open, so once they have gone the file cannot become
/// busy again, and every later `exec` of it is safe. The spawn passes no arguments and
/// ignores the exit status, so `body` must tolerate being run bare. Retrying inside the
/// non-test code would be the wrong place: no code path there execs a file it wrote
/// itself, since a compiler has exited before its artifact is run.
#[cfg(test)]
pub(crate) fn test_script(path: &Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    // ETXTBSY is 26 on Linux and on Darwin alike. Any other error is left to the caller: a
    // script that cannot be run for another reason is a broken test, and waiting on it
    // would hide that.
    const ETXTBSY: i32 = 26;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("write a script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("mark the script executable");

    // Spawned through `capture`, which is where this crate's spawns are bounded;
    // `every_spawn_site_sits_where_something_bounds_it` holds every other file to it, test
    // modules included, and it is the same call the code under test will make.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let Err(why) = capture(path, &[]) else {
            break;
        };
        let busy = why.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.raw_os_error() == Some(ETXTBSY))
        });
        assert!(busy, "running the script {}: {why:#}", path.display());
        assert!(
            std::time::Instant::now() < deadline,
            "{} stayed busy for 5s; a descriptor is held open for writing somewhere that \
             never execs",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    /// [`dump_digest`] is SHA-256 of the lines sorted bytewise and joined by newlines with
    /// none after the last, a repeated line counted, the case of a line kept.
    #[test]
    fn a_dump_digest_is_the_sha256_of_its_sorted_lines() {
        use super::dump_digest;
        use crate::digest::sha256_hex;
        assert_eq!(dump_digest("b\na\n"), sha256_hex(b"a\nb"));
        assert_eq!(
            dump_digest("#define B 1\n#define A 2"),
            sha256_hex(b"#define A 2\n#define B 1")
        );
        assert_ne!(
            dump_digest("a\na"),
            dump_digest("a"),
            "a repeated line counts"
        );
        assert_ne!(dump_digest("A"), dump_digest("a"), "case is kept");
        assert_ne!(
            dump_digest("a b"),
            dump_digest("a  b"),
            "a line is kept whole"
        );
        assert_ne!(
            dump_digest("a \nb"),
            dump_digest("a\nb"),
            "a trailing space is kept"
        );
        assert_ne!(
            dump_digest(" a\nb"),
            dump_digest("a\nb"),
            "a leading space is kept"
        );
    }
    use super::*;

    /// Every C driver this corpus meets maps to its own C++ driver.
    ///
    /// Two arms could be deleted with the suite green. What that changes is which compiler
    /// builds the C++ probes: a missing `clang` arm sends a clang toolchain's C++ probes to
    /// no driver at all, so every C++ check reports its probe unbuildable — and the report
    /// blames chard rather than saying the toolchain has no C++ driver. `no-driver` withholds
    /// as `indeterminate` and names the lookup as its premise.
    ///
    /// The lookup only answers for a driver that is actually there, so the test puts the
    /// siblings on disk. The cross-compilation spellings matter as much as the bare ones:
    /// a driver is commonly `x86_64-linux-gnu-gcc`, and the mapping replaces that one
    /// component rather than the whole name.
    #[test]
    fn every_c_driver_maps_to_its_own_cxx_driver() {
        let dir = std::env::temp_dir().join(format!("chard-cxxmap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        for name in [
            "g++",
            "clang++",
            "c++",
            "x86_64-linux-gnu-g++",
            "aarch64-redhat-linux-clang++",
        ] {
            std::fs::write(dir.join(name), b"").expect("a driver to find");
        }
        let mapped = |name: &str| -> Option<String> {
            cxx_driver_for(&dir.join(name))
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        };

        assert_eq!(mapped("gcc").as_deref(), Some("g++"));
        assert_eq!(mapped("clang").as_deref(), Some("clang++"));
        assert_eq!(mapped("cc").as_deref(), Some("c++"));
        assert_eq!(
            mapped("x86_64-linux-gnu-gcc").as_deref(),
            Some("x86_64-linux-gnu-g++"),
            "a cross driver keeps its target triple"
        );
        assert_eq!(
            mapped("aarch64-redhat-linux-clang").as_deref(),
            Some("aarch64-redhat-linux-clang++")
        );

        // A driver with no C++ counterpart to name is `None` rather than a guess, and so
        // is one whose counterpart is not installed — the distinction the caller needs.
        assert_eq!(mapped("tcc"), None);
        std::fs::write(dir.join("icx"), b"").expect("write");
        assert_eq!(
            mapped("icx"),
            None,
            "a driver this mapping does not know is not guessed at"
        );

        // Cleanup, and its failure is not a finding: the scratch directory is
        // per-process and the next run makes its own.
        drop(std::fs::remove_dir_all(&dir));
    }

    /// Each path-bearing form is read in both spellings, an absolute, sysroot-relative or
    /// searched argument passes, and a word that only begins like an option is not one.
    #[test]
    fn a_relative_path_argument_is_found_in_every_form_it_takes() {
        let words = |text: &str| {
            text.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            relative_path_arguments(&words(
                "-Bld -L lib -Iinc -isystem sys -iquote q -include h.h --sysroot=sr \
                 --sysroot sr2 -resource-dir=rd --gcc-toolchain=tc -specs=dir/s.specs \
                 -specs dir2/t.specs -fuse-ld=bin/ld.lld @args -Wl,-z,now,-Lwl -Wl,-T,link.ld \
                 -fsanitize-ignorelist=ign.txt -iwithprefixbefore wpb"
            )),
            [
                "-Bld",
                "-L lib",
                "-Iinc",
                "-isystem sys",
                "-iquote q",
                "-include h.h",
                "--sysroot=sr",
                "--sysroot sr2",
                "-resource-dir=rd",
                "--gcc-toolchain=tc",
                "-specs=dir/s.specs",
                "-specs dir2/t.specs",
                "-fuse-ld=bin/ld.lld",
                "@args",
                "-Wl,-z,now,-Lwl",
                "-Wl,-T,link.ld",
                "-fsanitize-ignorelist=ign.txt",
                "-iwithprefixbefore wpb",
            ]
        );
        assert!(
            relative_path_arguments(&words(
                "-O2 -B/opt/ld -L /usr/lib -I=/inc -isystem $SYSROOT/inc --sysroot=/sr \
                 -fuse-ld=lld -specs=nosys.specs -specs nosys.specs @/tmp/args -Wl,-z,relro,-L/lib \
                 --config-user-dir=/c -fstack-protector-strong -D_FORTIFY_SOURCE=3"
            ))
            .is_empty()
        );
        assert_eq!(
            relative_path_arguments(&words("--config-user-dir=cfg --configure")),
            ["--config-user-dir=cfg"],
            "a long option joins only after `=`, and the longest option is the one read"
        );
    }

    /// clang's `-resource-dir`, which `toolchain::runtime_selecting_flags` carries to every
    /// arm, is refused relative in both spellings clang 22.1.8 accepts.
    #[test]
    fn a_relative_resource_directory_is_found_in_both_spellings() {
        let words = |text: &str| {
            text.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };
        let found = relative_path_arguments(&words(
            "-resource-dir rd -O2 -resource-dir=rd2 -resource-dir /abs -resource-dir=/abs2 \
             --gcc-triple=x86_64-other-linux-gnu",
        ));
        assert_eq!(found, ["-resource-dir rd", "-resource-dir=rd2"]);
    }

    /// `--prefix`, which gcc 16.1.1 and clang 22.1.8 read as `-B`, and clang's
    /// `-ccc-install-dir`, both carried to every arm by `toolchain::runtime_selecting_flags`,
    /// are refused relative in every spelling the drivers accept. Left out of
    /// [`PATH_OPTIONS`], `--prefix rel` would name one directory to the probe builds and
    /// another to the interrogations, as an unrefused `-Brel` would.
    #[test]
    fn a_relative_prefix_or_install_directory_is_found_in_every_spelling() {
        let words = |text: &str| {
            text.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };
        let fed = words(
            "--prefix=p1 -O2 --prefix p2 -ccc-install-dir bin --prefix=/abs --prefix /abs2 \
             -ccc-install-dir /abs3/bin --prefixes=x --prefix==/sr",
        );
        assert_eq!(fed.len(), 13, "the words fed");
        assert_eq!(
            relative_path_arguments(&fed),
            ["--prefix=p1", "--prefix p2", "-ccc-install-dir bin"],
            "the three relative spellings, and no absolute, sysroot-relative or longer option"
        );
    }

    /// clang's `-stdlib++-isystem`, which `toolchain::runtime_selecting_flags` carries to
    /// every arm, opens its directory as `-isystem` does, in both of the spellings clang
    /// 22.1.8 accepts. Missed, a relative C++ library header directory would reach the macro
    /// dump and the probe builds as two different directories.
    #[test]
    fn a_relative_cxx_library_header_directory_is_found_in_both_spellings() {
        let words = |text: &str| {
            text.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            relative_path_arguments(&words(
                "-stdlib++-isystem v1 -O2 -stdlib++-isystemv2 -stdlib++-isystem /abs                  -stdlib++-isystem/abs2 -stdlib=libc++ --gcc-install-dir=gid"
            )),
            [
                "-stdlib++-isystem v1",
                "-stdlib++-isystemv2",
                "--gcc-install-dir=gid"
            ]
        );
    }

    /// The readings of `line`'s relative paths, each as its argument and the reading's name.
    fn readings_of(line: &str) -> Vec<(String, String)> {
        let words: Vec<String> = line.split_whitespace().map(ToOwned::to_owned).collect();
        relative_path_readings(&words)
            .into_iter()
            .map(|found| {
                let reading = match found.reading {
                    PathReading::Relative => "relative".to_owned(),
                    PathReading::GccJoined { option, value } => format!("gcc {option} {value}"),
                    PathReading::Unpaired => "unpaired".to_owned(),
                };
                (found.argument, reading)
            })
            .collect()
    }

    /// Each line, and the arguments refused in it with their readings (`(argument, reading)`
    /// joined by `|`, `;` between them; empty where nothing is refused).
    fn row(line: &str, expected: &str) {
        let found: Vec<String> = readings_of(line)
            .into_iter()
            .map(|(argument, reading)| format!("{argument}|{reading}"))
            .collect();
        let expected: Vec<&str> = expected.split(';').filter(|e| !e.is_empty()).collect();
        assert_eq!(found, expected, "{line}");
    }

    /// The three lines below are read as the drivers read them (measured 2026-10-28 on
    /// Fedora 44 x86_64 with `-v -E`, gcc 16.1.1 and clang 22.1.8; [`relative_path_readings`]
    /// has the measurement): the path `-Xpreprocessor` hands the preprocessor is the one the
    /// pair after it hands, gcc's `-I-` names no directory, and clang's `-isystem-after` and
    /// `-include-pch` are refused for gcc's reading, which names its path. The relative shapes
    /// beside them are refused still.
    #[test]
    fn the_preprocessor_pair_gccs_split_and_clangs_longer_options_are_read_as_the_drivers_read_them()
     {
        let xp = "-Xpreprocessor";
        row(&format!("-O2 {xp} -I {xp} /abs"), "");
        row(
            &format!("{xp} -I {xp} rel"),
            &format!("{xp} -I {xp} rel|relative"),
        );
        row(
            &format!("{xp} -Irel {xp} -I/abs"),
            &format!("{xp} -Irel|relative"),
        );
        // The driver's `-I` still takes the word after it, a hand-on word included.
        row(&format!("-I {xp} /abs"), &format!("-I {xp}|relative"));
        row("-I- -O2", "");
        // clang reads the directory `-` for `-I -`, and its `-cc1` for `-I-` handed to it.
        row("-I -", "-I -|relative");
        row(&format!("{xp} -I-"), &format!("{xp} -I-|relative"));
        row("-Wp,-I-", "-Wp,-I-|relative");
        row("-Xclang -I-", "-Xclang -I-|relative");
        row("-Wp,-I,/abs -Wp,-I,rel", "-Wp,-I,rel|relative");
        // The assembler's lists read its `-I`, and the joined hand-ons to `-cc1` the driver's
        // options, as the pairs to them do.
        row(
            "-Wa,-I,rel -Wa,-I,/abs -Wa,--noexecstack",
            "-Wa,-I,rel|relative",
        );
        row("-Xclang=-Irel -Xclang=-I/abs", "-Xclang=-Irel|relative");
        row("-isystem-after /abs", "-isystem-after|gcc -isystem -after");
        row(
            "-isystem-after/abs",
            "-isystem-after/abs|gcc -isystem -after/abs",
        );
        row("-include-pch /abs.pch", "-include-pch|gcc -include -pch");
        // gcc reads the word after it as a driver word, and so does this reader.
        row(
            "-isystem-after -Lrel",
            "-isystem-after|gcc -isystem -after;-Lrel|relative",
        );
        // A tool gcc does not drive reads them as clang does.
        row("-Xclang -isystem-after -Xclang /abs", "");
        row(
            "-Xclang -include-pch -Xclang rel.pch",
            "-Xclang -include-pch -Xclang rel.pch|relative",
        );
        row(
            "-Xarch_x86_64 -Irel -Xarch_x86_64 -I/abs",
            "-Xarch_x86_64 -Irel|relative",
        );
    }

    /// The words handed to the linker are read as GNU ld reads them: `-L`, `-T` and their long
    /// spellings take a path, `-B` and the `-T` address options do not, and the words of
    /// `-Xlinker`, `--for-linker` and `-Wl,` read alike, as do the dynamic linker, the run-time
    /// search paths and the scripts and lists ld reads (`LINKER_PATH_OPTIONS`).
    #[test]
    fn the_words_handed_to_the_linker_are_read_as_the_linker_reads_them() {
        row("-Xlinker -Bsymbolic -Wl,-Bstatic", "");
        row("-Wl,-Ttext=0x1000 -Wl,-Ttext-segment,0x400000", "");
        row("-Xlinker -Tbss -Xlinker 0x0 -Xlinker -Tdata=0x10", "");
        row(
            "-Xlinker -L -Xlinker rel",
            "-Xlinker -L -Xlinker rel|relative",
        );
        row(
            "--for-linker -T --for-l rel.ld",
            "--for-linker -T --for-l rel.ld|relative",
        );
        row(
            "-Xlinker -L -Xlinker /abs -Xlinker -Lrel",
            "-Xlinker -Lrel|relative",
        );
        row(
            "-Wl,--library-path=lib -Wl,--script,s.ld -Wl,--sysroot=sr",
            "-Wl,--library-path=lib|relative;-Wl,--script,s.ld|relative;-Wl,--sysroot=sr|relative",
        );
        row("-Wl,-L,a,-L,b", "-Wl,-L,a,-L,b|relative");
        // The joined hand-on reads its one value within the word, as `-Wl,` reads its items.
        row(
            "--for-linker=-Lrel --for-linker=-L/abs --for-linker=-Bsymbolic --for-linker=-L",
            "--for-linker=-Lrel|relative;--for-linker=-L|unpaired",
        );
        row("-Xlinker @rel", "-Xlinker @rel|relative");
        row(
            "-Xoffload-linker -L -Xoffload-linker rel",
            "-Xoffload-linker -L -Xoffload-linker rel|relative",
        );
    }

    /// A path option handed to a tool with no path in the same word or the pair after it is
    /// refused as unpaired, since the tool reads its path from a word this reader does not
    /// pair with it, or the line hands it none; a hand-on word that ends the list hands it
    /// nothing.
    #[test]
    fn a_path_option_handed_without_its_path_is_refused_as_unpaired() {
        let xp = "-Xpreprocessor";
        row(
            &format!("{xp} -I -O2 {xp} rel"),
            &format!("{xp} -I|unpaired"),
        );
        row(
            &format!("{xp} -I -Xlinker x {xp} /abs"),
            &format!("{xp} -I|unpaired"),
        );
        row("-Xlinker -L -O2 -Xlinker rel", "-Xlinker -L|unpaired");
        row("-Wl,-L -Wl,dir", "-Wl,-L|unpaired");
        row("-Wp,-I", "-Wp,-I|unpaired");
        row(&format!("{xp} -I {xp}"), &format!("{xp} -I|unpaired"));
        row(&format!("{xp} -I -Xlinker"), &format!("{xp} -I|unpaired"));
        // The driver's own option at the end of a list is no path: the driver refuses it.
        row("-O2 -I", "");
        row("-Xarch_x86_64 -L", "");
    }

    /// Each tool's own options: clang's longer options handed to the preprocessor are read as
    /// gcc's `cc1` reads them, GNU as reads only `-I` (its `-L` keeps local symbols), ld's
    /// dynamic linker, run-time search paths, scripts and lists name paths and its `-T`
    /// address options do not, and the word `-Xarch_<arch>` hands clang's driver is read with
    /// the list it carries.
    #[test]
    fn each_tool_reads_its_own_options() {
        let xp = "-Xpreprocessor";
        row(
            &format!("{xp} -isystem-after {xp} /abs"),
            &format!("{xp} -isystem-after|gcc -isystem -after"),
        );
        row(
            "-Wp,-include-pch,/p.pch",
            "-Wp,-include-pch,/p.pch|gcc -include -pch",
        );
        row("-Wa,-L -Xassembler -L -Wa,--noexecstack,-L", "");
        row(
            "-Xassembler -I --for-a rel",
            "-Xassembler -I --for-a rel|relative",
        );
        row(
            "-Wa,-I --for-assembler=-Irel",
            "-Wa,-I|unpaired;--for-assembler=-Irel|relative",
        );
        row(
            "-Xlinker --library-path -Xlinker rel",
            "-Xlinker --library-path -Xlinker rel|relative",
        );
        row(
            "-Wl,-Trodata-segment=0x1000 -Wl,-Tldata-segment,0x0 -Wl,-call_shared",
            "",
        );
        row(
            "-Xlinker -Irel -Xlinker -I/lib/ld.so",
            "-Xlinker -Irel|relative",
        );
        row(
            "-Wl,--dynamic-linker=rel -Wl,-rpath,rel -Wl,--version-script=v.map -Wl,-R,lib",
            "-Wl,--dynamic-linker=rel|relative;-Wl,-rpath,rel|relative;\
             -Wl,--version-script=v.map|relative;-Wl,-R,lib|relative",
        );
        row(
            "-Wl,-rpath,/opt/lib -Wl,-rpath-link=/opt/lib -Wl,-o,out",
            "",
        );
        row(
            "-Xarch_x86_64 -Wl,-Lrel",
            "-Xarch_x86_64 -Wl,-Lrel|relative",
        );
    }

    /// A value-taking option that names no path takes the next word as its value, unread,
    /// as both drivers take it (`toolchain::takes_a_value`), and an option of
    /// [`PATH_OPTIONS`] among them keeps its path reading.
    #[test]
    fn a_value_taking_option_takes_its_value_unread() {
        row("-u -Brel -MF -Lrel -o -Irel -D -Irel -z -L", "");
        row("-u -Brel -Lrel", "-Lrel|relative");
        row(
            "-iprefix rel -F rel",
            "-iprefix rel|relative;-F rel|relative",
        );
        row("-O2 -u", "");
        // gcc's long spellings of a value-taking option, and of a word that joins the next
        // (`--std rel` is `-std=rel`, `--machine rel` is `-mrel`), take it unread too.
        row(
            "--forc -Brel --force-link=rel --def -Lrel --la rel --std rel --machine rel",
            "",
        );
    }

    /// gcc's long spellings and abbreviations of the path options are read as the short
    /// words (`toolchain::LONG_ALIASES`): `--li rel` is `-L rel`, `--sys rel` is `--sysroot
    /// rel`, `--pref rel/` is `-B rel/`, `--im rel.h` is `-imacros rel.h`,
    /// `--include-directory rel` is `-I rel`, `--include=rel.h` is `-include rel.h`,
    /// `--specs rel/f` and `--sp rel/f` are `-specs=rel/f`, each refused as the short
    /// spelling is; an absolute path under each passes, as do `--machine 32`, which names no
    /// path, and `--sp nosys.specs`, a name the driver searches for.
    #[test]
    fn gccs_long_spellings_of_the_path_options_are_read_as_the_short_words() {
        row(
            "--li rel --sys rel2 --pref rel3/ --im rel.h --include-directory rel4 \
             --include=rel5.h --library-directory=rel6 --prefix rel7/ --sysroot=rel8 \
             --specs rel9/s.specs --sp rel10/s.specs",
            "--li rel|relative;--sys rel2|relative;--pref rel3/|relative;--im rel.h|relative;\
             --include-directory rel4|relative;--include=rel5.h|relative;\
             --library-directory=rel6|relative;--prefix rel7/|relative;--sysroot=rel8|relative;\
             --specs rel9/s.specs|relative;--sp rel10/s.specs|relative",
        );
        row(
            "--li /x --sys /r --pref /p/ --im /m.h --include-directory /i --include=/h \
             --machine 32 --machine=32 --optimize=2 --op --specs /s.specs --sp nosys.specs",
            "",
        );
        // Handed to gcc's `cc1`, which reads the long spellings as the driver does.
        row(
            "-Wp,--include=rel.h -Xpreprocessor --imacros=rel2.h -Wp,--im,rel3.h \
             -Xpreprocessor --include -Xpreprocessor rel4.h",
            "-Wp,--include=rel.h|relative;-Xpreprocessor --imacros=rel2.h|relative;\
             -Wp,--im,rel3.h|relative;-Xpreprocessor --include -Xpreprocessor rel4.h|relative",
        );
        row(
            "-Wp,--include=/h -Xpreprocessor --im -Xpreprocessor /m.h",
            "",
        );
        // Applied by clang for one architecture, and through gcc's generic map.
        row(
            "-Xarch_x86_64 --include-directory=rel --profile-use=rel2",
            "-Xarch_x86_64 --include-directory=rel|relative;--profile-use=rel2|relative",
        );
        row(
            "-Xarch_x86_64 --include-directory=/i --profile-use=/p --use-ld=gold",
            "",
        );
        // clang's own `--` options stay as written through gcc's generic map (`--config=f`
        // is no `-fconfig=f`), joined and two-token; and every `--` option of this reader
        // joined to a relative path is found, whatever table owns it.
        row(
            "--config=rel/c.cfg --config rel2/c.cfg --gcc-toolchain=rel3 --config-user-dir=rel4",
            "--config=rel/c.cfg|relative;--config rel2/c.cfg|relative;--gcc-toolchain=rel3|relative;\
             --config-user-dir=rel4|relative",
        );
        row("--config=/c.cfg --config /c2.cfg --gcc-toolchain=/t", "");
        let mut fed = 0_usize;
        for option in PATH_OPTIONS.iter().chain(PATH_OR_NAME_OPTIONS) {
            let stem = option.trim_end_matches('=');
            if !stem.starts_with("--") {
                continue;
            }
            row(&format!("{stem}=rel/p"), &format!("{stem}=rel/p|relative"));
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 8, "every `--` option of the path tables was fed");
    }

    /// Every entry of the linker's tables is read as it says: a path option refuses a relative
    /// path handed after it, through `-Xlinker` pairs and in a `-Wl,` list, and passes an
    /// absolute one and a loader token; a joined one refuses its relative path in the word; a
    /// path-or-name option refuses a relative path holding a `/` and passes a bare name; and
    /// the offload linker's words are its own run, apart from the linker's.
    #[test]
    fn every_linker_table_entry_is_read_as_it_says() {
        let mut fed = 0_usize;
        for option in LINKER_PATH_OPTIONS {
            row(
                &format!("-Xlinker {option} -Xlinker rel"),
                &format!("-Xlinker {option} -Xlinker rel|relative"),
            );
            row(
                &format!("-Wl,{option},rel"),
                &format!("-Wl,{option},rel|relative"),
            );
            row(&format!("-Wl,{option},/abs -Wl,{option},$ORIGIN/lib"), "");
            fed = fed.saturating_add(1);
        }
        for option in LINKER_PATH_JOINED {
            row(
                &format!("-Wl,{option}rel"),
                &format!("-Wl,{option}rel|relative"),
            );
            row(&format!("-Wl,{option}/abs"), "");
            fed = fed.saturating_add(1);
        }
        for option in LINKER_PATH_OR_NAME_OPTIONS {
            row(
                &format!("-Wl,{option},sub/x.so"),
                &format!("-Wl,{option},sub/x.so|relative"),
            );
            row(&format!("-Wl,{option},x.so -Wl,{option},/abs/x.so"), "");
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed,
            LINKER_PATH_OPTIONS.len()
                + LINKER_PATH_JOINED.len()
                + LINKER_PATH_OR_NAME_OPTIONS.len()
        );
        row(
            "-Wl,--plugin=sub/p.so -Wl,--audit=a.so",
            "-Wl,--plugin=sub/p.so|relative",
        );
        row(
            "-Xoffload-linker -L -Xlinker rel",
            "-Xoffload-linker -L|unpaired",
        );
    }

    /// clang's longer options this reader reads gcc's way are the ones the selection walk
    /// passes over alone (`toolchain::HEADER_LONGER`), each begins with the shorter
    /// [`PATH_OPTIONS`] option gcc reads, and both are in that list.
    #[test]
    fn clangs_longer_options_are_the_selection_walks() {
        let longer: Vec<&str> = CLANG_LONGER.iter().map(|(longer, _)| *longer).collect();
        assert_eq!(longer, crate::toolchain::HEADER_LONGER);
        for (longer, shorter) in CLANG_LONGER {
            assert!(
                longer.starts_with(shorter),
                "{longer} begins with {shorter}"
            );
            assert!(PATH_OPTIONS.contains(&longer) && PATH_OPTIONS.contains(&shorter));
        }
    }

    /// An `--env` value is refused with how its argument was read: gcc's reading of clang's own
    /// option, or a path option handed without its path, beside the relative path as written.
    #[test]
    fn an_env_value_is_refused_with_its_reading() {
        let refused = |value: &str| {
            let err =
                compiler_environment_additions(&[format!("CHARD_W={value}")]).expect_err("refused");
            format!("{err:#}")
        };
        assert!(refused("-isystem-after /abs").contains("which gcc reads as -isystem"));
        assert!(refused("-Xlinker -L -O1").contains("whose path is not handed"));
        assert!(refused("-Lrel").contains("is a relative path"));
    }

    /// A response file is found in every spelling the 2026-10-05 measurement saw a tool
    /// expand, and an `@` inside a word that hands no tool a file is not one.
    #[test]
    fn a_response_file_is_found_in_every_spelling_a_tool_expands() {
        let words = |text: &str| {
            text.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            response_file_arguments(&words(
                "-O2 @args @/opt/m32.rsp -Xlinker @ld.rsp -Xclang @cc1.rsp -Wp,@pp.rsp \
                 -Wa,@as.rsp -Wl,-z,now,@ld2.rsp -Wl,-rpath,@loader_path/lib \
                 --for-linker=@ld3.rsp -Xpreprocessor @pp2.rsp -Xclang=@cc1b.rsp \
                 --for-assembler=@as2.rsp -mllvm=@llvm.rsp -Xclangas=@cc1as.rsp \
                 -Xthinlto-distributor=@dist.rsp -Xarch_x86_64 @arch.rsp"
            )),
            [
                "@args",
                "@/opt/m32.rsp",
                "@ld.rsp",
                "@cc1.rsp",
                "-Wp,@pp.rsp",
                "-Wa,@as.rsp",
                "-Wl,-z,now,@ld2.rsp",
                "-Wl,-rpath,@loader_path/lib",
                "--for-linker=@ld3.rsp",
                "@pp2.rsp",
                "-Xclang=@cc1b.rsp",
                "--for-assembler=@as2.rsp",
                "-mllvm=@llvm.rsp",
                "-Xclangas=@cc1as.rsp",
                "-Xthinlto-distributor=@dist.rsp",
                "@arch.rsp",
            ]
        );
        assert!(
            response_file_arguments(&words(
                "-O2 -DAT=@ -Wl,--defsym,a@b=0 -fuse-ld=lld -I/opt/x@y -Wl,-z,now \
                 -Xclang=-DX=@ -mllvm=-x=@y --for-assembler=--noexecstack"
            ))
            .is_empty()
        );
    }

    /// The variables the 2026-10-05 measurement found a driver reading stay named.
    ///
    /// `tests/fake_driver.rs` holds the spawned process to whatever the list says and
    /// `tests/register.rs` holds `THREAT_MODEL.md` to it, so neither notices an entry
    /// leaving both. This names the four the list's comment records as measured.
    #[test]
    fn the_include_and_temporary_directory_variables_are_on_the_record() {
        for name in ["CPLUS_INCLUDE_PATH", "TMP", "TEMP", "TEMPDIR"] {
            assert!(
                COMPILER_ENV_NAMED.contains(&name),
                "{name} left the named variables, which a driver was measured reading"
            );
        }
    }

    /// A passed variable chard lacks is left out of the compiler's environment rather than
    /// handed over empty, and one it has is handed over as it has it, before the pins.
    #[test]
    fn a_passed_variable_chard_lacks_is_absent_from_the_compiler_environment() {
        use std::ffi::OsString;
        let pins: Vec<(OsString, OsString)> = COMPILER_ENV_PINNED
            .iter()
            .map(|(name, value)| ((*name).into(), (*value).into()))
            .collect();
        assert_eq!(
            compiler_environment_from(|_| None, &EnvPairs::default()),
            pins
        );
        let expected: Vec<(OsString, OsString)> = COMPILER_ENV_PASSED
            .iter()
            .map(|name| ((*name).into(), format!("value-of-{name}").into()))
            .chain(pins)
            .collect();
        assert_eq!(
            compiler_environment_from(
                |name| Some(format!("value-of-{name}").into()),
                &EnvPairs::default()
            ),
            expected
        );
    }

    /// The `--env` pairs reach the compiler after the passed variables and before the pins,
    /// and the published form names the passed variables without their values and carries
    /// every value chard set.
    #[test]
    fn the_added_pairs_sit_between_the_passed_variables_and_the_pins() {
        use std::ffi::OsString;
        let added =
            compiler_environment_additions(&["NIX_HARDENING_ENABLE=fortify pic".to_owned()])
                .expect("a plain pair");
        let applied =
            compiler_environment_from(|name| Some(format!("value-of-{name}").into()), &added);
        let names: Vec<OsString> = applied.iter().map(|(name, _)| name.clone()).collect();
        let expected: Vec<OsString> = COMPILER_ENV_PASSED
            .iter()
            .map(|name| OsString::from(*name))
            .chain(std::iter::once("NIX_HARDENING_ENABLE".into()))
            .chain(
                COMPILER_ENV_PINNED
                    .iter()
                    .map(|(name, _)| OsString::from(*name)),
            )
            .collect();
        assert_eq!(names, expected);
        let published = CompilerEnvironment::published(applied, &added);
        assert_eq!(published.passed, COMPILER_ENV_PASSED);
        assert_eq!(
            published
                .set
                .get("NIX_HARDENING_ENABLE")
                .map(String::as_str),
            Some("fortify pic")
        );
        for (name, value) in COMPILER_ENV_PINNED {
            assert_eq!(published.set.get(*name).map(String::as_str), Some(*value));
        }
        assert!(
            !serde_json::to_string(&published)
                .unwrap()
                .contains("value-of-PATH"),
            "the passed variable's value is published"
        );
        assert_eq!(
            published.added().collect::<Vec<_>>(),
            [("NIX_HARDENING_ENABLE", "fortify pic")]
        );
    }

    /// The run's pairs are fixed by their first read: a set after it fails, as does a second
    /// set, and the value read stays the one every invocation saw.
    #[test]
    fn a_set_after_the_pairs_were_read_is_an_error() {
        let pairs = compiler_environment_additions(&["A=1".to_owned()]).expect("a plain pair");
        let read_first = RunEnvironment::new();
        assert!(read_first.get().as_slice().is_empty());
        assert!(
            read_first.set(pairs.clone()).is_err(),
            "a set after a read succeeded, so invocations before and after it saw two environments"
        );
        assert!(read_first.get().as_slice().is_empty());

        let set_first = RunEnvironment::new();
        set_first
            .set(pairs.clone())
            .expect("the first set, before any read");
        assert!(
            set_first.set(EnvPairs::default()).is_err(),
            "a second set succeeded"
        );
        assert_eq!(set_first.get(), &pairs);
    }

    /// `--env` is refused, every argument named, where the compiler's environment cannot
    /// honour it as written; what it accepts comes back sorted by name.
    #[test]
    fn an_env_argument_naming_a_passed_or_pinned_or_malformed_name_is_refused() {
        let args = |list: &[&str]| list.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        for refused in [
            "PATH=/usr/bin",
            "LC_ALL=en_US.UTF-8",
            "TERM=xterm",
            "NOVALUE",
            "=x",
            "1ABC=x",
            "A-B=x",
            "G++_ROOT=x",
            "A=x\0y",
        ] {
            let err = compiler_environment_additions(&args(&[refused]))
                .expect_err(refused)
                .downcast::<crate::error::ConfigError>()
                .unwrap_or_else(|e| panic!("{refused}: not a ConfigError: {e}"));
            assert!(
                err.0.contains(&format!("{refused:?}")),
                "{refused}: {}",
                err.0
            );
            assert!(
                !err.0.contains("  "),
                "{refused}: the message holds a run of spaces: {}",
                err.0
            );
        }
        let twice = compiler_environment_additions(&args(&["A=1", "A=2"]))
            .unwrap_err()
            .downcast::<crate::error::ConfigError>()
            .expect("a twice-given name is a ConfigError");
        assert!(twice.0.contains("more than once"), "{}", twice.0);
        let both = compiler_environment_additions(&args(&["PATH=x", "TERM=y"])).unwrap_err();
        assert!(
            both.to_string().contains("PATH") && both.to_string().contains("TERM"),
            "every refused argument is named: {both}"
        );
        assert_eq!(
            compiler_environment_additions(&args(&["ZED=", "NIX_HARDENING_ENABLE=a=b c"]))
                .unwrap()
                .as_slice(),
            [
                ("NIX_HARDENING_ENABLE".to_owned(), "a=b c".to_owned()),
                ("ZED".to_owned(), String::new()),
            ]
        );
        let late = RunEnvironment::new();
        late.get();
        let message = late.set(EnvPairs::default()).unwrap_err().to_string();
        assert!(!message.contains("  "), "a run of spaces: {message}");
    }

    /// A value holding a relative path is found, whether as a path-list entry, a word naming
    /// something in chard's directory, or a flag a wrapper variable carries; an absolute
    /// path, a sysroot path, a reference and a plain word are not.
    #[test]
    fn a_relative_path_in_an_env_value_is_found() {
        let in_cwd = |path: &Path| path == Path::new("rel");
        for (value, found) in [
            ("rel", Some("rel")),
            ("/opt/a:rel", Some("rel")),
            ("bin/ld", Some("bin/ld")),
            ("/opt/a:./b", Some("./b")),
            (".", Some(".")),
            ("..", Some("..")),
            ("-isystem inc/x", Some("-isystem inc/x")),
            ("-Bmy-ld", Some("-Bmy-ld")),
            ("-O2 @flags.rsp", Some("@flags.rsp")),
            ("/opt/a:/opt/b", None),
            ("-B/opt/ld -isystem=/inc", None),
            ("$ORIGIN/lib", None),
            ("bindnow format fortify pic", None),
            ("1", None),
            ("", None),
        ] {
            assert_eq!(
                relative_path_in_value(value, in_cwd)
                    .map(|found| found.argument)
                    .as_deref(),
                found,
                "{value:?}"
            );
        }
        assert!(
            compiler_environment_additions(&["COMPILER_PATH=bin/ld".to_owned()]).is_err(),
            "a relative path entry was accepted"
        );
    }

    /// The environment a toolchain invocation is given names the passed variables chard
    /// has and the pins, and nothing else: no found variable, whatever chard's own
    /// environment holds, and no name twice.
    #[test]
    fn the_compiler_environment_is_the_passed_variables_and_the_pins() {
        let given: Vec<String> = compiler_environment()
            .into_iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        let expected: Vec<String> = COMPILER_ENV_PASSED
            .iter()
            .filter(|name| std::env::var_os(name).is_some())
            .copied()
            .chain(COMPILER_ENV_PINNED.iter().map(|(name, _)| *name))
            .map(str::to_owned)
            .collect();
        assert_eq!(given, expected);
        for name in COMPILER_ENV_NAMED {
            assert!(
                !given.iter().any(|g| g == name),
                "{name} is handed to the driver"
            );
        }
        for (name, value) in COMPILER_ENV_PINNED {
            assert!(
                compiler_environment()
                    .iter()
                    .any(|(n, v)| n == *name && v == *value),
                "{name} is not pinned to {value}"
            );
        }
        let mut names = given.clone();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), given.len(), "a name is set twice: {given:?}");
    }

    /// The driver is handed the source by its file name and runs where that name
    /// resolves, so the name it compiles in does not carry the work directory.
    ///
    /// The stand-in driver copies whatever its last argument names, read from its own
    /// working directory, to its `-o` path: a copy of the source means both halves held.
    #[test]
    fn a_build_names_its_source_relative_to_the_directory_it_runs_in() {
        let dir = std::env::temp_dir().join(format!("chard-in-place-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        // Run bare by `test_script`'s wait, with no `-o`: it exits before touching a file.
        let driver = test_script(
            &dir.join("driver.sh"),
            "[ $# -gt 0 ] || exit 0\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -o ]; then o=$2; shift; fi\n  \
             last=$1; shift\ndone\ncat \"$last\" > \"$o\"",
        );
        let source = dir.join("probe.c");
        std::fs::write(&source, "int main(void){return 0;}\n").expect("source");
        let out = dir.join("probe");

        let record = build(&driver, &[], &source, &out, &[]).expect("a record");
        assert!(record.succeeded(), "{}", record.stderr);
        assert_eq!(record.argv.last().map(String::as_str), Some("probe.c"));
        assert_eq!(
            std::fs::read_to_string(&out).expect("the copy"),
            "int main(void){return 0;}\n",
            "the bare name resolved somewhere other than the source's directory"
        );
        assert_eq!(in_place(Path::new("probe.c")), (None, "probe.c".to_owned()));
        drop(std::fs::remove_dir_all(&dir));
    }

    /// A program that outlives the bound is killed, and the failure is an error.
    ///
    /// The distinction being pinned is not "does it stop" but "what does stopping produce".
    /// A timed-out compile that came back as a `BuildRecord` would have `succeeded() ==
    /// false`, and the `compiler-diag` channel reads a failed compile as its *observable* —
    /// so a wedged toolchain would publish as "the compiler rejected this", a measurement
    /// from a run that measured nothing.
    ///
    /// Uses a one-second bound via a helper rather than the real 120s, because a test that
    /// takes two minutes to prove a timeout is a test nobody runs.
    /// A build reads back only what it wrote, never what was already there.
    ///
    /// The work directory is reused by design — `--workdir` defaults into the caller's
    /// CWD and is retained as evidence rather than cleaned — so a probe whose build
    /// writes no output file would otherwise inherit the previous run's binary at the
    /// same name. Measured before the removal existed: `--profile openssf-tldr` followed
    /// by `--profile explicit --flags -fsyntax-only` over one work directory published
    /// `pie`, `relro` and `noexecstack` as `on`, from the first run's artifact, with the
    /// same `artifact_sha256` in both reports and every control triple `discriminating`.
    ///
    /// A fabricated `on` is the one outcome the control triple exists to make impossible,
    /// and reaching it took two ordinary invocations rather than a hostile compiler.
    ///
    /// `true` stands in for a driver that exits 0 and writes nothing, which is what
    /// `-fsyntax-only` does to a real one. Resolved on `PATH` rather than hardcoded to
    /// `/bin/true`, which does not exist on macOS -- a host this project claims to run
    /// on, and where the hardcoded path failed the test for the host's reasons rather
    /// than the code's.
    #[test]
    fn a_build_that_writes_nothing_does_not_inherit_the_last_one() {
        let dir = std::env::temp_dir().join(format!("chard-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let out = dir.join("probe");
        let source = dir.join("probe.c");
        std::fs::write(&source, "int main(void){return 0;}\n").expect("source");
        std::fs::write(&out, b"\x7fELF stale artifact from a previous run").expect("stale");

        let exits_zero = crate::toolchain::resolve_driver("true").expect("`true` on PATH");
        let record = build(&exits_zero, &[], &source, &out, &[])
            .expect("a driver that exits 0 yields a record");

        assert!(record.succeeded(), "`true` exits 0");
        assert_eq!(
            record.artifact_sha256, None,
            "no artifact was written, so there is no artifact to hash — a `Some` here is \
             the hash of somebody else's build"
        );
        assert!(
            !out.exists(),
            "the stale file must be gone, not merely unhashed: the runner and the ELF \
             reader both open this path by name"
        );
        // Named rather than `.ok()`, so the lint wall stays intact: a temp directory
        // that outlives a failing test is not a failure worth reporting.
        crate::error::best_effort(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_program_that_never_exits_is_an_error_and_not_a_failed_build() {
        let started = Instant::now();
        let got = invoke_with_timeout(
            Path::new("/bin/sh"),
            &["-c".to_owned(), "sleep 30".to_owned()],
            None,
            Duration::from_millis(400),
            Duration::from_millis(300),
        );
        let err = got.expect_err("a program that outlives the bound must not return a record");
        let text = format!("{err}");
        assert!(
            text.contains("did not finish"),
            "the error has to say what happened: {text}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the child must actually be killed, not merely reported on"
        );
    }

    /// The bound covers *reading* the output, not merely waiting for the child.
    ///
    /// `try_wait` returning a status means the child is gone, not that its pipes are
    /// closed — a backgrounded process inherits the write end and holds it open. Joining
    /// the drain threads therefore had no deadline of its own, and this exact call
    /// returned after 30.0 s under a 400 ms bound before `DRAIN_GRACE` existed.
    ///
    /// What it must produce is an error rather than a `BuildRecord` with empty streams:
    /// an unread stderr published as empty says "the compiler was silent", which is a
    /// `compiler-diag` observable, from a stream nobody read.
    #[test]
    fn the_bound_covers_reading_the_output_not_only_waiting_for_the_child() {
        let started = Instant::now();
        let got = invoke_with_timeout(
            Path::new("/bin/sh"),
            &["-c".to_owned(), "sleep 30 & exit 0".to_owned()],
            None,
            Duration::from_millis(400),
            Duration::from_millis(300),
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the call outlived both of its bounds, taking {:?}",
            started.elapsed()
        );
        let err = got.expect_err("a stream that could not be read must not publish as empty");
        assert!(
            format!("{err}").contains("still held"),
            "the error has to say what happened: {err}"
        );
    }

    /// Output still arrives whole, on both streams, when the program exits normally.
    ///
    /// The timeout drains by hand where `.output()` would, and the hazard of that is a
    /// child that fills a pipe while nothing is reading it. This writes more than a pipe
    /// buffer holds (`64 KiB` is the usual Linux capacity), so a version that waits on the
    /// child before draining deadlocks here rather than in a sweep.
    #[test]
    fn output_survives_the_draining_even_when_it_exceeds_a_pipe_buffer() {
        let record = invoke(
            Path::new("/bin/sh"),
            &[
                "-c".to_owned(),
                "yes abcdefghijklmnopqrstuvwxyz | head -c 200000; \
                 yes ERRORLINE | head -c 200000 >&2; exit 3"
                    .to_owned(),
            ],
        )
        .expect("a program that exits is not an error");
        assert_eq!(
            record.exit_status, 3,
            "the real status, not an invented one"
        );
        // Not an exact count: `BuildRecord` trims trailing whitespace on both streams, so
        // stderr lands one byte short of what was written. What is being pinned is that
        // neither stream stopped at a pipe buffer — 64 KiB on Linux — which is the failure
        // a wait-before-drain would produce.
        assert!(
            record.stdout.len() > 150_000,
            "stdout truncated at {} bytes, which is a pipe buffer and not the output",
            record.stdout.len()
        );
        assert!(
            record.stderr.len() > 150_000,
            "stderr truncated at {} bytes, which is a pipe buffer and not the output",
            record.stderr.len()
        );
        assert!(record.diagnostics_contain("errorline"));
    }

    /// The mapping is pure string work; `sibling` is what touches the filesystem.
    /// Testing it separately keeps the table honest without needing a toolchain.
    fn map_name(name: &str) -> Option<String> {
        let mut parts: Vec<&str> = name.split('-').collect();
        let (slot, replacement) = parts.iter_mut().find_map(|part| match *part {
            "gcc" => Some((part, "g++")),
            "clang" => Some((part, "clang++")),
            "cc" => Some((part, "c++")),
            _ => None,
        })?;
        *slot = replacement;
        Some(parts.join("-"))
    }

    #[test]
    fn maps_versioned_and_triple_prefixed_drivers() {
        assert_eq!(map_name("gcc").as_deref(), Some("g++"));
        assert_eq!(map_name("gcc-15").as_deref(), Some("g++-15"));
        assert_eq!(map_name("clang-19").as_deref(), Some("clang++-19"));
        assert_eq!(
            map_name("x86_64-pc-linux-gnu-gcc").as_deref(),
            Some("x86_64-pc-linux-gnu-g++")
        );
        assert_eq!(
            map_name("x86_64-pc-linux-gnu-gcc-15").as_deref(),
            Some("x86_64-pc-linux-gnu-g++-15")
        );
        assert_eq!(map_name("cc").as_deref(), Some("c++"));
        // Already a C++ driver, and things that merely contain the letters.
        assert_eq!(map_name("g++"), None);
        assert_eq!(map_name("clang++"), None);
        assert_eq!(map_name("tcc"), None);
    }

    /// Every child chard spawns is spawned somewhere that bounds it.
    ///
    /// `INVOKE_TIMEOUT` claims that every measurement runs through this module. That is
    /// a claim about the whole crate, and it was false: `env::musl_version` called
    /// `.output()` directly — which waits forever — on the `chard measure` path of every
    /// musl host. Nothing detected it, because a claim in a doc comment has nothing
    /// holding it up.
    ///
    /// Two modules may spawn, and each carries its own bound: `compile` with
    /// `INVOKE_TIMEOUT` and `DRAIN_GRACE`, `run` with the probe timeout its caller
    /// supplies. A `Command::new` anywhere else is a child with nothing bounding it,
    /// which is how an unbounded `.output()` call would get in.
    #[test]
    fn every_spawn_site_sits_where_something_bounds_it() {
        const BOUNDED: &[&str] = &["compile.rs", "run.rs"];
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        // The whole tree, not its top level: `src/decode/` and `src/predicate/` hold modules,
        // and a child spawned there is as unbounded as one spawned beside this file. The
        // exemption is keyed on the path below `src/`, so a nested file sharing a bounded
        // module's name is scanned rather than excused.
        let mut dirs = vec![src.clone()];
        let mut files = Vec::new();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("src/ is readable") {
                let path = entry.expect("a readable entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        for path in files {
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            scanned += 1;
            if path
                .strip_prefix(&src)
                .is_ok_and(|p| p.to_str().is_some_and(|n| BOUNDED.contains(&n)))
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a readable source file");
            for (i, line) in text.lines().enumerate() {
                if line.contains("Command::new") {
                    offenders.push(format!("{}:{}", path.display(), i + 1));
                }
            }
        }
        // Emit the frame, not just the count: a scan that silently walked zero files
        // would report "no offenders" just as loudly as a clean tree.
        assert!(
            scanned >= 15,
            "the scan covered only {scanned} source files, which is not the crate"
        );
        assert!(
            offenders.is_empty(),
            "these spawn a child outside {BOUNDED:?}, so nothing bounds it: {}",
            offenders.join(", ")
        );
    }

    /// Every Rust source file under `src/`, nested modules included, keyed on its path
    /// below `src/` and sorted, so the scan reads the same frame on every host.
    fn rust_sources() -> Vec<(String, String)> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut dirs = vec![src.clone()];
        let mut files = Vec::new();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("src/ is readable") {
                let path = entry.expect("a readable entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let name = path
                        .strip_prefix(&src)
                        .expect("a file found under src/")
                        .to_string_lossy()
                        .into_owned();
                    let text = std::fs::read_to_string(&path).expect("a readable source file");
                    files.push((name, text));
                }
            }
        }
        files.sort();
        files
    }

    /// `text` with every comment and every string, byte-string and character literal blanked
    /// to spaces and its newlines kept, so line `n` of the result is line `n` of `text` and a
    /// word left in it is code. A block comment or literal still open at the end of the file
    /// panics: that is how a lexer that lost its place shows, rather than as a file whose
    /// remainder it silently blanked.
    fn code_only(name: &str, text: &str) -> String {
        let s: Vec<char> = text.chars().collect();
        let mut out = s.clone();
        let ident = |c: char| c.is_alphanumeric() || c == '_';
        let mut i = 0;
        while i < s.len() {
            let start = i;
            let at = |k: usize| s.get(i + k).copied();
            if s[i] == '/' && at(1) == Some('/') {
                while i < s.len() && s[i] != '\n' {
                    i += 1;
                }
            } else if s[i] == '/' && at(1) == Some('*') {
                let mut depth = 0usize;
                loop {
                    match (s.get(i), s.get(i + 1)) {
                        (Some('/'), Some('*')) => (depth, i) = (depth + 1, i + 2),
                        (Some('*'), Some('/')) => (depth, i) = (depth - 1, i + 2),
                        (Some(_), _) => i += 1,
                        (None, _) => {
                            panic!("{name}: a block comment at char {start} is not closed")
                        }
                    }
                    if depth == 0 {
                        break;
                    }
                }
            } else if s[i] == '"' {
                i += 1;
                loop {
                    match s.get(i) {
                        Some('\\') => i += 2,
                        Some('"') => break i += 1,
                        Some(_) => i += 1,
                        None => panic!("{name}: a string at char {start} is not closed"),
                    }
                }
            } else if s[i] == '\'' {
                // A character literal, `'x'` or an escape `'\n'`, `'\''`, `'\u{..}'`; any other
                // quote opens a lifetime or a label, which is code.
                if at(1) == Some('\\') {
                    i += 3;
                    while s.get(i).is_some_and(|c| *c != '\'') {
                        i += 1;
                    }
                    i += 1;
                } else if at(2) == Some('\'') {
                    i += 3;
                } else {
                    i += 1;
                    continue;
                }
            } else if ident(s[i]) {
                let mut j = i;
                while s.get(j).is_some_and(|c| ident(*c)) {
                    j += 1;
                }
                let word: String = s[i..j].iter().collect();
                let hashes = s[j..].iter().take_while(|c| **c == '#').count();
                if !(matches!(word.as_str(), "r" | "br" | "cr") && s.get(j + hashes) == Some(&'"'))
                {
                    i = j;
                    continue;
                }
                // A raw string: it ends at the first `"` followed by as many `#` as opened it.
                i = j + hashes + 1;
                loop {
                    assert!(
                        i < s.len(),
                        "{name}: a raw string at char {start} is not closed"
                    );
                    if s[i] == '"' && s[i + 1..].iter().take_while(|c| **c == '#').count() >= hashes
                    {
                        break i += 1 + hashes;
                    }
                    i += 1;
                }
            } else {
                i += 1;
                continue;
            }
            for c in &mut out[start..i.min(s.len())] {
                if *c != '\n' {
                    *c = ' ';
                }
            }
        }
        out.into_iter().collect()
    }

    /// The words of a line of code, each with its byte offset: the runs of identifier
    /// characters, so `Command::spawn(` and `.spawn()` both hold the word `spawn`.
    fn words(line: &str) -> Vec<(usize, &str)> {
        let mut found = Vec::new();
        let mut start = None;
        for (at, c) in line.char_indices().chain([(line.len(), ' ')]) {
            match (start, c.is_alphanumeric() || c == '_') {
                (None, true) => start = Some(at),
                (Some(from), false) => {
                    found.push((from, &line[from..at]));
                    start = None;
                }
                _ => {}
            }
        }
        found
    }

    /// The lexer `one_child_runs_at_a_time_and_its_spawner_waits_for_it` reads the crate
    /// through: every literal and comment form blanked, the code around them kept word for
    /// word, and every line kept in place.
    #[test]
    fn the_one_child_scan_reads_code_and_only_code() {
        let source = r##"use std::thread::{sleep, spawn}; // spawn
let a = "spawn \" // spawn"; let b = spawn(|| ());
let c = r#"spawn "spawn"#; /* spawn /* spawn */ spawn */ Command::spawn(&mut d);
let e = '\''; let f = '"'; let g: &'static str = "\
spawn"; fn h<'life>(x: &'life u8) { b'x'; br"spawn"; r#async; }
"##;
        let code = code_only("fixture", source);
        let found: Vec<(usize, &str)> = code
            .lines()
            .enumerate()
            .flat_map(|(n, l)| words(l).into_iter().map(move |(_, w)| (n + 1, w)))
            .filter(|(_, w)| ["spawn", "async", "static", "life", "Command"].contains(w))
            .collect();
        eprintln!(
            "one child, lexer: {} lines in, {} out; {found:?}",
            source.lines().count(),
            code.lines().count()
        );
        assert_eq!(code.lines().count(), source.lines().count());
        assert_eq!(
            found,
            [
                (1, "spawn"),
                (2, "spawn"),
                (3, "Command"),
                (3, "spawn"),
                (4, "static"),
                (5, "life"),
                (5, "life"),
                (5, "async"),
            ]
        );
    }

    /// Every brace pair in `code` (`code_only`'s output, so a brace left in it is code),
    /// keyed on the opening brace's byte offset and holding the closing one's.
    fn brace_pairs(name: &str, code: &str) -> BTreeMap<usize, usize> {
        let line_of = |p: usize| code[..p].matches('\n').count() + 1;
        let mut braces: BTreeMap<usize, usize> = BTreeMap::new();
        let mut open = Vec::new();
        for (p, c) in code.char_indices() {
            match c {
                '{' => open.push(p),
                '}' => {
                    let o = open.pop().unwrap_or_else(|| {
                        panic!("{name}: the `}}` at line {} closes nothing", line_of(p))
                    });
                    braces.insert(o, p);
                }
                _ => {}
            }
        }
        assert!(open.is_empty(), "{name}: {} braces never close", open.len());
        braces
    }

    /// The innermost function whose body holds byte `at` of `code`: the offsets of its `fn`
    /// keyword, its opening brace and its closing brace. Any qualifier may precede the `fn`
    /// (`pub(in ..)`, `const`, `async`, `unsafe`, `extern`). A `fn` whose first `{` or `;`
    /// is a `;` has no body here: a trait item, or a function-pointer type.
    fn enclosing_fn(
        code: &str,
        braces: &BTreeMap<usize, usize>,
        at: usize,
    ) -> Option<(usize, usize, usize)> {
        words(code)
            .into_iter()
            .filter(|&(p, w)| w == "fn" && p < at)
            .filter_map(|(p, _)| {
                let o = p + code[p..].find(['{', ';'])?;
                let c = braces.get(&o).copied()?;
                (o < at && at < c).then_some((p, o, c))
            })
            .max_by_key(|&(_, o, _)| o)
    }

    /// The blocks inside the body opened at byte `body` that hold byte `at`, outermost
    /// first: each opening brace's offset, and `for`, `while` or `loop` where that brace is
    /// the body of a loop whose keyword stands in the enclosing block ([`loop_owning`]).
    fn blocks_around<'a>(
        code: &'a str,
        braces: &BTreeMap<usize, usize>,
        body: usize,
        at: usize,
    ) -> Vec<(usize, Option<&'a str>)> {
        let opens: Vec<usize> = braces
            .range(body + 1..at)
            .filter(|&(_, &c)| c > at)
            .map(|(&o, _)| o)
            .collect();
        let mut parent = body;
        let mut out = Vec::new();
        for o in opens {
            out.push((o, loop_owning(code, braces, parent, o)));
            parent = o;
        }
        out
    }

    /// The loop keyword whose body is the brace at byte `o`, where `o` sits directly in the
    /// block opened at byte `parent`. Each `for`, `while` or `loop` word standing in that
    /// block, not in a block nested in it, is followed forward with `()` and `[]` balanced:
    /// a `;` at its level ends the statement, a brace group at its level is skipped and the
    /// head goes on only when another `{` follows at once (`while { .. } { .. }`), and
    /// reaching `o` makes `o` its body. A closure or block in the loop's head
    /// (`for _ in it.filter(|_| { .. }) {`) is inside parentheses or skipped as a group, so it
    /// does not hide the keyword, as it would from a scan of the text before `o` alone.
    fn loop_owning<'a>(
        code: &'a str,
        braces: &BTreeMap<usize, usize>,
        parent: usize,
        o: usize,
    ) -> Option<&'a str> {
        let nested = |p: usize| {
            braces
                .range(parent + 1..p)
                .any(|(&inner, &close)| inner < p && p < close)
        };
        words(&code[parent + 1..o])
            .into_iter()
            .map(|(q, w)| (parent + 1 + q, w))
            .filter(|&(p, w)| ["for", "while", "loop"].contains(&w) && !nested(p))
            .find_map(|(p, w)| {
                let bytes = code.as_bytes();
                let mut depth = 0usize;
                let mut i = p + w.len();
                while i < o {
                    match bytes[i] {
                        b'(' | b'[' => depth += 1,
                        b')' | b']' => depth = depth.saturating_sub(1),
                        b';' if depth == 0 => return None,
                        b'{' if depth == 0 => {
                            let close = *braces.get(&i)?;
                            let next = code[close + 1..].trim_start();
                            if !next.starts_with('{') {
                                return None;
                            }
                            i = close;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                (i == o).then_some(w)
            })
    }

    /// The process spawn whose word `spawn` starts at byte `start` of `code` (`code_only`'s
    /// output, so a wait or a loop in a comment is neither) is one child, bound once and
    /// waited for by the function that spawned it. Four rejections, each named in its panic:
    ///
    /// - The spawn sits in a `for`, `while` or `loop` body inside its function. A loop that
    ///   spawns is how a pool starts, and whether each iteration waits before the next is not
    ///   something a scan can follow, so the scan refuses the shape.
    /// - The statement holding the spawn is not `let mut <name> = ...`, or is `let` without
    ///   `mut`.
    /// - Anywhere between that binding and the brace that closes the function, `<name>` is
    ///   used other than through `.` (a method or a field) or behind `&`/`&mut`: passed to a
    ///   call by value, pushed, returned, assigned, or bound again by `let`. Any of those can
    ///   put the child where the wait does not reach, and a re-let makes a wait that follows
    ///   name another child. The scan does not stop at the first wait: a `try_wait`, which
    ///   does not block, followed by `Ok(child)` would return a running child.
    /// - No blocking `<name>.wait()`, with `<name>` a whole word not reached through `.` or
    ///   `::`, comes before that brace. A `try_wait` alone polls and does not hold the child
    ///   to its end; both sites today poll with `try_wait` and end on `wait` after `kill`.
    ///
    /// The function is the innermost `fn` (any qualifiers: `pub(in ..)`, `const`, `async`,
    /// `unsafe`, `extern`) whose body, found by matching braces, holds the spawn.
    fn assert_spawner_waits(name: &str, code: &str, start: usize) {
        let line_of = |p: usize| code[..p].matches('\n').count() + 1;
        let line_text = |p: usize| {
            let from = code[..p].rfind('\n').map_or(0, |n| n + 1);
            let to = code[p..].find('\n').map_or(code.len(), |n| p + n);
            code[from..to].trim()
        };
        let site = format!("{name}:{}", line_of(start));

        let braces = brace_pairs(name, code);

        let (signature, body, close) = enclosing_fn(code, &braces, start)
            .unwrap_or_else(|| panic!("{site}: no function body holds this spawn"));
        let signature = line_text(signature);

        // No loop between the function's body and the spawn.
        let blocks = blocks_around(code, &braces, body, start);
        if let Some((o, w)) = blocks.iter().find_map(|&(o, w)| w.map(|w| (o, w))) {
            panic!(
                "{site}: the spawn sits in the `{w}` body opened at line {} of `{signature}`; \
                 a spawn in a loop is how a pool of children starts",
                line_of(o)
            );
        }
        let enclosing = blocks.len();

        // The statement holding the spawn binds it: `let mut <child>`.
        let statement = code[..start].rfind([';', '{', '}']).map_or(0, |b| b + 1);
        let head = words(&code[statement..start]);
        let (bound, child) = match head.as_slice() {
            [(_, "let"), (_, "mut"), (p, child), ..] => (statement + p, *child),
            [(_, "let"), ..] => {
                panic!(
                    "{site}: the spawned child is bound without `mut`, so it cannot be waited for"
                )
            }
            _ => panic!(
                "{site}: the spawned child is not bound by `let mut` in the statement that spawns it"
            ),
        };

        // Every later mention of `child` up to the first wait: a method or a field, or a
        // borrow, and nothing else.
        let from = bound + child.len();
        let mut waited = None;
        let mut mentions = 0usize;
        for (q, w) in words(&code[from..close]) {
            if w != child {
                continue;
            }
            let at = from + q;
            let before = code[..at].trim_end();
            let after = code[at + w.len()..].trim_start();
            if before.ends_with('.') || before.ends_with("::") {
                continue; // another value's field, or a path: not this binding
            }
            mentions += 1;
            if after.starts_with(".wait()") {
                waited.get_or_insert(at);
                continue;
            }
            let through_dot = after.starts_with('.') && !after.starts_with("..");
            let borrowed = before.ends_with('&')
                || before
                    .strip_suffix("mut")
                    .is_some_and(|b| b.trim_end().ends_with('&'));
            if through_dot || borrowed {
                continue;
            }
            let previous = before
                .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("");
            if matches!(previous, "let" | "mut") {
                panic!(
                    "{site}: `{child}` is bound again at line {} in the function that spawned \
                     it, so a wait after it names another child: `{}`",
                    line_of(at),
                    line_text(at)
                );
            }
            panic!(
                "{site}: `{child}` is used by value at line {} in the function that spawned it \
                 (moved into a call, a collection, a return or another place), so the wait no \
                 longer holds the one child that ran: `{}`",
                line_of(at),
                line_text(at)
            );
        }
        let waited = waited.unwrap_or_else(|| {
            panic!(
                "{site}: `{child}` is spawned and no blocking `{child}.wait()` comes before \
                 line {} closes `{signature}`, so a second child can start while it runs",
                line_of(close)
            )
        });
        eprintln!(
            "one child: {site} binds `{child}` in `{signature}` (body lines {}..={}), {enclosing} \
             blocks around the spawn and none a loop, {mentions} mentions, waited at line {}",
            line_of(body),
            line_of(close),
            line_of(waited)
        );
    }

    /// The words that start concurrent work, for the ratchet below.
    const WORDS: &[&str] = &[
        "spawn",
        "spawn_scoped",
        "spawn_unchecked",
        "scope",
        "Builder",
        "async",
        "await",
        "rayon",
        "tokio",
    ];
    // (file below `src/`, site, occurrences, the bound that keeps the site to one child).
    // A site is a word from `WORDS`, or `thread::spawn` for a `spawn` that path names.
    /// The sites allowed, each with the bound that keeps it to one child (the ratchet below).
    const ALLOWED: &[(&str, &str, usize, &str)] = &[
        (
            "compile.rs",
            "thread::spawn",
            2,
            "the stdout and stderr readers of the one child `invoke_with_timeout` \
             spawned; each reads a pipe and spawns nothing, and is joined or abandoned \
             before that function returns",
        ),
        (
            "compile.rs",
            "spawn",
            1,
            "`invoke_with_timeout`'s toolchain child, waited for under `INVOKE_TIMEOUT`",
        ),
        (
            "run.rs",
            "spawn",
            1,
            "`execute`'s probe, waited for under the probe timeout its caller supplies",
        ),
        (
            "elf.rs",
            "scope",
            1,
            "the corruption test's `thread::scope` (test module only): its workers are \
             joined before the scope returns, and each parses an in-memory copy and \
             starts no process",
        ),
        (
            "elf.rs",
            "thread::spawn",
            1,
            "the workers that `scope` starts in the corruption test, written out as \
             `thread::Scope::spawn`, one per thread the host offers; no child process",
        ),
    ];

    /// One child at a time: nothing in the crate runs work concurrently, and each process
    /// spawn is waited for in the function that spawned it.
    ///
    /// One exception, in a test module and outside every measurement: `src/elf.rs`'s
    /// corruption test parses in-memory copies on scoped threads, written out as
    /// `thread::Scope::spawn` so the scan below counts them as threads, and allowlisted with
    /// that bound. They start no process.
    ///
    /// `measure::Driver` rests on this. The `runtime` channel and both records'
    /// `duration_ms` are read off a harness running one child, and the auxiliary libraries
    /// are linked at one name per work directory, so a second child beside the first
    /// perturbs a measurement or overwrites another variant's dependency chain, with no
    /// error either way. The property is held by construction (the sequential probe loop in
    /// `main.rs`, and `invoke_with_timeout` and `run::execute` each waiting for their
    /// child), and held to it by this test rather than by a sentence.
    ///
    /// Two halves. Every word in `src/` that starts concurrent work is counted per file and
    /// compared, exactly, with an allowlist whose entries name their site and the bound that
    /// keeps it to one child: an added site fails, and so does an allowlisted one that is
    /// gone. Then each process spawn passes `assert_spawner_waits`, whose four rejections are
    /// listed on it: no spawn in a `for`, `while` or `loop` body, a `let mut` binding, no
    /// by-value use or re-binding of that name in its function, and a blocking `wait` naming
    /// it as a whole word before the function's closing brace. `.output()` and `.status()` wait for
    /// their child themselves; `every_spawn_site_sits_where_something_bounds_it` holds where
    /// any `Command` may be built.
    ///
    /// The scan reads words of code, not substrings of lines. `code_only` blanks comments and
    /// literals (`the_one_child_scan_reads_code_and_only_code` holds it), and a word is
    /// counted wherever it stands, so `Command::spawn(&mut c)`, a bare `spawn` imported by
    /// `use std::thread::{spawn}`, and `.spawn()` are one word three ways. Every way into
    /// `std::thread`'s concurrency names `spawn`, `scope` or `Builder` at its use or its call,
    /// so `thread` itself, which `sleep` also needs, is not counted. A `spawn` preceded by
    /// `thread::` is a thread; any other is a process spawn and gets the wait check. The
    /// wait check reads the file as one text and matches braces, so line breaks, trailing
    /// comments and function qualifiers do not move it. The frame is `src/`: `build.rs`
    /// runs at build time, before any measurement.
    ///
    /// What the wait check does not see, and why each is tolerable or is not yet held:
    ///
    /// - Order in the text, not control flow. A wait inside one branch, or an early return
    ///   (`?`, `bail!`) between the spawn and the wait, passes; a dropped `Child` is neither
    ///   waited for nor killed. `invoke_with_timeout` has such a return today: it kills,
    ///   without reaping, a child whose pipes were not set up, which the spawn configuration
    ///   above it rules out.
    /// - A move through a borrow: `std::mem::replace(&mut child, ..)` or `swap` reads as a
    ///   borrow.
    /// - Iteration through a closure (`(0..n).map(|_| ...spawn())`) is not a loop body. It
    ///   fails anyway, as the binding check or as a missing wait, because the statement then
    ///   binds a collection, and `.wait()` on a collection does not compile.
    /// - A loop in a caller is outside the frame. The spawner waits before it returns, so a
    ///   sequential caller still runs one child, and a threaded caller is counted above.
    /// - A function-pointer type whose next `{` comes before any `;` (`|f: fn()| { .. }`)
    ///   reads as a `fn` body, which narrows the function to that brace: a wait after it
    ///   fails, and a loop outside it is missed. An `impl .. for` block inside a function
    ///   reads as a loop and fails. Neither stands in `src/` today.
    #[test]
    fn one_child_runs_at_a_time_and_its_spawner_waits_for_it() {
        let sources = rust_sources();

        let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
        let mut spawns: Vec<(&str, String, usize)> = Vec::new();
        let mut scanned_lines = 0usize;
        let mut scanned_words = 0usize;
        for (name, text) in &sources {
            let code = code_only(name, text);
            scanned_lines += code.lines().count();
            for (offset, word) in words(&code) {
                scanned_words += 1;
                if !WORDS.contains(&word) {
                    continue;
                }
                // A thread, not a process: `thread::spawn`, or a scoped thread written out as
                // `thread::Scope::spawn(scope, ..)` (a scope's workers are joined before the
                // scope returns). A method call `s.spawn(..)` reads as a process spawn here.
                let threaded = word == "spawn"
                    && code[..offset]
                        .trim_end()
                        .strip_suffix("::")
                        .is_some_and(|p| {
                            let p = p.trim_end();
                            let p = p.strip_suffix("thread::Scope").map_or(p, |q| {
                                if q.is_empty()
                                    || q.ends_with(|c: char| !(c.is_alphanumeric() || c == '_'))
                                {
                                    "thread"
                                } else {
                                    p
                                }
                            });
                            p.rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
                                .next()
                                == Some("thread")
                        });
                let site = if threaded { "thread::spawn" } else { word };
                *found.entry((name.clone(), site.to_owned())).or_default() += 1;
                if site == "spawn" {
                    spawns.push((name, code.clone(), offset));
                }
            }
        }
        let allowed: BTreeMap<(String, String), usize> = ALLOWED
            .iter()
            .map(|(file, site, n, _)| (((*file).to_owned(), (*site).to_owned()), *n))
            .collect();
        // Emit the frame, not just the verdict: a scan over no files, or over files holding
        // none of the allowlisted sites, would report agreement as loudly as a clean tree.
        eprintln!(
            "one child: {} source files, {scanned_lines} lines, {scanned_words} words of code, \
             {} words sought; sites {found:?}",
            sources.len(),
            WORDS.len()
        );
        assert!(
            sources.len() >= 15,
            "the scan covered only {} source files, which is not the crate",
            sources.len()
        );
        assert_eq!(
            found, allowed,
            "the concurrency sites in src/ are not the allowlisted ones; a site added needs an \
             entry naming the bound that keeps it to one child, and an entry whose site is \
             gone needs removing: {ALLOWED:#?}"
        );

        // Each process spawn, waited for in its own function.
        for (name, code, at) in &spawns {
            assert_spawner_waits(name, code, *at);
        }
        let expected: usize = ALLOWED
            .iter()
            .filter(|(_, site, _, _)| *site == "spawn")
            .map(|(_, _, n, _)| n)
            .sum();
        assert_eq!(
            spawns.len(),
            expected,
            "{} spawn sites checked for a wait, where the allowlist names {expected}",
            spawns.len()
        );
    }

    /// `failure` is `None` for a job that exited 0 whatever it wrote to stderr, and for one
    /// that did not, `exited N` (or `was killed by a signal` for a recorded `-1`) with the
    /// first non-empty stderr line after a colon where there is one, published against the
    /// work directory.
    #[test]
    fn a_failure_names_the_status_and_the_first_stderr_line() {
        let workdir = Path::new("/scratch/chard-work");
        let record = |exit_status: i32, stderr: &str| BuildRecord {
            argv: Vec::new(),
            dropped_flags: Vec::new(),
            exit_status,
            stdout: "#define __GNUC__ 16\n".to_owned(),
            stderr: stderr.to_owned(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };
        assert_eq!(
            record(0, "cc: warning: late\n").failure(Some(workdir)),
            None
        );
        assert_eq!(
            record(
                1,
                "\n  /scratch/chard-work/macros-intrinsic.c: fatal error: late.h\nmore\n"
            )
            .failure(Some(workdir)),
            Some("exited 1: macros-intrinsic.c: fatal error: late.h".to_owned())
        );
        assert_eq!(
            record(-1, "").failure(None),
            Some("was killed by a signal".to_owned())
        );
        assert_eq!(
            record(-1, "cc: internal compiler error: Killed\n").failure(None),
            Some("was killed by a signal: cc: internal compiler error: Killed".to_owned())
        );
        assert_eq!(record(255, "").failure(None), Some("exited 255".to_owned()));
    }

    /// `invoke` records whether the job's stdout ended partway through a line from the bytes
    /// it read, which the stored, trimmed `stdout` cannot show: `printf 'a\nb'` and
    /// `printf 'a\nb\n'` are stored alike.
    #[test]
    fn invoke_records_an_unterminated_stdout_before_the_trim() {
        let run = |script: &str| {
            invoke(Path::new("/bin/sh"), &["-c".to_owned(), script.to_owned()]).expect("sh runs")
        };
        let cut = run("printf '#define A 1\\n#define B 2'");
        let whole = run("printf '#define A 1\\n#define B 2\\n'");
        assert_eq!(cut.stdout, whole.stdout);
        assert!(cut.stdout_unterminated);
        assert!(!whole.stdout_unterminated);
        assert!(!run("true").stdout_unterminated, "no output ends no line");
        let spaces = run("printf '#define A 1\\n#define B 2\\n  '");
        assert!(
            !spaces.stdout_unterminated,
            "whitespace after the last newline is no line a cut ended"
        );
        assert_eq!(spaces.whole_stdout(), "#define A 1\n#define B 2");
        assert!(run("printf '#define A 1\\n#define B 2  '").stdout_unterminated);
        // The status does not enter into it: a job that exits 1 after a cut is cut.
        let failed = run("printf '#define A'; exit 1");
        assert!(failed.stdout_unterminated);
        assert_eq!(failed.exit_status, 1);
    }

    /// A dump loses the last line its output ended partway through, whatever its status, and
    /// no other: `#define __GLIBC_MINOR__ 4` cut from `43` is not glibc 2.4, and a whole last
    /// line is read where a signal or a non-zero status followed it.
    #[test]
    fn a_dump_loses_only_a_last_line_its_output_ended_partway_through() {
        let record = |exit_status: i32, raw: &str| BuildRecord {
            argv: Vec::new(),
            dropped_flags: Vec::new(),
            exit_status,
            // Shaped as `invoke` records it.
            stdout: raw.trim_end().to_owned(),
            stderr: String::new(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: ends_mid_line(raw),
        };
        let read =
            |exit_status: i32, raw: &str| parse_macros(record(exit_status, raw).whole_stdout());
        let both = BTreeMap::from([
            ("__GLIBC_MINOR__".to_owned(), "43".to_owned()),
            ("__GLIBC__".to_owned(), "2".to_owned()),
        ]);
        let whole = "#define __GLIBC_MINOR__ 43\n#define __GLIBC__ 2\n";
        for status in [0, 1, -1] {
            assert_eq!(read(status, whole), both, "exit {status}");
        }
        let cut = "#define __GLIBC__ 2\n#define __GLIBC_MINOR__ 4";
        let glibc = BTreeMap::from([("__GLIBC__".to_owned(), "2".to_owned())]);
        for status in [0, 1, -1] {
            assert_eq!(read(status, cut), glibc, "exit {status}");
        }
        assert_eq!(read(0, "#define __GLIBC_MI"), BTreeMap::new());
        // Only the last line goes: the lines before it, all of them, are read.
        assert_eq!(
            read(
                0,
                "#define __unix__ 1\n#define __GLIBC__ 2\n#define __GLIBC_MINOR__ 4"
            ),
            BTreeMap::from([
                ("__unix__".to_owned(), "1".to_owned()),
                ("__GLIBC__".to_owned(), "2".to_owned()),
            ])
        );
    }

    /// Every byte prefix of a listing, shaped as `invoke` records it, parses to defines the
    /// whole listing has with the values it gives them, and one that stops partway through a
    /// define reads as failed under exit 0: no cut point yields a define the listing lacks.
    #[test]
    fn no_cut_of_a_listing_reads_a_define_it_lacks() {
        let listing = "#define __GLIBC_MINOR__ 43\n#define __GLIBC__ 2\n#define __SSP_STRONG__ 3\n\
                       #define __x86_64__ 1\n#define f(x) ((x) + 1)\n";
        let whole = parse_macros(listing);
        for cut in 0..=listing.len() {
            let raw = &listing[..cut];
            let record = BuildRecord {
                argv: Vec::new(),
                dropped_flags: Vec::new(),
                exit_status: 0,
                stdout: raw.trim_end().to_owned(),
                stderr: String::new(),
                duration_ms: 0,
                artifact_sha256: None,
                stdout_sha256: None,
                stdout_unterminated: ends_mid_line(raw),
            };
            let read = parse_macros(record.whole_stdout());
            for (name, value) in &read {
                assert_eq!(whole.get(name), Some(value), "cut at {cut}: {raw:?}");
            }
            // Exactly the lines a newline ended: no more, and none of them lost.
            let ended = raw.rsplit_once('\n').map_or("", |(lines, _)| lines);
            assert_eq!(read, parse_macros(ended), "cut at {cut}: {raw:?}");
            assert_eq!(
                record.dump_failure(None).is_some(),
                !raw.is_empty() && !raw.ends_with('\n'),
                "cut at {cut}: {raw:?}"
            );
        }
        // The same listing with a whitespace-only tail after its last newline loses nothing.
        for tail in [" ", "\t", "  \t ", "\r"] {
            assert!(!ends_mid_line(&format!("{listing}{tail}")), "{tail:?}");
        }
        assert!(ends_mid_line("#define A"));
        assert!(!ends_mid_line(""));
    }

    /// `dump_failure` is `failure` where the job did not succeed, the cut where it exited 0
    /// with its output ended partway through a line, and `None` for a whole listing that
    /// exited 0, whatever it wrote to stderr.
    #[test]
    fn a_dump_that_exited_0_with_its_output_cut_off_failed() {
        let record = |exit_status: i32, stdout_unterminated: bool| BuildRecord {
            argv: Vec::new(),
            dropped_flags: Vec::new(),
            exit_status,
            stdout: "#define __GNUC__ 1".to_owned(),
            stderr: "cc: warning: late".to_owned(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated,
        };
        assert_eq!(record(0, false).dump_failure(None), None);
        assert_eq!(
            record(0, true).dump_failure(None).as_deref(),
            Some("exited 0 with its output cut off partway through a line")
        );
        assert_eq!(
            record(0, true).failure(None),
            None,
            "the status reading is the status's"
        );
        assert_eq!(
            record(1, true).dump_failure(None),
            record(1, true).failure(None),
            "a dump that failed is named by its status"
        );
        assert_eq!(
            record(-1, false).dump_failure(None).as_deref(),
            Some("was killed by a signal: cc: warning: late")
        );
    }

    /// The published copy of a build is relative to the work directory, and the record
    /// it was copied from is not touched.
    ///
    /// Both spellings the driver is handed: `workdir/name` for the output and the source,
    /// which become bare names, and `-Lworkdir` for the chain search path, which becomes
    /// `-L.`. The diagnostic quoting the source path is rewritten the same way, so a
    /// report measured in two directories carries the same text.
    #[test]
    fn a_published_build_is_relative_to_its_work_directory_and_the_original_is_not() {
        let workdir = Path::new("/scratch/chard-work");
        let record = BuildRecord {
            argv: vec![
                "/usr/bin/cc".to_owned(),
                "-L/scratch/chard-work".to_owned(),
                "-Wl,-rpath-link,/scratch/chard-work".to_owned(),
                "-o".to_owned(),
                "/scratch/chard-work/probe".to_owned(),
                "/scratch/chard-work/probe.c".to_owned(),
            ],
            dropped_flags: vec!["-pie".to_owned()],
            exit_status: 1,
            stdout: String::new(),
            stderr: "/scratch/chard-work/probe.c:3:5: warning: something".to_owned(),
            duration_ms: 7,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };
        let published = record.relative_to(workdir);
        assert_eq!(
            published.argv,
            [
                "/usr/bin/cc",
                "-L.",
                "-Wl,-rpath-link,.",
                "-o",
                "probe",
                "probe.c"
            ]
        );
        assert_eq!(published.stderr, "probe.c:3:5: warning: something");
        assert_eq!(published.dropped_flags, record.dropped_flags);
        assert_eq!(published.exit_status, 1);
        assert_eq!(published.duration_ms, 7);
        // The original is what a detector reads, and it is as captured.
        assert_eq!(record.argv[4], "/scratch/chard-work/probe");
        assert!(record.stderr.starts_with("/scratch/chard-work/"));

        // A root that would match everything is left alone rather than rewriting every
        // path in the report to a dot.
        assert_eq!(relativize("/usr/bin/cc", Path::new("/")), "/usr/bin/cc");
        assert_eq!(relativize("/usr/bin/cc", Path::new("")), "/usr/bin/cc");

        // Whole components. A directory that merely begins with the work directory's
        // spelling is a different directory, and the operator's `-I/tmp/wd2` under a
        // work directory of `/tmp/wd` was published as `-I.2`.
        let wd = Path::new("/tmp/wd");
        for kept in [
            "-I/tmp/wd2",
            "/tmp/wd2/x.c:1:1: error",
            "/tmp/wd.bak/x.c",
            "/tmp/wd_old",
        ] {
            assert_eq!(
                relativize(kept, wd),
                kept,
                "{kept} shares a prefix and no more"
            );
        }
        assert_eq!(
            relativize("/tmp/wd/x.c /tmp/wd2/x.c", wd),
            "x.c /tmp/wd2/x.c"
        );
        assert_eq!(relativize("in '/tmp/wd'", wd), "in '.'");
        assert_eq!(relativize("/tmp/wd:", wd), ".:");
        assert_eq!(relativize("--sysroot=/tmp/wd", wd), "--sysroot=.");
        assert_eq!(relativize("-L/tmp/wd/", wd), "-L.");
        assert_eq!(relativize("-L/tmp/wd/", Path::new("/tmp/wd/")), "-L.");
    }

    #[test]
    fn parses_object_and_function_like_macros() {
        let text = "#define __GNUC__ 16\n\
                    #define __SSP_STRONG__ 3\n\
                    #define __has_builtin(x) 1\n\
                    #define _GLIBCXX_ASSERTIONS\n\
                    not a define line\n";
        let macros = parse_macros(text);
        assert_eq!(macros.get("__GNUC__").map(String::as_str), Some("16"));
        assert_eq!(macros.get("__SSP_STRONG__").map(String::as_str), Some("3"));
        assert_eq!(
            macros.get("__has_builtin(x)").map(String::as_str),
            Some("1")
        );
        // Present with an empty replacement list, not absent.
        assert_eq!(
            macros.get("_GLIBCXX_ASSERTIONS").map(String::as_str),
            Some("")
        );
        assert_eq!(macros.len(), 4);
    }

    #[test]
    fn diagnostics_matching_is_case_insensitive() {
        let record = BuildRecord {
            argv: vec![],
            dropped_flags: Vec::new(),
            exit_status: 1,
            stdout: String::new(),
            stderr: "error: implicit declaration of function 'foo'".to_owned(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };
        assert!(record.diagnostics_contain("IMPLICIT DECLARATION"));
        assert!(!record.succeeded());
    }

    /// A relative driver path run under another working directory is the path from this
    /// process's own: it is made absolute before the change of directory, so the child's
    /// directory, deeper than this one, does not move what it names.
    #[test]
    fn a_relative_driver_names_the_same_file_under_another_working_directory() {
        let root = std::env::temp_dir().join(format!("chard-relcc-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("a scratch directory");
        let script = test_script(&root.join("cc"), "echo ran");
        let here = std::env::current_dir().expect("this process's directory");
        let mut relative = PathBuf::new();
        for _ in here.components().skip(1) {
            relative.push("..");
        }
        relative.push(script.strip_prefix("/").expect("an absolute script path"));
        // Deeper than this process's directory, so the `..`s stop short of the root there.
        let mut deep = root.clone();
        for _ in 0..=here.components().count() {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).expect("a deep working directory");
        let record = invoke_with_timeout(
            &relative,
            &[],
            Some(&deep),
            Duration::from_secs(10),
            Duration::from_secs(1),
        )
        .expect("the relative driver runs");
        assert_eq!(record.stdout.trim(), "ran");
        crate::error::best_effort(std::fs::remove_dir_all(&root));
    }

    /// The drain bound holds where one pipe closes and the other stays held: a child that
    /// exits leaving a grandchild on its stderr alone is an error once the bound passes, not
    /// a record read after the grandchild lets go.
    #[test]
    fn one_pipe_still_held_after_the_child_exits_is_an_error() {
        let started = Instant::now();
        let got = invoke_with_timeout(
            Path::new("/bin/sh"),
            &["-c".to_owned(), "sleep 30 >/dev/null & exit 0".to_owned()],
            None,
            Duration::from_secs(60),
            Duration::from_millis(300),
        );
        let err = got.expect_err("a held stderr must not be read as a silent compiler");
        assert!(
            format!("{err}").contains("output pipes were still held"),
            "{err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the drain bound, not the grandchild or the call's own timeout, ended the wait"
        );
    }
}
