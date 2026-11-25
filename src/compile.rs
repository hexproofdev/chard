// SPDX-License-Identifier: BSD-3-Clause

//! Invoking the toolchain under test.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::digest;

/// The synthetic translation unit whose macro dump identifies the C library. `__GLIBC__` and
/// `__USE_FORTIFY_LEVEL` are defined by libc headers, not by the compiler, so a bare `-dM -E`
/// on empty input cannot see them; `__USE_FORTIFY_LEVEL` is the level glibc settled on, not
/// the one the command line asked for.
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
    /// coexist with this probe's output kind: `-pie` against `-shared`, and the rest of
    /// [`crate::probe::LinkMode::conflicts_with`].
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
    /// count of the defines. It keys the dump's `macro-dump` entry in the report's `facts`
    /// store, so the macros a verdict was read from are named by the lines they were parsed
    /// out of. `None` on every other record, and on the record a detector reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_sha256: Option<String>,
    /// Whether the job's standard output ended partway through a line: text other than
    /// whitespace followed its last newline, or made up the whole output where it printed
    /// none. Set by `invoke` from the text it read, before `stdout` is stored with its
    /// trailing whitespace trimmed, which leaves no other trace of it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stdout_unterminated: bool,
}

/// How a job that recorded `exit_status` ended: `exited N`, or `was killed by a signal` for
/// the `-1` `invoke` records where the child has no exit code (a real `exit(-1)` reads 255
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

/// How long any single toolchain invocation may take.
pub const INVOKE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the output threads once the child itself has been reaped.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// The longest `invoke_with_timeout` waits between looks at its child while either of the
/// child's pipes is open.
const EXIT_WAKE_BOUND: Duration = Duration::from_millis(10);

/// Read a child's pipe to the end, on a thread of its own, then say so on `ended`.
fn drain<R: std::io::Read>(mut pipe: R, ended: &Sender<()>) -> Vec<u8> {
    let mut buf = Vec::new();
    crate::error::best_effort(pipe.read_to_end(&mut buf));
    crate::error::best_effort(ended.send(()));
    buf
}

/// The variables of chard's own environment a toolchain invocation is handed, when chard has
/// them: `PATH` alone.
pub const COMPILER_ENV_PASSED: &[&str] = &["PATH"];

/// The environment every toolchain invocation receives, in the order it is applied:
/// [`COMPILER_ENV_PASSED`] as chard has them, then the run's `--env` pairs (`ADDED`), then
/// [`COMPILER_ENV_PINNED`].
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
static ADDED: RunEnvironment = RunEnvironment::new();

/// A list of pairs set at most once and fixed by its first read. `ADDED` is the one chard
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
                "the compiler environment's --env pairs were set after a toolchain invocation had read them"
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
            refused.push(format!("{arg:?}: {name:?} is not a portable variable name"));
        } else if COMPILER_ENV_PASSED.contains(&name) {
            refused.push(format!(
                "{arg:?}: {name} is passed to the compiler from chard's own environment"
            ));
        } else if let Some((pinned, pinned_value)) = COMPILER_ENV_PINNED
            .iter()
            .find(|(pinned, _)| *pinned == name)
        {
            let why = pin_reason(pinned).unwrap_or("");
            refused.push(format!(
                "{arg:?}: {name} is pinned to {pinned_value:?} for every compiler invocation, \
                 {why}"
            ));
        } else if let Some(pinned) = countermanded_pin(name) {
            let why = pin_reason(pinned).unwrap_or("");
            let value = COMPILER_ENV_PINNED
                .iter()
                .find(|(pin, _)| *pin == pinned)
                .map_or("", |(_, value)| *value);
            refused.push(format!(
                "{arg:?}: {name} would undo {pinned}: ccache reads {name} as {pinned} negated, \
                 and every compiler invocation receives {pinned}={value} {why}"
            ));
        } else if value.contains('\0') {
            refused.push(format!("{arg:?}: the value holds a NUL"));
        } else if let Some(found) = relative_path_in_value(value, Path::exists) {
            let path = found.argument;
            refused.push(match found.reading.note() {
                Some(note) => format!("{arg:?}: {path:?}, {note}"),
                None => format!(
                    "{arg:?}: {path:?} is a relative path, which the toolchain would read against chard's directory in some invocations and the work directory in others"
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
pub fn relative_path_in_value(value: &str, exists: impl Fn(&Path) -> bool) -> Option<RelativePath> {
    let words: Vec<String> = value.split_ascii_whitespace().map(str::to_owned).collect();
    // The entry reading below decides a word that is no option.
    if let Some(found) = relative_path_readings(&words).into_iter().find(|found| {
        !matches!(
            found.reading,
            PathReading::Input | PathReading::Divided { .. }
        )
    }) {
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
pub const COMPILER_ENV_NAMED: &[&str] = &[
    // Build configuration: a `CFLAGS` or `CPATH` in the ambient environment silently
    // changing what is measured is the class of error chard exists to detect.
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "C_INCLUDE_PATH",
    // The C++ sibling of `C_INCLUDE_PATH`.
    "CPLUS_INCLUDE_PATH",
    "LIBRARY_PATH",
    // The linker writes what this names into the artifact as `DT_RPATH`, so
    // `rpath-absent` sees an RPATH in every arm, the negative control included, and
    // publishes `probe-invalid` because the operator's shell had a variable set.
    "LD_RUN_PATH",
    // gcc's diagnostic colour palette.
    "GCC_COLORS",
    // Both drivers put their temporary objects where this points, and a linker
    // warning names the object it is about, so the name reaches the captured stderr
    // and from there a control arm's `detail`.
    "TMPDIR",
    "TMP",
    "TEMP",
    "TEMPDIR",
    // The driver's own search path for the programs it runs.
    "COMPILER_PATH",
    "GCC_EXEC_PREFIX",
    // clang skips its default configuration file when this is set.
    "CLANG_NO_DEFAULT_CONFIG",
    // clang rewrites its own command line from this before doing anything else.
    "CCC_OVERRIDE_OPTIONS",
    // The diagnostic language, pinned by `LC_ALL` in [`COMPILER_ENV_PINNED`]; these
    // three are removed so nothing outranks or supplements the pin.
    "LANG",
    "LANGUAGE",
    "LC_MESSAGES",
    // `$HOME`, because a file in it must not decide what chard measures: an ambient file
    // changing what is measured is the class of error chard exists to detect.
    "HOME",
    // The Darwin deployment target.
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
    "TVOS_DEPLOYMENT_TARGET",
    "WATCHOS_DEPLOYMENT_TARGET",
    "XROS_DEPLOYMENT_TARGET",
    "DRIVERKIT_DEPLOYMENT_TARGET",
    "RC_DEBUG_PREFIX_MAP",
    "RC_DEBUG_OPTIONS",
    // The SDK, which `-isysroot` also names.
    "SDKROOT",
    // gcc's `-fcompare-debug` through the environment.
    "GCC_COMPARE_DEBUG",
    // `fixits-v1` and `fixits-v2` add a `fix-it:` line to gcc's stderr (12 lines against 11
    // for an implicit `printf`), and the compiler-diag channel matches stderr text.
    "GCC_EXTRA_DIAGNOSTIC_OUTPUT",
    // gcc's hyperlinks in diagnostics.
    "GCC_URLS",
    // gcc writes a trace of its diagnostics machinery to the path named.
    "GCC_DIAGNOSTICS_LOG",
    // gcc 16 sends diagnostics to a SARIF socket.
    "EXPERIMENTAL_SARIF_SOCKET",
    // GNU ld reads it, and `gcc` and `clang` both pass `-m` themselves, so a link through
    // either driver is unchanged (measured).
    "LDEMULATION",
    "GNUTARGET",
    // `COLLECT_NO_DEMANGLE=1` turns the linker's symbol demangling off: `undefined
    // reference to `f()'` becomes `undefined reference to `_Z1fv'`.
    "COLLECT_NO_DEMANGLE",
    // The embedded build time.
    "SOURCE_DATE_EPOCH",
    // gcc's driver reads these three as search roots.
    "LPATH",
    "GCC_ROOT",
    "BINUTILS_ROOT",
    // gcc's older dependency-output variables behave as `-MM` and `-MD` for every compile.
    "DEPENDENCIES_OUTPUT",
    "SUNPRO_DEPENDENCIES",
    // clang's own reporting.
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
    // clang's crash handling.
    "FORCE_CLANG_DIAGNOSTICS_CRASH",
    "CLANG_CRASH_DIAGNOSTICS_DIR",
    // Where `-fmodules` keeps its cache, printed in the `-cc1` line (measured).
    "CLANG_MODULE_CACHE_PATH",
];

/// The variables every compiler invocation receives with a fixed value.
pub const COMPILER_ENV_PINNED: &[(&str, &str)] = &[
    ("LC_ALL", "C"),
    ("TERM", "dumb"),
    ("CCACHE_DISABLE", "1"),
    ("CCACHE_CONFIGPATH", "/dev/null"),
];

/// Whether the pin `name` is one of ccache's boolean settings, which ccache negates as
/// `CCACHE_NO<setting>` (its manual, "Boolean values"); `None` for a name that is not a pin.
/// Every pin is named here, so a pin added without a class fails
/// `every_pin_is_refused_with_its_own_reason`. Booleanness is the setting's, never inferred
/// from the pin's value: ccache takes a boolean variable set to any value, the empty string
/// included, as true.
#[must_use]
pub fn ccache_boolean_pin(name: &str) -> Option<bool> {
    match name {
        "CCACHE_DISABLE" => Some(true),
        "LC_ALL" | "TERM" | "CCACHE_CONFIGPATH" => Some(false),
        _ => None,
    }
}

/// The pin a variable named `name` would undo, read the way the pin's reader reads it: ccache
/// takes `CCACHE_NO<setting>` as a boolean `CCACHE_<setting>` negated, so `CCACHE_NODISABLE`
/// undoes `CCACHE_DISABLE=1`. Measured with ccache 4.12.3 under `env -i`: with both set, the
/// later in the environment decides. The child's environment chard builds is sorted by name
/// (measured through a driver printing its `environ`), which puts `CCACHE_NODISABLE` after
/// `CCACHE_DISABLE`, so the negation would win.
#[must_use]
pub fn countermanded_pin(name: &str) -> Option<&'static str> {
    let setting = name.strip_prefix("CCACHE_NO")?;
    COMPILER_ENV_PINNED
        .iter()
        .map(|(pinned, _)| *pinned)
        .filter(|pinned| ccache_boolean_pin(pinned) == Some(true))
        .find(|pinned| pinned.strip_prefix("CCACHE_") == Some(setting))
}

/// The reason a pin is pinned, as the `--env` refusal of its name gives it; `None` for a name
/// that is not a pin. A test holds every pin to have one.
fn pin_reason(name: &str) -> Option<&'static str> {
    match name {
        "LC_ALL" | "TERM" => {
            Some("because the compiler-diag channel reads its diagnostics under that value")
        }
        "CCACHE_DISABLE" => Some(
            "so that a ccache masquerade directory on PATH serves no object this run did not build",
        ),
        "CCACHE_CONFIGPATH" => Some("so that no ccache configuration file decides the compile"),
        _ => None,
    }
}

/// The file name of the run's generated header ([`RunWitness`]), written into the work
/// directory and named on each build's command line as `-include` names it. A bare name:
/// the driver runs in the work directory ([`build`]), where `-include` looks first, and a
/// path would reach whatever the compiler records of the names it was given, as the source's
/// would.
pub const RUN_WITNESS_HEADER_NAME: &str = "chard_run_witness.h";

/// Where [`RunWitness::random_in`] reads the nonce: the kernel's random device, present on
/// every platform chard builds probes on.
const RANDOM_DEVICE: &str = "/dev/urandom";

/// Where a run's nonce came from, as `run.artifact_witness.source` publishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessSource {
    /// 128 bits read from the operating system for this run alone.
    OsRandom,
    /// The first 128 bits of a digest over what the run was asked ([`RunWitness::derived_in`]),
    /// so that a second run of the same measurement builds the same bytes.
    Derived,
}

impl WitnessSource {
    /// Every source, which `tests/schema_conformance.rs` holds the schema's enumeration to.
    pub const ALL: [Self; 2] = [Self::OsRandom, Self::Derived];

    /// The source as `run.artifact_witness.source` spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OsRandom => "os-random",
            Self::Derived => "derived",
        }
    }
}

/// The run's witness: one nonce, written into every artifact the run builds and read back
/// from each before anything else is read from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunWitness {
    /// The nonce as lowercase hex, two digits a byte: the spelling
    /// `ElfFacts::run_witness` reads one back in.
    nonce: String,
    source: WitnessSource,
}

/// Why an artifact the ELF reader read is not read as this run's build by the compiler the
/// report names, as the gating's reason and a withheld arm's `detail` say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessAbsence {
    /// The reader read no run witness from the artifact: it found no note of the witness's
    /// owner, type and length, or found one only in a section of the witness's name that it
    /// could not follow to its end.
    Missing,
    /// No run witness, as for [`Self::Missing`], in an artifact holding compiler IR
    /// (`report::LTO_IR_SECTION_PREFIX`): an object compiled under `-flto` and not linked,
    /// which cannot carry the note, since the compiler writes it with the code at the link.
    /// Said apart from [`Self::Missing`] so the reason does not blame a cache where the
    /// profile explains it.
    MissingFromIr,
    /// The artifact carries these run witnesses, and they are not this run's alone.
    Foreign(Vec<String>),
    /// The ELF reader refused the artifact, for this reason, so no witness could be read
    /// from it: a file that is not an object at all (a script a wrapper left in the
    /// executable's place) is as little this run's build as an object without the note.
    Unread(String),
    /// The artifact is LLVM bitcode (its first four bytes are the bitcode magic), which the
    /// ELF reader does not read: clang's object under `-flto`, compiled and not linked. As
    /// with [`Self::MissingFromIr`], the profile explains it and no cache need have.
    Bitcode,
    /// A library the probe's link takes, which this run builds first, is not this run's
    /// for the `absence` given, so the probe was not linked against it.
    Library {
        /// The library's file name.
        name: String,
        absence: Box<WitnessAbsence>,
    },
    /// The artifact is a relocatable object whose `.comment` holds these compiler lines,
    /// which name another family than the one the report names, or that family at another
    /// release (`toolchain::object_compiler`). `named` is the compiler the report names, as
    /// `toolchain.kind` and `toolchain.version` spell it. `witnessed` says the run had a
    /// witness, which the object carries; a run with no witness (a macOS run reading an ELF
    /// cross-compiler's objects) holds its objects to their line all the same.
    OtherCompiler {
        lines: Vec<String>,
        named: String,
        witnessed: bool,
    },
}

impl std::fmt::Display for WitnessAbsence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let section = crate::elf::RUN_WITNESS_SECTION;
        match self {
            Self::Missing => write!(
                f,
                "carries no run witness: the reader read no `{}` note of type {} and {} bytes \
                 from `{section}` or the note segments",
                crate::elf::RUN_WITNESS_OWNER,
                crate::elf::RUN_WITNESS_TYPE,
                crate::elf::RUN_WITNESS_BYTES
            ),
            Self::MissingFromIr => write!(
                f,
                "carries no run witness and holds compiler IR (`{}` sections): under link-time optimization the compiler writes the `{section}` note with the code it generates",
                crate::report::LTO_IR_SECTION_PREFIX
            ),
            Self::Foreign(found) => match found.as_slice() {
                [one] => write!(f, "carries a run witness this run did not write (`{one}`)"),
                many => write!(
                    f,
                    "carries {}{} run witnesses (`{}`) where a build of this run carries its \
                     one",
                    if many.len() == crate::elf::RUN_WITNESSES_KEPT {
                        "at least "
                    } else {
                        ""
                    },
                    many.len(),
                    many.join("`, `")
                ),
            },
            Self::Unread(why) => write!(
                f,
                "is one the ELF reader refused, so no run witness could be read from it ({why})"
            ),
            Self::Bitcode => write!(
                f,
                "is LLVM bitcode, compiler IR the ELF reader does not read: under link-time optimization the compiler writes the `{section}` note with the code it generates"
            ),
            Self::Library { name, absence } => write!(
                f,
                "was not linked: `{name}`, a library the probe's link takes and this run \
                 builds first, {absence}"
            ),
            Self::OtherCompiler {
                lines,
                named,
                witnessed,
            } => write!(
                f,
                "{}its `.comment` names another compiler (`{}`, where `toolchain` is {named})",
                if *witnessed {
                    "carries this run's witness, and "
                } else {
                    "is a relocatable object, and "
                },
                lines.join("`, `")
            ),
        }
    }
}

/// What a run was asked, as a derived nonce digests it ([`RunWitness::derived_in`]): the
/// profile's three flag lists, the run's `--env` pairs, the driver as the report names it,
/// its version line and target triple, and the probe corpus's digest, which moves with any
/// probe source and with the code that reads one.
#[derive(Debug, Clone)]
pub struct WitnessQuestion<'a> {
    pub cflags: &'a [String],
    pub cxxflags: &'a [String],
    pub ldflags: &'a [String],
    /// The run's `--env` pairs, name and value.
    pub env: Vec<(&'a str, &'a str)>,
    /// `toolchain.driver`.
    pub driver: &'a str,
    pub version_raw: Option<&'a str>,
    pub target_triple: Option<&'a str>,
    /// `run.probe_corpus_sha256`.
    pub probe_corpus_sha256: &'a str,
}

impl WitnessQuestion<'_> {
    /// One labelled line per field, a list's words joined by the unit separator, so no two
    /// questions that differ in a field give the same lines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let list = |name: &str, flags: &[String]| format!("{name}={}", flags.join("\u{1f}"));
        let mut lines = vec![
            list("profile.cflags", self.cflags),
            list("profile.cxxflags", self.cxxflags),
            list("profile.ldflags", self.ldflags),
        ];
        lines.extend(
            self.env
                .iter()
                .map(|(name, value)| format!("env.{name}={value}")),
        );
        lines.push(format!("toolchain.driver={}", self.driver));
        for (name, value) in [
            ("version_raw", self.version_raw),
            ("target_triple", self.target_triple),
        ] {
            lines.push(format!("toolchain.{name}={}", value.unwrap_or("<unread>")));
        }
        lines.push(format!("probe_corpus_sha256={}", self.probe_corpus_sha256));
        lines
    }
}

/// The first four bytes of an LLVM bitcode file.
pub const BITCODE_MAGIC: [u8; 4] = [b'B', b'C', 0xc0, 0xde];

impl WitnessAbsence {
    /// What can have left the artifact so, for the reason and the diagnostic to say after
    /// the absence: a cache or a wrapper where nothing in the profile explains a missing or
    /// foreign note, and nothing where the artifact's own form does (an object of IR).
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Missing | Self::Foreign(_) => {
                ": a compiler cache or a wrapper on PATH can hand chard an object another run \
                 built"
            }
            Self::Unread(_) => {
                ": a file the reader cannot read is one chard cannot show this run built, \
                 whatever left it there"
            }
            Self::MissingFromIr | Self::Bitcode => "",
            Self::Library { absence, .. } => absence.cause(),
            Self::OtherCompiler { .. } => {
                ": a compiler cache's prefix command or a wrapper on PATH can send a compile to another compiler"
            }
        }
    }

    /// The gating rule a check over a build whose artifact is set aside for this absence
    /// publishes: `artifact-compiled-by-another-compiler` for [`Self::OtherCompiler`],
    /// `artifact-lacks-run-witness` for every other.
    #[must_use]
    pub fn rule(&self) -> crate::report::gating_rule::Rule {
        use crate::report::gating_rule::{ARTIFACT_OTHER_COMPILER, ARTIFACT_UNWITNESSED};
        match self {
            Self::OtherCompiler { .. } => ARTIFACT_OTHER_COMPILER,
            Self::Library { absence, .. } => absence.rule(),
            _ => ARTIFACT_UNWITNESSED,
        }
    }

    /// What this absence keeps chard from showing of the artifact, for a sentence that ends
    /// "so chard cannot show ...".
    #[must_use]
    pub fn unshown(&self) -> &'static str {
        match self {
            Self::OtherCompiler { .. } => "the compiler the report names built it",
            Self::Library { absence, .. } => absence.unshown(),
            _ => "this run built it",
        }
    }
}

impl RunWitness {
    /// A witness whose nonce is 128 bits from the operating system, with its header written
    /// into `workdir`.
    ///
    /// # Errors
    ///
    /// Errors when the random device cannot be read or the header cannot be written.
    pub fn random_in(workdir: &Path) -> Result<Self> {
        Self::random_from(Path::new(RANDOM_DEVICE), workdir)
    }

    /// [`Self::random_in`], reading `device`, so a test can hand it one that is short.
    fn random_from(device: &Path, workdir: &Path) -> Result<Self> {
        use std::io::Read as _;
        let mut nonce = [0u8; crate::elf::RUN_WITNESS_BYTES];
        std::fs::File::open(device)
            .and_then(|mut file| file.read_exact(&mut nonce))
            .with_context(|| format!("reading the run's nonce from {}", device.display()))?;
        let nonce = crate::elf::hex_of(&nonce);
        Self::installed(nonce, WitnessSource::OsRandom, workdir)
    }

    /// A witness whose nonce is the first 128 bits of a SHA-256 over `asked`, one line each,
    /// with its header written into `workdir`: what a run that must build the same bytes as
    /// another run of the same measurement uses (`measure --normalize`).
    ///
    /// # Errors
    ///
    /// Errors when the header cannot be written.
    pub fn derived_in<I, S>(asked: I, workdir: &Path) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seed = String::from("chard-run-witness-v1\n");
        for line in asked {
            seed.push_str(line.as_ref());
            seed.push('\n');
        }
        let nonce = digest::sha256_hex(seed.as_bytes())
            .chars()
            .take(crate::elf::RUN_WITNESS_BYTES.saturating_mul(2))
            .collect();
        Self::installed(nonce, WitnessSource::Derived, workdir)
    }

    fn installed(nonce: String, source: WitnessSource, workdir: &Path) -> Result<Self> {
        use std::io::Write as _;
        let witness = Self { nonce, source };
        let path = workdir.join(RUN_WITNESS_HEADER_NAME);
        // The name is cleared and the file created new, never written through what is
        // there: a reused work directory can hold an earlier run's header, and a link left
        // at the name would otherwise send this run's header wherever it points.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .context(crate::error::HarnessPath(path.clone()))
                    .context("clearing an earlier run-witness header");
            }
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(witness.header().as_bytes()))
            .with_context(|| crate::error::HarnessPath(path.clone()))
            .context("writing the run-witness header")?;
        Ok(witness)
    }

    /// The nonce as [`crate::elf::ElfFacts::run_witness`] spells one.
    #[must_use]
    pub fn nonce_hex(&self) -> &str {
        &self.nonce
    }

    /// Where the nonce came from.
    #[must_use]
    pub const fn source(&self) -> WitnessSource {
        self.source
    }

    /// The words a build's command line carries for the witness, after its flags.
    #[must_use]
    pub fn compile_words() -> [String; 2] {
        ["-include".to_owned(), RUN_WITNESS_HEADER_NAME.to_owned()]
    }

    /// The generated header's text.
    #[must_use]
    pub fn header(&self) -> String {
        let bytes = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|b| format!("{b:#04x}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut owner = crate::elf::RUN_WITNESS_OWNER.as_bytes().to_vec();
        owner.push(0);
        let namesz = owner.len();
        while !owner.len().is_multiple_of(4) {
            owner.push(0);
        }
        let nonce = self
            .nonce
            .as_bytes()
            .chunks(2)
            .map(|pair| format!("0x{}", String::from_utf8_lossy(pair)))
            .collect::<Vec<_>>()
            .join(",");
        let directives = [
            format!(
                ".pushsection {},\"a\",%note",
                crate::elf::RUN_WITNESS_SECTION
            ),
            ".balign 4".to_owned(),
            format!(
                ".4byte {namesz},{},{}",
                crate::elf::RUN_WITNESS_BYTES,
                crate::elf::RUN_WITNESS_TYPE
            ),
            format!(".byte {}", bytes(&owner)),
            format!(".byte {nonce}"),
            ".popsection".to_owned(),
        ];
        let mut text = String::from(
            "/* Written by chard for one run and named on each compile line with -include.\n\
             \x20* It is not a probe source. It places the run's nonce in a note section, and\n\
             \x20* chard reads an artifact only where it finds that note. */\n\
             #if defined(__ASSEMBLER__)\n",
        );
        for directive in &directives {
            text.push('\t');
            text.push_str(directive);
            text.push('\n');
        }
        text.push_str("#else\n__asm__(\n");
        for directive in &directives {
            text.push_str("    \"\\t");
            text.push_str(&directive.replace('"', "\\\""));
            text.push_str("\\n\"\n");
        }
        text.push_str(");\n#endif\n");
        text
    }

    /// Whether `facts` is an artifact of this run: its run witnesses are this nonce and
    /// nothing else.
    ///
    /// # Errors
    ///
    /// The absence, where the artifact carries no witness or one this run did not write.
    pub fn confirm(&self, facts: &crate::elf::ElfFacts) -> Result<(), WitnessAbsence> {
        let holds_ir = || {
            facts
                .sections
                .iter()
                .any(|name| name.starts_with(crate::report::LTO_IR_SECTION_PREFIX))
        };
        match facts.run_witness.as_slice() {
            [] if holds_ir() => Err(WitnessAbsence::MissingFromIr),
            [] => Err(WitnessAbsence::Missing),
            [one] if *one == self.nonce => Ok(()),
            found => Err(WitnessAbsence::Foreign(found.to_vec())),
        }
    }
}

/// A build's words without the run-witness words ([`RunWitness::compile_words`]), wherever
/// that pair stands on the line.
#[must_use]
pub fn without_witness_words(words: &[String]) -> Vec<String> {
    let [include, header] = RunWitness::compile_words();
    let mut kept = Vec::with_capacity(words.len());
    let mut rest = words.iter().peekable();
    while let Some(word) = rest.next() {
        if *word == include && rest.peek().is_some_and(|next| **next == header) {
            rest.next();
        } else {
            kept.push(word.clone());
        }
    }
    kept
}

fn invoke(program: &Path, args: &[String]) -> Result<BuildRecord> {
    invoke_with_timeout(program, args, None, INVOKE_TIMEOUT, DRAIN_GRACE)
}

/// The body, with both bounds as parameters so a test can prove each of them fires
/// without taking two minutes to do it.
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
        // A group of its own, so a timeout kills the driver's `cc1`, `as` and `ld` too
        // (`run::kill_group`).
        .process_group(0)
        .spawn()
        .with_context(|| format!("running {}", program.display()))?;

    // Drained on their own threads rather than into files, unlike `run::execute`: `capture`
    // is called from `toolchain`'s driver and linker probes, which have no work directory.
    let (Some(out_pipe), Some(err_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        crate::error::best_effort(child.kill());
        anyhow::bail!("{}: stdout and stderr were not piped", program.display());
    };
    let (err_ended, pipe_ended) = std::sync::mpsc::channel();
    let out_ended = err_ended.clone();
    let out_reader = std::thread::spawn(move || drain(out_pipe, &out_ended));
    let err_reader = std::thread::spawn(move || drain(err_pipe, &err_ended));

    // The readers' end of file wakes this wait, under `EXIT_WAKE_BOUND`, and `try_wait` alone
    // decides the child has exited: a pipe closes early where the child closes or redirects
    // it, and late where another process holds it.
    let mut open = 2_u8;
    let mut closed_at = started;
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
            // The driver's whole group, before the reap (`run::kill_group` says why), so no
            // `cc1` or `ld` it started runs on, or holds the pipes the readers wait on.
            crate::run::kill_group(&mut child);
            crate::error::best_effort(child.wait());
            drop(out_reader);
            drop(err_reader);
            // An error, not a `BuildRecord`: the `compiler-diag` channel reads a failed
            // compile as its observable, so a wedged toolchain would publish as a
            // measurement from a run that measured nothing.
            anyhow::bail!(
                "{} did not finish within {}s: {}",
                program.display(),
                timeout.as_secs(),
                args.join(" ")
            );
        }
        if open == 0 {
            crate::run::poll_sleep(closed_at.elapsed());
            continue;
        }
        let left = timeout.saturating_sub(started.elapsed());
        match pipe_ended.recv_timeout(left.min(EXIT_WAKE_BOUND)) {
            Ok(()) => open = open.saturating_sub(1),
            Err(RecvTimeoutError::Timeout) => continue,
            // Both senders dropped and no end of file will come: a reader panicked, and
            // `read_both` reports it.
            Err(RecvTimeoutError::Disconnected) => open = 0,
        }
        if open == 0 {
            closed_at = Instant::now();
        }
    };
    // Before draining, not after: the reported duration is the child's lifetime, not the
    // child's lifetime plus our own bookkeeping.
    let ran_for = started.elapsed();

    let (stdout, stderr) = read_both(out_reader, err_reader, drain_grace, program, args)?;

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

/// The two readers' output once `invoke_with_timeout`'s child has been reaped, waited for
/// under `drain_grace`.
///
/// # Errors
///
/// Where a pipe is still held `drain_grace` after the exit, or a reader panicked. A stream
/// that could not be read is a failure to observe, for the reason the timeout branch gives: an
/// unread stderr published as empty is a `compiler-diag` measurement nobody made.
fn read_both(
    out_reader: JoinHandle<Vec<u8>>,
    err_reader: JoinHandle<Vec<u8>>,
    drain_grace: Duration,
    program: &Path,
    args: &[String],
) -> Result<(Vec<u8>, Vec<u8>)> {
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
    Ok((stdout, stderr))
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
/// # Errors
///
/// Errors when the program cannot be spawned at all. A non-zero exit status is
/// not an error: it is recorded in the returned [`BuildRecord`].
pub fn capture(program: &Path, args: &[String]) -> Result<BuildRecord> {
    invoke(program, args)
}

/// Compile and link `source` into `out`, with `flags` inserted before it.
///
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
    witness: Option<&RunWitness>,
) -> Result<BuildRecord> {
    build_with_inputs(driver, flags, source, &[], out, link_libs, witness)
}

/// [`build`] with `inputs` (`probe::PositiveInput`), file names in `source`'s directory,
/// named after `source` and before the libraries, since a library resolves only the objects
/// named before it.
///
/// # Errors
///
/// As [`build`].
pub fn build_with_inputs(
    driver: &Path,
    flags: &[String],
    source: &Path,
    inputs: &[&str],
    out: &Path,
    link_libs: &[&str],
    witness: Option<&RunWitness>,
) -> Result<BuildRecord> {
    let (cwd, source_arg) = in_place(source);
    let mut args: Vec<String> = Vec::new();
    args.extend(flags.iter().cloned());
    if witness.is_some() {
        args.extend(RunWitness::compile_words());
    }
    args.push("-o".to_owned());
    args.push(out.display().to_string());
    args.push(source_arg);
    args.extend(inputs.iter().map(|s| (*s).to_owned()));
    // After the source, never before: GNU ld resolves libraries in command-line
    // order, so a `-l` ahead of the object that needs it contributes nothing — and
    // under `--as-needed` is dropped even when the symbol *is* used, which would make
    // the probe for that very flag report it active in both arms.
    args.extend(link_libs.iter().map(|s| (*s).to_owned()));

    // Clear the path first, so what is read afterwards can only be what this build
    // wrote.
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
        // `None` here means the driver exited 0 and wrote nothing: no artifact to inspect,
        // not a build failure.
        record.artifact_sha256 = digest::sha256_file(out);
    }
    Ok(record)
}

/// Driver options whose argument is a path the driver, or a tool it runs, opens relative
/// to its working directory: the argument either joined (`-Ifoo`, `--sysroot=foo`) or the
/// next word (`-I foo`, `--sysroot foo`). An option spelled with `--`, and
/// `-resource-dir`, joins its argument only after `=`, so `--config-user-dir=d` is not
/// `--config` with the argument `-user-dir=d`. One ending in `=` takes no next word.
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
    /// `-isystem-after` or `-include-pch` (`CLANG_LONGER`), which gcc does not know.
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
    /// A word the driver reads as an input file (`foo.c`, `./foo.o`, `libfoo.a`): no option,
    /// and the value of none, named by a relative path.
    Input,
    /// `option` and the word after it, which one driver reads as the option's value and the
    /// other as an input file named by a relative path (`-Ttext 0x8000`, `-dumpbase foo.c`).
    Divided {
        /// The option the drivers divide.
        option: String,
    },
}

impl PathReading {
    /// What a refusal says of an argument read so, beside the argument, and what to write
    /// instead; `None` for a relative path as written, which the refusal's own sentence covers.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        match self {
            Self::Relative => None,
            Self::GccJoined { option, value } => Some(format!(
                "which gcc reads as {option} with the relative path {value:?}"
            )),
            Self::Unpaired => {
                Some("whose path is not handed in the same word or the pair after it".to_owned())
            }
            Self::Input => Some("an input file the driver opens in the work directory".to_owned()),
            Self::Divided { option } => Some(format!(
                "which one driver reads as the value of {option} and the other as an input file it opens in the work directory"
            )),
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
    /// clang's driver for one architecture (`-Xarch_<arch>`): one word, read as the driver
    /// reads its own, so a word that is no option is an input file; a two-token option with
    /// no path in it clang refuses.
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

/// Whether `word`, read by the driver as no option, names an input file by a relative path.
/// `=` and `$SYSROOT` mean nothing at the head of an input's name, as they do for a path
/// option's argument ([`relative`]); `@` begins a response file, which is refused apart.
fn input_name(word: &str) -> bool {
    !word.is_empty() && !word.starts_with(['-', '@']) && Path::new(word).is_relative()
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
        // An option the drivers divide takes the next word as its value under one and leaves
        // it an input file under the other (`toolchain::divides_its_value`).
        if reader == PathReader::Driver
            && crate::toolchain::divides_its_value(word)
            && let Some(value) = next
            && input_name(value)
        {
            return (
                2,
                Some(PathReading::Divided {
                    option: word.to_owned(),
                }),
            );
        }
        // A value-taking option that names no path takes the next word as its value, which
        // is no option of its own (`-u -B<dir>`, `-MF -L<dir>`; `toolchain::takes_a_value`).
        if reader == PathReader::Driver && crate::toolchain::takes_a_value(word) {
            return (if next.is_some() { 2 } else { 1 }, None);
        }
        // Any other word of the driver's own that is no option is an input file it opens
        // where it runs.
        if matches!(reader, PathReader::Driver | PathReader::Arch) && input_name(word) {
            return (1, Some(PathReading::Input));
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
/// that begins with `@`; and a `JOINED_PASS_THROUGH` option whose value begins with
/// `@`. Each comes back as written.
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
/// is not part of a line; the record's output is trimmed at its end before it gets here. For
/// a dump with no `\r`, the same value is `LC_ALL=C sort` over the dump with the final
/// newline of its output removed, then `sha256sum`.
#[must_use]
pub fn dump_digest(stdout: &str) -> String {
    let mut lines: Vec<&str> = stdout.lines().collect();
    lines.sort_unstable();
    digest::sha256_hex(lines.join("\n").as_bytes())
}

/// The translation unit a [`macro_dump`] preprocesses.
#[derive(Debug, Clone, Copy)]
pub enum DumpUnit<'a> {
    /// An empty unit: what the compiler defines by itself (`toolchain`'s intrinsic and
    /// profile dumps), so `__SSP_STRONG__` reflects a compiler default.
    Empty,
    /// The libc headers of `LIBC_PROBE_HEADERS`: what the C library concludes besides
    /// (`__USE_FORTIFY_LEVEL`), for `toolchain`'s with-headers dump.
    LibcHeaders,
    /// A probe's own source text, dumped under the words its build compiles with, so the
    /// macro channel's two views are one translation unit through two jobs. The file is
    /// written beside the probe's source and `chard_selfreport.h`, so its quoted include
    /// resolves as the build's does.
    Source(&'a str),
}

/// Preprocess `unit` with `-dM -E` and return the macros defined at its end.
///
/// # Errors
///
/// Errors when the throwaway source cannot be written to `work`, or when the
/// compiler cannot be spawned.
pub fn macro_dump(
    driver: &Path,
    lang: crate::probe::Lang,
    flags: &[String],
    unit: DumpUnit<'_>,
    work: &Path,
    tag: &str,
) -> Result<(BTreeMap<String, String>, BuildRecord)> {
    // A real file rather than stdin: it keeps the invocation reproducible by
    // hand and leaves the exact input behind as evidence.
    let source = work.join(format!("macros-{tag}.{}", lang.source_suffix()));
    let body = match unit {
        DumpUnit::Empty => "",
        DumpUnit::LibcHeaders => LIBC_PROBE_HEADERS,
        DumpUnit::Source(text) => text,
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
    // [`build`] does for a probe.
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
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "the condition is a sibling test's fork closing its copy of the write descriptor, \
              which nothing here can wait on: retrying the exec between sleeps, under the 5 s \
              deadline, is the wait"
)]
pub(crate) fn test_script(path: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    // ETXTBSY is 26 on Linux and on Darwin alike.
    const ETXTBSY: i32 = 26;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("write a script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("mark the script executable");

    // Spawned through `capture`, where this crate's spawns are bounded
    // (`every_spawn_site_sits_where_something_bounds_it`), the call the code under test makes.
    let deadline = Instant::now() + Duration::from_secs(5);
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
            Instant::now() < deadline,
            "{} stayed busy for 5s; a descriptor is held open for writing somewhere that \
             never execs",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
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
        // is one whose counterpart is not installed.
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
            .is_empty(),
            "no word here takes a relative path argument"
        );
        assert_eq!(
            relative_path_arguments(&words("--config-user-dir=cfg --configure")),
            ["--config-user-dir=cfg"],
            "a long option joins only after `=`, and the longest option is the one read"
        );
    }

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
                    PathReading::Input => "input".to_owned(),
                    PathReading::Divided { option } => format!("divided {option}"),
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

    #[test]
    fn an_input_file_named_by_a_relative_path_is_read_as_one() {
        row("foo.c", "foo.c|input");
        row("-O2 ./foo.o", "./foo.o|input");
        row("libfoo.a -lm", "libfoo.a|input");
        row("sub/libfoo.a", "sub/libfoo.a|input");
        row("=foo.o", "=foo.o|input");
        row("$SYSROOT/foo.o", "$SYSROOT/foo.o|input");
        row("-Xarch_x86_64 foo.c", "-Xarch_x86_64 foo.c|input");
        row(
            "/srv/src/foo.c /srv/lib/libfoo.a -Xarch_x86_64 /srv/foo.o",
            "",
        );
        row(
            "-o out -x c -l m -z relro -u sym -D X -MT tgt -MF dep.d --param ssp-buffer-size=4",
            "",
        );
        row(
            "-target x86_64-linux-gnu --target=x86_64-linux-gnu -arch x86_64",
            "",
        );
        // `--optimize` is gcc's `-O` alone, and the word after it the driver's own
        // (`toolchain::read`): an input file.
        row(
            "--optimize 2 --machine 32 --output out --language c",
            "2|input",
        );
        row("-dumpbase foo.c", "-dumpbase foo.c|divided -dumpbase");
        row("-Ttext 0x8000", "-Ttext 0x8000|divided -Ttext");
        row(
            "-undefined dynamic_lookup",
            "-undefined dynamic_lookup|divided -undefined",
        );
        row("--entry foo.c", "--entry foo.c|divided --entry");
        row(
            "-dependency-file dep.d",
            "-dependency-file dep.d|divided -dependency-file",
        );
        row("-dumpbase /srv/foo.c -Ttext -O2", "");
        row("-Ttext @/srv/args.rsp", "");
        row(
            "-Wl,-z,relro -Xlinker -z -Xlinker now -Wl,foo.o -Xlinker foo.o -Wa,foo.s \
             -Xassembler foo.s -Wp,foo.c -Xclang foo.c -Xarch_x86_64 -Wl,foo.o",
            "",
        );
        row("-O2 -- -foo.c", "");
        // Distributions' own lists name no input file.
        row(
            "-g -O2 -ffile-prefix-map=/build/p=. -fstack-protector-strong \
             -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection \
             -Wdate-time -D_FORTIFY_SOURCE=3 -Wl,-z,relro -Wl,-z,now -Wl,-Bsymbolic-functions",
            "",
        );
        row(
            "-O2 -flto=auto -ffat-lto-objects -fexceptions -g -grecord-gcc-switches -pipe -Wall \
             -Werror=format-security -Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3 \
             -Wp,-D_GLIBCXX_ASSERTIONS -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 \
             -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -march=x86-64 -mtune=generic \
             -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection \
             -mtls-dialect=gnu2 -Wl,-z,relro -Wl,--as-needed -Wl,-z,pack-relative-relocs \
             -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld",
            "",
        );
        row(
            "-march=x86-64 -mtune=generic -O2 -pipe -fno-plt -fexceptions \
             -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security \
             -fstack-clash-protection -fcf-protection -fno-omit-frame-pointer \
             -mno-omit-leaf-frame-pointer -Wl,-O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro \
             -Wl,-z,now -Wl,-z,pack-relative-relocs",
            "",
        );
        row(
            "-Os -fstack-clash-protection -Wformat -Werror=format-security \
             -D_FORTIFY_SOURCE=2 -Wl,--as-needed,-O1,--sort-common -Wl,-z,pack-relative-relocs",
            "",
        );
        assert!(
            relative_path_readings(&[String::new()]).is_empty(),
            "an empty word"
        );
        assert_eq!(relative_path_in_value("hello world", |_| false), None);
        assert_eq!(relative_path_in_value("foo.c", |_| false), None);
        assert_eq!(relative_path_in_value("-Ttext 0x8000", |_| false), None);
        assert_eq!(
            relative_path_in_value("foo.c -I bar", |_| false).map(|found| found.argument),
            Some("-I bar".to_owned()),
            "a value's relative path option is refused beside a word that is no input"
        );
        assert_eq!(
            relative_path_in_value("foo.c", |_| true).map(|found| found.reading),
            Some(PathReading::Relative),
            "a word naming a file in chard's directory is refused as the entry reading says"
        );
    }

    #[test]
    fn every_driver_path_option_begins_with_a_dash() {
        let options: Vec<&str> = PATH_OPTIONS
            .iter()
            .chain(PATH_OR_NAME_OPTIONS)
            .copied()
            .chain(
                CLANG_LONGER
                    .iter()
                    .flat_map(|(longer, shorter)| [*longer, *shorter]),
            )
            .collect();
        assert!(options.len() > 30, "{options:?}");
        for option in options {
            assert!(option.starts_with('-'), "{option}");
        }
    }

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
            .is_empty(),
            "an @ inside a word's value is not a response file"
        );
    }

    #[test]
    fn the_include_and_temporary_directory_variables_are_on_the_record() {
        for name in ["CPLUS_INCLUDE_PATH", "TMP", "TEMP", "TEMPDIR"] {
            assert!(
                COMPILER_ENV_NAMED.contains(&name),
                "{name} left the named variables, which a driver was measured reading"
            );
        }
    }

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

    #[test]
    fn a_set_after_the_pairs_were_read_is_an_error() {
        let pairs = compiler_environment_additions(&["A=1".to_owned()]).expect("a plain pair");
        let read_first = RunEnvironment::new();
        assert!(
            read_first.get().as_slice().is_empty(),
            "an environment read before any set is empty: {:?}",
            read_first.get().as_slice()
        );
        assert!(
            read_first.set(pairs.clone()).is_err(),
            "a set after a read succeeded, so invocations before and after it saw two environments"
        );
        assert!(
            read_first.get().as_slice().is_empty(),
            "a refused set leaves the environment as it was read: {:?}",
            read_first.get().as_slice()
        );

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

    #[test]
    fn an_env_argument_naming_a_passed_or_pinned_or_malformed_name_is_refused() {
        let args = |list: &[&str]| list.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        for refused in [
            "PATH=/usr/bin",
            "LC_ALL=en_US.UTF-8",
            "TERM=xterm",
            "CCACHE_DISABLE=0",
            "CCACHE_NODISABLE=1",
            "CCACHE_CONFIGPATH=/tmp/ccache.conf",
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

    #[test]
    fn every_pin_is_refused_with_its_own_reason() {
        for (name, value) in COMPILER_ENV_PINNED {
            let Some(why) = pin_reason(name) else {
                panic!("the pin {name} has no reason for its --env refusal to give");
            };
            // Every pin is classed, and a boolean one is ccache's and set to a value ccache
            // reads as true: its manual's negative words are an error, not a false.
            let Some(boolean) = ccache_boolean_pin(name) else {
                panic!("the pin {name} is not classed by `ccache_boolean_pin`");
            };
            if boolean {
                assert!(name.starts_with("CCACHE_"), "{name} is not ccache's");
                assert!(
                    !["0", "false", "disable", "no"].contains(&value.to_ascii_lowercase().as_str()),
                    "the boolean pin {name}={value} is a value ccache refuses"
                );
            }
            let reader = if name.starts_with("CCACHE_") {
                "ccache"
            } else {
                "compiler-diag"
            };
            assert!(
                why.contains(reader),
                "the pin {name}'s --env refusal does not name what reads it ({reader}): {why:?}"
            );
        }
        assert_eq!(pin_reason("CCACHE_DIR"), None);
        // Each refusal names the pin's value: the pin's own as `pinned to "1"`, its negation's
        // as the variable every invocation receives.
        for (arg, value) in [
            ("CCACHE_DISABLE=", "pinned to \"1\""),
            ("CCACHE_NODISABLE=true", "receives CCACHE_DISABLE=1 "),
        ] {
            let message = compiler_environment_additions(&[arg.to_owned()])
                .expect_err(arg)
                .to_string();
            assert!(
                message.contains("ccache masquerade directory")
                    && message.contains(value)
                    && !message.contains("compiler-diag"),
                "{arg}: {message}"
            );
        }
        assert_eq!(ccache_boolean_pin("CCACHE_DIR"), None);
        assert_eq!(
            countermanded_pin("CCACHE_NODISABLE"),
            Some("CCACHE_DISABLE")
        );
        for name in [
            "CCACHE_NODIRECT",
            "CCACHE_NOCONFIGPATH",
            "CCACHE_DISABLE",
            "CCACHE_NO",
            "NODISABLE",
        ] {
            assert_eq!(countermanded_pin(name), None, "{name}");
        }
        let kept = compiler_environment_additions(&["CCACHE_DIR=/var/cache/x".to_owned()])
            .expect("CCACHE_DIR names no pin");
        assert_eq!(kept.as_slice().len(), 1);
    }

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

        let record = build(&driver, &[], &source, &out, &[], None).expect("a record");
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

    #[test]
    fn a_build_that_writes_nothing_does_not_inherit_the_last_one() {
        let dir = std::env::temp_dir().join(format!("chard-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let out = dir.join("probe");
        let source = dir.join("probe.c");
        std::fs::write(&source, "int main(void){return 0;}\n").expect("source");
        std::fs::write(&out, b"\x7fELF stale artifact from a previous run").expect("stale");

        let exits_zero = crate::toolchain::resolve_driver("true").expect("`true` on PATH");
        let record = build(&exits_zero, &[], &source, &out, &[], None)
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

    #[test]
    fn a_timeout_kills_what_the_driver_started() {
        let dir = std::env::temp_dir().join(format!("chard-invokegroup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let started = dir.join("started");
        let got = invoke_with_timeout(
            Path::new("/bin/sh"),
            &[
                "-c".to_owned(),
                format!(
                    "(trap '' TERM HUP INT; exec /bin/sleep 30) & echo $! > '{}'; wait",
                    started.display()
                ),
            ],
            None,
            Duration::from_millis(400),
            Duration::from_millis(300),
        );
        let err = got.expect_err("a driver that outlives the bound must not return a record");
        assert!(format!("{err}").contains("did not finish"), "{err}");
        let pid: u32 = std::fs::read_to_string(&started)
            .expect("the driver wrote its child's pid")
            .trim()
            .parse()
            .expect("a pid");
        assert!(
            crate::run::gone_within(pid, Duration::from_secs(2)),
            "the driver's child {pid} is still running after the timeout killed the driver"
        );
        drop(std::fs::remove_dir_all(&dir));
    }

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

    #[test]
    fn a_child_that_closes_its_output_early_is_still_waited_for() {
        let record = invoke_with_timeout(
            Path::new("/bin/sh"),
            &[
                "-c".to_owned(),
                "echo early; exec >/dev/null 2>&1; sleep 0.3; exit 4".to_owned(),
            ],
            None,
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .expect("a program that exits is not an error");
        assert_eq!(
            record.exit_status, 4,
            "the status of the exit, not of the end of file"
        );
        assert_eq!(record.stdout, "early");
        assert!(
            record.duration_ms >= 300,
            "the record must cover the child's whole lifetime, not end at its end of file: {} ms",
            record.duration_ms
        );
    }

    #[test]
    fn a_child_that_closes_its_output_and_hangs_still_times_out() {
        let started = Instant::now();
        let got = invoke_with_timeout(
            Path::new("/bin/sh"),
            &[
                "-c".to_owned(),
                "exec >/dev/null 2>&1; exec /bin/sleep 30".to_owned(),
            ],
            None,
            Duration::from_millis(400),
            Duration::from_millis(300),
        );
        let err = got.expect_err("a child that outlives the bound must not return a record");
        assert!(format!("{err}").contains("did not finish"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the timeout, not the child, ended the wait: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_duration_ends_at_the_exit_not_when_the_pipes_are_let_go() {
        let record = invoke_with_timeout(
            Path::new("/bin/sh"),
            &[
                "-c".to_owned(),
                "/bin/sleep 1 & /bin/sleep 0.05; exit 0".to_owned(),
            ],
            None,
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .expect("a holder that lets go within the drain bound leaves a record");
        assert!(
            record.duration_ms < 300,
            "the duration ran on to the holder's end of file: {} ms",
            record.duration_ms
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_wait_after_both_pipes_close_does_not_spin() {
        const SCHEDSTAT: &str = "/proc/thread-self/schedstat";
        // The first field of `schedstat` is the thread's time on a CPU, in nanoseconds.
        let on_cpu = |text: &str| -> u64 {
            let field = text.split_whitespace().next().expect("a time on CPU");
            field.parse().expect("a time on CPU in nanoseconds")
        };
        let before = match std::fs::read_to_string(SCHEDSTAT) {
            Ok(text) => on_cpu(&text),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                panic!("{SCHEDSTAT} is there and does not read: {e}")
            }
            Err(_) => {
                crate::error::capability_gap(
                    "the_wait_after_both_pipes_close_does_not_spin",
                    "this kernel has no /proc/thread-self/schedstat",
                );
                return;
            }
        };
        let record = invoke_with_timeout(
            Path::new("/bin/sh"),
            &[
                "-c".to_owned(),
                "exec >/dev/null 2>&1; exec /bin/sleep 1".to_owned(),
            ],
            None,
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .expect("a program that exits is not an error");
        let after = on_cpu(&std::fs::read_to_string(SCHEDSTAT).expect("the thread's schedstat"));
        // A counter that did not move over a second of waiting is a kernel that does not
        // account it, and a zero read from it would pass a spinning wait.
        if after <= before {
            crate::error::capability_gap(
                "the_wait_after_both_pipes_close_does_not_spin",
                "this kernel's /proc/thread-self/schedstat does not count time on a CPU",
            );
            return;
        }
        let spent = Duration::from_nanos(after.saturating_sub(before));
        assert!(record.duration_ms >= 1000, "{} ms", record.duration_ms);
        assert!(
            spent < Duration::from_millis(200),
            "the wait spent {spent:?} on a CPU over a one-second child"
        );
    }

    #[test]
    fn a_reader_that_panicked_is_an_error() {
        let ok = || std::thread::spawn(Vec::new);
        let panicked = || std::thread::spawn(|| -> Vec<u8> { panic!("a reader panicked") });
        for (out_reader, err_reader) in [(ok(), panicked()), (panicked(), ok())] {
            let got = read_both(
                out_reader,
                err_reader,
                Duration::from_secs(5),
                Path::new("cc"),
                &[],
            );
            let err = got.expect_err("an unread stream must not publish as empty");
            assert!(format!("{err}").contains("output reader panicked"), "{err}");
        }
    }

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
        // stderr lands one byte short of what was written.
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

    #[test]
    fn every_spawn_site_sits_where_something_bounds_it() {
        const BOUNDED: &[&str] = &["compile.rs", "run.rs"];
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        // The whole tree, not its top level: `src/decode/` and `src/predicate/` hold modules,
        // and a child spawned there is as unbounded as one spawned beside this file.
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
    /// keyword, its opening brace and its closing brace. A `fn` whose first `{` or `;` is a
    /// `;` has no body here: a trait item, or a function-pointer type.
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
    /// block opened at byte `parent`. Each loop word in that block is followed forward with
    /// `()` and `[]` balanced and brace groups skipped, so a closure or block in the loop's
    /// head (`for _ in it.filter(|_| { .. }) {`) does not hide the keyword.
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
    /// output) is one child, bound once and waited for by the innermost function that holds
    /// it. Four rejections, each named in its panic:
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

        // Every later mention of `child` up to the function's close: a method or a field, or
        // a borrow, and nothing else.
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
    /// The sites allowed, each with the bound that keeps it to one child (the ratchet below).
    const ALLOWED: &[(&str, &str, usize, &str)] = &[
        (
            "compile.rs",
            "thread::spawn",
            4,
            "the stdout and stderr readers of the one child `invoke_with_timeout` \
             spawned; each reads a pipe, sends its end of file on a channel to that \
             function and spawns nothing, and is joined or abandoned before that function \
             returns; and the two stand-in readers of `a_reader_that_panicked_is_an_error` \
             (test module only), which start no process and are joined by `read_both`",
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
            3,
            "`execute`'s probe, waited for under the probe timeout its caller supplies; \
             `kill_group`'s shell, spawned only once a child has outlived its bound, beside \
             that child as it is killed and before it is reaped, and waited for under \
             `KILL_BOUND`; and a test's `sleep`, killed by `kill_group_through` and reaped \
             by the test",
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
                // scope returns).
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

        // Whole components: a directory that merely begins with the work directory's
        // spelling is a different directory.
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

    /// A directory of one witness test's own under the temporary directory, emptied first.
    fn witness_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("chard-nonce-{tag}-{}", std::process::id()));
        crate::error::best_effort(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).expect("the test's directory");
        dir
    }

    /// Facts whose run witnesses are `witnesses`.
    fn facts_carrying(witnesses: &[&str]) -> crate::elf::ElfFacts {
        let mut facts = crate::probe::tests::elf_with_report("");
        facts.run_witness = witnesses.iter().map(|w| (*w).to_owned()).collect();
        facts
    }

    #[test]
    fn a_witness_writes_the_header_its_builds_name() {
        let dir = witness_dir("header");
        let witness = RunWitness::derived_in(["a line"], &dir).expect("a witness");
        let written = std::fs::read_to_string(dir.join(RUN_WITNESS_HEADER_NAME))
            .expect("the header is on disk");
        assert_eq!(written, witness.header());
        assert_eq!(
            RunWitness::compile_words(),
            ["-include", RUN_WITNESS_HEADER_NAME]
        );

        let nonce = witness.nonce_hex();
        assert_eq!(nonce.len(), crate::elf::RUN_WITNESS_BYTES * 2, "{nonce}");
        assert!(
            nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{nonce}"
        );
        let bytes: Vec<String> = nonce
            .as_bytes()
            .chunks(2)
            .map(|pair| format!("0x{}", String::from_utf8_lossy(pair)))
            .collect();
        let nonce_line = format!(".byte {}", bytes.join(","));
        let section = format!(".pushsection {},", crate::elf::RUN_WITNESS_SECTION);
        // "chard" and its NUL, padded to a multiple of four.
        let owner_line = ".byte 0x63,0x68,0x61,0x72,0x64,0x00,0x00,0x00";
        let header_line = format!(
            ".4byte 6,{},{}",
            crate::elf::RUN_WITNESS_BYTES,
            crate::elf::RUN_WITNESS_TYPE
        );
        for needle in [&nonce_line, &section, owner_line, &header_line, "%note"] {
            assert_eq!(
                written.matches(needle).count(),
                2,
                "`{needle}` is not in both forms of the header:\n{written}"
            );
        }
        let conditionals: Vec<&str> = written.lines().filter(|l| l.starts_with('#')).collect();
        assert_eq!(
            conditionals,
            ["#if defined(__ASSEMBLER__)", "#else", "#endif"],
            "the header is conditional on more than the unit's language"
        );
        assert!(written.contains("__asm__("), "{written}");
        assert!(
            !written.contains("  \\"),
            "a line continuation left a run of spaces in the header"
        );
    }

    #[test]
    fn a_nonce_is_derived_from_the_question_or_read_whole_from_the_device() {
        let dir = witness_dir("sources");
        let asked = ["profile.cflags=-O2", "env.A=1"];
        let first = RunWitness::derived_in(asked, &dir).expect("a witness");
        let again = RunWitness::derived_in(asked, &dir).expect("a witness");
        let other =
            RunWitness::derived_in(["profile.cflags=-O2", "env.A=2"], &dir).expect("a witness");
        let joined =
            RunWitness::derived_in(["profile.cflags=-O2env.A=1"], &dir).expect("a witness");
        assert_eq!(first, again);
        assert_eq!(first.source(), WitnessSource::Derived);
        assert_ne!(first.nonce_hex(), other.nonce_hex());
        assert_ne!(
            first.nonce_hex(),
            joined.nonce_hex(),
            "two lines and their concatenation derive one nonce"
        );

        let device = dir.join("device");
        std::fs::write(&device, [0xa5u8; crate::elf::RUN_WITNESS_BYTES]).expect("a device");
        let random = RunWitness::random_from(&device, &dir).expect("a witness");
        assert_eq!(random.source(), WitnessSource::OsRandom);
        assert_eq!(
            random.nonce_hex(),
            "a5".repeat(crate::elf::RUN_WITNESS_BYTES)
        );
        std::fs::write(&device, [0xa5u8; 15]).expect("a short device");
        let short = RunWitness::random_from(&device, &dir).expect_err("fifteen bytes are no nonce");
        assert!(
            format!("{short:#}").contains("reading the run's nonce"),
            "{short:#}"
        );
        let absent =
            RunWitness::random_from(&dir.join("no-device"), &dir).expect_err("no device, no nonce");
        assert!(format!("{absent:#}").contains("no-device"), "{absent:#}");

        // The host's device gives two runs two nonces.
        if Path::new(RANDOM_DEVICE).exists() {
            let one = RunWitness::random_in(&dir).expect("a witness");
            let two = RunWitness::random_in(&dir).expect("a witness");
            assert_ne!(one.nonce_hex(), two.nonce_hex());
        }
    }

    #[test]
    fn an_artifact_is_confirmed_by_the_runs_nonce_alone() {
        let dir = witness_dir("confirm");
        let witness = RunWitness::derived_in(["confirm"], &dir).expect("a witness");
        let own = witness.nonce_hex().to_owned();
        let other = "00".repeat(crate::elf::RUN_WITNESS_BYTES);
        assert_ne!(own, other);

        assert_eq!(witness.confirm(&facts_carrying(&[&own])), Ok(()));
        assert_eq!(
            witness.confirm(&facts_carrying(&[])),
            Err(WitnessAbsence::Missing)
        );
        // An object of IR alone: no note, and the absence says the IR is why.
        let mut ir = facts_carrying(&[]);
        ir.sections = vec![
            ".text".to_owned(),
            format!("{}decls.0", crate::report::LTO_IR_SECTION_PREFIX),
        ];
        assert_eq!(witness.confirm(&ir), Err(WitnessAbsence::MissingFromIr));
        ir.run_witness = vec![own.clone()];
        assert_eq!(witness.confirm(&ir), Ok(()));
        let from_ir = WitnessAbsence::MissingFromIr.to_string();
        assert!(
            from_ir.contains("carries no run witness") && from_ir.contains("compiler IR"),
            "{from_ir}"
        );
        assert_eq!(
            witness.confirm(&facts_carrying(&[&other])),
            Err(WitnessAbsence::Foreign(vec![other.clone()]))
        );
        assert_eq!(
            witness.confirm(&facts_carrying(&[&own, &other])),
            Err(WitnessAbsence::Foreign(vec![own.clone(), other.clone()]))
        );
        // Upper case is another spelling the reader never writes, so it is not the nonce.
        if own.to_uppercase() != own {
            assert!(
                witness
                    .confirm(&facts_carrying(&[&own.to_uppercase()]))
                    .is_err()
            );
        }

        let missing = WitnessAbsence::Missing.to_string();
        assert!(missing.contains("carries no run witness"), "{missing}");
        assert!(
            missing.contains(crate::elf::RUN_WITNESS_SECTION),
            "{missing}"
        );
        let foreign = WitnessAbsence::Foreign(vec![other.clone()]).to_string();
        assert!(
            foreign.contains(&other) && foreign.contains("did not write"),
            "{foreign}"
        );
        let mixed = WitnessAbsence::Foreign(vec![own.clone(), other.clone()]).to_string();
        assert!(
            mixed.contains("2 run witnesses") && mixed.contains(&own) && mixed.contains(&other),
            "{mixed}"
        );
        assert!(!mixed.contains("at least"), "{mixed}");
        // A list read from note segments has no section to name, so neither form names one.
        for reason in [&foreign, &mixed] {
            assert!(
                !reason.contains(crate::elf::RUN_WITNESS_SECTION),
                "{reason}"
            );
        }
        // A list at the reader's cap may stand for more values than it holds.
        let capped: Vec<String> = (0..crate::elf::RUN_WITNESSES_KEPT)
            .map(|i| format!("{i:032x}"))
            .collect();
        let capped = WitnessAbsence::Foreign(capped).to_string();
        assert!(
            capped.contains(&format!(
                "at least {} run witnesses",
                crate::elf::RUN_WITNESSES_KEPT
            )),
            "{capped}"
        );
    }

    /// A question in literals, for
    /// [`a_derived_nonce_moves_with_every_field_of_the_question`]'s rows.
    #[derive(Clone, Copy)]
    struct Asked {
        c: &'static [&'static str],
        cxx: &'static [&'static str],
        ld: &'static [&'static str],
        env: &'static [(&'static str, &'static str)],
        driver: &'static str,
        version: Option<&'static str>,
        triple: Option<&'static str>,
        corpus: &'static str,
    }

    const ASKED: Asked = Asked {
        c: &["-O2"],
        cxx: &[],
        ld: &["-pie"],
        env: &[("A", "1")],
        driver: "/usr/bin/cc",
        version: Some("cc 1.0"),
        triple: Some("x86_64-linux-gnu"),
        corpus: "00",
    };

    /// The nonce derived from `asked`, with its header written under `dir`.
    fn derived_nonce(asked: Asked, dir: &Path) -> String {
        let words =
            |list: &[&str]| -> Vec<String> { list.iter().map(|w| (*w).to_owned()).collect() };
        let (cflags, cxxflags, ldflags) = (words(asked.c), words(asked.cxx), words(asked.ld));
        let question = WitnessQuestion {
            cflags: &cflags,
            cxxflags: &cxxflags,
            ldflags: &ldflags,
            env: asked.env.to_vec(),
            driver: asked.driver,
            version_raw: asked.version,
            target_triple: asked.triple,
            probe_corpus_sha256: asked.corpus,
        };
        RunWitness::derived_in(question.lines(), dir)
            .expect("a witness")
            .nonce_hex()
            .to_owned()
    }

    /// [`ASKED`] with one field moved, by what moved.
    #[rustfmt::skip]
    const MOVED: [(&str, Asked); 12] = [
        ("cflags", Asked { c: &["-O1"], ..ASKED }),
        ("cxxflags", Asked { cxx: &["-O2"], ..ASKED }),
        ("ldflags", Asked { ld: &[], ..ASKED }),
        ("a flag moved between lists", Asked { c: &[], cxx: &["-O2"], ..ASKED }),
        ("an env value", Asked { env: &[("A", "2")], ..ASKED }),
        ("an env name", Asked { env: &[("B", "1")], ..ASKED }),
        ("no env pair", Asked { env: &[], ..ASKED }),
        ("driver", Asked { driver: "/usr/bin/gcc", ..ASKED }),
        ("version_raw", Asked { version: Some("cc 1.1"), ..ASKED }),
        ("no version_raw", Asked { version: None, ..ASKED }),
        ("target_triple", Asked { triple: Some("aarch64-linux-gnu"), ..ASKED }),
        ("probe corpus", Asked { corpus: "01", ..ASKED }),
    ];

    #[test]
    fn a_derived_nonce_moves_with_every_field_of_the_question() {
        let dir = witness_dir("question");
        let asked = derived_nonce(ASKED, &dir);
        assert_eq!(derived_nonce(ASKED, &dir), asked);
        let mut seen = vec![asked];
        for (what, question) in MOVED {
            let other = derived_nonce(question, &dir);
            assert!(
                !seen.contains(&other),
                "{what} does not move the derived nonce"
            );
            seen.push(other);
        }
        // Two words of one list and one word holding both are two questions.
        let split = Asked {
            c: &["-O2", "-g"],
            ..ASKED
        };
        let joined = Asked {
            c: &["-O2 -g"],
            ..ASKED
        };
        assert_ne!(derived_nonce(split, &dir), derived_nonce(joined, &dir));
    }

    #[cfg(unix)]
    #[test]
    fn the_header_is_written_fresh_and_never_through_a_link() {
        let dir = witness_dir("fresh");
        let elsewhere = dir.join("elsewhere.h");
        std::fs::write(&elsewhere, "untouched\n").expect("a file to point at");
        let name = dir.join(RUN_WITNESS_HEADER_NAME);
        std::os::unix::fs::symlink(&elsewhere, &name).expect("a link at the header's name");
        let witness = RunWitness::derived_in(["fresh"], &dir).expect("a witness");
        assert_eq!(
            std::fs::read_to_string(&elsewhere).expect("the pointed-at file"),
            "untouched\n",
            "the header was written through the link"
        );
        let meta = std::fs::symlink_metadata(&name).expect("the header");
        assert!(
            meta.file_type().is_file(),
            "the header's name is still a link"
        );
        assert_eq!(
            std::fs::read_to_string(&name).expect("the header"),
            witness.header()
        );
        // An earlier run's header at the name is replaced, not kept.
        let again = RunWitness::derived_in(["another question"], &dir).expect("a witness");
        assert_eq!(
            std::fs::read_to_string(&name).expect("the header"),
            again.header()
        );
        assert_ne!(again.nonce_hex(), witness.nonce_hex());
    }

    #[test]
    fn an_absence_blames_a_cache_only_where_nothing_else_explains_it() {
        let foreign = WitnessAbsence::Foreign(vec!["ab".repeat(crate::elf::RUN_WITNESS_BYTES)]);
        for blamed in [&WitnessAbsence::Missing, &foreign] {
            assert!(blamed.cause().contains("compiler cache"), "{blamed}");
        }
        for explained in [WitnessAbsence::MissingFromIr, WitnessAbsence::Bitcode] {
            assert_eq!(explained.cause(), "", "{explained}");
            let said = explained.to_string();
            assert!(
                said.contains("compiler IR") && !said.contains("cache"),
                "{said}"
            );
        }
        let unread = WitnessAbsence::Unread("x: not an ELF file".to_owned());
        assert!(
            !unread.cause().contains("compiler cache"),
            "{}",
            unread.cause()
        );
        assert!(unread.to_string().contains("not an ELF file"));
        let library = WitnessAbsence::Library {
            name: "liba.so".to_owned(),
            absence: Box::new(WitnessAbsence::Missing),
        };
        assert_eq!(library.cause(), WitnessAbsence::Missing.cause());
        assert!(library.to_string().contains("`liba.so`"), "{library}");
        assert_eq!(BITCODE_MAGIC, *b"BC\xc0\xde");
    }

    /// Its sentence quotes each `.comment` line and the compiler the report names, and its
    /// cause names a prefix or a wrapper. Every other absence keeps the witness's rule, and a
    /// library takes its absence's rule.
    #[test]
    fn an_object_another_compiler_built_is_held_under_its_own_rule() {
        use crate::report::gating_rule::{ARTIFACT_OTHER_COMPILER, ARTIFACT_UNWITNESSED};
        let other = WitnessAbsence::OtherCompiler {
            lines: vec![
                "GCC: (GNU) 16.2.1 20261029 (Red Hat 16.2.1-3)".to_owned(),
                "GCC: (GNU) 15.2.1".to_owned(),
            ],
            named: "clang 22.1.8".to_owned(),
            witnessed: true,
        };
        assert_eq!(other.rule(), ARTIFACT_OTHER_COMPILER);
        assert_eq!(other.unshown(), "the compiler the report names built it");
        let said = other.to_string();
        assert!(
            said.contains("carries this run's witness, and its `.comment` names another compiler")
                && said.contains(
                    "(`GCC: (GNU) 16.2.1 20261029 (Red Hat 16.2.1-3)`, `GCC: (GNU) 15.2.1`, \
                     where `toolchain` is clang 22.1.8)"
                ),
            "{said}"
        );
        assert!(
            other.cause().contains("prefix command or a wrapper"),
            "{}",
            other.cause()
        );
        for kept in [
            WitnessAbsence::Missing,
            WitnessAbsence::MissingFromIr,
            WitnessAbsence::Foreign(vec!["ab".repeat(crate::elf::RUN_WITNESS_BYTES)]),
            WitnessAbsence::Unread("x: not an ELF file".to_owned()),
            WitnessAbsence::Bitcode,
        ] {
            assert_eq!(kept.rule(), ARTIFACT_UNWITNESSED, "{kept}");
            assert_eq!(kept.unshown(), "this run built it", "{kept}");
        }
        // A run with no witness holds the object all the same, and claims no witness.
        let unwitnessed = WitnessAbsence::OtherCompiler {
            lines: vec!["GCC: (GNU) 15.2.0".to_owned()],
            named: "clang 21.0.0".to_owned(),
            witnessed: false,
        };
        let said = unwitnessed.to_string();
        assert!(
            said.starts_with("is a relocatable object, and its `.comment` names another")
                && !said.contains("witness"),
            "{said}"
        );
        assert_eq!(unwitnessed.rule(), ARTIFACT_OTHER_COMPILER);
        let library = WitnessAbsence::Library {
            name: "liba.so".to_owned(),
            absence: Box::new(other.clone()),
        };
        assert_eq!(library.rule(), other.rule());
        assert_eq!(library.unshown(), other.unshown());
    }

    /// A build handed a witness names the header on its recorded command line, after its
    /// flags and before `-o`; a build handed none names nothing.
    #[test]
    fn a_build_names_the_witness_header_after_its_flags() {
        let dir = witness_dir("argv");
        let driver = test_script(&dir.join("cc"), "exit 0\n");
        let source = dir.join("probe.c");
        std::fs::write(&source, "int main(void){return 0;}\n").expect("a source");
        let out = dir.join("probe");
        let witness = RunWitness::derived_in(["argv"], &dir).expect("a witness");
        let flags = ["-O2".to_owned(), "-include".to_owned(), "own.h".to_owned()];

        let with =
            build(&driver, &flags, &source, &out, &["-lm"], Some(&witness)).expect("a record");
        let words: Vec<&str> = with.argv.iter().skip(1).map(String::as_str).collect();
        assert_eq!(
            words,
            [
                "-O2",
                "-include",
                "own.h",
                "-include",
                RUN_WITNESS_HEADER_NAME,
                "-o",
                out.to_str().expect("a UTF-8 path"),
                "probe.c",
                "-lm"
            ]
        );
        let without = build(&driver, &flags, &source, &out, &[], None).expect("a record");
        assert!(
            !without.argv.iter().any(|w| w == RUN_WITNESS_HEADER_NAME),
            "{:?}",
            without.argv
        );
    }
}
