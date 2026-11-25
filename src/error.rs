// SPDX-License-Identifier: BSD-3-Clause

//! Classified error envelope.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use crate::elf::ElfError;

pub const EXIT_OK: u8 = 0;
/// A gate tripped, and the document is written: `measure --fail-on-missing` over a check
/// that did not settle, that `--allow` did not excuse, where [`EXIT_MACHINE_LIMIT`] does not
/// apply, or `detect` over a report
/// that disagrees with its replay. Both are a finding about the input, not a fault in chard.
pub const EXIT_GATE: u8 = 1;
pub const EXIT_FAILURE: u8 = 2;
/// chard contradicted itself: `measure` built a report that disagrees with itself and did
/// not publish it where a consumer could read it (never opt-in: a self-contradicting report
/// has no valid use), so [`emit_contradiction`] writes an `INTERNAL` envelope naming the
/// quarantine file. Nothing else exits 3, `detect`'s disagreement included: a caller routing 3
/// to a chard bug report would otherwise file one for every report that failed its replay.
pub const EXIT_CONTRADICTION: u8 = 3;
/// `measure --fail-on-missing` tripped, as for [`EXIT_GATE`], and every shortfall is a machine
/// limit or a target limit, at least one a machine limit. A machine limit is a check the
/// kernel and CPU the run had cannot answer (a gating rule of `MACHINE_LIMITS` in `main.rs`).
/// A target limit is a check chard does not read on the target (`TARGET_LIMITS`). A rerun on a
/// machine that gives every feature the machine limits name withholds the target limits again,
/// so it still exits [`EXIT_GATE`] while a target limit that `--allow` does not excuse stands.
/// No allowance moves this status: it is decided over every shortfall, the excused ones with
/// the rest. The report is written as for [`EXIT_GATE`].
pub const EXIT_MACHINE_LIMIT: u8 = 4;

/// Errno for a program the kernel has no loader for: a `+x` text file with no shebang.
/// `std` maps it to no [`std::io::ErrorKind`], so it is read from the raw value, which is
/// 8 on Linux and on Darwin alike.
const ENOEXEC: i32 = 8;

/// Errno for a path that loops through its own symbolic links. `std` maps it to
/// `ErrorKind::FilesystemLoop`, which is unstable at the crate's `rust-version`, so it is
/// read from the raw value: 40 on Linux, 62 on Darwin and the BSDs. The unit table checks
/// the constant against the kind `std` decodes it to on the host running the tests.
#[cfg(target_os = "linux")]
const ELOOP: i32 = 40;
#[cfg(not(target_os = "linux"))]
const ELOOP: i32 = 62;

/// Error classes for a caller (human or agent) deciding what to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Bad input from the caller: missing compiler, unreadable path, unknown
    /// probe id. Fix the call and retry.
    UserInput,
    /// EACCES/EPERM writing the work directory or executing a probe.
    Permission,
    /// Interrupted I/O, EAGAIN, a probe that timed out for environmental
    /// reasons. Safe to retry.
    Transient,
    /// Conflicting flags or an unusable profile (e.g. `--profile explicit` with no
    /// `--flags`, or an `--image-attestation` for a run that booted no image).
    Configuration,
    /// Anything unrecognized. These are bugs in chard.
    Internal,
}

impl ErrorClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::UserInput => "USER_INPUT",
            Self::Permission => "PERMISSION",
            Self::Transient => "TRANSIENT",
            Self::Configuration => "CONFIGURATION",
            Self::Internal => "INTERNAL",
        }
    }
}

/// Typed marker for operator-supplied configuration that cannot be honored.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Typed marker for a caller mistake: unknown probe id, missing compiler,
/// unreadable path.
#[derive(Debug)]
pub struct UserError {
    pub message: String,
    pub hint: Option<String>,
}

impl UserError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: Some(hint.into()),
        }
    }
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UserError {}

/// Typed marker for a path the caller named that chard may not write, with the hint
/// that says what to change.
#[derive(Debug)]
pub struct PermissionError {
    pub message: String,
    pub hint: String,
}

impl std::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PermissionError {}

/// Typed marker for a failure worth retrying as it stands, decided on grounds no errno
/// carries: `measure::claim_workdir` builds one for a work directory a live run holds, and
/// `measure::WorkdirClaim::confirm` for a run whose claim was removed under it. The
/// driver-interrogation timeout stays untyped, since a driver that hangs on `--version`
/// hangs again.
#[derive(Debug)]
pub struct TransientError(pub String);

impl std::fmt::Display for TransientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransientError {}

/// Context tag for io on a path chard constructed: work-directory contents, probe
/// artifacts, macro-dump sources, capture files.
#[derive(Debug)]
pub struct HarnessPath(pub PathBuf);

impl std::fmt::Display for HarnessPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// `chard_schema` in the envelope: the major version of `schema/chard-error.schema.json`,
/// under the rule the CLI's contract states.
pub const SCHEMA_VERSION: &str = "1";

#[derive(Serialize)]
struct Envelope<'a> {
    chard_schema: &'static str,
    error: Body<'a>,
}

#[derive(Serialize)]
struct Body<'a> {
    code: &'static str,
    operation: &'a str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// The ordered decision the module doc tabulates.
pub(crate) fn classify(err: &anyhow::Error) -> (ErrorClass, Option<String>) {
    if let Some(user) = err.downcast_ref::<UserError>() {
        return (ErrorClass::UserInput, user.hint.clone());
    }
    if let Some(denied) = err.downcast_ref::<PermissionError>() {
        return (ErrorClass::Permission, Some(denied.hint.clone()));
    }
    if err.downcast_ref::<ConfigError>().is_some() {
        return (ErrorClass::Configuration, None);
    }
    if err.downcast_ref::<TransientError>().is_some() {
        return (ErrorClass::Transient, None);
    }
    if let Some(elf) = err.downcast_ref::<ElfError>() {
        return classify_elf(elf);
    }
    if let Some(io) = err.downcast_ref::<std::io::Error>() {
        let harness = err.downcast_ref::<HarnessPath>().map(|tag| tag.0.as_path());
        return classify_io(io, harness);
    }
    (ErrorClass::Internal, None)
}

/// Would the same call, made again, plausibly succeed?
pub fn is_transient(err: &anyhow::Error) -> bool {
    classify(err).0 == ErrorClass::Transient
}

/// The object `chard elf` or the measurement loop could not read.
fn classify_elf(elf: &ElfError) -> (ErrorClass, Option<String>) {
    let named = elf
        .path()
        .map_or_else(|| "the file".to_owned(), |p| p.display().to_string());
    match elf {
        ElfError::Io { source, .. } => classify_io(source, None),
        ElfError::NotElf { .. } | ElfError::MachO { .. } => (
            ErrorClass::UserInput,
            Some(format!(
                "`chard elf` reads ELF objects, and {named} is not one"
            )),
        ),
        ElfError::TooLarge { cap, .. } => (
            ErrorClass::UserInput,
            Some(format!(
                "`chard elf` refuses an object above {cap} bytes before reading it"
            )),
        ),
        ElfError::Malformed { .. } | ElfError::Truncated { .. } => (
            ErrorClass::UserInput,
            Some(format!("{named} is malformed or truncated")),
        ),
    }
}

/// An io failure, read with the owner of the path it happened on.
fn classify_io(io: &std::io::Error, harness: Option<&Path>) -> (ErrorClass, Option<String>) {
    use std::io::ErrorKind as Kind;
    match (io.kind(), harness) {
        // One hint for both operations a chard-owned path meets, a write and a run: a
        // `noexec` mount returns `EACCES` at the probe artifact's spawn.
        (Kind::PermissionDenied, Some(path)) => (
            ErrorClass::Permission,
            Some(format!("chard could not write or run {}", path.display())),
        ),
        (Kind::PermissionDenied, None) => (ErrorClass::Permission, None),
        (Kind::ReadOnlyFilesystem | Kind::StorageFull, harness) => (
            ErrorClass::Permission,
            harness.map(|path| {
                format!(
                    "chard could not write {}; the filesystem is read-only or full",
                    path.display()
                )
            }),
        ),
        (Kind::Interrupted | Kind::WouldBlock | Kind::ExecutableFileBusy, _) => {
            (ErrorClass::Transient, None)
        }
        (Kind::NotFound, Some(path)) => (
            ErrorClass::Internal,
            Some(format!(
                "the work directory was removed while chard ran (it lost {})",
                path.display()
            )),
        ),
        // Op-neutral on purpose: the same arm serves a file `elf` could not open, an
        // `--output` whose directory does not exist and a `--cc` script whose shebang
        // names an interpreter that does not exist, and `classify_io` cannot see which.
        (Kind::NotFound, None) => (
            ErrorClass::UserInput,
            Some("check that the path, every directory in it".to_owned()),
        ),
        (Kind::IsADirectory, None) => (
            ErrorClass::UserInput,
            Some("the path names a directory; name a regular file".to_owned()),
        ),
        (Kind::NotADirectory, None) => (
            ErrorClass::UserInput,
            Some("a directory in the path is a regular file; check the path".to_owned()),
        ),
        (Kind::AlreadyExists, None) => (
            ErrorClass::UserInput,
            Some("the path exists and is not a directory; name a directory".to_owned()),
        ),
        (Kind::InvalidFilename, None) => (
            ErrorClass::UserInput,
            Some("the path is too long or malformed for this filesystem".to_owned()),
        ),
        (_, None) if io.raw_os_error() == Some(ELOOP) => (
            ErrorClass::UserInput,
            Some("the path loops through its own symbolic links; resolve it".to_owned()),
        ),
        (_, None) if io.raw_os_error() == Some(ENOEXEC) => (
            ErrorClass::UserInput,
            Some("the program must be an executable this system can run".to_owned()),
        ),
        _ => (ErrorClass::Internal, None),
    }
}

/// Print the envelope on stdout and return the process exit code. The only path
/// by which an error leaves chard. A stdout that refuses the envelope for any reason
/// but a closed pipe gets it on stderr instead.
pub fn emit(operation: &str, err: &anyhow::Error) -> ExitCode {
    let (class, hint) = classify(err);
    // anyhow's chain carries the context breadcrumbs; join them so the envelope
    // says which stage failed rather than only the innermost cause.
    let message = err
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    write_envelope(&Envelope {
        chard_schema: SCHEMA_VERSION,
        error: Body {
            code: class.as_str(),
            operation,
            message,
            hint,
        },
    });
    ExitCode::from(EXIT_FAILURE)
}

/// `measure`'s refusal to publish a report that contradicts itself in `contradictions`
/// places: an `INTERNAL` envelope, since the fault is chard's, naming where the report was
/// quarantined (`report::publish`), and exit [`EXIT_CONTRADICTION`]. The `CONTRADICTION`
/// and `REFUSED` notes `publish` wrote to stderr stay; this is what a caller reading stdout
/// gets in their place, so stdout is never empty.
pub fn emit_contradiction(contradictions: usize, quarantine: Option<&Path>) -> ExitCode {
    write_rendered(&contradiction_envelope(contradictions, quarantine));
    ExitCode::from(EXIT_CONTRADICTION)
}

/// The envelope [`emit_contradiction`] writes, rendered: public so a test holds it to
/// `schema/chard-error.schema.json`, since no end-to-end run reaches a contradiction short of
/// a defect in chard (`report::publish`'s tests make one).
#[must_use]
pub fn contradiction_envelope(contradictions: usize, quarantine: Option<&Path>) -> String {
    render(&Envelope {
        chard_schema: SCHEMA_VERSION,
        error: Body {
            code: ErrorClass::Internal.as_str(),
            operation: "measure",
            message: contradiction_message(contradictions),
            hint: Some(contradiction_hint(quarantine)),
        },
    })
}

/// `measure`'s refusal of a report whose one contradiction is the operator's: the
/// `--execution` they declared, contradicted by what chard observed
/// (`report::RefusalCause::DeclaredExecution`). A `CONFIGURATION` envelope and exit
/// [`EXIT_FAILURE`], as any refused invocation: the operator acts, by declaring the mode the
/// run is in or none, and nothing is chard's to report. The report is kept beside `-o` as for
/// [`emit_contradiction`], and never published.
pub fn emit_declaration_contradicted(
    execution: &crate::env::Execution,
    quarantine: Option<&Path>,
) -> ExitCode {
    // The rule fires only beside an observation; "nothing" would be a defect in the rule.
    let observed = execution
        .mode_evidence
        .observed
        .map_or("nothing", crate::env::ExecutionMode::as_str);
    let kept = quarantine.map_or_else(
        || "re-run with -o naming a regular file to keep the report".to_owned(),
        |path| format!("the report is kept as {}", path.display()),
    );
    write_envelope(&Envelope {
        chard_schema: SCHEMA_VERSION,
        error: Body {
            code: ErrorClass::Configuration.as_str(),
            operation: "measure",
            message: format!(
                "--execution {} was declared and chard observed {observed} ({})",
                execution.mode.as_str(),
                execution.mode_evidence.observation
            ),
            hint: Some(format!(
                "declare the execution mode the run is in, or omit --execution; {kept}"
            )),
        },
    });
    ExitCode::from(EXIT_FAILURE)
}

fn contradiction_message(contradictions: usize) -> String {
    format!("the report contradicts itself in {contradictions} place(s) and was not published")
}

fn contradiction_hint(quarantine: Option<&Path>) -> String {
    quarantine.map_or_else(
        || {
            "re-run with -o naming a regular file FILE to keep the report as FILE.contradicted"
                .to_owned()
        },
        |path| {
            format!(
                "the report is kept as {}; attach it to a bug report",
                path.display()
            )
        },
    )
}

fn render(envelope: &Envelope<'_>) -> String {
    serde_json::to_string_pretty(envelope).unwrap_or_else(|_| {
        format!(
            r#"{{"chard_schema":"{SCHEMA_VERSION}","error":{{"code":"INTERNAL","operation":{},"message":"failed to serialize error"}}}}"#,
            // `Value`'s `Display` writes a JSON string and cannot fail.
            serde_json::Value::from(envelope.error.operation)
        )
    })
}

/// Write `envelope` to stdout, or to stderr where stdout refuses it.
fn write_envelope(envelope: &Envelope<'_>) {
    write_rendered(&render(envelope));
}

fn write_rendered(rendered: &str) {
    let mut out = std::io::stdout().lock();
    match writeln!(out, "{rendered}").and_then(|()| out.flush()) {
        // A reader that closed the pipe has left; the exit status is the signal.
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
        // Stdout is there and refuses (`> /dev/full`): the envelope goes where progress
        // goes, so the failure is not reported by its exit status alone.
        Err(err) => note(&format!(
            "the error envelope could not be written to stdout ({err}):\n{rendered}"
        )),
        Ok(()) => {}
    }
}

/// Deliberately discard a fallible result.
pub fn best_effort<T, E>(_result: Result<T, E>) {}

/// Progress and warnings. Never stdout: that is the document's alone, where it goes there.
pub fn note(message: &str) {
    let mut err = std::io::stderr().lock();
    best_effort(writeln!(err, "chard: {message}"));
}

/// What a path a command refused from its metadata is, for the refusal to name.
#[must_use]
pub fn file_type_name(kind: std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt as _;
    if kind.is_dir() {
        "a directory"
    } else if kind.is_fifo() {
        "a FIFO"
    } else if kind.is_char_device() || kind.is_block_device() {
        "a device"
    } else if kind.is_socket() {
        "a socket"
    } else {
        "of an unknown type"
    }
}

/// Announce, from a unit test, an arm the host could not exercise.
#[cfg(test)]
pub(crate) fn capability_gap(arm: &str, why: &str) {
    let banner = format!("\nchard: arm not exercised — {arm}: {why}\n");
    let mut err = std::io::stderr().lock();
    best_effort(err.write_all(banner.as_bytes()));
    best_effort(err.flush());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    fn io(kind: ErrorKind) -> anyhow::Error {
        anyhow::Error::new(Error::new(kind, "x"))
    }

    /// The same io error, one link under a [`HarnessPath`] and a human message: the shape
    /// every tagged site produces.
    fn harness_io(kind: ErrorKind, path: &str) -> anyhow::Error {
        io(kind)
            .context(HarnessPath(PathBuf::from(path)))
            .context("writing the self-report header")
    }

    #[test]
    fn a_permission_error_carries_its_hint() {
        let denied = || PermissionError {
            message: "chard cannot write the output /ro/out.json".to_owned(),
            hint: "give -o a path in a directory this user can write".to_owned(),
        };
        let bare = anyhow::Error::new(denied());
        let wrapped = io(ErrorKind::NotFound)
            .context(denied())
            .context("checking the output");
        for err in [&bare, &wrapped] {
            let (class, hint) = classify(err);
            assert_eq!(class, ErrorClass::Permission, "{err:#}");
            assert_eq!(
                hint.as_deref(),
                Some("give -o a path in a directory this user can write"),
                "{err:#}"
            );
        }
        assert_eq!(classify(&io(ErrorKind::PermissionDenied)).1, None);
    }

    #[test]
    fn every_io_kind_is_classified_by_its_kind_and_its_owner() {
        use ErrorClass::{Internal, Permission, Transient, UserInput};
        let table = [
            (ErrorKind::PermissionDenied, Permission, Permission),
            (ErrorKind::ReadOnlyFilesystem, Permission, Permission),
            (ErrorKind::StorageFull, Permission, Permission),
            (ErrorKind::NotFound, UserInput, Internal),
            (ErrorKind::Interrupted, Transient, Transient),
            (ErrorKind::WouldBlock, Transient, Transient),
            (ErrorKind::ExecutableFileBusy, Transient, Transient),
            (ErrorKind::IsADirectory, UserInput, Internal),
            (ErrorKind::NotADirectory, UserInput, Internal),
            (ErrorKind::AlreadyExists, UserInput, Internal),
            (ErrorKind::InvalidFilename, UserInput, Internal),
            // Considered and left in the default arm: no site produces either on a path
            // it owns, as the module doc says.
            (ErrorKind::InvalidInput, Internal, Internal),
            (ErrorKind::InvalidData, Internal, Internal),
            (ErrorKind::Other, Internal, Internal),
        ];
        for (kind, on_caller_path, on_harness_path) in table {
            assert_eq!(
                classify(&io(kind)).0,
                on_caller_path,
                "{kind:?} on a path the caller typed"
            );
            assert_eq!(
                classify(&harness_io(kind, "/w/chard_selfreport.h")).0,
                on_harness_path,
                "{kind:?} on a path chard constructed"
            );
        }

        // The two errnos read raw.
        let eloop = Error::from_raw_os_error(ELOOP);
        assert_eq!(format!("{:?}", eloop.kind()), "FilesystemLoop");
        assert_eq!(classify(&anyhow::Error::new(eloop)).0, UserInput);
        assert_eq!(
            classify(
                &anyhow::Error::new(Error::from_raw_os_error(ELOOP))
                    .context(HarnessPath(PathBuf::from("/w/probe")))
            )
            .0,
            Internal
        );
        assert_eq!(
            classify(&anyhow::Error::new(Error::from_raw_os_error(ENOEXEC))).0,
            UserInput
        );

        let (_, hint) = classify(&io(ErrorKind::NotFound));
        assert!(
            hint.is_some_and(|h| h.contains("path")),
            "the caller-path hint is what makes the class actionable"
        );

        // The names are the published contract, so they are spelled out here: a constant
        // would rename them everywhere at once and agree with itself while doing it.
        assert_eq!(UserInput.as_str(), "USER_INPUT");
        assert_eq!(Permission.as_str(), "PERMISSION");
        assert_eq!(Transient.as_str(), "TRANSIENT");
        assert_eq!(ErrorClass::Configuration.as_str(), "CONFIGURATION");
        assert_eq!(Internal.as_str(), "INTERNAL");
    }

    /// The rows of [`the_default_arm_catches_only_the_inventoried_internal_sites`] for the
    /// reader's refusals of the bytes, each `USER_INPUT`.
    fn elf_refusal_rows() -> Vec<(&'static str, anyhow::Error, ErrorClass)> {
        use ErrorClass::UserInput;
        vec![
            (
                "ElfError::NotElf",
                ElfError::NotElf {
                    path: Some(PathBuf::from("/etc/hosts")),
                    why: "not an ELF file".to_owned(),
                }
                .into(),
                UserInput,
            ),
            (
                "ElfError::MachO",
                ElfError::MachO {
                    path: Some(PathBuf::from("/objects/x")),
                }
                .into(),
                UserInput,
            ),
            (
                "ElfError::Malformed",
                ElfError::Malformed {
                    path: Some(PathBuf::from("/objects/x")),
                    what: "e_shentsize is 0".to_owned(),
                }
                .into(),
                UserInput,
            ),
            (
                "ElfError::Truncated",
                ElfError::Truncated {
                    path: Some(PathBuf::from("/objects/x")),
                    read: crate::elf::ReadError::OutOfBounds {
                        start: 40,
                        count: 8,
                    },
                }
                .into(),
                UserInput,
            ),
            (
                "ElfError::TooLarge",
                ElfError::TooLarge {
                    path: PathBuf::from("/objects/x"),
                    size: Some(1),
                    cap: 0,
                }
                .into(),
                UserInput,
            ),
        ]
    }

    #[test]
    fn the_default_arm_catches_only_the_inventoried_internal_sites() {
        use ErrorClass::{Configuration, Internal, Permission, Transient, UserInput};
        let elf_io = |kind: ErrorKind| ElfError::Io {
            path: PathBuf::from("/objects/x"),
            op: "reading",
            source: Error::new(kind, "x"),
        };
        let serde_failure = serde_json::from_str::<serde_json::Value>("{").expect_err("not JSON");
        let mut rows: Vec<(&str, anyhow::Error, ErrorClass)> = vec![
            (
                "UserError",
                UserError::with_hint("no compiler", "pass --cc").into(),
                UserInput,
            ),
            (
                "ConfigError",
                ConfigError("bad profile".to_owned()).into(),
                Configuration,
            ),
            (
                "TransientError",
                TransientError("worth retrying as it stands".to_owned()).into(),
                Transient,
            ),
            (
                "ElfError::Io NotFound",
                elf_io(ErrorKind::NotFound).into(),
                UserInput,
            ),
            (
                "ElfError::Io PermissionDenied",
                elf_io(ErrorKind::PermissionDenied).into(),
                Permission,
            ),
            (
                "ElfError::Io IsADirectory",
                elf_io(ErrorKind::IsADirectory).into(),
                UserInput,
            ),
            (
                "io ENOEXEC",
                anyhow::Error::new(Error::from_raw_os_error(ENOEXEC)),
                UserInput,
            ),
            (
                "io ENOEXEC under a HarnessPath",
                anyhow::Error::new(Error::from_raw_os_error(ENOEXEC))
                    .context(HarnessPath(PathBuf::from("/w/probe"))),
                Internal,
            ),
            ("serde_json::Error", serde_failure.into(), Internal),
            (
                "bare anyhow!",
                anyhow::anyhow!("something unanticipated"),
                Internal,
            ),
        ];
        rows.extend(elf_refusal_rows());
        assert_eq!(rows.len(), 15, "the table covers every constructor");
        for (name, err, expected) in rows {
            assert_eq!(classify(&err).0, expected, "{name}: {err:#}");
        }
    }

    #[test]
    fn user_error_classifies_as_user_input_and_keeps_its_hint() {
        let err = anyhow::Error::new(UserError::with_hint("no compiler", "pass --cc"));
        let (class, hint) = classify(&err);
        assert_eq!(class, ErrorClass::UserInput);
        assert_eq!(hint.as_deref(), Some("pass --cc"));
    }

    #[test]
    fn a_user_error_as_context_still_classifies_as_user_input() {
        let err = anyhow::Error::new(Error::new(ErrorKind::InvalidData, "expected value"))
            .context(UserError::with_hint("parsing r.json", "pass a report"));
        let (class, hint) = classify(&err);
        assert_eq!(class, ErrorClass::UserInput);
        assert_eq!(hint.as_deref(), Some("pass a report"));
        assert_eq!(format!("{err:#}"), "parsing r.json: expected value");
    }

    #[test]
    fn config_error_classifies_as_configuration() {
        let err = anyhow::Error::new(ConfigError("bad profile".to_owned()));
        assert_eq!(classify(&err).0, ErrorClass::Configuration);
    }

    #[test]
    fn permission_denied_io_classifies_as_permission() {
        let err = anyhow::Error::new(Error::from(ErrorKind::PermissionDenied));
        assert_eq!(classify(&err).0, ErrorClass::Permission);
    }

    #[test]
    fn a_missing_file_chard_created_is_chards_own_defect() {
        let err = harness_io(ErrorKind::NotFound, "/w/chard_selfreport.h");
        let (class, hint) = classify(&err);
        assert_eq!(class, ErrorClass::Internal);
        assert!(
            hint.as_deref()
                .is_some_and(|h| h.contains("/w/chard_selfreport.h")),
            "{hint:?}"
        );
        assert_eq!(
            format!("{err:#}"),
            "writing the self-report header: /w/chard_selfreport.h: x",
            "the tag renders as the path alone, so the chain reads as one sentence"
        );
    }

    #[test]
    fn a_permission_failure_on_a_chard_path_is_still_permission() {
        for path in ["/w/stack-canary-clean.stdout", "/w/stack-canary-clean"] {
            let err = harness_io(ErrorKind::PermissionDenied, path);
            let (class, hint) = classify(&err);
            assert_eq!(class, ErrorClass::Permission);
            assert!(
                hint.as_deref().is_some_and(|h| h.contains(path)),
                "{hint:?}"
            );
        }
    }

    #[test]
    fn executable_file_busy_is_transient_on_either_path() {
        assert_eq!(
            classify(&io(ErrorKind::ExecutableFileBusy)).0,
            ErrorClass::Transient
        );
        assert_eq!(
            classify(&harness_io(ErrorKind::ExecutableFileBusy, "/w/probe")).0,
            ErrorClass::Transient
        );
        assert!(is_transient(&io(ErrorKind::ExecutableFileBusy)));
        assert!(is_transient(&anyhow::Error::new(TransientError(
            "busy".to_owned()
        ))));
        assert!(!is_transient(&io(ErrorKind::NotFound)));
        assert!(
            !is_transient(&anyhow::Error::new(UserError::new("x"))),
            "a marker earlier in the order wins over any kind under it"
        );
    }

    #[test]
    fn an_elf_refusal_is_the_callers_object_and_names_the_cross_check() {
        let truncated = anyhow::Error::new(ElfError::Truncated {
            path: Some(PathBuf::from("/objects/cut")),
            read: crate::elf::ReadError::OutOfBounds {
                start: 40,
                count: 8,
            },
        });
        let (class, hint) = classify(&truncated);
        assert_eq!(class, ErrorClass::UserInput);
        assert!(
            hint.as_deref().is_some_and(|h| h.contains("/objects/cut")),
            "{hint:?}"
        );

        let text = anyhow::Error::new(ElfError::NotElf {
            path: Some(PathBuf::from("/etc/hosts")),
            why: "not an ELF file".to_owned(),
        });
        let (class, hint) = classify(&text);
        assert_eq!(class, ErrorClass::UserInput);
        assert!(
            hint.as_deref()
                .is_some_and(|h| h.contains("/etc/hosts") && h.contains("chard elf")),
            "{hint:?}"
        );

        let unreadable = anyhow::Error::new(ElfError::Io {
            path: PathBuf::from("/objects/locked"),
            op: "reading",
            source: Error::from(ErrorKind::PermissionDenied),
        });
        assert_eq!(classify(&unreadable).0, ErrorClass::Permission);
    }

    #[test]
    fn unknown_errors_are_internal_bugs_not_user_error() {
        let err = anyhow::anyhow!("something we did not anticipate");
        assert_eq!(classify(&err).0, ErrorClass::Internal);
    }
}
