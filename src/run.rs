// SPDX-License-Identifier: BSD-3-Clause

//! Executing a probe binary and recording how it died.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// How long to sleep between `try_wait` calls once a child has run long enough that
/// millisecond resolution describes it honestly. Long enough not to spin a core.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The finer interval, and how long it is used for.
const FINE_POLL_INTERVAL: Duration = Duration::from_micros(100);
const FINE_POLL_WINDOW: Duration = Duration::from_millis(10);

/// Sleep before the next `try_wait`, finely while the child is still young.
#[expect(clippy::disallowed_methods, reason = "the wait is on a child's exit")]
pub(crate) fn poll_sleep(elapsed: Duration) {
    if elapsed < FINE_POLL_WINDOW {
        std::thread::sleep(FINE_POLL_INTERVAL);
    } else {
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// How long [`kill_group`] waits for the shell it signals the group through. The shell's
/// `kill` is a builtin and returns at once; this bounds a shell that does not.
const KILL_BOUND: Duration = Duration::from_secs(5);

/// The shell [`kill_group`] runs, by absolute path, so `PATH` does not choose it.
const KILL_SHELL: &str = "/bin/sh";

/// Kill the process group `child` leads, `child` with it, after a timeout and before `child`
/// is reaped.
pub(crate) fn kill_group(child: &mut Child) {
    kill_group_through(child, KILL_SHELL);
}

/// [`kill_group`] through the shell `shell`, so a test can name one that cannot run.
fn kill_group_through(child: &mut Child, shell: &str) {
    let pid = child.id();
    if let Some(group) = group_operand(pid)
        && let Err(err) = signal_group(shell, &group)
    {
        crate::error::note(&format!(
            "the process group of timed-out child {pid} could not be killed ({err})"
        ));
    }
    crate::error::best_effort(child.kill());
}

/// The operand `kill` names the group `pid` leads by, `-<pid>`; none for a pid of 0 or 1,
/// which as a group operand would name the caller's own group or every process.
fn group_operand(pid: u32) -> Option<String> {
    (pid > 1).then(|| format!("-{pid}"))
}

/// [`kill_group`]'s shell, `shell`: `kill -KILL <group>`, waited for under [`KILL_BOUND`] and
/// killed past it. An error where the shell cannot be spawned, outlives the bound, or exits
/// other than 0, as `kill` does where it signalled nothing.
fn signal_group(shell: &str, group: &str) -> std::io::Result<()> {
    let started = Instant::now();
    let mut killer = Command::new(shell)
        .args(["-c", "kill -KILL \"$1\"", "sh", group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()?;
    let status = loop {
        if let Some(status) = killer.try_wait()? {
            break status;
        }
        if started.elapsed() >= KILL_BOUND {
            crate::error::best_effort(killer.kill());
            crate::error::best_effort(killer.wait());
            return Err(std::io::Error::other(format!(
                "{shell} did not finish within {KILL_BOUND:?}"
            )));
        }
        poll_sleep(started.elapsed());
    };
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{shell}'s kill ended with {status}"
        )))
    }
}

/// Whether process `pid` has ended within `grace`, read by `kill -0` through `/bin/sh` every 20
/// ms: the tests of [`kill_group`]'s two callers read what a timeout left behind with it. A
/// zombie still answers `kill -0`, and a process whose parent was killed is reaped by the one
/// it is handed to, so `grace` covers that reap.
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "the condition is another process's end, which no handle here can wait on: the pid \
              is not this process's child, so `kill -0` between sleeps, under `grace`, is the \
              wait"
)]
pub(crate) fn gone_within(pid: u32, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        let alive = Command::new(KILL_SHELL)
            .args(["-c", "kill -0 \"$1\" 2>/dev/null", "sh", &pid.to_string()])
            .status()
            .expect("spawning /bin/sh to ask whether the process is alive")
            .success();
        if !alive {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The whole environment a probe runs under.
pub const PROBE_ENVIRONMENT: &[(&str, &str)] = &[("LC_ALL", "C"), ("LIBC_FATAL_STDERR_", "1")];

/// [`PROBE_ENVIRONMENT`] and the probe's own `pins`, as the map the record carries and the
/// child is given.
fn probe_environment(pins: &[(&str, &str)]) -> BTreeMap<String, String> {
    PROBE_ENVIRONMENT
        .iter()
        .chain(pins)
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// Cap on captured output. A probe that floods its stderr is itself a finding,
/// but the report must stay a report.
const MAX_CAPTURE: u64 = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub argv: Vec<String>,
    /// `-1` when the process did not exit normally; see `signal`.
    pub exit_status: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    /// Whether `deadline_ms` elapsed before chard saw the child exit.
    pub timed_out: bool,
    /// The deadline this run was held to, in whole milliseconds: `--timeout`, applied to
    /// each probe run on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u128>,
    /// Why an output stream could not be read, when one could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_error: Option<String>,
    /// Whether a stream hit `MAX_CAPTURE` and lost its tail.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(default)]
    pub output_truncated: bool,
    /// Whole milliseconds, so `0` means the probe finished in under a millisecond,
    /// not that it went untimed.
    pub duration_ms: u128,
    /// Every variable the probe received, with its value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
}

impl RunRecord {
    /// True when the process died by `SIGABRT`, the usual shape of a hardening
    /// check firing.
    pub fn aborted(&self) -> bool {
        self.signal.as_deref() == Some("SIGABRT")
    }

    /// True when the process hit a deliberate trap instruction.
    pub fn trapped(&self) -> bool {
        match self.fault() {
            Some(fault) => fault == Fault::CompilerTrap,
            None => matches!(self.signal.as_deref(), Some("SIGILL" | "SIGTRAP")),
        }
    }

    /// The fault report a probe built with `CHARD_WANT_FAULT_REPORT` wrote to stderr,
    /// when it wrote one about the signal this record says it died by.
    #[must_use]
    pub fn fault_report(&self) -> Option<FaultReport> {
        let line = self
            .stderr
            .lines()
            .rev()
            .find(|line| line.starts_with(FaultReport::PREFIX))?;
        let report = FaultReport::parse(line)?;
        (self.signal.as_deref() == Some(signal_name(report.signal).as_str())).then_some(report)
    }

    /// What killed the probe, from its own fault report; `None` without one that
    /// describes the recorded death.
    #[must_use]
    pub fn fault(&self) -> Option<Fault> {
        self.fault_report().map(|report| report.classify())
    }

    /// True when the process ran to completion with status 0.
    pub fn exited_cleanly(&self) -> bool {
        self.signal.is_none() && self.exit_status == 0
    }

    /// Why this record's streams are not the whole of what the probe printed, in one
    /// sentence, or `None` when both were read whole.
    #[must_use]
    pub fn stream_cut(&self) -> Option<String> {
        let mut cuts: Vec<String> = Vec::new();
        if self.killed_at_deadline() {
            cuts.push(format!(
                "the {} and was killed before it finished writing",
                self.timeout_note()
            ));
        }
        if let Some(e) = self.output_error.as_deref() {
            cuts.push(format!("a stream could not be read ({e})"));
        }
        if self.output_truncated {
            cuts.push(format!(
                "a stream reached the {MAX_CAPTURE}-byte capture cap and lost its tail"
            ));
        }
        if cuts.is_empty() {
            return None;
        }
        Some(format!(
            "{}, so a marker absent from this run's output is chard's silence rather \
             than the probe's and the reading is withheld as unmeasured",
            cuts.join(" and ")
        ))
    }

    /// Whether chard's deadline is what ended this run: it timed out and the status is
    /// the `SIGKILL` [`execute`] sends, or no status at all (a `wait` that failed after
    /// the kill).
    #[must_use]
    pub fn killed_at_deadline(&self) -> bool {
        self.timed_out
            && match self.signal.as_deref() {
                Some(signal) => signal == "SIGKILL",
                None => self.exit_status == -1,
            }
    }

    /// That the run's deadline elapsed, naming the deadline.
    #[must_use]
    pub fn timeout_note(&self) -> String {
        match self.deadline_ms {
            Some(k) => format!("probe timed out at its {k} ms deadline"),
            None => "probe timed out".to_owned(),
        }
    }

    /// Case-insensitive search across both streams. glibc writes fortify and
    /// canary diagnostics to stderr, but a probe may echo a marker on stdout, so
    /// both are searched.
    pub fn output_contains(&self, needle: &str) -> bool {
        let needle = needle.to_lowercase();
        self.stdout.to_lowercase().contains(&needle) || self.stderr.to_lowercase().contains(&needle)
    }

    /// Whether a probe's stdout carries `marker` as a whole whitespace-separated token.
    #[must_use]
    pub fn has_marker(&self, marker: &str) -> bool {
        self.stdout
            .lines()
            .any(|l| l.split_whitespace().any(|t| t == marker))
    }

    /// Whether any whole token on a line of stdout begins with `key` (including its `=`),
    /// whatever follows. For a probe that names a witness by key alone.
    #[must_use]
    pub fn has_marker_key(&self, key: &str) -> bool {
        self.stdout
            .lines()
            .any(|l| l.split_whitespace().any(|t| t.starts_with(key)))
    }
}

/// What a fault report says killed a probe: the classes the enforcement checks need kept
/// apart. The rules are in [`FaultReport::classify`] and the measurements behind them in
/// `probes/chard_selfreport.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// `brk` on aarch64; on x86 SIGILL `ILL_ILLOPN` at `ud2`, `ud1` or `ud0`, legacy and
    /// REX prefixes allowed before them (clang's sanitizer and `-ftrapv` traps are
    /// `67 0f b9`), or SIGTRAP `SI_KERNEL` from `int3`.
    CompilerTrap,
    /// SIGILL `ILL_ILLOPC` with an ESR record of exception class 0x0d, or, where the kernel
    /// writes no ESR record, at the address the probe declared as an indirect branch's
    /// target, where the word is not a `udf`.
    BtiFault,
    /// SIGILL `ILL_ILLOPN` with an ESR record of exception class 0x1c, the `FEAT_FPAC`
    /// authentication failure. Without `FEAT_FPAC` a failed authentication poisons the
    /// pointer and the fault is the later SIGSEGV, which this does not claim.
    PacFailure,
    /// Any other SIGILL an instruction raised: an undefined instruction, or a BTI-shaped
    /// fault the probe did not declare a target for.
    IllegalInstruction,
    /// A SIGILL or SIGTRAP whose class turns on the instruction bytes, which the reporter
    /// could not read. Neither a trap nor its absence: a reading over it withholds.
    Undetermined,
    /// Anything else the reporter saw: a SIGSEGV, a SIGBUS, a SIGTRAP that is not a trap
    /// instruction, or a signal sent with `kill`, `raise` or `sigqueue`.
    Other,
}

impl Fault {
    /// Every class, held to the enum by the exhaustive match in its test.
    pub const ALL: [Self; 6] = [
        Self::CompilerTrap,
        Self::BtiFault,
        Self::PacFailure,
        Self::IllegalInstruction,
        Self::Undetermined,
        Self::Other,
    ];
}

/// The architecture a fault report names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultArch {
    /// `aarch64`.
    Aarch64,
    /// `x86_64`.
    X86_64,
    /// `x86`, 32-bit.
    X86,
}

/// One `chard-fault-v1` line, parsed. See `probes/chard_selfreport.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FaultReport {
    /// The signal number, Linux numbering.
    pub signal: i32,
    /// `si_code`.
    pub code: i32,
    /// `si_code` was zero or negative: the signal was sent (`SI_USER` from `kill`,
    /// `SI_TKILL` from `raise`, `SI_QUEUE`), so no instruction faulted.
    pub sent: bool,
    /// The architecture the reporter was built for.
    pub arch: FaultArch,
    /// The faulting pc.
    pub pc: u64,
    /// The fault address, `si_addr`.
    pub addr: u64,
    /// The instruction at the pc: one word on aarch64, the bytes there packed
    /// little-endian on x86 (eight on `x86_64`, four on i386); `None` where `si_addr` is
    /// not the pc or the pc could not be read.
    pub word: Option<u64>,
    /// `ESR_EL1` from the signal frame on aarch64; `None` where the kernel wrote none.
    pub esr: Option<u64>,
    /// Whether the pc is the address the probe declared; `None` when it declared none.
    pub at_target: Option<bool>,
}

impl FaultReport {
    /// What a report line begins with: the version token and the space after it.
    pub const PREFIX: &'static str = "chard-fault-v1 ";

    /// Every field a report line carries, each exactly once, in sorted order, which is the
    /// order `parse` collects them in.
    pub const FIELDS: [&'static str; 9] = [
        "addr",
        "arch",
        "at-target",
        "code",
        "esr",
        "pc",
        "sent",
        "signal",
        "word",
    ];

    /// One report line, or `None` for any line that is not exactly the reporter's shape:
    /// a field missing, repeated, unknown or malformed, or a number with a sign the
    /// reporter never writes, rejects the whole line, so a half-written report never
    /// classifies.
    fn parse(line: &str) -> Option<Self> {
        let rest = line.strip_prefix(Self::PREFIX)?;
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for pair in rest.split(' ') {
            let (key, value) = pair.split_once('=')?;
            if value.starts_with('+') || value.contains("x+") || fields.insert(key, value).is_some()
            {
                return None;
            }
        }
        if !fields.keys().copied().eq(Self::FIELDS) {
            return None;
        }
        let field = |key: &str| fields.get(key).copied();
        let hex = |v: &str| -> Option<u64> { u64::from_str_radix(v.strip_prefix("0x")?, 16).ok() };
        let optional_hex = |v: &str| -> Option<Option<u64>> {
            if v == "none" {
                Some(None)
            } else {
                hex(v).map(Some)
            }
        };
        let arch = match field("arch")? {
            "aarch64" => FaultArch::Aarch64,
            "x86_64" => FaultArch::X86_64,
            "x86" => FaultArch::X86,
            _ => return None,
        };
        let code: i32 = field("code")?.parse().ok()?;
        let sent = match field("sent")? {
            "yes" => true,
            "no" => false,
            _ => return None,
        };
        if sent != (code <= 0) {
            return None;
        }
        let word = optional_hex(field("word")?)?;
        if arch == FaultArch::Aarch64 && word.is_some_and(|w| w > u64::from(u32::MAX)) {
            return None;
        }
        Some(Self {
            signal: field("signal")?.parse().ok()?,
            code,
            sent,
            arch,
            pc: hex(field("pc")?)?,
            addr: hex(field("addr")?)?,
            word,
            esr: optional_hex(field("esr")?)?,
            at_target: match field("at-target")? {
                "yes" => Some(true),
                "no" => Some(false),
                "undeclared" => None,
                _ => return None,
            },
        })
    }

    /// The class of fault this report describes.
    #[must_use]
    pub fn classify(&self) -> Fault {
        const SIGILL: i32 = 4;
        const SIGTRAP: i32 = 5;
        const ILL_ILLOPC: i32 = 1;
        const ILL_ILLOPN: i32 = 2;
        const TRAP_BRKPT: i32 = 1;
        const SI_KERNEL: i32 = 128;
        const EC_BTI: u64 = 0x0d;
        const EC_FPAC: u64 = 0x1c;
        let class = |esr: u64| (esr >> 26) & 0x3f;
        if self.sent {
            return Fault::Other;
        }
        let aarch64 = self.arch == FaultArch::Aarch64;
        match (aarch64, self.signal, self.code) {
            (true, SIGILL, ILL_ILLOPN) if self.esr.is_some_and(|e| class(e) == EC_FPAC) => {
                return Fault::PacFailure;
            }
            (true, SIGILL, ILL_ILLOPC) if self.esr.is_some_and(|e| class(e) == EC_BTI) => {
                return Fault::BtiFault;
            }
            (false, SIGTRAP, SI_KERNEL) => return Fault::CompilerTrap,
            _ => {}
        }
        let Some(word) = self.word else {
            return if matches!(self.signal, SIGILL | SIGTRAP) {
                Fault::Undetermined
            } else {
                Fault::Other
            };
        };
        match (aarch64, self.signal, self.code) {
            (true, SIGTRAP, TRAP_BRKPT) if word & 0xffe0_001f == 0xd420_0000 => Fault::CompilerTrap,
            (true, SIGILL, ILL_ILLOPC)
                if self.esr.is_none() && self.at_target == Some(true) && word >> 16 != 0 =>
            {
                Fault::BtiFault
            }
            (false, SIGILL, ILL_ILLOPN) if x86_trap_bytes(word) => Fault::CompilerTrap,
            (_, SIGILL, _) => Fault::IllegalInstruction,
            _ => Fault::Other,
        }
    }
}

/// Whether these bytes, little-endian from the pc, are `ud2` (`0f 0b`), `ud1` (`0f b9`)
/// or `ud0` (`0f ff`) after at most four prefixes: the legacy ones (operand and address
/// size, the segment overrides, `rep`, `repne`) and REX. clang's sanitizer and `-ftrapv`
/// traps carry an address-size prefix (`67 0f b9`), measured with clang 22.1.8.
fn x86_trap_bytes(word: u64) -> bool {
    let bytes = word.to_le_bytes();
    let prefixes = bytes
        .iter()
        .take(4)
        .take_while(|b| {
            matches!(
                b,
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf2 | 0xf3 | 0x40..=0x4f
            )
        })
        .count();
    matches!(bytes.get(prefixes..), Some([0x0f, 0x0b | 0xb9 | 0xff, ..]))
}

/// This platform's number for the signal a run record names, the inverse of the table run
/// records are named by: `Some(10)` for `SIGBUS` on Darwin and the BSDs, `Some(7)` on Linux.
/// The table's bare `SIG<n>` for a number it does not name is found too, for 1 to 64; any
/// other name is `None`. A test that writes a number beside a name takes the number from
/// here, so it holds on every platform the table covers.
#[must_use]
pub fn signal_number(name: &str) -> Option<i32> {
    (1..=64).find(|&sig| signal_name(sig) == name)
}

/// Signal numbers are per-platform, and only some of them agree.
#[cfg(target_os = "linux")]
fn signal_name(sig: i32) -> String {
    match sig {
        4 => "SIGILL".to_owned(),
        5 => "SIGTRAP".to_owned(),
        6 => "SIGABRT".to_owned(),
        7 => "SIGBUS".to_owned(),
        8 => "SIGFPE".to_owned(),
        9 => "SIGKILL".to_owned(),
        11 => "SIGSEGV".to_owned(),
        13 => "SIGPIPE".to_owned(),
        15 => "SIGTERM".to_owned(),
        31 => "SIGSYS".to_owned(),
        other => format!("SIG{other}"),
    }
}

/// `4.4BSD` numbering, shared by Darwin, `FreeBSD` and `OpenBSD`. Differs from Linux above at
/// 7, 10, 12 and 31; the hardening-relevant ones are the same.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
fn signal_name(sig: i32) -> String {
    match sig {
        4 => "SIGILL".to_owned(),
        5 => "SIGTRAP".to_owned(),
        6 => "SIGABRT".to_owned(),
        7 => "SIGEMT".to_owned(),
        8 => "SIGFPE".to_owned(),
        9 => "SIGKILL".to_owned(),
        10 => "SIGBUS".to_owned(),
        11 => "SIGSEGV".to_owned(),
        12 => "SIGSYS".to_owned(),
        13 => "SIGPIPE".to_owned(),
        15 => "SIGTERM".to_owned(),
        other => format!("SIG{other}"),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd"
)))]
compile_error!("chard has no signal-number table for this target_os.");

/// Read one of the probe's output files, capped, reporting what it could not do.
fn read_capped(path: &Path) -> Result<(String, bool), std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    // take() rather than read_to_end so a runaway probe cannot exhaust memory.
    let read = std::io::Read::take(&mut file, MAX_CAPTURE).read_to_end(&mut buf)?;
    let truncated = u64::try_from(read).is_ok_and(|n| n >= MAX_CAPTURE);
    Ok((
        String::from_utf8_lossy(&buf).trim_end().to_owned(),
        truncated,
    ))
}

/// Execute `binary`, capturing its fate. `work` holds the two output files.
///
/// # Errors
///
/// Errors when the capture files cannot be created or the binary cannot be
/// spawned. A probe that crashes, aborts, or times out is a normal result and
/// is reported in the [`RunRecord`].
pub fn execute(
    binary: &Path,
    work: &Path,
    timeout: Duration,
    pins: &[(&str, &str)],
) -> Result<RunRecord> {
    let stem = binary
        .file_name()
        .map_or_else(|| "probe".into(), std::ffi::OsString::from);
    let out_path = work.join(format!("{}.stdout", stem.to_string_lossy()));
    let err_path = work.join(format!("{}.stderr", stem.to_string_lossy()));
    // Every path here is chard's own, tagged `HarnessPath` so that an envelope carrying one
    // does not tell an operator to check a path chard constructed.
    let out_file = std::fs::File::create(&out_path)
        .with_context(|| crate::error::HarnessPath(out_path.clone()))
        .context("creating the stdout capture")?;
    let err_file = std::fs::File::create(&err_path)
        .with_context(|| crate::error::HarnessPath(err_path.clone()))
        .context("creating the stderr capture")?;

    // The child's working directory is set to `work`, and execvp resolves the
    // program path *after* that chdir, so a `work`-relative program path would be
    // looked up as `work/work/...` and fail with ENOENT.
    let program = std::path::absolute(binary)
        .with_context(|| format!("resolving {} to an absolute path", binary.display()))?;

    let argv = vec![program.display().to_string()];
    let environment = probe_environment(pins);
    let started = Instant::now();
    let mut child = Command::new(&program)
        .current_dir(work)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        // The probe's whole environment (`PROBE_ENVIRONMENT` says why); the record below
        // carries the same map, so what the child was given and what the report says cannot
        // differ.
        .env_clear()
        .envs(&environment)
        // A group of its own, so a timeout kills what the probe forked too ([`kill_group`]).
        .process_group(0)
        .spawn()
        .with_context(|| crate::error::HarnessPath(program.clone()))
        .with_context(|| format!("executing {}", binary.display()))?;

    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().context("waiting for probe")? {
            break Some(status);
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            // One more look before killing.
            if let Ok(Some(status)) = child.try_wait() {
                break Some(status);
            }
            // The probe's whole group, before the reap ([`kill_group`] says why).
            kill_group(&mut child);
            // Reap, and keep the signal that ended the process, not the `SIGKILL` chard sent.
            break child.wait().ok();
        }
        poll_sleep(started.elapsed());
    };

    let duration_ms = started.elapsed().as_millis();
    let (exit_status, signal) = match status {
        Some(status) => (
            status.code().unwrap_or(-1),
            status.signal().map(signal_name),
        ),
        // Only when `wait` itself failed: the status is unknown, not known to be a kill, and
        // `timed_out` carries what was measured.
        None => (-1, None),
    };

    // A stream chard could not read is recorded as such rather than as an empty one.
    let mut output_error: Vec<String> = Vec::new();
    let mut output_truncated = false;
    let mut read = |path: &Path, name: &str| match read_capped(path) {
        Ok((text, cut)) => {
            output_truncated |= cut;
            text
        }
        Err(e) => {
            output_error.push(format!("{name}: {e}"));
            String::new()
        }
    };
    let stdout = read(&out_path, "stdout");
    let stderr = read(&err_path, "stderr");

    Ok(RunRecord {
        argv,
        exit_status,
        signal,
        stdout,
        stderr,
        timed_out,
        deadline_ms: Some(timeout.as_millis()),
        output_error: (!output_error.is_empty()).then(|| output_error.join("; ")),
        output_truncated,
        duration_ms,
        environment: Some(environment),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_exit_needs_both_halves() {
        let record = |signal: Option<&str>, status: i32| RunRecord {
            argv: vec!["probe".to_owned()],
            exit_status: status,
            signal: signal.map(ToOwned::to_owned),
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            deadline_ms: None,
            output_error: None,
            output_truncated: false,
            duration_ms: 1,
            environment: None,
        };

        assert!(record(None, 0).exited_cleanly());
        assert!(
            !record(Some("SIGABRT"), 0).exited_cleanly(),
            "a signalled death is not a clean exit whatever the status field says"
        );
        assert!(
            !record(None, 1).exited_cleanly(),
            "nor is a non-zero status"
        );
        assert!(!record(Some("SIGABRT"), 1).exited_cleanly());
    }

    #[test]
    fn a_cut_stream_and_a_deadline_are_named() {
        let mut run = RunRecord {
            argv: vec!["probe".to_owned()],
            exit_status: 0,
            signal: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            deadline_ms: None,
            output_error: None,
            output_truncated: false,
            duration_ms: 1,
            environment: None,
        };
        assert!(run.stream_cut().is_none());
        assert_eq!(run.timeout_note(), "probe timed out");

        run.output_truncated = true;
        let capped = run.stream_cut().expect("a capped stream is cut");
        assert!(
            capped.contains(&format!("{MAX_CAPTURE}-byte capture cap")),
            "{capped}"
        );

        run.output_error = Some("stderr: permission denied".to_owned());
        let both = run.stream_cut().expect("still cut");
        assert!(
            both.contains("permission denied") && both.contains("capture cap"),
            "{both}"
        );

        run.deadline_ms = Some(Duration::from_secs(5).as_millis());
        assert_eq!(
            run.timeout_note(),
            "probe timed out at its 5000 ms deadline"
        );

        // A run the deadline killed is cut however short its output; one that exited in
        // the window before the kill, or a `wait` that failed after it, is judged by status.
        run.output_error = None;
        run.output_truncated = false;
        run.timed_out = true;
        assert!(!run.killed_at_deadline(), "exit 0 in the window finished");
        assert!(run.stream_cut().is_none());
        run.exit_status = -1;
        assert!(run.killed_at_deadline(), "no status after the kill");
        run.signal = Some("SIGKILL".to_owned());
        assert!(run.killed_at_deadline());
        let killed = run.stream_cut().expect("a killed run is cut");
        assert!(
            killed.contains("5000 ms deadline and was killed"),
            "{killed}"
        );
        run.signal = Some("SIGSEGV".to_owned());
        assert!(!run.killed_at_deadline(), "its own signal ended it");
    }

    #[test]
    fn a_timeout_kills_what_the_probe_forked() {
        let dir = std::env::temp_dir().join(format!("chard-rungroup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        // `test_script` runs the script once from this process's directory to wait out
        // `ETXTBSY`, and there it exits at once: `execute` runs it in `dir`, beside itself.
        let probe = crate::compile::test_script(
            &dir.join("forks-on-timeout"),
            "[ -e forks-on-timeout ] || exit 0\n(trap '' TERM HUP INT; exec /bin/sleep 30) &\n\
             echo $! > forked\nwait",
        );
        let record = execute(&probe, &dir, Duration::from_millis(400), &[]).expect("ran");
        assert!(record.timed_out, "the probe outlived its bound: {record:?}");
        let forked: u32 = std::fs::read_to_string(dir.join("forked"))
            .expect("the probe wrote its child's pid")
            .trim()
            .parse()
            .expect("a pid");
        assert!(
            gone_within(forked, Duration::from_secs(2)),
            "the probe's child {forked} is still running after the timeout killed the probe"
        );
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_group_operand_is_never_the_callers_group_or_every_process() {
        assert_eq!(group_operand(0), None);
        assert_eq!(group_operand(1), None);
        assert_eq!(group_operand(2).as_deref(), Some("-2"));
    }

    #[test]
    fn a_failed_group_kill_is_an_error_and_the_child_is_killed() {
        assert!(
            signal_group("/nonexistent/sh", "-2").is_err(),
            "a shell that cannot run"
        );
        assert!(
            signal_group(KILL_SHELL, "-2147483646").is_err(),
            "a group that does not exist: `kill` exits other than 0"
        );
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("spawning sleep");
        kill_group_through(&mut child, "/nonexistent/sh");
        let status = child.wait().expect("reaping sleep");
        assert_eq!(
            status.signal(),
            Some(9),
            "the child alone is killed: {status:?}"
        );
    }

    #[test]
    fn a_run_record_carries_its_deadline() {
        let dir = std::env::temp_dir().join(format!("chard-rundeadline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let record = execute(
            Path::new("/usr/bin/true"),
            &dir,
            Duration::from_millis(4321),
            &[],
        )
        .expect("ran");
        assert_eq!(record.deadline_ms, Some(4321));
        // Cleanup, and its failure is not a finding: the directory is per-process.
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn truncation_is_reported_at_the_cap_and_not_before() {
        // Named for this test, not just the process: tests share a process, and `elf.rs`
        // has a `chard-cap-<pid>` scratch directory the cleanup below must not delete.
        let dir = std::env::temp_dir().join(format!("chard-runcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");

        let write = |name: &str, len: usize| {
            let path = dir.join(name);
            std::fs::write(&path, "x".repeat(len)).expect("write");
            path
        };

        let cap = usize::try_from(MAX_CAPTURE).expect("the cap fits a usize");
        let (short, truncated) = read_capped(&write("short", cap - 1)).expect("read");
        assert_eq!(short.len(), cap - 1);
        assert!(!truncated, "one byte under the cap is the whole stream");

        let (exact, truncated) = read_capped(&write("exact", cap)).expect("read");
        assert_eq!(exact.len(), cap);
        assert!(truncated, "at the cap the tail may already be gone");

        let (over, truncated) = read_capped(&write("over", cap * 2)).expect("read");
        assert_eq!(over.len(), cap, "and nothing past the cap is read");
        assert!(truncated);

        // Cleanup, and its failure is not a finding: the directory is per-process.
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_probe_receives_the_pinned_environment_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("chard-runenv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        // Through `test_script`, which waits out `ETXTBSY`: written with `std::fs::write` and
        // run at once, this test failed `Text file busy` once in four lib runs on Fedora 44
        // x86_64 (2026-10-01).
        let probe = crate::compile::test_script(&dir.join("printenv-probe"), "exec /usr/bin/env");

        let names = |text: &str| -> BTreeMap<String, String> {
            text.lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        };

        // The control: the same script with this process's environment inherited.
        let inherited = Command::new(&probe)
            .current_dir(&dir)
            .output()
            .expect("run the probe directly");
        let inherited = names(&String::from_utf8_lossy(&inherited.stdout));
        assert!(
            inherited.contains_key("PATH") && inherited.contains_key("HOME"),
            "the control has nothing to clear, so the measurement below proves nothing: \
             {inherited:?}"
        );

        // A pin of the probe's own, beside the base list: it reaches the child and the
        // record, as the base pins do, and nothing else comes with it.
        let own = [("CHARD_PROBE_PIN", "1")];
        let record = execute(&probe, &dir, Duration::from_secs(10), &own).expect("spawn the probe");
        assert!(record.exited_cleanly(), "{record:?}");
        let received = names(&record.stdout);

        let pinned = probe_environment(&own);
        assert!(pinned.contains_key("CHARD_PROBE_PIN") && pinned.contains_key("LC_ALL"));
        for (name, value) in &pinned {
            assert_eq!(
                received.get(name),
                Some(value),
                "`{name}` did not reach the probe: {received:?}"
            );
        }
        let shell_own = ["PWD", "SHLVL", "OLDPWD", "_"];
        let strays: Vec<&String> = received
            .keys()
            .filter(|k| !pinned.contains_key(*k) && !shell_own.contains(&k.as_str()))
            .collect();
        assert!(
            strays.is_empty(),
            "ambient variables reached the probe: {strays:?}"
        );
        assert_eq!(
            record.environment.as_ref(),
            Some(&pinned),
            "the record must name exactly what the probe was given"
        );

        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn signal_names_cover_the_hardening_relevant_ones() {
        assert_eq!(signal_name(6), "SIGABRT");
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(4), "SIGILL");
        assert_eq!(signal_name(99), "SIG99");
    }

    #[test]
    fn signal_numbers_are_this_platforms() {
        for sig in 1..=64 {
            let name = signal_name(sig);
            assert_eq!(signal_number(&name), Some(sig), "{name}");
        }
        assert_eq!(signal_number("SIGNOPE"), None);
        assert_eq!(signal_number("SIG99"), None);
        assert_eq!(signal_number("SIG34"), Some(34));
        let bus = if cfg!(target_os = "linux") { 7 } else { 10 };
        assert_eq!(signal_number("SIGBUS"), Some(bus));
        assert_eq!(signal_number("SIGSEGV"), Some(11));
    }

    #[test]
    fn a_trap_is_named_rather_than_numbered() {
        assert_eq!(signal_name(5), "SIGTRAP");
    }

    fn record(exit: i32, sig: Option<&str>, stderr: &str) -> RunRecord {
        RunRecord {
            argv: vec!["probe".to_owned()],
            exit_status: exit,
            signal: sig.map(ToOwned::to_owned),
            stdout: String::new(),
            stderr: stderr.to_owned(),
            timed_out: false,
            deadline_ms: None,
            output_error: None,
            output_truncated: false,
            duration_ms: 1,
            environment: None,
        }
    }

    #[test]
    fn fortify_and_canary_aborts_are_distinguishable() {
        let fortify = record(
            -1,
            Some("SIGABRT"),
            "*** buffer overflow detected ***: terminated",
        );
        let canary = record(
            -1,
            Some("SIGABRT"),
            "*** stack smashing detected ***: terminated",
        );
        assert!(fortify.aborted() && canary.aborted());
        assert!(fortify.output_contains("buffer overflow detected"));
        assert!(!fortify.output_contains("stack smashing detected"));
        assert!(canary.output_contains("stack smashing detected"));
    }

    #[test]
    fn a_marker_is_a_whole_token_on_stdout() {
        let mut run = record(0, None, "overflow-guard=ran");
        run.stdout = "optimize=yes\noverflow-guard=ranged frontend=gcc\n".to_owned();
        assert!(run.has_marker("optimize=yes"));
        assert!(run.has_marker("frontend=gcc"));
        assert!(!run.has_marker("overflow-guard=ran"));
        assert!(!run.has_marker("optimize=y"));
        assert!(run.has_marker_key("overflow-guard="));
        assert!(!run.has_marker_key("null-check="));
    }

    #[test]
    fn both_architectures_spellings_of_a_trap_are_traps() {
        assert!(record(-1, Some("SIGILL"), "").trapped());
        assert!(record(-1, Some("SIGTRAP"), "").trapped());
        assert!(!record(-1, Some("SIGABRT"), "").trapped());
        assert!(!record(0, None, "").trapped());
    }

    /// Fault reports as the reporter wrote them, each from `tests/fault_classes.c` built
    /// and run on 2026-10-09, one row per distinct line (pc and addr vary by build).
    /// aarch64: Apple M2 (`FEAT_BTI`, `FEAT_PAuth2`, `FEAT_FPAC`), a Linux 7.0.0-38 guest
    /// under Apple's Virtualization.framework, Ubuntu 24.04, gcc 13.3.0 and clang 18.1.3 at
    /// `-O2 -mbranch-protection=standard`. x86_64: Fedora 44, gcc 16.1.1 and clang 22.1.8
    /// at `-O2`. Emulated, and labelled so: static aarch64 builds under qemu-user 10.2.2
    /// `-cpu max` on the x86_64 host: the only rows in which a BTI fault carries an ESR
    /// record; the hardware guest wrote none.
    const MEASURED: &[(&str, &str, &str, Fault)] = &[
        (
            "aarch64 on hardware: gcc trap",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xb93cf0ca09dc addr=0xb93cf0ca09dc word=0xd4207d00 esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on hardware: gcc udf",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xc06a95440a5c addr=0xc06a95440a5c word=0x0 esr=none at-target=undeclared",
            Fault::IllegalInstruction,
        ),
        (
            "aarch64 on hardware: gcc segv",
            "SIGSEGV",
            "chard-fault-v1 signal=11 code=1 sent=no arch=aarch64 pc=0xb300c0560a6c addr=0x8 word=none esr=0x92000044 at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on hardware: gcc jump-unmapped",
            "SIGSEGV",
            "chard-fault-v1 signal=11 code=1 sent=no arch=aarch64 pc=0x10 addr=0x10 word=none esr=0x82000004 at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on hardware: gcc trap-elsewhere",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xb99c3ac509ec addr=0xb99c3ac509ec word=0xd4207d00 esr=none at-target=no",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on hardware: gcc kill",
            "SIGILL",
            "chard-fault-v1 signal=4 code=0 sent=yes arch=aarch64 pc=0xef7f9aa3cd8c addr=0x3e800017c40 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on hardware: gcc raise",
            "SIGILL",
            "chard-fault-v1 signal=4 code=-6 sent=yes arch=aarch64 pc=0xe6be0ca274d8 addr=0x3e800017c47 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on hardware: gcc bus",
            "SIGBUS",
            "chard-fault-v1 signal=7 code=2 sent=no arch=aarch64 pc=0xc31961010b18 addr=0xf0122596e000 word=none esr=0x92000007 at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on hardware: gcc pac",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=aarch64 pc=0xb95168ec0cdc addr=0xb95168ec0cdc word=0xd50323bf esr=0x72000000 at-target=undeclared",
            Fault::PacFailure,
        ),
        (
            "aarch64 on hardware: gcc bti-declared",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xe8e60eb4f000 addr=0xe8e60eb4f000 word=0xd28000e0 esr=none at-target=yes",
            Fault::BtiFault,
        ),
        (
            "aarch64 on hardware: gcc bti-undeclared",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xefd19fd92000 addr=0xefd19fd92000 word=0xd28000e0 esr=none at-target=undeclared",
            Fault::IllegalInstruction,
        ),
        (
            "aarch64 on hardware: clang trap",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xcaa96e590984 addr=0xcaa96e590984 word=0xd4200020 esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on hardware: clang trap-elsewhere",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xb8f64a6e0994 addr=0xb8f64a6e0994 word=0xd4200020 esr=none at-target=no",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on hardware: clang overflow -fsanitize=signed-integer-overflow -fsanitize-trap=signed-integer-overflow",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xc6c82ebd0ac0 addr=0xc6c82ebd0ac0 word=0xd42aa000 esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: gcc trap",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x4004a9 addr=0x4004a9 word=0xf30000441f0f0b0f esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: gcc ud1",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x4004a9 addr=0x4004a9 word=0x4013fdbec0b90f esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: gcc int3",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=128 sent=no arch=x86_64 pc=0x4004aa addr=0x0 word=none esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: gcc segv",
            "SIGSEGV",
            "chard-fault-v1 signal=11 code=1 sent=no arch=x86_64 pc=0x4004b5 addr=0x8 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "x86_64: gcc trap-elsewhere",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x4004b4 addr=0x4004b4 word=0x841f0f2e660b0f esr=none at-target=no",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: gcc kill",
            "SIGILL",
            "chard-fault-v1 signal=4 code=0 sent=yes arch=x86_64 pc=0x7fb1db9731bb addr=0x3e800090331 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "x86_64: gcc raise",
            "SIGILL",
            "chard-fault-v1 signal=4 code=-6 sent=yes arch=x86_64 pc=0x7f9965053ccc addr=0x3e800090353 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "x86_64: gcc bus",
            "SIGBUS",
            "chard-fault-v1 signal=7 code=2 sent=no arch=x86_64 pc=0x400521 addr=0x7f6007440000 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "x86_64: gcc page-end",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x7fc4423f7ffe addr=0x7fc4423f7ffe word=0xb0f esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: gcc overflow -fsanitize=signed-integer-overflow -fsanitize-trap=signed-integer-overflow",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x4004e8 addr=0x4004e8 word=0x441f0f660b0f esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: clang trap",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x4003fb addr=0x4003fb word=0x1e0ff3001f0f0b0f esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: clang ud1",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x400592 addr=0x400592 word=0x4023b4bfc0b90f esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: clang trap-elsewhere",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x400406 addr=0x400406 word=0x841f0f0b0f esr=none at-target=no",
            Fault::CompilerTrap,
        ),
        (
            "x86_64: clang overflow -fsanitize=signed-integer-overflow -fsanitize-trap=signed-integer-overflow",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x4005cc addr=0x4005cc word=0x4157415500b90f67 esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 under emulation: emulated bti-declared",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0x7f2dfcdc1000 addr=0x7f2dfcdc1000 word=0xd28000e0 esr=0x36000002 at-target=yes",
            Fault::BtiFault,
        ),
        (
            "aarch64 under emulation: emulated udf",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0x4006dc addr=0x4006dc word=0x0 esr=0x2000000 at-target=undeclared",
            Fault::IllegalInstruction,
        ),
    ];

    #[test]
    fn each_measured_fault_report_classifies_as_what_provoked_it() {
        for (what, signal, line, want) in MEASURED {
            let line = on_this_platform(line, signal);
            let run = record(-1, Some(signal), &format!("{line}\n"));
            assert_eq!(run.fault(), Some(*want), "{what}: {line}");
            assert_eq!(run.trapped(), *want == Fault::CompilerTrap, "{what}");
        }
        for needed in [
            "clang overflow -fsanitize=signed-integer-overflow",
            "emulated bti",
            "gcc bti-declared",
            "gcc pac",
            "gcc kill",
            "gcc raise",
            "gcc bus",
            "gcc page-end",
            "jump-unmapped",
        ] {
            assert!(
                MEASURED.iter().any(|(what, ..)| what.contains(needed)),
                "a measured row for {needed}"
            );
        }
    }

    #[test]
    fn every_class_is_measured_or_held_by_name() {
        for fault in Fault::ALL {
            let measured = MEASURED.iter().any(|(.., f)| *f == fault);
            match fault {
                Fault::CompilerTrap
                | Fault::BtiFault
                | Fault::PacFailure
                | Fault::IllegalInstruction
                | Fault::Other => assert!(measured, "{fault:?} has a measured row"),
                Fault::Undetermined => assert!(!measured, "no working reporter writes one"),
            }
        }
    }

    #[test]
    fn without_a_report_the_bare_signal_decides() {
        for signal in ["SIGILL", "SIGTRAP"] {
            let run = record(-1, Some(signal), "some diagnostic\n");
            assert_eq!(run.fault(), None);
            assert!(run.trapped(), "{signal}");
        }
        assert!(!record(-1, Some("SIGSEGV"), "").trapped());
    }

    /// A measured hardware BTI line, re-used below as the base the mutations change.
    const BTI: &str = "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xbd74c4c00a5c addr=0xbd74c4c00a5c word=0xd28000e0 esr=none at-target=yes";

    /// The measured line for `what`, from the table.
    fn measured(what: &str) -> &'static str {
        MEASURED
            .iter()
            .find(|(w, ..)| w.contains(what))
            .map(|row| row.2)
            .expect("a measured row")
    }

    /// `line`, measured on Linux, with its one `signal=` field in this platform's number for
    /// `name`: the reporter emits on Linux alone, and the classification under test must not
    /// rest on Linux's numbering where the table is another (`SIGBUS` is 7 on Linux and 10
    /// under 4.4BSD numbering). On Linux it is the line itself, asserted, so a measured row
    /// whose number is not its name's still fails where it was measured.
    fn on_this_platform(line: &str, name: &str) -> String {
        let number = signal_number(name).expect("the table names the signal");
        let fields = line.split(' ').filter(|f| f.starts_with("signal=")).count();
        assert_eq!(
            fields, 1,
            "a measured line carries one signal field: {line}"
        );
        let renumbered = line
            .split(' ')
            .map(|field| {
                if field.starts_with("signal=") {
                    format!("signal={number}")
                } else {
                    field.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        if cfg!(target_os = "linux") {
            assert_eq!(renumbered, line, "{name} is not the measured line's signal");
        }
        renumbered
    }

    #[test]
    fn a_report_that_does_not_describe_the_death_or_is_malformed_is_ignored() {
        let bti = measured("gcc bti-declared");
        // The process died by SIGTRAP, so a SIGILL report is about something else; the
        // bare signal decides.
        let other_death = record(-1, Some("SIGTRAP"), &format!("{bti}\n"));
        assert_eq!(other_death.fault(), None);
        assert!(other_death.trapped());
        // A clean exit after a report: no death to classify.
        assert_eq!(record(0, None, &format!("{bti}\n")).fault(), None);
        for broken in [
            BTI.replace(" at-target=yes", ""),
            format!("{BTI} extra=1"),
            BTI.replace("signal=4", "signal=4 signal=4"),
            BTI.replace("arch=aarch64", "arch=riscv64"),
            BTI.replace("word=0xd28000e0", "word=d28000e0"),
            BTI.replace("word=0xd28000e0", "word=0x1d28000e0"),
            BTI.replace("at-target=yes", "at-target=maybe"),
            BTI.replace("sent=no", "sent=yes"),
            BTI.replace("code=1", "code=0"),
            BTI.replace("pc=0xbd74c4c00a5c", "pc=none"),
            BTI.replace("signal=4", "signal=+4"),
            BTI.replace("code=1", "code=+1"),
            BTI.replace("word=0xd28000e0", "word=0x+d28000e0"),
            BTI.replace("chard-fault-v1 ", "chard-fault-v1  "),
            // A decoy that only contains the prefix is not a report line.
            format!("probe said: {BTI}"),
        ] {
            let run = record(-1, Some("SIGILL"), &format!("{broken}\n"));
            assert_eq!(run.fault(), None, "{broken}");
            assert!(run.trapped(), "falls back to the bare signal: {broken}");
        }
        // The last report counts.
        let two = format!("{}\n{BTI}\n", measured("gcc pac"));
        assert_eq!(
            record(-1, Some("SIGILL"), &two).fault(),
            Some(Fault::BtiFault)
        );
        // A SIGBUS report describes a SIGBUS death and no other.
        let bus = on_this_platform(measured("gcc bus"), "SIGBUS");
        assert_eq!(record(-1, Some("SIGBUS"), &bus).fault(), Some(Fault::Other));
        assert_eq!(record(-1, Some("SIGSEGV"), &bus).fault(), None);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one assertion per part of each rule's evidence, read as one table"
    )]
    fn each_rule_needs_all_of_its_evidence() {
        let class = |signal: &str, line: &str| record(-1, Some(signal), line).fault();
        let illegal = Some(Fault::IllegalInstruction);
        let undetermined = Some(Fault::Undetermined);
        // BTI on hardware: the declaration, a word that is not a udf, no ESR, ILL_ILLOPC.
        assert_eq!(class("SIGILL", BTI), Some(Fault::BtiFault));
        assert_eq!(
            class("SIGILL", &BTI.replace("at-target=yes", "at-target=no")),
            illegal
        );
        assert_eq!(
            class(
                "SIGILL",
                &BTI.replace("at-target=yes", "at-target=undeclared")
            ),
            illegal
        );
        assert_eq!(
            class("SIGILL", &BTI.replace("word=0xd28000e0", "word=0x0")),
            illegal
        );
        assert_eq!(
            class("SIGILL", &BTI.replace("word=0xd28000e0", "word=0x1234")),
            illegal
        );
        assert_eq!(
            class("SIGILL", &BTI.replace("word=0xd28000e0", "word=0x10000")),
            Some(Fault::BtiFault)
        );
        assert_eq!(
            class("SIGILL", &BTI.replace("word=0xd28000e0", "word=none")),
            undetermined
        );
        assert_eq!(
            class("SIGILL", &BTI.replace("esr=none", "esr=0x2000000")),
            illegal
        );
        assert_eq!(class("SIGILL", &BTI.replace("code=1", "code=2")), illegal);
        // BTI from an ESR of class 0x0d needs no declaration and no word; class 0 is a udf.
        let emulated =
            measured("emulated bti-declared").replace("at-target=yes", "at-target=undeclared");
        assert_eq!(class("SIGILL", &emulated), Some(Fault::BtiFault));
        assert_eq!(
            class("SIGILL", &emulated.replace("word=0xd28000e0", "word=none")),
            Some(Fault::BtiFault)
        );
        assert_eq!(
            class("SIGILL", &emulated.replace("code=1", "code=2")),
            illegal
        );
        assert_eq!(
            class("SIGILL", &emulated.replace("arch=aarch64", "arch=x86_64")),
            illegal
        );
        // PAC needs class 0x1c and ILL_ILLOPN, and no word.
        let pac = measured("gcc pac");
        assert_eq!(class("SIGILL", pac), Some(Fault::PacFailure));
        assert_eq!(
            class("SIGILL", &pac.replace("word=0xd50323bf", "word=none")),
            Some(Fault::PacFailure)
        );
        assert_eq!(
            class("SIGILL", &pac.replace("esr=0x72000000", "esr=0x0")),
            illegal
        );
        assert_eq!(
            class("SIGILL", &pac.replace("esr=0x72000000", "esr=none")),
            illegal
        );
        assert_eq!(class("SIGILL", &pac.replace("code=2", "code=1")), illegal);
        // A brk needs TRAP_BRKPT and a brk word; hlt, svc and an immediate-less mask do not pass.
        let brk = measured("aarch64 on hardware: gcc trap");
        assert_eq!(class("SIGTRAP", brk), Some(Fault::CompilerTrap));
        for not_brk in [
            "0xd28000e0",
            "0xd4400000",
            "0xd4000001",
            "0xd4200001",
            "0xd4600000",
        ] {
            let line = brk.replace("word=0xd4207d00", &format!("word={not_brk}"));
            assert_eq!(class("SIGTRAP", &line), Some(Fault::Other), "{not_brk}");
        }
        assert_eq!(
            class("SIGTRAP", &brk.replace("code=1", "code=2")),
            Some(Fault::Other)
        );
        assert_eq!(
            class("SIGTRAP", &brk.replace("word=0xd4207d00", "word=none")),
            undetermined
        );
        // An x86 trap needs ILL_ILLOPN and a ud opcode after at most four prefixes.
        let ud = |bytes: &str| {
            format!(
                "chard-fault-v1 signal=4 code=2 sent=no arch=x86_64 pc=0x1 addr=0x1 word={bytes} esr=none at-target=undeclared"
            )
        };
        let mut traps = vec![
            "0x801f0f0b0f".to_owned(),
            "0x4155906600b90f67".to_owned(),
            "0xff0f48".to_owned(),
            "0x0b0f676767".to_owned(),
            "0x0b0f67676767".to_owned(),
        ];
        for prefix in [
            0x26_u64, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf2, 0xf3, 0x40, 0x4f,
        ] {
            traps.push(format!("{:#x}", 0xb9_0f00 | prefix));
        }
        for trap in &traps {
            assert_eq!(
                class("SIGILL", &ud(trap)),
                Some(Fault::CompilerTrap),
                "{trap}"
            );
            assert_eq!(
                class("SIGILL", &ud(trap).replace("arch=x86_64", "arch=x86")),
                Some(Fault::CompilerTrap),
                "{trap}"
            );
        }
        for not_trap in [
            "0x90909090",
            "0x0b0f6767676767",
            "0x050f",
            "0xb90e67",
            "0x0f",
            "0xb90f50",
        ] {
            assert_eq!(class("SIGILL", &ud(not_trap)), illegal, "{not_trap}");
        }
        assert_eq!(
            class("SIGILL", &ud("0x0b0f").replace("code=2", "code=1")),
            illegal
        );
        assert_eq!(class("SIGILL", &ud("none")), undetermined);
        assert_eq!(
            class(
                "SIGILL",
                &ud("0xb90f67").replace("arch=x86_64", "arch=aarch64")
            ),
            illegal
        );
        // int3 is SI_KERNEL and needs no word; another SIGTRAP code does.
        let int3 = measured("x86_64: gcc int3");
        assert_eq!(class("SIGTRAP", int3), Some(Fault::CompilerTrap));
        assert_eq!(
            class("SIGTRAP", &int3.replace("code=128", "code=1")),
            undetermined
        );
        // A sent signal is never a fault, whatever its numbers: kill (0) and raise (-6).
        let kill = pac.replace("code=2 sent=no", "code=0 sent=yes");
        assert_eq!(class("SIGILL", &kill), Some(Fault::Other));
        assert!(!record(-1, Some("SIGILL"), &kill).trapped());
        assert_eq!(class("SIGILL", measured("gcc raise")), Some(Fault::Other));
        // An undetermined report is not a trap, and it is not the bare signal either.
        let unread = record(-1, Some("SIGILL"), &ud("none"));
        assert!(unread.fault_report().is_some());
        assert!(!unread.trapped());
    }

    #[test]
    fn a_clean_exit_is_not_an_abort() {
        let clean = record(0, None, "");
        assert!(clean.exited_cleanly());
        assert!(!clean.aborted());
    }

    #[test]
    fn segv_is_neither_clean_nor_an_abort() {
        let segv = record(-1, Some("SIGSEGV"), "");
        assert!(!segv.exited_cleanly());
        assert!(!segv.aborted());
    }

    #[test]
    fn a_run_keeps_a_few_kib_whole_and_names_a_cut_stream() {
        let dir = std::env::temp_dir().join(format!("chard-runkeep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let cap = usize::try_from(MAX_CAPTURE).expect("the cap fits a usize");
        let printing = |name: &str, body: &str| {
            let probe = crate::compile::test_script(&dir.join(name), body);
            execute(&probe, &dir, Duration::from_secs(10), &[]).expect("spawn the probe")
        };
        let kept = printing("kept", "printf '%04096d' 0");
        assert_eq!((kept.stdout.len(), kept.output_truncated), (4096, false));
        assert!(kept.output_error.is_none());
        let cut = printing("cut", &format!("printf '%0{}d' 0 >&2", cap * 2));
        assert_eq!((cut.stderr.len(), cut.output_truncated), (cap, true));
        // Stdout cut and stderr whole: stdout is read first, so the cut must survive the
        // second read.
        let first = printing("first", &format!("printf '%0{}d' 0", cap * 2));
        assert_eq!((first.stdout.len(), first.output_truncated), (cap, true));
        assert!(first.output_error.is_none());
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_signalled_run_is_recorded_by_its_signal() {
        let dir = std::env::temp_dir().join(format!("chard-runsignal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let probe = crate::compile::test_script(&dir.join("segv"), "kill -SEGV $$");
        let record = execute(&probe, &dir, Duration::from_secs(10), &[]).expect("spawn the probe");
        assert_eq!(
            (record.exit_status, record.signal.as_deref()),
            (-1, Some("SIGSEGV"))
        );
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn an_aarch64_word_is_held_to_32_bits() {
        let line = |word: &str| {
            format!(
                "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0x1000 addr=0x1000 \
                 word={word} esr=none at-target=undeclared"
            )
        };
        assert!(FaultReport::parse(&line("0xffffffff")).is_some());
        assert!(FaultReport::parse(&line("0x100000000")).is_none());
    }
}
