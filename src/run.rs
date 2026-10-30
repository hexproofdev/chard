// SPDX-License-Identifier: BSD-3-Clause

//! Executing a probe binary and recording how it died.
//!
//! For the `runtime` channel the observable *is* the manner of death: exit
//! status, terminating signal, and the diagnostic text libc printed. Under glibc,
//! `SIGABRT` with `*** buffer overflow detected ***` means FORTIFY caught the write;
//! `SIGABRT` with `*** stack smashing detected ***` means the canary did;
//! `SIGSEGV` means nothing caught it; `SIGILL` is how a CET or BTI violation
//! surfaces. These must be distinguishable, so we record all three facts rather
//! than collapsing them to a boolean.
//!
//! ## The diagnostic is glibc's convention, not the mechanism's
//!
//! Recording all three matters most where that mapping does not hold. Alpine's
//! fortify-headers signals an overflow with `__builtin_trap()` (`ud2` on x86_64, so
//! `SIGILL` and an empty stderr) and musl's canary handler calls `a_crash()` rather
//! than printing and aborting. A detector keyed on glibc's wording sees a bare signal
//! with no message and correctly declines to claim anything, which is safe and useless:
//! it reports nothing on a system where the protection is present and working.
//!
//! So a signal alone can license a verdict, but only once something else has
//! established who owns it. [`RunRecord::trapped`] is deliberately separate from
//! [`RunRecord::aborted`] for that reason, and its callers pair it with the probe's
//! self-reported `_FORTIFY_IMPL` before reading anything into it; a compiler-inserted
//! trap for undefined behaviour is the same instruction.
//!
//! Output goes to files rather than pipes. Probes emit almost nothing, but a
//! pipe that fills while we are polling `try_wait` would deadlock, and the files
//! double as retained evidence in the work directory.
//!
//! ## The environment a probe runs under
//!
//! A probe receives no ambient variable at all. [`execute`] clears the environment and sets exactly
//! [`PROBE_ENVIRONMENT`] and the pins the probe itself declares (`probe::Probe::run_environment`,
//! empty for all but one probe), and every [`RunRecord`] carries that map as
//! [`RunRecord::environment`] so a reader can re-derive a runtime verdict under the same
//! conditions. The constant's own documentation says why clearing rather than a named list, and why
//! each pin. `DESIGN.md` places this among the conditions the control triple cannot see, since
//! an ambient variable reaches every arm alike.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// How long to sleep between `try_wait` calls once a child has run long enough that
/// millisecond resolution describes it honestly. Long enough not to spin a core.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The finer interval, and how long it is used for.
///
/// A flat 2 ms poll does not round a short duration, it *replaces* it: a probe that
/// finishes in 300 µs sleeps exactly once and is recorded as 2 ms. That is not a fast
/// probe reported imprecisely; it is the instrument's own resolution published as a
/// measurement. Ten of the thirteen run records in a full `chard measure` on the
/// development host read exactly 2 ms, and so does every run record in
/// `tests/fixtures/detectors.json`. For a tool whose entire claim is that it reports
/// what it measured rather than what it was told, that is the wrong number to ship.
///
/// So poll finely while a short child could still be running, then back off. The extra
/// cost is bounded at `FINE_POLL_WINDOW / FINE_POLL_INTERVAL` (one hundred wakeups,
/// after which a two-minute compile polls exactly as it did before.
const FINE_POLL_INTERVAL: Duration = Duration::from_micros(100);
const FINE_POLL_WINDOW: Duration = Duration::from_millis(10);

/// Sleep before the next `try_wait`, finely while the child is still young.
///
/// Shared with [`crate::compile`], which polls a child the same way, so the reasoning
/// above lives in one place instead of being restated at each polling site.
pub(crate) fn poll_sleep(elapsed: Duration) {
    if elapsed < FINE_POLL_WINDOW {
        std::thread::sleep(FINE_POLL_INTERVAL);
    } else {
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The whole environment a probe runs under.
///
/// A probe consults no variable legitimately, so it receives none: [`execute`] clears the
/// ambient environment and sets exactly these. The driver side is cleared the same way
/// (`compile::compiler_environment`) and differs in one name: a compiler is handed `PATH`,
/// which it needs to find its assembler and linker, and a probe is not. A named list of
/// variables to remove would have to
/// enumerate everything a loader or a libc reads, and any name left off it would reach the
/// probe unrecorded. `LD_PRELOAD` substitutes the functions under test, `LD_AUDIT` and
/// `LD_LIBRARY_PATH` substitute the objects they live in, `GLIBC_TUNABLES` arms and disarms
/// the hardware features a check observes, `MALLOC_CHECK_` and `MALLOC_PERTURB_` change
/// what the heap probes see, `LD_BIND_NOW` makes a lazy binding look eager, and
/// `UBSAN_OPTIONS=log_path=` moves a diagnostic off the stream a detector reads. Clearing
/// covers each of those and the ones nobody has listed yet, and it is what lets
/// [`RunRecord::environment`] be exact without chard reading its own environment, which
/// it does not do beyond `PATH`.
///
/// Each pin has a reason:
///
/// - `LC_ALL=C` pins the wording of every diagnostic a runtime detector matches on, for
///   the reason `compile.rs` gives at length: glibc ships translated messages.
/// - `LIBC_FATAL_STDERR_=1` keeps glibc's fatal messages on stderr on the releases that
///   would otherwise send them to the terminal. In `sysdeps/posix/libc_fatal.c` at the
///   2.28, 2.29 and 2.30 tags, `__libc_message` reads this variable and, when it is
///   unset, opens `/dev/tty` for `*** buffer overflow detected ***` and `*** stack
///   smashing detected ***` (in 2.30 only under the `do_backtrace` action), falling back
///   to file descriptor 2 only when that open fails. A probe run from an interactive
///   terminal on those releases prints its diagnostic to the terminal, the captured
///   stderr is empty, and the fortify and canary detectors read a bare `SIGABRT` they
///   decline to attribute. From the 2.31 tag on, through master, the message goes to
///   `STDERR_FILENO` unconditionally and the variable is never read. The pin is
///   load-bearing on glibc 2.30 and earlier (RHEL 8's 2.28 is in the fixture span),
///   inert from 2.31 on, and harmless on musl and Apple libc, which have no such path.
///
/// A probe that needs something else, a cross-architecture artifact whose `binfmt_misc`
/// interpreter is configured only through `QEMU_LD_PREFIX`, say, fails to run and is
/// recorded as such; the record's `environment` is what explains it.
///
/// One probe needs a variable as part of its question, and declares it rather than
/// receiving it from here: `shadow-stack` runs with
/// `GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK:glibc.malloc.perturb=170`, glibc's opt-in to the x86
/// shadow stack, which glibc 2.39 and later leave off without it, beside a tunable whose effect
/// shows the opt-in reached the C library.
/// A pin on this list would reach every probe, and arming the shadow stack under every
/// runtime probe built with `-fcf-protection` changes the conditions of checks that are
/// not about it; a pin on the probe reaches its own arms and nothing else, and its run
/// records carry it like these two. The pin's reason is on the probe, and `THREAT_MODEL.md`
/// names it beside these, which `tests/register.rs` holds. That probe also
/// starts a second process of its own, the same program with `GLIBC_TUNABLES` removed, so
/// under exactly this list; that is the probe's act rather than chard's, read from its
/// stdout, and `probes/shadow_stack.c` says why (the check's level is what a deployment that
/// sets nothing gets).
pub const PROBE_ENVIRONMENT: &[(&str, &str)] = &[("LC_ALL", "C"), ("LIBC_FATAL_STDERR_", "1")];

/// [`PROBE_ENVIRONMENT`] and the probe's own `pins`, as the map the record carries and the
/// child is given.
///
/// A pin naming a variable this list already sets would replace the list's value for one
/// probe, which is not what a pin is for;
/// `probe::tests::no_probe_pin_restates_the_base_environment` refuses one in the corpus, so
/// the merge here never has to choose.
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
    ///
    /// `true` does not by itself mean the probe was killed: [`execute`] looks once more
    /// before killing, and a probe that exited in that window keeps its real status beside
    /// this flag. Read with `deadline_ms`, the bound it hit.
    pub timed_out: bool,
    /// The deadline this run was held to, in whole milliseconds: `--timeout`, applied to
    /// each probe run on its own.
    ///
    /// Published so that `timed_out` names the bound it hit. Without it a report would carry
    /// the flag and not the bound, and `--timeout` would reach a report only through
    /// `run.invocation`, which does not carry the default. `None` only on a record without
    /// the field, which the replay fixtures are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u128>,
    /// Why an output stream could not be read, when one could not.
    ///
    /// Absent on every healthy run. Present means `stdout` or `stderr` above is empty
    /// because chard failed to read the file, **not** because the probe was silent,
    /// and on the runtime and `compiler-diag` channels those two are opposite
    /// measurements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_error: Option<String>,
    /// Whether a stream hit `MAX_CAPTURE` and lost its tail.
    ///
    /// A detector scanning for a diagnostic that appears late would otherwise read a
    /// truncated stream's silence as the probe's. Consumed through
    /// [`stream_cut`](Self::stream_cut), with `output_error`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(default)]
    pub output_truncated: bool,
    /// Whole milliseconds, so `0` means the probe finished in under a millisecond,
    /// not that it went untimed. Most probes do: before `poll_sleep` backed off
    /// instead of sleeping a flat 2 ms, ten of the thirteen run records in a full
    /// measurement reported exactly the poll interval.
    pub duration_ms: u128,
    /// Every variable the probe received, with its value.
    ///
    /// The complete environment, since [`execute`] clears the ambient one before setting
    /// [`PROBE_ENVIRONMENT`]: a reader re-deriving a runtime verdict runs the artifact
    /// under exactly this map (`env -i LC_ALL=C LIBC_FATAL_STDERR_=1 ./probe`) and has
    /// reproduced the conditions. `None` only on a record made before the field existed,
    /// which the replay fixtures are; a record chard writes today always carries it.
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
    ///
    /// Deliberately separate from [`aborted`](Self::aborted). `__builtin_trap()` is how
    /// fortify-headers signals an overflow, and it is a far weaker signal than an abort
    /// carrying a diagnostic: a compiler-inserted trap for undefined behaviour looks
    /// identical. A caller must establish who owns the trap before reading anything
    /// into it.
    ///
    /// Both signals, because the instruction differs by architecture rather than by who
    /// emitted it: `__builtin_trap()` is `ud2` on x86_64, which raises `SIGILL`, and
    /// `brk` on aarch64, which raises `SIGTRAP`. Matching only `SIGILL` made this
    /// predicate silently architecture-specific; it would miss an aarch64
    /// fortify-headers trap as readily as the Apple one it was first observed to miss.
    ///
    /// Where the probe was built with the fault reporter and its report matches the
    /// signal it died by, the report decides: only a [`Fault::CompilerTrap`] is a trap.
    /// A BTI fault, a PAC authentication failure, an undefined instruction and a report
    /// that could not decide ([`Fault::Undetermined`]) are not. Without a report the bare
    /// signal decides; a probe that does not opt in is unaffected.
    ///
    /// A reading for a probe that opts in must read [`fault`](Self::fault) rather than
    /// this: there `None` means the report the probe was built to write is missing, and
    /// `Undetermined` that it could not decide, and either withholds the reading. This
    /// predicate cannot say which of those it saw.
    pub fn trapped(&self) -> bool {
        match self.fault() {
            Some(fault) => fault == Fault::CompilerTrap,
            None => matches!(self.signal.as_deref(), Some("SIGILL" | "SIGTRAP")),
        }
    }

    /// The fault report a probe built with `CHARD_WANT_FAULT_REPORT` wrote to stderr,
    /// when it wrote one about the signal this record says it died by.
    ///
    /// The last `chard-fault-v1` line counts, since the handler resets itself and so
    /// writes at most one; an earlier one would be a probe printing the prefix itself.
    /// A report whose signal is not the recorded death is about something else (a fault
    /// the probe survived, or a death the handler never saw) and is not returned, so a
    /// mismatch falls back to the bare signal rather than classifying the wrong event.
    /// The numbers are read with this platform's signal table; the reporter emits on
    /// Linux only, where the table is Linux's.
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
    ///
    /// Every runtime decoder reads a marker's absence somewhere: `absent` needs the
    /// survival marker and no diagnostic, the reason for an `indeterminate` falls through
    /// a list of messages, and `cxx-stdlib-assertions` reads the optimisation level from
    /// whether `chard-opt=0` was printed. On a stream that lost its tail, or that chard
    /// could not read at all, a missing marker is chard's silence rather than the probe's.
    /// So a reading over such a record is withheld whatever it was, the way
    /// `report::truncated_reading` withholds a reading over a half-read ELF table:
    /// `measure::withhold_unreadable` replaces the detection before the control triple
    /// sees it, and `report::stream_limitation` names the rule on the measured cell.
    ///
    /// A probe [killed at its deadline](Self::killed_at_deadline) is cut the same way: it
    /// never finished writing, stdout redirected to a file is fully buffered so its
    /// unflushed tail is lost, and a partial last line can parse as a different marker
    /// (`ratio_pct=9` from `ratio_pct=95`), so on such a run a decoder could read a false
    /// `on` as readily as a false `off`. Counting only the capture cap and a failed read,
    /// a killed run printing `null-check=deleted` would read `off`.
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
    ///
    /// A probe that exited in the window between the deadline and the kill keeps its real
    /// status beside `timed_out`, and this reads `false` for it: the probe finished, and
    /// its streams are whole.
    #[must_use]
    pub fn killed_at_deadline(&self) -> bool {
        self.timed_out
            && match self.signal.as_deref() {
                Some(signal) => signal == "SIGKILL",
                None => self.exit_status == -1,
            }
    }

    /// That the run's deadline elapsed, naming the deadline.
    ///
    /// The one spelling a runtime decoder and the `run-deadline-elapsed` gating use for a
    /// timed-out run, so a reader sees the bound beside the fact.
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
    ///
    /// The reader for a `key=value` marker the probe prints on its own line. A substring
    /// search ([`RunRecord::output_contains`]) reads `overflow-guard=ranged` as
    /// `overflow-guard=ran` and `null-check=kept-over` as `null-check=kept`; a token
    /// match does not, and is case-sensitive because the probes print lower-case markers.
    /// Stdout only: every probe that prints a marker prints it there, and stderr carries
    /// the C library's and the compiler runtime's words, which can quote a marker back.
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

/// What a fault report says killed a probe.
///
/// The classes the enforcement checks need kept apart: a trap a compiler or sanitizer
/// planted, a branch-target (BTI) fault, a pointer-authentication (PAC) failure, an
/// undefined instruction that is none of these, and a report that cannot tell. The rules
/// are in [`FaultReport::classify`] and the measurements behind them in
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
///
/// Made only by [`RunRecord::fault_report`], which holds it to the reporter's shape:
/// `sent` agrees with `code`, an aarch64 word fits 32 bits, every field is present once.
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
    /// order `parse` collects them in. `tests/register.rs` holds this list to
    /// the fields the handler in `probes/chard_selfreport.h` writes and to `THREAT_MODEL.md`.
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
    ///
    /// Each rule keys on what the 2026-10-09 measurements showed the kernel delivers
    /// (`probes/chard_selfreport.h` lists them) and on the instruction itself, so a
    /// signal with the right number and the wrong cause is not credited:
    ///
    /// - a sent signal (`si_code` at or below zero) is other, whatever its number.
    /// - aarch64 SIGILL `ILL_ILLOPN` with ESR class 0x1c is a PAC failure.
    /// - aarch64 SIGILL `ILL_ILLOPC` with ESR class 0x0d is a BTI fault, as qemu-user
    ///   reports it. On the hardware measured the kernel writes no ESR record for a BTI
    ///   fault and delivers it exactly as a `udf`, so there a BTI fault needs the probe's
    ///   declared target, and a word that is not a `udf`; undeclared, it reads as an
    ///   illegal instruction.
    /// - aarch64 SIGTRAP `TRAP_BRKPT` at a `brk` word is a compiler trap.
    /// - x86 SIGILL `ILL_ILLOPN` at `ud2`, `ud1` or `ud0` after at most four legacy or
    ///   REX prefixes, or SIGTRAP `SI_KERNEL` (`int3`), is a compiler trap. On i386 the
    ///   reporter reads four bytes, so a trap behind more than two prefixes reads as an
    ///   illegal instruction there.
    /// - a SIGILL or SIGTRAP whose rule needs the instruction bytes, where the reporter
    ///   could not read them, is undetermined: without the bytes a trap and an undefined
    ///   instruction cannot be told apart.
    /// - any other SIGILL is an illegal instruction; everything else is other.
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

/// Signal numbers are per-platform, and only some of them agree.
///
/// 4, 5, 6, 8, 9, 11, 13 and 15 are identical under Linux's asm-generic numbering and the
/// 4.4BSD numbering the Darwin and BSD targets use, which is every signal any predicate
/// in this file keys on, so no verdict turns on the difference. The rest diverge, and
/// silently: Linux's 7 is `SIGBUS` where Darwin's 7 is `SIGEMT`, Linux's 31 is `SIGSYS`
/// where Darwin's 31 is `SIGUSR2`. A single table would not fail on the wrong platform,
/// it would publish a confident wrong *name* into a report field, which is worse than the
/// bare `SIG7` an unmapped number produces.
///
/// Split the way `env.rs::platform_reads` is split, and for the same reason: a new target
/// should be a build failure rather than a silent inheritance of Linux semantics.
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
compile_error!(
    "chard has no signal-number table for this target_os. Add a `signal_name` arm in \
     src/run.rs rather than letting the build fall through to Linux numbering: a run \
     record naming a signal the process did not receive is not a thing chard emits."
);

/// Read one of the probe's output files, capped, reporting what it could not do.
///
/// The empty string is a *measurement* on the runtime channel: "the probe printed
/// nothing" is what a `compiler-diag` or runtime detector reads to decide a verdict, so
/// returning it for a file that could not be opened or read publishes an observation
/// chard never made. This is the same conversion `compile::invoke_with_timeout` refuses
/// twice, with a regression test, one module away.
///
/// Truncation is reported for the same reason and a weaker one: at `MAX_CAPTURE` the
/// tail is gone, and a detector scanning for a diagnostic that appears late would read
/// its absence as absence.
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
/// A timeout is reported as `timed_out` rather than raised as an error: a probe
/// that hangs is a measurement result (`indeterminate`), not a harness failure,
/// and the sweep must continue.
///
/// # Core files
///
/// Several probes work by aborting. On Linux each makes itself non-dumpable first
/// (`CHARD_NOT_DUMPABLE` in `probes/chard_selfreport.h`), so its abort leaves no core.
/// Off Linux, or where that call fails, each abort leaves a core wherever the system
/// collects them. The limit that would stop that is `RLIMIT_CORE`, which can only be set
/// between `fork` and `exec` through `CommandExt::pre_exec`, an `unsafe` hook, and the
/// crate denies `unsafe_code`. A `prlimit --core=0` or `sh -c 'ulimit -c 0; exec ...'`
/// wrapper lowers its own limit and execs the probe in its own process, so chard's child is
/// still the probe and the signal and status it reports are the probe's (measured 2026-10-05
/// on Fedora 44 x86_64, util-linux 2.41.5 `prlimit`, bash 5.3.9 as `sh`; only a shell that
/// runs the probe as a non-final command forks it, and then reports `128+n` for the signal).
/// What a wrapper adds is a program chard did not build in front of every probe, whose own
/// failure to exec the probe reads back as exit status 127, where a failed spawn here is a
/// harness error. So the limit is not set, and `THREAT_MODEL.md` tells the caller: confining
/// a run is the caller's job, and a container or a `core_pattern` the caller controls is
/// where the cores go. `MALLOC_CHECK_=0` does not prevent cores either: its whole effect is
/// on heap consistency checking, and on glibc 2.34 and later even that effect needs
/// `libc_malloc_debug.so` preloaded.
///
/// # Errors
///
/// Errors when the capture files cannot be created or the binary cannot be
/// spawned. A probe that crashes, aborts, or times out is a normal result and
/// is reported in the [`RunRecord`].
///
/// `pins` is the probe's own `run_environment`, set beside [`PROBE_ENVIRONMENT`].
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
    // Every path here is chard's own, and each is tagged `HarnessPath` under its message.
    // `measure::gather` contains what this function returns, so none of these reaches the
    // envelope today; the tag is so that a future caller which does propagate them cannot
    // have the envelope tell an operator to check a path chard constructed.
    let out_file = std::fs::File::create(&out_path)
        .with_context(|| crate::error::HarnessPath(out_path.clone()))
        .context("creating the stdout capture")?;
    let err_file = std::fs::File::create(&err_path)
        .with_context(|| crate::error::HarnessPath(err_path.clone()))
        .context("creating the stderr capture")?;

    // The child's working directory is set to `work`, and execvp resolves the
    // program path *after* that chdir, so a `work`-relative program path would be
    // looked up as `work/work/...` and fail with ENOENT. Absolutize first.
    //
    // This was live: with the default relative `--workdir chard-work`, every
    // runtime probe failed to spawn and the documented `chard measure` invocation
    // produced an error envelope instead of a report. It went unnoticed because
    // every test invocation happened to pass an absolute workdir.
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
        // The probe's whole environment. `PROBE_ENVIRONMENT` says why nothing ambient is
        // let through and why each of these is set; the record below carries the same
        // map, so what the child was given and what the report says it was given cannot
        // differ.
        .env_clear()
        .envs(&environment)
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
            // One more look before killing. The probe may have finished in the window between the
            // `try_wait` above and this comparison, and its real status is worth more than the one
            // this branch would invent; a probe that aborted with `*** buffer overflow detected
            // ***` microseconds before the deadline is a *measurement*, and recording it as
            // `SIGKILL` makes `aborted()` false, drops the fortify detector to `indeterminate`, and
            // on a control arm publishes `probe-invalid` with a `failure_reason` blaming the
            // detector. A loaded sweep host would then read as a chard defect.
            if let Ok(Some(status)) = child.try_wait() {
                break Some(status);
            }
            // Both calls can only fail if the child has already exited, which is
            // the outcome we were trying to bring about.
            crate::error::best_effort(child.kill());
            // Reap, and keep what the kernel says. `wait` returns the real status: the signal
            // that actually ended the process. A hardcoded `SIGKILL` in its place would be a
            // field derived from chard's own request rather than from a measured outcome.
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
        // Only when `wait` itself failed, which means the status is genuinely unknown rather than
        // known to be a kill. `timed_out` carries the fact that the deadline elapsed; that much is
        // measured.
        None => (-1, None),
    };

    // A stream chard could not read is recorded as such rather than as an empty one.
    // Both are attempted before reporting, so one unreadable file does not hide what
    // the other stream said.
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

    /// A clean exit is both halves, and a signal is never one.
    ///
    /// Every runtime detector's `absent` reading rests on this: the probe ran to
    /// completion and printed its survival marker. As a disjunction, a process killed by
    /// a signal with an exit status of 0 (which is how a signalled child is recorded,
    /// `exit_status: -1` notwithstanding on some platforms), would read as having exited
    /// cleanly, and a death would be published as the flag being absent.
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

    /// A record read whole has no cut to name; a capped or unreadable stream does, and
    /// the sentence says which. The timeout note carries the deadline when the record has
    /// one.
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

    /// `execute` publishes the deadline it held the child to.
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

    /// The capture cap reports truncation exactly at the boundary.
    ///
    /// A detector scanning for a diagnostic that appears late reads its absence as the
    /// observable being absent, so a silently truncated stream is a wrong verdict waiting
    /// to happen. The flag must be set when the cap was reached and not when the output
    /// merely came close to it.
    #[test]
    fn truncation_is_reported_at_the_cap_and_not_before() {
        // Named for this test, not just the process: `elf.rs` has a scratch directory
        // under the same `chard-cap-<pid>` name, tests share a process, and the cleanup
        // below deleted that one mid-run the first time this was written.
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

        // Cleanup, and its failure is not a finding: the scratch directory is
        // per-process and the next run makes its own.
        drop(std::fs::remove_dir_all(&dir));
    }

    /// The probe receives the pinned environment and nothing else, and the record says so.
    ///
    /// The probe is a shell script that prints its environment. Run directly, inheriting
    /// this process's environment, it prints `PATH` and `HOME` like every process on the
    /// host; run through `execute` it must not, and that pair is what proves the ambient
    /// environment was cleared rather than that there was nothing to clear. `PWD`,
    /// `SHLVL`, `OLDPWD` and `_` are set by the shell running the script, for itself, and
    /// are the only names allowed past the pinned set.
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

    /// `SIGTRAP` is how `__builtin_trap()` surfaces on aarch64, so a missing entry here
    /// left every trap on that architecture named `SIG5`. A detector matching a name
    /// then cannot match it, and the number is not a name.
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

    /// The trap instruction differs by architecture, not by who emitted it: `ud2` on
    /// x86_64 raises `SIGILL`, `brk` on aarch64 raises `SIGTRAP`. Both are the same
    /// `__builtin_trap()`, so a predicate that recognised only one was reporting the
    /// host architecture rather than the mechanism.
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
            "aarch64 on the M2 guest: gcc trap",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xb93cf0ca09dc addr=0xb93cf0ca09dc word=0xd4207d00 esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on the M2 guest: gcc udf",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xc06a95440a5c addr=0xc06a95440a5c word=0x0 esr=none at-target=undeclared",
            Fault::IllegalInstruction,
        ),
        (
            "aarch64 on the M2 guest: gcc segv",
            "SIGSEGV",
            "chard-fault-v1 signal=11 code=1 sent=no arch=aarch64 pc=0xb300c0560a6c addr=0x8 word=none esr=0x92000044 at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on the M2 guest: gcc jump-unmapped",
            "SIGSEGV",
            "chard-fault-v1 signal=11 code=1 sent=no arch=aarch64 pc=0x10 addr=0x10 word=none esr=0x82000004 at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on the M2 guest: gcc trap-elsewhere",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xb99c3ac509ec addr=0xb99c3ac509ec word=0xd4207d00 esr=none at-target=no",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on the M2 guest: gcc kill",
            "SIGILL",
            "chard-fault-v1 signal=4 code=0 sent=yes arch=aarch64 pc=0xef7f9aa3cd8c addr=0x3e800017c40 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on the M2 guest: gcc raise",
            "SIGILL",
            "chard-fault-v1 signal=4 code=-6 sent=yes arch=aarch64 pc=0xe6be0ca274d8 addr=0x3e800017c47 word=none esr=none at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on the M2 guest: gcc bus",
            "SIGBUS",
            "chard-fault-v1 signal=7 code=2 sent=no arch=aarch64 pc=0xc31961010b18 addr=0xf0122596e000 word=none esr=0x92000007 at-target=undeclared",
            Fault::Other,
        ),
        (
            "aarch64 on the M2 guest: gcc pac",
            "SIGILL",
            "chard-fault-v1 signal=4 code=2 sent=no arch=aarch64 pc=0xb95168ec0cdc addr=0xb95168ec0cdc word=0xd50323bf esr=0x72000000 at-target=undeclared",
            Fault::PacFailure,
        ),
        (
            "aarch64 on the M2 guest: gcc bti-declared",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xe8e60eb4f000 addr=0xe8e60eb4f000 word=0xd28000e0 esr=none at-target=yes",
            Fault::BtiFault,
        ),
        (
            "aarch64 on the M2 guest: gcc bti-undeclared",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0xefd19fd92000 addr=0xefd19fd92000 word=0xd28000e0 esr=none at-target=undeclared",
            Fault::IllegalInstruction,
        ),
        (
            "aarch64 on the M2 guest: clang trap",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xcaa96e590984 addr=0xcaa96e590984 word=0xd4200020 esr=none at-target=undeclared",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on the M2 guest: clang trap-elsewhere",
            "SIGTRAP",
            "chard-fault-v1 signal=5 code=1 sent=no arch=aarch64 pc=0xb8f64a6e0994 addr=0xb8f64a6e0994 word=0xd4200020 esr=none at-target=no",
            Fault::CompilerTrap,
        ),
        (
            "aarch64 on the M2 guest: clang overflow -fsanitize=signed-integer-overflow -fsanitize-trap=signed-integer-overflow",
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
            "aarch64 under qemu-user (emulated): emulated bti-declared",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0x7f2dfcdc1000 addr=0x7f2dfcdc1000 word=0xd28000e0 esr=0x36000002 at-target=yes",
            Fault::BtiFault,
        ),
        (
            "aarch64 under qemu-user (emulated): emulated udf",
            "SIGILL",
            "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0x4006dc addr=0x4006dc word=0x0 esr=0x2000000 at-target=undeclared",
            Fault::IllegalInstruction,
        ),
    ];

    /// Each measured fault classifies as what provoked it, and only the compiler traps
    /// count as [`RunRecord::trapped`]: a BTI fault, a PAC failure and an undefined
    /// instruction all die by SIGILL, which the bare-signal rule reads as a trap.
    #[test]
    fn each_measured_fault_report_classifies_as_what_provoked_it() {
        for (what, signal, line, want) in MEASURED {
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

    /// Every class but `Undetermined` has a measured row; `Undetermined` is the class of
    /// a report the reporter could not complete, which a working reporter never writes,
    /// and it is held by `each_rule_needs_all_of_its_evidence`. The match is exhaustive,
    /// so a new class fails to compile here until it is placed.
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

    /// A probe without the reporter reads as the bare signal says.
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

    /// A report is believed only about the death it describes, and only whole.
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
        let bus = measured("gcc bus");
        assert_eq!(record(-1, Some("SIGBUS"), bus).fault(), Some(Fault::Other));
        assert_eq!(record(-1, Some("SIGSEGV"), bus).fault(), None);
    }

    /// Each rule needs every part of its evidence: change one and the class changes.
    #[test]
    #[allow(
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
        let brk = measured("aarch64 on the M2 guest: gcc trap");
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

    /// A probe's own output of a few KiB is kept whole, and a stream past the cap is cut
    /// and the record says so, whichever stream it was.
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

    /// A probe ended by a signal is recorded as that signal, by name, beside the exit
    /// status that is no status.
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

    /// An aarch64 instruction word is 32 bits: the largest reads, one past it rejects the
    /// line.
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
