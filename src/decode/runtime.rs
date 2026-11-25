// SPDX-License-Identifier: BSD-3-Clause

//! The runtime detectors: each reads what a probe did when it ran, from its exit status,
//! its signal and its two streams.

use std::collections::BTreeMap;

use super::common::{cut_tail, cxx_stdlib, excerpt_tail, marked_region, parse_self_report};
use crate::elf::{ElfFacts, ElfTable};
use crate::probe::{Detection, Evidence};
use crate::report::gating_rule::{self, DetectorRule};
use crate::run::RunRecord;

// --- runtime detectors --------------------------------------------------------

impl Evidence<'_> {
    /// Which library supplied the fortify wrappers for this translation unit, if the
    /// artifact says: `glibc`, `fortify-headers`, `apple`, or `freebsd`.
    pub fn fortify_impl(&self) -> Option<String> {
        // From the artifact's own `.chard.report`, not from `macros`: the driver leaves
        // `macros` empty for a runtime check, and the section is written by the same `cc1`
        // that generated the code, so a spec file cannot make it disagree with the binary.
        let report = match self.elf {
            Some(elf) => elf.self_report.clone(),
            // Bounded to the marker region: a probe's own output shares the stream, and
            // `stack-clash-guard-page` prints `SCPRT dist=8367487 n=66977792`, `name=value`
            // lines that would enter the map as `dist` and `n`.
            None => marked_region(&self.run?.stdout)?,
        };
        match parse_self_report(&report)?
            .get("_FORTIFY_IMPL")
            .map(String::as_str)
        {
            Some("?") | None => None,
            Some(other) => Some(other.to_owned()),
        }
    }
}

/// glibc's fortify diagnostic. Matched as text because the *manner* of abort is
/// what distinguishes fortify from the stack protector and from heap corruption,
/// all of which are `SIGABRT`.
const FORTIFY_MESSAGE: &str = "buffer overflow detected";

/// glibc's own, distinct message for a `%n` in a writable segment. Distinct text is
/// what makes rung 2' an independent witness rather than a second look at rung 2.
const FORTIFY_PERCENT_N_MESSAGES: [&str; 2] = [
    "%n in writable segment detected",
    "%n in writable segments detected",
];
const CANARY_MESSAGE: &str = "stack smashing detected";
const PROBE_SURVIVED: &str = "no-check-fired";

/// Exit statuses the fortify probes reserve for a precondition they could not establish.
const PROBE_EXIT_NO_ALLOCATION: i32 = 77;
/// `fortify_known_object.c`: neither guard array directly follows `dst`, so the bytes
/// the overflow would write are not inside an object the probe declares.
const PROBE_EXIT_LAYOUT: i32 = 78;
/// `fortify_dynamic_object.c`: `malloc_usable_size(dst)` or the position of `src` is not
/// the glibc chunk geometry the probe's safety margin is computed from.
const PROBE_EXIT_HEAP_GEOMETRY: i32 = 79;
/// `fortify_dynamic_object.c`: `__builtin_object_size(dst)` was statically known, so a
/// level-2 build would fire exactly like level 3 and the run cannot separate them.
const PROBE_EXIT_OPACITY_LOST: i32 = 80;

pub(crate) fn detect_fortify_runtime(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let observed = format!(
        "exit={} signal={:?} stderr={:?}",
        run.exit_status,
        run.signal,
        excerpt_tail(ev, &run.stderr, 160)
    );
    if run.aborted() && run.output_contains(FORTIFY_MESSAGE) {
        return Detection::present(None, observed);
    }
    // Two implementations trap with nothing in band: fortify-headers, Alpine's
    // reimplementation, calls `__builtin_trap()` on every overflow branch, 63 of them across
    // its nine headers, and Apple's `__chk_fail_overflow` message reaches a `.ips` report
    // and the unified log, never the probe's streams.
    if run.trapped()
        && let Some(implementation) = ev.fortify_impl()
        && matches!(implementation.as_str(), "fortify-headers" | "apple")
    {
        return Detection::present(None, format!("{observed} ({implementation} trap)"));
    }
    // FreeBSD's wrappers abort with nothing in band: `__chk_fail` writes "buffer overflow
    // detected; terminated" to syslog(3), not to a stream the probe was run with.
    if run.aborted() && ev.fortify_impl().as_deref() == Some("freebsd") {
        let loud = !run.stderr.trim().is_empty();
        let survived = run.output_contains(PROBE_SURVIVED);
        if !loud
            && !survived
            && let Some(symbol) = freebsd_checking_call(ev)
        {
            return Detection::present(
                None,
                format!(
                    "{observed} (FreeBSD's __chk_fail: SIGABRT with nothing on stderr and no \
                     survival marker on stdout, and the artifact calls {symbol})"
                ),
            );
        }
        let why = if loud {
            "stderr carries text, which __chk_fail writes none of".to_owned()
        } else if survived {
            "the probe printed that it survived before it aborted".to_owned()
        } else {
            match ev.elf {
                Some(elf) if elf.symbol_tables.is_empty() => {
                    "the artifact carries no symbol table".to_owned()
                }
                Some(elf) if elf.unread(&[ElfTable::Symbols]).is_some() => {
                    "the artifact's symbol table was not read whole".to_owned()
                }
                Some(elf) => match freebsd_checking_definition(elf) {
                    Some(symbol) => format!(
                        "the artifact defines {symbol} rather than referencing it, a static \
                         link this rule does not read"
                    ),
                    None => "the artifact references no checking function chard watches".to_owned(),
                },
                None => "the artifact was not read".to_owned(),
            }
        };
        return Detection::indeterminate(format!(
            "{observed} (aborted with FreeBSD's wrappers instantiated, but {why}, so the \
             abort is not credited to them)"
        ));
    }
    if run.exited_cleanly() && run.output_contains(PROBE_SURVIVED) {
        return Detection::absent(observed);
    }
    // Anything else means the probe did not measure what it set out to, and is never `off`.
    let timeout = run.timeout_note();
    let why = if run.output_contains(CANARY_MESSAGE) {
        "stack protector fired first"
    } else if run.timed_out {
        timeout.as_str()
    } else if run.exit_status == PROBE_EXIT_NO_ALLOCATION {
        "probe could not allocate"
    } else if run.exit_status == PROBE_EXIT_OPACITY_LOST {
        "the probe found its destination's size statically known to the compiler"
    } else if run.exit_status == PROBE_EXIT_LAYOUT {
        "the probe found no guard object directly after its destination"
    } else if run.exit_status == PROBE_EXIT_HEAP_GEOMETRY {
        "the probe found a heap chunk geometry other than the one its safety margin is computed from"
    } else {
        "unexpected termination"
    };
    Detection::indeterminate(format!("{observed} ({why})"))
}

/// The checking functions FreeBSD's wrappers route a copy through, whose reference the
/// silent-abort credit reads: the `__*_chk` functions, and `__chk_fail`, which a wrapper that
/// checks inline calls directly. A closed list, so a name added to the watch list cannot
/// widen the witness unnoticed; `tests::every_freebsd_checking_call_is_watched` holds each
/// entry to [`crate::elf::WATCHED_SYMBOLS`]. Measured with `nm -u` on FreeBSD
/// 15.1 amd64 (clang 19.1.7): the fortify probes reference `__memcpy_chk` or `__strcpy_chk`,
/// and a `read(2)` into a short buffer `__chk_fail`.
pub(crate) const FREEBSD_CHECKING_CALLS: &[&str] = &[
    "__chk_fail",
    "__memcpy_chk",
    "__memmove_chk",
    "__memset_chk",
    "__strcpy_chk",
    "__strncpy_chk",
    "__strcat_chk",
    "__sprintf_chk",
    "__snprintf_chk",
    "__vsnprintf_chk",
    "__read_chk",
];

/// The first of [`FREEBSD_CHECKING_CALLS`] the artifact references and does not define.
/// `None` where the facts hold no such reference, or where there are no facts.
fn freebsd_checking_call(ev: &Evidence<'_>) -> Option<String> {
    freebsd_checking(ev.elf?, false)
}

/// The first of [`FREEBSD_CHECKING_CALLS`] the artifact holds with the given `defined`.
fn freebsd_checking(facts: &ElfFacts, defined: bool) -> Option<String> {
    FREEBSD_CHECKING_CALLS
        .iter()
        .find(|name| {
            facts
                .watched_symbols
                .get(**name)
                .is_some_and(|f| f.defined == defined)
        })
        .map(|name| (*name).to_owned())
}

/// The first of [`FREEBSD_CHECKING_CALLS`] the artifact defines, if any.
fn freebsd_checking_definition(facts: &ElfFacts) -> Option<String> {
    freebsd_checking(facts, true)
}

/// Markers a C++ standard library prints when a precondition check fires.
pub const CXX_ASSERT_MESSAGES: &[&str] = &["assertion ", "libc++ hardening"];

/// Did a standard-library precondition check fire?
pub(crate) fn detect_cxx_assertions(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    // An unoptimized build is measured too.
    let unoptimized = run.output_contains("chard-opt=0");
    let observed = format!(
        "exit={} signal={:?} optimized={} stderr={:?}",
        run.exit_status,
        run.signal,
        !unoptimized,
        excerpt_tail(ev, &run.stderr, 160)
    );
    // libc++ can signal a hardening failure with `__builtin_trap()`: SIGILL and an empty
    // stderr.
    let libcpp = cxx_stdlib(ev.macros) == Some("libc++");
    if run.trapped() && libcpp {
        return Detection::present(None, format!("{observed} (libc++ hardening trap)"));
    }
    let diagnosed = CXX_ASSERT_MESSAGES.iter().any(|m| run.output_contains(m));
    if run.aborted() && diagnosed {
        return Detection::present(None, observed);
    }
    if run.exited_cleanly() && run.output_contains(PROBE_SURVIVED) {
        return Detection::absent(observed);
    }
    let timeout = run.timeout_note();
    let why = if run.output_contains(CANARY_MESSAGE) {
        "stack protector fired first"
    } else if run.timed_out {
        timeout.as_str()
    } else if run.aborted() {
        "aborted without a standard-library diagnostic"
    } else {
        "unexpected termination"
    };
    Detection::indeterminate(format!("{observed} ({why})"))
}

/// Where the first touch landed, as a percentage of the allocation.
pub(crate) fn detect_stack_clash(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let observed = format!(
        "exit={} signal={:?} out={:?}",
        run.exit_status,
        run.signal,
        stack_clash_excerpt(ev, run)
    );
    let text = &run.stdout;

    if let Some(rest) = text.split("probe-invalid=").nth(1) {
        let why = rest.split_whitespace().next().unwrap_or("unknown");
        return Detection::indeterminate(format!("{observed} (probe declined: {why})"));
    }

    let Some(ratio) = stack_clash_field(text, "ratio_pct=") else {
        return Detection::indeterminate(format!("{observed} (no ratio reported)"));
    };
    let Some(n) = stack_clash_field(text, " n=") else {
        return Detection::indeterminate(format!(
            "{observed} (no distance or size reported beside the ratio)"
        ));
    };
    if n == 0 {
        return Detection::indeterminate(format!(
            "{observed} (fault before the allocation was sized)"
        ));
    }
    if stack_clash_distance_is_normalized(text) {
        // `--normalize` masked the distance after this decoder read it, so the recompute
        // ran when the report was produced and cannot run again.
        if ratio == 0 {
            return Detection::indeterminate(format!(
                "{observed} (ratio 0 beside a normalized distance)"
            ));
        }
    } else {
        let Some(dist) = stack_clash_field(text, "dist=") else {
            return Detection::indeterminate(format!(
                "{observed} (no distance or size reported beside the ratio)"
            ));
        };
        if dist == 0 {
            return Detection::indeterminate(format!(
                "{observed} (first touch at or above the frame)"
            ));
        }
        // u64 times 100 cannot overflow u128, and `n` is not zero here: neither branch of
        // the `checked_` calls is reachable, and neither may become a ratio if it were.
        let Some(recomputed) = u128::from(dist)
            .checked_mul(100)
            .and_then(|x| x.checked_div(u128::from(n)))
        else {
            return Detection::indeterminate(format!("{observed} (ratio not recomputable)"));
        };
        if recomputed != u128::from(ratio) {
            return Detection::indeterminate(format!(
                "{observed} (ratio {ratio}% is not 100 * dist / n = {recomputed}%: the \
                 probe's arithmetic wrapped)"
            ));
        }
    }

    if ratio >= 90 {
        // Affirmative: the first touch was the whole allocation below the frame, so
        // the guard page was skipped.
        Detection::absent(observed)
    } else if ratio <= 50 {
        Detection::present(None, observed)
    } else {
        Detection::indeterminate(format!(
            "{observed} (ratio {ratio}% matches neither a page-walk nor a single \
             subtraction, so the prologue's behaviour is not identifiable)"
        ))
    }
}

/// The first `name` field of the stack-clash probe's stream, as an unsigned integer.
/// Read in 64 bits: a 64-bit probe's `n` exceeds 32 from a `512 MiB` limit up.
fn stack_clash_field(text: &str, name: &str) -> Option<u64> {
    text.split(name)
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|r| r.parse::<u64>().ok())
}

/// Whether the stream's first `dist=` value is exactly `report::NORMALIZED_READING`, the
/// form a `--normalize` report publishes. Exact, so any other non-number still withholds
/// as a missing distance.
fn stack_clash_distance_is_normalized(text: &str) -> bool {
    text.split("dist=")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .is_some_and(|v| v == crate::report::NORMALIZED_READING)
}

/// The stack-clash probe's stream as `observed` quotes it: the probe's own lines
/// (`SCPRT ...`) whole and in order, then the rest of stdout and all of stderr cut to 140
/// characters by [`excerpt_tail`]. A newline stands between the two where the stored
/// stream lost its last one: on Darwin the rest holds the `CHARD-TRANSLATION` line, which
/// would otherwise run into `ratio_pct`.
fn stack_clash_excerpt(ev: &Evidence<'_>, run: &RunRecord) -> String {
    let (probe, other): (Vec<&str>, Vec<&str>) = run
        .stdout
        .split_inclusive('\n')
        .partition(|line| line.starts_with("SCPRT "));
    let mut rest = other.concat();
    rest.push_str(&run.stderr);
    let mut quoted = ev.published(&probe.concat());
    let tail = excerpt_tail(ev, &rest, 140);
    if !quoted.is_empty() && !quoted.ends_with('\n') && !tail.is_empty() {
        quoted.push('\n');
    }
    quoted.push_str(&tail);
    quoted
}

/// What the three fill bytes came back as.
enum FillReading {
    /// All three shapes read the same byte.
    Uniform(u8),
    /// The shapes disagreed, which is absence. It carries no per-byte guess at a fill:
    /// uninitialized garbage holds a 0x00 often enough that gcc's negative arm would go
    /// indeterminate at random.
    Mixed,
    /// The compiler has no `__attribute__((uninitialized))` (`ctrl_supported=0`), so `ctrl`
    /// witnesses nothing, and the shapes did not all read the dirt back, the one reading that
    /// would witness the frame's reuse. Any other, a zero fill above all, is what a frame never
    /// dirtied reads too, so it is withheld. The line, for the reason.
    Unwitnessed(String),
}

/// The fields of the `TAVI` line the decoder requires, by name: the three shapes, then the
/// witness and whether the compiler could opt it out. The probe's `printf` is held to them.
pub(crate) const TAVI_FIELDS: [&str; 5] = ["arr", "word", "small", "ctrl", "ctrl_supported"];

fn auto_var_init_fill(run: &RunRecord) -> Option<FillReading> {
    let line = run.stdout.lines().find(|l| l.starts_with("TAVI "))?;
    let [arr, word, small, ctrl_name, supported_name] = TAVI_FIELDS;

    let mut fields = BTreeMap::new();
    for field in line.split_whitespace().skip(1) {
        if let Some((name, value)) = field.split_once('=') {
            fields.insert(name, value);
        }
    }

    // The witness is required: the live probe always prints `ctrl` and `ctrl_supported`, so
    // a line without either is not its line.
    let supported = match *fields.get(supported_name)? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let ctrl = u8::from_str_radix(fields.get(ctrl_name)?, 16).ok()?;
    if supported && ctrl != AUTO_VAR_INIT_DIRT {
        return None;
    }

    let mut bytes = Vec::new();
    for name in [arr, word, small] {
        bytes.push(u8::from_str_radix(fields.get(name)?, 16).ok()?);
    }
    if !supported && bytes.iter().any(|b| *b != AUTO_VAR_INIT_DIRT) {
        return Some(FillReading::Unwitnessed(line.trim_end().to_owned()));
    }

    let first = *bytes.first()?;
    if bytes.iter().all(|b| *b == first) {
        return Some(FillReading::Uniform(first));
    }
    Some(FillReading::Mixed)
}

/// The dirt byte `dirty()` writes. Surviving it is positive evidence that nothing
/// initialized the variable.
const AUTO_VAR_INIT_DIRT: u8 = 0x5A;
/// gcc's `=pattern` byte, on every target measured: every type in the frame reads `0xFE`
/// under gcc 16.1.1 on x86_64 and, on i386, gcc 12.2.0 (Debian 12 i386) and gcc 16.2.1
/// `-m32` (`fedora:44`), at -O0, -O1 and -O2.
const AUTO_VAR_INIT_GCC_PATTERN: u8 = 0xFE;
/// clang's `=pattern` byte for integers and pointers on a target with 64-bit pointers.
const AUTO_VAR_INIT_CLANG_PATTERN_64: u8 = 0xAA;
/// clang's `=pattern` byte on a target whose pointers are narrower than 64 bits.
const AUTO_VAR_INIT_CLANG_PATTERN_32: u8 = 0xFF;

/// Whether `byte`, read uniformly from all three shapes, is a `=pattern` fill for the
/// target the artifact was built for, or `None` where that cannot be told.
fn pattern_fill(byte: u8, elf: Option<&ElfFacts>) -> Option<bool> {
    if byte == AUTO_VAR_INIT_GCC_PATTERN {
        return Some(true);
    }
    if byte != AUTO_VAR_INIT_CLANG_PATTERN_32 && byte != AUTO_VAR_INIT_CLANG_PATTERN_64 {
        return Some(false);
    }
    match elf.map(|e| e.elf_class) {
        Some(32) => (byte == AUTO_VAR_INIT_CLANG_PATTERN_32).then_some(true),
        // A Mach-O artifact, or an unread header, is held to the 64-bit byte.
        Some(64) | None => (byte == AUTO_VAR_INIT_CLANG_PATTERN_64).then_some(true),
        Some(_) => None,
    }
}

/// The detection for a clang pattern byte [`pattern_fill`] cannot place on this artifact.
fn unplaced_fill(byte: u8, elf: Option<&ElfFacts>) -> Detection {
    Detection::indeterminate(match elf {
        None => format!("fill=0x{byte:02x} is clang's pattern on a 32-bit target"),
        Some(e) => format!(
            "fill=0x{byte:02x} is clang's pattern on another pointer width than an ELFCLASS{} artifact's",
            e.elf_class
        ),
    })
}

/// Which trailing-array spellings are still treated as flexible members.
pub(crate) fn detect_strict_flex_arrays(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let read = |key: &str| -> Option<i64> {
        run.stdout
            .split_whitespace()
            .find_map(|f| f.strip_prefix(key)?.parse().ok())
    };
    let (Some(two), Some(one), Some(zero)) =
        (read("flex-two="), read("flex-one="), read("flex-zero="))
    else {
        return Detection::indeterminate(format!(
            "no flex-array readings in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 80),
            run.exit_status,
            run.signal
        ));
    };
    // A declaration is bounded when the query answers with its own declared size.
    let observed = format!("bos1: [2]={two} [1]={one} [0]={zero}");
    // `-1` is `__builtin_object_size` saying it could not determine a size, not that the
    // array is unbounded, so reading it as level 0 would report the flag off for a build
    // that set it.
    if two < 0 || one < 0 || zero < 0 {
        let said = |field: &str| run.stdout.split_whitespace().any(|f| f == field);
        let cause = if said("storage=declared") {
            if said("optimize=no") {
                "the build was not optimized"
            } else if said("optimize=yes") {
                "the build was optimized and the objects are declared"
            } else {
                "the probe did not report whether the build was optimized"
            }
        } else if said("optimize=no") {
            "the build was not optimized"
        } else if said("optimize=yes") {
            "the build was optimized, so the compiler could not bound the allocation"
        } else {
            "the probe did not report whether the build was optimized"
        };
        let reason =
            format!("{observed}: __builtin_object_size could not determine a size; {cause}");
        return if said("optimize=no") {
            Detection::withheld(UNOPTIMIZED_BUILD_CANNOT_SHOW, reason)
        } else {
            Detection::indeterminate(reason)
        };
    }
    let level = match (two == 2, one == 1, zero == 0) {
        (true, true, true) => "3",
        (true, true, false) => "2",
        (true, false, false) => "1",
        (false, false, false) => "0",
        // Bounded at a wider spelling than a narrower one cannot describe any level:
        // the flag exempts spellings in one order and nothing produces the reverse.
        _ => {
            return Detection::indeterminate(format!(
                "{observed}: no -fstrict-flex-arrays level produces this combination"
            ));
        }
    };
    if level == "0" {
        Detection::absent(format!("{observed} (every trailing array is flexible)"))
    } else {
        Detection::present(Some(level), observed)
    }
}

/// The marker `probes/strict_flex_arrays_enforced.c` writes to stderr around each row.
const SFA_ENFORCED_MARKER: &str = "CHARD-SFA-ENFORCED";

/// The probe's rows, in the order it runs them: the witness first, then the three
/// trailing spellings from widest to narrowest, then the true flexible member.
const SFA_ENFORCED_ROWS: [&str; 5] = ["ctrl", "two", "one", "zero", "flex"];

/// What one row's child did with its overflowing copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowOutcome {
    /// A fortified copy stopped it: SIGABRT with glibc's diagnostic between the row's own
    /// markers, a trap from an implementation the self-report names, or FreeBSD's silent
    /// `__chk_fail` abort.
    Caught,
    /// The child copied and exited 0, and nothing was written between its markers.
    Survived,
}

/// One row's outcome, read from the stderr between its begin and end markers, or the
/// reason it cannot be read.
fn sfa_enforced_row(ev: &Evidence<'_>, stderr: &str, row: &str) -> Result<RowOutcome, String> {
    let begin = format!("{SFA_ENFORCED_MARKER} begin row={row}\n");
    let end = format!("{SFA_ENFORCED_MARKER} end row={row} status=");
    let Some((_, after_begin)) = stderr.split_once(&begin) else {
        return Err(format!("row {row} has no begin marker"));
    };
    // Between the markers is what the child, and only the child, wrote: the parent writes
    // the end marker after waiting for it.
    let Some((segment, rest)) = after_begin.split_once(&end) else {
        return Err(format!("row {row} has no end marker"));
    };
    // The rest of the end marker's line; a stream that ends on the marker has no newline
    // after it, and the whole remainder is then that line.
    let status = rest.split_once('\n').map_or(rest, |(line, _)| line).trim();
    let diagnosed = segment.to_lowercase().contains(FORTIFY_MESSAGE);
    // 4, 5 and 6 are SIGILL, SIGTRAP and SIGABRT under both Linux's numbering and the BSD
    // one Darwin uses.
    match status {
        "signal:6" if diagnosed => Ok(RowOutcome::Caught),
        // A trap is credited only where the self-report names an implementation that traps,
        // for the reason `detect_fortify_runtime` gives.
        "signal:4" | "signal:5"
            if ev
                .fortify_impl()
                .is_some_and(|i| matches!(i.as_str(), "fortify-headers" | "apple")) =>
        {
            Ok(RowOutcome::Caught)
        }
        // A silent abort is FreeBSD's `__chk_fail` where its wrappers instantiated, the
        // artifact calls a checking function and the row's child wrote nothing, for the
        // reason `detect_fortify_runtime` gives.
        "signal:6"
            if segment.trim().is_empty()
                && ev.fortify_impl().as_deref() == Some("freebsd")
                && freebsd_checking_call(ev).is_some() =>
        {
            Ok(RowOutcome::Caught)
        }
        "exit:0" if segment.trim().is_empty() => Ok(RowOutcome::Survived),
        _ => Err(format!(
            "row {row} ended {status:?} with {:?} between its markers",
            cut_tail(&ev.published(segment.trim()), 120)
        )),
    }
}

/// The settled fortify level of a glibc build, from the probe's own self-report, where it is
/// below 2: `__USE_FORTIFY_LEVEL`, which glibc's `<features.h>` defines in every build.
/// `None` where the report is missing, names no glibc, gives no readable level, or the level
/// is 2 or more.
fn glibc_fortify_below_two(ev: &Evidence<'_>) -> Option<u32> {
    let report = match ev.elf {
        Some(elf) => Some(elf.self_report.clone()),
        None => ev.run.and_then(|run| marked_region(&run.stdout)),
    }?;
    let fields = parse_self_report(&report)?;
    fields.get("__GLIBC__")?;
    let level = fields.get("__USE_FORTIFY_LEVEL")?.parse::<u32>().ok()?;
    (level < 2).then_some(level)
}

/// The C library, where the build's self-report says fortify was requested at 2 or more and
/// the library is one with no subobject bound: no glibc (`__GLIBC__` undefined), and either
/// fortify-headers, which sizes every destination as a whole object, FreeBSD's
/// `<ssp/string.h>`, whose `strcpy` wrapper does the same (`__ssp_bos0`; measured on 15.1,
/// where the `ctrl` row survives at every level), or no fortify implementation
/// (`_FORTIFY_IMPL` undefined) on a library the probe's `libc=` line names as musl,
/// OpenBSD's or FreeBSD's before 15.0: the three `libc_unsupported` lists on this check.
fn library_without_subobject_bounds(ev: &Evidence<'_>, stdout: &str) -> Option<&'static str> {
    let report = match ev.elf {
        Some(elf) => Some(elf.self_report.clone()),
        None => ev.run.and_then(|run| marked_region(&run.stdout)),
    }?;
    // `parse_self_report` leaves out every field the report gave as undefined, and the report
    // between its markers carries every field, so a key missing here is one the compiler
    // did not define.
    let fields = parse_self_report(&report)?;
    let requested = fields
        .get("_FORTIFY_SOURCE")
        .and_then(|level| level.parse::<u32>().ok())
        .is_some_and(|level| level >= 2);
    if !requested || fields.contains_key("__GLIBC__") {
        return None;
    }
    // `_FORTIFY_IMPL` undefined means the self-report did not recognise the implementation, not
    // that there is none, so it is not enough alone: a library that checks subobject bounds
    // but is not one `chard_selfreport.h` names (bionic) prints `libc=?`, and its silent ctrl
    // row is withheld.
    let libc = stdout
        .split_whitespace()
        .find_map(|field| field.strip_prefix("libc="));
    match (fields.get("_FORTIFY_IMPL").map(String::as_str), libc) {
        (Some("fortify-headers"), _) => Some("fortify-headers"),
        (Some("freebsd"), _) => Some("FreeBSD's <ssp/string.h>"),
        (None, Some("musl")) => Some("musl without fortify-headers"),
        (None, Some("openbsd")) => Some("OpenBSD's libc"),
        // No wrapper named on a FreeBSD below 15 is a release whose headers carry no
        // <ssp/ssp.h> (measured on 14.5); on 15 or later it is a build whose wrappers did not
        // instantiate or whose headers were not reached, and its silence is withheld.
        (None, Some("freebsd"))
            if fields
                .get("__FreeBSD__")
                .and_then(|major| major.parse::<u32>().ok())
                .is_some_and(|major| major < 15) =>
        {
            Some("FreeBSD's libc below 15, whose headers carry no <ssp/ssp.h>")
        }
        _ => None,
    }
}

/// Which trailing-array spellings a fortified copy enforces a bound on.
pub(crate) fn detect_strict_flex_arrays_enforced(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let mut caught = [false; SFA_ENFORCED_ROWS.len()];
    for (slot, row) in caught.iter_mut().zip(SFA_ENFORCED_ROWS) {
        match sfa_enforced_row(ev, &run.stderr, row) {
            Ok(outcome) => *slot = outcome == RowOutcome::Caught,
            Err(why) => {
                return Detection::indeterminate(format!(
                    "{why} (exit={} signal={:?})",
                    run.exit_status, run.signal
                ));
            }
        }
    }
    if !run.exited_cleanly() {
        return Detection::indeterminate(format!(
            "every row was read, and the probe itself ended exit={} signal={:?} rather than \
             exiting 0 after its last row",
            run.exit_status, run.signal
        ));
    }
    let observed = SFA_ENFORCED_ROWS
        .iter()
        .zip(caught)
        .map(|(row, c)| format!("{row}={}", if c { "caught" } else { "survived" }))
        .collect::<Vec<_>>()
        .join(" ");
    let [ctrl, two, one, zero, flex] = caught;
    if !ctrl {
        return sfa_enforced_ctrl_survived(ev, run, &observed, [two, one, zero, flex]);
    }
    if flex {
        return Detection::indeterminate(format!(
            "{observed}: the flex row, a true flexible member no level bounds, was caught"
        ));
    }
    let level = match (two, one, zero) {
        (true, true, true) => "3",
        (true, true, false) => "2",
        (true, false, false) => "1",
        (false, false, false) => "0",
        // The levels exempt spellings in one order, so a narrower spelling enforced while
        // a wider one is not describes none of them.
        _ => {
            return Detection::indeterminate(format!(
                "{observed}: no -fstrict-flex-arrays level enforces this combination"
            ));
        }
    };
    if level == "0" {
        Detection::absent(format!(
            "{observed} (the ctrl copy was caught and no trailing-array copy was)"
        ))
    } else {
        Detection::present(Some(level), observed)
    }
}

/// The reading of a run whose `ctrl` copy survived: nothing in the build checked the one bound
/// every level sets, so the trailing rows cannot show the flag, and what is published is why.
/// `two`, `one`, `zero` and `flex` are the trailing rows' outcomes.
fn sfa_enforced_ctrl_survived(
    ev: &Evidence<'_>,
    run: &RunRecord,
    observed: &str,
    [two, one, zero, flex]: [bool; 4],
) -> Detection {
    // A trailing row caught beside a silent ctrl row is no build that checks no subobject
    // bound, whatever the library or the line says: it is withheld below.
    let none_caught = !(two || one || zero || flex);
    let said = |field: &str| run.stdout.split_whitespace().any(|f| f == field);
    if none_caught
        && said("optimize=yes")
        && let Some(library) = library_without_subobject_bounds(ev, &run.stdout)
    {
        return Detection::absent(format!(
            "{observed}: _FORTIFY_SOURCE of 2 or more was requested in an optimized build under {library}"
        ));
    }
    // The run's `CHARD-BOS` line: the ctrl member bounded at the call site and the whole
    // object inside the always-inline wrapper form, with glibc's string wrappers in and its
    // clang path not taken, is glibc's `strcpy` wrapper losing the bound (clang 18.1.3 and
    // 21.1.8 with glibc 2.39).
    let witness = crate::report::SubobjectSizes::parse(&run.stdout);
    if none_caught
        && said("optimize=yes")
        && let Some((sizes, line)) = witness
        && sizes.lost_in_wrapper()
    {
        return Detection::absent(format!(
            "{observed}: `{line}`: the compiler bounds the ctrl member at the call site and answers the whole object inside an always-inline function"
        ));
    }
    // An optimized glibc build whose own self-report settles fortify below 2: glibc's
    // wrappers check no subobject bound there, so the rows cannot show the flag in this
    // build (`bare-optimized`, which requests no fortify level).
    if none_caught
        && said("optimize=yes")
        && let Some(level) = glibc_fortify_below_two(ev)
    {
        return Detection::withheld(
            FORTIFY_BELOW_SUBOBJECT_LEVEL,
            format!(
                "{observed}: the build is optimized and glibc settled its fortify level at __USE_FORTIFY_LEVEL={level}, below 2"
            ),
        );
    }
    let cause = if said("optimize=no") {
        "the build was not optimized"
    } else if witness.is_none() {
        "the build checks no subobject bound, and the run printed no complete CHARD-BOS line"
    } else {
        "the build checks no subobject bound"
    };
    let reason = format!(
        "{observed}: the ctrl copy, past a member every -fstrict-flex-arrays level bounds, was not caught, so {cause}"
    );
    if said("optimize=no") {
        Detection::withheld(UNOPTIMIZED_BUILD_CANNOT_SHOW, reason)
    } else {
        Detection::indeterminate(reason)
    }
}

/// Did the guard the optimizer would otherwise delete survive?
pub(crate) fn detect_no_strict_overflow(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    if run.has_marker("overflow-guard=ran") {
        // A sanitizer reports on stderr when it takes the addition, and the control arms
        // never carry it, so they discriminate over a cell the sanitizer produced (clang
        // 22.1.8, Fedora 44 x86_64: `-O2 -fsanitize=undefined` read `on` with this report on
        // stderr, and `-O2` alone read `off`).
        let stderr_lines = run
            .stderr
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with(QEMU_SIGNAL_REPORT))
            .count();
        if stderr_lines > 0 {
            return Detection::withheld(
                GUARD_KEPT_WITHOUT_THE_FLAG,
                format!(
                    "the overflow guard ran beside output on stderr ({:?})",
                    excerpt_tail(ev, &run.stderr, 120)
                ),
            );
        }
        if !run.has_marker("optimize=yes") {
            return unoptimized_guard_ran(run);
        }
        if run.has_marker("frontend=gcc") {
            match gcc_major(run) {
                Some(Ok(major)) if major >= GCC_FOLDS_UNOPTIMIZED_FROM => {}
                Some(Ok(major)) => return optimized_guard_ran_before_8(ev, Some(major)),
                Some(Err(_)) | None => return optimized_guard_ran_before_8(ev, None),
            }
        }
        Detection::present(None, "the overflow guard survived and fired".to_owned())
    } else if run.has_marker("overflow-guard=deleted") {
        Detection::absent("the overflow guard was folded away".to_owned())
    } else {
        Detection::indeterminate(format!(
            "no guard reading in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 80),
            run.exit_status,
            run.signal
        ))
    }
}

/// The first gcc major version that folds the overflow guard at `-O0` without
/// the flag: measured 8.3.0 folding it and 7.5.0 keeping it, with 8.1 and 8.2 unmeasured
/// ([`detect_no_strict_overflow`] has the runs).
const GCC_FOLDS_UNOPTIMIZED_FROM: u32 = 8;

/// The rule every withholding of a guard that ran names, as the detector's rule: a `const`,
/// so a rule of another stage is a compile error here ([`DetectorRule::of`]).
const GUARD_KEPT_WITHOUT_THE_FLAG: DetectorRule =
    DetectorRule::of(gating_rule::GUARD_KEPT_WITHOUT_THE_FLAG);

/// The rule a reading withheld because the measured build was not optimized names, where the
/// observable does not depend on the flag without optimization
/// ([`gating_rule::UNOPTIMIZED_BUILD_CANNOT_SHOW`]).
const UNOPTIMIZED_BUILD_CANNOT_SHOW: DetectorRule =
    DetectorRule::of(gating_rule::UNOPTIMIZED_BUILD_CANNOT_SHOW);

/// The rule `strict-flex-arrays-enforced` names where the measured build's settled fortify level
/// is below 2 ([`gating_rule::FORTIFY_BELOW_SUBOBJECT_LEVEL`]).
const FORTIFY_BELOW_SUBOBJECT_LEVEL: DetectorRule =
    DetectorRule::of(gating_rule::FORTIFY_BELOW_SUBOBJECT_LEVEL);

/// The rule `zero-init-padding-bits` names where its control did not read the dirt back
/// ([`gating_rule::FRAME_REUSE_DID_NOT_HOLD`]).
const FRAME_REUSE_DID_NOT_HOLD: DetectorRule =
    DetectorRule::of(gating_rule::FRAME_REUSE_DID_NOT_HOLD);

/// The probe's `gcc-major=` value: the last line carrying the key, as `detect_trapv` reads
/// its markers, and `None` where no line does. A value that is not a number is no version,
/// and an earlier line is not consulted in its place.
fn gcc_major(run: &RunRecord) -> Option<Result<u32, std::num::ParseIntError>> {
    run.stdout.lines().rev().find_map(|l| {
        l.trim()
            .strip_prefix("gcc-major=")
            .map(|v| v.split_whitespace().next().unwrap_or("").parse::<u32>())
    })
}

/// The optimization levels at which gcc before 8 folds the overflow guard without the
/// flag, as the compile line spells them: `-O2` and `-Os` measured on gcc 4.8.4, 5.4.0 and
/// 7.5.0, `-O3` and `-Ofast` on 7.5.0 ([`detect_no_strict_overflow`] has the runs). A
/// guard that ran at one of these on such a gcc was kept by the flag.
const GCC_BEFORE_8_FOLDING_LEVELS: [&str; 4] = ["-O2", "-O3", "-Os", "-Ofast"];

/// The optimizing levels at which gcc before 8 keeps the guard without the flag: `-O`
/// (gcc's `-O1`), measured on gcc 7.5.0, and `-O1` and `-Og`, measured on gcc 4.8.4, 5.4.0
/// and 7.5.0 ([`detect_no_strict_overflow`] has the runs). A guard that ran at one of these
/// says nothing about the flag.
const GCC_BEFORE_8_KEEPING_LEVELS: [&str; 3] = ["-O", "-O1", "-Og"];

/// A level word as gcc reads it: `--optimize` is `-O` and `--optimize=X` is `-OX` (gcc
/// 7.5.0 ran the guard under `-O2 --optimize=1` and `-O2 --optimize`, and folded it under
/// `-O1 --optimize=2`, `--optimize=3`, `--optimize=s` and `--optimize=fast`), an
/// abbreviation of the long name from `--op` the same (gcc's driver completes `--opti` to
/// `--optimize`, and 7.5.0 ran the guard under `-O2 --opti`; one it rejects never builds);
/// any other word is itself. The reading is the one classifier's
/// (`toolchain::LONG_ALIASES`, which has the bound as gcc 16.1.1 measured it).
fn level_as_gcc_reads(word: &str) -> String {
    crate::toolchain::spelled_alone(word).into_owned()
}

/// Whether a compile word lets a file chard did not read set the level after the line's last
/// `-O` word:
fn can_reset_the_level(word: &str) -> bool {
    word.starts_with("-specs")
        || word.starts_with("-B")
        || word.starts_with("-fplugin")
        || word == "-wrapper"
        || forces_a_header(word)
        || word.strip_prefix("-Wp,").is_some_and(|list| {
            list.split(',')
                .any(|piece| can_reset_the_level(&crate::toolchain::spelled_alone(piece)))
        })
}

/// Whether `word`, as gcc's driver or its `cc1` reads it, forces a header or a macro file
/// in: `-include` or `-imacros`, joined or alone, in gcc's long and abbreviated spellings.
fn forces_a_header(word: &str) -> bool {
    let word = crate::toolchain::spelled_alone(word);
    word.starts_with("-include") || word.starts_with("-imacros")
}

/// The first word of a compile line through which a file chard did not read can set the
/// level ([`can_reset_the_level`]), as the line spells it. The line is walked by the one
/// classifier (`toolchain::read`), so a word another takes with it is passed over (`-u -B`
/// names a symbol, `-Xlinker -specs=f` is the linker's word), and the word `-Xpreprocessor`
/// hands `cc1`, or clang applies for one architecture, is named where it resets.
fn level_resetting_word(words: &[String]) -> Option<&str> {
    use crate::toolchain::{Hand, read};
    let mut i = 0;
    while let Some(word) = words.get(i) {
        let next = words.get(i.saturating_add(1)).map(String::as_str);
        let reading = read(word, next);
        let resets = match reading.hand {
            Hand::Driver | Hand::Value => can_reset_the_level(&reading.word),
            // `cc1` loads a plugin handed to it through `-Xpreprocessor` (gcc 16.1.1 on
            // Fedora 44 x86_64, 2026-10-28 UTC: `cc1: error: cannot load plugin` under
            // `-Xpreprocessor -fplugin=/nonexistent/p.so`) and reads a forced include
            // there; a specs or prefix word handed to it fails the build anyway.
            Hand::Preprocessor | Hand::Arch => {
                if let Some(handed) = next
                    .filter(|handed| can_reset_the_level(&crate::toolchain::spelled_alone(handed)))
                {
                    return Some(handed);
                }
                false
            }
            Hand::Tool => false,
        };
        if resets {
            return Some(word);
        }
        i = i.saturating_add(reading.span());
    }
    None
}

/// The reading of a guard that ran, silently, in a build the probe reports as optimized on
/// a gcc before [`GCC_FOLDS_UNOPTIMIZED_FROM`], or on a gcc whose major version the probe
/// did not report (`None`): `on` only where the build's own compile line names a level at
/// which that gcc folds the guard without the flag.
fn optimized_guard_ran_before_8(ev: &Evidence<'_>, major: Option<u32>) -> Detection {
    let who = major.map_or_else(
        || "a gcc that reported no readable major version".to_owned(),
        |major| format!("gcc {major}"),
    );
    let keeps = "gcc 4.8, 5.4 and 7.5 keep it at -O, -O1 and -Og without the flag";
    let Some(build) = ev.build else {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the overflow guard ran in an optimized build on {who} with no build record to read the level from; {keeps}"
            ),
        );
    };
    // chard's own forced include, the run-witness header, holds a note and no pragma; left
    // in, every build would carry such a word and this reading would withhold on each.
    let words = build.argv.split_first().map_or(&[][..], |(_, flags)| flags);
    let words = crate::compile::without_witness_words(words);
    if let Some(word) = level_resetting_word(&words) {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the overflow guard ran in an optimized build on {who} whose compile line carries \
             {word}, through which a file chard did not read can set the level after the \
             line's last -O word (a specs file appending -O1 under -O2, named by -specs or \
             found in a -B prefix, and a forced include carrying `#pragma GCC optimize \
             (\"O1\")`, each ran the guard on gcc 7.5.0 without the flag); {keeps}, so this \
             build cannot answer the question"
            ),
        );
    }
    let Some(word) = crate::compile_inputs::optimization_words(&words).pop() else {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the overflow guard ran in an optimized build on {who} whose compile line carries no -O word, so the level came from outside the words chard passed (a specs or configuration file, or a wrapper); {keeps}"
            ),
        );
    };
    let level = level_as_gcc_reads(&word);
    let spelled = if level == word {
        word.clone()
    } else {
        format!("{word} (gcc's {level})")
    };
    if GCC_BEFORE_8_FOLDING_LEVELS.contains(&level.as_str()) {
        return Detection::present(
            None,
            format!("the overflow guard survived and fired, on {who} at {spelled}"),
        );
    }
    if GCC_BEFORE_8_KEEPING_LEVELS.contains(&level.as_str()) {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!("the overflow guard ran in a build at {spelled} on {who}: {keeps}"),
        );
    }
    if level == "-O0" {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the overflow guard ran on {who} in a build the probe reports as optimized while the compile line's last -O word is {spelled}, so the build was compiled at a level chard's words did not set; {keeps}"
            ),
        );
    }
    Detection::withheld(
        GUARD_KEPT_WITHOUT_THE_FLAG,
        format!(
            "the overflow guard ran in a build at {spelled} on {who}, a level not measured on gcc before 8"
        ),
    )
}

/// The reading of a guard that ran, silently, in a build the probe reports as not
/// optimized: `on` only where the compiler would have folded it without the flag.
fn unoptimized_guard_ran(run: &RunRecord) -> Detection {
    if run.has_marker("frontend=clang") {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            "the guard ran in a build that was not optimized".to_owned(),
        );
    }
    if !run.has_marker("frontend=gcc") {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            "the guard ran in a build that was not optimized".to_owned(),
        );
    }
    match gcc_major(run) {
        Some(Ok(major)) if major >= GCC_FOLDS_UNOPTIMIZED_FROM => Detection::present(
            None,
            format!(
                "the overflow guard survived and fired in a build that was not optimized, \
                 on gcc {major}, and gcc folds it at -O0 without the flag from gcc \
                 {GCC_FOLDS_UNOPTIMIZED_FROM} on"
            ),
        ),
        Some(Ok(major)) => Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the guard ran in a build that was not optimized, on gcc {major}: gcc 4.8, 5.4 and 7.5 keep it whether or not the flag was passed, and only gcc {GCC_FOLDS_UNOPTIMIZED_FROM} and later are known to fold it at -O0"
            ),
        ),
        Some(Err(_)) | None => Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the guard ran in a build that was not optimized, on a gcc that reported no readable major version, and only gcc {GCC_FOLDS_UNOPTIMIZED_FROM} and later fold it at -O0 without the flag"
            ),
        ),
    }
}

/// Did the null check survive the dereference that preceded it?
pub(crate) fn detect_no_delete_null_checks(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    if run.has_marker("null-check=kept") {
        Detection::present(None, "the null check survived the dereference".to_owned())
    } else if run.has_marker("null-check=deleted") {
        Detection::absent("the null check was deleted".to_owned())
    } else if run.has_marker("optimize=no")
        && matches!(run.signal.as_deref(), Some("SIGSEGV" | "SIGBUS"))
    {
        // An unoptimized build that died of a memory fault: the build, not the flag.
        Detection::withheld(
            UNOPTIMIZED_BUILD_CANNOT_SHOW,
            format!(
                "the build was not optimized and the probe died (signal={:?})",
                run.signal
            ),
        )
    } else {
        Detection::indeterminate(format!(
            "no null-check reading in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 80),
            run.exit_status,
            run.signal
        ))
    }
}

/// Was the store through the incompatible pointer observed?
pub(crate) fn detect_no_strict_aliasing(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    // Read from the probe's own output, not from `ev.macros`: that map is populated
    // only for probes carrying a macro-channel check, and this one is runtime-only.
    if run.has_marker("optimize=no") {
        return Detection::withheld(
            UNOPTIMIZED_BUILD_CANNOT_SHOW,
            "compiled without optimization".to_owned(),
        );
    }
    let o2_observed = run.has_marker("o2-witness=observed");
    if run.has_marker("aliasing-store=observed") {
        if run.has_marker("uninstrumented-store=lost") {
            return Detection::indeterminate(
                "the store through the incompatible pointer was observed".to_owned(),
            );
        }
        aliasing_store_observed(run, o2_observed)
    } else if run.has_marker("aliasing-store=lost") {
        if run.has_marker("uninstrumented-store=observed") {
            return Detection::indeterminate("the store was lost in the build".to_owned());
        }
        if o2_observed {
            return Detection::indeterminate("the store was lost in the build".to_owned());
        }
        Detection::absent("the store was not observed".to_owned())
    } else {
        Detection::indeterminate(format!(
            "no aliasing reading in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 80),
            run.exit_status,
            run.signal
        ))
    }
}

/// An observed store, credited to the flag only where a witness separates it from the
/// level. [`detect_no_strict_aliasing`] carries the argument.
fn aliasing_store_observed(run: &RunRecord, o2_observed: bool) -> Detection {
    let observed = "the store through the incompatible pointer was observed";
    let no_witness = !run.has_marker_key("o2-witness=");
    if no_witness || run.has_marker("o2-witness=not-built") {
        return Detection::present(None, observed.to_owned());
    }
    if !run.has_marker("attribute-check=honoured") {
        return Detection::indeterminate(format!(
            "{observed}, and the copy compiled under optimize(\"O2\", \"strict-aliasing\") did not report losing it"
        ));
    }
    if o2_observed {
        return o2_copy_observed(run, observed);
    }
    if run.has_marker("level-witness=lost") {
        return Detection::present(
            None,
            format!(
                "{observed}, while the copy rebuilt from this optimization level's defaults lost it"
            ),
        );
    }
    if run.has_marker("level-witness=observed") {
        return Detection::indeterminate(format!(
            "{observed}, but the copy compiled at -O2 lost it and the copy at this level observed it"
        ));
    }
    Detection::indeterminate(format!("{observed}, and the -O2 copy lost it"))
}

/// The store observed by the build and by the `-O2` copy, which shows the flag on gcc 12
/// and later; the build's tail call says whether its level is one the flag acts at.
/// [`detect_no_strict_aliasing`] carries the argument.
fn o2_copy_observed(run: &RunRecord, observed: &str) -> Detection {
    let by_o2_copy = "and observed by the copy compiled at -O2 under the build's own options";
    if run.has_marker("sibling-call=made") {
        return Detection::present(
            None,
            format!("{observed}, {by_o2_copy}; the build's own tail call became a jump"),
        );
    }
    if run.has_marker("sibling-call=not-made") {
        return Detection::indeterminate(format!(
            "{observed}, {by_o2_copy}, but the build's own tail call stayed a call"
        ));
    }
    // No `sibling-call` line: recorded fixtures carry it, and a live run cannot produce it.
    Detection::present(
        None,
        format!("{observed}, {by_o2_copy}, which applies the rule by default"),
    )
}

/// The dirt byte `zero_init_padding.c` writes, and the value that means it survived.
const ZIPB_DIRT: u8 = 0x5A;

/// Read `ZIPB pad=xx ctrl=xx ctrl_supported=n` out of the probe's stdout.
fn zipb_reading(run: &RunRecord) -> Option<(u8, u8, bool)> {
    let line = run.stdout.lines().find(|l| l.starts_with("ZIPB "))?;
    let field =
        |name: &str| -> Option<&str> { line.split_whitespace().find_map(|t| t.strip_prefix(name)) };
    let hex = |name: &str| u8::from_str_radix(field(name)?, 16).ok();
    Some((
        hex("pad=")?,
        hex("ctrl=")?,
        match field("ctrl_supported=")? {
            "1" => true,
            "0" => false,
            _ => return None,
        },
    ))
}

/// Whether the initializer covered the bytes it does not name.
pub(crate) fn detect_zero_init_padding(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let Some((pad, ctrl, ctrl_supported)) = zipb_reading(run) else {
        return Detection::indeterminate(format!(
            "no ZIPB line in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 80),
            run.exit_status,
            run.signal
        ));
    };
    if ctrl != ZIPB_DIRT {
        let control = if ctrl_supported {
            "the opted-out control"
        } else {
            "the control (this compiler has no __attribute__((uninitialized)))"
        };
        return Detection::withheld(
            FRAME_REUSE_DID_NOT_HOLD,
            format!(
                "frame reuse not witnessed: {control} read 0x{ctrl:02x} rather than the \
                 dirt, 0x{ZIPB_DIRT:02x}, so pad=0x{pad:02x} establishes nothing either way"
            ),
        );
    }
    match pad {
        0x00 => Detection::present(None, format!("pad=0x00 ctrl=0x{ctrl:02x}")),
        ZIPB_DIRT => Detection::absent(format!(
            "pad=0x{ZIPB_DIRT:02x} (the dirt survived: the initializer left the bytes it \
             does not name)"
        )),
        other => {
            Detection::indeterminate(format!("pad=0x{other:02x} is neither the dirt nor zero"))
        }
    }
}

pub(crate) fn detect_auto_var_init(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let Some(fill) = auto_var_init_fill(run) else {
        return Detection::indeterminate(format!(
            "no agreeing TAVI fill byte in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 80),
            run.exit_status,
            run.signal
        ));
    };
    match fill {
        FillReading::Uniform(0x00) => Detection::present(Some("zero"), "fill=0x00".to_owned()),
        FillReading::Uniform(b) if pattern_fill(b, ev.elf) == Some(true) => {
            Detection::present(Some("pattern"), format!("fill=0x{b:02x}"))
        }
        FillReading::Uniform(b) if pattern_fill(b, ev.elf).is_none() => unplaced_fill(b, ev.elf),
        FillReading::Uniform(AUTO_VAR_INIT_DIRT) => {
            Detection::absent("fill=0x5a (the dirt survived: nothing initialized it)".to_owned())
        }
        FillReading::Uniform(b) => Detection::absent(format!(
            "fill=0x{b:02x} (uniform but not an initializer's value)"
        )),
        // The shapes disagreed, so nothing filled them uniformly: that is what
        // "flag off" looks like.
        FillReading::Mixed => {
            Detection::absent("shapes disagreed: no uniform initializer ran".to_owned())
        }
        FillReading::Unwitnessed(line) => unwitnessed_fill(&line),
    }
}

/// The reading of a [`FillReading::Unwitnessed`] line, for both detectors.
fn unwitnessed_fill(line: &str) -> Detection {
    Detection::indeterminate(format!(
        "{line}: this compiler has no __attribute__((uninitialized))"
    ))
}

/// `=pattern` specifically. Kept separate from [`detect_auto_var_init`] because
/// the pattern bytes can be attributed to the flag on both compilers while `0x00` cannot:
/// clang zeroes automatic variables incidentally from `-O1` upward, so a zero fill
/// cannot be attributed to the flag there. `0xFE` and clang's 64-bit `0xAA` are values
/// nothing else writes; clang's 32-bit `0xFF` is not, and its attribution rests on the
/// `ctrl` witness and the three shapes agreeing (`AUTO_VAR_INIT_CLANG_PATTERN_32`).
pub(crate) fn detect_auto_var_init_pattern(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let Some(fill) = auto_var_init_fill(run) else {
        return Detection::indeterminate("no TAVI line in the probe's output".to_owned());
    };
    match fill {
        FillReading::Uniform(b) if pattern_fill(b, ev.elf) == Some(true) => {
            Detection::present(Some("pattern"), format!("fill=0x{b:02x}"))
        }
        FillReading::Uniform(b) if pattern_fill(b, ev.elf).is_none() => unplaced_fill(b, ev.elf),
        // A uniform 0x00 is `=zero` or clang's incidental zeroing: `absent` for `=pattern`.
        FillReading::Uniform(b) => Detection::absent(format!("fill=0x{b:02x}, not a pattern fill")),
        FillReading::Mixed => {
            Detection::absent("shapes disagreed: no uniform pattern fill".to_owned())
        }
        FillReading::Unwitnessed(line) => unwitnessed_fill(&line),
    }
}

/// What `zero_call_used_regs.c` printed: the letters for the argument registers and the
/// one non-argument register, after the trampoline called the do-nothing witness and
/// after it called the compiled function.
struct ZcurReading<'a> {
    line: &'a str,
    null_args: &'a str,
    null_temp: &'a str,
    args: &'a str,
    temp: &'a str,
}

/// The argument-register count and the non-argument register the probe reads, per
/// architecture (`CHARD_ARGS` and `CHARD_TEMP` in `zero_call_used_regs.c`). The probe prints
/// no architecture name, so the pair is how the line says where it ran. A count outside the
/// pair is a line this probe did not print, and `args=0` would otherwise pass every letter
/// test over an empty string.
const ZCUR_ARCHITECTURES: [(usize, &str); 2] = [(6, "r11"), (8, "x10")];

/// Read `ZCUR args=N temp=R null=<args>/<temp> target=<args>/<temp>`. `None` for a line
/// that does not have that shape, including one whose letter counts disagree with `args=`
/// or whose `args=` and `temp=` are not one architecture's pair in [`ZCUR_ARCHITECTURES`].
fn zcur_reading(run: &RunRecord) -> Option<ZcurReading<'_>> {
    let line = run.stdout.lines().find(|l| l.starts_with("ZCUR "))?;
    let field =
        |name: &str| -> Option<&str> { line.split_whitespace().find_map(|t| t.strip_prefix(name)) };
    let count: usize = field("args=")?.parse().ok()?;
    let temp_name = field("temp=")?;
    if !ZCUR_ARCHITECTURES.contains(&(count, temp_name)) {
        return None;
    }
    let split = |name: &str| -> Option<(&str, &str)> {
        let (args, temp) = field(name)?.split_once('/')?;
        (args.len() == count
            && temp.len() == 1
            && args
                .chars()
                .chain(temp.chars())
                .all(|c| matches!(c, 'z' | 'k' | 'o')))
        .then_some((args, temp))
    };
    let (null_args, null_temp) = split("null=")?;
    let (args, temp) = split("target=")?;
    Some(ZcurReading {
        line,
        null_args,
        null_temp,
        args,
        temp,
    })
}

/// Whether the function cleared the call-used registers it used before returning.
pub(crate) fn detect_zero_call_used_regs(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    if run
        .stdout
        .lines()
        .any(|l| l.trim_end() == "ZCUR unsupported-arch")
    {
        return Detection::indeterminate(
            "the probe has no register witness for this architecture".to_owned(),
        );
    }
    let Some(r) = zcur_reading(run) else {
        let what = if run.stdout.lines().any(|l| l.starts_with("ZCUR ")) {
            "a ZCUR line this probe does not print"
        } else {
            "no ZCUR line"
        };
        return Detection::indeterminate(format!(
            "{what} in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 120),
            run.exit_status,
            run.signal
        ));
    };
    let line = r.line;
    if !(r.null_args.chars().all(|c| c == 'k') && r.null_temp == "k") {
        return Detection::indeterminate(format!(
            "{line}: the witness failed, since a function that only returns gave back registers other than the markers loaded into them"
        ));
    }
    if r.args.chars().all(|c| c == 'z') {
        if r.temp == "z" {
            return Detection::present(
                Some("gpr"),
                format!(
                    "{line}: every argument register and the non-argument register the \
                     function used read zero after it returned"
                ),
            );
        }
        return Detection::present(
            Some("arg"),
            format!("{line}: every argument register read zero after the function returned"),
        );
    }
    if r.args.contains('k') {
        return Detection::absent(format!(
            "{line}: an argument register the function read came back holding the value \
             the caller put there"
        ));
    }
    Detection::indeterminate(format!(
        "{line}: the argument registers neither all read zero nor kept a value the caller put there"
    ))
}

/// What glibc's loader prints when it refuses to start a program whose `PT_GNU_STACK` asks
/// for an executable stack, as a Wolfi-derived rootfs's glibc 2.44-r23 did (measured 2026-10-21
/// on Fedora 44 x86_64's kernel: exit 127, `Fatal glibc error: executable stack is not allowed`).
const LOADER_EXECSTACK_REFUSAL: &str = "executable stack is not allowed";

/// The loader's refusal line in a run's stderr, where the run exited 127 (the loader's
/// fatal-error status) and no signal ended it; `None` for any other run.
pub(crate) fn loader_refusal(run: &RunRecord) -> Option<&str> {
    if run.exit_status != 127 || run.signal.is_some() {
        return None;
    }
    run.stderr
        .lines()
        .map(str::trim_end)
        .find(|l| l.contains(LOADER_EXECSTACK_REFUSAL))
}

/// The architecture a `NXRT arch=<arch> calling` line names, if it is that line.
fn nxrt_call_arch(line: &str) -> Option<&str> {
    line.strip_prefix("NXRT arch=")?.strip_suffix(" calling")
}

/// Whether the kernel executed bytes on main's stack: `probes/stack_exec_runtime.c`.
pub(crate) fn detect_stack_exec(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let observed = format!(
        "exit={} signal={:?} out={:?}",
        run.exit_status,
        run.signal,
        excerpt_tail(ev, &run.stdout, 140)
    );
    let lines: Vec<&str> = run
        .stdout
        .lines()
        .map(str::trim_end)
        .filter(|l| l.starts_with("NXRT "))
        .collect();
    if let Some(why) = lines
        .iter()
        .find_map(|l| l.strip_prefix("NXRT probe-invalid="))
    {
        return Detection::indeterminate(format!("{observed} (probe declined: {why})"));
    }
    if !lines
        .iter()
        .any(|l| nxrt_call_arch(l).is_some_and(|arch| !arch.is_empty()))
    {
        if let Some(refusal) = loader_refusal(run) {
            return Detection::indeterminate(format!(
                "{observed} (the C library's loader refused to start the program, so it never \
                 reached `main`: `{refusal}`)"
            ));
        }
        return Detection::indeterminate(format!(
            "{observed} (the probe never reached the call into its stack buffer)"
        ));
    }
    if !run.exited_cleanly() {
        return Detection::indeterminate(format!(
            "{observed} (the probe did not exit cleanly after the call)"
        ));
    }
    let not_exec = lines.contains(&"NXRT stack-exec=no fault=payload");
    let exec = lines.contains(&"NXRT stack-exec=yes ret=77");
    match (not_exec, exec) {
        (true, false) => Detection::present(None, observed),
        (false, true) => Detection::absent(observed),
        _ => Detection::indeterminate(format!(
            "{observed} (neither a fault at the payload's address nor the payload's marker)"
        )),
    }
}

/// The two lines `shadow_stack.c` prints, as `detect_shadow_stack` and the gating rules
/// `kernel-lacks-shadow-stack` and `cpu-lacks-shadow-stack` read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShadowStackReading<'a> {
    /// The first `SHSTK` line, verbatim: `SHSTK kernel=.. cpu=.. features=.. ssp=..`.
    pub line: &'a str,
    /// The kernel's answer to `ARCH_SHSTK_STATUS`: `ok`, or `errno:N`.
    pub kernel: &'a str,
    /// CPUID leaf 7's `CET_SS` bit: `ss`, `no-ss`, or `no-leaf7`.
    pub cpu: &'a str,
    /// The status word the kernel returned, bit 0 the shadow stack.
    pub features: u64,
    /// Whether `rdsspq` wrote a pointer into the zeroed register.
    pub ssp_nonzero: bool,
    /// The second line, verbatim, where the probe printed one.
    pub clobber_line: Option<&'a str>,
    /// The pinned process's `SHSTK tunables=` word: `honoured` where the pin's witness
    /// tunable showed its effect, `ignored` where it did not, `unallocated` where the witness
    /// could not run. `None` for the unpinned process, which prints no such line, and for a
    /// pinned one that printed none.
    pub tunables: Option<&'a str>,
    /// What the overwritten return did: `cperr`, `segv:N` or `hijacked`.
    pub clobber: Option<&'a str>,
}

/// The one refusal of `ARCH_SHSTK_STATUS` measured to mean the kernel has no user shadow
/// stack: `EINVAL`, the answer of a kernel without `CONFIG_X86_USER_SHADOW_STACK`.
const KERNEL_LACKS_SHSTK: &str = "errno:22";

/// Which part of the machine a [`ShadowStackReading`] says has no user shadow stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LackingPart {
    /// `arch_prctl(ARCH_SHSTK_STATUS)` answered `EINVAL`.
    Kernel,
    /// CPUID leaf 7 does not enumerate `CET_SS`, or the CPU has no leaf 7.
    Cpu,
}

/// What a [`ShadowStackReading`] says the machine lacks, and the sentence naming it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachineLack {
    pub part: LackingPart,
    pub sentence: String,
}

impl ShadowStackReading<'_> {
    /// Why this machine cannot run a shadow stack for any build, where its own answers say
    /// so: the kernel answered the status query with `EINVAL`, or the CPU does not enumerate
    /// `CET_SS`. The kernel is named first where both hold, since a kernel without the
    /// interface offers none on any CPU.
    pub fn machine_lacks(&self) -> Option<MachineLack> {
        if self.kernel == KERNEL_LACKS_SHSTK {
            return Some(MachineLack {
                part: LackingPart::Kernel,
                sentence: format!(
                    "the kernel answered `arch_prctl(ARCH_SHSTK_STATUS)` with `{}`",
                    self.kernel
                ),
            });
        }
        if self.cpu != "ss" {
            return Some(MachineLack {
                part: LackingPart::Cpu,
                sentence: format!(
                    "the CPU does not enumerate CET shadow stack in CPUID leaf 7 (`cpu={}`)",
                    self.cpu
                ),
            });
        }
        None
    }
}

/// The prefix of the pinned process's lines, the one chard started.
const SHSTK_PINNED: &str = "SHSTK";
/// The prefix of the lines the probe's second process prints, run without `GLIBC_TUNABLES`.
const SHSTK_UNPINNED: &str = "SHSTK-UNPINNED";

/// Read `shadow_stack.c`'s pinned lines out of a run's stdout. `None` where the first line is
/// missing or a field does not have its shape; the second line is optional, since a probe
/// that died some other way never printed it.
pub(crate) fn shadow_stack_reading(stdout: &str) -> Option<ShadowStackReading<'_>> {
    shadow_stack_reading_under(stdout, SHSTK_PINNED)
}

/// The same two lines under `prefix`: [`SHSTK_PINNED`] or [`SHSTK_UNPINNED`].
fn shadow_stack_reading_under<'a>(stdout: &'a str, prefix: &str) -> Option<ShadowStackReading<'a>> {
    let first = format!("{prefix} kernel=");
    let second = format!("{prefix} clobber=");
    let line = stdout.lines().find(|l| l.starts_with(&first))?;
    let field =
        |name: &str| -> Option<&str> { line.split_whitespace().find_map(|t| t.strip_prefix(name)) };
    let kernel = field("kernel=")?;
    let cpu = field("cpu=")?;
    let features = field("features=")?;
    // `%#lx`: `0` for zero, `0x..` otherwise.
    let features = u64::from_str_radix(features.strip_prefix("0x").unwrap_or(features), 16).ok()?;
    let ssp_nonzero = match field("ssp=")? {
        "nonzero" => true,
        "zero" => false,
        _ => return None,
    };
    let kernel_shape = kernel == "ok"
        || kernel
            .strip_prefix("errno:")
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    if !kernel_shape || !matches!(cpu, "ss" | "no-ss" | "no-leaf7") {
        return None;
    }
    let clobber_line = stdout.lines().find(|l| l.starts_with(&second));
    let tunables = (prefix == SHSTK_PINNED)
        .then(|| {
            stdout
                .lines()
                .find_map(|l| l.trim_end().strip_prefix(SHSTK_TUNABLES))
        })
        .flatten();
    Some(ShadowStackReading {
        line,
        kernel,
        cpu,
        features,
        ssp_nonzero,
        clobber_line,
        clobber: clobber_line
            .and_then(|l| l.strip_prefix(second.as_str()))
            .map(str::trim_end),
        tunables,
    })
}

/// The pinned process's witness line: whether `GLIBC_TUNABLES` reached the C library.
const SHSTK_TUNABLES: &str = "SHSTK tunables=";
/// The witness's word for a C library on which the pin's witness tunable had no effect.
pub(crate) const SHSTK_TUNABLES_IGNORED: &str = "ignored";

/// How a shadow-stack sentence names the opt-in, by what the pinned process's witness
/// showed: applied only where its tunable took effect, since a C library that ignores
/// `GLIBC_TUNABLES` runs the pinned process as an unpinned one. A process enforced under the
/// pin shows the opt-in took effect whatever the witness read.
fn opt_in_phrase(tunables: Option<&str>, enforced: bool) -> &'static str {
    match tunables {
        Some("honoured") => "under glibc's opt-in",
        _ if enforced => "with glibc's opt-in set",
        Some(SHSTK_TUNABLES_IGNORED) => {
            "with glibc's opt-in set, the tunable pinned beside it showing no effect"
        }
        _ => {
            "with glibc's opt-in set, though the probe could not show that it reached the C \
             library"
        }
    }
}

/// What one process's pair of lines says about its shadow stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Enforcement {
    /// Bit 0 set, a non-zero pointer, and the overwritten return faulted with `SEGV_CPERR`.
    Enforced,
    /// Bit 0 clear, a zero pointer, and the overwritten return taken.
    NotEnforced,
    /// Anything else: the readings disagree, or a line is missing.
    Unestablished,
}

impl ShadowStackReading<'_> {
    fn enforcement(&self) -> Enforcement {
        match (self.features & 1 == 1, self.ssp_nonzero, self.clobber) {
            (true, true, Some("cperr")) => Enforcement::Enforced,
            (false, false, Some("hijacked")) => Enforcement::NotEnforced,
            _ => Enforcement::Unestablished,
        }
    }
}

/// The level word for a shadow stack enforced with the pin and without it: what a deployment
/// that sets no tunable gets. The ask.
pub(crate) const SHSTK_DEFAULT: &str = "default";
/// The level word for a shadow stack enforced only under glibc's opt-in, the pin chard sets.
pub(crate) const SHSTK_OPT_IN: &str = "opt-in";

/// The probe's second process, run without `GLIBC_TUNABLES`: what it established, and its
/// lines (or the parent's account of why there are none) for the evidence.
fn unpinned_enforcement(stdout: &str) -> (Enforcement, String) {
    let Some(u) = shadow_stack_reading_under(stdout, SHSTK_UNPINNED) else {
        let said = stdout
            .lines()
            .find(|l| l.starts_with(SHSTK_UNPINNED))
            .map_or_else(
                || "no SHSTK-UNPINNED line".to_owned(),
                |l| l.trim_end().to_owned(),
            );
        return (Enforcement::Unestablished, said);
    };
    let said = match u.clobber_line {
        Some(c) => format!("{} / {}", u.line, c.trim_end()),
        None => u.line.to_owned(),
    };
    (u.enforcement(), said)
}

/// Whether the shadow stack was enforced for the probe's process, and whether it was without
/// glibc's opt-in.
pub(crate) fn detect_shadow_stack(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    if run
        .stdout
        .lines()
        .any(|l| l.trim_end() == "SHSTK unsupported-arch")
    {
        return Detection::indeterminate(
            "the probe has no shadow-stack reading for this architecture".to_owned(),
        );
    }
    let Some(r) = shadow_stack_reading(&run.stdout) else {
        return Detection::indeterminate(format!(
            "no SHSTK line in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 120),
            run.exit_status,
            run.signal
        ));
    };
    let line = r.line;
    if let Some(lack) = r.machine_lacks() {
        return Detection::indeterminate(format!(
            "{line}: {}, so the shadow stack could not be enabled on this machine \
             whatever the build",
            lack.sentence
        ));
    }
    if r.kernel != "ok" {
        return Detection::indeterminate(format!(
            "{line}: the kernel refused `arch_prctl(ARCH_SHSTK_STATUS)` with `{}`",
            r.kernel
        ));
    }
    let Some(clobber) = r.clobber else {
        return Detection::indeterminate(format!(
            "{line}: the probe printed no clobber line (exit={} signal={:?})",
            run.exit_status, run.signal
        ));
    };
    let (unpinned, unpinned_said) = unpinned_enforcement(&run.stdout);
    let opt_in = opt_in_phrase(r.tunables, r.enforcement() == Enforcement::Enforced);
    match (r.enforcement(), unpinned) {
        (Enforcement::Enforced, Enforcement::Enforced) => Detection::present(
            Some(SHSTK_DEFAULT),
            format!(
                "{line} / clobber={clobber}: the kernel reports the shadow stack enabled, \
                 the shadow stack pointer is set, and the overwritten return address \
                 faulted with SEGV_CPERR; without the opt-in, the same: {unpinned_said}"
            ),
        ),
        (Enforcement::Enforced, Enforcement::NotEnforced) => Detection::present(
            Some(SHSTK_OPT_IN),
            format!(
                "{line} / clobber={clobber}: the kernel reports the shadow stack enabled, \
                 the shadow stack pointer is set, and the overwritten return address \
                 faulted with SEGV_CPERR, {opt_in}; without it the shadow stack was off \
                 and the return was taken: {unpinned_said}"
            ),
        ),
        (Enforcement::Enforced, Enforcement::Unestablished) => Detection::present(
            None,
            format!(
                "{line} / clobber={clobber}: enforced {opt_in}, and the run without it established neither enforcement nor its absence ({unpinned_said})"
            ),
        ),
        (Enforcement::NotEnforced, Enforcement::Enforced) => Detection::indeterminate(format!(
            "{line} / clobber={clobber}: off {opt_in}, yet enforced without it ({unpinned_said})"
        )),
        (Enforcement::NotEnforced, _) => Detection::absent(format!(
            "{line} / clobber={clobber}: the kernel reports no shadow stack for the \
             process, the shadow stack pointer reads zero, and the overwritten return \
             address was taken, {opt_in}"
        )),
        (Enforcement::Unestablished, _) => Detection::indeterminate(format!(
            "{line} / clobber={clobber}: the status word, the shadow stack pointer and the overwritten return disagree"
        )),
    }
}

/// The kernel's `HWCAP2_BTI` answer, the probe's first line.
const BTI_HWCAP: &str = "BTI hwcap=";
/// Printed and flushed just before the indirect branch.
const BTI_ATTEMPTED: &str = "BTI branch=attempted";
/// The branch taken and returning; the target's value follows.
const BTI_LANDED: &str = "BTI branch=landed returned=";
/// What the probe's target returns, a value `main`'s own paths never print.
const BTI_TARGET_RETURNS: &str = "42";

/// What `bti_enforced.c` printed before it branched, and whether it came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BtiReading<'a> {
    /// The `hwcap` line, whole, for the evidence.
    pub line: &'a str,
    /// `HWCAP2_BTI` as the kernel gave it: `yes` or `no`.
    pub hwcap: &'a str,
    /// The probe printed that it was about to branch.
    pub attempted: bool,
    /// What the target returned, where the branch landed and the probe printed it.
    pub landed: Option<&'a str>,
}

/// Read `bti_enforced.c`'s lines out of a run's stdout. `None` where the `hwcap` line is
/// missing or its value is neither `yes` nor `no`.
pub(crate) fn bti_reading(stdout: &str) -> Option<BtiReading<'_>> {
    let line = stdout
        .lines()
        .map(str::trim_end)
        .find(|l| l.starts_with(BTI_HWCAP))?;
    let hwcap = line.strip_prefix(BTI_HWCAP)?;
    if !matches!(hwcap, "yes" | "no") {
        return None;
    }
    let mut lines = stdout.lines().map(str::trim_end);
    Some(BtiReading {
        line,
        hwcap,
        attempted: stdout.lines().any(|l| l.trim_end() == BTI_ATTEMPTED),
        landed: lines.find_map(|l| l.strip_prefix(BTI_LANDED)),
    })
}

impl BtiReading<'_> {
    /// Why this machine enforces BTI for no build, where its own answer says so: the kernel
    /// gave no `HWCAP2_BTI`, which it sets only where the CPU implements `FEAT_BTI` and the
    /// kernel was built with `CONFIG_ARM64_BTI`. Read from the probe's own run rather than
    /// `environment.cpu`: the auxiliary vector is the kernel's word to the process whose
    /// branches are in question. The premise is the register's `hwcap2-bti-names-the-machine`.
    pub fn machine_lacks(&self) -> Option<String> {
        (self.hwcap == "no").then(|| "the kernel gave the process no `HWCAP2_BTI`".to_owned())
    }
}

/// Whether an indirect branch to an instruction that is not a landing pad faulted in the
/// probe's own process.
pub(crate) fn detect_bti_enforced(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    if run
        .stdout
        .lines()
        .any(|l| l.trim_end() == "BTI unsupported-arch")
    {
        return Detection::indeterminate(
            "the probe has no BTI reading for this architecture".to_owned(),
        );
    }
    if run
        .stdout
        .lines()
        .any(|l| l.trim_end() == "BTI unsupported-os")
    {
        return Detection::indeterminate(
            "the probe reads Linux's `HWCAP2_BTI` and fault report".to_owned(),
        );
    }
    let Some(r) = bti_reading(&run.stdout) else {
        return Detection::indeterminate(format!(
            "no `{BTI_HWCAP}` line in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 120),
            run.exit_status,
            run.signal
        ));
    };
    let line = r.line;
    if let Some(lack) = r.machine_lacks() {
        return Detection::indeterminate(format!("{line}: {lack}, whatever the build"));
    }
    if !r.attempted {
        return Detection::indeterminate(format!(
            "{line}: the probe did not print `{BTI_ATTEMPTED}` (exit={} signal={:?})",
            run.exit_status, run.signal
        ));
    }
    let marked = ev.elf.map(|f| f.aarch64_bti);
    let marking = match marked {
        Some(true) => "the program's property note carries the BTI bit",
        Some(false) => "the program's property note carries no BTI bit",
        None => "the program's property note was not read",
    };
    if let Some(returned) = r.landed {
        if returned != BTI_TARGET_RETURNS || !run.exited_cleanly() {
            return Detection::indeterminate(format!(
                "{line} / {BTI_LANDED}{returned} (exit={} signal={:?}): the branch landed",
                run.exit_status, run.signal
            ));
        }
        // `off` says whether the program was marked, which an unread note cannot.
        if marked.is_none() {
            return Detection::indeterminate(format!(
                "{line} / {BTI_LANDED}{returned}: the branch landed, but {marking}"
            ));
        }
        return Detection::absent(format!(
            "{line} / {BTI_LANDED}{returned}: the indirect branch to an instruction that is not \
             a landing pad was taken and returned; {marking}"
        ));
    }
    bti_death(run, line, marked, marking)
}

/// What `detect_bti_enforced` reads from a probe that branched and did not come back: a BTI
/// fault at the declared target in a marked program is `present`, and every other death
/// withholds.
fn bti_death(run: &RunRecord, line: &str, marked: Option<bool>, marking: &str) -> Detection {
    let report = run.fault_report();
    match (run.signal.as_deref(), run.fault(), marked) {
        (Some("SIGILL"), Some(crate::run::Fault::BtiFault), Some(true))
            if report.as_ref().is_some_and(|f| f.at_target == Some(true)) =>
        {
            Detection::present(
                None,
                format!(
                    "{line} / {BTI_ATTEMPTED}: the process died by SIGILL at the declared target, \
                 which its fault report classifies as a branch-target exception ({}); {marking}",
                    report.as_ref().map_or_else(String::new, |f| format!(
                        "si_code={} pc={:#x} word={}",
                        f.code,
                        f.pc,
                        f.word
                            .map_or_else(|| "none".to_owned(), |w| format!("{w:#010x}"))
                    ))
                ),
            )
        }
        (Some("SIGILL"), Some(crate::run::Fault::BtiFault), Some(true)) => {
            Detection::indeterminate(format!(
                "{line} / {BTI_ATTEMPTED}: the fault report reads a branch-target exception"
            ))
        }
        (Some("SIGILL"), Some(crate::run::Fault::BtiFault), _) => {
            Detection::indeterminate(format!(
                "{line} / {BTI_ATTEMPTED}: the fault report reads a branch-target exception, but {marking}"
            ))
        }
        (signal, Some(fault), _) => Detection::indeterminate(format!(
            "{line} / {BTI_ATTEMPTED}: the process died by {} and its fault report reads {fault:?}",
            signal.unwrap_or("no signal")
        )),
        (signal, None, _) => Detection::indeterminate(format!(
            "{line} / {BTI_ATTEMPTED}: the process ended (exit={} signal={}) with no fault report about its death",
            run.exit_status,
            signal.unwrap_or("none")
        )),
    }
}

/// The kernel's `HWCAP_PACA` answer and the FPAC reading, the probe's first line.
const PAC_HWCAP: &str = "PAC hwcap=";
/// Printed and flushed just before the return through the overwritten address.
const PAC_ATTEMPTED: &str = "PAC return=attempted";
/// The marker reached: the return was not authenticated.
const PAC_HIJACKED: &str = "PAC return=hijacked";
/// `victim` returned to its caller: the overwrite did not take.
const PAC_RETURNED: &str = "PAC return=returned";

/// What `pac_ret_enforced.c` printed before the return, and what came of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PacReading<'a> {
    /// The `hwcap` line, whole, for the evidence.
    pub line: &'a str,
    /// `HWCAP_PACA` as the kernel gave it: `yes` or `no`.
    pub hwcap: &'a str,
    /// `FEAT_FPAC` from the ID registers: `yes`, `no`, or `unread`.
    pub fpac: &'a str,
    /// The probe printed that it was about to return.
    pub attempted: bool,
    /// The marker was reached.
    pub hijacked: bool,
    /// `victim` returned to its caller.
    pub returned: bool,
}

/// Read `pac_ret_enforced.c`'s lines out of a run's stdout. `None` where the `hwcap` line is
/// missing or a field is not of its vocabulary.
pub(crate) fn pac_reading(stdout: &str) -> Option<PacReading<'_>> {
    let line = stdout
        .lines()
        .map(str::trim_end)
        .find(|l| l.starts_with(PAC_HWCAP))?;
    let field =
        |name: &str| -> Option<&str> { line.split_whitespace().find_map(|t| t.strip_prefix(name)) };
    let hwcap = field("hwcap=")?;
    let fpac = field("fpac=")?;
    if !matches!(hwcap, "yes" | "no") || !matches!(fpac, "yes" | "no" | "unread") {
        return None;
    }
    let has = |want: &str| stdout.lines().any(|l| l.trim_end() == want);
    Some(PacReading {
        line,
        hwcap,
        fpac,
        attempted: has(PAC_ATTEMPTED),
        hijacked: has(PAC_HIJACKED),
        returned: has(PAC_RETURNED),
    })
}

/// Why the machine a `pac-ret-enforced` run had could not show a failed authentication as one,
/// by the part of its own answer that says so. Each carries the sentence a reason quotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacLack {
    /// The kernel gave no `HWCAP_PACA`: the register's `hwcap-paca-names-the-machine`.
    Hwcap(String),
    /// Address authentication is enabled, the ID registers read no `FEAT_FPAC`, and the run
    /// died during the return by the fault a failed authentication raises there: the
    /// register's `fpac-names-the-fault`.
    Fpac(String),
}

impl PacReading<'_> {
    /// Why this run's machine could not show a failed authentication as one, where its own
    /// answer and its death say so.
    pub fn machine_lacks(&self, run: &RunRecord) -> Option<PacLack> {
        if self.hwcap == "no" {
            return Some(PacLack::Hwcap(
                "the kernel gave the process no `HWCAP_PACA`".to_owned(),
            ));
        }
        let died_returning = self.attempted && !self.hijacked && !self.returned;
        let poisoned = run.signal.as_deref() == Some("SIGSEGV")
            && run
                .fault()
                .is_some_and(|f| f != crate::run::Fault::PacFailure);
        (self.fpac == "no" && died_returning && poisoned).then(|| {
            PacLack::Fpac(
                "address authentication is enabled, the ID registers read no `FEAT_FPAC`"
                    .to_owned(),
            )
        })
    }
}

/// Whether a function's return through its own overwritten saved return address was caught.
pub(crate) fn detect_pac_ret_enforced(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let said = |want: &str| run.stdout.lines().any(|l| l.trim_end() == want);
    if said("PAC unsupported-arch") {
        return Detection::indeterminate(
            "the probe has no PAC reading for this architecture".to_owned(),
        );
    }
    if said("PAC unsupported-os") {
        return Detection::indeterminate(
            "the probe reads Linux's `HWCAP_PACA` and fault report".to_owned(),
        );
    }
    let Some(r) = pac_reading(&run.stdout) else {
        return Detection::indeterminate(format!(
            "no `{PAC_HWCAP}` line in {:?} (exit={} signal={:?})",
            excerpt_tail(ev, &run.stdout, 120),
            run.exit_status,
            run.signal
        ));
    };
    let line = r.line;
    // Only the hwcap lack settles the run whatever it did; the FPAC one is about a death,
    // which `pac_death` reads.
    if let Some(PacLack::Hwcap(lack)) = r.machine_lacks(run) {
        return Detection::indeterminate(format!("{line}: {lack}, whatever the build"));
    }
    if !r.attempted {
        return Detection::indeterminate(format!(
            "{line}: the probe did not print `{PAC_ATTEMPTED}` (exit={} signal={:?})",
            run.exit_status, run.signal
        ));
    }
    if r.returned {
        return Detection::indeterminate(format!(
            "{line} / {PAC_RETURNED}: the function returned to its caller"
        ));
    }
    if r.hijacked {
        return if run.exited_cleanly() {
            Detection::absent(format!(
                "{line} / {PAC_HIJACKED}: the return through the overwritten address reached the address written"
            ))
        } else {
            Detection::indeterminate(format!(
                "{line} / {PAC_HIJACKED} (exit={} signal={:?}): the marker was reached but the process did not end as the marker ends it",
                run.exit_status, run.signal
            ))
        };
    }
    pac_death(run, &r)
}

/// What `detect_pac_ret_enforced` reads from a probe whose return neither reached the marker nor
/// came back: a PAC failure on a machine not read as without FPAC is `present`, and every other
/// death withholds.
fn pac_death(run: &RunRecord, r: &PacReading<'_>) -> Detection {
    let line = r.line;
    match (run.signal.as_deref(), run.fault()) {
        (Some("SIGILL"), Some(crate::run::Fault::PacFailure)) if r.fpac != "no" => {
            Detection::present(
                None,
                format!(
                    "{line} / {PAC_ATTEMPTED}: the process died by SIGILL at the authenticating \
                     instruction, which its fault report classifies as a pointer authentication \
                     failure (ESR class 0x1c, FEAT_FPAC; the ID registers read fpac={})",
                    r.fpac
                ),
            )
        }
        (Some("SIGILL"), Some(crate::run::Fault::PacFailure)) => Detection::indeterminate(format!(
            "{line} / {PAC_ATTEMPTED}: the fault report reads a pointer authentication failure"
        )),
        (Some("SIGSEGV"), Some(_)) if r.fpac != "yes" => Detection::indeterminate(format!(
            "{line} / {PAC_ATTEMPTED}: the return faulted with SIGSEGV on a machine the ID registers read as fpac={}",
            r.fpac
        )),
        (signal, Some(fault)) => Detection::indeterminate(format!(
            "{line} / {PAC_ATTEMPTED}: the process died by {} and its fault report reads {fault:?}",
            signal.unwrap_or("no signal")
        )),
        (signal, None) => Detection::indeterminate(format!(
            "{line} / {PAC_ATTEMPTED}: the process ended (exit={} signal={}) with no fault report about its death",
            run.exit_status,
            signal.unwrap_or("none")
        )),
    }
}

/// Rung 2' of the fortify ratchet: glibc rejecting a `%n` in writable memory.
pub(crate) fn detect_fortify_percent_n(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    let observed = format!(
        "exit={} signal={:?} stderr={:?}",
        run.exit_status,
        run.signal,
        excerpt_tail(ev, &run.stderr, 120)
    );
    if run.aborted()
        && FORTIFY_PERCENT_N_MESSAGES
            .iter()
            .any(|message| run.output_contains(message))
    {
        return Detection::present(None, observed);
    }
    if run.exited_cleanly() && run.output_contains(PROBE_SURVIVED) {
        return Detection::absent(observed);
    }
    // A plain "buffer overflow detected" here would mean something other than the
    // %n check fired, which is not this rung's observable.
    Detection::indeterminate(format!("{observed} (unexpected termination for this rung)"))
}

/// The line qemu-user writes to the guest's stderr when the guest dies by a signal:
/// `qemu: uncaught target signal 6 (Aborted) - core dumped`. It appears
/// on every signal death under emulation (qemu-user on Fedora 44 x86_64 and aarch64,
/// 2026-10-01).
const QEMU_SIGNAL_REPORT: &str = "qemu: uncaught target signal";

/// What UBSAN's handler prints when it reports a check, in its recovering and its
/// aborting mode alike.
const UBSAN_REPORT: &str = "runtime error:";

/// Did a signed `int` overflow kill the `trapv` probe, and was it -ftrapv that did?
pub(crate) fn detect_trapv(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    // The last line for a key, so `trapv-overflow=wrapped` supersedes the `attempted`
    // printed before the addition.
    let line = |key: &str| -> Option<&str> {
        run.stdout.lines().rev().find_map(|l| {
            l.trim()
                .strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
                .map(|v| v.split_whitespace().next().unwrap_or(""))
        })
    };
    let frontend = line("frontend").unwrap_or("?");
    let ubsan = line("ubsan").unwrap_or("?");
    let overflow = line("trapv-overflow");
    // Every line of stderr but the emulator's report of a signal death.
    let stderr: Vec<&str> = run
        .stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(QEMU_SIGNAL_REPORT))
        .collect();
    let observed = format!(
        "frontend={frontend} ubsan={ubsan} overflow={} exit={} signal={:?} stderr={:?}",
        overflow.unwrap_or("?"),
        run.exit_status,
        run.signal,
        excerpt_tail(ev, &run.stderr, 120)
    );
    if overflow.is_none() {
        return Detection::indeterminate(format!(
            "{observed} (the probe never reached the overflow)"
        ));
    }
    if run.stderr.contains(UBSAN_REPORT) {
        return Detection::indeterminate(format!("{observed} (UBSan reported the overflow)"));
    }
    // A recovering UBSan check lets the sum wrap with or without -ftrapv, and not every
    // runtime says `runtime error:`: clang's minimal runtime printed `ubsan: add-overflow by
    // 0x...` and exited 0 (clang 22.1.8, Fedora 44 x86_64, 2026-10-02).
    if overflow == Some("wrapped") && (ubsan == "yes" || !stderr.is_empty()) {
        return Detection::indeterminate(format!(
            "{observed} (the sum wrapped beside a compiled-in UBSan check or output on stderr)"
        ));
    }
    if overflow == Some("wrapped") && run.exited_cleanly() {
        return Detection::absent(format!(
            "{observed} (the overflow wrapped and the run went on)"
        ));
    }
    if overflow != Some("attempted") {
        return Detection::indeterminate(format!("{observed} (unexpected overflow reading)"));
    }
    if run.aborted() && stderr.is_empty() {
        if frontend == "gcc" {
            return Detection::present(
                None,
                format!("{observed} (aborted in the overflowing addition, libgcc's -ftrapv path)"),
            );
        }
        return Detection::indeterminate(format!(
            "{observed} (an abort from a {frontend} build, where -ftrapv traps rather than \
             aborts)"
        ));
    }
    if run.trapped() && stderr.is_empty() {
        return match (frontend, ubsan) {
            ("clang", "no") => Detection::present(
                None,
                format!(
                    "{observed} (trapped in the overflowing addition with no UBSan check compiled in)"
                ),
            ),
            ("clang", _) => Detection::indeterminate(format!(
                "{observed} (a UBSan check was compiled in or could not be ruled out)"
            )),
            ("gcc", _) => Detection::indeterminate(format!(
                "{observed} (gcc's -ftrapv aborts rather than traps)"
            )),
            _ => Detection::indeterminate(format!(
                "{observed} (a trap from a front end whose -ftrapv was not measured)"
            )),
        };
    }
    let timeout = run.timeout_note();
    let why = if run.timed_out {
        timeout.as_str()
    } else if !stderr.is_empty() {
        "the run printed on stderr"
    } else {
        "unexpected termination"
    };
    Detection::indeterminate(format!("{observed} ({why})"))
}

// --- the translation read ----------------------------------------------------

/// The word opening the line `chard_report_translation` in `probes/chard_selfreport.h`
/// writes first on a [`crate::probe::RunBasis::Machine`] probe's stdout, on Darwin alone.
pub const TRANSLATION_MARKER: &str = "CHARD-TRANSLATION";

/// What a probe's stdout says of `sysctl.proc_translated`, the one read that tells a run
/// under Rosetta 2 from a native one on Darwin, where a Mach-O artifact gives chard's reader
/// nothing to hold to the kernel (`probes/chard_selfreport.h` has the measurement).
///
/// On a macOS run, only [`Translation::Native`] publishes a reading that rests on the
/// machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Translation {
    /// `CHARD-TRANSLATION 0`: the process ran on the machine it was built for.
    Native,
    /// `CHARD-TRANSLATION 1`: Rosetta 2 translated it.
    Translated,
    /// `CHARD-TRANSLATION unreadable <why>`, where `why` is the probe's own `errno:N`,
    /// `size:N` or `value:N`: the read failed, or answered neither 0 nor 1.
    Unreadable(String),
    /// No line: a probe built before the read, one that died before printing it, or a run
    /// on a platform whose probes print none.
    Unreported,
    /// A line in no shape the header writes, or more than one line: each quoted, escaped
    /// and cut.
    Unrecognised(String),
}

impl Translation {
    /// The clause a gating reason carries for this read.
    #[must_use]
    pub fn clause(&self) -> String {
        match self {
            Self::Native => "the probe read sysctl.proc_translated as 0".to_owned(),
            Self::Translated => "the probe read sysctl.proc_translated as 1".to_owned(),
            Self::Unreadable(why) if why == "errno:2" => format!(
                "the probe could not read sysctl.proc_translated ({why}, ENOENT: no such \
                 sysctl, as on an Intel Mac)"
            ),
            Self::Unreadable(why) => {
                format!("the probe could not read sysctl.proc_translated ({why})")
            }
            Self::Unreported => format!("the probe printed no {TRANSLATION_MARKER} line"),
            Self::Unrecognised(lines) => format!(
                "the probe's {TRANSLATION_MARKER} output is in no shape chard reads ({lines})"
            ),
        }
    }
}

/// The longest stretch of an unrecognised line [`translation`] quotes.
const TRANSLATION_QUOTE_CAP: usize = 64;

/// The [`Translation`] a run's stdout carries, read from stdout's first line, where the
/// header writes it.
///
/// A [`TRANSLATION_MARKER`] line anywhere later makes the read [`Translation::Unrecognised`]
/// whatever the lines say, since the header writes one, first, and any other is not the
/// probe's own. A trailing word is unrecognised too. A line is quoted with Rust's escapes and
/// cut at `TRANSLATION_QUOTE_CAP` characters, so a control character reaches a reason as text.
#[must_use]
pub fn translation(stdout: &str) -> Translation {
    let quote = |line: &str| {
        let cut: String = line.chars().take(TRANSLATION_QUOTE_CAP).collect();
        let more = line.chars().count().saturating_sub(TRANSLATION_QUOTE_CAP);
        if more == 0 {
            format!("{cut:?}")
        } else {
            format!("{cut:?} and {more} character(s) more")
        }
    };
    let marked = |l: &&str| l.starts_with(TRANSLATION_MARKER);
    let mut lines = stdout.lines();
    let first = lines.next().filter(marked);
    let later: Vec<&str> = lines.filter(marked).collect();
    let line = match (first, later.is_empty()) {
        (None, true) => return Translation::Unreported,
        (Some(line), true) => line,
        _ => {
            return Translation::Unrecognised(
                first
                    .into_iter()
                    .chain(later)
                    .map(quote)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
    };
    let read = line
        .strip_prefix(TRANSLATION_MARKER)
        .and_then(|rest| rest.strip_prefix(' '));
    match read {
        Some("0") => Translation::Native,
        Some("1") => Translation::Translated,
        Some(rest) => match rest.strip_prefix("unreadable ") {
            Some(why) if is_unreadable_word(why) => Translation::Unreadable(why.to_owned()),
            _ => Translation::Unrecognised(quote(line)),
        },
        None => Translation::Unrecognised(quote(line)),
    }
}

/// `errno:N` or `size:N` with N decimal digits, or `value:N` with an optional minus: the
/// three words `chard_report_translation` writes after `unreadable`.
fn is_unreadable_word(why: &str) -> bool {
    let Some((name, number)) = why.split_once(':') else {
        return false;
    };
    let digits = match name {
        "errno" | "size" => number,
        "value" => number.strip_prefix('-').unwrap_or(number),
        _ => return false,
    };
    (1..=20).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
