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
    ///
    /// `None` covers two things the caller cannot tell apart: no implementation was active,
    /// or the artifact carries no `.chard.report` at all.
    ///
    /// A Mach-O binary is not a third. Its section says `_FORTIFY_IMPL=apple` in plain text,
    /// and a route to it through `self.elf` alone would leave the Apple arm of
    /// `detect_fortify_runtime` never firing on Apple. The probes print the same report on
    /// stdout, so a platform whose container chard cannot parse still has a route to the
    /// identity.
    ///
    /// Read from the compiled artifact's own self-report rather than inferred from the
    /// libc, because the two are not the same question: a musl system without the
    /// fortify-headers package answers `None` here and must keep withholding. The
    /// implementations fail in incompatible ways, so a runtime detector cannot read a
    /// termination correctly without knowing which one it is looking at.
    pub fn fortify_impl(&self) -> Option<String> {
        // From the artifact's own `.chard.report`, not from `macros`: the driver leaves
        // `macros` empty for a runtime check and carries the section on the ELF facts
        // instead. Reading the section is also the stronger source — it is written by
        // the same `cc1` that generated the code, so a spec file cannot make it
        // disagree with the binary the way `cc -dM -E` can.
        // The section first, and the run's stdout only when there is no section to read.
        // Order, not preference expressed twice: an artifact chard *can* parse is the
        // stronger evidence, and a probe that printed one thing while its section said
        // another would be a finding rather than a tie to break here.
        let report = match self.elf {
            Some(elf) => elf.self_report.clone(),
            // Bounded to the marker region rather than parsed out of the whole stream. A
            // probe's own output shares the stream, and `stack-clash-guard-page` prints
            // `SCPRT dist=8367487 n=66977792` — `name=value` lines that would enter the map
            // as `dist` and `n`. Nothing reads those keys today, which is exactly why the
            // bound belongs here and not in the next reader.
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
///
/// Two spellings, because glibc does not have one. The recorded corpus splits cleanly:
/// Fedora 43/44, Arch, Tumbleweed, Ubuntu 26.04, AlmaLinux 9 and 10, Gentoo and Wolfi
/// print `segments`; Debian 11/12/13, Ubuntu 20.04 through 24.04 and AlmaLinux 8 print
/// `segment`. It does not order by glibc version — 2.39 says it both ways depending on
/// whose 2.39 it is — so this is a list of what was observed rather than a rule about
/// where the wording changed.
///
/// Matching only the plural would cost not a wrong answer but a withheld one: the abort
/// fires, `run.aborted()` is true, and one letter sends the detector down its
/// "unexpected termination" path, which makes both control arms indeterminate and
/// publishes `probe-invalid` (on 17 toolchains, Debian and Ubuntu LTS among them, when
/// the constant matched only the plural). A unit test would not catch it if it built
/// its evidence from this same constant's wording, which is the failure mode a literal
/// shared between a detector and its test always has.
const FORTIFY_PERCENT_N_MESSAGES: [&str; 2] = [
    "%n in writable segment detected",
    "%n in writable segments detected",
];
const CANARY_MESSAGE: &str = "stack smashing detected";
const PROBE_SURVIVED: &str = "no-check-fired";

/// Exit statuses the fortify probes reserve for a precondition they could not establish.
///
/// Each names a reason the probe never put its question, and each is read here as a
/// withheld verdict with that reason rather than as `off` or as an anomaly. The probes
/// spell them as `CHARD_EXIT_*` in `probes/chard_selfreport.h`; the test
/// `the_probe_exit_vocabulary_is_the_one_the_header_defines` reads that header back so
/// the two spellings cannot drift. The header's `CHARD_EXIT_DECLINED` has no twin here:
/// the probes that exit with it print a `probe-invalid=` line first, and their detectors
/// read the line.
///
/// `malloc` returned NULL: the host ran out of memory, a condition of the machine alone.
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
    // Two implementations trap instead of aborting with a diagnostic, for different
    // reasons, and neither leaves anything in band to match on.
    //
    // fortify-headers, Alpine's reimplementation, calls `__builtin_trap()` on every
    // overflow branch — 63 of them across its nine headers — and ships no `abort()`,
    // no diagnostic and no `__chk_fail` equivalent. There is nothing to print.
    //
    // Apple's `__chk_fail_overflow` does have a message, "detected buffer overflow",
    // and still counts as silent here: `ReportCrash` writes it to a `.ips` report and
    // the unified log after the fact, so it never reaches the streams the probe was
    // run with. Measured on arm64, both pipes empty. Reaching that text would mean
    // parsing crash reports, which is a different mechanism from reading a pipe and
    // not one this project takes on.
    //
    // Credited only when the artifact says which implementation wrapped this
    // translation unit. A bare trap is also an illegal instruction from any other
    // cause, and matching glibc's message existed precisely to stop crediting fortify
    // for an unrelated death; keying on the self-report keeps that guarantee instead
    // of trading it for coverage. The evidence is each implementation's own activation
    // macro, so it is not a guess about the libc — a musl system without the package
    // still reads undefined and still withholds.
    //
    // The Apple half of this rests on one configuration: macOS 26.5.1 (build 25F80),
    // SDK 26.5, Apple clang 21.0.0, arm64. Nothing here has been observed on Intel.
    // FreeBSD is left out on purpose: its wrappers abort, and its arm follows.
    if run.trapped()
        && let Some(implementation) = ev.fortify_impl()
        && matches!(implementation.as_str(), "fortify-headers" | "apple")
    {
        return Detection::present(None, format!("{observed} ({implementation} trap)"));
    }
    // FreeBSD's wrappers abort with nothing in band. `__chk_fail` writes "buffer overflow
    // detected; terminated" to syslog(3) and aborts: the message goes to the system log,
    // which is not a stream the probe was run with, and nothing can be matched. Measured on
    // FreeBSD 15.1 amd64 (clang 19.1.7): the abort, an empty stderr, the survival marker
    // unprinted, the line in /var/log/messages. The credited sentence names the three
    // witnesses chard read and not the log line, which it does not read: the register's
    // `freebsd-silent-abort-is-the-fortify-kill` carries the log as the measured premise.
    //
    // Credited on three witnesses together, each of which a bare SIGABRT lacks. The
    // self-report names FreeBSD's wrappers as the ones that instantiated in this translation
    // unit (`_FORTIFY_IMPL=freebsd`, from `__SSP_FORTIFY_LEVEL > 0` beside `__FreeBSD__`).
    // The artifact references a checking function those wrappers route a copy through
    // ([`FREEBSD_CHECKING_CALLS`]), resolved from libc, so a fortified call is in the code
    // that ran and not only in a header that was seen; the reference is the artifact's,
    // not the overflowing copy's, which is why the third witness carries the weight. And
    // the death is the silent one `__chk_fail` makes: SIGABRT, nothing on stderr, and no
    // survival marker on stdout, from a probe that takes SIGABRT from no other source (its
    // destination is at file scope or on the heap, where no canary covers it, and it calls
    // nothing that asserts). An abort with text on stderr is some other abort (an assert, an
    // allocator, the stack protector), an abort after the survival marker is an abort after
    // the copy, and both withhold naming what was found; so does an abort without the
    // reference, as a trap without a named implementation does. FreeBSD 14.5, whose headers
    // carry no wrappers, never reaches here, since its self-report names no implementation.
    //
    // The symbol tables are read here and not declared in the check's `reads`: the read is
    // this branch's alone, and a declaration would withhold glibc's reading, which needs no
    // symbol, over a stripped static artifact. So an artifact with no symbol table, or one
    // whose table was cut, is named by this reason instead.
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
                    "the artifact carries no symbol table, so whether it calls a checking \
                     function cannot be read"
                        .to_owned()
                }
                Some(elf) if elf.unread(&[ElfTable::Symbols]).is_some() => {
                    "the artifact's symbol table was not read whole, so whether it calls a \
                     checking function cannot be read"
                        .to_owned()
                }
                Some(elf) => match freebsd_checking_definition(elf) {
                    Some(symbol) => format!(
                        "the artifact defines {symbol} rather than referencing it, a static \
                         link this rule does not read"
                    ),
                    None => "the artifact references no checking function chard watches".to_owned(),
                },
                None => "the artifact was not read, so whether it calls a checking function \
                         cannot be read"
                    .to_owned(),
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
    // Anything else — a canary abort, a segfault, a timeout, exit 77 from a
    // failed allocation — means the probe did not measure what it set out to.
    // Reporting that as "fortify off" would be inventing a result.
    let timeout = run.timeout_note();
    let why = if run.output_contains(CANARY_MESSAGE) {
        "stack protector fired first"
    } else if run.timed_out {
        timeout.as_str()
    } else if run.exit_status == PROBE_EXIT_NO_ALLOCATION {
        "probe could not allocate"
    } else if run.exit_status == PROBE_EXIT_OPACITY_LOST {
        "the probe found its destination's size statically known to the compiler, so a \
         level-2 build would fire like level 3 and this run cannot tell them apart"
    } else if run.exit_status == PROBE_EXIT_LAYOUT {
        "the probe found no guard object directly after its destination, so the overflow \
         would have landed in memory the probe does not declare and was not attempted"
    } else if run.exit_status == PROBE_EXIT_HEAP_GEOMETRY {
        "the probe found a heap chunk geometry other than the one its safety margin is \
         computed from, so the overflow was not attempted"
    } else {
        "unexpected termination"
    };
    Detection::indeterminate(format!("{observed} ({why})"))
}

/// The checking functions FreeBSD's wrappers route a copy through, which the silent-abort
/// credit reads a reference to: the `__*_chk` functions `<ssp/string.h>` and `<ssp/stdio.h>`
/// reach through `__builtin___*_chk`, and `__chk_fail`, which a wrapper that checks inline
/// calls directly. A closed list rather than a name shape, so a name later added to the
/// watch list cannot widen the witness unnoticed; `tests::every_freebsd_checking_call_is_watched`
/// holds each entry to [`crate::elf::WATCHED_SYMBOLS`]. Measured with `nm -u` on FreeBSD
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
///
/// Referenced and not defined, because an artifact that defines one carries its own copy
/// (a static link), and whether that copy is the library's wrapper is not read here;
/// [`freebsd_checking_definition`] names that case for the withheld reason.
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
///
/// libstdc++'s `__glibcxx_assert` prints "Assertion '...' failed" with a source
/// location; libc++'s hardening mode routes through `__libcpp_verbose_abort`. Both
/// are matched because a distribution may ship either, and a probe that only knew
/// one would report `off` on the other for a reason that has nothing to do with the
/// flag.
///
/// The trailing space in the first needle is load-bearing rather than incidental, and one
/// spelling had to cover both libraries: libstdc++ prints `Assertion '__n < this->size()'
/// failed.` and libc++ prints `assertion __n < size() failed:`, so neither the quote nor
/// the phrase `assertion failed` catches both. A space does, and cannot occur in the
/// artifact path this ran from. The bare word `assertion` is not the needle, because
/// [`RunRecord::output_contains`] lowercases both streams, so it would match the probe's
/// own artifact path, `.../cxx-stdlib-assertions-measured`, which glibc 2.28 prints in
/// every `__libc_message` abort ("*** buffer overflow detected ***: /tmp/.../x
/// terminated"). Any abort inside this probe on that libc would then be credited to the
/// standard library, and the `stack protector fired first` branch below, which exists to
/// catch exactly that, would be unreachable, because this test runs first. The same hazard is
/// already recorded twice in `decode::diag`, at [`detect_trampolines`] and
/// [`detect_bidi_chars`], for the same reason: a probe id is a substring of its own
/// diagnostics.
///
/// [`detect_trampolines`]: super::diag::detect_trampolines
/// [`detect_bidi_chars`]: super::diag::detect_bidi_chars
pub const CXX_ASSERT_MESSAGES: &[&str] = &["assertion ", "libc++ hardening"];

/// Did a standard-library precondition check fire?
///
/// The abort must carry the library's own message. A bare SIGABRT is not the
/// observable: a stack-protector abort, a fortify abort and a segfault are
/// indistinguishable from it at the level of "the process stopped", and with
/// assertions off the probe's out-of-range read is undefined behaviour that could
/// in principle die on its own. Requiring the message means a crash chard cannot
/// attribute is reported as indeterminate rather than credited to this flag.
pub(crate) fn detect_cxx_assertions(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    // An unoptimized build is measured here too. Without `__OPTIMIZE__` libstdc++ 16 turns
    // this precondition check on by itself (measured, not assumed), so an unoptimized
    // build can show the observable for a reason unrelated to the flag. The library's own
    // `__OPTIMIZE__`-gated default can be told apart from the flag: `-U_GLIBCXX_ASSERTIONS`
    // cannot suppress the default because `c++config.h` re-defines the macro afterwards, but
    // `-D_GLIBCXX_NO_ASSERTIONS` is a term of the same condition and does. With that in
    // the negative arm the controls discriminate at -O0, so the question is answerable,
    // and refusing it would withhold a mitigation that is in force: the mirror image of
    // the error this project exists to prevent.
    //
    // The optimization state still matters for *attribution*, so it is recorded in the
    // evidence rather than used to suppress the verdict. The regime control does not
    // answer which of the library and the packager is responsible. The regime arm is the
    // profile's flags followed by the negative list, and the list's
    // -D_GLIBCXX_NO_ASSERTIONS suppresses the -O0 library default in that arm too, so it
    // reads `absent` whether or not the packager asked. Measured with gcc and clang on
    // Fedora 44 x86_64 and Fedora 44 aarch64, `--profile explicit` with
    // `-U_GLIBCXX_ASSERTIONS` and no -O: `on` with the regime arm `absent` in every cell.
    // The attribution is `evidence.cxx_assertions_source` (`measure::cxx_assertions_source`),
    // held to the published macros and the profile's C++ flags by the consistency rule
    // `cxx-assertions-derived-from-inputs`.
    let unoptimized = run.output_contains("chard-opt=0");
    let observed = format!(
        "exit={} signal={:?} optimized={} stderr={:?}",
        run.exit_status,
        run.signal,
        !unoptimized,
        excerpt_tail(ev, &run.stderr, 160)
    );
    // libc++ can signal a hardening failure with `__builtin_trap()` rather than an
    // abort carrying a message — SIGILL and an empty stderr. Measured on Chimera, whose
    // default is hardening mode `debug`: the check dies on SIGILL and no standard-library
    // message is printed. Refusing to credit an unattributable death is safe there and
    // useless, and it is exactly the shape fortify-headers presents for the C library.
    //
    // Credited only when the artifact says libc++ provided the headers, for the same
    // reason the fortify trap is keyed on `_FORTIFY_IMPL`: a bare SIGILL is also an
    // illegal instruction from any other cause, and matching a message exists to stop
    // crediting a mechanism for an unrelated death.
    //
    // Two spellings of the same evidence. `_CXX_STDLIB` is chard's own summary, written
    // into the self-report by the header's `#if defined(_LIBCPP_VERSION)` arm, and it is
    // the stronger source because the artifact wrote it. But it exists only inside that
    // report, so it is unavailable wherever the artifact cannot be read — Mach-O today —
    // and there the identity would be lost for a reason that has nothing to do with the
    // C++ library. `_LIBCPP_VERSION` is the real macro that arm tests, so the
    // preprocessor dump carries it either way.
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
        "aborted without a standard-library diagnostic, so the cause is unattributable"
    } else {
        "unexpected termination"
    };
    Detection::indeterminate(format!("{observed} ({why})"))
}

/// Where the first touch landed, as a percentage of the allocation.
///
/// The observable for `-fstack-clash-protection` is not whether the probe faults —
/// it faults either way — but *where*. A prologue that walks down a page at a time
/// hits the guard page almost immediately; one that subtracts the whole frame in a
/// single step first touches memory the full allocation below, which is the
/// stack-clash primitive. Measured here: 12 with the flag, 100 without, on gcc and
/// clang alike.
///
/// The band between 50 and 90 is deliberately unclaimed. A ratio there means the
/// fault landed somewhere neither hypothesis predicts, and inventing a verdict from
/// it would be exactly the guess this project refuses.
///
/// The printed ratio is believed only where it is the probe's own arithmetic over the
/// distance and size printed beside it, recomputed here in 128 bits. A probe that does that
/// arithmetic in `unsigned long`, which is 32 bits on i386, wraps `100 * dist`: a
/// probing-off build at the default `8 MiB` limit prints
/// `dist=67108879 n=67108864 ratio_pct=36` (Debian 12 gcc 12.2.0 i386, gcc 16.2.1 and
/// clang 22.1.8 `-m32`), which would read `present`. A line whose ratio disagrees with its own
/// operands is a wrapped one and withholds. So do the two shapes no ratio can describe:
/// `n=0`, a fault before the size was recorded, and `dist=0`, a first touch at or above
/// the frame, which such a probe prints when `sp - n` wraps under a limit of `16 TiB`
/// or more on 4-level x86_64 (`dist=0 n=140737488355328 ratio_pct=0`, gcc 16.1.1 and
/// clang 22.1.8) and at `4 GiB` minus `1 KiB` on i386. `probes/stack_clash.c` declines all
/// of these itself; the checks here hold for a line from any probe.
///
/// `observed` quotes the probe's `SCPRT` lines whole and cuts only the rest of the stream
/// ([`stack_clash_excerpt`]). The readings are parsed from stdout, the only stream the
/// probe writes. A run record's stdout is stored with its trailing newline trimmed, so in
/// stdout and stderr joined, a loader's warning on stderr would run into `ratio_pct=12`
/// and the reading would parse as `12ld.so:`, which is no number; no recorded run had
/// anything on stderr.
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
            "{observed} (fault before the allocation was sized, so nothing was measured)"
        ));
    }
    if stack_clash_distance_is_normalized(text) {
        // `--normalize` replaced the distance after this decoder read it (see
        // `report::VOLATILE_READINGS`), so the recompute below already ran on the digits
        // when the report was produced and cannot run again. The ratio is kept unmasked
        // for exactly this replay. One case stays withheld: a masked distance cannot be
        // told from `dist=0`, which prints ratio 0 and which the unmasked line withholds,
        // so a masked ratio of 0 withholds rather than read `present`.
        if ratio == 0 {
            return Detection::indeterminate(format!(
                "{observed} (ratio 0 beside a normalized distance, which could have been \
                 dist=0, a first touch at or above the frame)"
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
                "{observed} (first touch at or above the frame: the allocation wrapped the \
                 address space, so this is not a distance below the frame)"
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
        // the guard page was skipped. This is why absence is sound here.
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
/// (`SCPRT ...`) whole and in order, then the rest of stdout and all of stderr, a loader's
/// or a runtime's, cut to 140 characters by [`excerpt_tail`]. Where the probe wrote only
/// its own lines and stderr is empty, the quote is stdout alone. A
/// newline stands between the probe's lines and the rest where the stored stream lost its
/// last one, so the reading is quoted whole: on Darwin the rest holds the
/// `CHARD-TRANSLATION` line that opens the stream, which would otherwise run into
/// `ratio_pct`.
///
/// One tail cut over the whole stream would place the cut by the length of `dist`, which
/// the kernel's stack randomization moves between runs of one artifact (see
/// `report::VOLATILE_READINGS`). A stream longer than the budget could then be cut inside
/// `SCPRT dist=`, leaving digits with no marker ahead of them that `--normalize` cannot
/// find, and the `[N chars omitted]` count would move with the digit count either way. The
/// probe's lines are short (the handler formats into 160 bytes) and carry the reading the
/// verdict rests on, so they are never cut; the rest carries no reading, so where its cut
/// falls does not depend on one. No recorded run has needed the cut: in a set of reports
/// from Fedora 44, x86_64 and aarch64, every arm's stdout was 42 or 44
/// characters and stderr was empty.
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
///
/// Uniformity is the signature that matters. Every initialization mode writes the
/// *same* byte to all three variable shapes, while uninitialized memory has no
/// reason to agree across them — gcc at `-O1` with the flag off yields three
/// different bytes. So disagreement is evidence of absence, not an inability to
/// tell, and treating it as indeterminate would make the negative control unusable on
/// gcc and leave every verdict withheld.
enum FillReading {
    /// All three shapes read the same byte.
    Uniform(u8),
    /// The shapes disagreed. Carries whether any of them nonetheless looked like a
    /// deliberate fill, which would mean initialization applied to some variables
    /// and not others — a genuinely ambiguous state rather than plain absence.
    ///
    /// Deliberately carries nothing else. Recording whether any single byte *looked*
    /// like a fill value and treating that as ambiguous would make the negative control
    /// flaky: uninitialized garbage contains a 0x00 byte often enough that gcc's
    /// negative arm would go indeterminate at random and withhold an otherwise sound
    /// verdict. Every mode of this flag fills all
    /// automatic variables uniformly, so disagreement is absence.
    Mixed,
}

/// Parse the `TAVI` line by *field name*, not by position or count.
///
/// Requiring exactly three fields and rejecting anything else would make the probe and
/// the detector a matched pair that had to change together, and silently. A
/// replacement probe carrying an extra field would return `None` on every arm,
/// controls included, so the check would stay `probe-invalid` for a brand new
/// and completely invisible reason. Reading named fields means a probe may add
/// diagnostics without the detector having to know about them.
///
/// `ctrl` is the validity witness rather than an observation. It carries
/// `__attribute__((uninitialized))`, so the flag must never touch it and it must
/// always read back the dirt byte. When it does not, the probe's frame-reuse premise
/// has failed and *nothing* the run reported can be trusted — including a reading
/// that would otherwise look like a clean result. That is refused here, from the
/// measured build alone, without reference to the controls. A line with no `ctrl` or
/// no `ctrl_supported` field is refused the same way: no fixture in the corpus lacks
/// either, and the live probe always prints both.
fn auto_var_init_fill(run: &RunRecord) -> Option<FillReading> {
    let line = run.stdout.lines().find(|l| l.starts_with("TAVI "))?;

    let mut fields = BTreeMap::new();
    for field in line.split_whitespace().skip(1) {
        if let Some((name, value)) = field.split_once('=') {
            fields.insert(name, value);
        }
    }

    // The witness is required, as `zipb_reading` requires it: the live probe always
    // prints `ctrl` and `ctrl_supported`, so a line without either is not that probe's
    // line, and reading its fill anyway would take an unwitnessed run for a measured
    // one. Where the compiler lacks the opt-out attribute the probe says so itself with
    // ctrl_supported=0, and the witness value is then not compared.
    let supported = match *fields.get("ctrl_supported")? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let ctrl = u8::from_str_radix(fields.get("ctrl")?, 16).ok()?;
    if supported && ctrl != AUTO_VAR_INIT_DIRT {
        return None;
    }

    let mut bytes = Vec::new();
    for name in ["arr", "word", "small"] {
        bytes.push(u8::from_str_radix(fields.get(name)?, 16).ok()?);
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
///
/// clang chooses the integer and pointer fill by the target's maximum pointer width
/// (`clang/lib/CodeGen/PatternInit.cpp`): `0xAA` repeated where it is 64 bits, `0xFF`
/// repeated below that, because on a 32-bit target only the zero page can be expected
/// unmapped and an all-ones pointer is meant to wrap into it. Floats take a negative `NaN`
/// with an all-ones payload, which is `0xFF` repeated on either width. Measured on
/// 2026-09-30 with a frame holding `unsigned char[8]`, `unsigned int`, `unsigned
/// char[4]`, `void *`, `float`, `double`, `long`, `long long` and `unsigned short`, dirtied
/// and reread as the probe does: every byte of every one reads `0xFF` under clang 14.0.6
/// (Debian 12 i386, natively), clang 14.0.0 `-m32` (`ubuntu:22.04`) and clang 22.1.8
/// `-m32` (`fedora:44`), at -O0, -O1 and -O2, while clang 22.1.8 on x86_64 reads `0xAA`
/// for the integers and pointer and `0xFF` for the two floating types. The probe's three
/// shapes are integers, so on i386 its whole line reads `ff`.
///
/// Accepted only when the artifact's ELF header says `ELFCLASS32`, and `0xAA` only when
/// it says `ELFCLASS64`, so each target is held to the byte its compiler writes. Neither is a
/// value the negative arm can produce: with `ctrl` witnessing the frame reuse, an
/// uninitialized read returns the probe's own `0x5A`, and an all-`0xFF` line from
/// anything but this flag would need three differently-shaped locals to agree on it.
/// Reading the class as the pointer width is assumption `elf-class-names-clang-pattern-width`
/// in `report::ASSUMPTIONS`, and a clang pattern byte the class does not name is withheld
/// rather than read as absent, so the assumption failing costs a verdict, never an `off`
/// ([`pattern_fill`]).
const AUTO_VAR_INIT_CLANG_PATTERN_32: u8 = 0xFF;

/// Whether `byte`, read uniformly from all three shapes, is a `=pattern` fill for the
/// target the artifact was built for, or `None` where that cannot be told.
///
/// The ELF class picks which of clang's two bytes is this target's pattern (assumption
/// `elf-class-names-clang-pattern-width`). The other one is `None`, not `Some(false)`: it is
/// clang's pattern on some target, and the class is an inference about the pointer width
/// rather than a reading of it. `--target=aarch64-linux-gnu_ilp32` under clang 22.1.8 emits
/// an `ELFCLASS32` object whose IR stores `0xAA`, while defining `__LP64__`, so an
/// `ELFCLASS32` artifact with an `0xAA` fill has been produced; reading it as absent would
/// publish an `off` for a build that set the flag.
///
/// No ELF facts is either a Mach-O artifact, which every measured Darwin target builds
/// with 64-bit pointers and fills with `0xAA`, or an ELF artifact whose header the reader
/// refused. `0xAA` is read as the pattern there, as it was before the class was read. A
/// `0xFF` is not read as anything: on a 32-bit target it is the pattern, and calling it
/// absent over an unread header would publish an `off` for a build that set the flag.
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
        None => format!(
            "fill=0x{byte:02x} is clang's pattern on a 32-bit target, and no ELF header was \
             read to say which target this is"
        ),
        Some(e) => format!(
            "fill=0x{byte:02x} is clang's pattern on another pointer width than an \
             ELFCLASS{} artifact's, so it is neither this target's pattern nor established \
             absent (assumption elf-class-names-clang-pattern-width)",
            e.elf_class
        ),
    })
}

/// Did the overflow guard survive to run?
///
/// The observable is the program's own report on its generated code. `ran` means the
/// comparison was still there and evaluated true, which requires wrapping semantics;
/// `deleted` means the compiler folded it away on the strength of signed overflow being
/// assumed impossible.
/// Which trailing-array spellings are still treated as flexible members.
///
/// Each declaration is bounded when the flag covers its spelling and reads as the whole
/// remaining allocation when it does not, so the reported level is the strictest one the
/// three readings jointly support. Graded rather than boolean: `=1` and `=2` are real
/// postures, and a distribution sitting at one of them is `partial` against the guide's
/// recommended `=3` rather than off.
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
    // `-1` is `__builtin_object_size` saying it could not determine a size at all, which
    // is not the same as determining that the array is unbounded. Without optimization
    // the compiler does not track the allocation, so a flexible reading has no size to
    // report: gcc answers `-1` for every query, clang for the flexible ones while
    // answering a bounded one from its declaration (Fedora 44 x86_64, gcc 16.1.1, clang
    // 22.1.8, `-O0`: gcc `-1` at `=0` and `=3`, clang `-1` at `=0` and `2` at `=3` for
    // `tail[2]`). Reading it as level 0 would report the flag off for a build that set
    // it: absence of an answer taken as an answer, which is the error this project
    // exists to refuse.
    //
    // The withholding is right whatever the cause; the reason has to name the cause the
    // build shows. An optimized build answers `-1` too when the compiler does not
    // recognize the allocator, which OpenBSD 7.9's `-fno-builtin-malloc` and its
    // alloc_size-less `malloc` produce at `-O2`, and a reason blaming a missing `-O`
    // there points at the wrong fix. The probe reports `__OPTIMIZE__` itself, read here
    // as a whole field; evidence from before it did names both causes rather than
    // choosing one.
    //
    // The probe's objects are declared rather than allocated, and it
    // says so with `storage=declared`; the allocator cause cannot produce a reading from
    // that construct, so an optimized `-1` there is withheld with no cause named rather
    // than with the allocator's. The unoptimized cause is the same one: the query goes
    // through a pointer the unoptimized compiler does not follow to its object. Evidence
    // without the line is the heap construct's, and keeps the reasons above.
    if two < 0 || one < 0 || zero < 0 {
        let said = |field: &str| run.stdout.split_whitespace().any(|f| f == field);
        let cause = if said("storage=declared") {
            if said("optimize=no") {
                "the build was not optimized, and without optimization the compiler does \
                 not follow the pointers to the declared objects, so the flexible readings \
                 have no size to report"
            } else if said("optimize=yes") {
                "the build was optimized and the objects are declared, and no cause chard \
                 knows of accounts for the reading"
            } else {
                "the probe did not report whether the build was optimized, and a build \
                 without optimization produces this answer"
            }
        } else if said("optimize=no") {
            "the build was not optimized, and without optimization the compiler does not \
             track the allocation, so the flexible readings have no size to report"
        } else if said("optimize=yes") {
            "the build was optimized, so the compiler could not bound the allocation; an \
             allocator it does not recognize, such as malloc under -fno-builtin-malloc or \
             one declared without alloc_size, leaves no size to narrow"
        } else {
            "the probe did not report whether the build was optimized, and both a build \
             without optimization and an allocator the compiler does not recognize \
             produce this answer"
        };
        return Detection::indeterminate(format!(
            "{observed}: __builtin_object_size could not determine a size; {cause}"
        ));
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
                "{observed} — no -fstrict-flex-arrays level produces this combination, so \
                 one of the three readings is not measuring what it is meant to"
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
    /// markers, or a trap from an implementation the self-report names.
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
    // The probe prints the signal's number. 4, 5 and 6 are SIGILL, SIGTRAP and SIGABRT
    // under both Linux's numbering and the BSD one Darwin uses, which `run.rs` records
    // beside its own signal table.
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
        // reason `detect_fortify_runtime` gives; each row is a child of the one artifact,
        // so the call is read once, and the segment is the child's own stderr.
        "signal:6"
            if segment.trim().is_empty()
                && ev.fortify_impl().as_deref() == Some("freebsd")
                && freebsd_checking_call(ev).is_some() =>
        {
            Ok(RowOutcome::Caught)
        }
        "exit:0" if segment.trim().is_empty() => Ok(RowOutcome::Survived),
        _ => Err(format!(
            "row {row} ended {status:?} with {:?} between its markers, which is neither a \
             caught copy nor a survived one",
            cut_tail(&ev.published(segment.trim()), 120)
        )),
    }
}

/// The C library, where the build's self-report says fortify was requested at 2 or more and
/// the library is one with no subobject bound: no glibc (`__GLIBC__` undefined), and either
/// fortify-headers, which sizes every destination as a whole object, FreeBSD's
/// `<ssp/string.h>`, whose `strcpy` wrapper does the same (`__ssp_bos0`, as for the
/// `memcpy` family; `strlcpy`, `strlcat` and the stdio wrappers ask the subobject bound,
/// which the rows' `strcpy` does not reach; measured on 15.1, where the `ctrl` row survives
/// at every level), or no fortify implementation (`_FORTIFY_IMPL`
/// undefined) on a library the probe's `libc=` line names as musl, OpenBSD's or FreeBSD's
/// (a release before 15.0, whose headers carry no wrappers), the three `libc_unsupported`
/// lists on this check.
///
/// There no arm of the triple can catch the ctrl copy, so its silence is the library's
/// rather than this build's configuration, and the reading is `absent`. That is what lets
/// `report::libc_limitation` publish the check `unsupported` from a positive arm that showed
/// nothing, as it does for `fortify-level-ge-2-subobject`. It cannot publish `off`: the
/// positive arm runs on the same library and is silent too, so the triple does not
/// discriminate. glibc is excluded by its own macro, so no glibc build, whatever suppressed
/// its wrappers, takes this path to a level-0 reading, and Apple's wrappers, which check
/// subobject bounds, are excluded by name.
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
    // that there is none, so it is not enough alone: a library that does check subobject
    // bounds but is not one `chard_selfreport.h` names (bionic) would otherwise be described
    // as having no fortify implementation. Such a library prints `libc=?` and its silent ctrl
    // row is withheld. FreeBSD's libc is named (`libc=freebsd`, and `_FORTIFY_IMPL=freebsd`
    // where its wrappers instantiated), measured on the fleet's two guests: its `__chk_fail`
    // logs through syslog and a caught row is a silent `signal:6`, which `sfa_enforced_row`
    // reads under the rule `detect_fortify_runtime` gives.
    let libc = stdout
        .split_whitespace()
        .find_map(|field| field.strip_prefix("libc="));
    match (fields.get("_FORTIFY_IMPL").map(String::as_str), libc) {
        (Some("fortify-headers"), _) => Some("fortify-headers"),
        (Some("freebsd"), _) => Some(
            "FreeBSD's <ssp/string.h>, whose strcpy wrapper sizes the destination as a whole \
             object",
        ),
        (None, Some("musl")) => Some("musl without fortify-headers"),
        (None, Some("openbsd")) => Some("OpenBSD's libc"),
        // A request of 2 or more, optimized, and no wrapper named, on a FreeBSD below 15: a
        // release whose headers carry no <ssp/ssp.h> (measured on 14.5). A 15 or later with
        // no wrapper named is a build whose wrappers did not instantiate (a level settled at
        // 0) or whose headers were not reached, and its silence is withheld.
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
///
/// The enforcement half of `-fstrict-flex-arrays`: [`detect_strict_flex_arrays`] reads the
/// bound the compiler computes, and this reads whether a fortified `strcpy` past each
/// trailing array aborts. A row is read only from its own child's stderr, between the
/// markers the parent wrote around it, so one row's abort cannot be credited to another.
///
/// The `ctrl` row is a copy past a member that is not last, which every level bounds. It
/// is the witness that this build checks a subobject bound at all: where it survives,
/// fortify is below level 2, unoptimized, or absent, and every trailing row survives
/// whatever the flag says, so the reading is withheld rather than taken as level 0. A
/// caught `flex` row, a true flexible member no level bounds, says the probe is not
/// measuring what it means to, and withholds too.
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
        let said = |field: &str| run.stdout.split_whitespace().any(|f| f == field);
        if said("optimize=yes")
            && let Some(library) = library_without_subobject_bounds(ev, &run.stdout)
        {
            return Detection::absent(format!(
                "{observed}: _FORTIFY_SOURCE of 2 or more was requested in an optimized build \
                 under {library}, which checks no subobject bound, so no row has a \
                 fortified copy that could catch it"
            ));
        }
        let cause = if said("optimize=no") {
            "the build was not optimized, and glibc installs its fortified wrappers only in \
             an optimized build"
        } else {
            "the build checks no subobject bound: _FORTIFY_SOURCE below 2, no fortified \
             wrapper, or a wrapper that asks for the whole object"
        };
        return Detection::indeterminate(format!(
            "{observed}: the ctrl copy, past a member every -fstrict-flex-arrays level \
             bounds, was not caught, so {cause}, and the trailing rows cannot show the flag"
        ));
    }
    if flex {
        return Detection::indeterminate(format!(
            "{observed}: the flex row, a true flexible member no level bounds, was caught, \
             so the probe is not measuring what it is meant to"
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
                "{observed}: no -fstrict-flex-arrays level enforces this combination, so one \
                 of the rows is not measuring what it is meant to"
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

/// Did the guard the optimizer would otherwise delete survive?
///
/// Gated on optimization, on which compiler, and on gcc's version, which is two more
/// inputs than the aliasing detector beside it needs. At `-O0` gcc 8 and later fold the
/// guard away without the flag, so an unoptimized build of theirs that ran the guard ran
/// it because the flag was passed, and that reading is worth keeping. clang folds only in
/// the optimizer, so an unoptimized clang build runs the guard either way; crediting that
/// would publish `-fno-strict-overflow: on` for every clang measured under `bare`,
/// contradicting chard's own `bare-optimized` column for the same toolchain. The controls
/// cannot see it: both arms carry their own `-O2`, so they discriminate perfectly over a
/// measured cell the optimization level produced.
///
/// The gcc before 8 measured are clang's case, not gcc 8's. Measured with this probe on
/// x86_64, each compiler's own build at `-O0`, `-O1`, `-Og`, `-O2` and `-Os`
/// without the flag, and at `-O0`, `-O1` and `-O2` with it. Without the flag, gcc 4.8.4
/// (Ubuntu 14.04), 5.4.0 (Ubuntu 16.04) and 7.5.0 (Ubuntu 18.04) ran the guard at `-O0`,
/// `-O1` and `-Og`, and folded it at `-O2` and `-Os`. gcc 8.3.0 (Debian 10), 8.3.1 (Fedora
/// 28 and 29), 8.5.0 (AlmaLinux 8) and 9.4.0 (Ubuntu 20.04) folded it at every level. With
/// the flag, all seven versions ran it at every level measured. gcc 7.5.0 on Ubuntu 18.04
/// i386 read as on x86_64. At `-O`, measured on 7.5.0 and 8.3.0 alone, 7.5.0 ran the guard
/// and 8.3.0 folded it; both folded it at `-O3` and `-Ofast`. So the probe reports
/// `gcc-major=` beside `frontend=gcc`. An unoptimized gcc build is read from
/// [`GCC_FOLDS_UNOPTIMIZED_FROM`] on, and withheld below it with a reason that names the
/// optimization gate, as clang's is. gcc 6, 8.1 and 8.2 are unmeasured. The bound is 7.5.0
/// keeping the guard and 8.3.0 folding it, so a gcc 8.1 that kept it would read `on` here,
/// a wrong `on` the version alone cannot see. The assumption is
/// `gcc-folds-the-overflow-guard-unoptimized-from-8`.
///
/// An optimized build of a gcc before 8 that ran the guard is read by the level its own
/// compile line set, since no macro names the level and the probe cannot tell `-O1` from
/// `-O2`: at `-O`, `-O1` or `-Og` on gcc 4.8, 5.4 or 7.5 the guard ran without the flag
/// too, so an `on` there would be wrong. [`optimized_guard_ran_before_8`] reads the build
/// record's words through [`crate::compile_inputs::optimization_words`] (the driver's own
/// `-O` and `--optimize` words, so a `-Wl,-O1`, a `-Wp,-O1` or a word handed to another
/// program is not one), and the last one decides, as gcc's driver does. At
/// [`GCC_BEFORE_8_FOLDING_LEVELS`] the reading is `on` and names the level; at
/// [`GCC_BEFORE_8_KEEPING_LEVELS`] it is withheld; a build with no `-O` word that the probe
/// still reports optimized, a last word of `-O0` beside that report, a level not measured
/// (`-Oz`, `-O4`), a `-specs`, `-B`, `--prefix` or `-wrapper` word (each can lower the level
/// after the last `-O` word: on gcc 7.5.0 a specs file appending `-O1` to `cc1_options`
/// under `-O2`, named by `-specs` or found in a `-B` directory, ran the guard without the
/// flag), or no build record is withheld too, never `on`. A gcc that
/// reported no readable major version (evidence from a probe that prints none) is read
/// the same way, since the version that would excuse it is not there. Both control arms
/// carry `-O2`, so under every built-in profile and the arms the reading is unchanged; the
/// explicit profiles at those levels, which a reading of the guard alone would call `on`
/// under gcc 4.8.4, 5.4.0 and 7.5.0, withhold. The assumption is
/// `gcc-before-8-folds-the-overflow-guard-from-o2`.
///
/// `frontend=gcc` is any compiler that defines `__GNUC__` and not `__clang__`, and its
/// `gcc-major=` is that compiler's `__GNUC__`. A compiler that is not gcc and claims gcc 8
/// or later would be read by gcc 8's rule; none has been measured.
///
/// A guard that ran beside output on stderr is withheld whatever else the run says: a
/// sanitizer's checked add keeps the guard without the flag, and prints. The reasoning is
/// at the check below; the assumption is `signed-overflow-sanitizer-reports-on-stderr`.
/// A folded guard stays `off` beside any sanitizer, since nothing a sanitizer adds deletes
/// it.
///
/// Evidence carrying neither marker, and gcc evidence without `gcc-major=`, reads as
/// coming from a probe that did not emit them; an unoptimized guard that ran in either is
/// withheld rather than read under an assumption about which compiler produced it.
///
/// Every withholding of a guard that ran names `guard-kept-without-the-flag`
/// ([`GUARD_KEPT_WITHOUT_THE_FLAG`], through [`Detection::withheld`]), which
/// `measure::settle` publishes as the observation's `gating` where the triple
/// discriminated, so `coverage.withholding` counts it by rule rather than under
/// `no_named_cause`; a run that was not executed or carries no guard reading names no rule,
/// since nothing ran that the rule could speak about.
pub(crate) fn detect_no_strict_overflow(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    if run.has_marker("overflow-guard=ran") {
        // A guard that ran beside output on stderr is not the flag's doing alone. A
        // sanitizer's signed-overflow check is a checked add the optimizer cannot fold,
        // so with one compiled in the guard survives whether or not `-fwrapv` or
        // `-fno-strict-overflow` was passed, and that sanitizer says so on stderr: the
        // full runtime's `runtime error:` report, clang's minimal runtime's `ubsan:
        // add-overflow by 0x...`. The control arms are built from their own flags alone
        // and never carry the sanitizer, so they discriminate perfectly over a cell the
        // sanitizer produced (clang 22.1.8, Fedora 44 x86_64: `-O2 -fsanitize=undefined`
        // read `on` with this report on stderr, and `-O2` alone read `off`).
        //
        // Read from the run, not from the compile's flags: clang's `-fwrapv` switches the
        // signed-overflow check off beside `-fsanitize=undefined` (the guard ran and stderr
        // was empty, which is the flag's doing and still reads `on`) and not beside an
        // explicit `-fsanitize=signed-integer-overflow` (the guard ran and reported). The
        // flag list cannot tell those apart; the run can. A sanitizer that traps or aborts
        // never prints the guard line, and reads `indeterminate` below as no guard reading.
        // Any output counts, as it does for `detect_trapv`: a clean run of this probe
        // prints nothing on stderr, so what is there is not the probe's. The assumption
        // `signed-overflow-sanitizer-reports-on-stderr` in `report::ASSUMPTIONS` carries
        // what rests on the silent half.
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
                    "the overflow guard ran beside output on stderr ({:?}), which a sanitizer's \
                 signed-overflow check prints when it takes the addition; that check cannot \
                 be folded, so the guard survives whether or not the flag was passed and \
                 this build cannot answer the question",
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
/// flag, as the compile line spells them: `-O2`, `-O3` and `-Os` measured on gcc 4.8.4,
/// 5.4.0 and 7.5.0, `-Ofast` on 7.5.0 ([`detect_no_strict_overflow`] has the runs). A
/// guard that ran at one of these on such a gcc was kept by the flag.
const GCC_BEFORE_8_FOLDING_LEVELS: [&str; 4] = ["-O2", "-O3", "-Os", "-Ofast"];

/// The optimizing levels at which gcc before 8 keeps the guard without the flag: `-O`
/// (gcc's `-O1`), `-O1` and `-Og`, measured on gcc 4.8.4, 5.4.0 and 7.5.0. A guard that ran
/// at one of these says nothing about the flag.
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
/// `-O` word: gcc's `-specs=FILE` (also `-specs FILE` and `--specs`), whose `cc1_options`
/// can append an `-O1` that wins; `-B DIR` and `--prefix=DIR`, from whose directory gcc reads
/// a `specs` file the same way (gcc 7.5.0 ran the guard under `-O2 -B/dir/`, `-O2 -B /dir/`
/// and `-O2 --prefix=/dir/` with such a file, as under `-specs`); a forced include
/// (`-include`, `-imacros`, with one dash or two, alone, after `-Xpreprocessor` or inside a
/// `-Wp,` word), whose header can carry `#pragma GCC optimize ("O1")`, which lowers the
/// level for every function after it while `__OPTIMIZE__` stays defined (gcc 7.5.0 ran the
/// guard under `-O2 -include h` with that pragma, and under `--include h`, `-Wp,-include,h`
/// and `-Xpreprocessor -include h`); `-fplugin`, which loads code into the compiler, in a
/// `-Wp,` list or after `-Xpreprocessor` too (gcc 16.1.1 loaded the plugin named either
/// way); and `-wrapper`, which runs the compiler through a program of the profile's
/// choosing. `word`
/// is the word as the one classifier reads it (`toolchain::read`, whose readings
/// [`level_resetting_word`] walks the line by): each long spelling, and the abbreviations
/// gcc completes (7.5.0 ran the guard under `-O2 --pref /dir/` and `-O2 --spec file` as
/// under the full words), arrives as the short word; the value of an option that takes the
/// next word (`-u -B`, a symbol) never arrives; and a shorter abbreviation, which gcc
/// rejects (`--inc`), never builds.
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
/// names a symbol, `-o --pref` an output file, `-L -specs` a directory, and `-Xlinker
/// -specs=f` is the linker's word), and the word `-Xpreprocessor` hands `cc1`, or clang
/// applies for one architecture, is read as the driver's own and named where it resets.
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
            // there; a specs or prefix word handed to it fails the build, so naming that
            // too withholds a build that could not be read anyway.
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
///
/// The level is the last of the driver's own `-O` words on the recorded command, which is
/// how gcc resolves two of them. The probe's `optimize=yes` says only that `__OPTIMIZE__`
/// was defined, which `-O`, `-O1` and `-Og` define as `-O2` does, so the level has to come
/// from the words; a build whose words name none, or name `-O0` while the probe reports an
/// optimized build, was given its level by something chard did not pass (a specs or
/// configuration file, a wrapper), and is withheld rather than read under a guess, as is a
/// line that names such a file itself.
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
                "the overflow guard ran in an optimized build on {who} with no build record to \
             read the level from; {keeps}, so this build cannot answer the question"
            ),
        );
    };
    let words = build.argv.split_first().map_or(&[][..], |(_, flags)| flags);
    if let Some(word) = level_resetting_word(words) {
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
    let Some(word) = crate::compile_inputs::optimization_words(words).pop() else {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the overflow guard ran in an optimized build on {who} whose compile line carries \
             no -O word, so the level came from outside the words chard passed (a specs or \
             configuration file, or a wrapper); {keeps}, so this build cannot answer the \
             question"
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
            format!(
                "the overflow guard survived and fired, on {who} at {spelled}: gcc 4.8, 5.4 \
                 and 7.5 fold it there without the flag (-O2, -O3 and -Os measured on all \
                 three, -Ofast on 7.5; gcc 6 and 7.1 to 7.4 are unmeasured), so the flag is \
                 what kept it"
            ),
        );
    }
    if GCC_BEFORE_8_KEEPING_LEVELS.contains(&level.as_str()) {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the overflow guard ran in a build at {spelled} on {who}: {keeps}, and the \
             measured levels that fold it start at -O2, so this build cannot answer the \
             question"
            ),
        );
    }
    if level == "-O0" {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the overflow guard ran on {who} in a build the probe reports as optimized while \
             the compile line's last -O word is {spelled}, so the build was compiled at a \
             level chard's words did not set; {keeps}, so this build cannot answer the \
             question"
            ),
        );
    }
    Detection::withheld(
        GUARD_KEPT_WITHOUT_THE_FLAG,
        format!(
            "the overflow guard ran in a build at {spelled} on {who}, a level not measured on gcc \
         before 8, where only -O2, -O3, -Os and -Ofast are measured to fold it without the \
         flag, so this build cannot answer the question"
        ),
    )
}

/// The reading of a guard that ran, silently, in a build the probe reports as not
/// optimized: `on` only where the compiler would have folded it without the flag.
fn unoptimized_guard_ran(run: &RunRecord) -> Detection {
    if run.has_marker("frontend=clang") {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            "the guard ran in a build that was not optimized, where clang keeps it whether \
             or not the flag was passed, so this build cannot answer the question"
                .to_owned(),
        );
    }
    if !run.has_marker("frontend=gcc") {
        return Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            "the guard ran in a build that was not optimized, on a compiler the probe did \
             not identify as gcc or clang, and only gcc 8 and later are known to fold it \
             at -O0 without the flag, so this build cannot answer the question"
                .to_owned(),
        );
    }
    match gcc_major(run) {
        Some(Ok(major)) if major >= GCC_FOLDS_UNOPTIMIZED_FROM => Detection::present(
            None,
            format!(
                "the overflow guard survived and fired in a build that was not optimized, \
                 on gcc {major}, and gcc folds it at -O0 without the flag from gcc \
                 {GCC_FOLDS_UNOPTIMIZED_FROM} on (8.3.0 the oldest measured)"
            ),
        ),
        Some(Ok(major)) => Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the guard ran in a build that was not optimized, on gcc {major}: gcc 4.8, 5.4 \
             and 7.5 keep it whether or not the flag was passed, and only gcc \
             {GCC_FOLDS_UNOPTIMIZED_FROM} and later are known to fold it at -O0, so this \
             build cannot answer the question"
            ),
        ),
        Some(Err(_)) | None => Detection::withheld(
            GUARD_KEPT_WITHOUT_THE_FLAG,
            format!(
                "the guard ran in a build that was not optimized, on a gcc that reported no \
             readable major version, and only gcc {GCC_FOLDS_UNOPTIMIZED_FROM} and later \
             fold it at -O0 without the flag, so this build cannot answer the question"
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
        Detection::absent(
            "the null check was deleted: the dereference was taken as proof the pointer \
             could not be null"
                .to_owned(),
        )
    } else {
        Detection::indeterminate(format!(
            "no null-check reading in {:?} (exit={} signal={:?}). A death here is the \
             probe needing optimization it did not get: without it the dead load is not \
             eliminated and the null dereference actually executes",
            excerpt_tail(ev, &run.stdout, 80),
            run.exit_status,
            run.signal
        ))
    }
}

/// Was the store through the incompatible pointer observed?
///
/// Gated on `__OPTIMIZE__`, and that gate is the whole difference between this detector
/// and the overflow one beside it. Measured on gcc: at `-O0` the store is observed
/// whether or not the flag is passed, because nothing is being held in a register to go
/// stale. Crediting that would report the flag in force for a build that merely was not
/// optimized — a positive reading produced by the question not having been put.
///
/// `__OPTIMIZE__` is not enough on gcc, which enables the rule by default only from `-O2`
/// and `-Os`: at `-O1` and `-Og` the store is observed with no flag passed, and this
/// detector would publish `on` there without a witness. The probe's two witness copies, and
/// what each one's reading means on which gcc, are in `probes/ub_strict_aliasing.c`. An
/// observed store is credited only where a witness shows the flag rather than the level:
/// the `-O2` copy observed it too and the build's own tail call became a jump, or the copy
/// rebuilt at the build's own level lost it. An observed store beside neither is the level
/// speaking and is withheld, and so is one beside a witness that did not run as built. The
/// witnesses can only withhold or confirm an observed store; a lost one is `off` as before,
/// since the rule was applied.
///
/// The tail call is the level witness on gcc 12 and later, where the `-O2` copy keeps the
/// flag and so shows the flag without the level: -O1 and -Og with the flag print the
/// same lines as -O2 with it, and the flag there is present and inert. gcc enables
/// sibling calls by default at the levels that enable the aliasing rule, so a jump names
/// a level where the flag does something. The probe carries the measurement and what
/// moves the witness; the assumption is `sibling-calls-follow-the-aliasing-level` in
/// `report::ASSUMPTIONS`. Crediting from the `-O2` copy alone would read `present` at -O1
/// and -Og.
///
/// Two outputs read without a witness: a `not-built` witness,
/// which is clang (it implements no `optimize` attribute and applies the rule from
/// `-O1`), and evidence with no witness line at all, as a probe without the witnesses records.
/// The first is measured to need nothing more; the second is what the recorded fixtures
/// carry, and a live run cannot produce it, since the probe source is in the corpus
/// digest. Evidence with the `-O2` witness and no `sibling-call` line is the same case
/// with the one witness, and reads the same way.
///
/// A sanitizer can keep the store too. clang's recoverable `-fsanitize=alignment`, part of
/// `-fsanitize=undefined`, puts a handler call that may write memory between the store and
/// the reload, so the reload stays with the rule in force, and this check would read `on`
/// under clang's `-fsanitize=undefined` with no flag passed. The probe carries the
/// shape once more without sanitizer instrumentation, and an observed store beside an
/// uninstrumented copy that lost it is the instrumentation speaking and is withheld. That
/// copy can only withhold: one that observed the store beside a build that lost it is
/// withheld as a reading no mechanism produces, and `not-built`, a compiler without the
/// `no_sanitize` attribute, reads as a probe without the copy does. The mechanism
/// and the sanitizers measured are in `probes/ub_strict_aliasing.c`; that the attribute
/// removes whatever instrumentation keeps the store is
/// `no-sanitize-removes-store-keeping-instrumentation` in `report::ASSUMPTIONS`.
pub(crate) fn detect_no_strict_aliasing(ev: &Evidence<'_>) -> Detection {
    let Some(run) = ev.run else {
        return Detection::indeterminate("probe not executed".to_owned());
    };
    // Read from the probe's own output, not from `ev.macros`: that map is populated
    // only for probes carrying a macro-channel check, and this one is runtime-only. A
    // detector reading it there found nothing and withheld every arm, so the control
    // triple could not discriminate and the check reported `probe-invalid` on a
    // toolchain where it works perfectly.
    if run.has_marker("optimize=no") {
        return Detection::indeterminate(
            "compiled without optimization: the store is observed whether or not the \
             flag was passed, so this build cannot answer the question"
                .to_owned(),
        );
    }
    let o2_observed = run.has_marker("o2-witness=observed");
    if run.has_marker("aliasing-store=observed") {
        if run.has_marker("uninstrumented-store=lost") {
            return Detection::indeterminate(
                "the store through the incompatible pointer was observed, but the copy \
                 compiled without sanitizer instrumentation under the build's own options \
                 lost it: the rule is in force, and the build's sanitizer checks kept the \
                 store (measured for clang's -fsanitize=alignment, part of \
                 -fsanitize=undefined, and -fsanitize=type), not the flag"
                    .to_owned(),
            );
        }
        aliasing_store_observed(run, o2_observed)
    } else if run.has_marker("aliasing-store=lost") {
        if run.has_marker("uninstrumented-store=observed") {
            return Detection::indeterminate(
                "the store was lost in the build, yet the copy compiled without sanitizer \
                 instrumentation under the build's own options observed it; no \
                 instrumentation measured produces that, so one of the two readings is not \
                 measuring what it is meant to"
                    .to_owned(),
            );
        }
        if o2_observed {
            return Detection::indeterminate(
                "the store was lost in the build, yet the copy compiled at -O2 under the \
                 build's own options observed it; no combination of level and flag \
                 produces that, so one of the two readings is not measuring what it is \
                 meant to"
                    .to_owned(),
            );
        }
        Detection::absent(
            "the store was not observed: the read was folded to the stale value".to_owned(),
        )
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
            "{observed}, and the copy compiled under optimize(\"O2\", \"strict-aliasing\") \
             did not report losing it, so the optimize attribute the witnesses rest on was \
             not honoured and nothing separates the flag from the optimization level"
        ));
    }
    if o2_observed {
        return o2_copy_observed(run, observed);
    }
    if run.has_marker("level-witness=lost") {
        return Detection::present(
            None,
            format!(
                "{observed}, while the copy rebuilt from this optimization level's defaults \
                 lost it, so the level applies the rule and the build turned it off"
            ),
        );
    }
    if run.has_marker("level-witness=observed") {
        return Detection::indeterminate(format!(
            "{observed}, but the copy compiled at -O2 lost it and the copy at this level \
             observed it: this optimization level does not apply the rule by default (gcc \
             enables it from -O2 and -Os), so the observation is the level's and not the \
             flag's"
        ));
    }
    Detection::indeterminate(format!(
        "{observed}, and the -O2 copy lost it, but the probe printed no reading for the \
         copy at this level, so nothing separates the flag from the optimization level"
    ))
}

/// The store observed by the build and by the `-O2` copy, which shows the flag on gcc 12
/// and later; the build's tail call says whether its level is one the flag acts at.
/// [`detect_no_strict_aliasing`] carries the argument.
fn o2_copy_observed(run: &RunRecord, observed: &str) -> Detection {
    let by_o2_copy = "and observed by the copy compiled at -O2 under the build's own options, \
                      so the flag is in force at -O2";
    if run.has_marker("sibling-call=made") {
        return Detection::present(
            None,
            format!(
                "{observed}, {by_o2_copy}; the build's own tail call became a jump, which \
                 gcc does by default at the levels that apply the rule (-O2, -O3, -Os, -Oz, \
                 -Ofast), so this build's level is one the flag acts at"
            ),
        );
    }
    if run.has_marker("sibling-call=not-made") {
        return Detection::indeterminate(format!(
            "{observed}, {by_o2_copy}, but the build's own tail call stayed a call: gcc \
             makes it a jump by default only at the levels that apply the rule, so this \
             build is at -O1 or -Og, where the rule is off by default and the flag changes \
             nothing, or its flags keep the call from becoming a jump (measured for \
             -fno-optimize-sibling-calls, -finstrument-functions, -fstrub=all and \
             -fstrub=at-calls), which takes the witness away"
        ));
    }
    // Recorded by the probe revision before the tail-call witness, which credited this
    // reading from the -O2 copy alone; a live run cannot produce it.
    Detection::present(
        None,
        format!(
            "{observed}, {by_o2_copy}, which applies the rule by default; this reading \
             does not establish the build's own level, and at -O1 or -Og the flag is \
             credited from that copy alone"
        ),
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
///
/// The witness is checked before the observation, not after. `ctrl` opts out of
/// initialization entirely, so it must read back the dirt; when it does not, the two
/// frames did not coincide and the padding byte means nothing — and it means nothing in
/// the direction that looks like success, because a frame that was never dirtied reads
/// zero. From `-O1` upward on gcc that is exactly what happens, so this withholds there
/// rather than reporting a flag that was never established.
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
    if ctrl_supported && ctrl != ZIPB_DIRT {
        return Detection::indeterminate(format!(
            "frame reuse did not hold: the opted-out control read 0x{ctrl:02x} rather than \
             0x{ZIPB_DIRT:02x}, so pad=0x{pad:02x} establishes nothing either way"
        ));
    }
    match pad {
        0x00 => Detection::present(None, format!("pad=0x00 ctrl=0x{ctrl:02x}")),
        ZIPB_DIRT => Detection::absent(format!(
            "pad=0x{ZIPB_DIRT:02x} (the dirt survived: the initializer left the bytes it \
             does not name)"
        )),
        other => Detection::indeterminate(format!(
            "pad=0x{other:02x} is neither the dirt nor zero, so nothing is established"
        )),
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
    }
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
        // Anything else is not a pattern fill. Note this includes a uniform 0x00,
        // which means `=zero` (or clang's incidental zeroing) — correctly `absent`
        // for a check asking specifically about `=pattern`.
        FillReading::Uniform(b) => Detection::absent(format!("fill=0x{b:02x}, not a pattern fill")),
        FillReading::Mixed => {
            Detection::absent("shapes disagreed: no uniform pattern fill".to_owned())
        }
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
/// architecture (`CHARD_ARGS` and `CHARD_TEMP` in `zero_call_used_regs.c`). The probe
/// prints both from the one `#if` that picks the architecture and prints no architecture
/// name, so the pair is how the line says where it ran: `Evidence` carries no architecture
/// and this adds no channel for it. A count outside the pair is a line this probe did not
/// print, and `args=0` would otherwise pass every letter test over an empty string.
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
///
/// The probe reads the registers in an assembly trampoline immediately after the return,
/// one letter each: `z` zero, `k` the marker the trampoline loaded, `o` anything else. The
/// witness comes first: the same trampoline around a function that only returns must give
/// back every marker, or the reading says nothing about the compiled function. Then:
///
/// - every argument register zero is the flag; the non-argument register the function was
///   made to use separates the forms that clear every used register (`gpr`) from the
///   `-arg` forms that clear only argument registers (`arg`). Code the compiler emits after
///   the clearing can write that register too and read `arg` under a `gpr` form, which is
///   why the probe's choice of register is measured: OpenBSD's RETGUARD epilogue writes
///   `x9` on arm64, and the probe reads `x10` (`zero_call_used_regs.c`);
/// - any argument register still holding its marker is a register the function read and
///   returned unchanged, which the flag in any form that reaches argument registers does
///   not allow, so it is `absent`;
/// - anything else, argument registers changed but none kept and not all cleared, is
///   withheld.
///
/// `absent` asks for a kept marker rather than for no zero, because an epilogue can zero
/// a register for its own reasons. gcc 16.2.1 on aarch64 under `-fstack-protector-all`
/// leaves the canary comparison's two registers, `x1` and `x2`, at zero, and the line reads
/// `ozzkkokk/o` with no zeroing flag at all (Fedora 44, 2026-10-01). Requiring every
/// argument register zero for `present` is what keeps that from reading `on`.
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
            "the probe has no register witness for this architecture (it is written for \
             x86_64 and aarch64), so nothing was read"
                .to_owned(),
        );
    }
    let Some(r) = zcur_reading(run) else {
        let what = if run.stdout.lines().any(|l| l.starts_with("ZCUR ")) {
            "a ZCUR line this probe does not print (a field missing or malformed, or an \
             args= and temp= pair no supported architecture gives)"
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
            "{line}: the witness failed, since a function that only returns gave back \
             registers other than the markers loaded into them, so the trampoline's reading \
             of the compiled function establishes nothing"
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
            format!(
                "{line}: every argument register read zero after the function returned, and \
                 the non-argument register it used did not, which is what the `-arg` forms \
                 leave, or what code emitted after the clearing leaves"
            ),
        );
    }
    if r.args.contains('k') {
        return Detection::absent(format!(
            "{line}: an argument register the function read came back holding the value \
             the caller put there"
        ));
    }
    Detection::indeterminate(format!(
        "{line}: the argument registers neither all read zero nor kept a value the caller \
         put there, so the reading is neither the flag nor its absence"
    ))
}

/// What glibc's loader prints when it refuses to start a program whose `PT_GNU_STACK` asks
/// for an executable stack, as a Wolfi-derived rootfs's glibc 2.44-r23 did (measured 2026-10-21
/// on Fedora 44 x86_64's kernel: exit 127, `Fatal glibc error: executable stack is not allowed`).
const LOADER_EXECSTACK_REFUSAL: &str = "executable stack is not allowed";

/// The loader's refusal line in a run's stderr, where the run exited 127 (the loader's
/// fatal-error status) and no signal ended it; `None` for any other run.
pub(crate) fn loader_refusal(run: &crate::run::RunRecord) -> Option<&str> {
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
///
/// Both readings are affirmative and each needs the probe's `calling` line first, so a probe
/// that died before the call has no reading. `present` (the stack is not executable) is a
/// SIGSEGV whose fault address the handler compared with the payload's own address and
/// found equal; a fault anywhere else, a SIGILL, or a return value other than the marker is
/// `stack-exec=unknown` and withheld. `absent` is the payload returning its marker, 77,
/// which nothing else in the probe produces. Either reading also needs the clean exit the
/// probe takes after printing it, so a line followed by a crash is not read.
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
            "{observed} (the probe did not exit cleanly after the call, so no line it printed \
             is read)"
        ));
    }
    let not_exec = lines.contains(&"NXRT stack-exec=no fault=payload");
    let exec = lines.contains(&"NXRT stack-exec=yes ret=77");
    match (not_exec, exec) {
        (true, false) => Detection::present(None, observed),
        (false, true) => Detection::absent(observed),
        _ => Detection::indeterminate(format!(
            "{observed} (neither a fault at the payload's address nor the payload's marker, \
             so the stack's mapping is not identified)"
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
///
/// The two are published differently, so the reading keeps them apart. The kernel is the
/// measured system's own (the host's, or the guest's in a VM the fleet boots from the
/// distribution's image), and its lack is a fact about what was measured. The CPU is the
/// one the run was handed: bare metal chard happened to run on, or the virtual CPU a
/// hypervisor gave the guest, which belongs to the harness and not to the distribution.
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
    ///
    /// Only errno 22 names the kernel: it is what `arch_prctl` returns for an option the
    /// kernel does not implement, measured on Ubuntu 22.04's 5.15 kernel. Any other errno
    /// (an `EPERM` or `ENOSYS` from a seccomp filter in a sandbox or a lane) is a refusal
    /// with an unmeasured cause, which `detect_shadow_stack` withholds as `indeterminate` and
    /// this leaves unattributed, so the cell stays `probe-invalid`.
    ///
    /// Read from the probe's own run rather than from `environment.cpu`: the probe asks the
    /// kernel and the CPU it ran on, in the process whose shadow stack is in question, and
    /// `/proc/cpuinfo` is the kernel's account of the CPU, which a kernel without the
    /// feature compiled in does not give. The premise is the register's
    /// `shstk-status-and-cpuid-name-the-machine`.
    pub fn machine_lacks(&self) -> Option<MachineLack> {
        if self.kernel == KERNEL_LACKS_SHSTK {
            return Some(MachineLack {
                part: LackingPart::Kernel,
                sentence: format!(
                    "the kernel answered `arch_prctl(ARCH_SHSTK_STATUS)` with `{}`, so it \
                     offers no user shadow stack",
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
    // `%#lx`: `0` for zero, `0x..` otherwise. `None` is "the probe printed no number".
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
/// showed: applied only where its tunable took effect. A C library that ignores
/// `GLIBC_TUNABLES` runs the pinned process as an unpinned one, and a sentence saying the
/// opt-in was in force there would be false.
/// A process enforced under the pin shows the opt-in took effect whatever the witness read,
/// so its sentence claims nothing about the witness beyond `honoured`.
fn opt_in_phrase(tunables: Option<&str>, enforced: bool) -> &'static str {
    match tunables {
        Some("honoured") => "under glibc's opt-in",
        _ if enforced => "with glibc's opt-in set",
        Some(SHSTK_TUNABLES_IGNORED) => {
            "with glibc's opt-in set, the tunable pinned beside it showing no effect (`SHSTK \
             tunables=ignored`), so the probe does not show that the opt-in reached the C \
             library"
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
///
/// Three readings of one process must agree. The kernel's status word has bit 0 set, the
/// shadow stack pointer `rdsspq` reads is non-zero, and the return address an assembly
/// function overwrote faulted with `SEGV_CPERR`: that is `present`. Bit 0 clear, a zero
/// pointer and the overwritten return taken is `absent`. Anything else is withheld:
///
/// - a kernel that refused the status query or a CPU that does not enumerate `CET_SS` is a
///   machine that cannot run a shadow stack for any build, which the gating rule
///   `kernel-lacks-shadow-stack` or `cpu-lacks-shadow-stack` names when it silences the
///   positive control;
/// - readings that disagree (bit 0 set and the return taken, a fault with another `si_code`,
///   no second line) say something is wrong with the probe or the machine, and neither
///   side is established.
///
/// `absent` asks for the hijack to have happened, not only for the status to be clear, so a
/// probe that crashed before the clobber, or a clobber that faulted for another reason,
/// cannot read as a program running without a shadow stack. The probe's header carries the
/// measurements; the pin that arms glibc is `Probe::run_environment`.
///
/// That is the pinned process, and it decides the outcome, so the control triple
/// discriminates on it. The level comes from the probe's second process, the same program
/// run without `GLIBC_TUNABLES`, read the same way: enforced there too is
/// [`SHSTK_DEFAULT`], not enforced there is [`SHSTK_OPT_IN`], which `decide` grades below
/// the ask and publishes `partial`. Where the unpinned reading is neither (no line, a
/// process that could not be started, readings that disagree), `present` carries no level
/// and the graded check withholds the verdict under `level-outside-check-scale`, which an
/// `on` from the pinned reading alone would otherwise have been: the reverse error. An
/// unpinned process enforced beside a pinned one that is not contradicts the tunable's only
/// effect, and is withheld.
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
            "the probe has no shadow-stack reading for this architecture (it reads x86 \
             CET through `arch_prctl`, which Linux offers on x86_64 alone), so nothing was read"
                .to_owned(),
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
            "{line}: the kernel refused `arch_prctl(ARCH_SHSTK_STATUS)` with `{}`, which is \
             not the `EINVAL` of a kernel without the feature, so the status word was not \
             read and the refusal's cause is not established",
            r.kernel
        ));
    }
    let Some(clobber) = r.clobber else {
        return Detection::indeterminate(format!(
            "{line}: the probe printed no clobber line (exit={} signal={:?}), so the \
             overwritten return was not observed",
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
                "{line} / clobber={clobber}: enforced {opt_in}, and the run without it \
                 established neither enforcement nor its absence ({unpinned_said}), \
                 so whether a deployment that sets no tunable gets it is not read"
            ),
        ),
        (Enforcement::NotEnforced, Enforcement::Enforced) => Detection::indeterminate(format!(
            "{line} / clobber={clobber}: off {opt_in}, yet enforced without it \
             ({unpinned_said}), which contradicts the tunable's only effect, so neither side \
             is established"
        )),
        (Enforcement::NotEnforced, _) => Detection::absent(format!(
            "{line} / clobber={clobber}: the kernel reports no shadow stack for the \
             process, the shadow stack pointer reads zero, and the overwritten return \
             address was taken, {opt_in}"
        )),
        (Enforcement::Unestablished, _) => Detection::indeterminate(format!(
            "{line} / clobber={clobber}: the status word, the shadow stack pointer and the \
             overwritten return disagree, so neither enforcement nor its absence is \
             established"
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
/// on every signal death under emulation (see the project ledger).
const QEMU_SIGNAL_REPORT: &str = "qemu: uncaught target signal";

/// What UBSAN's handler prints when it reports a check, in its recovering and its
/// aborting mode alike.
const UBSAN_REPORT: &str = "runtime error:";

/// Did a signed `int` overflow kill the `trapv` probe, and was it -ftrapv that did?
///
/// The probe prints which front end built it, whether a UBSAN check was compiled in, and
/// `trapv-overflow=attempted`, flushes, adds 1 to `INT_MAX`, and prints
/// `trapv-overflow=wrapped` if it is still alive. Each compiler's -ftrapv has one manner
/// of death and nothing on stderr, and this function credits only that one:
///
/// - gcc calls libgcc's `__addvsi3`, which calls `abort()`: `SIGABRT`.
/// - clang branches to a trap instruction: `SIGILL` on x86 (`ud1`), `SIGTRAP` on aarch64
///   (`brk`), which is [`RunRecord::trapped`].
///
/// Measured 2026-10-02 over the probe's addition at `-O0`, `-O1`, `-O2`, `-O3`, `-Os` and
/// `-Og`. gcc under `-ftrapv`: `SIGABRT`, stderr empty, on gcc 16.1.1 (Fedora 44 x86_64),
/// 16.2.1 (Fedora 44 aarch64), 15.2.0 (Alpine x86_64, musl), 13.3.0 (Ubuntu 24.04), 12.2.0
/// (Debian 12 i386) and 11.4.0 (Ubuntu 22.04). clang under `-ftrapv`: `SIGILL` on clang
/// 22.1.8 (Fedora 44 x86_64), 23.1.2 (Alpine), 18.1.3 (Ubuntu 24.04) and 14.0.0 (Ubuntu
/// 22.04), `SIGTRAP` on clang 22.1.8 (Fedora 44 aarch64), stderr empty. Flagless, each
/// exited 0 with the wrapped sum.
///
/// The precedence of `-fwrapv` differs and decides what an `off` means. On gcc the last of
/// `-ftrapv`, `-fno-trapv`, `-fwrapv` and `-fno-strict-overflow` wins, so `-ftrapv
/// -fwrapv` wraps and reads `off`, truly. clang has no `-fno-trapv`, and its -ftrapv
/// trapped under `-fwrapv` and `-fno-strict-overflow` in either order, so there it reads
/// `on`, truly.
///
/// What is withheld, and why:
///
/// - A trap from a gcc build. gcc's -ftrapv aborts; a gcc trap here is UBSAN's
///   signed-integer-overflow check in trap mode, which trapped on every gcc above that
///   has trap mode, with and without `-ftrapv` beside it.
/// - A clang trap beside `ubsan=yes` or `ubsan=unknown`. clang's trap-mode UBSAN emits the
///   same test and the same instruction as its -ftrapv (the detection recipe found the
///   objects identical), so the trap is credited only where
///   `__has_feature(undefined_behavior_sanitizer)` read 0, which is the assumption
///   `clang-ubsan-feature-covers-signed-overflow` in `report::ASSUMPTIONS`.
/// - An abort from a clang build, an abort with anything on stderr (the stack protector,
///   fortify and an aborting UBSAN handler all print first), and a UBSAN report on
///   stderr with any outcome: with the signed-overflow check compiled in, the sanitizer
///   takes the addition and -ftrapv's own effect cannot be seen.
/// - A wrapped sum beside `ubsan=yes` or anything on stderr. The `runtime error:` match
///   finds only the full runtime's report; clang's minimal runtime reports as `ubsan:
///   add-overflow by 0x...` and recovers, so a wrapped sum with a sanitizer compiled in
///   is not the flag off.
///
///   The feature test says that some UBSAN check is compiled in, not which one, so this
///   rule and the clang trap rule above withhold beside any check at all. A build carrying
///   only `-fsanitize=bounds` in trap mode reads `indeterminate` where it would otherwise
///   read `off` (clang, and gcc wherever it has `__has_feature`), and clang reads
///   `indeterminate` with `-ftrapv` beside it too; gcc's abort is still credited there. The
///   cost is coverage, never a wrong verdict: the project ledger has the readings and what would
///   narrow it.
/// - A run that never printed `trapv-overflow=attempted`, which did not reach the question.
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
    // Every line of stderr but the one qemu-user appends to a guest that dies by a signal,
    // which is the emulator's report of the death and not the probe's output. Measured
    // 2026-10-02: the static aarch64 probe printed nothing on stderr natively and that one
    // line under qemu-aarch64 10.2.2, for gcc's abort and clang's trap alike.
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
        return Detection::indeterminate(format!(
            "{observed} (UBSan reported the overflow, so its signed-overflow check took the \
             addition and -ftrapv's own effect cannot be seen)"
        ));
    }
    // A wrapped sum is the flag off only where nothing else could have taken the addition.
    // A UBSan check compiled in, in recovering mode, reports and lets the sum wrap whether
    // or not -ftrapv is beside it, and not every runtime says `runtime error:`: clang's
    // minimal runtime printed `ubsan: add-overflow by 0x...` and exited 0 (clang 22.1.8,
    // Fedora 44 x86_64, 2026-10-02). So a feature test reading `yes`, or any stderr at all,
    // withholds the `off`.
    if overflow == Some("wrapped") && (ubsan == "yes" || !stderr.is_empty()) {
        return Detection::indeterminate(format!(
            "{observed} (the sum wrapped beside a compiled-in UBSan check or output on \
             stderr, so a recovering sanitizer may have taken the addition and -ftrapv's own \
             effect cannot be seen)"
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
                "{observed} (a UBSan check was compiled in or could not be ruled out, and \
                 clang's trap-mode signed-overflow check traps exactly as its -ftrapv does)"
            )),
            ("gcc", _) => Detection::indeterminate(format!(
                "{observed} (gcc's -ftrapv aborts rather than traps; a trap here is UBSan's \
                 signed-overflow check in trap mode)"
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
        "the run printed on stderr, which neither compiler's -ftrapv does"
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
/// Parsed by [`translation`]; read by `report::emulation_limitation` and
/// `report::emulation_agrees` on a macOS run alone, where only [`Translation::Native`]
/// publishes a reading that rests on the machine.
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

/// The [`Translation`] a run's stdout carries.
///
/// The line is read where the header writes it, as stdout's first line. No line opening
/// with [`TRANSLATION_MARKER`] anywhere is [`Translation::Unreported`]; one on any later
/// line, a second or one after the probe's own output, makes the read
/// [`Translation::Unrecognised`] whatever the lines say, since the header writes one, first,
/// and any other is not the probe's own. `0` and `1` alone are
/// readings; `unreadable` with one of the header's three `name:number` words is
/// [`Translation::Unreadable`]; anything else, a trailing word included, is unrecognised.
/// A line is quoted with Rust's escapes and cut at [`TRANSLATION_QUOTE_CAP`] characters, so
/// a control character in the stream reaches a reason as text.
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
