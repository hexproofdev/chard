// SPDX-License-Identifier: BSD-3-Clause

//! The compiler-diag detectors: each reads what the compiler or the linker said while
//! building a probe, from the build's exit status and stderr.

use super::common::{excerpt_around, excerpt_at, needle_line, structured_stream};
use crate::compile::BuildRecord;
use crate::probe::{Detection, Evidence, Outcome};
use crate::report::gating_rule::{self, DetectorRule};

// --- compiler-diag detectors --------------------------------------------------

pub(crate) fn detect_hardened_warning(ev: &Evidence<'_>) -> Detection {
    // The wording, never the `[-Whardened]` tag: see `diag_severity_of` for the three
    // measured ways keying on an option name goes wrong.
    let mut detection = diag_presence_with(ev, HARDENED_DOWNGRADE_NEEDLES, Canary::AskedByFlags);
    let unread = ev.build.and_then(|build| {
        let (index, _) = needle_line(&build.stderr, &["is not enabled by"])?;
        build
            .stderr
            .lines()
            .nth(index)
            .map(|line| ev.published(line.trim()))
    });
    if detection.outcome == Outcome::Absent
        && let Some(line) = unread
    {
        detection.observed = format!(
            "{} (another option's downgrade was reported and is not read: {line:?})",
            detection.observed
        );
    }
    detection
}

/// `-Wl,--no-copy-dt-needed-entries`, read from a link that refused.
pub(crate) fn detect_no_copy_dt_needed(ev: &Evidence<'_>) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, DT_NEEDED_REFUSALS);

    if build.succeeded() {
        // The linker followed A's DT_NEEDED into B and resolved the symbol, which is
        // exactly what the flag exists to forbid.
        return Detection::absent(observed);
    }

    // The symbol only the transitive library defines, in the linker's refusal: other
    // failures produce undefined references too, and a compiler quotes the name alone.
    if needle_line(&build.stderr, DT_NEEDED_REFUSALS).is_some() {
        return Detection::present(None, observed);
    }

    Detection::indeterminate(format!(
        "{observed} (the link failed and no line of its stderr is a linker refusing chard_dt_bfunc in a wording chard reads)"
    ))
}

/// The linker's refusal of `chard_dt_bfunc`, the symbol only `libchard_dt_b.so` defines,
/// in each spelling measured: GNU ld's
/// `undefined reference to symbol 'chard_dt_bfunc'` (Ubuntu 20.04 to Fedora 44) and lld's
/// `undefined symbol: chard_dt_bfunc` (Chimera Linux, clang 22.1.7). The compiler runs under
/// `LC_ALL=C`, so GNU ld quotes in ASCII, and its needle carries the closing quote. lld's
/// line ends at the name, so its needle is a prefix: the probe and its libraries define no
/// other symbol beginning `chard_dt_bfunc`, which a test holds. lld 23.1.0 (macOS, linking
/// aarch64 objects of these sources, 2026-10-23) words the refusal the same way, and
/// words a library B it cannot find through A the same way too, a recipe failure every arm
/// shares and the triple reads `probe-invalid`. A linker whose refusal is worded otherwise
/// (gold and mold were not measured) reads `indeterminate`, the safe side. Named once so
/// the line the detector matches and the line its excerpt centres on are the same line.
pub(crate) const DT_NEEDED_REFUSALS: &[&str] = &[
    "undefined reference to symbol 'chard_dt_bfunc'",
    "undefined symbol: chard_dt_bfunc",
];

/// The exported global `probes/pic_shared_link.c` defines and reads, which a non-PIC
/// reference makes the linker refuse by name.
const PIC_SHARED_SYMBOL: &str = "chard_pic_anchor";

/// The part of the refusal every linker measured writes on the line naming the symbol, after
/// the symbol: GNU ld, lld, mold and gold, on x86_64 (`R_X86_64_PC32`) and aarch64
/// (`R_AARCH64_ADR_PREL_PG_HI21`) alike, so the relocation's name is not matched.
const PIC_SHARED_REFUSAL: &str = "recompile with -fPIC";

/// The linker naming [`PIC_SHARED_SYMBOL`] as the target of the relocation it refuses, in
/// each spelling measured for `-O2 -fPIE -shared probes/pic_shared_link.c` in a Fedora 44
/// x86_64 image (gcc 16.2.1 and clang 22.1.8, `LC_ALL=C`): GNU ld 2.46.1 and mold 2.40.4
/// write ``against symbol `chard_pic_anchor'``, LLD 22.1.8 `against symbol
/// 'chard_pic_anchor'`, and gold 1.16 `against 'chard_pic_anchor'`. GNU ld on aarch64 words
/// it as on x86_64, and GNU ld 2.24 and 2.26 (Ubuntu 14.04
/// and 16.04 x86_64) write ``against `chard_pic_anchor'``.
/// The compiler runs under `LC_ALL=C`, so GNU ld quotes in ASCII. A linker whose refusal is
/// worded otherwise reads `indeterminate`, the safe side.
const PIC_SHARED_REFUSALS: &[&str] = &[
    "against symbol `chard_pic_anchor'",
    "against `chard_pic_anchor'",
    "against symbol 'chard_pic_anchor'",
    "against 'chard_pic_anchor'",
];

/// The line of `stderr` that is the linker refusing the probe's reference for want of
/// -fPIC: one of [`PIC_SHARED_REFUSALS`], and [`PIC_SHARED_REFUSAL`] after it on the same
/// line. Returns the line's index, counted as `str::lines` counts, so the verdict and the
/// excerpt ([`excerpt_at`]) rest on one line by construction.
fn pic_refusal_line(stderr: &str) -> Option<usize> {
    stderr.lines().position(|line| {
        PIC_SHARED_REFUSALS.iter().any(|symbol| {
            line.split_once(symbol)
                .is_some_and(|(_, after)| after.contains(PIC_SHARED_REFUSAL))
        })
    })
}

/// `-fPIC`, read from whether code compiled under the flags links `-shared`.
pub(crate) fn detect_pic_shared_link(ev: &Evidence<'_>) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let refusal = pic_refusal_line(&build.stderr);
    let observed = build_observed_at(ev, build, refusal, PIC_SHARED_REFUSALS);

    if build.succeeded() {
        if build.artifact_sha256.is_none() {
            return Detection::indeterminate(format!(
                "{observed} (the link exited 0 and wrote no shared object)"
            ));
        }
        // Text relocations are the one way non-PIC code is linked into a shared object
        // whole, and the link succeeds over them.
        if let Some(why) = text_relocations_permitted(build) {
            return Detection::indeterminate(format!(
                "{observed} (the link succeeded {why}, so it does not show the code is \
                 position-independent)"
            ));
        }
        // What the link wrote, whatever its line said.
        let Some(elf) = ev.elf.filter(|elf| elf.has_dynamic) else {
            return Detection::indeterminate(format!(
                "{observed} (the dynamic section of the shared object the link wrote was not read)"
            ));
        };
        if elf.textrel {
            return Detection::indeterminate(format!(
                "{observed} (the linked shared object carries DT_TEXTREL)"
            ));
        }
        return Detection::present(None, observed);
    }

    if refusal.is_some() {
        return Detection::absent(observed);
    }

    Detection::indeterminate(format!(
        "{observed} (the link failed and no line of its stderr is a linker refusing a \
         reference to {PIC_SHARED_SYMBOL} for want of -fPIC in a wording chard reads, so the \
         failure is not read as this check's refusal and the arm poses no question)"
    ))
}

/// Why a successful link may have taken non-PIC code by text relocation, if it may have.
fn text_relocations_permitted(build: &BuildRecord) -> Option<&'static str> {
    if link_line_permits_text_relocations(&build.argv) {
        return Some("under a link line that permits text relocations");
    }
    let reported = build.stderr.lines().any(|line| {
        TEXT_RELOCATION_WARNINGS
            .iter()
            .any(|warning| line.contains(warning))
    });
    if reported {
        return Some("with the linker reporting text relocations");
    }
    None
}

/// The warnings a linker writes where it linked a shared object by text relocation and its
/// textrel check warns rather than refuses (`--warn-textrel`, `--warn-shared-textrel`, or GNU
/// ld configured `--enable-textrel-check=warning`, which no image here carries, so that one
/// is not measured), each in the linker's own words, case included. Measured with `-O2
/// -fno-pic -mcmodel=large -Wl,-z,notext -Wl,--warn-shared-textrel -shared` over the probe
/// on x86_64: GNU ld 2.38 (Ubuntu 22.04), 2.42 (Ubuntu 24.04), 2.45.1 (Alpine) and 2.46.1
/// (Fedora 44) write `warning: creating DT_TEXTREL in a shared object`, and 2.46.1 writes it
/// under `-Wl,--warn-textrel` alone too, linking where it refuses without; gold 1.16
/// (binutils 2.38, 2.42 and 2.46.1) writes `warning: shared library text segment is not
/// shareable`; mold 2.40.4 (Fedora 44), under `-Wl,--warn-textrel` with or without `-z
/// notext`, writes `warning: creating a DT_TEXTREL in an output file`, after a line naming
/// the relocation in a read-only section, which is not read. GNU ld 2.30's (AlmaLinux 8)
/// `warning: creating a DT_TEXTREL in a shared object.` is read from its libbfd's strings,
/// not from a link: the image has no compiler. GNU ld 2.31 to 2.37 are not measured; an
/// unlisted wording is read through the tag. Each needle keeps the `warning: ` the
/// linker writes before it, which a test holds. LLD 22.1.8 refuses
/// `--warn-textrel` as an unknown argument and writes no warning under `-z notext`, so a link
/// under it is read through the object's `DT_TEXTREL`. The probe's source, raw and as a JSON
/// string, holds none of these, which a test holds.
const TEXT_RELOCATION_WARNINGS: [&str; 3] = [
    "warning: creating DT_TEXTREL in ",
    "warning: creating a DT_TEXTREL in ",
    "warning: shared library text segment is not shareable",
];

/// Whether the options the driver passes to the linker include `-z notext` or `-z textoff`.
fn link_line_permits_text_relocations(argv: &[String]) -> bool {
    let mut tokens: Vec<&str> = Vec::new();
    let mut i = 0;
    while let Some(arg) = argv.get(i) {
        let next = argv.get(i.saturating_add(1)).map(String::as_str);
        // Each word as the driver reads it (`--for-l` and `--for-linker` are `-Xlinker`;
        // `toolchain::read`), the pair passed over where another word takes the next
        // (`-o -znotext` names an output file).
        let reading = crate::toolchain::read(arg, next);
        let word = &*reading.word;
        if let Some(list) = arg.strip_prefix("-Wl,") {
            tokens.extend(list.split(','));
        } else if let Some(value) = arg.strip_prefix("--for-linker=") {
            tokens.push(value);
        } else if word == "-Xlinker" {
            tokens.extend(next.filter(|_| reading.span() == 2));
        } else if word == "-z" {
            tokens.push("-z");
            tokens.extend(next);
            i = i.saturating_add(2);
            continue;
        } else if word.starts_with("-z") {
            tokens.push(arg);
        }
        i = i.saturating_add(reading.own_words_span());
    }
    PERMITS_TEXT_RELOCATIONS.iter().any(|keyword| {
        tokens
            .iter()
            .any(|token| token.strip_prefix("-z") == Some(keyword))
            || tokens
                .windows(2)
                .any(|pair| matches!(pair, [z, value] if *z == "-z" && value == keyword))
    })
}

/// The `-z` keywords that permit text relocations: `notext`, and `textoff`, which GNU ld
/// and mold accept as its synonym. Measured 2026-10-02 on Fedora 44
/// x86_64 (gcc 16.2.1, clang 22.1.8): `-O2 -fno-pic -mcmodel=large -Wl,-z,textoff` links
/// under GNU ld 2.46.1 and mold and reads `probe-invalid`, the regime arm linking too, and
/// GNU ld 2.38 (Ubuntu 22.04) and 2.45.1 (Alpine) link it as well. lld 22.1.8 warns
/// `unknown -z value: textoff`, ignores it and refuses the link, a true `off`.
const PERMITS_TEXT_RELOCATIONS: [&str; 2] = ["notext", "textoff"];

/// Marker the diagnostic-channel canary raises when warnings are being reported.
pub(crate) const DIAG_CANARY: &str = "chard_canary_unused";

/// The severity the compiler gave *this* diagnostic, read from the line carrying it: the
/// shared reader for the compiler-diagnostic channel.
pub(crate) fn diag_severity_of(build: &BuildRecord, needles: &[&str]) -> Option<Seen> {
    // The stream is asked about before any line is: in a structured document no line is a
    // diagnostic, so neither the needle nor the severity word on it means anything.
    if structured_stream(&build.stderr) {
        return Some(Seen::Unreadable(Unreadable::StructuredStream));
    }
    let (_, line) = needle_line(&build.stderr, needles)?;
    if line.contains("error:") {
        return Some(Seen::Error);
    }
    if line.contains("warning:") {
        return Some(Seen::Warning);
    }
    // Diagnosed, but with no severity word recognised: a needle on a line that is not a
    // diagnostic (a path header, a quoted source line) is no level, so it is withheld rather
    // than read `on` at warning strength.
    Some(Seen::Unreadable(Unreadable::NoSeverityWord))
}

/// What [`diag_severity_of`] read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seen {
    Error,
    Warning,
    /// The needle was found, or the stream is not text, and the level cannot be read from it.
    Unreadable(Unreadable),
}

/// Why a level could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreadable {
    /// The build's stderr is a structured diagnostics document: the rule
    /// [`STRUCTURED_STREAM_RULE`].
    StructuredStream,
    /// The matched line carries neither `error:` nor `warning:`.
    NoSeverityWord,
}

/// The rule id a detector names when it withholds a build whose stderr is a structured
/// diagnostics document.
pub(crate) const STRUCTURED_STREAM_RULE: &str = "diag-stream-is-text-unless-recognised";

impl Unreadable {
    /// The sentence a detector appends to `observed`.
    fn reason(self) -> String {
        match self {
            Self::StructuredStream => format!(
                "(withheld under {STRUCTURED_STREAM_RULE}: stderr is a structured diagnostics \
                 document, in which a needle on a line and a severity word beside it are not a \
                 diagnostic and its level)"
            ),
            Self::NoSeverityWord => "(withheld: the line carrying the diagnostic names no \
                 severity, so its level cannot be read from it)"
                .to_owned(),
        }
    }
}

impl Seen {
    /// The prose decoder's word for this reading in the structured-diagnostics comparison.
    #[must_use]
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Unreadable(_) => "unreadable",
        }
    }
}

/// The needles each prose-decoded compiler-diag check matches, by check id.
pub const DIAG_NEEDLES: &[(&str, &[&str])] = &[
    ("hardened-downgrade-warned", HARDENED_DOWNGRADE_NEEDLES),
    (
        "implicit-function-declaration-is-error",
        IMPLICIT_DECLARATION_NEEDLES,
    ),
    ("format-security-is-error", FORMAT_SECURITY_NEEDLES),
    ("warn-all", WARN_ALL_NEEDLES),
    ("warn-extra", WARN_EXTRA_NEEDLES),
    ("format-mismatch-warned", WARN_FORMAT_NEEDLES),
    ("format-nonliteral-warned", FORMAT_NONLITERAL_NEEDLES),
    ("conversion-warns-on-narrowing", CONVERSION_NEEDLES),
    (
        "sign-conversion-warns-on-signedness-change",
        SIGN_CONVERSION_NEEDLES,
    ),
    ("implicit-fallthrough-warned", FALLTHROUGH_NEEDLES),
    ("trampolines-warned", TRAMPOLINE_NEEDLES),
    ("bidi-chars-any", BIDI_NEEDLES),
    ("implicit-int-is-error", IMPLICIT_INT_NEEDLES),
    (
        "incompatible-pointer-types-is-error",
        INCOMPATIBLE_POINTER_NEEDLES,
    ),
    ("int-conversion-is-error", INT_CONVERSION_NEEDLES),
];

/// Compiler-diag checks the structured decoder does not read, and why.
pub const DIAG_NEEDLES_EXEMPT: &[(&str, &str)] = &[
    (
        "no-copy-dt-needed",
        "the observable is the linker refusing to resolve a symbol",
    ),
    (
        "pic-shared-link",
        "the observable is the linker refusing a relocation in a shared object",
    ),
];

/// The needles a compiler-diag check matches, when it has a list.
#[must_use]
pub fn diag_needles(check: &str) -> Option<&'static [&'static str]> {
    DIAG_NEEDLES
        .iter()
        .find(|(id, _)| *id == check)
        .map(|(_, needles)| *needles)
}

/// The downgrade the positive arm makes, in both of gcc's closing quotes; see
/// [`detect_hardened_warning`].
const HARDENED_DOWNGRADE_NEEDLES: &[&str] = &[
    "-fstack-protector-strong' is not enabled by",
    "-fstack-protector-strong\u{2019} is not enabled by",
];
const WARN_ALL_NEEDLES: &[&str] = &["chard_wall_dead_label"];
const WARN_EXTRA_NEEDLES: &[&str] = &["different sign"];
const WARN_FORMAT_NEEDLES: &[&str] = &["expects argument of type", "format specifies type"];
const FORMAT_NONLITERAL_NEEDLES: &[&str] = &["not a string literal"];
const FORMAT_SECURITY_NEEDLES: &[&str] = &["not a string literal"];
const CONVERSION_NEEDLES: &[&str] = &["may change value", "loses integer precision"];
const SIGN_CONVERSION_NEEDLES: &[&str] = &["change the sign", "changes signedness"];
const FALLTHROUGH_NEEDLES: &[&str] = &["may fall through", "fall-through between switch labels"];
const TRAMPOLINE_NEEDLES: &[&str] = &["trampoline generated for nested function"];
const BIDI_NEEDLES: &[&str] = &["problematic unicode character", "u+202e"];
const IMPLICIT_INT_NEEDLES: &[&str] = &["type defaults to", "type specifier missing"];
const INCOMPATIBLE_POINTER_NEEDLES: &[&str] = &[
    "incompatible pointer type",
    "from incompatible pointer type",
];
const INT_CONVERSION_NEEDLES: &[&str] = &[
    "makes pointer from integer without a cast",
    "integer to pointer conversion",
];

/// What was seen, in the one spelling every compiler-diag detector reports it in, so the
/// budget a reader compares across cells is one number.
fn build_observed(ev: &Evidence<'_>, build: &BuildRecord, needles: &[&str]) -> String {
    format!(
        "exit={} stderr={:?}",
        build.exit_status,
        excerpt_around(ev, &build.stderr, needles, DIAG_EXCERPT)
    )
}

/// [`build_observed`] around line `hit` of the build's stderr, for a detector whose deciding
/// line is found by a rule of its own ([`pic_refusal_line`]) rather than by one needle.
fn build_observed_at(
    ev: &Evidence<'_>,
    build: &BuildRecord,
    hit: Option<usize>,
    needles: &[&str],
) -> String {
    format!(
        "exit={} stderr={:?}",
        build.exit_status,
        excerpt_at(ev, &build.stderr, hit, needles, DIAG_EXCERPT)
    )
}

/// How much of a compiler's stderr a compiler-diag `observed` string quotes. See
/// [`build_observed`] for the measurement it is sized from.
const DIAG_EXCERPT: usize = 640;

/// How a probe's canary comes to fire: from its own source, or from the build's flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Canary {
    /// The probe's source pins the canary's warning; silence means it was taken away.
    Pinned,
    /// The canary fires only where the build's flags enable `-Wunused-variable`.
    AskedByFlags,
}

/// The options that turn `-Wunused-variable` on, in gcc's and clang's spellings, each also
/// read in its `-Werror=` form, which enables the warning as well as escalating it.
const CANARY_WARNING_ENABLERS: &[&str] =
    &["all", "unused", "unused-variable", "most", "everything"];

/// Whether `argv` shows that the canary's warning was never asked for: no word in it may
/// enable `-Wunused-variable`, may take diagnostics away, or may carry flags the record does
/// not show. Read as a set of words, not in order, so any doubt keeps the other sentence.
fn canary_never_asked(argv: &[String]) -> bool {
    fn name(word: &str) -> Option<&str> {
        let rest = word
            .strip_prefix("-Werror=")
            .or_else(|| word.strip_prefix("--warn-"))
            .or_else(|| word.strip_prefix("-W"))?;
        Some(rest.split_once('=').map_or(rest, |(n, _)| n))
    }
    fn enabler(name: Option<&str>) -> bool {
        name.is_some_and(|n| CANARY_WARNING_ENABLERS.contains(&n))
    }
    let words = argv.iter().flat_map(|arg| {
        let arg = arg.strip_prefix("-Xclang=").unwrap_or(arg);
        match arg.strip_prefix("-Wp,") {
            Some(list) => list.split(',').collect::<Vec<_>>(),
            None => vec![arg],
        }
    });
    !words.into_iter().any(|word| {
        let taken_back = word
            .strip_prefix("-Wno-")
            .or_else(|| word.strip_prefix("--warn-no-"));
        word == "--all-warnings"
            || enabler(name(word))
            || matches!(word, "-w" | "--no-warnings")
            || enabler(taken_back)
            || [
                "-fdiagnostics-format=",
                "-fdiagnostics-add-output=",
                "-fdiagnostics-set-output=",
            ]
            .iter()
            .any(|p| word.starts_with(p))
            || word.starts_with('@')
            || ["-specs", "--specs", "--config"]
                .iter()
                .any(|p| word.starts_with(p))
    })
}

/// The rule a silent build whose flags never asked for the canary names
/// ([`gating_rule::CANARY_NOT_ASKED_FOR`]).
const CANARY_NOT_ASKED_FOR: DetectorRule = DetectorRule::of(gating_rule::CANARY_NOT_ASKED_FOR);

/// What silence means, once the needles have not matched.
fn diag_silence(build: &BuildRecord, observed: String, what: &str, canary: Canary) -> Detection {
    if !build.succeeded() {
        return Detection::indeterminate(format!(
            "{observed} (the build failed without the {what}, so the failure is not \
             attributable to this flag)"
        ));
    }
    if !build.diagnostics_contain(DIAG_CANARY) {
        if canary == Canary::AskedByFlags && canary_never_asked(&build.argv) {
            return Detection::withheld(
                CANARY_NOT_ASKED_FOR,
                format!(
                    "{observed} (neither the {what} nor the canary warning was emitted, and no \
                     recorded flag of the build asked for the canary warning, as -Wall or \
                     -Wunused-variable would, so silence cannot be read as absence)"
                ),
            );
        }
        return Detection::indeterminate(format!(
            "{observed} (neither the {what} nor the canary warning was emitted: the build's \
             diagnostics are suppressed or redirected, so silence cannot be read as absence)"
        ));
    }
    Detection::absent(observed)
}

/// Read a Table 1 warning as presence: did the diagnostic appear at all? Silence is read by
/// [`diag_silence`].
fn diag_presence(ev: &Evidence<'_>, needles: &[&str]) -> Detection {
    diag_presence_with(ev, needles, Canary::Pinned)
}

/// [`diag_presence`] for a probe whose canary comes to fire as `canary` says.
fn diag_presence_with(ev: &Evidence<'_>, needles: &[&str], canary: Canary) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, needles);

    // Presence is what this channel reports, but the published level is read from *this*
    // diagnostic's own line: from stderr as a whole, a bogus `-l`'s linker error would make
    // a construct only warned about read `error`.
    match diag_severity_of(build, needles) {
        Some(Seen::Error) => return Detection::present(Some("error"), observed),
        Some(Seen::Warning) => return Detection::present(Some("warning"), observed),
        Some(Seen::Unreadable(why)) => {
            return Detection::indeterminate(format!("{observed} {}", why.reason()));
        }
        None => {}
    }

    diag_silence(build, observed, "diagnostic", canary)
}

/// Read a Table 1 construct as severity: the same sentence appears either way, and
/// only whether it stops the build differs.
fn diag_severity(ev: &Evidence<'_>, needles: &[&str]) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, needles);

    // Severity is read from the diagnostic's own line, never from stderr as a whole:
    // an unrelated failure elsewhere in the build must not promote a warning to an
    // error.
    match diag_severity_of(build, needles) {
        Some(Seen::Error) => return Detection::present(Some("error"), observed),
        Some(Seen::Warning) => {
            return Detection::absent(format!("{observed} (diagnosed as a warning only)"));
        }
        Some(Seen::Unreadable(why)) => {
            return Detection::indeterminate(format!("{observed} {}", why.reason()));
        }
        None => {}
    }

    diag_silence(build, observed, "diagnostic", Canary::Pinned)
}

/// gcc: "label 'x' defined but not used". clang: "unused label 'x'". Both quote the
/// identifier, which is what makes one needle serve both.
pub(crate) fn detect_warn_all(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, WARN_ALL_NEEDLES)
}

pub(crate) fn detect_warn_extra(ev: &Evidence<'_>) -> Detection {
    // gcc "of different signedness", clang "of different signs".
    diag_presence(ev, WARN_EXTRA_NEEDLES)
}

pub(crate) fn detect_warn_format(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, WARN_FORMAT_NEEDLES)
}

pub(crate) fn detect_warn_format_nonliteral(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, FORMAT_NONLITERAL_NEEDLES)
}

pub(crate) fn detect_warn_conversion(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, CONVERSION_NEEDLES)
}

pub(crate) fn detect_warn_sign_conversion(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, SIGN_CONVERSION_NEEDLES)
}

pub(crate) fn detect_implicit_fallthrough(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, FALLTHROUGH_NEEDLES)
}

pub(crate) fn detect_trampolines(ev: &Evidence<'_>) -> Detection {
    // Not the bare word "trampoline": it appears in the probe's own path, so it
    // matched in every arm including the negative one.
    diag_presence(ev, TRAMPOLINE_NEEDLES)
}

pub(crate) fn detect_bidi_chars(ev: &Evidence<'_>) -> Detection {
    // Not the option name: clang prints "unknown warning option '-Wbidi-chars=any'"
    // while diagnosing nothing.
    diag_presence(ev, BIDI_NEEDLES)
}

pub(crate) fn detect_implicit_int(ev: &Evidence<'_>) -> Detection {
    diag_severity(ev, IMPLICIT_INT_NEEDLES)
}

pub(crate) fn detect_incompatible_pointer_types(ev: &Evidence<'_>) -> Detection {
    diag_severity(ev, INCOMPATIBLE_POINTER_NEEDLES)
}

pub(crate) fn detect_int_conversion(ev: &Evidence<'_>) -> Detection {
    // Never the bare word "incompatible": clang's -Wint-conversion wording is
    // "incompatible integer to pointer conversion", which would collide with the
    // sibling incompatible-pointer-types check.
    diag_severity(ev, INT_CONVERSION_NEEDLES)
}

pub(crate) fn detect_format_security(ev: &Evidence<'_>) -> Detection {
    const NEEDLES: &[&str] = FORMAT_SECURITY_NEEDLES;
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, NEEDLES);

    // Severity decides, since both arms print the same sentence (gcc's "format not a string
    // literal and no format arguments", clang's "format string is not a string literal",
    // which share the needle), and it is read from the diagnostic's own line.
    match diag_severity_of(build, NEEDLES) {
        Some(Seen::Error) => return Detection::present(Some("error"), observed),
        Some(Seen::Warning) => {
            return Detection::absent(format!("{observed} (diagnosed as a warning only)"));
        }
        Some(Seen::Unreadable(why)) => {
            return Detection::indeterminate(format!("{observed} {}", why.reason()));
        }
        None => {}
    }

    diag_silence(build, observed, "format diagnostic", Canary::Pinned)
}

/// Was calling an undeclared function an error, or only a warning?
pub(crate) fn detect_implicit_function_declaration(ev: &Evidence<'_>) -> Detection {
    diag_severity(ev, IMPLICIT_DECLARATION_NEEDLES)
}

/// gcc: "implicit declaration of function"; clang 16 and later: "call to undeclared
/// function", with the option name as a third spelling for a compiler that prints only
/// the tag. Named so the unit tests quote the detector's own needles.
///
/// The tag needle carries its `-W`, for the reason `detect_trampolines` gives: a needle
/// short enough to appear in a path matches the compiler's own `<path>: In function ...`
/// header line, which carries no severity word, and a real `error:` two lines below it is
/// never reached. Measured on Fedora
/// 44 gcc 16.1.1 with a work directory named for the check: the positive control arm of
/// `implicit-function-declaration-is-error` read `absent` with `error: implicit
/// declaration of function` in its stderr, and the check read `probe-invalid` where it
/// reads `off` from the same toolchain under a work directory named anything else. A
/// measured arm under such a directory would have read `off` with the diagnostic present,
/// which is the verdict this project cannot publish wrongly.
const IMPLICIT_DECLARATION_NEEDLES: &[&str] = &[
    "implicit declaration",
    "-wimplicit-function-declaration",
    "call to undeclared function",
];

#[cfg(test)]
#[path = "diag_tests.rs"]
mod tests;
