// SPDX-License-Identifier: BSD-3-Clause

//! What the runtime and compiler-diag detectors both read: the excerpt helpers every
//! quoted stream passes through, the self-report parser, and the C++ standard library
//! identity.

use std::collections::BTreeMap;

use crate::probe::Evidence;

/// The words a cut marker is spelled with, in the one place that spells them.
///
/// Five call sites built `[N chars omitted]` independently, and `coverage` has to
/// recognise the result to count the observations carrying one. A sixth spelling, or a
/// reworded fifth, would leave the counter reporting zero cuts over a report full of
/// them, which is the shape of clean-looking zero this project refuses.
pub const CUT_MARKER: &str = "chars omitted";

/// Whether a published string carries a cut marker.
///
/// The predicate `coverage` counts with, kept beside the spelling it depends on.
#[must_use]
pub fn carries_a_cut(text: &str) -> bool {
    text.contains(CUT_MARKER)
}

/// Keep the informative end of a captured stream, and say how much was cut.
///
/// Every `observed` string that quotes a runtime stream goes through here, and so does
/// every control arm's `detail` on those channels, since `report::decide` publishes the
/// detector's `observed` as the arm's detail. The compiler-diag channel quotes through
/// [`excerpt_around`] instead, which cuts around the line the detector matched; this
/// function is its fallback for a stream with no match. The two properties a reader
/// depends on:
///
/// - **The tail is kept.** A message follows its prefix: glibc's `__libc_message` names
///   the artifact path ahead of `buffer overflow detected`, and the probes' own stdout
///   puts the self-report first and the reading last. A cut that kept the head spent
///   the whole budget on the path when the work directory was long, and the `observed`
///   for `implicit-function-declaration-is-error` ended mid-path with `error: implicit
///   declaration of function` never appearing, in a report whose control detail was
///   the only evidence for that arm.
/// - **The cut is marked, at the cut.** A silent cut reads as the whole stream, and
///   on the compiler-diag and runtime channels a stream that ends early is a
///   different measurement. The marker states the count in characters, which is
///   also the unit the cut is made in, so a multi-byte quote (gcc's U+2018 under a
///   UTF-8 locale) is never split.
///
/// The text is cut as the report publishes it: [`Evidence::published`] makes the work
/// directory relative and replaces the compilers' temporary names first, so the cut point
/// and the count do not depend on `--workdir`. With the cut first and the rewrite after
/// it, the count would include path characters the published text does not carry;
/// [`Evidence::published`] has the fleet measurement. Taking the evidence
/// rather than a published string is what keeps a call site from cutting first again.
///
/// `keep` is per call site rather than one constant, because the budgets differ by
/// what the string is for: 160 for a stream a reader compares across cells, 80 for a
/// stdout that should have carried a one-line reading and did not.
pub(crate) fn excerpt_tail(ev: &Evidence<'_>, text: &str, keep: usize) -> String {
    cut_tail(&ev.published(text), keep)
}

/// [`excerpt_tail`]'s cut, over text that is already the published copy.
pub(crate) fn cut_tail(text: &str, keep: usize) -> String {
    let total = text.chars().count();
    if total <= keep {
        return text.to_owned();
    }
    let omitted = total.saturating_sub(keep);
    let tail: String = text.chars().skip(omitted).collect();
    format!("[{omitted} {CUT_MARKER}]{tail}")
}

/// Whether `stderr` is, or carries, a structured diagnostics document rather than the
/// compiler's text.
///
/// The compiler-diag detectors read prose: a needle on a line, the severity word on the same
/// line. A SARIF document breaks both halves. gcc 16.1.1 writes the message on a line of its
/// own with the level on another, and embeds the translation unit's source in
/// `artifacts[].contents.text` whenever it reports anything, so a needle the probe's own
/// source or comments contain matches a line that is not a diagnostic (measured 2026-10-09
/// on Fedora 44 x86_64, gcc 16.1.1: `-O2 -fdiagnostics-format=sarif-stderr` read six
/// warning checks `on` that `-O2` read `off`, and four error checks `off` that read `on`).
///
/// The stream is recognised by its own shape and not by the flag list, because the format
/// also arrives by a specs file, a clang configuration file or `-fdiagnostics-set-output`:
///
/// - a SARIF document opens at column 0 with `{` and names `"$schema"` and `sarif` within its
///   first few hundred bytes (gcc 16.1.1 and clang 22.1.8; clang prints a text banner ahead
///   of it and a count after, which is why the opening is looked for on every line);
/// - gcc's `-fdiagnostics-format=json` (gcc 9 to 15; gcc 16 rejects it) is an array of
///   objects opening with `"kind"`, one line (gcc 12.2.0 in a Debian 12 image and gcc 13.3.0
///   in an Ubuntu 24.04 image, 2026-10-09).
///
/// A document cut short by the capture still opens the same way, so the test reads the
/// opening and parses nothing. `-fdiagnostics-add-output=sarif:...` writes to a file and
/// leaves stderr as text, so it is correctly not recognised.
#[must_use]
pub(crate) fn structured_stream(stderr: &str) -> bool {
    /// How far past an opening brace the schema key may sit.
    const OPENING: usize = 400;
    let mut offset = 0;
    for line in stderr.split_inclusive('\n') {
        if line.starts_with('{') {
            let window: String = stderr
                .get(offset..)
                .unwrap_or("")
                .chars()
                .take(OPENING)
                .collect::<String>()
                .to_lowercase();
            if window.contains("\"$schema\"") && window.contains("sarif") {
                return true;
            }
        }
        if line.starts_with("[{") || line.starts_with("[\n") {
            let window: String = stderr
                .get(offset..)
                .unwrap_or("")
                .chars()
                .take(OPENING)
                .collect();
            let opening: String = window.split_whitespace().collect();
            if opening.starts_with("[{\"kind\"") {
                return true;
            }
        }
        offset = offset.saturating_add(line.len());
    }
    false
}

/// The first line of `stderr` carrying one of `needles`, matched the way every
/// compiler-diag detector matches: case-insensitively, on the whole line.
///
/// Returns the line's index and its lowercased text. [`diag_severity_of`] reads the
/// severity from that text and [`excerpt_around`] quotes that index, so the line whose
/// severity decided the verdict and the line the published `detail` is built around are
/// one line by construction rather than two lines that happen to agree.
///
/// [`diag_severity_of`]: super::diag::diag_severity_of
pub(crate) fn needle_line(stderr: &str, needles: &[&str]) -> Option<(usize, String)> {
    let needles: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();
    stderr
        .to_lowercase()
        .lines()
        .enumerate()
        .find(|(_, line)| needles.iter().any(|n| line.contains(n.as_str())))
        .map(|(index, line)| (index, line.to_owned()))
}

/// A quoted compiler stream cut around the line the detector matched, with the count of
/// what was removed on each side.
///
/// [`excerpt_tail`] keeps a stream's end, and a compiler diagnostic has no fixed end.
/// gcc prints the observable and then the canary; clang prints the observable, then its
/// fix-it notes, then the canary. Measured on Apple clang 21 for
/// `implicit-fallthrough-warned` under a 24-character work directory: 741 characters of
/// stderr with `fall-through between switch labels` in the first line, so a
/// 640-character tail quotes three notes and the canary and cuts the diagnostic the
/// verdict rests on. The detector reads the whole stream and the verdict is right, but
/// the `detail` a reader re-derives it from loses the match. That is the failure a tail
/// cut exists to prevent, at the head of the stream instead of its foot.
///
/// So the excerpt is built from the match. The line [`needle_line`] found is kept whole,
/// the lines on either side are added while they fit the budget, nearer lines first,
/// and each side that lost anything says how much: `[N chars omitted]` before the first
/// kept line and after the last. A matched line that alone exceeds the budget is cut
/// inside itself, in a window centred on the needle, so the matched text survives
/// whatever the path prefix ahead of it cost. A stream with no matched line, the shape of
/// a clean build and of a suppressed channel, falls back to [`excerpt_tail`]: there is
/// nothing to centre on, and the end, where both compilers print the canary, is then the
/// informative part.
///
/// The needle's position inside an over-long line is read from the lowercased published
/// line. A case fold that changes a character count would shift the window
/// by that much and the centring absorbs it; no compiler diagnostic has been seen to
/// carry one.
///
/// The line is found in the stream as captured, the stream the detector read, and the
/// cut is made in the published copy ([`Evidence::published`]), which has the same lines
/// because the rewrite touches paths and never a line break. The matched line is
/// therefore the detector's line, whatever a path in an earlier line spelled, and the
/// counts are what the published text lost.
pub(crate) fn excerpt_around(
    ev: &Evidence<'_>,
    text: &str,
    needles: &[&str],
    keep: usize,
) -> String {
    let hit = needle_line(text, needles).map(|(index, _)| index);
    excerpt_at(ev, text, hit, needles, keep)
}

/// [`excerpt_around`]'s cut around line `hit` of `text`, for a detector that finds the
/// deciding line by a rule of its own rather than by [`needle_line`].
///
/// `hit` counts the lines of `text` as captured, as `str::lines` and `needle_line` count
/// them; `needles` only places the window inside a matched line longer than `keep`.
pub(crate) fn excerpt_at(
    ev: &Evidence<'_>,
    text: &str,
    hit: Option<usize>,
    needles: &[&str],
    keep: usize,
) -> String {
    cut_at(&ev.published(text), hit, needles, keep)
}

/// The cut [`excerpt_around`] describes, around line `hit` of `text`.
fn cut_at(text: &str, hit: Option<usize>, needles: &[&str], keep: usize) -> String {
    let total = text.chars().count();
    if total <= keep {
        return text.to_owned();
    }
    let Some(hit) = hit else {
        return cut_tail(text, keep);
    };
    let lines: Vec<(&str, usize)> = text
        .split_inclusive('\n')
        .map(|line| (line, line.chars().count()))
        .collect();
    let Some(&(matched, matched_len)) = lines.get(hit) else {
        // `needle_line` counted the same lines; unreachable, and the fallback is honest.
        return cut_tail(text, keep);
    };
    let lower_line = matched.to_lowercase();
    let chars_in = |range: std::ops::Range<usize>| -> usize {
        lines
            .iter()
            .skip(range.start)
            .take(range.end.saturating_sub(range.start))
            .map(|(_, n)| n)
            .sum()
    };

    if matched_len > keep {
        let (at, len) = needles
            .iter()
            .find_map(|needle| {
                let lowered = needle.to_lowercase();
                lower_line.find(&lowered).map(|byte| {
                    let at = lower_line
                        .get(..byte)
                        .map_or(0, |prefix| prefix.chars().count());
                    (at, lowered.chars().count())
                })
            })
            .unwrap_or((0, 0));
        let start = at
            .saturating_add(len / 2)
            .saturating_sub(keep / 2)
            .min(matched_len.saturating_sub(keep));
        let window: String = matched.chars().skip(start).take(keep).collect();
        let before = chars_in(0..hit).saturating_add(start);
        let after = total.saturating_sub(before).saturating_sub(keep);
        return format!("[{before} {CUT_MARKER}]{window}[{after} {CUT_MARKER}]");
    }

    let (mut lo, mut hi, mut used) = (hit, hit, matched_len);
    loop {
        let mut grew = false;
        if let Some(&(_, next)) = lines.get(hi.saturating_add(1))
            && used.saturating_add(next) <= keep
        {
            hi = hi.saturating_add(1);
            used = used.saturating_add(next);
            grew = true;
        }
        if let Some(previous) = lo.checked_sub(1)
            && let Some(&(_, prev)) = lines.get(previous)
            && used.saturating_add(prev) <= keep
        {
            lo = previous;
            used = used.saturating_add(prev);
            grew = true;
        }
        if !grew {
            break;
        }
    }
    let before = chars_in(0..lo);
    let after = chars_in(hi.saturating_add(1)..lines.len());
    let body: String = lines
        .iter()
        .skip(lo)
        .take(hi.saturating_sub(lo).saturating_add(1))
        .map(|(line, _)| *line)
        .collect();
    let leading = if before > 0 {
        format!("[{before} {CUT_MARKER}]")
    } else {
        String::new()
    };
    let trailing = if after > 0 {
        format!("[{after} {CUT_MARKER}]")
    } else {
        String::new()
    };
    format!("{leading}{body}{trailing}")
}

/// Which C++ standard library the toolchain says it is using, from its own macros.
///
/// `_CXX_STDLIB` is chard's own summary, written into the self-report by the probe
/// header's `#if defined(_LIBCPP_VERSION)` arm, so it is available only where the
/// artifact can be read. `_LIBCPP_VERSION` and `__GLIBCXX__` are the real macros that arm
/// tests, and a preprocessor dump carries them whatever the object format is, which keeps
/// the identity answerable on a platform chard has no reader for.
///
/// One function rather than the three copies of this ladder that preceded it. The copies
/// were identical in effect and differed in wording, which is the arrangement where one
/// of them silently stops matching the others.
#[must_use]
pub fn cxx_stdlib(macros: &BTreeMap<String, String>) -> Option<&str> {
    match macros.get("_CXX_STDLIB").map(String::as_str) {
        Some(named) => Some(named),
        None if macros.contains_key("_LIBCPP_VERSION") => Some("libc++"),
        None if macros.contains_key("__GLIBCXX__") => Some("libstdc++"),
        None => None,
    }
}

/// The self-report between its own markers, when a probe printed one on stdout.
///
/// `None` when the region is absent or unterminated — a probe killed mid-write would leave
/// an opening marker and a truncated body, and half a report read as a whole one is how a
/// missing field becomes a confident undefined. `CHARD_PRINT_REPORT` flushes for this
/// reason; this is the half that does not trust it. The region is [`report_region`]'s.
pub(crate) fn marked_region(stream: &str) -> Option<String> {
    let region = report_region(stream)?;
    region.terminated.then(|| region.text.to_owned())
}

/// The markers `probes/chard_selfreport.h` wraps the report in. Spelled once here so the
/// header and the reader cannot drift; `tests/probe_sources.rs` reads a header build back
/// through them.
const CHARD_REPORT_MARKER: &str = "CHARD-REPORT-V2";
const CHARD_REPORT_END: &str = "CHARD-REPORT-END";

/// The marker of the report format that does not spell an undefined macro apart from a
/// defined one. Such a report writes `name=?` for both, so its `?` fields are read as
/// undefined, the reading that format was written for: the register entry
/// `legacy-self-report-question-mark-reads-undefined` names the macro defined as `?` this
/// cannot see.
const CHARD_REPORT_MARKER_V1: &str = "CHARD-REPORT-V1";

/// How the header spells a macro that was not defined: the name, then this, and no `=`.
/// A defined macro's line is the name, `=` and the value's spelling, and a stringified
/// value holds no newline, so no value can write this line. The predicate language's
/// `observed` spells an undefined macro read with it too (`predicate`, Rendering).
pub(crate) const UNDEFINED_SUFFIX: &str = " undefined";

/// Which header wrote a report, from its marker line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// `CHARD-REPORT-V1`: `name=?` is undefined, and a line that is not a field is skipped.
    V1,
    /// `CHARD-REPORT-V2`: `name=value` or `name undefined`, and nothing else.
    V2,
}

/// A report located in a text: the dialect its marker names, the text from the marker line
/// through the end line, or to the end of the text where no end line follows, and which.
struct Region<'a> {
    dialect: Dialect,
    text: &'a str,
    terminated: bool,
}

/// The first report in `text`. A marker is a whole line, trimmed, that is exactly one of the
/// two markers, and the end is the first whole line after it that is exactly
/// `CHARD-REPORT-END`, so no value's spelling starts or ends a report: a macro defined as
/// `CHARD-REPORT-END` writes `name=CHARD-REPORT-END`, which until V2 cut the report at
/// that field and read every field after it as undefined. A line naming another version
/// (`CHARD-REPORT-V3`) starts nothing, so a report this reader has no dialect for is no
/// report.
fn report_region(text: &str) -> Option<Region<'_>> {
    let mut offset = 0usize;
    let mut opened: Option<(usize, Dialect)> = None;
    for line in text.split_inclusive('\n') {
        let here = offset;
        offset = offset.saturating_add(line.len());
        let trimmed = line.trim();
        match opened {
            None => {
                opened = match trimmed {
                    CHARD_REPORT_MARKER => Some((here, Dialect::V2)),
                    CHARD_REPORT_MARKER_V1 => Some((here, Dialect::V1)),
                    _ => None,
                };
            }
            Some((start, dialect)) if trimmed == CHARD_REPORT_END => {
                let close = here.saturating_add(line.trim_end().len());
                return Some(Region {
                    dialect,
                    text: text.get(start..close)?,
                    terminated: true,
                });
            }
            Some(_) => {}
        }
    }
    let (start, dialect) = opened?;
    Some(Region {
        dialect,
        text: text.get(start..)?,
        terminated: false,
    })
}

/// Every field of the first report in `report` ([`report_region`]), in order, with the
/// value the header wrote for a defined macro and `None` for one it says was not defined
/// when the unit was preprocessed; a report whose fields all read undefined is a report.
/// `None` where the text holds no report or holds one this cannot read whole.
/// [`parse_self_report`] is this with the undefined fields dropped, and
/// `report::self_report_entries` reads this to tell a report of nothing defined from no
/// report.
///
/// A `CHARD-REPORT-V2` report spells undefined `name undefined`, so its `name=?` is a macro
/// defined as `?` and is read as that value. It is read strictly, as the header writes it:
/// closed by its end line, and every line between is `name=value` or `name undefined` with a
/// name holding no whitespace and given once; a blank line, any other line, another marker
/// among them, or no end line makes the text no report, since a line dropped or a tail cut
/// would read as a macro undefined. A `CHARD-REPORT-V1` report is read as its
/// header wrote it: `name=?` is undefined and a line without `=` is skipped, except an
/// exact marker line, which makes the text no report as under V2: two reports in one
/// region would read the second by the first's dialect.
pub fn self_report_fields(report: &str) -> Option<Vec<(&str, Option<&str>)>> {
    let region = report_region(report)?;
    if region.dialect == Dialect::V2 && !region.terminated {
        return None;
    }
    let mut fields: Vec<(&str, Option<&str>)> = Vec::new();
    for line in region.text.lines().skip(1).map(str::trim) {
        if line == CHARD_REPORT_END {
            continue;
        }
        if line.is_empty() {
            if region.dialect == Dialect::V2 {
                return None;
            }
            continue;
        }
        if line == CHARD_REPORT_MARKER || line == CHARD_REPORT_MARKER_V1 {
            return None;
        }
        let field = match (region.dialect, line.split_once('=')) {
            (Dialect::V1, _) if line.starts_with("CHARD-REPORT") => continue,
            (Dialect::V1, Some((name, "?"))) => (name, None),
            (_, Some((name, value))) => (name, Some(value)),
            (Dialect::V1, None) => continue,
            (Dialect::V2, None) => (line.strip_suffix(UNDEFINED_SUFFIX)?, None),
        };
        if region.dialect == Dialect::V2
            && (field.0.is_empty()
                || field.0.contains(char::is_whitespace)
                || field.0.starts_with("CHARD-REPORT")
                || fields.iter().any(|(name, _)| *name == field.0))
        {
            return None;
        }
        fields.push(field);
    }
    Some(fields)
}

/// The account a `.chard.report` section's text gives, or `None` where the text holds no
/// report: a report is what `probes/chard_selfreport.h` writes, the `CHARD-REPORT-V2`
/// marker (or the `CHARD-REPORT-V1` of an older header), `CHARD-REPORT-END` after it, each
/// a whole line ([`report_region`]), and at least one field between them, every line read
/// ([`self_report_fields`]). The map is [`parse_self_report`] over the region, and it is
/// empty where every field reads undefined, the artifact's word that nothing is defined.
/// Every reader that asks "did this artifact give an account" reads this:
/// `report::self_report_entries` for `measure`, `detect` and the per-probe warning,
/// `report::FactStore::macro_view` and the facts-key binder for the replay rules.
pub fn self_report_account(text: &str) -> Option<BTreeMap<String, String>> {
    let region = marked_region(text)?;
    let fields = self_report_fields(&region)?;
    (!fields.is_empty()).then(|| defined(fields))
}

/// Whether `text` holds a report closed by its end line that the reader refuses to read
/// whole ([`self_report_fields`]): a V2 report with a line of neither form, a blank line, a
/// name given twice or a second marker, or a V1 report with a second marker. The reason
/// `report::SelfReportAbsence` gives for such a section names this rather than a missing
/// marker.
pub fn self_report_malformed(text: &str) -> bool {
    report_region(text)
        .is_some_and(|region| region.terminated && self_report_fields(region.text).is_none())
}

/// The macros a report says are defined, by name and value: its fields with the undefined
/// fields left out ([`self_report_fields`]), so a consumer reads presence as definition.
/// `None` where the text holds no report it can read whole, so a caller says what no report
/// means for it.
pub fn parse_self_report(report: &str) -> Option<BTreeMap<String, String>> {
    self_report_fields(report).map(defined)
}

fn defined(fields: Vec<(&str, Option<&str>)>) -> BTreeMap<String, String> {
    fields
        .into_iter()
        .filter_map(|(name, value)| Some((name.to_owned(), value?.to_owned())))
        .collect()
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
