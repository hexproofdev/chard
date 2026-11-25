// SPDX-License-Identifier: BSD-3-Clause

//! What the runtime and compiler-diag detectors both read: the excerpt helpers every
//! quoted stream passes through, the self-report parser, and the C++ standard library
//! identity.

use std::collections::BTreeMap;

use crate::probe::Evidence;

/// The words a cut marker is spelled with, in the one place that spells them.
pub const CUT_MARKER: &str = "chars omitted";

/// Whether a published string carries a cut marker.
#[must_use]
pub fn carries_a_cut(text: &str) -> bool {
    text.contains(CUT_MARKER)
}

/// Keep the informative end of a captured stream, and say how much was cut.
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
pub(crate) fn marked_region(stream: &str) -> Option<String> {
    let region = report_region(stream)?;
    region.terminated.then(|| region.text.to_owned())
}

/// The markers `probes/chard_selfreport.h` wraps the report in; `tests/probe_sources.rs`
/// reads a header build back through them.
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
/// value holds no newline, so no value can write this line.
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
/// `CHARD-REPORT-END` writes `name=CHARD-REPORT-END`, which is no end line. A line naming
/// another version (`CHARD-REPORT-V3`) starts nothing, so a report this reader has no
/// dialect for is no report.
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

/// Every field of the first report in `report` (`report_region`), in order, with the
/// value the header wrote for a defined macro and `None` for one it says was not defined
/// when the unit was preprocessed; a report whose fields all read undefined is a report.
/// `None` where the text holds no report or holds one this cannot read whole.
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
/// a whole line, and at least one field between them, every line read
/// ([`self_report_fields`]). The map is empty where every field reads undefined, the
/// artifact's word that nothing is defined. Every reader that asks whether an artifact gave
/// an account reads this.
pub fn self_report_account(text: &str) -> Option<BTreeMap<String, String>> {
    self_report_listing(text).map(|fields| {
        fields
            .into_iter()
            .filter_map(|(name, value)| Some((name, value?)))
            .collect()
    })
}

/// The account's every field in order, the undefined ones kept as `None`: the fields
/// [`self_report_account`] reads, by the same parse, so the two never differ on whether a
/// section gives an account. An undefined field is the artifact's word about a macro as much
/// as a defined one is.
pub fn self_report_listing(text: &str) -> Option<Vec<(String, Option<String>)>> {
    let region = marked_region(text)?;
    let fields = self_report_fields(&region)?;
    (!fields.is_empty()).then(|| {
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.map(str::to_owned)))
            .collect()
    })
}

/// Whether `text` holds a report closed by its end line that the reader refuses to read
/// whole ([`self_report_fields`]): a V2 report with a line of neither form, a blank line, a
/// name given twice or a second marker, or a V1 report with a second marker. Such a section's
/// absence reason names this rather than a missing marker.
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
