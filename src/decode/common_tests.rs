// SPDX-License-Identifier: BSD-3-Clause

//! Unit tests for `decode::common`, kept out of the module so its file holds detector code
//! alone.

use super::*;

/// [`excerpt_around`]'s cut over a stream that needs no rewrite.
fn cut_around(text: &str, needles: &[&str], keep: usize) -> String {
    cut_at(
        text,
        needle_line(text, needles).map(|(index, _)| index),
        needles,
        keep,
    )
}

/// A marker line is never read as a field, whatever it carries.
///
/// The self-report is spliced into `variant.macros` wholesale and verdicts are taken
/// from it, so anything parsed out of it is load-bearing. The markers carry no `=` and
/// would be skipped by the field split alone, but a line spelt like a marker with a value
/// (`CHARD-REPORT-V2=1`) would be parsed as a macro named `CHARD-REPORT-V2` and
/// injected into the map a verdict reads. The guard is what makes the marker namespace
/// reserved rather than accidentally free.
#[test]
fn a_marker_line_is_never_parsed_as_a_macro() {
    let parsed = parse_self_report(
        "CHARD-REPORT-V1\n\
         CHARD-REPORT-V2=1\n\
         \n\
         __SSP_STRONG__=3\n\
         UNDEFINED=?\n\
         CHARD-REPORT-END\n",
    )
    .expect("a V1 report");
    assert_eq!(
        parsed.get("__SSP_STRONG__").map(String::as_str),
        Some("3"),
        "a real field still has to survive the skipping"
    );
    assert!(
        !parsed.keys().any(|k| k.starts_with("CHARD-REPORT")),
        "a marker reached the macro map: {parsed:?}"
    );
    assert!(
        !parsed.contains_key("UNDEFINED"),
        "`?` was the header's spelling for a macro it did not find until CHARD-REPORT-V2"
    );
}

/// A `CHARD-REPORT-V2` report spells an undefined macro `name undefined`, so its `name=?`
/// is a macro defined as `?`, and a `CHARD-REPORT-V1` report keeps the reading it was
/// written for, `name=?` undefined.
///
/// A V1 report writes `name=?` for both, so under it `-D__EXCEPTIONS=?` reads as undefined
/// and the check `off`. The value of a defined field is read whatever it holds: `?`, an
/// empty replacement list, a value holding `=`, the word `undefined`, and the end marker's
/// own spelling, which does not end the report inside its field.
#[test]
fn the_current_report_tells_a_macro_defined_as_a_question_mark_from_an_undefined_one() {
    let current = "CHARD-REPORT-V2\n\
                   __EXCEPTIONS=?\n\
                   __PIE__ undefined\n\
                   __PIC__=\n\
                   __CET__=a=b\n\
                   __SSP__=undefined\n\
                   __OPTIMIZE__=CHARD-REPORT-END\n\
                   __ARM_FEATURE_GCS_DEFAULT=1\n\
                   CHARD-REPORT-END\n";
    let fields = self_report_fields(current).expect("a report read whole");
    assert_eq!(
        fields,
        [
            ("__EXCEPTIONS", Some("?")),
            ("__PIE__", None),
            ("__PIC__", Some("")),
            ("__CET__", Some("a=b")),
            ("__SSP__", Some("undefined")),
            ("__OPTIMIZE__", Some("CHARD-REPORT-END")),
            ("__ARM_FEATURE_GCS_DEFAULT", Some("1")),
        ]
    );
    let account = self_report_account(current).expect("a report");
    assert_eq!(account.get("__EXCEPTIONS").map(String::as_str), Some("?"));
    assert!(!account.contains_key("__PIE__"), "{account:?}");
    assert_eq!(
        account.get("__ARM_FEATURE_GCS_DEFAULT").map(String::as_str),
        Some("1"),
        "a field after one spelling the end marker is read"
    );

    let legacy = current.replacen("CHARD-REPORT-V2", "CHARD-REPORT-V1", 1);
    let fields = self_report_fields(&legacy).expect("a V1 report");
    assert_eq!(
        fields,
        [
            ("__EXCEPTIONS", None),
            ("__PIC__", Some("")),
            ("__CET__", Some("a=b")),
            ("__SSP__", Some("undefined")),
            ("__OPTIMIZE__", Some("CHARD-REPORT-END")),
            ("__ARM_FEATURE_GCS_DEFAULT", Some("1")),
        ],
        "a V1 report reads `?` as undefined and skips a line without `=`"
    );
    // On a stream the region starts at the first whole marker line.
    let stream = format!("noise=1 CHARD-REPORT-V1\n{current}after=2\n");
    let region = marked_region(&stream).expect("a region");
    assert!(region.starts_with("CHARD-REPORT-V2\n"), "{region}");
    assert!(region.ends_with("\nCHARD-REPORT-END"), "{region}");
}

/// A text this reader cannot read whole is no report, never a report missing a field: a
/// field dropped would read as a macro undefined, the `off` the V2 spelling exists to stop.
/// Under V2 that is any line that is neither `name=value` nor `name undefined`, a name
/// holding whitespace or none, a name given twice, and a second marker; under V1 a second
/// marker. A marker of a version this reader has no dialect for starts no report.
#[test]
fn a_report_the_reader_cannot_read_whole_is_no_report() {
    let v2 = |body: &str| format!("CHARD-REPORT-V2\n__SSP__=1\n{body}\nCHARD-REPORT-END\n");
    for body in [
        "__EXCEPTIONS undefind",
        "__EXCEPTIONS  undefined trailing",
        "A B undefined",
        "A B=1",
        "=1",
        " undefined\n__X undefined",
        "__SSP__ undefined",
        "__SSP__=2",
        "CHARD-REPORT-V1",
        "CHARD-REPORT-V2",
        "CHARD-REPORT-V2=1",
        "CHARD-REPORT-ENDX\n__PIE__=2",
    ] {
        let text = v2(body);
        assert_eq!(self_report_fields(&text), None, "{body:?}");
        assert_eq!(self_report_account(&text), None, "{body:?}");
        assert_eq!(parse_self_report(&text), None, "{body:?}");
    }
    // A stray V1 marker ahead of a V2 report opens a V1 region holding the V2 marker: no
    // report, rather than the V2 `?` read under V1's rule.
    let stray = "CHARD-REPORT-V1\nCHARD-REPORT-V2\n__EXCEPTIONS=?\nCHARD-REPORT-END\n";
    assert_eq!(self_report_account(stray), None);
    assert!(
        self_report_malformed(stray),
        "a closed report with a second marker"
    );
    // A V2 report is read only closed and without a blank line; a V1 one as it was.
    let open = "CHARD-REPORT-V2\n__SSP__=1\n__PIE__ undefined\n";
    assert_eq!(self_report_fields(open), None, "no end line");
    assert!(
        !self_report_malformed(open),
        "no end line is no report, not a malformed one"
    );
    let blank = "CHARD-REPORT-V2\n__SSP__=1\n\n__PIE__ undefined\nCHARD-REPORT-END\n";
    assert_eq!(self_report_fields(blank), None, "a blank line");
    assert!(self_report_malformed(blank));
    let v1_open = "CHARD-REPORT-V1\n__SSP__=1\n\n__PIE__=?\n";
    assert_eq!(
        self_report_fields(v1_open),
        Some(vec![("__SSP__", Some("1")), ("__PIE__", None)]),
        "V1 keeps its reading"
    );
    for marker in [
        "CHARD-REPORT-V3",
        "CHARD-REPORT-V10",
        "CHARD-REPORT-V2x",
        "CHARD-REPORT-V20",
        "x CHARD-REPORT-V2",
    ] {
        let text = format!("{marker}\n__EXCEPTIONS=?\nCHARD-REPORT-END\n");
        assert_eq!(self_report_fields(&text), None, "{marker}");
        assert_eq!(parse_self_report(&text), None, "{marker}");
    }
    assert_eq!(
        parse_self_report("__EXCEPTIONS=1\n"),
        None,
        "no marker, no report"
    );
    // A line ending in CRLF, or a marker padded with spaces, is the same whole line.
    let crlf = "CHARD-REPORT-V2\r\n__SSP__=1\r\n__PIE__ undefined\r\n CHARD-REPORT-END \r\n";
    assert_eq!(
        self_report_fields(crlf),
        Some(vec![("__SSP__", Some("1")), ("__PIE__", None)])
    );
    assert!(self_report_account(crlf).is_some());
    // Only the exact end line closes a report: under V1, which skips a line spelt like a
    // marker, a line starting with the end marker's spelling does not cut the fields after it.
    let endx = "CHARD-REPORT-V1\n__SSP__=1\nCHARD-REPORT-ENDX\n__PIE__=2\nCHARD-REPORT-END\n";
    assert_eq!(
        self_report_account(endx).and_then(|m| m.get("__PIE__").cloned()),
        Some("2".to_owned())
    );
    // The V1 reading of a line that is not a field stays what it was.
    let v1 = "CHARD-REPORT-V1\nnoise\nCHARD-REPORT-V2=1\n__SSP__=1\nCHARD-REPORT-END\n";
    assert_eq!(
        self_report_account(v1).map(|m| m.len()),
        Some(1),
        "V1 skips a line that is not a field"
    );
}

/// A quoted stream keeps its end, and says how much of its start is gone.
///
/// The head-cut this replaced kept the path and lost the diagnostic, silently: with a
/// long work directory the `observed` for `implicit-function-declaration-is-error`
/// ended inside the second path and the words `error: implicit declaration` never
/// appeared, in a control arm whose detail was the only evidence for it. Each property
/// is pinned separately, because a helper that kept the tail without the marker would
/// still read as the whole stream, and one that marked without counting in characters
/// would split gcc's U+2018 quote.
#[test]
fn a_cut_stream_keeps_its_informative_end_and_says_how_much_is_gone() {
    // Under the budget: verbatim, no marker.
    assert_eq!(cut_tail("short", 160), "short");
    assert_eq!(cut_tail("", 80), "");
    let exact: String = "x".repeat(80);
    assert_eq!(cut_tail(&exact, 80), exact, "at the budget nothing is cut");

    // Over it: the tail survives, the head is replaced by a count.
    let prefix = "/a/very/long/work/directory/that/eats/the/budget/probe.c:5:5: ";
    let message = "error: implicit declaration of function foo";
    let stderr = format!("{prefix}{message}");
    let cut = cut_tail(&stderr, message.len());
    assert_eq!(
        cut,
        format!("[{} chars omitted]{message}", prefix.chars().count()),
        "the diagnostic is what a reader needs and the path is what was cut"
    );
    assert!(
        !cut.contains("/a/very/long"),
        "the path prefix is the part the cut removed"
    );

    // The count is in characters and so is the cut: a multi-byte quote is kept
    // whole rather than split into an invalid boundary.
    let quoted = "0123456789\u{2018}main\u{2019}";
    let cut = cut_tail(quoted, 6);
    assert_eq!(cut, "[10 chars omitted]\u{2018}main\u{2019}");
    assert_eq!(
        cut.chars().count(),
        "[10 chars omitted]".chars().count() + 6
    );
}

/// The cut around a matched line marks each side it removed, and a stream with no
/// match keeps its end.
///
/// Each shape the cut can take is pinned on its own: an under-budget stream is
/// verbatim; a match with lines removed on both sides carries two counts that add up
/// to what is gone; a matched line longer than the whole budget is cut inside itself
/// around the needle rather than dropped; and a stream carrying no needle, the shape
/// of `absent`, is the tail cut with its single leading count.
#[test]
fn a_cut_around_a_matched_line_marks_each_side_and_a_stream_with_no_match_keeps_its_end() {
    let needles = &["the observable"];

    assert_eq!(cut_around("short", needles, 40), "short");

    let (first, matched, last) = (
        "first line of context\n",
        "here is the observable\n",
        "last line of context\n",
    );
    let stream = format!("{first}{matched}{last}");
    let cut = cut_around(&stream, needles, matched.chars().count());
    assert_eq!(
        cut,
        format!(
            "[{} chars omitted]{matched}[{} chars omitted]",
            first.chars().count(),
            last.chars().count()
        ),
        "the matched line alone fits the budget, and each side says what it lost"
    );

    let prefix = "/p".repeat(200);
    let long_line = format!("{prefix}: warning: the observable [-Wsomething]\n");
    let cut = cut_around(&format!("before\n{long_line}after\n"), needles, 60);
    assert!(
        cut.contains("the observable"),
        "a matched line over the whole budget is cut around the needle: {cut}"
    );
    assert!(
        cut.starts_with('[') && cut.ends_with("chars omitted]"),
        "both sides of the window are marked: {cut}"
    );

    let unmatched = format!("{}\nwarning: something else entirely\n", "x".repeat(100));
    assert_eq!(
        cut_around(&unmatched, needles, 40),
        cut_tail(&unmatched, 40),
        "with no matched line the informative part is the end"
    );
}

/// What `self_report_account` takes as a report, over every sequence of up to four lines
/// drawn from the two markers, the end marker, a defined field, a `?` field, an undefined
/// field in V2's spelling, junk and an empty line, against an oracle written apart from it:
/// the first marker line of either version, an end marker line after it, and a field
/// strictly between them. Under V1 a field is a line holding `=`, the rest skipped; under
/// V2 every line between them is `a=1`, `b=?` or `c undefined`, each name once, with no
/// blank line, or there is no report. Under either, a second marker between them is no
/// report. The map is the defined names between them: `a`, and `b` under V2 only, where `?`
/// is a value. So a report whose fields all read undefined is an empty account.
#[test]
fn a_report_is_the_markers_with_a_field_between_them() {
    const TOKENS: [&str; 8] = [
        "CHARD-REPORT-V1",
        "CHARD-REPORT-V2",
        "CHARD-REPORT-END",
        "a=1",
        "b=?",
        "c undefined",
        "junk",
        "",
    ];
    let oracle = |lines: &[&str]| -> Option<usize> {
        let start = lines
            .iter()
            .position(|l| *l == "CHARD-REPORT-V1" || *l == "CHARD-REPORT-V2")?;
        let end = start
            + 1
            + lines[start + 1..]
                .iter()
                .position(|l| *l == "CHARD-REPORT-END")?;
        let v2 = lines[start] == "CHARD-REPORT-V2";
        let body = &lines[start + 1..end];
        if body
            .iter()
            .any(|l| *l == "CHARD-REPORT-V1" || *l == "CHARD-REPORT-V2")
        {
            return None;
        }
        if v2 {
            let readable = |l: &&str| ["a=1", "b=?", "c undefined"].contains(l);
            if !body.iter().all(readable) {
                return None;
            }
            let mut names: Vec<&str> = body.to_vec();
            let fields = names.len();
            names.sort_unstable();
            names.dedup();
            if names.len() != fields {
                return None;
            }
            return (fields > 0).then(|| names.iter().filter(|l| **l != "c undefined").count());
        }
        let fields = body.iter().filter(|l| l.contains('=')).count();
        (fields > 0).then(|| usize::from(body.contains(&"a=1")))
    };
    let mut fed = 0usize;
    let mut reports = 0usize;
    for len in 1..=4 {
        let mut index = vec![0usize; len];
        loop {
            let lines: Vec<&str> = index.iter().map(|i| TOKENS[*i]).collect();
            let text = lines.join("\n");
            fed += 1;
            let expected = oracle(&lines);
            let got = self_report_account(&text).map(|m| m.len());
            assert_eq!(got, expected, "{lines:?}");
            reports += usize::from(expected.is_some());
            let mut k = 0;
            loop {
                if k == len {
                    break;
                }
                index[k] += 1;
                if index[k] < TOKENS.len() {
                    break;
                }
                index[k] = 0;
                k += 1;
            }
            if k == len {
                break;
            }
        }
    }
    assert_eq!(
        fed,
        8 + 64 + 512 + 4096,
        "every sequence up to four lines was fed"
    );
    assert!(
        reports > 0 && reports < fed,
        "{reports} of {fed} read as a report"
    );
}
