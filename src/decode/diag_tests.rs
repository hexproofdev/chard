// SPDX-License-Identifier: BSD-3-Clause

//! Unit tests for `decode::diag`, kept out of the module so its file holds detector code
//! alone.

use std::collections::BTreeMap;

use super::*;
use crate::elf::ElfFacts;
use crate::probe::Outcome;

/// Build a stderr-only [`BuildRecord`] for the diagnostic-channel detectors.
fn diag_build(exit_status: i32, stderr: &str) -> crate::compile::BuildRecord {
    crate::compile::BuildRecord {
        argv: Vec::new(),
        dropped_flags: Vec::new(),
        exit_status,
        stdout: String::new(),
        stderr: stderr.to_owned(),
        duration_ms: 0,
        artifact_sha256: None,
        stdout_sha256: None,
        stdout_unterminated: false,
    }
}

/// [`build_observed`] over `build` alone, its paths taken as already published.
fn observed_of(build: &crate::compile::BuildRecord, needles: &[&str]) -> String {
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(build),
        run: None,
        workdir: None,
    };
    build_observed(&ev, build, needles)
}

/// A compiler that *rejects* a flag prints the flag's name while saying so, and
/// keying a detector on the option name scores that as the flag being on.
///
/// Measured on clang 22.1.8 with `-Wimplicit-fallthrough=5` — a spelling the
/// Linux kernel and several distributions really pass. clang ignores the option
/// entirely and emits no fall-through diagnostic, yet the string
/// "implicit-fallthrough" appears twice. A detector keyed on the option name reads
/// that as `present`, which is why every Table 1 detector matches the diagnostic's
/// *wording* instead.
#[test]
fn rejected_flag_is_not_read_as_the_flag_being_on() {
    let stderr = "warning: unknown warning option '-Wimplicit-fallthrough=5'; did you \
                  mean '-Wimplicit-fallthrough'? [-Wunknown-warning-option]\n\
                  x.c:71:9: warning: unused variable 'chard_canary_unused' \
                  [-Wunused-variable]\n";
    let build = diag_build(0, stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    assert_eq!(
        detect_implicit_fallthrough(&ev).outcome,
        Outcome::Absent,
        "a flag the compiler rejected must not read as present"
    );
}

/// The probe's own filename can contain the needle. `grep trampoline` matched
/// `probes/trampolines.c` in the diagnostic's file-and-line prefix, so the
/// negative control appeared to carry the observable and the check never
/// discriminated. The needle is the diagnostic sentence for this reason.
#[test]
fn probe_filename_in_the_prefix_is_not_read_as_the_observable() {
    let stderr = "probes/trampolines.c: In function 'main':\n\
                  probes/trampolines.c:53:9: warning: unused variable \
                  'chard_canary_unused' [-Wunused-variable]\n";
    let build = diag_build(0, stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    assert_eq!(detect_trampolines(&ev).outcome, Outcome::Absent);
}

/// clang's `-Wint-conversion` wording contains the word "incompatible", so a
/// detector keyed on that bare word would fire for the sibling
/// incompatible-pointer-types check as well. The two must stay separable.
#[test]
fn int_conversion_and_incompatible_pointer_types_do_not_collide() {
    let stderr = "x.c:57:10: error: incompatible integer to pointer conversion \
                  initializing 'int *' with an expression of type 'int' \
                  [-Wint-conversion]\n";
    let build = diag_build(1, stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    assert_eq!(detect_int_conversion(&ev).outcome, Outcome::Present);
    assert_eq!(
        detect_incompatible_pointer_types(&ev).outcome,
        Outcome::Indeterminate,
        "the int-conversion wording must not be claimed by the pointer-types check"
    );
}

/// An unrelated failure must not promote a warning into a hardening claim.
///
/// A severity check that asked two independent questions (is the needle present, and
/// does stderr contain `error:` anywhere) would let any other error in the
/// same build answer both. Measured on clang 22: a bogus `-l` makes the linker
/// fail while the construct is still only warned about, and such a check would report
/// `-Werror=int-conversion` **on** for a command line that never mentioned it. A
/// profile carrying `-static` fails exactly this way where no static libc exists.
#[test]
fn unrelated_build_failure_does_not_fake_an_error_severity() {
    let stderr = "int_conversion.c:57:10: warning: incompatible integer to pointer \
                  conversion initializing 'int *' with an expression of type 'int' \
                  [-Wint-conversion]\n\
                  clang: error: linker command failed with exit code 1\n";
    let build = diag_build(1, stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    assert_eq!(
        detect_int_conversion(&ev).outcome,
        Outcome::Absent,
        "the construct was diagnosed as a warning; the error belongs to the linker"
    );
}

/// The same guard for `implicit-function-declaration`.
///
/// Verified to discriminate against a body that reads the needle anywhere in stderr and the
/// severity from the build's status: it returns `Present(Some("error"))` for a build whose own
/// captured stderr says `warning:` on the diagnostic's line, and that `build` record ships in
/// the same JSON object as the verdict it contradicts.
#[test]
fn an_unrelated_link_failure_does_not_make_an_implicit_declaration_an_error() {
    let stderr = "impl.c:3:5: warning: implicit declaration of function 'foo' \
                  [-Wimplicit-function-declaration]\n\
                  clang: error: linker command failed with exit code 1\n";
    let build = diag_build(1, stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    assert_eq!(
        detect_implicit_function_declaration(&ev).outcome,
        Outcome::Absent,
        "the call was diagnosed as a warning; the error belongs to the linker"
    );

    // And a genuine escalation still reads as present.
    let build = diag_build(
        1,
        "impl.c:3:5: error: call to undeclared function 'foo' \
         [-Wimplicit-function-declaration]\n",
    );
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    assert_eq!(
        detect_implicit_function_declaration(&ev).outcome,
        Outcome::Present
    );
}

/// The converse: a genuine escalation must still read as present, even though the
/// same build also carries unrelated warnings.
#[test]
fn genuine_error_severity_is_still_present() {
    let stderr = "int_conversion.c:53:9: warning: unused variable \
                  'chard_canary_unused' [-Wunused-variable]\n\
                  int_conversion.c:57:10: error: incompatible integer to pointer \
                  conversion initializing 'int *' with an expression of type 'int' \
                  [-Wint-conversion]\n";
    let build = diag_build(1, stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    let d = detect_int_conversion(&ev);
    assert_eq!(d.outcome, Outcome::Present);
    assert_eq!(d.level.as_deref(), Some("error"));
}

/// Silence is only absence when something was listening. `-w` and
/// `-fdiagnostics-format=sarif-file` empty stderr without countermanding any
/// control flag, so a build carrying neither the observable nor the canary is
/// unreadable rather than off.
#[test]
fn silent_diagnostic_channel_is_indeterminate_not_off() {
    let build = diag_build(0, "");
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    assert_eq!(detect_warn_all(&ev).outcome, Outcome::Indeterminate);
    assert_eq!(detect_int_conversion(&ev).outcome, Outcome::Indeterminate);
}

/// A build that emitted the canary and nothing else diagnosed nothing, and that is an
/// absence rather than a broken channel.
///
/// The canary is how this detector tells "the flag diagnosed nothing" from "this
/// build's diagnostic channel is not reaching chard at all" — silence on both is not
/// readable as absence. Inverting the guard turns every clean build into an
/// indeterminate, which reads as a harness fault on a toolchain that is working.
#[test]
fn a_clean_build_that_emitted_the_canary_diagnosed_nothing() {
    let needles = ["chard_marker_construct"];

    let clean = diag_build(0, &format!("warning: {DIAG_CANARY} is unused"));
    let d = diag_severity(
        &Evidence {
            macros: &BTreeMap::new(),
            elf: None,
            build: Some(&clean),
            run: None,
            workdir: None,
        },
        &needles,
    );
    assert_eq!(
        d.outcome,
        Outcome::Absent,
        "the channel reached chard and carried no diagnostic: {}",
        d.observed
    );

    // Without the canary, silence is unreadable: the channel may be suppressed.
    let silent = diag_build(0, "");
    let unreadable = diag_severity(
        &Evidence {
            macros: &BTreeMap::new(),
            elf: None,
            build: Some(&silent),
            run: None,
            workdir: None,
        },
        &needles,
    );
    assert_eq!(unreadable.outcome, Outcome::Indeterminate);
    assert!(
        unreadable.observed.contains("suppressed or redirected"),
        "{}",
        unreadable.observed
    );
}

/// A build that failed and emitted no canary is read as a failed build, not as a
/// suppressed channel, on all three silence readers; a build that succeeded without the
/// canary is still the suppressed channel; a build that failed with the canary and without
/// the diagnostic is the failed build it was.
///
/// The driver's own refusals that the rejection reader has no phrase for are the shape:
/// clang refusing to open a `--config=` file prints one error line and compiles nothing,
/// and every compiler-diag cell said its channel was suppressed or redirected.
#[test]
fn a_failed_build_without_the_canary_is_read_as_the_failure_not_as_a_suppressed_channel() {
    fn presence(ev: &Evidence<'_>) -> Detection {
        diag_presence(ev, WARN_ALL_NEEDLES)
    }
    fn severity(ev: &Evidence<'_>) -> Detection {
        diag_severity(ev, IMPLICIT_INT_NEEDLES)
    }
    type Reader = fn(&Evidence<'_>) -> Detection;
    let readers: [(&str, Reader); 3] = [
        ("diag_presence", presence),
        ("diag_severity", severity),
        ("detect_format_security", detect_format_security),
    ];
    let macros = BTreeMap::new();
    let refused = diag_build(
        1,
        "clang: error: configuration file '/nonexistent/x.cfg' cannot be opened: No such \
         file or directory",
    );
    let silent_ok = diag_build(0, "");
    let failed_with_canary = diag_build(
        1,
        "probe.c:3:9: warning: unused variable 'chard_canary_unused' [-Wunused-variable]\n\
         probe.c:9:1: error: expected ';'",
    );
    for (name, reader) in readers {
        let read = |build: &crate::compile::BuildRecord| {
            reader(&Evidence {
                macros: &macros,
                elf: None,
                build: Some(build),
                run: None,
                workdir: None,
            })
        };
        let d = read(&refused);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{name}: {}", d.observed);
        assert!(
            d.observed.contains("the build failed without the")
                && !d.observed.contains("suppressed or redirected"),
            "{name}: a failed build is the failure, not a suppressed channel: {}",
            d.observed
        );
        let d = read(&silent_ok);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{name}: {}", d.observed);
        assert!(
            d.observed.contains("suppressed or redirected"),
            "{name}: a build that ran and emitted nothing is the suppressed channel: {}",
            d.observed
        );
        let d = read(&failed_with_canary);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{name}: {}", d.observed);
        assert!(
            d.observed.contains("the build failed without the"),
            "{name}: {}",
            d.observed
        );
    }
}

/// A compiler-diag `observed` string holds the diagnostic and the canary beside it.
///
/// Both are always present on this channel: the probe's construct draws the diagnostic
/// under test and the deliberately unused local draws the canary warning, each with a
/// source line and a caret line. The stderr here is Apple clang 21's, verbatim but for
/// the path, for `implicit-function-declaration-is-error` under its positive control;
/// at the runtime strings' budget of 160 the error block was the part cut.
#[test]
fn a_compiler_diag_observed_string_holds_both_diagnostics_the_probe_draws() {
    let stderr = "<workdir>/implicit_function_declaration.c:48:5: error: call to \
                  undeclared function 'chard_no_such_function_exists'; ISO C99 and later \
                  do not support implicit function declarations \
                  [-Wimplicit-function-declaration]\n\
                  \x20  48 |     chard_no_such_function_exists();\n\
                  \x20     |     ^\n\
                  <workdir>/implicit_function_declaration.c:43:9: warning: unused \
                  variable 'chard_canary_unused' [-Wunused-variable]\n\
                  \x20  43 |     int chard_canary_unused = 0;\n\
                  \x20     |         ^~~~~~~~~~~~~~~~~~~\n\
                  1 warning and 1 error generated.\n";
    let observed = observed_of(&diag_build(1, stderr), IMPLICIT_DECLARATION_NEEDLES);
    assert!(
        observed.contains("error: call to undeclared function"),
        "the diagnostic the check is about must be quoted: {observed}"
    );
    assert!(
        observed.contains("warning: unused variable 'chard_canary_unused'"),
        "the canary that proves the channel was listening must be quoted: {observed}"
    );
    assert!(
        !observed.contains("chars omitted"),
        "two diagnostics with carets and short prefixes fit the budget whole: {observed}"
    );

    // A long path that is not the work directory costs the lines farthest from the
    // matched diagnostic.
    let long_path = stderr.replace("<workdir>", &"/w".repeat(80));
    let observed = observed_of(&diag_build(1, &long_path), IMPLICIT_DECLARATION_NEEDLES);
    assert!(
        observed.contains("chars omitted]") && observed.contains("error: call to undeclared"),
        "the cut is marked and the diagnostic survives it: {observed}"
    );
}

/// A work directory named for the check must not decide the check's verdict.
///
/// gcc opens a diagnostic with `<path>: In function 'main':`, a line carrying no
/// severity word. When a needle is short enough to appear in a path, that header line
/// is the first line `needle_line` matches, `diag_severity_of` reads it at warning
/// strength, and the `error:` below it is never reached: the positive control read
/// `absent` and the check read `probe-invalid`. Under a measured arm the same reading
/// is `off` with the diagnostic present. Reproduced on Fedora 44 gcc 16.1.1 with
/// `--workdir /tmp/chard-inert-9-implicit-function-declaration-is-error-12345/work`,
/// which `tests/inert_flags.rs` constructs from the check's own id.
#[test]
fn a_work_directory_named_for_the_option_does_not_lower_an_error_to_a_warning() {
    let dir = "/tmp/chard-inert-9-implicit-function-declaration-is-error-12345/work";
    let stderr = format!(
        "{dir}/implicit_function_declaration.c: In function 'main':\n\
         {dir}/implicit_function_declaration.c:45:12: error: implicit declaration of \
         function 'chard_probe_target' [-Wimplicit-function-declaration]\n\
         \x20  45 |     return chard_probe_target();\n\
         \x20     |            ^~~~~~~~~~~~~~~~~\n"
    );
    let (_, line) = needle_line(&stderr, IMPLICIT_DECLARATION_NEEDLES)
        .expect("the diagnostic carries the option tag");
    assert!(
        line.contains("error:"),
        "the matched line must be the diagnostic, not the path-bearing header: {line}"
    );
    assert_eq!(
        diag_severity_of(&diag_build(1, &stderr), IMPLICIT_DECLARATION_NEEDLES),
        Some(Seen::Error),
        "an error under a work directory named for the option is still an error"
    );
}

/// clang's `-Wimplicit-fallthrough` stderr, as Apple clang 21 printed it for the
/// probe under a work directory of `dir`: the observable first, three fix-it notes,
/// then the canary. 741 characters at 24, over the 640 budget by the first line.
fn clang_fallthrough_stderr(dir: &str) -> String {
    let source = format!("{dir}/implicit_fallthrough.c");
    [
        format!(
            "{source}:54:5: warning: unannotated fall-through between switch labels \
             [-Wimplicit-fallthrough]"
        ),
        "   54 |     case 1:".to_owned(),
        "      |     ^".to_owned(),
        format!(
            "{source}:54:5: note: insert '__attribute__((fallthrough));' to silence this \
             warning"
        ),
        "   54 |     case 1:".to_owned(),
        "      |     ^".to_owned(),
        "      |     __attribute__((fallthrough)); ".to_owned(),
        format!("{source}:54:5: note: insert 'break;' to avoid fall-through"),
        "   54 |     case 1:".to_owned(),
        "      |     ^".to_owned(),
        "      |     break; ".to_owned(),
        format!(
            "{source}:67:9: warning: unused variable 'chard_canary_unused' \
             [-Wunused-variable]"
        ),
        "   67 |     int chard_canary_unused = 0;".to_owned(),
        "      |         ^~~~~~~~~~~~~~~~~~~".to_owned(),
        "2 warnings generated.".to_owned(),
    ]
    .join("\n")
        + "\n"
}

/// gcc's `-Werror=format-security` stderr, as Homebrew gcc 16.2.0 printed it for the
/// probe: a function banner, the error, the canary, the cc1 summary. 508 characters
/// under a 29-character directory; the path appears three times, so a long directory
/// moves the error line past any tail budget.
fn gcc_format_security_stderr(dir: &str) -> String {
    let source = format!("{dir}/format_security.c");
    [
        format!("{source}: In function 'main':"),
        format!(
            "{source}:61:5: error: format not a string literal and no format arguments \
             [-Werror=format-security]"
        ),
        "   61 |     chard_fmt(chard_pick());".to_owned(),
        "      |     ^~~~~~~~~".to_owned(),
        format!(
            "{source}:58:9: warning: unused variable 'chard_canary_unused' \
             [-Wunused-variable]"
        ),
        "   58 |     int chard_canary_unused = 0;".to_owned(),
        "      |         ^~~~~~~~~~~~~~~~~~~".to_owned(),
        "cc1: some warnings being treated as errors".to_owned(),
    ]
    .join("\n")
        + "\n"
}

/// The published detail of a compiler-diag arm quotes the line the detector matched.
///
/// A tail cut kept whatever the compiler printed last. gcc prints the observable and
/// then the canary, so the tail held both; clang prints the observable first and its
/// fix-it notes after, so under a 24-character work directory the 640-character tail
/// of `implicit-fallthrough-warned`'s positive arm quoted three notes and the canary
/// and cut `fall-through between switch labels`, the text the arm's `present` rests
/// on, out of the only evidence published for the arm. The verdict was right, since
/// the detector reads the whole stream; the detail a reader re-derives it from was
/// wrong. Both compilers are pinned, each through its real detector and then through
/// `report::decide`, which is where `observed` becomes an arm's `detail`.
#[test]
fn a_compiler_diag_detail_quotes_the_line_the_detector_matched() {
    use crate::report::{ArmInput, Verdict, decide};
    /// An evaluated arm with no flags: what is under test here is the detector.
    fn arm(d: &Detection) -> ArmInput<'_> {
        ArmInput {
            detection: Some(d),
            flags: Vec::new(),
        }
    }

    let macros = BTreeMap::new();
    let detect = |detector: fn(&Evidence<'_>) -> Detection, build: &BuildRecord| {
        detector(&Evidence {
            macros: &macros,
            elf: None,
            build: Some(build),
            run: None,
            workdir: None,
        })
    };
    let marker = "chars omitted]";

    // clang, 24-character work directory, the observable in the first line.
    let dir = "/w/chard-sweep/wd-bare-1";
    assert_eq!(
        dir.chars().count(),
        24,
        "the directory the failure was measured under"
    );
    let stderr = clang_fallthrough_stderr(dir);
    assert!(
        stderr.chars().count() > DIAG_EXCERPT,
        "the stream must be over budget for the cut to be exercised"
    );
    let needle = "fall-through between switch labels";
    let positive = detect(detect_implicit_fallthrough, &diag_build(0, &stderr));
    assert_eq!(positive.outcome, Outcome::Present);
    assert!(
        positive.observed.contains(marker),
        "the stream is over budget, so the cut is marked: {}",
        positive.observed
    );
    assert!(
        positive.observed.contains(needle),
        "the matched diagnostic is quoted whole: {}",
        positive.observed
    );
    let canary_only = diag_build(
        0,
        &format!(
            "{dir}/implicit_fallthrough.c:67:9: warning: unused variable 'chard_canary_unused' [-Wunused-variable]\n"
        ),
    );
    let negative = detect(detect_implicit_fallthrough, &canary_only);
    assert_eq!(negative.outcome, Outcome::Absent);
    let (verdict, controls) = decide(&positive, arm(&positive), arm(&negative), None, None);
    assert_eq!(verdict, Verdict::On);
    let detail = controls
        .positive
        .detail
        .as_deref()
        .expect("an evaluated arm publishes its detail");
    assert!(
        detail.contains(marker) && detail.contains(needle),
        "the published arm detail carries the match past the marker: {detail}"
    );

    // gcc, a 300-character work directory: the error line is the second of eight and
    // its own path prefix is longer than the text the detector matched, so a tail
    // budget spent on the canary block and the summary cut into the needle itself.
    let dir = "/w".repeat(150);
    let stderr = gcc_format_security_stderr(&dir);
    let needle = "not a string literal";
    let positive = detect(detect_format_security, &diag_build(1, &stderr));
    assert_eq!(positive.outcome, Outcome::Present);
    assert_eq!(positive.level.as_deref(), Some("error"));
    let observed = &positive.observed;
    let cut = observed.find(marker).expect("the stream is over budget");
    let matched = observed
        .find(needle)
        .expect("the matched diagnostic is quoted");
    assert!(
        cut < matched,
        "the cut is before the match, so the match is what was kept: {observed}"
    );
    assert!(
        observed.contains("error: format not a string literal"),
        "the severity the detector read is on the quoted line: {observed}"
    );
}

/// The same compiler stream captured under two work directories publishes one excerpt.
///
/// An excerpt cut from the captured stream, with `measure::publish` making the work
/// directory relative afterwards, would let a longer `--workdir` move the cut, and
/// the `[N chars omitted]` count would carry path characters the published text did not;
/// [`Evidence::published`] has the fleet measurement. Pinned on clang's
/// fall-through stream, which is over budget whatever the directory, through the real
/// detector and then through the rewrite `publish` applies, under directories of 11 and
/// 147 characters: the published
/// `observed` strings are byte-identical, and each count is what the published stream
/// lost, so the kept text and the counts add up to it.
#[test]
fn one_stream_under_two_work_directories_publishes_one_excerpt() {
    let macros = BTreeMap::new();
    let publish = |dir: &str| {
        let build = diag_build(0, &clang_fallthrough_stderr(dir));
        let workdir = std::path::Path::new(dir);
        let detection = detect_implicit_fallthrough(&Evidence {
            macros: &macros,
            elf: None,
            build: Some(&build),
            run: None,
            workdir: Some(workdir),
        });
        assert_eq!(detection.outcome, Outcome::Present);
        let stream = crate::measure::publish_text(&build.stderr, workdir);
        (
            crate::measure::publish_text(&detection.observed, workdir),
            stream,
        )
    };
    let short = "/w/chard-wd";
    let long = format!("/w/{}", "chard-sweep-".repeat(12));
    assert_eq!((short.len(), long.len()), (11, 147));
    let (short_observed, short_stream) = publish(short);
    let (long_observed, long_stream) = publish(&long);
    assert_eq!(
        short_stream, long_stream,
        "the published streams are one stream"
    );
    assert!(
        short_stream.chars().count() > DIAG_EXCERPT,
        "the stream must be over budget for the cut to be exercised"
    );
    assert_eq!(
        short_observed, long_observed,
        "the excerpt does not depend on the work directory"
    );

    // Each count is what the published stream lost: kept text plus counts is the stream.
    let marker = format!(" {}]", crate::probe::CUT_MARKER);
    let quoted = short_observed
        .split_once("stderr=")
        .map(|(_, q)| q)
        .expect("the observed string quotes stderr");
    let quoted: String = serde_json::from_str(quoted).expect("a Debug-quoted ASCII stream");
    let mut omitted = 0usize;
    let mut kept = String::new();
    let mut rest = quoted.as_str();
    while let Some(end) = rest.find(&marker) {
        let (head, tail) = rest.split_at(end);
        let open = head.rfind('[').expect("a cut marker opens with a bracket");
        let (text, count) = head.split_at(open);
        let count: usize = count
            .trim_start_matches('[')
            .parse()
            .expect("a cut marker carries its count");
        omitted = omitted.saturating_add(count);
        kept.push_str(text);
        rest = tail.split_at(marker.len()).1;
    }
    kept.push_str(rest);
    assert!(omitted > 0, "the cut is marked: {quoted}");
    assert_eq!(
        kept.chars().count().saturating_add(omitted),
        short_stream.chars().count(),
        "the counts are what the published stream lost: {quoted}"
    );
    assert!(
        short_stream.contains(&kept),
        "the kept text is a run of the published stream's lines: {quoted}"
    );
}

/// `detect_no_copy_dt_needed` over one link record.
fn no_copy_dt_needed(exit_status: i32, stderr: &str) -> Detection {
    let build = diag_build(exit_status, stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    detect_no_copy_dt_needed(&ev)
}

/// The link GNU ld wrote for `-lchardnosuchlib`, a failure that is not the refusal.
const MISSING_LIBRARY: &str = "/usr/bin/ld: cannot find -lchardnosuchlib: No such file or \
                               directory\ncollect2: error: ld returned 1 exit status\n";

/// The `copy-dt-needed` probe's sources: the probe and the libraries it links through.
fn copy_dt_needed_sources() -> Vec<&'static str> {
    let probe = crate::probe::CORPUS
        .iter()
        .find(|p| p.id == "copy-dt-needed")
        .expect("the copy-dt-needed probe is in the corpus");
    let sources: Vec<&'static str> = std::iter::once(probe.source)
        .chain(probe.aux_libs.iter().map(|lib| lib.source))
        .collect();
    assert_eq!(sources.len(), 3, "the probe and its two libraries");
    sources
}

/// The refusal reads `present` in each linker's words the corpus records. These streams fit
/// the excerpt whole; `a_refusal_behind_a_sarif_document_reads_present_and_is_quoted` holds
/// the cut to the refusal line.
///
/// The lines are GNU ld's (Fedora 44, sample-report.json) and lld's (Chimera Linux, clang
/// 22.1.7, detectors.json), with the object paths shortened.
#[test]
fn the_linkers_refusal_of_the_transitive_symbol_reads_present() {
    for refusal in [
        "/usr/bin/ld: <compiler-temp>: undefined reference to symbol 'chard_dt_bfunc'\n\
         /usr/bin/ld: libchard_dt_b.so: error adding symbols: DSO missing from command \
         line\ncollect2: error: ld returned 1 exit status\n",
        "x86_64-chimera-linux-musl-ld: error: undefined symbol: chard_dt_bfunc\n>>> \
         referenced by copy_dt_needed.c\n>>>               p.o:(main)\n>>> did you mean: \
         chard_dt_afunc\n>>> defined in: libchard_dt_a.so\nclang: error: linker command \
         failed with exit code 1 (use -v to see invocation)\n",
    ] {
        let d = no_copy_dt_needed(1, refusal);
        assert_eq!(d.outcome, Outcome::Present, "{refusal}");
        assert!(refused_in(&d.observed), "{}", d.observed);
    }
    assert_eq!(no_copy_dt_needed(0, "").outcome, Outcome::Absent);
}

/// Whether `observed` quotes a refusal line, as the excerpt must where one was read.
fn refused_in(observed: &str) -> bool {
    DT_NEEDED_REFUSALS
        .iter()
        .any(|needle| observed.contains(needle))
}

/// A refusal behind a SARIF document is still the refusal, and the excerpt, cut from a
/// stream far past its budget, centres on the refusal line rather than on the stream's end.
#[test]
fn a_refusal_behind_a_sarif_document_reads_present_and_is_quoted() {
    let source = copy_dt_needed_sources()[0];
    let escaped = serde_json::to_string(source).expect("a source string serialises");
    let refusal = "/usr/bin/ld: <compiler-temp>: undefined reference to symbol \
                   'chard_dt_bfunc'\n";
    let tail = "/usr/bin/ld: libchard_dt_b.so: error adding symbols: DSO missing from command \
                line\ncollect2: error: ld returned 1 exit status\n"
        .repeat(20);
    let stderr = format!(
        "{}{refusal}{tail}",
        gcc_sarif_stderr(escaped.trim_matches('"'))
    );
    assert!(stderr.chars().count() > DIAG_EXCERPT);
    let d = no_copy_dt_needed(1, &stderr);
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
    assert!(refused_in(&d.observed), "{}", d.observed);
}

/// A measured wrong `on` (gcc 16.1.1, Fedora 44 `x86_64`): under
/// `-fdiagnostics-format=sarif-stderr` the document quotes the probe's whole source, which
/// calls `chard_dt_bfunc`, so a reader that takes the symbol anywhere reads a link that
/// failed for a missing library as `present`.
#[test]
fn the_symbol_in_a_sarif_documents_embedded_source_is_not_the_refusal() {
    for source in copy_dt_needed_sources() {
        let escaped = serde_json::to_string(source).expect("a source string serialises");
        let text = escaped.trim_matches('"');
        let stderr = format!("{}{MISSING_LIBRARY}", gcc_sarif_stderr(text));
        assert!(stderr.contains("chard_dt_bfunc"));
        let d = no_copy_dt_needed(1, &stderr);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    }
}

/// The plain-text form of the same quotation: a diagnostic on the call line prints that line
/// under its caret, and the link then fails for another reason.
#[test]
fn a_caret_quote_of_the_call_line_is_not_the_refusal() {
    let stderr = format!(
        "copy_dt_needed.c:83:31: warning: a diagnostic on the call [-Wsomething]\n   83 | \
         \x20   return chard_dt_afunc() + chard_dt_bfunc();\n      |                       \
         \x20       ^~~~~~~~~~~~~~\n{MISSING_LIBRARY}"
    );
    let d = no_copy_dt_needed(1, &stderr);
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    // A refusal worded as neither linker words it is not read as one, whatever it names.
    for other in [
        "/usr/bin/ld: libchard_dt_a.so: undefined reference to `chard_dt_bfunc'\n",
        "error: chard_dt_bfunc: undefined symbol\n",
        // lld's wording about another symbol, the named library's own among them.
        "ld.lld: error: undefined symbol: chard_dt_afunc\n",
        "ld.lld: error: undefined symbol: chard_other\n",
        // GNU ld's wording about a longer name: the needle ends at the closing quote.
        "/usr/bin/ld: p.o: undefined reference to symbol 'chard_dt_bfunc_other'\n",
        MISSING_LIBRARY,
        // gold's wording, not in the corpus: withheld, and the reason says what was read
        // rather than that the flag was not in force.
        "/usr/bin/ld.gold: error: p.o: undefined reference to 'chard_dt_bfunc'\n",
    ] {
        let d = no_copy_dt_needed(1, other);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{other}");
        assert!(
            d.observed.contains("in a wording chard reads"),
            "{}",
            d.observed
        );
    }
}

/// lld's needle ends at the name, so it is a refusal of this symbol only while the probe's
/// sources name no other identifier beginning with it.
#[test]
fn no_other_symbol_of_the_probe_begins_with_the_refused_name() {
    for source in copy_dt_needed_sources() {
        for (at, _) in source.match_indices("chard_dt_bfunc") {
            let next = source[at + "chard_dt_bfunc".len()..].chars().next();
            assert!(
                !next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_'),
                "an identifier extends chard_dt_bfunc at byte {at}"
            );
        }
    }
}

/// The probe's sources carry no refusal, as written and as a JSON string carries them, so a
/// compiler quoting them cannot write one.
#[test]
fn the_probes_sources_carry_no_refusal() {
    for source in copy_dt_needed_sources() {
        let escaped = serde_json::to_string(source).expect("a source string serialises");
        for text in [source, escaped.as_str()] {
            assert_eq!(needle_line(text, DT_NEEDED_REFUSALS), None);
        }
    }
}

/// `detect_pic_shared_link` over one link record, with the facts of a shared object carrying
/// no text relocation where the link wrote one.
fn pic_shared_link(exit_status: i32, stderr: &str, wrote: bool) -> Detection {
    let mut build = diag_build(exit_status, stderr);
    if wrote {
        build.artifact_sha256 = Some("0".repeat(64));
    }
    let elf = wrote.then(|| shared_object(false));
    pic_shared_link_over(&build, elf.as_ref())
}

/// `detect_pic_shared_link` over `build` and the facts of the object it wrote.
fn pic_shared_link_over(build: &BuildRecord, elf: Option<&ElfFacts>) -> Detection {
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf,
        build: Some(build),
        run: None,
        workdir: None,
    };
    detect_pic_shared_link(&ev)
}

/// The facts of a shared object, `textrel` as given.
fn shared_object(textrel: bool) -> ElfFacts {
    let mut elf = crate::probe::tests::elf_with_report("");
    elf.shared_object = Some(true);
    elf.has_interp = false;
    elf.textrel = textrel;
    elf
}

/// The refusal reads `absent` in the wording of every linker measured, and only on a line
/// naming the probe's own symbol.
///
/// The lines are the ones GNU ld 2.46.1 (x86_64 and aarch64), lld 22.1.8 and mold wrote for
/// `-O2 -fPIE -shared probes/pic_shared_link.c` on Fedora 44, 2026-10-02, gold 1.16
/// (binutils 2.46.1) in the Fedora 44 x86_64 linkers image, and GNU ld 2.24 on Ubuntu 14.04
/// x86_64, with the object path shortened.
#[test]
fn a_link_refused_for_want_of_fpic_reads_absent_in_each_linkers_words() {
    for refusal in [
        "/usr/bin/ld.gold: error: p.o: requires dynamic R_X86_64_PC32 reloc against \
         'chard_pic_anchor' which may overflow at runtime; recompile with -fPIC\ncollect2: \
         error: ld returned 1 exit status\n",
        // GNU ld 2.24 (Ubuntu 14.04 x86_64), from a fleet sweep.
        "/usr/bin/ld: p.o: relocation R_X86_64_32S against `chard_pic_anchor' can not be \
         used when making a shared object; recompile with -fPIC\np.o: error adding symbols: \
         Bad value\ncollect2: error: ld returned 1 exit status\n",
        "/usr/bin/ld.bfd: p.o: warning: relocation against `chard_pic_anchor' in read-only \
         section `.text'\n/usr/bin/ld.bfd: p.o: relocation R_X86_64_PC32 against symbol \
         `chard_pic_anchor' can not be used when making a shared object; recompile with \
         -fPIC\n/usr/bin/ld.bfd: final link failed: bad value\ncollect2: error: ld returned \
         1 exit status\n",
        "ld.lld: error: relocation R_X86_64_PC32 cannot be used against symbol \
         'chard_pic_anchor'; recompile with -fPIC\n>>> defined in p.o\n>>> referenced by \
         p.c\ncollect2: error: ld returned 1 exit status\n",
        "mold: error: p.o:(.text): R_X86_64_PC32 relocation at offset 0x9 against symbol \
         `chard_pic_anchor' can not be used; recompile with -fPIC\nclang: error: linker \
         command failed with exit code 1 (use -v to see invocation)\n",
        "/usr/bin/ld.bfd: p.o: relocation R_AARCH64_ADR_PREL_PG_HI21 against symbol \
         `chard_pic_anchor' which may bind externally can not be used when making a shared \
         object; recompile with -fPIC\np.c:(.text+0x4): dangerous relocation: unsupported \
         relocation\ncollect2: error: ld returned 1 exit status\n",
    ] {
        let d = pic_shared_link(1, refusal, false);
        assert_eq!(d.outcome, Outcome::Absent, "{refusal}");
        assert!(
            d.observed.contains("recompile with -fPIC")
                && PIC_SHARED_REFUSALS.iter().any(|n| d.observed.contains(n)),
            "{}",
            d.observed
        );
    }
}

/// A link that wrote its shared object is `present`; one that exited 0 and wrote nothing
/// linked nothing, and a failure that is not this refusal poses no question.
#[test]
fn only_the_refusal_of_the_probes_own_symbol_reads_absent() {
    assert_eq!(pic_shared_link(0, "", true).outcome, Outcome::Present);
    assert_eq!(
        pic_shared_link(0, "", false).outcome,
        Outcome::Indeterminate,
        "exit 0 and no output is not a link"
    );
    for other in [
        "gcc: error: unrecognized command-line option '-fhardened'\n",
        "/usr/bin/ld: cannot find -lnosuch: No such file or directory\n",
        // The refusal, about a symbol that is not the probe's: a reference this probe did
        // not make cannot say what the profile did to the one it did.
        "ld.lld: error: relocation R_X86_64_PC32 cannot be used against symbol \
         'other_global'; recompile with -fPIC\n",
        // The symbol named, the refusal on another line.
        "p.c: undefined reference to `chard_pic_anchor'\nnote: recompile with -fPIC\n",
        // Both on one line, but not as a linker writes the refused reference.
        "p.c: note: chard_pic_anchor; recompile with -fPIC\n",
        // The phrase ahead of the symbol.
        "ld.lld: error: recompile with -fPIC: relocation against symbol 'chard_pic_anchor'\n",
        // GNU ld's own warning names the symbol in a needle's words with no phrase, and the
        // phrase follows on a refusal of another symbol: a line, not the stream, decides.
        "/usr/bin/ld: p.o: warning: relocation against `chard_pic_anchor' in read-only \
         section `.text'\n/usr/bin/ld: p.o: relocation R_X86_64_PC32 against symbol \
         `other_global' can not be used when making a shared object; recompile with -fPIC\n",
    ] {
        let d = pic_shared_link(1, other, false);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{other}");
        assert!(
            d.observed.contains("in a wording chard reads"),
            "{}",
            d.observed
        );
    }
}

/// The phrase and the symbol on different lines are no refusal, and the published reason and
/// excerpt are the line that decided it: the reason says no line is a refusal chard reads, and
/// where a later line is the refusal the excerpt centres on that line, not on an earlier one
/// carrying the phrase alone.
#[test]
fn the_excerpt_and_the_reason_are_the_line_that_decided_it() {
    let other = "ld.lld: error: relocation R_X86_64_PC32 cannot be used against symbol \
                 'other_global'; recompile with -fPIC\n";
    let padding = ">>> referenced by p.c\n".repeat(40);
    let refusal = "ld.lld: error: relocation R_X86_64_PC32 cannot be used against symbol \
                   'chard_pic_anchor'; recompile with -fPIC\n";

    // The phrase on one line, the symbol on another, past the excerpt's budget.
    let apart = format!("{other}{padding}p.c: undefined reference to `chard_pic_anchor'\n");
    assert!(apart.chars().count() > DIAG_EXCERPT);
    let d = pic_shared_link(1, &apart, false);
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(
        d.observed
            .contains("no line of its stderr is a linker refusing"),
        "{}",
        d.observed
    );
    // No line decided it, so the excerpt is the stream's end, where the linker's failure
    // is, and not the earlier line carrying the phrase for another symbol.
    assert!(
        d.observed
            .contains("undefined reference to `chard_pic_anchor'")
            && !d.observed.contains("other_global"),
        "{}",
        d.observed
    );

    // The refusal after a line carrying the phrase for another symbol, and after GNU ld's
    // warning naming the symbol in a needle's words: the excerpt quotes the refusal.
    // Centred on the phrase alone it quoted the first line, and centred on a needle alone
    // the warning, and either cut the refusal.
    let warning = "/usr/bin/ld: p.o: warning: relocation against `chard_pic_anchor' in \
                   read-only section `.text'\n";
    let later = format!("{other}{warning}{padding}{refusal}{padding}");
    assert!(later.chars().count() > DIAG_EXCERPT);
    let d = pic_shared_link(1, &later, false);
    assert_eq!(d.outcome, Outcome::Absent, "{}", d.observed);
    assert!(
        d.observed
            .contains("'chard_pic_anchor'; recompile with -fPIC"),
        "{}",
        d.observed
    );
    assert!(!d.observed.contains("other_global"), "{}", d.observed);
    assert!(!d.observed.contains("read-only section"), "{}", d.observed);
}

/// The `pic-shared-link` probe's source.
fn pic_shared_link_source() -> &'static str {
    crate::probe::CORPUS
        .iter()
        .find(|p| p.id == "pic-shared-link")
        .expect("the pic-shared-link probe is in the corpus")
        .source
}

/// A measured wrong `off` (gcc 16.1.1, Fedora 44 x86_64, `-O2 -fPIC
/// -fdiagnostics-format=sarif-stderr` with `--ldflags -lchardnosuchlib`): the SARIF document
/// carries the probe's source as one JSON string, holding both the phrase and the symbol, so
/// a reader that takes the phrase anywhere on a line reads a link that failed for a missing
/// library as `absent`. `tests/fixtures/detectors.json`
/// holds the measured stream verbatim.
#[test]
fn the_phrase_in_a_sarif_documents_embedded_source_is_not_the_refusal() {
    let escaped = serde_json::to_string(pic_shared_link_source()).expect("a source serialises");
    let stderr = format!(
        "{}{MISSING_LIBRARY}",
        gcc_sarif_stderr(escaped.trim_matches('"'))
    );
    assert!(
        stderr
            .lines()
            .any(|line| line.contains(PIC_SHARED_REFUSAL) && line.contains(PIC_SHARED_SYMBOL)),
        "the document's line holds both words, the shape a reading of any line takes for a refusal"
    );
    let d = pic_shared_link(1, &stderr, false);
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

/// A refusal behind a SARIF document is still the refusal, and is quoted.
#[test]
fn a_pic_refusal_behind_a_sarif_document_reads_absent_and_is_quoted() {
    let escaped = serde_json::to_string(pic_shared_link_source()).expect("a source serialises");
    let refusal = "/usr/bin/ld.bfd: p.o: relocation R_X86_64_PC32 against symbol \
                   `chard_pic_anchor' can not be used when making a shared object; recompile \
                   with -fPIC\n/usr/bin/ld.bfd: final link failed: bad value\ncollect2: error: \
                   ld returned 1 exit status\n";
    let stderr = format!("{}{refusal}", gcc_sarif_stderr(escaped.trim_matches('"')));
    assert!(stderr.chars().count() > DIAG_EXCERPT);
    let d = pic_shared_link(1, &stderr, false);
    assert_eq!(d.outcome, Outcome::Absent, "{}", d.observed);
    assert!(
        d.observed.contains("`chard_pic_anchor' can not be used"),
        "{}",
        d.observed
    );
}

/// Every needle names the symbol the detector's reason names and the probe defines, so a
/// rename of one cannot leave the needles reading every refusal `indeterminate`.
#[test]
fn every_pic_refusal_needle_names_the_probes_symbol() {
    assert!(
        pic_shared_link_source().contains(&format!("int {PIC_SHARED_SYMBOL}[")),
        "the probe defines {PIC_SHARED_SYMBOL}"
    );
    for needle in PIC_SHARED_REFUSALS {
        assert!(needle.contains(PIC_SHARED_SYMBOL), "{needle}");
    }
}

/// The probe's source carries no refusal, as written and as a JSON string carries it, so a
/// compiler quoting it cannot write one.
#[test]
fn the_pic_probes_source_carries_no_refusal() {
    let source = pic_shared_link_source();
    let escaped = serde_json::to_string(source).expect("a source serialises");
    for text in [source, escaped.as_str()] {
        assert_eq!(pic_refusal_line(text), None);
    }
}

/// The probe's source carries no linker text-relocation warning, as written and as a JSON
/// string carries it, so a compiler quoting it cannot write one. Its comment does say "text
/// relocation", the phrase the reader once matched.
#[test]
fn the_pic_probes_source_carries_no_text_relocation_warning() {
    let source = pic_shared_link_source();
    assert!(source.contains("text relocation"));
    let escaped = serde_json::to_string(source).expect("a source serialises");
    for text in [source, escaped.as_str()] {
        let mut build = diag_build(0, text);
        build.argv = vec!["cc".to_owned(), "-shared".to_owned()];
        assert_eq!(text_relocations_permitted(&build), None);
    }
}

/// A measured wrong reason (gcc 16.1.1, Fedora 44 x86_64, `-O2 -fPIC
/// -fdiagnostics-format=sarif-stderr`): the link exits 0 and writes a clean object, and a
/// reader that takes the SARIF document's copy of the probe's source, whose comment says "text
/// relocation", withholds it as a link the linker reported text relocations for. No linker
/// wrote a line.
#[test]
fn a_successful_link_behind_a_sarif_document_reads_present() {
    let escaped = serde_json::to_string(pic_shared_link_source()).expect("a source serialises");
    let d = pic_shared_link(0, &gcc_sarif_stderr(escaped.trim_matches('"')), true);
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
}

/// A linker's warning after a SARIF document is still read: the linker's lines follow the
/// document as text, so a recognised stream does not hide one (the register entry
/// `diag-stream-is-text-unless-recognised`). A reader that skipped the scan beside a
/// document would pass every other test.
#[test]
fn a_linker_warning_after_a_sarif_document_withholds_the_success() {
    let escaped = serde_json::to_string(pic_shared_link_source()).expect("a source serialises");
    let stderr = format!(
        "{}/usr/bin/ld.bfd: warning: creating DT_TEXTREL in a shared object\n",
        gcc_sarif_stderr(escaped.trim_matches('"'))
    );
    let d = pic_shared_link(0, &stderr, true);
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(
        d.observed.contains("linker reporting text relocations"),
        "{}",
        d.observed
    );
}

/// Each linker's text-relocation warning, as the linker wrote it, withholds a successful link
/// whose object was read clean. GNU ld 2.46.1 (Fedora 44) and gold 1.16 (binutils 2.46.1)
/// under `-Wl,-z,notext -Wl,--warn-shared-textrel`, mold 2.40.4 under `-Wl,--warn-textrel`,
/// and GNU ld 2.30's wording from its libbfd's strings (AlmaLinux 8); the measurements are
/// beside `TEXT_RELOCATION_WARNINGS`.
/// A line holding the words only in another case, without the linker's `warning: `, cut short,
/// or holding only "text relocation", is no linker's warning.
#[test]
fn only_a_linkers_own_text_relocation_warning_withholds_a_successful_link() {
    for line in [
        "/usr/bin/ld.bfd: warning: creating DT_TEXTREL in a shared object",
        "/usr/bin/ld: warning: creating a DT_TEXTREL in a shared object.",
        "/usr/bin/ld.gold: warning: shared library text segment is not shareable",
        "mold: warning: creating a DT_TEXTREL in an output file",
    ] {
        let d = pic_shared_link(0, &format!("{line}\n"), true);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{line}");
        assert!(
            d.observed.contains("linker reporting text relocations"),
            "{}",
            d.observed
        );
    }
    for line in [
        " * x86_64 GNU ld and mold accept `-mcmodel=large -fPIE` code, and mold `-fno-pic",
        " * -mcmodel=large` code by text relocation. Each link succeeds without -fPIC.",
        "/usr/bin/ld: warning: Creating dt_textrel in a shared object",
        "p.c:1:1: note: text relocations are not shareable",
        "creating DT_TEXTREL in a shared object",
        "/usr/bin/ld: warning: creating DT_TEXTREL",
        "/usr/bin/ld: warning: creating a DT_TEXTRELA",
        "/usr/bin/ld.gold: warning: shared library text segment",
        "creating a DT_TEXTREL in an output file",
        "p.c:1:1: note: shared library text segment is not shareable",
        "/usr/bin/ld.gold: warning: shared library text segment is not",
    ] {
        let d = pic_shared_link(0, &format!("{line}\n"), true);
        assert_eq!(d.outcome, Outcome::Present, "{line}: {}", d.observed);
    }
}

/// The permission is read through every spelling of the hand-on, gcc's abbreviations
/// included, and not in a word another option takes as its value.
#[test]
fn the_text_relocation_permission_is_read_through_every_spelling_of_the_hand_on() {
    let line = |w: &[&str]| w.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
    for permitted in [
        &["cc", "--for-linker", "-z", "--for-linker", "notext"][..],
        &["cc", "--for-l", "-z", "--for-l", "notext"],
        &["cc", "--for-linker=-znotext"],
        &["cc", "-Xlinker", "-z", "-Xlinker", "textoff"],
        &["cc", "-z", "notext"],
        &["cc", "-znotext"],
        &["cc", "-Wl,-z,notext"],
        &["cc", "-Xarch_x86_64", "-Wl,-znotext"],
    ] {
        assert!(
            link_line_permits_text_relocations(&line(permitted)),
            "{permitted:?}"
        );
    }
    for not in [
        &["cc", "-o", "-znotext"][..],
        &["cc", "-u", "-z", "notext"],
        &["cc", "-z", "now"],
        &["cc", "--for-linker"],
    ] {
        assert!(!link_line_permits_text_relocations(&line(not)), "{not:?}");
    }
}

/// A link allowed text relocations proves nothing about position independence, so its
/// success is withheld rather than read `present`.
#[test]
fn a_link_permitted_text_relocations_is_not_read_as_pic() {
    let mut build = diag_build(0, "");
    build.artifact_sha256 = Some("0".repeat(64));
    build.argv = vec![
        "cc".to_owned(),
        "-fno-pic".to_owned(),
        "-mcmodel=large".to_owned(),
        "-Wl,-z,notext".to_owned(),
        "-shared".to_owned(),
    ];
    let clean = shared_object(false);
    assert_eq!(
        pic_shared_link_over(&build, Some(&clean)).outcome,
        Outcome::Indeterminate
    );
    let warned = pic_shared_link(
        0,
        "/usr/bin/ld: warning: creating DT_TEXTREL in a shared object\n",
        true,
    );
    assert_eq!(warned.outcome, Outcome::Indeterminate);
}

/// A shared object carrying `DT_TEXTREL` was linked by text relocation whatever its link
/// line said, so the link's success is withheld; one whose facts were not read is withheld
/// too, since the tag is what a successful link is read through.
///
/// The measured shape: `-O2 -fno-pic -mcmodel=large -fuse-ld=lld` with a `-z notext` from a
/// specs file (gcc 16.2.1) or a configuration file (clang 22.1.8), LLD 22.1.8, Fedora 44
/// x86_64, 2026-10-08 and 2026-10-11: exit 0, an empty stderr, no `notext` on the line, and
/// the object carrying the tag. `tests/fixtures/detectors.json` holds both measured rows.
#[test]
fn a_shared_object_carrying_dt_textrel_is_not_read_as_pic() {
    let mut build = diag_build(0, "");
    build.artifact_sha256 = Some("0".repeat(64));
    build.argv = [
        "gcc",
        "-O2",
        "-fno-pic",
        "-mcmodel=large",
        "-fuse-ld=lld",
        "-specs=notext.specs",
        "-shared",
        "-o",
        "pic-shared-link-measured.so",
        "pic_shared_link.c",
    ]
    .map(str::to_owned)
    .to_vec();
    let tagged = pic_shared_link_over(&build, Some(&shared_object(true)));
    assert_eq!(tagged.outcome, Outcome::Indeterminate);
    assert!(
        tagged.observed.contains("DT_TEXTREL"),
        "{}",
        tagged.observed
    );
    let unread = pic_shared_link_over(&build, None);
    assert_eq!(unread.outcome, Outcome::Indeterminate);
    assert!(unread.observed.contains("not read"), "{}", unread.observed);
    // No dynamic section: `textrel` is false there whatever the code took.
    let mut no_dynamic = shared_object(false);
    no_dynamic.has_dynamic = false;
    assert_eq!(
        pic_shared_link_over(&build, Some(&no_dynamic)).outcome,
        Outcome::Indeterminate
    );
    assert_eq!(
        pic_shared_link_over(&build, Some(&shared_object(false))).outcome,
        Outcome::Present
    );
    // A refusal is read from the link alone: the facts of no object do not enter it.
    let refused = diag_build(
        1,
        "ld.lld: error: relocation R_X86_64_PC32 cannot be used against symbol \
         'chard_pic_anchor'; recompile with -fPIC\n",
    );
    assert_eq!(
        pic_shared_link_over(&refused, None).outcome,
        Outcome::Absent
    );
}

/// `--for-linker` hands the linker its argument as `-Xlinker` does, in both its spellings, so a
/// `-z notext` passed through it withholds the link's success as the `-Xlinker` one does.
///
/// A reader that skipped `--for-linker=-znotext` whole, or read
/// `--for-linker -z --for-linker notext` as `-z` followed by `--for-linker`, would read the
/// measured link of `-O2 -fno-pic -mcmodel=large` `present` on Fedora 44 x86_64.
#[test]
fn notext_is_read_through_for_linker_in_both_spellings() {
    let shared = |extra: &[&str]| {
        let mut build = diag_build(0, "");
        build.artifact_sha256 = Some("0".repeat(64));
        build.argv = ["cc", "-fno-pic", "-mcmodel=large"]
            .iter()
            .chain(extra)
            .chain(&["-shared", "-o", "p.so", "p.c"])
            .map(|arg| (*arg).to_owned())
            .collect();
        pic_shared_link_over(&build, Some(&shared_object(false))).outcome
    };
    for spelling in [
        &["--for-linker=-znotext"][..],
        &["--for-linker", "-znotext"],
        &["--for-linker", "-z", "--for-linker", "notext"],
        &["--for-linker=-z", "--for-linker=notext"],
        &["--for-linker=-z", "-Xlinker", "textoff"],
    ] {
        assert_eq!(shared(spelling), Outcome::Indeterminate, "{spelling:?}");
    }
    for other in [
        &["--for-linker=-znow"][..],
        &["--for-linker", "-z", "--for-linker", "now"],
        &["--for-linker", "--as-needed"],
    ] {
        assert_eq!(shared(other), Outcome::Present, "{other:?}");
    }
}

/// `-z notext`, and its synonym `-z textoff`, is read as a linker option in each spelling the
/// driver passes one, never as a substring of a path: an output, source or workdir path
/// naming `notext` or `TEXTREL` is a host's choice of directory, and a link under it still
/// reads `present`.
///
/// Seen 2026-10-02: under `--workdir wd-notext-dir` on Fedora 44 x86_64 with
/// gcc 16.1.1, the `-fPIC` positive arm read `indeterminate` and the check `probe-invalid`.
#[test]
fn notext_is_read_from_linker_options_not_from_paths() {
    let shared = |argv: &[&str], stderr: &str| {
        let mut build = diag_build(0, stderr);
        build.artifact_sha256 = Some("0".repeat(64));
        build.argv = argv.iter().map(|arg| (*arg).to_owned()).collect();
        pic_shared_link_over(&build, Some(&shared_object(false))).outcome
    };
    let paths = [
        "-o",
        "/w/wd-notext-dir/pic-shared-link/TEXTREL.so",
        "/w/wd-notext-dir/probes/notext.c",
    ];
    let with = |extra: &[&'static str]| {
        let mut argv = vec!["cc", "-fPIC", "-shared"];
        argv.extend_from_slice(extra);
        argv.extend_from_slice(&paths);
        argv
    };
    assert_eq!(shared(&with(&[]), ""), Outcome::Present);
    assert_eq!(
        shared(
            &with(&[]),
            "/usr/bin/ld: warning: /w/TEXTREL/notext.o: missing .note.GNU-stack section\n"
        ),
        Outcome::Present,
        "a path in a linker line is not the linker reporting text relocations"
    );
    for spelling in [
        &["-Wl,-z,notext"][..],
        &["-Wl,-znotext"],
        &["-Wl,--as-needed,-z,notext"],
        &["-Wl,-z", "-Wl,notext"],
        &["-Xlinker", "-z", "-Xlinker", "notext"],
        &["-Xlinker", "-znotext"],
        &["-z", "notext"],
        &["-Wl,-z,textoff"],
        &["-Wl,-ztextoff"],
        &["-Xlinker", "-z", "-Xlinker", "textoff"],
        &["-z", "textoff"],
    ] {
        assert_eq!(
            shared(&with(spelling), ""),
            Outcome::Indeterminate,
            "{spelling:?}"
        );
    }
    for other in [
        &["-Wl,-z,text"][..],
        &["-z", "now"],
        &["-Wl,-z,relro,-z,now"],
        &["-Wl,-z,texton"],
        &["-Wl,-ztext"],
    ] {
        assert_eq!(shared(&with(other), ""), Outcome::Present, "{other:?}");
    }
    assert_eq!(
        shared(
            &with(&[]),
            "/usr/bin/ld: warning: creating DT_TEXTREL in a shared object\n"
        ),
        Outcome::Indeterminate
    );
}

/// gcc 16.1.1's `-fdiagnostics-format=sarif-stderr` over an implicit declaration, cut to the
/// parts the detectors can be fooled by (Fedora 44 x86_64, 2026-10-09). The message sits on a
/// line with no severity word, the level on another, and the probe's source rides along in
/// `artifacts[].contents.text`.
fn gcc_sarif_stderr(source_line: &str) -> String {
    format!(
        "{{\"$schema\": \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json\",\n \
         \"version\": \"2.1.0\",\n \
         \"runs\": [{{\"tool\": {{\"driver\": {{\"name\": \"GNU C23\"}}}},\n \
         \"results\": [{{\"ruleId\": \"-Wimplicit-function-declaration\",\n \
         \"level\": \"error\",\n \
         \"message\": {{\"text\": \"implicit declaration of function 'chard_probe_target'\"}}}}],\n \
         \"artifacts\": [{{\"location\": {{\"uri\": \"p.c\"}},\n \
         \"contents\": {{\"text\": \"{source_line}\"}}}}]}}]}}\n"
    )
}

fn structured_withheld(d: &Detection) -> bool {
    d.outcome == Outcome::Indeterminate && d.observed.contains(STRUCTURED_STREAM_RULE)
}

fn evidence_of(build: &crate::compile::BuildRecord) -> Detection {
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(build),
        run: None,
        workdir: None,
    };
    detect_implicit_function_declaration(&ev)
}

/// The measured defect: the SARIF message line names the construct and no severity word, so
/// the detector read a failed build as a warning and the check as `off`.
#[test]
fn a_sarif_error_is_not_read_as_a_warning() {
    let build = diag_build(1, &gcc_sarif_stderr("int main(void) { return 0; }"));
    assert_eq!(
        diag_severity_of(&build, IMPLICIT_DECLARATION_NEEDLES),
        Some(Seen::Unreadable(Unreadable::StructuredStream))
    );
    let d = evidence_of(&build);
    assert!(structured_withheld(&d), "{}", d.observed);
}

/// The other half: the document quotes the translation unit, so a needle the probe's source
/// or comments carry matches a line that is no diagnostic. A build that said nothing at all
/// (empty results) still carries the source whenever gcc reported anything.
#[test]
fn a_needle_in_the_embedded_source_is_not_a_diagnostic() {
    let stderr = gcc_sarif_stderr("chard_wall_dead_label: ;")
        .replace("\"level\": \"error\"", "\"level\": \"note\"")
        .replace("implicit declaration of function", "unrelated");
    let build = diag_build(0, &stderr);
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    for d in [
        detect_warn_all(&ev),
        detect_warn_extra(&ev),
        detect_implicit_fallthrough(&ev),
        detect_implicit_int(&ev),
        detect_format_security(&ev),
        detect_hardened_warning(&ev),
    ] {
        assert!(structured_withheld(&d), "{}", d.observed);
    }
}

/// A stream the format arrives in by a specs file or a configuration file is the same
/// stream: the build record's argv names no format, the stderr does.
#[test]
fn the_stream_is_recognised_without_the_flag_in_the_argv() {
    let mut build = diag_build(1, &gcc_sarif_stderr("x"));
    build.argv = vec!["cc".to_owned(), "-O2".to_owned(), "p.c".to_owned()];
    assert!(structured_withheld(&evidence_of(&build)));
}

/// clang prints a text banner ahead of its document and a count after it.
#[test]
fn a_clang_sarif_document_behind_a_text_banner_is_recognised() {
    let stderr = "warning: diagnostic formatting in SARIF mode is currently unstable \
                  [-Wsarif-format-unstable]\n{\n  \"$schema\": \
                  \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/\
                  sarif-schema-2.1.0.json\",\n  \"version\": \"2.1.0\",\n  \"runs\": []\n}\n\
                  1 error generated.\n";
    assert!(structured_stream(stderr));
}

/// gcc 9 to 15's `-fdiagnostics-format=json`: an array of objects, one line. The first is gcc
/// 12.2.0's own output for an implicit declaration (Debian 12 image, 2026-10-09), cut; gcc
/// 13.3.0 orders the keys differently after `"kind"`. gcc 16 rejects the format.
#[test]
fn a_gcc_json_diagnostics_array_is_recognised() {
    let one = "[{\"kind\": \"warning\", \"locations\": [{\"caret\": {\"line\": 1}}], \
               \"column-origin\": 1, \"option\": \"-Wimplicit-function-declaration\", \
               \"children\": [], \"message\": \"implicit declaration of function 'f'\"}]\n";
    assert!(structured_stream(one));
    let spread = "[\n  {\"kind\": \"warning\", \"message\": \"x\"}\n]\n";
    assert!(structured_stream(spread));
}

/// Text is not mistaken for a document, including text that quotes the words.
#[test]
fn ordinary_text_diagnostics_are_not_structured() {
    let text = "p.c: In function 'main':\n\
                p.c:45:12: error: implicit declaration of function 'f' \
                [-Wimplicit-function-declaration]\n   \
                45 |     return f();\n      |            ^\n   \
                46 | { \"$schema\": sarif }\n";
    assert!(!structured_stream(text));
    assert!(!structured_stream(""));
    assert!(!structured_stream("[note] a bracket at the start\n"));
}

/// `-fdiagnostics-add-output=sarif:...` writes a file and leaves text on stderr, which is read
/// as text.
#[test]
fn text_stderr_beside_a_sarif_file_is_read_as_text() {
    let stderr = "p.c: In function 'main':\n\
                  p.c:45:12: error: implicit declaration of function 'f' \
                  [-Wimplicit-function-declaration]\n";
    assert_eq!(
        diag_severity_of(&diag_build(1, stderr), IMPLICIT_DECLARATION_NEEDLES),
        Some(Seen::Error)
    );
}

/// A matched line with no severity word is withheld, never a warning.
#[test]
fn a_matched_line_without_a_severity_word_is_unreadable() {
    let stderr = "p.c: In function 'implicit declaration of function':\n";
    let build = diag_build(1, stderr);
    assert_eq!(
        diag_severity_of(&build, IMPLICIT_DECLARATION_NEEDLES),
        Some(Seen::Unreadable(Unreadable::NoSeverityWord))
    );
    let d = evidence_of(&build);
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(d.level.is_none());
    let macros = BTreeMap::new();
    let ev = Evidence {
        macros: &macros,
        elf: None,
        build: Some(&build),
        run: None,
        workdir: None,
    };
    let w = detect_warn_extra(&Evidence {
        build: Some(&diag_build(0, "x.c: different sign\n")),
        ..ev
    });
    assert_eq!(w.outcome, Outcome::Indeterminate, "{}", w.observed);
}

/// The rule id a detector names is the one the register carries.
#[test]
fn the_rule_a_detector_names_is_in_the_assumption_register() {
    assert!(
        crate::report::ASSUMPTIONS
            .iter()
            .any(|a| a.id == STRUCTURED_STREAM_RULE),
        "{STRUCTURED_STREAM_RULE} withholds readings and has no assumption entry"
    );
}

const NOT_ASKED: &str = "never asked for the canary's warning";
const SUPPRESSED: &str = "suppressed or redirected";
const FAILED: &str = "the build failed without the diagnostic";

/// The rows of [`a_silent_build_that_never_asked_for_the_canary_says_so`]: how the probe's
/// canary fires, the build's exit status, its flags, and the sentence it must publish.
const SILENCE_ROWS: &[(Canary, i32, &[&str], &str)] = &[
    (Canary::AskedByFlags, 0, &[], NOT_ASKED),
    (Canary::AskedByFlags, 0, &["-O2"], NOT_ASKED),
    (Canary::AskedByFlags, 0, &["-O2", "-fhardened"], NOT_ASKED),
    (
        Canary::AskedByFlags,
        0,
        &["-O2", "-Wextra", "-Wl,-z,now"],
        NOT_ASKED,
    ),
    (
        Canary::AskedByFlags,
        0,
        &["-W", "-Wpedantic", "-Wno-error"],
        NOT_ASKED,
    ),
    (Canary::AskedByFlags, 0, &["-Wunused-parameter"], NOT_ASKED),
    (
        Canary::AskedByFlags,
        0,
        &["-Wunused-but-set-variable"],
        NOT_ASKED,
    ),
    (
        Canary::AskedByFlags,
        0,
        &["-Wl,-Wall", "-Wa,--all-warnings"],
        NOT_ASKED,
    ),
    (Canary::AskedByFlags, 0, &["-Werror=extra"], NOT_ASKED),
    (Canary::AskedByFlags, 0, &["-O2", "-Wall"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["-Wall", "-w"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["-Wall", "-Wno-unused-variable"],
        SUPPRESSED,
    ),
    (Canary::AskedByFlags, 0, &["-w"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["-O2", "-fhardened", "-w"],
        SUPPRESSED,
    ),
    (Canary::AskedByFlags, 0, &["--no-warnings"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["-Wno-unused-variable"],
        SUPPRESSED,
    ),
    (Canary::AskedByFlags, 0, &["-Wno-all"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["--warn-no-unused"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["-fdiagnostics-format=sarif-file"],
        SUPPRESSED,
    ),
    (
        Canary::AskedByFlags,
        0,
        &["-fdiagnostics-add-output=sarif"],
        SUPPRESSED,
    ),
    (
        Canary::AskedByFlags,
        0,
        &["-fdiagnostics-set-output=sarif"],
        SUPPRESSED,
    ),
    (Canary::AskedByFlags, 0, &["--all-warnings"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["--warn-all"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["--warn-unused-variable"],
        SUPPRESSED,
    ),
    (
        Canary::AskedByFlags,
        0,
        &["-Wunused-variable=1"],
        SUPPRESSED,
    ),
    (
        Canary::AskedByFlags,
        0,
        &["-Werror=unused-variable=1"],
        SUPPRESSED,
    ),
    (Canary::AskedByFlags, 0, &["-Wp,-Wall"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["-Wp,-DX,-Wunused"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["-Xclang", "-Wall"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["-Xclang=-Wall"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["-Xclang=-w"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["-Xclang=-fno-builtin"],
        NOT_ASKED,
    ),
    (
        Canary::AskedByFlags,
        0,
        &["-specs", "extra.specs"],
        SUPPRESSED,
    ),
    (Canary::AskedByFlags, 0, &["@flags.rsp"], SUPPRESSED),
    (Canary::AskedByFlags, 0, &["-specs=extra.specs"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["--specs=extra.specs"],
        SUPPRESSED,
    ),
    (Canary::AskedByFlags, 0, &["--config=extra.cfg"], SUPPRESSED),
    (
        Canary::AskedByFlags,
        0,
        &["--config", "extra.cfg"],
        SUPPRESSED,
    ),
    (Canary::Pinned, 0, &[], SUPPRESSED),
    (Canary::Pinned, 0, &["-O2", "-Wall"], SUPPRESSED),
    (Canary::AskedByFlags, 1, &[], FAILED),
    (Canary::AskedByFlags, 1, &["-Wall"], FAILED),
    (Canary::Pinned, 1, &[], FAILED),
];

/// `diag_silence` over its inputs, for a probe whose canary is not pinned and for one whose
/// canary is. The unpinned probe's build that succeeded silently with no flag asking for
/// `-Wunused-variable` (the measured build under `bare`, whose argv is the shape below) says
/// the warning was not asked for; the same build with `-Wall`, or with `-Wall` taken back by
/// `-w`, is the suppressed channel; a pinned probe's silent build is the suppressed channel
/// whatever its flags; and a failed build is the failure under both. No outcome differs
/// between the sentences.
#[test]
fn a_silent_build_that_never_asked_for_the_canary_says_so() {
    let argv = |flags: &[&str]| -> Vec<String> {
        ["gcc"]
            .iter()
            .chain(flags)
            .chain(&["-o", "hardened_downgrade", "hardened_downgrade.c"])
            .map(|s| (*s).to_owned())
            .collect()
    };
    let build = |exit_status: i32, flags: &[&str]| {
        let mut b = diag_build(exit_status, "");
        b.argv = argv(flags);
        b
    };
    // Every enabler, in each spelling that carries it, keeps the other sentence. The names are
    // written out here rather than read from the list, so a word dropped from the list fails
    // this loop instead of leaving it.
    for name in ["all", "unused", "unused-variable", "most", "everything"] {
        for word in [
            format!("-W{name}"),
            format!("-Werror={name}"),
            format!("--warn-{name}"),
        ] {
            let d = diag_silence(
                &build(0, &[word.as_str()]),
                String::new(),
                "diagnostic",
                Canary::AskedByFlags,
            );
            assert!(d.observed.contains(SUPPRESSED), "{word}: {}", d.observed);
        }
    }
    for (canary, exit_status, flags, says) in SILENCE_ROWS {
        let b = build(*exit_status, flags);
        let d = diag_silence(&b, "exit=0 stderr=\"\"".to_owned(), "diagnostic", *canary);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{canary:?} {flags:?}");
        for sentence in [NOT_ASKED, SUPPRESSED, FAILED] {
            assert_eq!(
                d.observed.contains(sentence),
                sentence == *says,
                "{canary:?} exit {exit_status} {flags:?}: {}",
                d.observed
            );
        }
    }

    // And through the detector, as the bare and bare-optimized cells read it.
    let macros = BTreeMap::new();
    for (flags, says) in [
        (&["-O2"][..], NOT_ASKED),
        (&["-O2", "-Wall"][..], SUPPRESSED),
    ] {
        let b = build(0, flags);
        let d = detect_hardened_warning(&Evidence {
            macros: &macros,
            elf: None,
            build: Some(&b),
            run: None,
            workdir: None,
        });
        assert_eq!(d.outcome, Outcome::Indeterminate, "{flags:?}");
        assert!(d.observed.contains(says), "{flags:?}: {}", d.observed);
    }
}

/// Ubuntu 26.04 gcc 15.2.0 defines `_FORTIFY_SOURCE` itself, so `-fhardened` downgrades it in
/// both arms of `hardened-downgrade-warned`. The negative arm's stderr is that downgrade and
/// the canary, and reads absent; the positive arm adds the downgrade its
/// `-fno-stack-protector` makes, and reads present. Both arms' stderr as measured, in gcc's
/// ASCII quotes (`LC_ALL=C`) and its UTF-8 ones.
#[test]
fn only_the_positive_arms_downgrade_is_the_observable() {
    let fortify = "cc1: warning: '_FORTIFY_SOURCE' is not enabled by '-fhardened' because it \
                   was specified in '-D' or '-U' [-Whardened]\n";
    let ssp = "cc1: warning: '-fstack-protector-strong' is not enabled by '-fhardened' because \
               it was specified on the command line [-Whardened]\n";
    let canary = concat!(
        "hardened_downgrade.c: In function 'main':\n",
        "hardened_downgrade.c:38:9: warning: unused variable 'chard_canary_unused' ",
        "[-Wunused-variable]\n",
        "   38 |     int chard_canary_unused = 0;\n",
        "      |         ^~~~~~~~~~~~~~~~~~~\n",
    );
    let negative = format!("{fortify}{canary}");
    let positive = format!("{ssp}{fortify}{canary}");
    let utf8 = |s: &str| {
        let mut out = String::new();
        let mut open = true;
        for c in s.chars() {
            if c == '\'' {
                out.push(if open { '\u{2018}' } else { '\u{2019}' });
                open = !open;
            } else {
                out.push(c);
            }
        }
        out
    };
    for (negative, positive) in [
        (negative.clone(), positive.clone()),
        (utf8(&negative), utf8(&positive)),
    ] {
        let read = |stderr: &str| {
            let build = diag_build(0, stderr);
            let macros = BTreeMap::new();
            let ev = Evidence {
                macros: &macros,
                elf: None,
                build: Some(&build),
                run: None,
                workdir: None,
            };
            detect_hardened_warning(&ev)
        };
        let n = read(&negative);
        assert_eq!(n.outcome, Outcome::Absent, "{negative}: {}", n.observed);
        assert!(
            n.observed
                .contains("another option's downgrade was reported and is not read")
                && n.observed.contains("_FORTIFY_SOURCE"),
            "{}",
            n.observed
        );
        let p = read(&positive);
        assert_eq!(p.outcome, Outcome::Present, "{positive}: {}", p.observed);
        assert_eq!(p.level.as_deref(), Some("warning"), "{}", p.observed);
        assert!(!p.observed.contains("is not read"), "{}", p.observed);

        // The as-configured arm of `--profile explicit` with `-fhardened` is the same read:
        // a build reporting only another option's downgrade is absent, and names it even
        // where the stream is long enough that the excerpt does not hold its line.
        let padding =
            "x.c:1:1: warning: unused parameter 'chard_pad' [-Wunused-parameter]\n".repeat(20);
        let long = format!("{}\n{padding}{canary}", negative.lines().next().unwrap());
        let l = read(&long);
        assert_eq!(l.outcome, Outcome::Absent, "{}", l.observed);
        assert!(l.observed.contains("chars omitted"), "{}", l.observed);
        assert!(
            l.observed.contains("is not read") && l.observed.contains("_FORTIFY_SOURCE"),
            "{}",
            l.observed
        );

        // A build that reported no downgrade at all names none.
        let quiet = read(canary);
        assert_eq!(quiet.outcome, Outcome::Absent, "{}", quiet.observed);
        assert!(
            !quiet.observed.contains("is not read"),
            "{}",
            quiet.observed
        );
    }
}
