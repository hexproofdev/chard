// SPDX-License-Identifier: BSD-3-Clause

//! The probes' own preconditions, exercised on the host compiler.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::string_slice,
    reason = "test code lays out fixture bytes, counts results and slices text at offsets it \
              found in the same string, from constants and the sizes of data in memory; the \
              test profile keeps overflow checks, and an overflow, or a slice off a character \
              boundary or past the end, panics and fails the test. Its casts widen a length or \
              a u32, take the offset between two addresses in one string, or name a function \
              pointer type or a closure's trait object. clippy has no test knob for these three \
              lints, and src/lib.rs's crate-root relief does not reach tests/"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chard::predicate::{self, Evaluation, Live, elf_static};
use chard::probe::{self, Outcome};
use chard::report;

/// Can this machine build and run a probe? See `tests/common`.
fn can_run(verifies: &str) -> bool {
    common::require_cc(verifies)
}

/// The value the probes' shared header gives an exit status, read from the header.
fn header_status(name: &str) -> i32 {
    let prefix = format!("#define {name} ");
    probe::SELFREPORT_HEADER
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("{name} is not defined in chard_selfreport.h"))
        .trim()
        .parse()
        .expect("a bare integer")
}

/// The probe with this id, written into `work` beside the header it includes, after
/// `rewrite` has had its say about the source.
fn write_probe(work: &common::Work, id: &str, rewrite: &dyn Fn(&str) -> String) -> PathBuf {
    let p = probe::find(id).unwrap_or_else(|| panic!("{id} is in the corpus"));
    work.write(probe::SELFREPORT_HEADER_NAME, probe::SELFREPORT_HEADER);
    work.write(p.source_name, &rewrite(p.source))
}

/// `source` with `from` replaced by `to`, and a failure if `from` is not there exactly
/// once: a mutation that matched nothing would test the intact probe twice.
fn rewritten(source: &str, from: &str, to: &str) -> String {
    assert_eq!(
        source.matches(from).count(),
        1,
        "the mutation {from:?} does not match the probe source exactly once"
    );
    source.replace(from, to)
}

/// Build one probe with the host `cc`, failing with the compiler's own words.
fn build(work: &common::Work, source: &Path, tag: &str, flags: &[&str]) -> PathBuf {
    let bin = work.path(tag);
    let out = Command::new("cc")
        .args(flags)
        .arg("-I")
        .arg(work.dir())
        .arg("-o")
        .arg(&bin)
        .arg(source)
        .output()
        .expect("spawning cc");
    assert!(
        out.status.success(),
        "cc could not build {tag} with {flags:?}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

fn run(bin: &Path) -> Output {
    Command::new(bin).output().expect("running the probe")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `rwx_segment` of a linked program on an ELF host.
fn rwx_segment_of(bin: &Path) -> Option<bool> {
    chard::elf::facts_for(bin)
        .unwrap_or_else(|why| {
            panic!(
                "{}: chard's reader refused the artifact: {why}",
                bin.display()
            )
        })
        .rwx_segment
}

#[test]
fn the_rwx_arm_input_survives_gc_sections_by_its_root() {
    if !can_run("that the RWX arm's input survives --gc-sections") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "the RWX arm's input under --gc-sections",
            "the host links artifacts that are not ELF, with a linker that takes neither \
             --gc-sections nor the input's section syntax",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "rwx-input");
    let check = probe::find("link-defaults")
        .and_then(|p| p.checks.iter().find(|c| c.id == "rwx-segment-absent"))
        .expect("rwx-segment-absent is a link-defaults check");
    let inputs = check.positive_inputs();
    assert_eq!(inputs.len(), 1, "the arm links one input of its own");
    let source = write_probe(&work, "link-defaults", &|s| s.to_owned());
    let input = work.write(inputs[0].source_name, inputs[0].source);
    let gc = [
        "-ffunction-sections",
        "-fdata-sections",
        "-Wl,--gc-sections",
    ];
    let link = |tag: &str, flags: &[&str], with_input: bool| {
        let bin = work.path(tag);
        let mut cc = Command::new("cc");
        cc.args(flags).arg("-o").arg(&bin).arg(&source);
        if with_input {
            cc.arg(&input);
        }
        let out = cc.current_dir(work.dir()).output().expect("spawning cc");
        assert!(
            out.status.success(),
            "cc could not build {tag} with {flags:?}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        bin
    };
    let arm: Vec<&str> = gc.iter().chain(check.positive).copied().collect();
    let rooted = rwx_segment_of(&link("rwx-arm-gc", &arm, true));
    assert_eq!(rooted, Some(true), "the arm as built holds an RWX segment");
    assert_eq!(
        rwx_segment_of(&link("rwx-arm-gc-unrooted", &gc, true)),
        Some(false),
        "without the root the collecting link drops the section, so the root is what keeps it"
    );
    assert_eq!(
        rwx_segment_of(&link("rwx-clean-gc", &gc, false)),
        Some(false),
        "the probe alone holds none"
    );
}

/// One reading of a `link-defaults` check: its id, verdict, level and gating rule, as JSON text.
type Reading = (String, String, String, String);

/// `chard measure --profile explicit --flags FLAGS` over the `link-defaults` probe with the host
/// `cc`, `extra` appended to the command line, read back as one [`Reading`] per check.
fn link_defaults_readings(
    work: &common::Work,
    tag: &str,
    flags: &str,
    extra: &[&str],
) -> Vec<Reading> {
    let report = work.path(&format!("{tag}.json"));
    let out = Command::new(common::chard_binary())
        .args([
            "measure",
            "--cc",
            "cc",
            "--profile",
            "explicit",
            "--flags",
            flags,
        ])
        .args(extra)
        .args(["--probe", "link-defaults", "--execution", "host"])
        .arg("--workdir")
        .arg(work.path(&format!("{tag}-work")))
        .arg("--output")
        .arg(&report)
        .output()
        .expect("spawning chard");
    assert!(
        report.exists(),
        "{tag}: chard published no report:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("reading the report"))
            .expect("the report is JSON");
    let field = |o: &serde_json::Value, at: &str| {
        o.pointer(at)
            .map_or_else(|| "-".to_owned(), ToString::to_string)
    };
    value["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .map(|o| {
            (
                field(o, "/check"),
                field(o, "/verdict"),
                field(o, "/level"),
                field(o, "/gating/rule"),
            )
        })
        .collect()
}

#[test]
fn rwx_segment_absent_input_reaches_its_positive_arm_alone() {
    if !can_run("that rwx-segment-absent's input reaches its positive arm alone")
        || !common::require_binary(&common::chard_binary(), "the link-defaults measurement")
    {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "rwx-segment-absent's input handed to its positive arm alone",
            "the host's artifacts are not ELF, so link-defaults' segment checks read nothing",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "rwx-handed");
    let header = work.write("plain_selection.h", "typedef int chard_plain_selection;\n");
    let input = probe::find("link-defaults")
        .and_then(|p| p.checks.iter().find(|c| c.id == "rwx-segment-absent"))
        .map(|c| c.positive_inputs()[0].source_name)
        .expect("rwx-segment-absent's input");
    let selection = format!("-O2 -include {}", header.display());
    for (tag, flags) in [("plain", "-O2"), ("selection", selection.as_str())] {
        link_defaults_readings(&work, tag, flags, &[]);
        let report: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.path(&format!("{tag}.json"))).expect("reading the report"),
        )
        .expect("the report is JSON");
        let observations = report["observations"].as_array().expect("observations");
        let mut handed = Vec::new();
        for o in observations {
            for (arm, at) in [
                ("measured", "/build/argv"),
                ("positive", "/controls/positive/build/argv"),
                ("negative", "/controls/negative/build/argv"),
            ] {
                let names = o
                    .pointer(at)
                    .and_then(|a| a.as_array())
                    .is_some_and(|argv| argv.iter().any(|w| w.as_str() == Some(input)));
                if names {
                    handed.push(format!("{} {arm}", o["check"].as_str().unwrap_or("?")));
                }
            }
        }
        assert_eq!(
            handed,
            ["rwx-segment-absent positive"],
            "{tag}: the builds handed {input}"
        );
        // Under the selection the negative is the check's own build, so the scan above read it.
        if tag == "selection" {
            let negative = observations
                .iter()
                .find(|o| o["check"] == "rwx-segment-absent")
                .and_then(|o| o.pointer("/controls/negative/build/argv"))
                .and_then(|a| a.as_array())
                .expect("rwx-segment-absent's negative argv");
            assert!(
                negative
                    .iter()
                    .any(|w| w.as_str() == Some("link-defaults-rwx-segment-absent-neg")),
                "the negative is not a build of its own under a header selection: {negative:?}"
            );
        }
    }
}

#[test]
fn a_chard_name_no_source_tests_moves_no_link_defaults_reading() {
    if !can_run("that a CHARD_ name no source tests moves no link-defaults reading")
        || !common::require_binary(&common::chard_binary(), "the link-defaults measurement")
    {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "a CHARD_ name no source tests, and a profile's own RWX section",
            "the host's artifacts are not ELF, so link-defaults' segment checks read nothing",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "rwx-define");
    let own_source = work.write(
        "own_rwx.c",
        "__asm__(\".section .own.rwx,\\\"awx\\\"\\n\\t.byte 0\\n\\t.previous\");\n",
    );
    let own = work.path("own_rwx.o");
    let compiled = Command::new("cc")
        .arg("-c")
        .arg("-o")
        .arg(&own)
        .arg(&own_source)
        .output()
        .expect("spawning cc");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let measure = |tag: &str, flags: &str, ldflags: &[&str]| {
        link_defaults_readings(&work, tag, flags, ldflags)
    };
    let plain = measure("plain", "-O2", &[]);
    let defined = measure("defined", "-O2 -DCHARD_RWX_SEGMENT", &[]);
    assert!(!plain.is_empty(), "the plain run read no check");
    assert_eq!(
        defined, plain,
        "a define no probe source tests moved a link-defaults reading"
    );
    let rwx = |readings: &[Reading]| {
        readings
            .iter()
            .find(|r| r.0 == "\"rwx-segment-absent\"")
            .map(|r| r.1.clone())
            .expect("rwx-segment-absent is read")
    };
    let measured = rwx(&plain);
    assert_eq!(
        measured, "\"off\"",
        "the plain -O2 link lays out no RWX segment"
    );
    let own = own.display().to_string();
    let linked = measure("own-section", "-O2", &["--ldflags", &own]);
    assert_eq!(
        rwx(&linked),
        "\"on\"",
        "a profile whose own link input declares an RWX section reads on"
    );
    // The positive arm's input stays in the work directory, as every source chard writes
    // there does.
    let named = probe::find("link-defaults")
        .and_then(|p| p.checks.iter().find(|c| c.id == "rwx-segment-absent"))
        .map(|c| c.positive_inputs()[0].source_name)
        .expect("rwx-segment-absent's input");
    let left = work.path("plain-work").join(named);
    assert!(left.is_file(), "the plain run left {}", left.display());
    refused_as_a_relative_input(&work, "plain", named);
    let absolute = left.display().to_string();
    let reused = measure("absolute", "-O2", &["--ldflags", &absolute]);
    assert_eq!(
        rwx(&reused),
        "\"on\"",
        "a profile naming the arm's input by its absolute path links it, and reads on"
    );
}

/// `link-defaults` measured with `input` in `--ldflags`, into the work directory and report
/// `tag`'s run used ([`link_defaults_readings`]), is refused as configuration, naming the
/// word and its list, and leaves the earlier report as it was.
fn refused_as_a_relative_input(work: &common::Work, tag: &str, input: &str) {
    let before = std::fs::read(work.path(&format!("{tag}.json"))).expect("the earlier report");
    let refused = Command::new(common::chard_binary())
        .args([
            "measure",
            "--cc",
            "cc",
            "--profile",
            "explicit",
            "--flags",
            "-O2",
        ])
        .args([
            "--ldflags",
            input,
            "--probe",
            "link-defaults",
            "--execution",
            "host",
        ])
        .arg("--workdir")
        .arg(work.path(&format!("{tag}-work")))
        .arg("--output")
        .arg(work.path(&format!("{tag}.json")))
        .output()
        .expect("spawning chard");
    let envelope: serde_json::Value =
        serde_json::from_slice(&refused.stdout).expect("the refusal's envelope is JSON");
    let message = envelope["error"]["message"].as_str().unwrap_or_default();
    assert!(
        refused.status.code() == Some(2)
            && envelope["error"]["code"] == "CONFIGURATION"
            && message.contains(&format!("{input:?} in --ldflags, an input file")),
        "a relative input is refused: {envelope}"
    );
    assert_eq!(
        std::fs::read(work.path(&format!("{tag}.json"))).expect("the earlier report"),
        before,
        "the refusal left the earlier report as it was"
    );
}

#[test]
fn the_rwx_decoder_withholds_an_unstated_segment_answer() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/elf/elf64-le-x86_64-exec-dt-bind-now.elf");
    let mut facts = chard::elf::facts_for(&path).expect("the fixture reads");
    let mut read = |answer: Option<bool>| {
        facts.rwx_segment = answer;
        let view = Live {
            macros: None,
            elf: Some(&facts),
        };
        predicate::evaluate(elf_static::rwx_segment(), &view)
            .expect("a live view is complete")
            .outcome
    };
    assert_eq!(read(None), Outcome::Indeterminate);
    assert_eq!(read(Some(false)), Outcome::Absent);
    assert_eq!(read(Some(true)), Outcome::Present);
}

#[test]
fn the_overflow_probe_reports_gccs_major_version_as_the_compiler_defines_it() {
    if !can_run("the overflow probe's gcc-major line") {
        return;
    }
    let work = common::Work::new("probe-sources", "gcc-major");
    let source = write_probe(&work, "ub-signed-overflow", &|s| s.to_owned());
    let bin = build(&work, &source, "overflow-o0", &["-O0"]);
    let out = run(&bin);
    assert!(out.status.success(), "the probe exited {}", out.status);
    let stdout = text(&out.stdout);
    let versions: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("gcc-major="))
        .collect();
    let empty = work.write("empty.c", "");
    let dump = Command::new("cc")
        .args(["-dM", "-E", "-x", "c"])
        .arg(&empty)
        .output()
        .expect("spawning cc -dM -E");
    let defines = text(&dump.stdout);
    let define = |name: &str| {
        defines
            .lines()
            .find_map(|l| l.strip_prefix(&format!("#define {name} ")))
            .map(str::trim)
    };
    if stdout.lines().any(|l| l == "frontend=gcc") {
        let gnuc = define("__GNUC__").expect("a gcc front end defines __GNUC__");
        assert_eq!(versions, [gnuc], "stdout:\n{stdout}");
    } else {
        assert!(
            define("__clang__").is_some() && versions.is_empty(),
            "a front end that is not gcc printed {versions:?}, or is not clang:\n{stdout}"
        );
    }
}

#[test]
fn the_heap_probe_keeps_its_size_opaque_and_exits_distinctly_when_it_cannot() {
    if !can_run("that the level-3 probe's discrimination rests on a checked precondition") {
        return;
    }
    let work = common::Work::new("probe-sources", "heap-opacity");
    let level_two = ["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"];

    let intact = write_probe(&work, "fortify-dynamic-object", &|s| s.to_owned());
    let out = run(&build(&work, &intact, "intact", &level_two));
    assert_eq!(
        out.status.code(),
        Some(0),
        "the intact probe at level 2 did not survive. stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stdout).contains("no-check-fired"),
        "a survivor says so: {}",
        text(&out.stdout)
    );

    let opacity_lost = header_status("CHARD_EXIT_OPACITY_LOST");
    let mutated = write_probe(&work, "fortify-dynamic-object", &|s| {
        rewritten(
            s,
            "static volatile size_t want = 16;",
            "static size_t want = 16;",
        )
    });
    let out = run(&build(&work, &mutated, "no-volatile", &level_two));
    assert_eq!(
        out.status.code(),
        Some(opacity_lost),
        "without the volatile the probe did not refuse to measure. stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("opacity lost"),
        "the refusal names its cause: {}",
        text(&out.stderr)
    );
}

#[test]
fn the_known_object_probe_overflows_into_a_guard_it_declares_or_says_it_cannot() {
    if !can_run("that the known-object probe's overflow lands in memory the probe declares") {
        return;
    }
    let work = common::Work::new("probe-sources", "known-guard");
    let fortify_off = ["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"];

    let intact = write_probe(&work, "fortify-known-object", &|s| s.to_owned());
    for level in ["-O0", "-O2"] {
        let mut flags = vec![level];
        flags.extend(fortify_off);
        let out = run(&build(&work, &intact, &format!("intact{level}"), &flags));
        assert_eq!(
            out.status.code(),
            Some(0),
            "at {level} a guard must follow dst on this compiler. stdout: {}\nstderr: {}",
            text(&out.stdout),
            text(&out.stderr)
        );
        assert!(
            text(&out.stdout).contains("no-check-fired"),
            "the copy was reached and nothing caught it: {}",
            text(&out.stdout)
        );
    }

    let layout = header_status("CHARD_EXIT_LAYOUT");
    let spread = write_probe(&work, "fortify-known-object", &|s| {
        let mut s = s.to_owned();
        for object in ["guard_lo", "dst", "guard_hi"] {
            s = rewritten(
                &s,
                &format!("static char {object}[16];"),
                &format!("static char {object}[16] __attribute__((aligned(256)));"),
            );
        }
        s
    });
    let mut flags = vec!["-O2"];
    flags.extend(fortify_off);
    let spread_bin = build(&work, &spread, "spread", &flags);
    let out = run(&spread_bin);
    assert_eq!(
        out.status.code(),
        Some(layout),
        "with every object 256-byte aligned the probe did not decline. stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("layout precondition failed"),
        "the refusal names its cause: {}",
        text(&out.stderr)
    );

    // The refusal becomes the withheld cell's `observed`, so it is stated in offsets
    // from `dst`, which the linker fixed, rather than in addresses, which the loader
    // randomises: the same binary says the same thing twice, and names no address.
    let again = run(&spread_bin);
    assert_eq!(
        text(&out.stderr),
        text(&again.stderr),
        "two runs of one binary must refuse in the same words"
    );
    let refusal = text(&out.stderr);
    assert!(
        refusal.contains("dst+") || refusal.contains("dst-"),
        "the refusal locates each guard as an offset from dst: {refusal}"
    );
    assert!(
        !refusal.contains("0x"),
        "an address in the refusal would differ run to run under ASLR: {refusal}"
    );
}

#[test]
fn the_heap_probe_declines_a_chunk_geometry_its_margin_was_not_computed_from() {
    if !can_run("that the heap probe's margin rests on an asserted chunk geometry") {
        return;
    }
    if !cfg!(all(target_os = "linux", target_env = "gnu")) {
        common::capability_gap(
            "heap geometry assertion",
            "the host C library is not glibc, so the probe makes no claim about its chunk \
             layout and compiles the assertion out",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "heap-geometry");
    let geometry = header_status("CHARD_EXIT_HEAP_GEOMETRY");
    let fortify_off = ["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"];

    let intact = write_probe(&work, "fortify-dynamic-object", &|s| s.to_owned());
    let out = run(&build(&work, &intact, "intact", &fortify_off));
    assert_eq!(
        out.status.code(),
        Some(0),
        "the intact probe did not find its chunk geometry and survive. stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stdout).contains("no-check-fired"),
        "with fortify off the copy completes: {}",
        text(&out.stdout)
    );
    let wide = write_probe(&work, "fortify-dynamic-object", &|s| {
        rewritten(
            s,
            "static volatile size_t want = 16;",
            "static volatile size_t want = 100;",
        )
    });
    let out = run(&build(&work, &wide, "wide", &fortify_off));
    assert_eq!(
        out.status.code(),
        Some(geometry),
        "a 100-byte request is not the 32-byte chunk the margin assumes. stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("heap geometry"),
        "the refusal names its cause: {}",
        text(&out.stderr)
    );
    // The expectation the refusal states is the one for this target's size_t, which is
    // the width of the `usize` this test was built for: the probe and the test are both
    // native to the host.
    let expected = format!("expected {}", 32 - size_of::<usize>());
    assert!(
        text(&out.stderr).contains(&expected),
        "the refusal states the usable size 32 - sizeof(size_t), {expected:?}: {}",
        text(&out.stderr)
    );

    // The neighbour's position is the other half of the premise.
    let displaced = write_probe(&work, "fortify-dynamic-object", &|s| {
        rewritten(
            s,
            "    char *src = malloc(64);\n",
            "    char *volatile spacer = malloc(64);\n    (void) spacer;\n    char *src = malloc(64);\n",
        )
    });
    let out = run(&build(&work, &displaced, "displaced", &fortify_off));
    assert_eq!(
        out.status.code(),
        Some(geometry),
        "with a chunk between them src is no longer at dst+32. stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("src is at dst+"),
        "the refusal names the offset it found: {}",
        text(&out.stderr)
    );
}

#[test]
fn the_self_report_header_refuses_to_be_included_before_a_libc_header() {
    if !can_run("that the self-report header's include order is enforced at preprocess time") {
        return;
    }
    if !cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )) {
        common::capability_gap(
            "include-order enforcement",
            "chard_selfreport.h names no libc guard macro for this host, so the order is \
             not checked here",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "include-order");
    work.write(probe::SELFREPORT_HEADER_NAME, probe::SELFREPORT_HEADER);
    let syntax_only = |source: &Path| {
        Command::new("cc")
            .arg("-fsyntax-only")
            .arg("-I")
            .arg(work.dir())
            .arg(source)
            .output()
            .expect("spawning cc")
    };

    let wrong = work.write(
        "wrong_order.c",
        "#include \"chard_selfreport.h\"\n\
         #include <stdio.h>\n\
         CHARD_EMIT_REPORT;\n\
         int main(void) { puts(chard_report); return 0; }\n",
    );
    let out = syntax_only(&wrong);
    assert!(
        !out.status.success(),
        "the header included first must not preprocess: {}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("chard_selfreport.h must be included after a libc header"),
        "the failure names the precondition: {}",
        text(&out.stderr)
    );

    let right = work.write(
        "right_order.c",
        "#include <stdio.h>\n\
         #include \"chard_selfreport.h\"\n\
         CHARD_EMIT_REPORT;\n\
         int main(void) { puts(chard_report); return 0; }\n",
    );
    let out = syntax_only(&right);
    assert!(
        out.status.success(),
        "the header after a libc header is the shape every probe uses: {}",
        text(&out.stderr)
    );
}

#[test]
fn every_probe_includes_a_libc_header_before_the_self_report_header() {
    // A probe with no system header at all fails its clean build on OpenBSD 7.9, FreeBSD
    // 15.1 and Fedora 44 (2026-09-30, `ret_protector.c` without one), publishing
    // `build-failed` for its checks in every profile, and a development host that compiles
    // no such test does not see it.
    let mut fed = 0usize;
    for p in probe::CORPUS {
        let lines: Vec<&str> = p.source.lines().map(str::trim_start).collect();
        let Some(own) = lines
            .iter()
            .position(|l| l.starts_with("#include \"chard_selfreport.h\""))
        else {
            continue;
        };
        fed += 1;
        assert!(
            lines[..own].iter().any(|l| l.starts_with("#include <")),
            "{}: {} includes chard_selfreport.h before any system header",
            p.id,
            p.source_name
        );
    }
    assert!(fed > 0, "no probe includes chard_selfreport.h");
}

#[test]
fn the_canary_probe_keeps_its_observable_when_the_array_threshold_is_raised() {
    if !can_run("that raising --param ssp-buffer-size alone does not remove the canary") {
        return;
    }
    let work = common::Work::new("probe-sources", "canary-threshold");
    let source = write_probe(&work, "stack-canary", &|s| s.to_owned());
    let raised = ["-O2", "-fstack-protector", "--param", "ssp-buffer-size=128"];
    let off = ["-O2", "-fno-stack-protector"];

    let assembly = |tag: &str, flags: &[&str]| -> String {
        let asm = work.path(&format!("{tag}.s"));
        let out = Command::new("cc")
            .args(flags)
            .arg("-S")
            .arg("-I")
            .arg(work.dir())
            .arg("-o")
            .arg(&asm)
            .arg(&source)
            .output()
            .expect("spawning cc");
        assert!(
            out.status.success(),
            "cc could not compile {tag} to assembly with {flags:?}:\n{}",
            text(&out.stderr)
        );
        std::fs::read_to_string(&asm).expect("reading the assembly")
    };
    assert!(
        assembly("raised", &raised).contains("stack_chk_fail"),
        "-fstack-protector with ssp-buffer-size=128 left no stack_chk_fail in the assembly"
    );
    assert!(
        !assembly("off", &off).contains("stack_chk_fail"),
        "with the protector off no function references the failure handler"
    );

    if !common::ELF_HOST {
        common::capability_gap(
            "canary reference read from the linked artifact",
            "the host cc emits Mach-O and chard reads only ELF",
        );
        return;
    }
    let facts = |tag: &str, flags: &[&str]| {
        let bin = build(&work, &source, tag, flags);
        chard::elf::facts_for(&bin).expect("the linked probe is ELF this reader accepts")
    };
    let referenced = |facts: &chard::elf::ElfFacts| {
        facts.watched_symbols.contains_key("__stack_chk_fail")
            || facts.watched_symbols.contains_key("__stack_chk_fail_local")
    };
    assert!(
        referenced(&facts("raised-linked", &raised)),
        "the linked artifact at the raised threshold carries the reference the check reads"
    );
    assert!(
        !referenced(&facts("off-linked", &off)),
        "with the protector off the linked artifact carries none"
    );
}

#[test]
fn the_stack_clash_probe_declines_an_allocation_that_wraps_below_the_frame() {
    if !can_run("that the stack-clash probe declines an allocation wrapping below the frame") {
        return;
    }
    if !cfg!(target_pointer_width = "64") {
        common::capability_gap(
            "stack-clash address wrap under a 2^57-byte stack limit",
            "the host is not 64-bit, so the limit does not fit its rlim_t",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "stack-clash-wrap");
    let source = write_probe(&work, "stack-clash", &|s| s.to_owned());
    let bin = build(
        &work,
        &source,
        "off",
        &["-O2", "-fno-stack-clash-protection"],
    );
    // 2^57 bytes, in the KiB `ulimit -s` takes.
    let kib = (1u64 << 57) / 1024;
    let out = Command::new("sh")
        .arg("-c")
        .arg("ulimit -s \"$1\" 2>/dev/null || exit 99; exec \"$2\"")
        .arg("sh")
        .arg(kib.to_string())
        .arg(&bin)
        .output()
        .expect("running the probe under a raised stack limit");
    if out.status.code() == Some(99) {
        common::capability_gap(
            "stack-clash address wrap under a 2^57-byte stack limit",
            "the hard RLIMIT_STACK does not allow raising the soft limit that far",
        );
        return;
    }
    let declined = header_status("CHARD_EXIT_DECLINED");
    assert_eq!(
        (out.status.code(), text(&out.stdout).trim()),
        (Some(declined), "SCPRT probe-invalid=address-wrap"),
        "an allocation larger than the frame's address was not declined by name. stderr: {}",
        text(&out.stderr)
    );
}

/// Every `-fsanitize=` group gcc 16.1.1 or clang 22.1.8 accepts beside a
/// `-fsanitize-trap=` of the same name for C, aggregates included: the leaves of
/// `-fsanitize=undefined`, the groups outside it, and clang's `integer`,
/// `implicit-conversion` and `nullability`. A driver that rejects a name is counted, not
/// failed; the floor below fails a list the drivers do not spell. Enumerated 2026-10-07
/// on Fedora 44 x86_64 by trying each name either driver documents.
const TRAP_GROUPS: &[&str] = &[
    "alignment",
    "array-bounds",
    "bool",
    "bounds",
    "bounds-strict",
    "builtin",
    "enum",
    "float-cast-overflow",
    "float-divide-by-zero",
    "function",
    "implicit-bitfield-conversion",
    "implicit-conversion",
    "implicit-integer-arithmetic-value-change",
    "implicit-integer-sign-change",
    "implicit-integer-truncation",
    "implicit-signed-integer-truncation",
    "implicit-unsigned-integer-truncation",
    "integer",
    "integer-divide-by-zero",
    "local-bounds",
    "nonnull-attribute",
    "null",
    "nullability",
    "nullability-arg",
    "nullability-assign",
    "nullability-return",
    "object-size",
    "pointer-overflow",
    "return",
    "returns-nonnull-attribute",
    "shift",
    "shift-base",
    "shift-exponent",
    "signed-integer-overflow",
    "undefined",
    "unreachable",
    "unsigned-integer-overflow",
    "unsigned-shift-base",
    "vla-bound",
];

/// The trap configurations whose `off` is earned without a construct, by compiler family,
/// group and optimization level, each with why. Every row must still read `off` where its
/// family is measured; a row that reads anything else is stale and fails, so the list
/// cannot outlive its reason.
const OFF_WITHOUT_A_CONSTRUCT: &[(&str, &str, &str, &str)] = &[(
    "clang",
    "object-size",
    "-O0",
    "clang 22.1.8 drops object-size at -O0 (it warns that the sanitizer has no \
     effect), so no check exists to trap and no sanitizer is reported enabled",
)];

/// The clause a [`ModeCase`] must read under, by class where the name is the machine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Under {
    /// A trap clause of the predicate for the machine the object was built for, pinned to
    /// this clause where the machine's set has it.
    Trap(&'static str),
    /// The clause with this id: a withholding clause, or `otherwise`.
    Named(&'static str),
}

/// One build of [`a_group_left_in_handler_mode_beside_trapped_groups_is_withheld`]: the
/// compiler family it is for, the flags, the outcome and clause it must read, and the
/// release that reading begins at, where it has one.
type ModeCase = (
    &'static str,
    &'static [&'static str],
    Outcome,
    Under,
    Option<Floor>,
);

/// The clang release a row's expected reading begins at, and the reading the row is held
/// to under an older clang. Named the way `tests/inert_flags.rs` names a row's floor, but
/// below it the row is not skipped: it is held to what that clang's object is, and its own
/// reading is announced as an arm not exercised there, naming the version seen.
#[derive(Debug, Clone, Copy)]
struct Floor {
    /// The first clang major version the row's own reading holds for.
    clang: u32,
    /// The outcome and clause below it.
    below: (Outcome, Under),
    /// Why the object differs below it, as measured.
    because: &'static str,
}

/// The floor of every `local-bounds` row. clang 20 is the first whose
/// `-fno-sanitize-trap=local-bounds` chooses the handler and whose trap for the group is
/// `UBSan`'s own (`ud1` on x86_64). Under Ubuntu 24.04's clang 18.1.3 and 19.1.1 (x86_64,
/// 2026-10-13 and 2026-10-14) all six rows read `Present` under `ud2`, and that is true of
/// the object. Measured under clang 18.1.3 in the two forms the rows build, no
/// `-fsanitize-trap` word for the group and `-fno-sanitize-trap=local-bounds`: the IR
/// calls `llvm.trap` in both, `objdump -d` finds one `ud2` in `chard_ubsan_trap_sized`,
/// and `readelf -r` no relocation against a `__ubsan_handle_local_out_of_bounds` spelling;
/// clang 22.1.8 (Fedora 44 x86_64, 2026-10-14) builds the negated rows with that handler
/// and no trap. clang 20.1.2 (Ubuntu 24.04 x86_64, 2026-10-13) reads every row as written.
const LOCAL_BOUNDS_FLOOR: Floor = Floor {
    clang: 20,
    below: (Outcome::Present, Under::Trap("ud2")),
    because: "local-bounds compiles to llvm.trap both with no -fsanitize-trap word for the \
              group and with -fno-sanitize-trap=local-bounds (the two forms measured), so \
              those builds trap and none calls the handler",
};

/// The cases of [`a_group_left_in_handler_mode_beside_trapped_groups_is_withheld`].
const MODE_CASES: &[ModeCase] = &[
    // The shapes the 2026-10-07 triage found, (3) and (4): a group with a construct
    // only in the third or fourth function, left in handler mode.
    (
        "clang",
        &[
            "-O2",
            "-fsanitize=undefined",
            "-fsanitize-trap=undefined",
            "-fno-sanitize-trap=function",
        ],
        Outcome::Indeterminate,
        Under::Named("trap-beside-handler"),
        None,
    ),
    (
        "gcc",
        &[
            "-O0",
            "-fsanitize=undefined",
            "-fsanitize-trap=undefined",
            "-fno-sanitize-trap=object-size",
        ],
        Outcome::Indeterminate,
        Under::Named("trap-beside-handler"),
        None,
    ),
    (
        "gcc",
        &[
            "-O2",
            "-fsanitize=undefined",
            "-fsanitize-trap=undefined",
            "-fno-sanitize-trap=object-size",
        ],
        Outcome::Indeterminate,
        Under::Named("trap-beside-handler"),
        None,
    ),
    // Shape (1): local-bounds traps by default, and the flag chooses handler mode.
    (
        "clang",
        &["-O2", "-fsanitize=local-bounds"],
        Outcome::Present,
        Under::Trap("ud1"),
        Some(LOCAL_BOUNDS_FLOOR),
    ),
    (
        "clang",
        &[
            "-O2",
            "-fsanitize=local-bounds",
            "-fno-sanitize-trap=local-bounds",
        ],
        Outcome::Absent,
        Under::Named(predicate::OTHERWISE),
        Some(LOCAL_BOUNDS_FLOOR),
    ),
    // local-bounds in handler mode beside a trapped group that checks arrays too
    // (2026-10-07).
    (
        "clang",
        &[
            "-O2",
            "-fsanitize=bounds,local-bounds",
            "-fsanitize-trap=bounds",
            "-fno-sanitize-trap=local-bounds",
        ],
        Outcome::Indeterminate,
        Under::Named("trap-beside-handler"),
        Some(LOCAL_BOUNDS_FLOOR),
    ),
    (
        "clang",
        &[
            "-O0",
            "-fsanitize=bounds,local-bounds",
            "-fsanitize-trap=bounds",
            "-fno-sanitize-trap=local-bounds",
        ],
        Outcome::Indeterminate,
        Under::Named("trap-beside-handler"),
        Some(LOCAL_BOUNDS_FLOOR),
    ),
    (
        "clang",
        &[
            "-O2",
            "-fsanitize=undefined,local-bounds",
            "-fsanitize-trap=undefined",
            "-fno-sanitize-trap=local-bounds",
        ],
        Outcome::Indeterminate,
        Under::Named("trap-beside-handler"),
        Some(LOCAL_BOUNDS_FLOOR),
    ),
    // The contrast: without the negation, -fsanitize-trap=undefined leaves local-bounds'
    // default trap in place (`clang -###` lists it in cc1's -fsanitize-trap=), so every
    // group named traps and the build reads `on`.
    (
        "clang",
        &[
            "-O2",
            "-fsanitize=undefined,local-bounds",
            "-fsanitize-trap=undefined",
        ],
        Outcome::Present,
        Under::Trap("ud1"),
        Some(LOCAL_BOUNDS_FLOOR),
    ),
    // clang's bounds alone, no trap flag: array-bounds calls its handler while
    // local-bounds, which bounds includes, traps by default; a mixed build.
    (
        "clang",
        &["-O2", "-fsanitize=bounds"],
        Outcome::Indeterminate,
        Under::Named("trap-beside-handler"),
        None,
    ),
    // Each new group alone, trap and handler mode.
    (
        "clang",
        &["-O2", "-fsanitize=function", "-fsanitize-trap=function"],
        Outcome::Present,
        Under::Trap("ud1"),
        None,
    ),
    (
        "clang",
        &["-O2", "-fsanitize=function"],
        Outcome::Absent,
        Under::Named(predicate::OTHERWISE),
        None,
    ),
    (
        "gcc",
        &[
            "-O2",
            "-fsanitize=object-size",
            "-fsanitize-trap=object-size",
        ],
        Outcome::Present,
        Under::Trap("ud2"),
        None,
    ),
    (
        "gcc",
        &["-O2", "-fsanitize=object-size"],
        Outcome::Absent,
        Under::Named(predicate::OTHERWISE),
        None,
    ),
    // clang's kcfi puts a ud2 in the function that calls through a pointer, and no
    // undefined-behavior sanitizer is enabled: not trap mode.
    (
        "clang",
        &["-O2", "-fsanitize=kcfi"],
        Outcome::Absent,
        Under::Named(predicate::OTHERWISE),
        None,
    ),
];

#[test]
fn a_group_left_in_handler_mode_beside_trapped_groups_is_withheld() {
    if !can_run("that a group in handler mode beside trapped groups is withheld") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "ubsan trap groups read from the probe's object",
            "the host cc emits Mach-O and chard reads only ELF",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "ubsan-trap-modes");
    let source = write_probe(&work, "ubsan-trap", &|s| s.to_owned());
    let drivers = sanitizer_drivers();
    let mut fed = 0usize;
    let mut refused = Vec::new();
    let mut wrong = Vec::new();
    let mut below = Vec::new();
    // The trap clauses the objects built here can read under, computed per object and
    // collected by machine as every distinct set read there, printed with the tally so the
    // frame a `Under::Trap` row was held to is on record.
    let mut trap_clauses: BTreeMap<String, BTreeSet<BTreeSet<String>>> = BTreeMap::new();
    for (driver, family) in &drivers {
        for (i, (for_family, flags, ..)) in MODE_CASES.iter().enumerate() {
            if family != for_family {
                continue;
            }
            fed += 1;
            let Some((outcome, read)) = held_to(driver, &MODE_CASES[i], &mut below, &mut wrong)
            else {
                continue;
            };
            let (outcome, read) = (&outcome, &read);
            let tag = format!("{driver}-mode-{i}");
            let Some((e, facts)) =
                ubsan_trap_reading_with_facts(&work, driver, &source, &tag, flags)
            else {
                refused.push(format!("{driver} {flags:?}"));
                continue;
            };
            let traps = trap_clauses_for(&facts);
            trap_clauses
                .entry(facts.machine.clone())
                .or_default()
                .insert(traps.clone());
            let (under, expected) = match read {
                Under::Trap(word) => {
                    assert!(
                        !traps.is_empty(),
                        "{driver} ({family}) {flags:?}: no trap clause searched on this {} object",
                        facts.machine
                    );
                    if traps.contains(*word) {
                        (
                            e.clause == *word,
                            format!("{word} (the {} trap clause of {})", family, facts.machine),
                        )
                    } else {
                        (
                            traps.contains(&e.clause),
                            format!(
                                "one of {traps:?} (the trap clauses for {}, which has no {word})",
                                facts.machine
                            ),
                        )
                    }
                }
                Under::Named(clause) => (e.clause == *clause, (*clause).to_owned()),
            };
            if e.outcome != *outcome || !under {
                wrong.push(format!(
                    "{driver} ({family}) {flags:?}: read {:?} under {}, expected {outcome:?} \
                     under {expected}",
                    e.outcome, e.clause
                ));
            }
        }
    }
    let expected: usize = drivers
        .iter()
        .map(|(_, family)| MODE_CASES.iter().filter(|(f, ..)| f == family).count())
        .sum();
    eprintln!(
        "chard: ubsan trap modes: {fed} builds fed over {} drivers, {} refused, {} held to \
         the reading below their floor; trap clauses by machine {trap_clauses:?}",
        drivers.len(),
        refused.len(),
        below.len()
    );
    assert_eq!(fed, expected, "every case of each driver's family was fed");
    for r in &refused {
        common::capability_gap(
            &format!("ubsan trap mode case {r}"),
            "the driver refused the flags",
        );
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The outcome and clause the row `case` is held to under `driver`: its own where it has no floor or
/// the driver is at or above it, and the floor's below it, with the line the tally prints
/// for it announced as a gap and pushed to `below`. `None`, with the reason pushed to `wrong`, where the row has a
/// floor and the driver names no clang version, since a row neither reading can be chosen
/// for is a failure, not a pass; and where the driver is below the floor while
/// `CHARD_TEST_EXPECT_CC` names clang (`make compiler-arms`), since that gate is the one
/// that runs the rows' own reading.
fn held_to(
    driver: &str,
    case: &ModeCase,
    below: &mut Vec<String>,
    wrong: &mut Vec<String>,
) -> Option<(Outcome, Under)> {
    let (_, flags, outcome, read, floor) = case;
    let own = (*outcome, *read);
    let Some(floor) = floor else {
        return Some(own);
    };
    match clang_major(driver) {
        Some(major) if major >= floor.clang => Some(own),
        // Under `make compiler-arms` the gate names the compiler whose rows must run as
        // written, so a clang below the floor fails it rather than holding the row to the
        // older object: a gate that passed there would be a gate that ran nothing new.
        Some(major) if common::expected_compiler().as_deref() == Some("clang") => {
            wrong.push(format!(
                "{driver} (clang {major}) {flags:?}: CHARD_TEST_EXPECT_CC names clang and this \
                 row reads as written only from clang {}; put a newer clang first on PATH",
                floor.clang
            ));
            None
        }
        Some(major) => {
            let line = format!(
                "{driver} (clang {major}) {flags:?}: held to {:?} under {:?}, below the clang \
                 {} floor of its own reading ({:?} under {:?}): {}",
                floor.below.0, floor.below.1, floor.clang, own.0, own.1, floor.because
            );
            // Below its floor the row is held to the older object, so its own reading is an
            // arm this toolchain does not exercise: announced and written to the ledger
            // `make test` prints, never only to the captured output of a passing test.
            common::capability_gap(
                "a local-bounds ubsan trap mode row at its own reading",
                &line,
            );
            below.push(line);
            Some(floor.below)
        }
        None => {
            wrong.push(format!(
                "{driver} {flags:?}: the row has a clang {} floor, and no clang version could \
                 be read from `{driver} --version`",
                floor.clang
            ));
            None
        }
    }
}

/// The major version `driver --version` names after `clang version`, or `None` where it
/// names none (gcc, or a banner this does not read).
fn clang_major(driver: &str) -> Option<u32> {
    let out = Command::new(driver).arg("--version").output().ok()?;
    let banner = text(&out.stdout);
    let (_, rest) = banner.split_once("clang version ")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The drivers to build with: `cc`, and `gcc` and `clang` where they run, one per
/// distinct `--version` banner, each with its family. The banner's first word is the name
/// the driver was run by (gcc prints `cc (GCC) 16.1.1` as `cc`), so it is left out of the
/// comparison.
fn sanitizer_drivers() -> Vec<(&'static str, &'static str)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for driver in ["cc", "gcc", "clang"] {
        let Ok(version) = Command::new(driver).arg("--version").output() else {
            common::capability_gap(
                &format!("ubsan trap groups under {driver}"),
                "no such driver on PATH",
            );
            continue;
        };
        let banner = text(&version.stdout);
        let first = banner.lines().next().unwrap_or_default();
        let identity = first
            .split_once(' ')
            .map_or(first, |(_, rest)| rest)
            .to_owned();
        if !seen.insert(identity) {
            continue;
        }
        let family = if banner.contains("clang") {
            "clang"
        } else {
            "gcc"
        };
        out.push((driver, family));
    }
    out
}

/// The ids of the `ubsan-trap-mode` predicate's trap clauses for the machine `facts` were
/// read from: the clauses that conclude `present`, kept where the reader searched this
/// object for a pattern the clause reads. The reader searches a pattern on the one machine
/// it is for and records no entry for any other (`elf::code`), so an x86_64 object keeps
/// `ud2` and `ud1` and an aarch64 object keeps `brk`, each read from the predicate's own
/// clause list and the object's `code_scanned` rather than from a table of trap words
/// written here a second time. Empty for an object of a machine no trap clause reads,
/// which the caller treats as a frame it cannot hold a row to, not as a match.
fn trap_clauses_for(facts: &chard::elf::ElfFacts) -> BTreeSet<String> {
    /// The `<function>:<pattern>=` keys of `code_scanned` that `cond` reads matches of.
    fn searched_keys(cond: &predicate::Cond, out: &mut Vec<String>) {
        use predicate::{Cond, ElfField, Term};
        match cond {
            Cond::All(inner) | Cond::Any(inner) | Cond::NoneOf(inner) => {
                for c in inner {
                    searched_keys(c, out);
                }
            }
            Cond::AnyStartsWith(Term::Elf(ElfField::CodeMatches), prefix) => {
                if let Some(pair) = prefix.strip_suffix('@') {
                    out.push(format!("{pair}="));
                }
            }
            Cond::Defined(_)
            | Cond::Missing(_)
            | Cond::Truth(_)
            | Cond::Eq(..)
            | Cond::Int(..)
            | Cond::AnyStartsWith(..)
            | Cond::AnyContains(..)
            | Cond::NonEmpty(_) => {}
        }
    }
    elf_static::ubsan_trap()
        .clauses
        .iter()
        .filter(|c| matches!(c.then, predicate::Conclusion::Present(_)))
        .filter(|c| {
            let mut keys = Vec::new();
            searched_keys(&c.when, &mut keys);
            keys.iter()
                .any(|key| facts.code_scanned.iter().any(|s| s.starts_with(key)))
        })
        .map(|c| c.id.clone())
        .collect()
}

/// One build of `source` as an object with `driver`, read through chard's reader and the
/// check's predicate; `None` where the driver refused the flags.
fn ubsan_trap_reading(
    work: &common::Work,
    driver: &str,
    source: &Path,
    tag: &str,
    flags: &[&str],
) -> Option<Evaluation> {
    ubsan_trap_reading_with_facts(work, driver, source, tag, flags).map(|(e, _)| e)
}

/// [`ubsan_trap_reading`], with the ELF facts the reading was made over.
fn ubsan_trap_reading_with_facts(
    work: &common::Work,
    driver: &str,
    source: &Path,
    tag: &str,
    flags: &[&str],
) -> Option<(Evaluation, chard::elf::ElfFacts)> {
    let object = work.path(&format!("{tag}.o"));
    let out = Command::new(driver)
        .args(flags)
        .arg("-c")
        .arg("-I")
        .arg(work.dir())
        .arg("-o")
        .arg(&object)
        .arg(source)
        .output()
        .expect("spawning the driver");
    if !out.status.success() {
        return None;
    }
    let facts = chard::elf::facts_for(&object).expect("the probe's object is ELF");
    let view = Live {
        macros: None,
        elf: Some(&facts),
    };
    let e = predicate::evaluate(elf_static::ubsan_trap(), &view).expect("a live view is complete");
    Some((e, facts))
}

/// The `ubsan-trap-mode` check, whose published verdict `report::sanitizer_group_limitation`
/// settles after the predicate has read the object.
fn ubsan_trap_check() -> &'static probe::Check {
    probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == "ubsan-trap-mode")
        .expect("ubsan-trap-mode is a corpus check")
}

/// Whether `off` is what chard publishes for the reading `e` of an object `driver` built
/// under `flags`: the predicate read `absent`, and the driver's own `-###` words for those
/// flags, read as `measure` reads them for the measured build, leave no group in trap mode
/// for `sanitizer-group-unmeasured` to withhold the `absent` over. A listing the driver
/// does not give withholds too, as it does in a report.
fn published_off(driver: &str, flags: &[&str], e: &Evaluation) -> bool {
    if e.outcome != Outcome::Absent {
        return false;
    }
    let words: Vec<String> = flags.iter().map(|f| (*f).to_owned()).collect();
    let listing = chard::compile_inputs::query(Path::new(driver), &words, "c")
        .map(|inputs| inputs.sanitizers);
    report::sanitizer_group_limitation(ubsan_trap_check(), report::Verdict::Off, Some(&listing))
        .is_none()
}

#[test]
fn a_trap_configuration_of_any_one_sanitizer_group_does_not_read_off() {
    if !can_run("that a trap configuration of any one sanitizer group does not read off") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "ubsan trap groups read from the probe's object",
            "the host cc emits Mach-O and chard reads only ELF",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "ubsan-trap-groups");
    let source = write_probe(&work, "ubsan-trap", &|s| s.to_owned());
    let drivers = sanitizer_drivers();
    let mut fed = 0usize;
    let mut refused = 0usize;
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut wrong = Vec::new();
    let mut exempt_and_off = BTreeSet::new();
    for (driver, family) in &drivers {
        for group in TRAP_GROUPS {
            for opt in ["-O0", "-O2"] {
                fed += 1;
                let sanitize = format!("-fsanitize={group}");
                let trap = format!("-fsanitize-trap={group}");
                let tag = format!("{driver}-{group}{opt}");
                let flags = [opt, sanitize.as_str(), trap.as_str()];
                let Some(e) = ubsan_trap_reading(&work, driver, &source, &tag, &flags) else {
                    refused += 1;
                    continue;
                };
                // Where the compiler answers `__has_feature`, the predicate itself must not
                // read `absent` for an enabled group (the witness is load-bearing, and the
                // publication rule is not allowed to cover for it); where it does not, the
                // published verdict is what must not be `off`.
                let off = if compiler_answers_feature(driver, &flags) {
                    e.outcome == Outcome::Absent
                } else {
                    published_off(driver, &flags, &e)
                };
                let withheld = if e.outcome == Outcome::Absent && !off {
                    " (withheld by sanitizer-group-unmeasured)"
                } else {
                    ""
                };
                *tally
                    .entry(format!("{family} {:?} {}{withheld}", e.outcome, e.clause))
                    .or_default() += 1;
                let exempt = OFF_WITHOUT_A_CONSTRUCT
                    .iter()
                    .find(|(f, g, o, _)| f == family && g == group && *o == opt);
                match (off, exempt) {
                    (true, None) => wrong.push(format!(
                        "{driver} ({family}) {flags:?}: off under {}",
                        e.clause
                    )),
                    (false, Some((_, _, _, why))) => wrong.push(format!(
                        "{driver} ({family}) {flags:?}: {:?} under {}, so the exemption \
                         ({why}) no longer holds",
                        e.outcome, e.clause
                    )),
                    (true, Some(_)) => {
                        exempt_and_off.insert((*family, *group, opt));
                    }
                    (false, None) => {}
                }
            }
        }
    }
    eprintln!(
        "chard: ubsan trap groups: {fed} builds fed ({} drivers x {} groups x 2 levels), \
         {refused} refused by the driver, readings {tally:?}",
        drivers.len(),
        TRAP_GROUPS.len()
    );
    assert_eq!(
        fed,
        drivers.len() * TRAP_GROUPS.len() * 2,
        "every build was fed"
    );
    assert!(
        fed - refused >= TRAP_GROUPS.len(),
        "the drivers here accepted only {} of {fed} trap configurations",
        fed - refused
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for (family, group, opt, why) in OFF_WITHOUT_A_CONSTRUCT {
        let measured = drivers.iter().any(|(_, f)| f == family);
        if measured && !exempt_and_off.contains(&(*family, *group, *opt)) {
            common::capability_gap(
                &format!("the {family} {group} {opt} exemption ({why})"),
                "the driver refused the group, so the exemption was not exercised",
            );
        }
    }
}

/// One build of [`the_ubsan_probe_withholds_off_without_its_constructs_or_its_witness`]:
/// a tag, a rewrite of the probe, the flags, and the outcome and clause it must read.
type WitnessCase<'a> = (
    &'a str,
    &'a dyn Fn(&str) -> String,
    &'a [&'a str],
    Outcome,
    &'a str,
);

/// Whether `driver` answers `__has_feature(undefined_behavior_sanitizer)` as 1 under
/// `flags`, asked of the preprocessor over a three-line source and not of the probe, so the
/// probe's witness is held to the compiler's answer rather than read back from itself: a
/// gcc that answers no `__has_feature` (13.3.0) reads as `false` here and the predicate's
/// witness clause is then not expected to fire. Printed, so a run's log says which reading
/// the witness cases were held to.
fn compiler_answers_feature(driver: &str, flags: &[&str]) -> bool {
    let source = "#if defined(__has_feature)\n#if __has_feature(undefined_behavior_sanitizer)\n\
                  CHARD_FEATURE_ANSWERED_YES\n#endif\n#endif\n";
    let mut child = Command::new(driver)
        .args(flags)
        .args(["-E", "-x", "c", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning the driver's preprocessor");
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("a piped stdin");
        stdin
            .write_all(source.as_bytes())
            .expect("writing the feature query");
    }
    let out = child.wait_with_output().expect("the driver's preprocessor");
    assert!(
        out.status.success(),
        "{driver} {flags:?} -E refused the feature query: {}",
        text(&out.stderr)
    );
    let answered = text(&out.stdout).contains("CHARD_FEATURE_ANSWERED_YES");
    eprintln!(
        "chard: ubsan trap witness: {driver} {} __has_feature(undefined_behavior_sanitizer) \
         under {flags:?}",
        if answered {
            "answers"
        } else {
            "does not answer"
        }
    );
    answered
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of six probe rewrites, each read against the predicate and, for the \
              sanitizer builds, the publication rule"
)]
fn the_ubsan_probe_withholds_off_without_its_constructs_or_its_witness() {
    if !can_run("that the ubsan probe's second function and witness are load-bearing") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "ubsan probe constructs read from the probe's object",
            "the host cc emits Mach-O and chard reads only ELF",
        );
        return;
    }
    let work = common::Work::new("probe-sources", "ubsan-trap-witness");
    let intact = |s: &str| s.to_owned();
    let renamed = |s: &str| {
        rewritten(
            s,
            "unsigned int chard_ubsan_trap_groups(",
            "unsigned int chard_ubsan_trap_renamed(",
        )
    };
    let resized = |s: &str| {
        rewritten(
            s,
            "int chard_ubsan_trap_sized(",
            "int chard_ubsan_trap_resized(",
        )
    };
    let redirected = |s: &str| {
        rewritten(
            s,
            "int chard_ubsan_trap_indirect(",
            "int chard_ubsan_trap_redirected(",
        )
    };
    let unwitnessed = |s: &str| {
        rewritten(
            s,
            "const char chard_ubsan_trap_feature = 1;",
            "const char chard_ubsan_trap_unwitnessed = 1;",
        )
    };
    let flagless: &[&str] = &["-O2"];
    let only_return: &[&str] = &["-O2", "-fsanitize=return", "-fsanitize-trap=return"];
    let (return_outcome, return_clause) = if compiler_answers_feature("cc", only_return) {
        (Outcome::Indeterminate, "sanitizer-group-unexercised")
    } else {
        (Outcome::Absent, predicate::OTHERWISE)
    };
    let cases: [WitnessCase; 6] = [
        (
            "intact-flagless",
            &intact,
            flagless,
            Outcome::Absent,
            predicate::OTHERWISE,
        ),
        (
            "renamed-flagless",
            &renamed,
            flagless,
            Outcome::Indeterminate,
            "groups-unsearched",
        ),
        (
            "resized-flagless",
            &resized,
            flagless,
            Outcome::Indeterminate,
            "groups-unsearched",
        ),
        (
            "redirected-flagless",
            &redirected,
            flagless,
            Outcome::Indeterminate,
            "groups-unsearched",
        ),
        (
            "intact-return",
            &intact,
            only_return,
            return_outcome,
            return_clause,
        ),
        (
            "unwitnessed-return",
            &unwitnessed,
            only_return,
            Outcome::Absent,
            predicate::OTHERWISE,
        ),
    ];
    let mut fed = 0usize;
    for (tag, rewrite, flags, outcome, clause) in cases {
        let source = write_probe(&work, "ubsan-trap", rewrite);
        let e = ubsan_trap_reading(&work, "cc", &source, tag, flags)
            .unwrap_or_else(|| panic!("cc could not build {tag} with {flags:?}"));
        fed += 1;
        assert_eq!(
            (e.outcome, e.clause.as_str()),
            (outcome, clause),
            "{tag} with {flags:?}"
        );
        if flags == only_return {
            assert!(
                !published_off("cc", flags, &e),
                "{tag} with {flags:?}: the verdict is published off, not withheld"
            );
        }
    }
    assert_eq!(fed, 6, "every case was built and read");
}

#[test]
fn every_probe_source_builds_in_the_oldest_default_dialect() {
    let verifies = "that the probe sources build under gnu89 and C++98";
    if !can_run(verifies) {
        return;
    }
    if Command::new("c++").arg("--version").output().is_err() {
        common::refuse("no C++ compiler on PATH", verifies);
        return;
    }
    let work = common::Work::new("probe-sources", "oldest-dialect");
    work.write(probe::SELFREPORT_HEADER_NAME, probe::SELFREPORT_HEADER);

    // C as `Some(false)`, C++ as `Some(true)`, by the extension the probes are written with.
    let cxx_of = |name: &std::ffi::OsStr| match Path::new(name).extension()?.to_str()? {
        "c" => Some(false),
        "cpp" => Some(true),
        _ => None,
    };
    // The frame: every distinct C or C++ source the corpus embeds, probe, auxiliary and a
    // positive arm's own input.
    let mut sources = BTreeMap::new();
    for p in probe::CORPUS {
        sources.insert(p.source_name, p.source);
        for aux in p.aux_libs {
            sources.insert(aux.source_name, aux.source);
        }
    }
    for input in probe::POSITIVE_INPUTS {
        sources.insert(input.source_name, input.source);
    }
    sources.retain(|name, _| cxx_of(name.as_ref()).is_some());
    // Checked against the directory the sources are embedded from, so a source the corpus
    // stopped naming, or a file it never named, shows as a count that differs.
    let on_disk = std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("probes"))
        .expect("listing probes/")
        .filter(|e| cxx_of(&e.as_ref().expect("a probes/ entry").file_name()).is_some())
        .count();
    assert_eq!(
        sources.len(),
        on_disk,
        "the corpus embeds {} C and C++ sources and probes/ holds {on_disk}",
        sources.len()
    );

    let syntax = |source: &Path, cxx: bool, std: Option<&str>| {
        Command::new(if cxx { "c++" } else { "cc" })
            .args(std)
            .arg("-fsyntax-only")
            .arg("-I")
            .arg(work.dir())
            .arg(source)
            .output()
            .expect("spawning the compiler")
    };
    let mut fed = 0usize;
    let mut checked = 0usize;
    let mut rejected_as_they_stand = Vec::new();
    let mut failures = Vec::new();
    for (name, source) in &sources {
        fed += 1;
        let cxx = cxx_of(name.as_ref()) == Some(true);
        let old = if cxx { "-std=c++98" } else { "-std=gnu89" };
        let path = work.write(name, source);
        if !syntax(&path, cxx, None).status.success() {
            rejected_as_they_stand.push(*name);
            continue;
        }
        checked += 1;
        let out = syntax(&path, cxx, Some(old));
        if !out.status.success() {
            failures.push(format!("{name} under {old}:\n{}", text(&out.stderr)));
        }
    }
    eprintln!(
        "oldest-dialect: fed {fed} of {} sources; {checked} checked; {} rejected by the host \
         as they stand: {rejected_as_they_stand:?}",
        sources.len(),
        rejected_as_they_stand.len()
    );
    assert_eq!(fed, sources.len(), "every source in the frame was fed");
    assert_eq!(checked + rejected_as_they_stand.len(), fed);
    assert!(
        checked > fed / 2,
        "only {checked} of {fed} sources built as they stand: {rejected_as_they_stand:?}"
    );
    assert!(
        failures.is_empty(),
        "{} of {checked} probe sources do not build in the oldest default dialect:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Build one probe source as a toolchain without `retain` would be asked to: `-O2` with
/// `-ffunction-sections -fdata-sections -Wl,--gc-sections` for a linked probe (the
/// per-function and per-datum sections are what gives the collector something to drop),
/// `-c` for an object probe, through `c++` for a C++ source and `cc` otherwise, failing
/// with the compiler's own words.
fn build_gc_sections(
    work: &common::Work,
    source: &Path,
    tag: &str,
    cxx: bool,
    object: bool,
) -> PathBuf {
    let bin = work.path(tag);
    let mut cmd = Command::new(if cxx { "c++" } else { "cc" });
    cmd.arg("-O2");
    if object {
        cmd.arg("-c");
    } else {
        cmd.args([
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
        ]);
    }
    let out = cmd
        .arg("-I")
        .arg(work.dir())
        .arg("-o")
        .arg(&bin)
        .arg(source)
        .output()
        .expect("spawning the compiler");
    assert!(
        out.status.success(),
        "could not build {tag}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

/// The artifact's `.chard.report` read as chard reads it, the ELF facts and then the
/// section's fields: the defined macros it names, the absence the facts show, or `None`
/// where the reader does not parse the artifact (a Mach-O host).
fn self_report_read(
    bin: &Path,
) -> Option<Result<BTreeMap<String, String>, report::SelfReportAbsence>> {
    let facts = match chard::elf::facts_for(bin) {
        Ok(facts) => facts,
        // Only an object that is not ELF is the host's gap; an ELF the reader refused is a
        // failure of this test's own frame and is said as one.
        Err(chard::elf::ElfError::NotElf { .. } | chard::elf::ElfError::MachO { .. }) => {
            return None;
        }
        Err(why) => panic!(
            "{}: chard's reader refused the artifact: {why}",
            bin.display()
        ),
    };
    Some(report::self_report_entries(&facts))
}

/// `strip --strip-all` leaves an allocated section in place, which DESIGN says of the
/// section: each linked probe of `frame`, stripped of every symbol, still carries its
/// report; `linked` is how many the frame linked, which every one of them must be.
fn strip_keeps_the_section(work: &common::Work, frame: &[&probe::Probe], linked: usize) {
    // `strip` leaves an allocated section in place, which DESIGN says of the section: the
    // linked artifacts, stripped of every symbol, still carry their report.
    if Command::new("strip").arg("--version").output().is_ok() {
        let mut stripped = 0usize;
        for p in frame {
            if p.link_mode == probe::LinkMode::Object {
                continue;
            }
            let bin = work.path(&format!("{}-gc", p.id));
            let out = Command::new("strip")
                .arg("--strip-all")
                .arg(&bin)
                .output()
                .expect("spawning strip");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            match self_report_read(&bin).expect("an ELF the frame read before") {
                Ok(_) => stripped += 1,
                Err(absence) => panic!("{}: after strip --strip-all the artifact {absence}", p.id),
            }
        }
        assert_eq!(
            stripped, linked,
            "every linked probe was stripped and read again"
        );
    } else {
        common::capability_gap(
            "strip keeps the section",
            "no strip on PATH, so the linked probes were not stripped and read again",
        );
    }
}

#[test]
fn every_macro_channel_probe_keeps_its_self_report_through_gc_sections_without_retain() {
    let verifies = "that a macro-channel probe keeps its .chard.report under --gc-sections \
                    without the retain attribute";
    if !can_run(verifies) {
        return;
    }
    if Command::new("c++").arg("--version").output().is_err() {
        common::refuse("no C++ compiler on PATH", verifies);
        return;
    }
    let work = common::Work::new("probe-sources", "gc-sections-no-retain");
    // The header with its `retain` arm never taken: `__has_attribute(retain)` answers
    // for the compiler, and a compiler without the attribute answers 0.
    work.write(
        probe::SELFREPORT_HEADER_NAME,
        &rewritten(
            probe::SELFREPORT_HEADER,
            "#  if __has_attribute(retain)\n",
            "#  if 0 /* the retain attribute, withheld by tests/probe_sources.rs */\n",
        ),
    );
    let frame: Vec<&probe::Probe> = probe::CORPUS
        .iter()
        .filter(|p| {
            p.checks
                .iter()
                .any(|c| c.channel() == probe::Channel::Macro)
        })
        .collect();
    assert!(!frame.is_empty(), "the corpus has no macro-channel probe");
    let mut fed = 0usize;
    let mut linked = 0usize;
    for p in &frame {
        assert!(
            p.embeds_self_report(),
            "{} carries a macro check and no section",
            p.id
        );
        let cxx = p.lang == probe::Lang::Cxx;
        let object = p.link_mode == probe::LinkMode::Object;
        let source = work.write(p.source_name, p.source);
        let bin = build_gc_sections(&work, &source, &format!("{}-gc", p.id), cxx, object);
        fed += 1;
        linked += usize::from(!object);
        let Some(read) = self_report_read(&bin) else {
            common::capability_gap(
                "gc-sections without retain",
                "the host builds an artifact chard's ELF reader does not parse (Mach-O), so \
                 the section cannot be read back here",
            );
            return;
        };
        match read {
            Ok(defined) => eprintln!(
                "{}: the section names {} defined macros",
                p.id,
                defined.len()
            ),
            Err(absence) => panic!(
                "{}: linked -O2 -Wl,--gc-sections with no `retain`, the artifact {absence}",
                p.id
            ),
        }
    }
    eprintln!(
        "gc-sections without retain: fed {fed} of {} macro-channel probes, {linked} linked \
         and {} compiled -c",
        frame.len(),
        fed - linked
    );
    assert_eq!(fed, frame.len(), "every probe in the frame was fed");
    assert!(
        linked > 0,
        "no probe in the frame was linked, so --gc-sections was never tried"
    );
    strip_keeps_the_section(&work, &frame, linked);

    // The control: the C++ probe with its reference removed loses the section under the
    // same build, which is what shows this test can see a loss.
    let cxx_probe = probe::find("cxx-stdlib-assertions").expect("the C++ probe is in the corpus");
    let unreferenced = rewritten(
        cxx_probe.source,
        "    const char *volatile keep_report = chard_report;\n    (void) keep_report;\n",
        "",
    );
    let source = work.write("cxx_assertions_unreferenced.cpp", &unreferenced);
    let bin = build_gc_sections(
        &work,
        &source,
        "cxx-stdlib-assertions-unreferenced-gc",
        true,
        false,
    );
    match self_report_read(&bin).expect("the frame's artifacts were readable, so this one is") {
        Err(report::SelfReportAbsence::Unlisted { .. }) => {}
        other => panic!("the control kept its section ({other:?}) under --gc-sections"),
    }
}

#[test]
fn every_compiler_diag_probe_s_canary_fires_on_the_host_compilers() {
    if !can_run("every compiler-diag probe's canary fires on the host compilers") {
        return;
    }
    // Each compiler on PATH with its family, read from what it says it is.
    let compilers: Vec<(&str, &str)> = ["cc", "gcc", "clang"]
        .into_iter()
        .filter_map(|c| {
            let out = Command::new(c).arg("--version").output().ok()?;
            out.status.success().then(|| {
                let family = if text(&out.stdout).contains("clang") {
                    "clang"
                } else {
                    "gcc"
                };
                (c, family)
            })
        })
        .collect();
    let work = common::Work::new("probe-sources", "canary-fires");
    let mut silent = Vec::new();
    let mut built = 0usize;
    for p in probe::CORPUS.iter().filter(|p| {
        p.checks
            .iter()
            .any(|c| c.channel() == probe::Channel::CompilerDiag)
    }) {
        let source = write_probe(&work, p.id, &str::to_owned);
        let pinned = p
            .source
            .contains("#pragma GCC diagnostic warning \"-Wunused-variable\"");
        let wall: &[&str] = if pinned { &[] } else { &["-Wall"] };
        for (cc, family) in &compilers {
            // A family every compiler-diag check of the probe is gated off never builds it.
            if p.checks
                .iter()
                .filter(|c| c.channel() == probe::Channel::CompilerDiag)
                .all(|c| c.gate.compiler_unsupported.contains(family))
            {
                continue;
            }
            for werror in [&[][..], &["-Werror"][..]] {
                let out = Command::new(cc)
                    .env("LC_ALL", "C")
                    .args(wall)
                    .args(werror)
                    .arg("-I")
                    .arg(work.dir())
                    .arg("-c")
                    .arg("-o")
                    .arg(work.path("canary.o"))
                    .arg(&source)
                    .output()
                    .unwrap_or_else(|e| panic!("running {cc}: {e}"));
                built += 1;
                let fired = text(&out.stderr)
                    .lines()
                    .any(|l| l.contains("unused variable") && l.contains("chard_canary_unused"));
                if !fired {
                    silent.push(format!("{} {cc} {wall:?} {werror:?}", p.id));
                }
            }
        }
    }
    assert!(
        silent.is_empty(),
        "a compiler-diag probe whose canary did not fire on this host: {silent:?}"
    );
    assert!(built > 0, "no compiler-diag probe was built");
    eprintln!("canary: {built} builds under {compilers:?}, every one printed the canary's warning");
}

#[test]
fn a_macro_defined_as_a_question_mark_is_not_read_as_undefined() {
    const READS: [(&str, &str); 7] = [
        ("exceptions-macro", "__EXCEPTIONS"),
        ("pie-macro", "__PIE__"),
        ("pic-macro", "__PIC__"),
        ("cet-macro", "__CET__"),
        ("branch-protection-macro", "__ARM_FEATURE_BTI_DEFAULT"),
        ("branch-protection-macro", "__ARM_FEATURE_PAC_DEFAULT"),
        ("gcs-macro", "__ARM_FEATURE_GCS_DEFAULT"),
    ];
    if !can_run("that the self-report tells a macro defined as `?` from an undefined one") {
        return;
    }
    let work = common::Work::new("probe-sources", "question-mark");
    work.write(probe::SELFREPORT_HEADER_NAME, probe::SELFREPORT_HEADER);
    let source = work.write(
        "question_mark.c",
        "#include <stdio.h>\n\
         #include \"chard_selfreport.h\"\n\
         CHARD_EMIT_REPORT;\n\
         int main(void) { CHARD_PRINT_REPORT; return 0; }\n",
    );
    // The section where the host's artifact is ELF, and stdout everywhere.
    let accounts = |tag: &str, flags: &[&str]| {
        let bin = build(&work, &source, tag, flags);
        let out = run(&bin);
        assert!(out.status.success(), "{tag} ran: {}", text(&out.stderr));
        let printed = probe::self_report_account(&text(&out.stdout))
            .unwrap_or_else(|| panic!("{tag} printed no report: {}", text(&out.stdout)));
        let mut read = vec![("stdout", printed)];
        match self_report_read(&bin) {
            Some(section) => {
                let section = section.unwrap_or_else(|why| panic!("{tag}'s section: {why}"));
                read.push(("section", section));
            }
            None if cfg!(target_os = "linux") => panic!("{tag}: no ELF artifact on Linux"),
            // Only a host whose artifacts chard's reader does not parse reads stdout alone.
            None => {}
        }
        read
    };
    let outcome = |check: &str, macros: &BTreeMap<String, String>| {
        let p = predicate::for_check(check).unwrap_or_else(|| panic!("{check} has a predicate"));
        let live = Live {
            macros: Some(macros),
            elf: None,
        };
        predicate::evaluate(p, &live)
            .unwrap_or_else(|why| panic!("{check} evaluates over a macro map: {why:?}"))
            .outcome
    };

    let mut fed = 0usize;
    for (i, (check, name)) in READS.iter().enumerate() {
        let define = format!("-D{name}=?");
        for (channel, macros) in accounts(&format!("defined-{i}"), &["-w", &define]) {
            fed += 1;
            assert_eq!(
                macros.get(*name).map(String::as_str),
                Some("?"),
                "{define}: the {channel} reads {name} as the value it was given"
            );
            assert_eq!(
                outcome(check, &macros),
                Outcome::Indeterminate,
                "{define}: {check} over the {channel} did not withhold a macro defined as `?`"
            );
        }
    }
    // Both channels on Linux, stdout at least elsewhere.
    let expected = if cfg!(target_os = "linux") {
        vec![READS.len() * 2]
    } else {
        vec![READS.len(), READS.len() * 2]
    };
    assert!(
        expected.contains(&fed),
        "{fed} readings of {} defines",
        READS.len()
    );

    // The other arm: nothing defined as `?`. A macro this host leaves undefined reads as
    // undefined, so the undefined spelling is still read, and its check still decides.
    for (channel, macros) in accounts("none", &["-fno-exceptions"]) {
        assert!(!macros.is_empty(), "the {channel} account names some macro");
        assert_eq!(
            macros.get("__EXCEPTIONS"),
            None,
            "-fno-exceptions: the {channel} reads __EXCEPTIONS undefined"
        );
        assert_eq!(
            outcome("exceptions-macro", &macros),
            Outcome::Absent,
            "-fno-exceptions: exceptions-macro over the {channel} decides"
        );
    }
    eprintln!("question mark: {fed} readings of {} defines", READS.len());
}
