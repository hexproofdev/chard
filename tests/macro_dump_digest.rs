// SPDX-License-Identifier: BSD-3-Clause

//! A `-dM -E` dump's digest does not depend on where `--workdir` points.

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

use std::path::{Path, PathBuf};
use std::process::Command;

use chard::compile;
use chard::digest::sha256_hex;
use chard::probe::Lang;

mod common;

/// Work directory names, enough that several land on a colliding path on gcc 16.1.1
/// (7 of 60 copies of this shape did).
const DIRECTORIES: usize = 64;

fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The language a driver on this list compiles: `g++` and `clang++` C++, the rest C.
fn lang_of(driver: &Path) -> Lang {
    if driver
        .file_name()
        .is_some_and(|n| n.to_string_lossy().contains("++"))
    {
        Lang::Cxx
    } else {
        Lang::C
    }
}

fn scratch(label: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("chard-macro-order-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creating the scratch directory");
    dir
}

/// The SHA-256 of the dump as printed (not `compile::dump_digest`), so the printed order is
/// part of what the first test holds.
fn digest_in(driver: &Path, work: &Path) -> String {
    let (_, record) = compile::macro_dump(
        driver,
        lang_of(driver),
        &[],
        compile::DumpUnit::LibcHeaders,
        work,
        "order",
    )
    .expect("the dump runs");
    assert_eq!(record.exit_status, 0, "the dump exits 0: {}", record.stderr);
    sha256_hex(record.stdout.as_bytes())
}

/// The discriminating spelling: the source `macro_dump` left behind, handed to the driver by
/// absolute path.
fn digest_by_absolute_path(driver: &Path, work: &Path) -> String {
    let source = work.join(format!("macros-order.{}", lang_of(driver).source_suffix()));
    let out = Command::new(driver)
        .args(["-dM", "-E"])
        .arg(&source)
        .env("LC_ALL", "C")
        .output()
        .expect("running the driver");
    assert!(out.status.success(), "the dump exits 0");
    sha256_hex(String::from_utf8_lossy(&out.stdout).trim_end().as_bytes())
}

#[test]
fn a_macro_dump_digest_does_not_depend_on_the_work_directory() {
    let verifies = "that a macro dump's digest is the same under every --workdir name";
    let mut drivers = Vec::new();
    for name in ["gcc", "g++"] {
        match on_path(name) {
            Some(path) => drivers.push(path),
            None => common::capability_gap(
                &format!("macro-dump digest under {name}"),
                "no such driver on PATH, so this arm did not run",
            ),
        }
    }
    if drivers.is_empty() {
        common::refuse("neither gcc nor g++ on PATH", verifies);
        return;
    }

    for driver in &drivers {
        let root = scratch(
            &driver
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
                .replace('+', "p"),
        );
        let mut by_name = std::collections::BTreeSet::new();
        let mut by_absolute = std::collections::BTreeSet::new();
        for n in 0..DIRECTORIES {
            let work = root.join(format!("wd{n}"));
            std::fs::create_dir_all(&work).expect("creating a work directory");
            by_name.insert(digest_in(driver, &work));
            by_absolute.insert(digest_by_absolute_path(driver, &work));
        }
        assert_eq!(
            by_name.len(),
            1,
            "{}: {DIRECTORIES} work directory names gave {} digests",
            driver.display(),
            by_name.len()
        );

        // One directory, again and again: a race or a clock would show here.
        let work = root.join("wd0");
        let first = digest_in(driver, &work);
        for _ in 0..25 {
            assert_eq!(
                digest_in(driver, &work),
                first,
                "{}: repeated dump",
                driver.display()
            );
        }
        assert!(by_name.contains(&first));

        if by_absolute.len() < 2 {
            common::capability_gap(
                &format!(
                    "{}: the dump's order depending on the path",
                    driver.display()
                ),
                "this driver listed its macros in one order for every path, so the arm above could not have failed here",
            );
        }
        common::removed(std::fs::remove_dir_all(&root), &root);
    }
}

/// Names to add with `-D`, enough that some land elsewhere in gcc's identifier table than the
/// macros around them.
const EXTRA_MACROS: usize = 64;

#[test]
fn a_macro_dump_digest_does_not_move_with_a_profile_define() {
    let verifies = "that a macro dump's digest moves only where a line does";
    let mut drivers = Vec::new();
    for name in ["gcc", "g++"] {
        match on_path(name) {
            Some(path) => drivers.push(path),
            None => common::capability_gap(
                &format!("macro-dump digest under a profile -D under {name}"),
                "no such driver on PATH, so this arm did not run",
            ),
        }
    }
    if drivers.is_empty() {
        common::refuse("neither gcc nor g++ on PATH", verifies);
        return;
    }
    for driver in &drivers {
        let root = scratch(&format!(
            "define-{}",
            driver
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
                .replace('+', "p")
        ));
        let (_, plain) = compile::macro_dump(
            driver,
            lang_of(driver),
            &[],
            compile::DumpUnit::LibcHeaders,
            &root,
            "plain",
        )
        .expect("the dump runs");
        assert_eq!(plain.exit_status, 0, "the dump exits 0: {}", plain.stderr);
        let mut reordered = 0_usize;
        for n in 0..EXTRA_MACROS {
            let name = format!("CHARD_EXTRA_{n}");
            let (_, with) = compile::macro_dump(
                driver,
                lang_of(driver),
                &[format!("-D{name}=1")],
                compile::DumpUnit::LibcHeaders,
                &root,
                &format!("extra{n}"),
            )
            .expect("the dump runs");
            assert_eq!(with.exit_status, 0, "the dump exits 0: {}", with.stderr);
            let added = format!("#define {name} 1");
            let shared: Vec<&str> = with.stdout.lines().filter(|l| *l != added).collect();
            assert_eq!(
                shared.len() + 1,
                with.stdout.lines().count(),
                "{}: the -D adds exactly its own line",
                driver.display()
            );
            let shared = shared.join("\n");
            assert_eq!(
                compile::dump_digest(&shared),
                compile::dump_digest(&plain.stdout),
                "{}: -D{name} moved the digest of the lines it did not add",
                driver.display()
            );
            if sha256_hex(shared.as_bytes()) != sha256_hex(plain.stdout.as_bytes()) {
                reordered += 1;
            }
        }
        // Both sides are the record's output trimmed at its end, or lines joined with no
        // newline after the last, so they differ only where the order does; a change to that
        // trimming would count every name as reordering and hide the gap below.
        eprintln!(
            "{}: {reordered} of {EXTRA_MACROS} added -D names reordered the dump's other lines",
            driver.display()
        );
        if reordered == 0 {
            common::capability_gap(
                &format!("{}: a profile -D reordering the dump", driver.display()),
                "no added name moved another macro in this driver's list, so the arm above could not have failed here",
            );
        }
        common::removed(std::fs::remove_dir_all(&root), &root);
    }
}

#[test]
fn a_macro_dump_digest_is_the_schemas_shell_recipe() {
    let verifies = "that a macro dump's digest is LC_ALL=C sort over its lines";
    let (Some(driver), Some(sort)) = (on_path("gcc"), on_path("sort")) else {
        common::refuse("gcc or sort not on PATH", verifies);
        return;
    };
    let root = scratch("recipe");
    let (_, record) = compile::macro_dump(
        &driver,
        Lang::C,
        &[],
        compile::DumpUnit::LibcHeaders,
        &root,
        "recipe",
    )
    .expect("the dump runs");
    assert_eq!(record.exit_status, 0, "the dump exits 0: {}", record.stderr);
    let mut child = Command::new(sort)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("running sort");
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("sort's stdin");
        stdin
            .write_all(format!("{}\n", record.stdout).as_bytes())
            .expect("writing the dump to sort");
    }
    let sorted = child.wait_with_output().expect("sort finishes");
    assert!(sorted.status.success(), "sort exits 0");
    let mut bytes = sorted.stdout;
    assert_eq!(
        bytes.pop(),
        Some(b'\n'),
        "sort ends its output with a newline"
    );
    assert_eq!(compile::dump_digest(&record.stdout), sha256_hex(&bytes));
    common::removed(std::fs::remove_dir_all(&root), &root);
}

#[test]
fn a_cxx_dump_is_a_cxx_source_and_runs_under_clang_werror() {
    let verifies = "that the C++ macro dump's source is C++, so clang++ -Werror runs it";
    let (Some(clang), Some(clangxx)) = (on_path("clang"), on_path("clang++")) else {
        common::refuse("clang or clang++ not on PATH", verifies);
        return;
    };
    let root = scratch("werror");
    let werror = ["-Werror".to_owned()];
    // A probe's own unit includes the self-report header beside it, as in a work directory.
    std::fs::write(
        root.join(chard::probe::SELFREPORT_HEADER_NAME),
        chard::probe::SELFREPORT_HEADER,
    )
    .expect("writing the self-report header");
    let mut fed = 0_usize;
    for (driver, lang, suffix, probe) in [
        (&clangxx, Lang::Cxx, "cpp", "cxx-stdlib-assertions"),
        (&clang, Lang::C, "c", "exceptions"),
    ] {
        let source = chard::probe::find(probe).expect("the probe").source;
        for (unit_name, unit) in [
            ("empty", compile::DumpUnit::Empty),
            ("headers", compile::DumpUnit::LibcHeaders),
            ("probe", compile::DumpUnit::Source(source)),
        ] {
            let tag = format!("werror-{suffix}-{unit_name}");
            let (macros, record) = compile::macro_dump(driver, lang, &werror, unit, &root, &tag)
                .expect("the dump runs");
            fed += 1;
            assert_eq!(
                record.exit_status,
                0,
                "{} -Werror over the {suffix} dump ({unit_name}) exits 0: {}",
                driver.display(),
                record.stderr
            );
            assert!(!macros.is_empty(), "the dump defined macros");
            assert_eq!(
                record.argv.last().map(String::as_str),
                Some(format!("macros-{tag}.{suffix}").as_str()),
                "the driver is handed the file under its language's suffix"
            );
        }
    }
    assert_eq!(
        fed, 6,
        "both drivers, over the empty unit, the libc headers and a probe's own"
    );
    // The discriminating shape: the C++ driver handed a `.c` source under -Werror.
    let old = root.join("macros-old.c");
    std::fs::write(&old, "").expect("writing the old-shape source");
    let out = Command::new(&clangxx)
        .args(["-Werror", "-dM", "-E", "macros-old.c"])
        .current_dir(&root)
        .env("LC_ALL", "C")
        .output()
        .expect("running clang++");
    let warned = String::from_utf8_lossy(&out.stderr).contains("treating 'c' input as 'c++'");
    assert!(
        out.status.success() || warned,
        "clang++ -Werror refused a .c name for another reason than the C-input warning: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        common::capability_gap(
            "a C++ dump named .c under clang++ -Werror",
            "this clang++ does not warn on a .c input in C++ mode, so a .c name would have passed and the arm above could not have failed here",
        );
    }
    common::removed(std::fs::remove_dir_all(&root), &root);
}

#[test]
fn the_cxx_probe_and_the_profiles_cxx_dump_pass_cxx_through_the_binary() {
    let verifies = "that measure's C++ dumps are .cpp sources under clang -Werror";
    if on_path("clang").is_none() || on_path("clang++").is_none() {
        common::refuse("clang or clang++ not on PATH", verifies);
        return;
    }
    let root = scratch("binary");
    let out = root.join("report.json");
    let run = Command::new(common::chard_binary())
        .args([
            "measure",
            "--cc",
            "clang",
            "--profile",
            "explicit",
            "--flags",
            "-O2",
        ])
        .args([
            "--cxxflags",
            "-O2 -Werror",
            "--probe",
            "cxx-stdlib-assertions",
        ])
        .arg("--workdir")
        .arg(root.join("work"))
        .arg("-o")
        .arg(&out)
        .output()
        .expect("running chard");
    assert!(
        run.status.success(),
        "chard measure exited {:?}: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("the report")).expect("JSON");
    let cxx = &report["toolchain"]["target"]["profile_macros_cxx"];
    assert_eq!(
        cxx["exit_status"],
        serde_json::json!(0),
        "the profile's C++ dump under -Werror exits 0: {cxx}"
    );
    let mut dumps = 0_usize;
    for o in report["observations"].as_array().expect("observations") {
        let records = [
            &o["evidence"]["macro_dump"],
            &o["controls"]["positive"]["macro_dump"],
            &o["controls"]["negative"]["macro_dump"],
        ];
        for record in records.into_iter().filter(|r| !r.is_null()) {
            dumps += 1;
            let source = record["argv"]
                .as_array()
                .and_then(|a| a.last())
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            assert!(
                source.starts_with("macros-")
                    && Path::new(source).extension().is_some_and(|e| e == "cpp"),
                "{}: a C++ probe's dump source is {source:?}",
                o["check"]
            );
        }
    }
    assert!(dumps > 0, "the C++ probe published a macro dump record");
    common::removed(std::fs::remove_dir_all(&root), &root);
}

#[test]
fn a_probe_dump_preprocesses_the_probes_own_unit_under_its_builds_words() {
    let verifies = "that a probe's macro dump is its own unit under its build's words";
    if on_path("gcc").is_none() || on_path("g++").is_none() {
        common::refuse("gcc or g++ not on PATH", verifies);
        return;
    }
    let root = scratch("own-unit");
    let work = root.join("work");
    let out = root.join("report.json");
    let run = Command::new(common::chard_binary())
        .args(["measure", "--cc", "gcc", "--profile", "bare"])
        .args(["--probe", "toolchain-macros", "--probe", "exceptions"])
        .args(["--probe", "cxx-stdlib-assertions", "--workdir"])
        .arg(&work)
        .arg("-o")
        .arg(&out)
        .output()
        .expect("running chard");
    assert!(
        run.status.success(),
        "chard measure exited {:?}: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("the report")).expect("JSON");
    let (mut fed, mut compared, mut macro_checks) = (0_usize, 0_usize, 0_usize);
    for o in report["observations"].as_array().expect("observations") {
        let probe_id = o["probe"].as_str().expect("an observation names its probe");
        let source = chard::probe::find(probe_id).expect("a corpus probe").source;
        // Every macro-channel check the run measured compared two views: its dump ran and
        // read, and its macros came from the artifact.
        if o["channel"] == "macro" {
            macro_checks += 1;
        }
        if o["channel"] == "macro" && o["verdict"] != "unsupported" {
            assert_eq!(
                o["evidence"]["macro_dump"]["exit_status"],
                serde_json::json!(0),
                "{}: the dump ran",
                o["check"]
            );
            assert_eq!(
                o["evidence"]["macro_source"], "compiled-artifact",
                "{}: the macros are the artifact's, so the views were compared",
                o["check"]
            );
            compared += 1;
        }
        let builds = [
            (&o["evidence"]["macro_dump"], &o["build"]),
            (
                &o["controls"]["positive"]["macro_dump"],
                &o["controls"]["positive"]["build"],
            ),
            (
                &o["controls"]["negative"]["macro_dump"],
                &o["controls"]["negative"]["build"],
            ),
        ];
        for (dump, build) in builds.into_iter().filter(|(d, _)| !d.is_null()) {
            fed += 1;
            hold_dump_record(&o["check"], dump, build, &work, source);
        }
    }
    // The frame: every macro-channel check of the three probes in the corpus was published,
    // and each measured one compared its views.
    let expected = macro_checks_of(&["toolchain-macros", "exceptions", "cxx-stdlib-assertions"]);
    eprintln!(
        "{macro_checks} macro check(s) of {expected}, {compared} compared, {fed} dump record(s)"
    );
    assert_eq!(macro_checks, expected, "every macro check was published");
    assert!(
        compared > 0 && fed >= compared,
        "{compared} compared, {fed} dump records"
    );
    let disagreements: Vec<&serde_json::Value> = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| {
            d["message"]
                .as_str()
                .is_some_and(|m| m.contains("disagree about"))
        })
        .collect();
    assert!(disagreements.is_empty(), "{disagreements:?}");
    common::removed(std::fs::remove_dir_all(&root), &root);
}

#[test]
fn a_probe_dump_leaves_out_its_builds_link_words() {
    let verifies = "that a probe's macro dump leaves out its build's link words";
    if on_path("gcc").is_none() {
        common::refuse("gcc not on PATH", verifies);
        return;
    }
    let root = scratch("link-words");
    let out = root.join("report.json");
    let run = Command::new(common::chard_binary())
        .args(["measure", "--cc", "gcc", "--profile", "explicit"])
        .args(["--flags", "-O2 -Wl,-z,now"])
        .args([
            "--probe",
            "toolchain-macros",
            "--probe",
            "exceptions",
            "--workdir",
        ])
        .arg(root.join("work"))
        .arg("-o")
        .arg(&out)
        .output()
        .expect("running chard");
    assert!(
        run.status.success(),
        "chard measure exited {:?}: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("the report")).expect("JSON");
    let (mut linked, mut dumps) = (0_usize, 0_usize);
    for o in report["observations"].as_array().expect("observations") {
        // The control arms are built on the clean footing, without the profile's `-O2`.
        let arms = [
            (&o["evidence"], true),
            (&o["controls"]["positive"], false),
            (&o["controls"]["negative"], false),
        ];
        for (arm, measured) in arms {
            let dump = &arm["macro_dump"];
            if dump.is_null() {
                continue;
            }
            dumps += 1;
            let words = argv_of(dump);
            assert!(
                !measured || words.contains(&"-O2"),
                "{}: {words:?}",
                o["check"]
            );
            assert!(!words.contains(&"-Wl,-z,now"), "{}: {words:?}", o["check"]);
        }
        let build = if o["evidence"]["macro_dump"].is_null() {
            &serde_json::Value::Null
        } else {
            &o["build"]
        };
        if o["probe"] == "toolchain-macros" && !build.is_null() {
            linked += 1;
            let built = argv_of(build);
            assert!(built.contains(&"-Wl,-z,now"), "{}: {built:?}", o["check"]);
        }
    }
    eprintln!("{dumps} dump record(s), {linked} linked build(s) carrying the link word");
    assert!(
        dumps > 0 && linked > 0,
        "{dumps} dumps, {linked} linked builds"
    );
    common::removed(std::fs::remove_dir_all(&root), &root);
}

/// The words of a published build record's `argv`.
fn argv_of(record: &serde_json::Value) -> Vec<&str> {
    record["argv"]
        .as_array()
        .expect("an argv")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect()
}

/// One dump record of `check` against its build's: the dump's source in `work` is the
/// probe's `source` byte for byte, the dump carries no output word, and the build and the
/// dump both carry the run witness's forced include.
fn hold_dump_record(
    check: &serde_json::Value,
    dump: &serde_json::Value,
    build: &serde_json::Value,
    work: &Path,
    source: &str,
) {
    let words = argv_of(dump);
    let name = words.last().copied().unwrap_or_default();
    let copied = std::fs::read_to_string(work.join(name)).expect("the dump's source");
    assert_eq!(copied, source, "{check}: {name} is the probe's own source");
    for word in ["-c", "-o", "-shared"] {
        assert!(!words.contains(&word), "{check}: {word} on {words:?}");
    }
    let witness = |argv: &[&str]| {
        argv.windows(2)
            .any(|w| w == ["-include", "chard_run_witness.h"])
    };
    assert!(
        witness(&argv_of(build)),
        "{check}: the build carries the witness"
    );
    assert!(
        witness(&words),
        "{check}: the dump carries it too: {words:?}"
    );
}

/// The macro-channel checks the corpus declares for the probes `ids`.
fn macro_checks_of(ids: &[&str]) -> usize {
    ids.iter()
        .map(|id| {
            chard::probe::find(id)
                .expect("a corpus probe")
                .checks
                .iter()
                .filter(|c| c.channel() == chard::probe::Channel::Macro)
                .count()
        })
        .sum()
}
