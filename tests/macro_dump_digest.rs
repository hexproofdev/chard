// SPDX-License-Identifier: BSD-3-Clause

//! A `-dM -E` dump's digest does not depend on where `--workdir` points.
//!
//! gcc lists its macros in the order of its identifier table, and the path it was given is
//! entered in that table, so a path whose hash collides with a macro's moves that macro to
//! another place in the list. The map `compile::macro_dump` parses is sorted and never sees
//! the order, but a digest of the stdout as printed does. `compile::macro_dump` runs the
//! driver in the work directory with the file named by its name alone; the cause and the
//! measurement are in its comment. The published digest is over the sorted lines
//! (`compile::dump_digest`); the first test below holds the printed order itself, and the
//! second holds the sorted digest across an
//! added `-D`, which moves the order and no other line; the third holds the digest to the
//! shell recipe the schema gives for it; the fourth holds the dump's source to its driver's
//! language, so a C++ driver under `-Werror` is not refused the file.
//!
//! Two arms, against the real `gcc` and `g++` when the host has them. The first calls
//! `macro_dump` over many differently named work directories, and repeatedly in one, and
//! requires one digest. The second is its discrimination: the same source dumped by absolute
//! path must produce more than one digest across those directories,
//! or the first arm could not have failed and is announced as unexercised. A gcc whose order
//! does not depend on the path would otherwise pass the first arm without being tested.

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
    let (_, record) = compile::macro_dump(driver, lang_of(driver), &[], true, work, "order")
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
        std::fs::remove_dir_all(&root).ok();
    }
}

/// Names to add with `-D`, enough that some land elsewhere in gcc's identifier table than the
/// macros around them.
const EXTRA_MACROS: usize = 64;

/// A dump under a profile `-D` and the dump without it share every line but the one the
/// `-D` adds, and `compile::dump_digest` gives the shared lines one digest whatever order
/// gcc printed them in. The discrimination arm: the shared lines as printed, digested
/// without sorting, must differ for at least one name, or the first assertion could not
/// have failed and the arm is announced as unexercised.
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
        let (_, plain) = compile::macro_dump(driver, lang_of(driver), &[], true, &root, "plain")
            .expect("the dump runs");
        assert_eq!(plain.exit_status, 0, "the dump exits 0: {}", plain.stderr);
        let mut reordered = 0_usize;
        for n in 0..EXTRA_MACROS {
            let name = format!("CHARD_EXTRA_{n}");
            let (_, with) = compile::macro_dump(
                driver,
                lang_of(driver),
                &[format!("-D{name}=1")],
                true,
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
        std::fs::remove_dir_all(&root).ok();
    }
}

/// The digest is the schema's shell recipe: `LC_ALL=C sort` over the dump with its final
/// newline removed, then SHA-256. Run over a real dump where the host has `gcc` and `sort`.
#[test]
fn a_macro_dump_digest_is_the_schemas_shell_recipe() {
    let verifies = "that a macro dump's digest is LC_ALL=C sort over its lines";
    let (Some(driver), Some(sort)) = (on_path("gcc"), on_path("sort")) else {
        common::refuse("gcc or sort not on PATH", verifies);
        return;
    };
    let root = scratch("recipe");
    let (_, record) =
        compile::macro_dump(&driver, Lang::C, &[], true, &root, "recipe").expect("the dump runs");
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
    std::fs::remove_dir_all(&root).ok();
}

/// A dump's source carries its driver's language, so `clang++` under `-Werror` runs it.
///
/// Given a dump named `macros-<tag>.c`, `clang++` warns "treating 'c' input as 'c++' when in
/// C++ mode" (`-Wdeprecated`), and under a profile carrying `-Werror` the C++ probe's dump
/// exits 1, so its macro-channel checks withhold (measured on Fedora 44 x86_64, clang
/// 22.1.8). The `.c` name is run beside the C++ one as the discrimination: it must fail under
/// `clang++ -Werror`, or this test could not have failed and the arm is announced as
/// unexercised. The C dump under `clang -Werror` keeps its `.c` name and exits 0.
#[test]
fn a_cxx_dump_is_a_cxx_source_and_runs_under_clang_werror() {
    let verifies = "that the C++ macro dump's source is C++, so clang++ -Werror runs it";
    let (Some(clang), Some(clangxx)) = (on_path("clang"), on_path("clang++")) else {
        common::refuse("clang or clang++ not on PATH", verifies);
        return;
    };
    let root = scratch("werror");
    let werror = ["-Werror".to_owned()];
    let mut fed = 0_usize;
    for (driver, lang, suffix) in [(&clangxx, Lang::Cxx, "cpp"), (&clang, Lang::C, "c")] {
        for with_headers in [false, true] {
            let tag = format!("werror-{suffix}-{with_headers}");
            let (macros, record) =
                compile::macro_dump(driver, lang, &werror, with_headers, &root, &tag)
                    .expect("the dump runs");
            fed += 1;
            assert_eq!(
                record.exit_status,
                0,
                "{} -Werror over the {suffix} dump (headers {with_headers}) exits 0: {}",
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
    assert_eq!(fed, 4, "both drivers, with and without the libc headers");
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
    std::fs::remove_dir_all(&root).ok();
}

/// The two call sites the suffix rests on pass their driver's language: a run under
/// `clang -Werror` builds the C++ probe's dumps from `.cpp` files and the profile's C++ dump
/// exits 0, through the binary, so a caller that passed C for the C++ driver fails here.
///
/// `measure::Gatherer::gather` passes the probe's language and `toolchain::dump_with` the
/// C++ driver's; the test above holds `compile::macro_dump` itself. `-Werror` goes in
/// `--cxxflags` alone so the profile's C++ dump is taken (it is only where the two lists
/// differ) and the C dumps carry no `-Werror`.
#[test]
fn the_cxx_probe_and_the_profiles_cxx_dump_pass_cxx_through_the_binary() {
    let verifies = "that measure's C++ dumps are .cpp sources under clang -Werror";
    if on_path("clang").is_none() || on_path("clang++").is_none() {
        common::refuse("clang or clang++ not on PATH", verifies);
        return;
    }
    let root = scratch("binary");
    let out = root.join("report.json");
    let run = Command::new(env!("CARGO_BIN_EXE_chard"))
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
    std::fs::remove_dir_all(&root).ok();
}
