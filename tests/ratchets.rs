// SPDX-License-Identifier: BSD-3-Clause
//! `tests/ratchets.txt`, the list `make ratchets` runs first in the merge gate, holds only
//! tests that exist.
//!
//! A line naming a test that was renamed or removed would not fail `cargo test --exact`:
//! the filter matches nothing and libtest reports 0 passed. scripts/ratchets.sh refuses
//! that count at run time; this refuses the line itself, in the suite, where a rename is
//! made: every target is a test target of this crate, every named test is a `#[test]`
//! function of that target's file, and no line appears twice.

use std::collections::BTreeSet;
use std::path::Path;

/// The `#[test]` functions of one source file: the name after the `fn` that follows each
/// `#[test]` attribute.
fn test_functions(path: &Path) -> BTreeSet<String> {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let mut out = BTreeSet::new();
    let mut after_attribute = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "#[test]" {
            after_attribute = true;
            continue;
        }
        if after_attribute {
            if let Some(rest) = line
                .strip_prefix("fn ")
                .or_else(|| line.split_once(" fn ").map(|(_, r)| r))
            {
                if let Some(name) = rest.split('(').next() {
                    out.insert(name.trim().to_owned());
                }
                after_attribute = false;
            } else if !line.starts_with("#[") && !line.starts_with("//") && !line.is_empty() {
                after_attribute = false;
            }
        }
    }
    out
}

/// The file a lib or bin test path's module lives in: `compile::tests::x` is in
/// `src/compile.rs` (or `src/compile/mod.rs`); a bin path is in `src/main.rs`.
fn file_of(root: &Path, target: &str, path: &str) -> Option<std::path::PathBuf> {
    match target {
        "bin" => Some(root.join("src/main.rs")),
        "lib" => {
            let module = path.split("::").next()?;
            [format!("src/{module}.rs"), format!("src/{module}/mod.rs")]
                .into_iter()
                .map(|p| root.join(p))
                .find(|p| p.is_file())
        }
        test => Some(root.join(format!("tests/{test}.rs"))).filter(|p| p.is_file()),
    }
}

#[test]
fn every_ratchet_the_list_names_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let list =
        std::fs::read_to_string(root.join("tests/ratchets.txt")).expect("tests/ratchets.txt");
    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    let mut lines = 0usize;
    for line in list.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        lines += 1;
        let Some((target, test)) = line.split_once('\t') else {
            problems.push(format!("{line:?}: not 'target<TAB>test'"));
            continue;
        };
        if !seen.insert(line) {
            problems.push(format!("{line:?}: named twice"));
        }
        // `*<TAB>count` for a whole target, whose count is its file's number of tests.
        let (test, count) = match test.split_once('\t') {
            Some((star, count)) => (star, Some(count)),
            None => (test, None),
        };
        let Some(file) = file_of(root, target, test) else {
            problems.push(format!("{line:?}: no source file for target {target:?}"));
            continue;
        };
        if test == "*" {
            let found = test_functions(&file).len();
            match count.map(str::parse::<usize>) {
                Some(Ok(n)) if n == found && n > 0 => {}
                Some(Ok(n)) => problems.push(format!(
                    "{line:?}: {} holds {found} #[test], the line says {n}",
                    file.display()
                )),
                _ => problems.push(format!("{line:?}: a `*` line carries its test count")),
            }
            continue;
        }
        if count.is_some() {
            problems.push(format!("{line:?}: only a `*` line carries a count"));
        }
        let name = test.rsplit("::").next().unwrap_or(test);
        if !test_functions(&file).contains(name) {
            problems.push(format!(
                "{line:?}: no #[test] fn {name} in {}",
                file.display()
            ));
        }
    }
    assert!(lines > 0, "tests/ratchets.txt names no ratchet");
    assert!(
        problems.is_empty(),
        "tests/ratchets.txt:\n{}",
        problems.join("\n")
    );
    eprintln!("ratchets: {lines} lines, each naming a test that exists");
}

/// Every `chard measure` that `tests/fake_driver.rs` starts carries `PROBE_DEADLINE`:
/// those tests compare readings across runs, and a run whose probe reached chard's
/// 5 s default on a busy host withholds a reading the other run made, which failed the merge
/// gate once with nothing wrong in the change. Held here, beside the ratchet list, so a new
/// measurement added without it fails in seconds.
#[test]
fn every_fake_driver_measurement_runs_under_the_long_probe_deadline() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text =
        std::fs::read_to_string(root.join("tests/fake_driver.rs")).expect("tests/fake_driver.rs");
    let lines: Vec<&str> = text.lines().collect();
    let mut sites = 0usize;
    let mut bare = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("//") || !line.contains("\"measure\"") {
            continue;
        }
        sites += 1;
        // Two shapes: `.arg("measure")` and the next line `.args(PROBE_DEADLINE)`, or an
        // argument list whose `"measure"` is followed by the deadline's two words. Any other
        // line naming "measure" fails here, so a new shape is held or named, not missed.
        let next = lines.get(i + 1).copied().unwrap_or("");
        let listed = line.contains("OsStr::new(\"measure\")")
            && next.contains("PROBE_DEADLINE[0]")
            && lines
                .get(i + 2)
                .is_some_and(|l| l.contains("PROBE_DEADLINE[1]"));
        let chained = line.contains(".arg(\"measure\")")
            && (line.contains(".args(PROBE_DEADLINE)")
                || next.trim_start().starts_with(".args(PROBE_DEADLINE)"));
        if !(listed || chained) {
            bare.push(format!("tests/fake_driver.rs:{}: {}", i + 1, line.trim()));
        }
    }
    assert!(
        sites > 0,
        "no `.arg(\"measure\")` in tests/fake_driver.rs: the ratchet reads nothing"
    );
    assert!(
        bare.is_empty(),
        "measurements without `.args(PROBE_DEADLINE)` on the next line:\n{}",
        bare.join("\n")
    );
    eprintln!("fake_driver: {sites} measurements, each under the long probe deadline");
}
