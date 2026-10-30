// SPDX-License-Identifier: BSD-3-Clause

//! A ratchet on the constructors that build an error the envelope cannot classify.
//!
//! `error::classify` reads types. An error built with `bail!`, `anyhow!` or `ensure!` has
//! none, so it lands in the last arm as `INTERNAL`, which tells the caller to file a bug.
//! That is the right answer for a defect in chard and the wrong one for everything else: a
//! text file handed to `chard elf`, an empty object handed to `chard table`, or a compiler
//! the kernel cannot load. Each of those constructs a typed error where the failure happens.
//!
//! The inventory below is the sites that are internal by intent, and `src/error.rs`'s
//! module doc names each with its reason. A file whose count rises has to say in review
//! which of the five classes the new error belongs to, next to the diff; if the answer is
//! `INTERNAL`, the site joins the inventory with its reason, and if it is anything else,
//! the site builds the typed error for it. Same mechanism as `tests/discarded_failures.rs`,
//! and the same honesty about being a tripwire rather than a proof.

use std::path::Path;

mod common;

/// The constructors that make an `anyhow::Error` from a message alone.
///
/// `.context(..)` is not scanned. On a `Result` it layers a message over a root that keeps
/// its type, which is the shape this file exists to encourage; on an `Option` it is an
/// untyped constructor of exactly the kind counted here, and a text scan cannot tell the
/// two apart. An `Option::context` site is therefore reviewed by eye, and `src/` holds
/// none today.
const CONSTRUCTORS: &[&str] = &["bail!(", "anyhow!(", "ensure!("];

/// Per-file counts as of the change that typed the reader's refusals and the driver's
/// spawn failures.
///
/// `compile.rs`: a child whose pipes were not the ones configured, a child whose pipes
/// were still held after it exited, a reader thread that panicked, and a child that did
/// not finish within the bound. The first three are defects in the capture itself; the
/// fourth reaches the envelope only from a driver that hung on its own interrogation, and
/// a driver that hangs on `--version` hangs again, so the retry `TRANSIENT` promises is a
/// class it has not earned. A fifth: the run's `--env` pairs set after a toolchain
/// invocation read them, which `measure` setting them at the door rules out, so one
/// reaching the envelope is a defect in chard. `matrix.rs`: a build over no reports, which
/// clap keeps off the command line with `required = true`. `error.rs`: the two tests that pin the
/// default arm each build one bare `anyhow!` on purpose.
const INVENTORY: &[(&str, usize)] = &[("compile.rs", 5), ("error.rs", 2), ("matrix.rs", 1)];

/// Count the constructors in `source`, ignoring comment lines.
///
/// Comments are stripped because `error.rs` and this file discuss the constructors by
/// name, and prose about a hazard is not an instance of it.
fn count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            CONSTRUCTORS
                .iter()
                .map(|c| line.matches(c).count())
                .sum::<usize>()
        })
        .sum()
}

#[test]
fn untyped_error_constructors_do_not_multiply_unnoticed() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut scanned = 0usize;
    let mut actual: Vec<(String, usize)> = Vec::new();
    for (name, path) in common::rust_sources(&src) {
        scanned += 1;
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let n = count(&source);
        if n > 0 {
            actual.push((name, n));
        }
    }
    actual.sort();

    // The frame, printed rather than inferred: a scan over no files would satisfy every
    // comparison below by having nothing to compare. Seventeen modules sit under `src/`
    // as of this test's writing, and the floor is set so a scan that reached a stray
    // subset of them fails here rather than in a comparison it never made.
    let total: usize = actual.iter().map(|(_, n)| n).sum();
    eprintln!("{total} untyped error constructors across {scanned} modules scanned");
    assert!(
        scanned >= INVENTORY.len() && scanned >= 15,
        "scanned {scanned} modules: the scan is not reaching the tree it is meant to check"
    );

    let mut grew = Vec::new();
    let mut shrank = Vec::new();
    for (name, n) in &actual {
        let known = INVENTORY
            .iter()
            .find(|(f, _)| f == name)
            .map_or(0, |(_, k)| *k);
        if *n > known {
            grew.push(format!("  {name}: {known} -> {n}"));
        } else if *n < known {
            shrank.push(format!("  {name}: {known} -> {n}"));
        }
    }
    for (name, known) in INVENTORY {
        if !actual.iter().any(|(f, _)| f == name) {
            shrank.push(format!("  {name}: {known} -> 0"));
        }
    }

    assert!(
        grew.is_empty(),
        "new errors built from a message alone, which the envelope can only report as \
         INTERNAL:\n{}\n\n\
         If the failure is the caller's, build a `UserError` with a hint; if it is worth \
         retrying, a `TransientError`; if it is an unusable invocation, a `ConfigError`; \
         if the reader refused an object, an `ElfError` variant. If it really is a defect \
         in chard, add the site to INVENTORY here and to the list in `src/error.rs`'s \
         module doc, with its reason.",
        grew.join("\n")
    );

    assert!(
        shrank.is_empty(),
        "these files now hold fewer than the inventory records:\n{}\n\n\
         Bank it by lowering the count, so the inventory keeps meaning what it says.",
        shrank.join("\n")
    );
}
