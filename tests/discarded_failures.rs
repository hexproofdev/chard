// SPDX-License-Identifier: BSD-3-Clause

//! A ratchet on the constructs that turn a failure into a value.
//!
//! Each construct below makes something that can fail produce a plausible value instead, and
//! the value is published.
//!
//! - `_ => "discriminating"`: a witness that returns `indeterminate` claims chard's artifact
//!   reader has been validated.
//! - `reader != "probe-invalid"`: a gate stated as a negation over an open set of states lets
//!   `absent` pass.
//! - `continue`: a timed-out package query leaves up to 256 files reported `unowned`.
//! - `elf::facts_for(..).ok()`: an unreadable artifact reports `build-failed` beside a build
//!   record with `exit_status: 0`.
//! - `String::new()`: an unreadable output stream becomes "the probe printed nothing", which
//!   on the runtime channel is a measurement.
//! - `is_some_and(|d| d.outcome == Present)`: a regime control that cannot be evaluated reads
//!   as "no confounding found".
//! - `unwrap_or_default()`: a summary that has lost its fields satisfies `0+0+0+0 == 0`.
//! - `.ok()` on `sufficient_for`: an arm that is required and fails becomes indistinguishable
//!   from one that is never required.
//! - no filter at all: objects that cannot answer a question are counted as answering
//!   `false`, and two commands publish rates 57 points apart.
//!
//! Finding another construct of this shape by reading costs a reading of every file each time.
//!
//! # Why a ratchet and not a lint
//!
//! What makes these defects is not the construct; it is the construct on a path whose
//! value reaches a published field. `parse::<u32>().ok()` inside an `and_then`, where
//! `None` is the honest answer to "is this a number", is fine and there are dozens of
//! them. No lint available here can tell the two apart, and dataflow analysis to do it
//! properly is a larger project than chard.
//!
//! Demanding a justifying comment on all of them was the other option and is worse: most
//! are benign, so the comments would be filler, and filler is how a reader stops reading
//! them.
//!
//! So this counts rather than judges. The inventory below is what the tree holds. A file
//! whose count rises has to say why in review,
//! next to the diff, where someone can see whether the new one is a parse or a
//! measurement. That is the same mechanism `the_corpus_is_the_size_it_is_published_as`
//! and `every_spawn_site_sits_where_something_bounds_it` already use, and it is honest
//! about being a tripwire rather than a proof.

use std::path::Path;

mod common;

/// Constructs that convert "this failed" into "here is a value".
///
/// `?` and `let ... else` are deliberately absent: both propagate rather than substitute,
/// which is the behaviour this file exists to encourage.
const CONSTRUCTS: &[&str] = &[
    ".ok()",
    "unwrap_or_default()",
    "unwrap_or(false)",
    "unwrap_or(0)",
];

/// Per-file counts of the constructs.
///
/// A table that describes a tree with modules this one lacks refuses the run, rather than
/// quietly comparing against a shape that does not exist, which is what it is for.
///
/// Not a budget to spend. A number that goes up is a question to answer, and a number
/// that goes down should be banked by editing this table, so the inventory keeps meaning
/// what it says.
const INVENTORY: &[(&str, usize)] = &[
    ("composite.rs", 3),
    ("dataset.rs", 1),
    // decode/runtime.rs: `detect_stack_clash` reads `ratio_pct` with `parse::<u32>().ok()`,
    // `auto_var_init_fill` reads its witness and its three bytes with
    // `from_str_radix(..).ok()`, `detect_strict_flex_arrays` reads each bound with
    // `parse().ok()`, and `zipb_reading` reads its two bytes the same way. Each `None` is "the
    // probe printed no number here", and each detector turns it into `indeterminate` quoting
    // the stream it could not read. `zcur_reading` reads the probe's `args=` count with
    // `parse().ok()`. `None` is "the probe printed no count", and
    // `detect_zero_call_used_regs` turns it into `indeterminate` quoting the stream.
    // `library_without_subobject_bounds` reads the self-report's `_FORTIFY_SOURCE` with
    // `parse::<u32>().ok()`. `None` is "the request is not a whole number", which is not a
    // request of 2 or more, and the detector then withholds. `shadow_stack_reading` reads the
    // probe's `features=` word with `from_str_radix(..).ok()`. `None` is "the probe printed no
    // number", and `detect_shadow_stack` turns it into `indeterminate` quoting the stream,
    // while `machine_lacks_shadow_stack` declines to fire. The ninth is
    // `library_without_subobject_bounds`'s read of the self-report's `__FreeBSD__`, where a
    // major that is not a number names no release below 15 and the arm declines.
    ("decode/runtime.rs", 9),
    // decode/runtime_tests.rs: `c_integer`, in the test that reads the probe sources for a
    // bare exit status, reads a C integer literal with `from_str_radix(..).ok()`. `None` is
    // "this token is not a number", and the token is then not a status the scan reports.
    ("decode/runtime_tests.rs", 1),
    // detect.rs: `chard detect` replays code decoders (`replay_code`), and none of the first
    // three is a failure: an artifact whose `.chard.report` carries no macros is the empty map
    // `measure` hands such a probe; a site whose build names no artifact publishes an empty
    // `facts_key`, which the detect schema describes; and a site that states nothing beside
    // its reading publishes an empty `published.outcome`, with `agrees` then resting on no
    // restatement. A record that does not read, or an artifact key the store does not
    // resolve, is refused as unusable input rather than defaulted. The fourth is
    // `self_reported`'s `self_report_entries(elf).ok()`: the `Err` is the artifact's way of
    // giving no account, and `None` is what `measure::Gatherer::gather` hands the predicate
    // for the same artifact, so the two readers agree; the absence itself is published by
    // `measure` as a withheld verdict, not by `detect`.
    ("detect.rs", 4),
    ("digest.rs", 1),
    // elf.rs: `feature_word` answers 0 for a note type this machine does not define before
    // it looks the type up, and the lookup's absent case is a `map_or` inside it. The
    // substituted 0 is the honest reading: no note carrying the word is no feature marked. A
    // table with no name is labelled by its section type, through a `match` with no discard
    // in it. A property word the file does not hold, a string offset that does not fit a
    // `u32`, and a symbol table below one entry or with a trailing partial one are each a
    // recorded stop (`notes`, `dynstr`, `symbols`), never a substituted value.
    ("elf.rs", 4),
    // env.rs, and the answer to the question the count asks: `platform_reads` discards the
    // `Err` from each host-instrument read, and the substituted `None` is the honest reading
    // rather than a value that can pass for data. It is the parse case this file names:
    // `None` means the instrument did not answer, which is exactly what the report goes on
    // to say. `unwrap_or_default()` on `/etc/os-release` and `/proc/cpuinfo` would be worse,
    // since the substituted empty string is indistinguishable from a file that read empty.
    // The FreeBSD arm of `platform_reads` reads `/etc/os-release` and discards the `Err` the
    // same way the Linux arm does. `None` is the honest reading, since the file is absent on
    // some images, and `distro_from` distinguishes it from a file that parsed to nothing.
    // The macOS arm reads `SystemVersion.plist`, that platform's `os-release`, and discards
    // the `Err` exactly as the two arms above do. `None` is the honest reading and lands in
    // the `unknown`/`unknown` distro, so a wrong path or an unreadable file degrades to that
    // answer rather than a fabricated one. `read_uid_map` parses each field of a uid-map line
    // as a `u32` through `.ok()`. `None` is the parse case this file names, "not a number",
    // and it is not substituted: the line makes the whole read `UidMap::Malformed`, which
    // settles nothing and is published as a map that is not three numbers to a line.
    ("env.rs", 9),
    // fixture.rs: `recorded_elf` names facts that do not parse `Unsaid`, and the observation
    // contributes no fixture. `arm_fixtures` reads an arm's macros through
    // `macro_view(..).unwrap_or_default()`, where `None` is an artifact entry with no macros
    // (refused by the reader, or carrying no `.chard.report`) or no entry for an arm whose
    // decoder reads none: the empty map `measure` handed that arm. A preprocessor dump the
    // store does not hold skips the arm instead.
    ("fixture.rs", 5),
    // main.rs, and two of them are the parse case this file names. `--cxxflags` and
    // `--ldflags` are optional, so `args.cxxflags.as_deref().map(split_flags)` is `None`
    // exactly when the caller did not supply them, and the substituted empty `Vec` is
    // already the published meaning of that: `measure::variant_flags` reads an empty
    // `cxxflags` as "build C++ with the C flags", and `skip_serializing_if` keeps the
    // field out of the report entirely. No `Err` is discarded and no value can pass for
    // one that was measured. The alternative spelling would be a `match` that produces
    // the same `Vec::new()` without being counted here, which is worse. Two are in
    // `measure`'s closing line: `Counts::of` reads a verdict `coverage.verdict_counts` has no
    // key for as `0`, which is what the map's absence of a key means (it counts the verdicts
    // present), and the line's counts are an empty string where the run ended before a
    // report existed. Neither substitutes for an `Err`. The refused report's counts are a
    // second empty string before a report exists, and whether a file is at the report's path
    // before the set-aside reads a metadata error as "none", which no line can then misstate:
    // the set-aside reads the same metadata next and refuses the run on that error, so the
    // run closes as refused before the set-aside and the flag is never read.
    ("main.rs", 6),
    ("matrix.rs", 2),
    // measure.rs: `fortify_level_declined` reads three numbers out of the positive arm's own
    // macros (the level requested, the level that arrived, and the level the C library
    // settled on), and each is `parse().ok()?`. `None` there means "this macro is not a
    // number", which is the honest reading and the one this file's header exempts: the `?`
    // withholds the gating rather than substituting a level, so a macro chard cannot parse
    // leaves the check `probe-invalid` and visible rather than explained away. The negative
    // arms discard their `Err` once, in one `sufficient_for` call. Seven are the work
    // directory claim. Three read what `/proc` says of this process (boot id, pid namespace,
    // start time), and a part it does not give becomes `-`, under which no other run's claim
    // is ever judged gone; one reads a claim's pid, the parse case; one reads a claim's name
    // as UTF-8 and one its owner, and `None` from either makes the claim one this system
    // cannot judge, which refuses the run. None of them reaches a report: each substitution
    // is a refusal or a name. The seventh is the live-holder test reading its parent's start
    // time before an `expect`.
    ("measure.rs", 12),
    // predicate/mod.rs, both the parse case. The integer reading of `chard-predicate/1` is
    // trim, then a base-10 i64, read as `trim().parse::<i64>().ok()`, and `None` there is "no
    // integer reading", under which every comparison is false and a `value` level makes the
    // conclusion `indeterminate`. `i64::try_from(symbol_count).ok()` is `Undefined` for a
    // count past `i64::MAX`, which is what the Published view reads back from the same count
    // serialized, so the two views agree rather than one inventing a number.
    ("predicate/mod.rs", 2),
    // probe.rs, the parse case: `Grade::meets` on a numeric scale reads the level and the ask
    // with `parse::<u32>().ok()?`, and `None` there means "not a whole number". The `?` makes
    // the grade answer `None`, which `report::decide` turns into `indeterminate` carrying the
    // word in `gating.reason` under `level-outside-check-scale`: a withheld verdict with the
    // unparsed word quoted, and nothing substituted for it. `corpus_sha256_of` is an
    // exhaustive `match` on the decoder, which pushes a predicate's canonical form or a code
    // detector's name and substitutes nothing.
    ("probe.rs", 2),
    // report.rs: two are in the store's `elf-delta` kind and neither reaches a published
    // field as a value. `overlay` resolves a delta through serde_json and its `None` means
    // "does not resolve", which `fact-store-disagrees-with-references` names as a
    // contradiction rather than reading as facts. `FactStore::compact_arms` drops a subject
    // whose facts do not serialize from the candidate bases, so an arm with no base stays a
    // whole `elf` entry. `SubobjectSizes::parse` reads the probe's `CHARD-BOS` line with
    // `parse().ok()`, where `None` means a field is not a number, and the gating rule it
    // feeds then declines to fire, so the check keeps its `probe-invalid`.
    // `subobject_bound_lost_in_wrapper` reads the positive arm's `__USE_FORTIFY_LEVEL` with
    // `parse().ok()`, where `None` is the self-report's `?`, and the rule declines, so the
    // check keeps its `probe-invalid`. `fortify_level_agrees` reads a ratchet level that is
    // not a number as a contradiction under its rule, with no discard.
    // `withholding_agrees_as_written` takes the classes the observations wrote with
    // `unwrap_or_default()` where `observations` did not read, a subtree the reread already
    // names as unreadable; the empty map holds each rule id to this build's table, the
    // reading of a report written without the class. Three are each a `None` that keeps a
    // file and says why, never a value that reaches a report: `own_effective_uid` reads
    // `/proc/self/status` with `.ok()?` and its uid field with `parse().ok()`, where `None`
    // keeps every other run's temporary file as "this process's own uid could not be read";
    // and a temporary file's owner is `metadata().ok()`, where `None` keeps it as "its owner
    // could not be read". `not_applicable_disagrees` reads the earned limitations' `by_rule`
    // count for `arch-gated` with `.copied().unwrap_or(0)`, where an absent key is the map's
    // own spelling of zero (`measure` omits a rule no observation carries), never a failure.
    // `fortify_slot_invariants` reads the dump's `_FORTIFY_SOURCE` with `parse::<u32>().ok()`,
    // where `None` is a value that is not a number, under which a bar the driver set is
    // refused: the statement fails closed. The nineteenth is `freebsd_limitation_cause`'s
    // read of `__FreeBSD__`, where a major that is not a number names no release and no
    // cause; the twentieth and twenty-first are `freebsd_gating`'s reads of the release and
    // the settled level, where a value that is not a number is not an instantiated 15 and the
    // gating stands; the twenty-second is `read_coverage`'s read of `coverage` without an
    // older withholding block, where `None` is "the rest of `coverage` does not read either"
    // and the generic unreadable finding is kept beside the older one, so the report reads as
    // contradicting.
    ("report.rs", 22),
    // run.rs: three of four are `FaultReport::parse`, where a field that is not a number
    // (`signal`, `code`, and the hex fields `pc`, `addr`, `word` and `esr`) rejects the
    // whole report line, and the record falls back to its bare signal.
    ("run.rs", 4),
    // toolchain.rs: `detect` reads `-dumpmachine` and `-v` through `answered`, which keeps
    // how each job ended, so a failed job's output is never read as the driver's answer.
    // `FhardenedFortify::refusal` reads the option's and the control's `_FORTIFY_SOURCE` with
    // `parse().ok()`, where `None` is a value that is not a number, and the level then counts
    // as not raised: the dump sets no bar, the library does.
    ("toolchain.rs", 4),
];

/// Count the constructs in `source`, ignoring comment lines.
///
/// Comments are stripped because this file and several modules *discuss* `.ok()` at
/// length, and prose about a hazard is not an instance of it. A block comment's interior
/// lines are not stripped, which is a known imprecision: the codebase uses `//`
/// throughout, and a scanner that tried to parse Rust to be exact would be a second
/// implementation of the thing it is checking.
fn count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            CONSTRUCTS
                .iter()
                .map(|c| line.matches(c).count())
                .sum::<usize>()
        })
        .sum()
}

#[test]
fn discarded_failures_do_not_multiply_unnoticed() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut actual: Vec<(String, usize)> = Vec::new();
    for (name, path) in common::rust_sources(&src) {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let n = count(&source);
        if n > 0 {
            actual.push((name, n));
        }
    }
    actual.sort();

    // The frame, printed rather than inferred: a scan that found no files would
    // otherwise satisfy every comparison below by having nothing to compare.
    let total: usize = actual.iter().map(|(_, n)| n).sum();
    eprintln!(
        "{total} failure-discarding constructs across {} modules",
        actual.len()
    );
    assert!(
        actual.len() >= INVENTORY.len(),
        "scanned {} modules against an inventory of {}: the scan is not reaching the \
         tree it is meant to check",
        actual.len(),
        INVENTORY.len()
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

    assert!(
        grew.is_empty(),
        "new constructs that turn a failure into a value:\n{}\n\n\
         If the new one is a parse — `parse::<u32>().ok()` where `None` honestly means \
         \"not a number\" — raise its count in INVENTORY and move on. If the discarded \
         `Err` means chard could not do something, and the substituted value can reach a \
         published field, it is the defect this file exists to catch: nine of them were \
         found in one review, each reading as a measurement. Propagate the reason \
         instead, or record it in a field of its own the way `Variant::elf_error` and \
         `RunRecord::output_error` do.",
        grew.join("\n")
    );

    assert!(
        shrank.is_empty(),
        "these files now hold fewer than the inventory records:\n{}\n\n\
         Bank it by lowering the count, so the inventory keeps meaning what it says.",
        shrank.join("\n")
    );
}
