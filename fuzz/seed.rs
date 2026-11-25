// SPDX-License-Identifier: BSD-3-Clause
//! Seeds for the input shapes the fuzzers do not find from a report alone, written into
//! the ignored corpus by `make fuzz-seed`.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};

/// Every string under a `stderr` key in `value` that carries a `runs` key, in document order.
fn sarif_stderrs<'a>(value: &'a Value, found: &mut Vec<&'a str>) {
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                match v {
                    Value::String(s) if key == "stderr" && s.contains("\"runs\"") => found.push(s),
                    _ => sarif_stderrs(v, found),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|v| sarif_stderrs(v, found)),
        _ => {}
    }
}

/// Write each SARIF stderr of the fixtures into `dir`, once by content, and hold each to
/// decode to findings with SARIF's levels. `None` where one does not, naming it.
#[expect(
    clippy::expect_used,
    reason = "the seed writer is a dev tool make fuzz-seed runs: an I/O failure stops it naming what it was doing, and make fails as on exit 1"
)]
fn seed_sarif(rows: &[Value], dir: &Path) -> Option<usize> {
    let mut found = Vec::new();
    for row in rows {
        sarif_stderrs(row, &mut found);
    }
    std::fs::create_dir_all(dir).expect("creating a corpus directory");
    let mut written = BTreeSet::new();
    for stderr in &found {
        let findings = chard::structured::decode(stderr).unwrap_or_default();
        if findings.is_empty()
            || !findings
                .iter()
                .all(|f| ["error", "warning", "note", "none"].contains(&f.level.as_str()))
        {
            eprintln!("seed: a fixture's SARIF stderr reads as {findings:?}: {stderr}");
            return None;
        }
        let mut digest = chard::digest::sha256_hex(stderr.as_bytes());
        digest.truncate(16);
        let name = format!("fixture-{digest}");
        if written.insert(name.clone()) {
            std::fs::write(dir.join(name), stderr).expect("writing a seed");
        }
    }
    (!written.is_empty()).then_some(written.len())
}

#[expect(
    clippy::expect_used,
    reason = "the seed writer is a dev tool make fuzz-seed runs: an I/O failure stops it naming what it was doing, and make fails as on exit 1"
)]
fn write(dir: &Path, name: &str, value: &Value) {
    std::fs::create_dir_all(dir).expect("creating a corpus directory");
    let bytes = serde_json::to_vec(value).expect("a seed serializes");
    std::fs::write(dir.join(name), bytes).expect("writing a seed");
}

/// `report` without what `table` and `matrix` do not read: the fact store, the decoders,
/// and each observation's controls, build and run records and every evidence field but
/// `observed`. A whole report runs to hundreds of kilobytes, and libFuzzer cuts any input
/// above 1048576 bytes when `-max_len` is not given (cargo-fuzz 0.13.1 and 0.13.2, 2026-09-29),
/// so a set of three joined whole was cut short, parsed as nothing, and reached none of
/// the paths it was written for.
fn slim(report: &Value) -> Value {
    let mut slim = report.clone();
    if let Some(map) = slim.as_object_mut() {
        for key in [
            "facts",
            "decoders",
            "evidence_filters",
            "structured_diagnostics",
        ] {
            map.remove(key);
        }
    }
    if let Some(observations) = slim.get_mut("observations").and_then(Value::as_array_mut) {
        for o in observations {
            if let Some(map) = o.as_object_mut() {
                for key in ["controls", "build", "run"] {
                    map.remove(key);
                }
                if let Some(observed) = map.get("evidence").and_then(|e| e.get("observed")).cloned()
                {
                    map.insert("evidence".to_owned(), json!({ "observed": observed }));
                }
            }
        }
    }
    slim
}

/// `text` with the digits after every `marker` replaced by `NORMALIZED_READING`, as
/// `report::normalize` replaces them; `None` where no marker is followed by a digit.
fn mask_reading(text: &str, marker: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut masked = false;
    while let Some((before, after)) = rest.split_once(marker) {
        out.push_str(before);
        out.push_str(marker);
        let tail = after.trim_start_matches(|c: char| c.is_ascii_digit());
        if tail.len() != after.len() {
            out.push_str(chard::report::NORMALIZED_READING);
            masked = true;
        }
        rest = tail;
    }
    out.push_str(rest);
    masked.then_some(out)
}

/// Every string under `value` masked at `marker`; whether any was.
fn mask_strings(value: &mut Value, marker: &str) -> bool {
    match value {
        Value::String(text) => match mask_reading(text, marker) {
            Some(masked) => {
                *text = masked;
                true
            }
            None => false,
        },
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |any, v| mask_strings(v, marker) | any),
        Value::Object(map) => map
            .values_mut()
            .fold(false, |any, v| mask_strings(v, marker) | any),
        _ => false,
    }
}

/// `record` as a normalized report carries it: every `VOLATILE_READINGS` value of its check
/// masked. `None` for a record whose check has none, or whose text holds no value to mask.
fn normalized(record: &Value) -> Option<Value> {
    let check = record["check"].as_str()?;
    let mut copy = record.clone();
    let mut masked = false;
    for reading in chard::report::VOLATILE_READINGS
        .iter()
        .filter(|r| r.check == check)
    {
        masked |= mask_strings(&mut copy, reading.marker);
    }
    masked.then_some(copy)
}

/// A normalized record with the first `ratio_pct=` value of each of its strings set to 0;
/// `None` where it has none.
fn masked_with_zero_ratio(masked: &Value) -> Option<Value> {
    fn zero(value: &mut Value) -> bool {
        match value {
            Value::String(text) => {
                let Some((before, after)) = text.split_once("ratio_pct=") else {
                    return false;
                };
                let tail = after.trim_start_matches(|c: char| c.is_ascii_digit());
                *text = format!("{before}ratio_pct=0{tail}");
                true
            }
            Value::Array(items) => items.iter_mut().fold(false, |any, v| zero(v) | any),
            Value::Object(map) => map.values_mut().fold(false, |any, v| zero(v) | any),
            _ => false,
        }
    }
    let mut copy = masked.clone();
    zero(&mut copy).then_some(copy)
}

/// Copies every `*.elf` in `fixtures` into `dir`, and how many it copied.
#[expect(
    clippy::expect_used,
    reason = "the seed writer is a dev tool make fuzz-seed runs: an I/O failure stops it naming what it was doing, and make fails as on exit 1"
)]
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the fixtures are told by the bytes of their names, so a file named .elf alone is copied and counted"
)]
fn seed_elf_fixtures(fixtures: &Path, dir: &Path) -> usize {
    let Ok(listing) = std::fs::read_dir(fixtures) else {
        eprintln!("seed: {} is not a readable directory", fixtures.display());
        return 0;
    };
    std::fs::create_dir_all(dir).expect("creating a corpus directory");
    let mut copied = 0usize;
    for entry in listing {
        let path = entry.expect("listing the ELF fixtures").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.ends_with(".elf") {
            std::fs::copy(&path, dir.join(format!("fixture-{name}"))).expect("copying a fixture");
            copied += 1;
        }
    }
    copied
}

/// Every object under `value` that carries a `digest_kind`, as `--image-attestation` takes
/// it: the two keys a report adds to a published block taken off.
fn attestations_in(value: &Value, found: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("digest_kind") {
                let mut bare = map.clone();
                bare.remove("status");
                bare.remove("established_by");
                found.push(Value::Object(bare));
            }
            map.values().for_each(|v| attestations_in(v, found));
        }
        Value::Array(items) => items.iter().for_each(|v| attestations_in(v, found)),
        _ => {}
    }
}

/// Writes `value` into `dir` named by its digest, so the same attestation is one seed.
#[expect(
    clippy::expect_used,
    reason = "the seed writer is a dev tool make fuzz-seed runs: an I/O failure stops it naming what it was doing, and make fails as on exit 1"
)]
fn write_by_content(dir: &Path, value: &Value) -> bool {
    let bytes = serde_json::to_vec(value).expect("a seed serializes");
    let mut digest = chard::digest::sha256_hex(&bytes);
    digest.truncate(16);
    let name = format!("att-{digest}.json");
    let path = dir.join(name);
    if path.exists() {
        return false;
    }
    std::fs::create_dir_all(dir).expect("creating a corpus directory");
    std::fs::write(path, bytes).expect("writing a seed");
    true
}

/// The fixed attestation seeds: each digest kind, an installed disk, the older shape, no
/// manifest, a mismatch.
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "each seed is a copy of the object json! builds above, and setting a key of an object adds it"
)]
fn attestation_seeds(dir: &Path) -> usize {
    let mut written = 0;
    for (kind, length) in [
        ("md5", 32),
        ("sha1", 40),
        ("sha256", 64),
        ("sha384", 96),
        ("sha512", 128),
        ("blake2b", 128),
    ] {
        let digest: String = "0123456789abcdef".chars().cycle().take(length).collect();
        let base = json!({
            "verdict": "signature-verified",
            "url": "https://example.invalid/image.qcow2",
            "served_by": "example.invalid",
            "origin": "recorded-at-fetch",
            "manifest_url": "https://example.invalid/SHA256SUMS",
            "digest_kind": kind,
            "digest": digest,
            "digest_matched": true,
            "manifest_fetched": true,
            "signature": "gpg",
            "signer": "0000000000000000000000000000000000000000",
            "caveat": "a seed",
        });
        written += usize::from(write_by_content(dir, &base));
        let mut disk = base.clone();
        disk["installed_disk"] = json!({
            "sha256": "f".repeat(64),
            "installed_at": "2024-02-29T23:59:59Z",
            "installed_from_digest": digest,
        });
        written += usize::from(write_by_content(dir, &disk));
        if kind == "sha256" {
            let mut older = base.clone();
            let map = older.as_object_mut().expect("an object");
            map.remove("origin");
            map.remove("manifest_fetched");
            map.insert("signer".to_owned(), Value::Null);
            map.insert("caveat".to_owned(), Value::Null);
            written += usize::from(write_by_content(dir, &older));
            let mut unfetched = base.clone();
            unfetched["digest_matched"] = json!(false);
            unfetched["manifest_fetched"] = json!(false);
            written += usize::from(write_by_content(dir, &unfetched));
            let mut mismatch = base.clone();
            mismatch["digest_matched"] = json!(false);
            written += usize::from(write_by_content(dir, &mismatch));
        }
    }
    written
}

/// `seed --attestations <corpus-dir> <file>...`. Whether every file named was read and at
/// least one attestation found: a mistyped glob in `FUZZ_SEED_ATTESTATIONS`, a file that is
/// not JSON, or files with no attestation in them seed nothing, and that is a failure rather
/// than a count line on the way to exit 0.
fn seed_attestations(corpus: &str, files: &[String]) -> bool {
    let dir = Path::new(corpus).join("attestation");
    let (mut read, mut found, mut written) = (0usize, 0usize, 0usize);
    for path in files {
        let Some(value) = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        else {
            eprintln!("seed: {path} is not readable JSON, skipped");
            continue;
        };
        read += 1;
        let mut all = Vec::new();
        attestations_in(&value, &mut all);
        found += all.len();
        written += all.iter().filter(|a| write_by_content(&dir, a)).count();
    }
    eprintln!(
        "seed: {read} of {} file(s) read, {found} attestation(s) found, {written} new into {}",
        files.len(),
        dir.display()
    );
    !files.is_empty() && read == files.len() && found > 0
}

#[expect(
    clippy::expect_used,
    reason = "the seed writer is a dev tool make fuzz-seed runs: an I/O failure stops it naming what it was doing, and make fails as on exit 1"
)]
#[expect(
    clippy::too_many_lines,
    reason = "the seeding's steps in sequence, each one's counts read by the summary line at its end"
)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, corpus, files @ ..] = args.as_slice()
        && flag == "--attestations"
    {
        if !seed_attestations(corpus, files) {
            eprintln!("seed: expected every file named read and an attestation found");
            std::process::exit(1);
        }
        return;
    }
    let [corpus, fixtures, elf_fixtures, reports @ ..] = args.as_slice() else {
        eprintln!("usage: seed <corpus-dir> <rows.json> <elf-fixture-dir> <report.json>...");
        std::process::exit(2);
    };
    let corpus = Path::new(corpus);
    let elf_dir = corpus.join("elf_parse");
    let elves = seed_elf_fixtures(Path::new(elf_fixtures), &elf_dir);
    eprintln!(
        "seed: {elves} ELF fixture(s) of {elf_fixtures} into {}",
        elf_dir.display()
    );
    if elves == 0 {
        eprintln!("seed: expected at least one ELF fixture");
        std::process::exit(1);
    }
    let detect = corpus.join("detect_evidence");
    let render = corpus.join("report_render");
    let macros = corpus.join("parse_macros");
    let attestation_dir = corpus.join("attestation");
    let mut attestations = attestation_seeds(&attestation_dir);

    let rows: Vec<Value> =
        serde_json::from_slice(&std::fs::read(fixtures).expect("reading the fixtures"))
            .expect("the fixtures parse");
    let sarif_dir = corpus.join("structured_diag");
    let Some(sarif) = seed_sarif(&rows, &sarif_dir) else {
        eprintln!("seed: expected every SARIF stderr of the fixtures to decode, and at least one");
        std::process::exit(1);
    };
    let mut seen = BTreeSet::new();
    let mut records = 0usize;
    let mut normal = 0usize;
    let mut zero_ratio = None;
    for row in &rows {
        let key = (
            row["check"].as_str().unwrap_or_default().to_owned(),
            row["arm"].as_str().unwrap_or("measured").to_owned(),
            row["expected"].as_str().unwrap_or_default().to_owned(),
        );
        if seen.insert(key) {
            write(&detect, &format!("record-{records:04}.json"), row);
            records += 1;
            if let Some(masked) = normalized(row) {
                write(
                    &detect,
                    &format!("record-normalized-{normal:04}.json"),
                    &masked,
                );
                normal += 1;
                if zero_ratio.is_none() {
                    zero_ratio = masked_with_zero_ratio(&masked);
                }
            }
        }
    }
    // `detect_stack_clash` withholds a normalized distance beside a ratio of 0, which could
    // have been `dist=0`; no fixture prints that ratio.
    if let Some(zero) = &zero_ratio {
        write(&detect, "record-normalized-ratio-0.json", zero);
        normal += 1;
    }
    if normal == 0 || zero_ratio.is_none() {
        eprintln!(
            "seed: no fixture record's run printed a reading report::VOLATILE_READINGS names, \
             so no normalized record was written"
        );
        std::process::exit(1);
    }

    let mut loaded = Vec::new();
    let mut entries = 0usize;
    let mut dumps = 0usize;
    for (i, path) in reports.iter().enumerate() {
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("seed: {path} is not readable, skipped");
            continue;
        };
        let Ok(report) = serde_json::from_slice::<Value>(&bytes) else {
            eprintln!("seed: {path} is not JSON, skipped");
            continue;
        };
        // A report is an object.
        if !report.is_object() {
            eprintln!("seed: {path} is JSON but not an object, so it is no report");
            std::process::exit(1);
        }
        if let Some(store) = report.get("facts").and_then(Value::as_object) {
            let mut kinds = BTreeSet::new();
            for (key, entry) in store {
                if let Some(defines) = entry["macros"].as_object()
                    && entry["kind"] == "macro-dump"
                {
                    let text = defines
                        .iter()
                        .fold(String::new(), |mut text, (name, value)| {
                            text.push_str("#define ");
                            text.push_str(name);
                            text.push(' ');
                            text.push_str(value.as_str().unwrap_or_default());
                            text.push('\n');
                            text
                        });
                    std::fs::create_dir_all(&macros).expect("creating a corpus directory");
                    // The first 16 characters, not bytes: the key is the report's, and a
                    // byte offset inside a character would panic.
                    let prefix: String = key.chars().take(16).collect();
                    let name = format!("dump-{prefix}.txt");
                    std::fs::write(macros.join(name), text).expect("writing a seed");
                    dumps += 1;
                }
                let kind = entry["kind"].as_str().unwrap_or_default().to_owned();
                if kinds.insert(kind.clone()) {
                    write(&detect, &format!("entry-{i}-{kind}.json"), entry);
                    entries += 1;
                    if kind == "elf" {
                        write(
                            &detect,
                            &format!("elf-output-{i}.json"),
                            &json!({ "a.out": entry["elf"] }),
                        );
                        entries += 1;
                    }
                }
            }
        }
        let mut found = Vec::new();
        if let Some(environment) = report.get("environment") {
            attestations_in(environment, &mut found);
        }
        for attestation in &found {
            attestations += usize::from(write_by_content(&attestation_dir, attestation));
        }
        if let Some(block) = report
            .pointer("/environment/execution/image_attestation")
            .and_then(Value::as_object)
            .filter(|b| b.contains_key("digest_kind"))
        {
            attestations += usize::from(write_by_content(
                &attestation_dir,
                &Value::Object(block.clone()),
            ));
        }
        write(&render, &format!("report-{i}.json"), &report);
        loaded.push(report);
    }
    if loaded.len() > 1 {
        let loaded: Vec<Value> = loaded.iter().map(slim).collect();
        write(
            &render,
            "reports-joined.json",
            &Value::Array(loaded.clone()),
        );
        // The same set with one report from another corpus and revision: what the
        // dataset identity refuses to join without `--allow-mixed`, and the only way its
        // conflict and decoder-movement paths are reached from a single sweep.
        let mut mixed = loaded.clone();
        #[expect(
            clippy::indexing_slicing,
            reason = "loaded holds more than one report here, each an object, since the load refuses any other JSON; setting a key of an object adds it"
        )]
        let other = &mut mixed[1]["run"];
        other["probe_corpus_sha256"] = json!("0".repeat(64));
        other["decoders_sha256"] = json!("1".repeat(64));
        other["harness_revision"] = json!("0000000");
        write(&render, "reports-mixed.json", &Value::Array(mixed));
    }
    eprintln!(
        "seed: {records} record(s), {normal} normalized, and {entries} store-entry or chard-elf seed(s) into {}; \
         {} report(s) and {} joined set into {}; {dumps} macro-dump entr(ies) into {}; \
         {attestations} attestation(s) into {}; {sarif} SARIF stderr(s) into {}",
        detect.display(),
        loaded.len(),
        usize::from(loaded.len() > 1),
        render.display(),
        macros.display(),
        attestation_dir.display(),
        sarif_dir.display()
    );
}
