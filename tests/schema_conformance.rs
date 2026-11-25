// SPDX-License-Identifier: BSD-3-Clause

//! Every report chard emits must validate against the schema it ships.

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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde_json::Value;

mod common;

use common::chard_binary;
use common::schema::{matches_format, matches_pattern, resolve, validate};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Can this machine run these tests at all? Checked once, at the top of each test.
fn can_run(verifies: &str) -> bool {
    common::require_binary(&chard_binary(), verifies) && common::require_cc(verifies)
}

/// A failure that arrived after [`can_run`] said the machine was capable.
fn cannot_run(reason: &str) -> ! {
    panic!("{reason}, after `can_run` passed");
}

/// Produce a report for `profile`, or refuse to pretend the test ran.
fn report_for(profile: &str, extra: &[&str], workdir: &Path) -> Value {
    let binary = chard_binary();
    if !binary.exists() {
        cannot_run(&format!("{} not built", binary.display()));
    }
    let output = match Command::new(&binary)
        .arg("measure")
        .args(["-o", "-"])
        .arg("--profile")
        .arg(profile)
        .arg("--workdir")
        .arg(workdir)
        .args(extra)
        .output()
    {
        Ok(o) => o,
        Err(e) => cannot_run(&format!("spawning {}: {e}", binary.display())),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => cannot_run(&format!("{profile}: output was not JSON ({e})")),
    };
    if parsed.get("error").is_some() {
        cannot_run(&format!("{profile}: chard reported {}", parsed["error"]));
    }
    parsed
}

fn schema_at(name: &str) -> Value {
    let path = repo_root().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).expect("schema is valid JSON")
}

fn schema() -> Value {
    let path = repo_root().join("schema/chard-report.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).expect("schema is valid JSON")
}

fn assert_conforms(report: &Value, label: &str) {
    let schema = schema();
    let mut errors = Vec::new();
    validate(report, &schema, &schema, "", &mut errors);
    errors.extend(fact_entries_carry_their_kinds_members(report));
    errors.extend(elf_entries_state_their_truncations(report));
    errors.extend(fact_deltas_resolve(report, &schema));
    errors.extend(replay_counts_add_up(report));
    assert!(
        errors.is_empty(),
        "{label}: report does not conform to its own schema ({} problems):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// The members each `facts` kind carries, besides `kind` itself.
const FACT_KIND_MEMBERS: [(&str, &[&str]); 4] = [
    ("elf", &["elf"]),
    ("unreadable", &["error"]),
    ("elf-delta", &["base", "elf_changes"]),
    ("macro-dump", &["defines", "macros_filter", "macros"]),
];

/// The members a `facts` kind may carry beside those [`FACT_KIND_MEMBERS`] names, each
/// omitted where it would be false.
const FACT_KIND_OPTIONAL: [(&str, &[&str]); 1] = [("unreadable", &["mach_o"])];

/// Every `facts` entry carries exactly the members of its kind.
fn fact_entries_carry_their_kinds_members(report: &Value) -> Vec<String> {
    let Some(entries) = report.get("facts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut errors = Vec::new();
    for (key, entry) in entries {
        let kind = entry["kind"].as_str().unwrap_or("");
        let Some((_, members)) = FACT_KIND_MEMBERS.iter().find(|(k, _)| *k == kind) else {
            errors.push(format!(
                "/facts/{key}: kind {kind:?} has no member list here"
            ));
            continue;
        };
        let carried: BTreeSet<&str> = entry
            .as_object()
            .map(|m| {
                m.keys()
                    .map(String::as_str)
                    .filter(|k| *k != "kind")
                    .collect()
            })
            .unwrap_or_default();
        let expected: BTreeSet<&str> = members.iter().copied().collect();
        let optional: BTreeSet<&str> = FACT_KIND_OPTIONAL
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, m)| m.iter().copied().collect())
            .unwrap_or_default();
        let carried: BTreeSet<&str> = carried.difference(&optional).copied().collect();
        if carried != expected {
            errors.push(format!(
                "/facts/{key}: a `{kind}` entry carries {carried:?}, and its kind carries \
                 {expected:?}"
            ));
        }
    }
    errors
}

/// `consistency.replay` counts every reading once: `readings` is `replayed + unresolved`
/// plus the length of `not_replayable`.
fn replay_counts_add_up(report: &Value) -> Vec<String> {
    let Some(replay) = report.get("consistency").and_then(|c| c.get("replay")) else {
        return Vec::new();
    };
    let count = |member: &str| replay[member].as_u64().unwrap_or(0);
    let not_replayable = replay
        .get("not_replayable")
        .and_then(Value::as_array)
        .map_or(0, |list| list.len() as u64);
    let (readings, replayed, unresolved) =
        (count("readings"), count("replayed"), count("unresolved"));
    if readings == replayed + unresolved + not_replayable {
        Vec::new()
    } else {
        vec![format!(
            "/consistency/replay: readings {readings} is not replayed {replayed} + unresolved \
             {unresolved} + not_replayable {not_replayable}"
        )]
    }
}

/// Every `elf` entry of the store carries `truncations`, `[]` included.
fn elf_entries_state_their_truncations(report: &Value) -> Vec<String> {
    let Some(entries) = report.get("facts").and_then(Value::as_object) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|(_, entry)| entry["kind"].as_str() == Some("elf"))
        .filter(|(_, entry)| !entry["elf"]["truncations"].is_array())
        .map(|(key, _)| format!("/facts/{key}/elf: an `elf` entry does not state `truncations`"))
        .collect()
}

/// Every `elf-delta` entry, laid over its base, is an instance of `$defs/elf_facts`.
fn fact_deltas_resolve(report: &Value, schema: &Value) -> Vec<String> {
    let Some(entries) = report.get("facts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let required = member_names(&schema["$defs"]["elf_facts"], "required");
    let mut errors = Vec::new();
    for (key, entry) in entries {
        if entry["kind"].as_str() != Some("elf-delta") {
            continue;
        }
        let base = entry["base"].as_str().unwrap_or("");
        let whole = entries
            .get(base)
            .filter(|b| b["kind"].as_str() == Some("elf"))
            .and_then(|b| b["elf"].as_object());
        let (Some(whole), Some(changes)) = (whole, entry["elf_changes"].as_object()) else {
            errors.push(format!(
                "/facts/{key}: an elf-delta's base {base:?} is not an `elf` entry of this store"
            ));
            continue;
        };
        let mut resolved = whole.clone();
        for (member, value) in changes {
            let emptied = matches!(value, Value::Array(a) if a.is_empty())
                || matches!(value, Value::Object(m) if m.is_empty())
                || matches!(value, Value::Bool(false));
            if emptied && whole.contains_key(member) && !required.contains(member.as_str()) {
                resolved.remove(member);
            } else {
                resolved.insert(member.clone(), value.clone());
            }
        }
        validate(
            &Value::Object(resolved),
            &serde_json::json!({"$ref": "#/$defs/elf_facts"}),
            schema,
            &format!("/facts/{key}/elf_changes"),
            &mut errors,
        );
    }
    errors
}

/// A whole-corpus sweep, produced once per profile and shared.
fn shared_report(profile: &str) -> Value {
    static BARE: OnceLock<Value> = OnceLock::new();
    static TLDR: OnceLock<Value> = OnceLock::new();
    let cell = match profile {
        "bare" => &BARE,
        "openssf-tldr" => &TLDR,
        other => panic!("no shared sweep is kept for profile `{other}`"),
    };
    cell.get_or_init(|| {
        let work = common::Work::new("schema", &format!("shared-{profile}"));
        report_for(profile, &[], work.dir())
    })
    .clone()
}

#[test]
fn a_bare_profile_report_conforms_to_the_schema() {
    if !can_run("that a bare-profile report validates against the schema chard ships") {
        return;
    }
    let report = shared_report("bare");
    assert_conforms(&report, "bare");
}

#[test]
fn a_report_carries_the_builds_revision_source_and_rustflags_digest() {
    if !can_run("that a report carries this build's revision source and rustflags digest") {
        return;
    }
    let report = shared_report("bare");
    let field = |key: &str| report["run"].get(key).and_then(Value::as_str);
    assert_eq!(field("harness_revision"), chard::report::HARNESS_REVISION);
    assert_eq!(
        field("harness_revision_source"),
        chard::report::HARNESS_REVISION_SOURCE
    );
    assert_eq!(
        field("harness_rustflags_sha256"),
        chard::report::HARNESS_RUSTFLAGS_SHA256
    );
    assert_eq!(
        field("harness_revision").is_some(),
        field("harness_revision_source").is_some()
    );
}

#[test]
fn chard_digest_output_conforms_to_the_digest_definition() {
    if !can_run("that chard digest's output validates against the schema chard ships") {
        return;
    }
    let report = shared_report("bare");
    let work = common::Work::new("schema", "digest");
    let path = work.write(
        "report.json",
        &serde_json::to_string(&report).expect("json"),
    );
    let output = Command::new(chard_binary())
        .arg("digest")
        .arg(&path)
        .output()
        .expect("spawning chard");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let digest: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(digest, report["digest"]);
    let schema = schema();
    let definition = resolve("#/$defs/digest", &schema).expect("the schema defines the digest");
    let mut errors = Vec::new();
    validate(&digest, definition, &schema, "", &mut errors);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_new_report_carries_the_compiler_environment_the_schema_leaves_optional() {
    if !can_run("that a report chard writes publishes the compiler environment") {
        return;
    }
    let report = shared_report("bare");
    let environment = &report["profile"]["compiler_environment"];
    assert!(
        environment["passed"].is_array() && environment["set"].is_object(),
        "a new report lacks profile.compiler_environment: {}",
        report["profile"]
    );
    for (name, value) in chard::compile::COMPILER_ENV_PINNED {
        assert_eq!(
            environment["set"][*name].as_str(),
            Some(*value),
            "{environment}"
        );
    }
}

#[test]
fn every_trimmed_macro_map_cites_the_published_filter_and_stays_inside_it() {
    if !can_run("that each macro-channel observation cites the evidence filter it was trimmed to") {
        return;
    }
    let report = shared_report("bare");
    let filter = &report["evidence_filters"]["macros"];
    let digest = filter["sha256"]
        .as_str()
        .expect("the filter carries a digest");
    let names: BTreeSet<&str> = filter["names"]
        .as_array()
        .expect("the filter carries its names")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        u64::try_from(names.len()).ok(),
        filter["size"].as_u64(),
        "the published size is the number of names"
    );

    let mut trimmed = 0usize;
    for obs in report["observations"].as_array().expect("observations") {
        let Some(macros) = obs["evidence"].get("macros").and_then(Value::as_object) else {
            assert!(
                obs["evidence"].get("macros_filter").is_none(),
                "{}: cites a filter with no trimmed map beside it",
                obs["check"]
            );
            continue;
        };
        trimmed += 1;
        assert_eq!(
            obs["evidence"]["macros_filter"].as_str(),
            Some(digest),
            "{}: a trimmed map must cite the filter it was trimmed to",
            obs["check"]
        );
        let outside: Vec<&String> = macros
            .keys()
            .filter(|k| !names.contains(k.as_str()))
            .collect();
        assert!(
            outside.is_empty(),
            "{}: evidence.macros carries names the published filter does not: {outside:?}",
            obs["check"]
        );
    }
    assert!(
        trimmed > 0,
        "no observation carried a trimmed map, so nothing was checked"
    );
    let announced = report["coverage"]["truncations"]
        .as_array()
        .expect("a report that trimmed records a truncation")
        .iter()
        .filter_map(Value::as_str)
        .find(|t| t.starts_with("evidence.macros on "))
        .expect("the trimming is announced");
    assert!(
        announced.contains(&format!("on {trimmed} observation(s)")) && announced.contains(digest),
        "the announcement names the count and the digest: {announced}"
    );
}

#[test]
fn a_bare_optimized_report_conforms_to_the_schema() {
    if !can_run("that a bare-optimized report validates against the schema chard ships") {
        return;
    }
    let work = common::Work::new("schema", "bare-optimized");
    let report = report_for("bare-optimized", &[], work.dir());
    assert_eq!(report["profile"]["id"], "bare-optimized");
    assert_eq!(
        report["profile"]["flags_source"],
        "chard-enabling-condition"
    );
    assert_conforms(&report, "bare-optimized");
}

#[test]
fn an_openssf_tldr_report_conforms_to_the_schema() {
    if !can_run("that an openssf-tldr report validates against the schema chard ships") {
        return;
    }
    let report = shared_report("openssf-tldr");
    assert_conforms(&report, "openssf-tldr");

    // The guide's block is examined in full by the corpus.
    assert!(
        report["coverage"].get("profile_flags_unexamined").is_none(),
        "the guide's profile left flags unexamined: {}",
        report["coverage"]["profile_flags_unexamined"]
    );
    assert!(
        report["coverage"]["truncations"]
            .as_array()
            .is_none_or(|t| !t.iter().any(|x| x
                .as_str()
                .is_some_and(|x| x.contains("examined by no check")))),
        "a full run under the guide's profile must record no unexamined-flag truncation"
    );
}

#[test]
fn measure_reads_the_gate_from_the_record_it_publishes() {
    if !can_run("that measure decides the gate from the record it publishes") {
        return;
    }
    let work = common::Work::new("schema", "gate-wiring");
    let run = |tag: &str, allow: bool| {
        let workdir = work.dir().join(tag);
        std::fs::create_dir_all(&workdir).expect("a work directory per run");
        let mut command = Command::new(chard_binary());
        command
            .args([
                "measure",
                "-o",
                "-",
                "--profile",
                "bare",
                "--probe",
                "bti-enforced",
            ])
            .arg("--workdir")
            .arg(&workdir)
            .arg("--fail-on-missing");
        if allow {
            command.args(["--allow", "no-check-on-target"]);
        }
        let output = command.output().expect("spawning chard");
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| cannot_run(&format!("{tag}: output was not JSON ({e})")));
        if report.get("error").is_some() {
            cannot_run(&format!("{tag}: chard reported {}", report["error"]));
        }
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            report,
        )
    };
    let (strict_status, strict_err, strict) = run("strict", false);
    let (allowed_status, allowed_err, allowed) = run("allowed", true);
    assert_eq!(strict_status, Some(1), "{strict_err}");
    assert_eq!(
        allowed_status,
        Some(1),
        "a narrowed run fails the gate: {allowed_err}"
    );
    assert_eq!(
        strict["coverage"]["gate"],
        serde_json::json!({"allowed": [], "excused": []}),
        "a strict run writes both lists empty"
    );
    assert_eq!(
        allowed["coverage"]["gate"]["allowed"],
        serde_json::json!(["no-check-on-target"])
    );
    if allowed["toolchain"]["target"]["arch"] == "x86_64" {
        assert_eq!(
            allowed["coverage"]["gate"]["excused"],
            serde_json::json!([{"check": "bti-enforced", "rule": "no-check-on-target"}])
        );
        assert!(
            allowed_err
                .contains("--fail-on-missing: excused by --allow no-check-on-target: bti-enforced"),
            "{allowed_err}"
        );
        assert!(
            allowed_err.contains("and 1 excused by --allow, named above"),
            "the closing line counts the excused check: {allowed_err}"
        );
        assert!(
            strict_err
                .lines()
                .any(|l| l.starts_with("chard: --fail-on-missing: exit 1")
                    && l.contains("--allow no-check-on-target excuses it")),
            "the strict gate's last line names the option: {strict_err}"
        );
    }
}

#[test]
fn a_gated_report_conforms_and_records_what_its_allowance_excused() {
    if !can_run("that a gated report validates and records what its allowance excused") {
        return;
    }
    let work = common::Work::new("schema", "gated");
    let report = report_for(
        "bare",
        &[
            "--probe",
            "bti-enforced",
            "--fail-on-missing",
            "--allow",
            "no-check-on-target",
        ],
        work.dir(),
    );
    assert_conforms(
        &report,
        "bare under --fail-on-missing --allow no-check-on-target",
    );
    let gate = &report["coverage"]["gate"];
    assert_eq!(gate["allowed"], serde_json::json!(["no-check-on-target"]));
    let withheld: Vec<Value> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["verdict"] == "indeterminate" && o["gating"]["rule"] == "no-check-on-target")
        .map(|o| serde_json::json!({"check": o["check"], "rule": "no-check-on-target"}))
        .collect();
    assert_eq!(gate["excused"], Value::Array(withheld.clone()), "{gate}");
    if report["toolchain"]["target"]["arch"] == "x86_64" {
        assert_eq!(
            withheld,
            [serde_json::json!({"check": "bti-enforced", "rule": "no-check-on-target"})]
        );
    }
    assert!(
        shared_report("bare")["coverage"].get("gate").is_none(),
        "a run without --fail-on-missing carries no gate record"
    );
}

#[test]
fn a_filtered_report_conforms_and_declares_itself_incomplete() {
    if !can_run("that a filtered run both conforms and admits its coverage is partial") {
        return;
    }
    let work = common::Work::new("schema", "filtered");
    let report = report_for("bare", &["--probe", "stack-canary"], work.dir());
    assert_conforms(&report, "filtered");

    let coverage = &report["coverage"];
    assert_eq!(
        coverage["all_checks_attempted"],
        Value::Bool(false),
        "a run restricted to one probe must not report itself complete"
    );
    assert!(
        coverage["corpus_checks_total"].as_u64().unwrap_or(0)
            > coverage["checks_expected"].as_u64().unwrap_or(0),
        "corpus total must exceed the filtered selection"
    );
    let truncations = coverage["truncations"]
        .as_array()
        .expect("a filtered run must record the truncation");
    assert!(
        truncations.iter().any(|t| t
            .as_str()
            .is_some_and(|t| t.starts_with("run restricted to 1 of "))),
        "the truncation names the distinct probe count: {truncations:?}"
    );
    // The reconciliation is by id: one probe's checks were asked for, and exactly those
    // came back, so nothing is missing and nothing arrived unasked.
    assert_eq!(
        coverage["checks_expected"], coverage["checks_attempted"],
        "the selection's checks all came back"
    );
    assert!(
        coverage.get("checks_missing").is_none() && coverage.get("checks_unexpected").is_none(),
        "a run whose observations match its selection names no discrepancy: {coverage}"
    );
}

#[test]
fn consistency_reports_its_scope_and_declares_contradictions_when_present() {
    if !can_run("that the consistency block publishes its own scope alongside its findings") {
        return;
    }
    let mut report = shared_report("bare");
    assert_conforms(&report, "bare");

    let block = report["consistency"].clone();
    assert!(
        block["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && block["status"] == "consistent",
        "a healthy report must contradict itself nowhere and say so, got: {block}"
    );
    // Every derived field the report can carry must be in scope.
    let checked: Vec<&str> = block["fields_checked"]
        .as_array()
        .expect("fields_checked is an array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in ["fortify_ratchet", "defect_coverage", "composites"] {
        assert!(
            checked.contains(&field),
            "{field} is a derived field and must be checked; scope is {checked:?}"
        );
    }
    // Compared against the published rule set rather than against a number.
    let announced: Vec<&str> = block["rules_applied"]
        .as_array()
        .expect("rules_applied is an array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        announced,
        chard::report::RULES.to_vec(),
        "every rule must announce itself, in order: {block}"
    );

    report["consistency"]["contradictions"] = serde_json::json!([{
        "rule": "derived-fortify-level-exceeds-measured",
        "property": "_FORTIFY_SOURCE",
        "claims": [
            "fortify_ratchet.implied_level = 3",
            "observations[fortify-effective].level = 1"
        ],
        "detail": "the ratchet derives level 3 while the C library reported level 1"
    }]);
    report["consistency"]["status"] = serde_json::json!("contradicted");
    assert_conforms(&report, "bare with a contradiction");

    assert_the_schema_refuses_each_wrong_consistency_shape(&report);

    // And the schema must not accept a contradiction missing the id a consumer gates on.
    let schema = schema();
    let mut errors = Vec::new();
    validate(
        &serde_json::json!({"consistency": {
            "status": "contradicted",
            "rules_applied": ["derived-fortify-level-exceeds-measured"], "fields_checked": [],
            "contradictions": [{"property": "_FORTIFY_SOURCE"}]
        }}),
        &schema,
        &schema,
        "",
        &mut errors,
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("missing required property `rule`")),
        "a contradiction without a rule id must be rejected, got: {errors:?}"
    );
}

/// The status word and the list are held together: each word beside the other's list, a
/// third word, and a block missing the word, the list or every rule are refused, where
/// `report` (carrying one contradiction and `contradicted`) conforms.
fn assert_the_schema_refuses_each_wrong_consistency_shape(report: &Value) {
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut r = report.clone();
        edit(&mut r);
        let schema = schema();
        let mut errors = Vec::new();
        validate(&r, &schema, &schema, "", &mut errors);
        errors
    };
    for (what, edit) in [
        (
            "consistent beside a contradiction",
            &(|r: &mut Value| r["consistency"]["status"] = serde_json::json!("consistent"))
                as &dyn Fn(&mut Value),
        ),
        ("contradicted beside none", &|r: &mut Value| {
            r["consistency"]["contradictions"] = serde_json::json!([]);
        }),
        ("a third word", &|r: &mut Value| {
            r["consistency"]["status"] = serde_json::json!("unchecked");
        }),
        ("no status", &|r: &mut Value| {
            r["consistency"]
                .as_object_mut()
                .expect("an object")
                .remove("status");
        }),
        ("no list", &|r: &mut Value| {
            r["consistency"]
                .as_object_mut()
                .expect("an object")
                .remove("contradictions");
        }),
        ("no rule", &|r: &mut Value| {
            r["consistency"]["rules_applied"] = serde_json::json!([]);
        }),
    ] {
        let errors = refused(edit);
        assert!(!errors.is_empty(), "{what} must be refused");
    }
}

/// The link facts whose type admits `null`, in the definition's order. The reader sets
/// all nine on an object the loader can run and withholds all nine on any other; the
/// sweep holds each instance to that, since the validator has no keyword for it.
const NULLABLE_LINK_FACTS: [&str; 9] = [
    "pie",
    "static_pie",
    "shared_object",
    "statically_linked",
    "relro",
    "gnu_relro",
    "bind_now",
    "gnu_stack_present",
    "gnu_stack_executable",
];

/// The members outside the link facts whose type admits `null`. `ElfFacts` omits each when
/// `None`, so no recorded instance carries the `null`; a report's `facts` store states it
/// (`report::serialize_stored_elf`), so `separate-code`'s and `ssp-level-emitted`'s
/// predicates read a stated value there, as do `plt-bypassed`'s and `pic-object-relocs`'.
/// `data_in_code_pages` is `None` on an object with no executable segment or no allocated
/// section, `function_references` on any object but a relocatable one with a symbol table,
/// and `code_relocations` on an object that is not `ET_REL` or has no section-header
/// table; `rwx_segment` is the link classification's own condition, as the nine are, but
/// is omitted when `None` like these three, so it is counted here and stated as `null` by
/// the store like them. None of the four is one of the nine.
const NULLABLE_OTHER_FACTS: [&str; 4] = [
    "data_in_code_pages",
    "code_relocations",
    "function_references",
    "rwx_segment",
];

/// What the ELF corpus sweep met, counted so that each optional declaration in
/// `$defs/elf_facts` is shown to have met at least one instance.
#[derive(Default)]
struct ElfCorpusSeen {
    instances: usize,
    property_notes: usize,
    truncations: usize,
    symbol_tables: usize,
    versioned: usize,
    elf32: usize,
    null_link_facts: usize,
}

impl ElfCorpusSeen {
    fn note(&mut self, origin: &str, facts: &Value) {
        self.instances += 1;
        self.property_notes += usize::from(facts.get("gnu_property_notes").is_some());
        self.symbol_tables += usize::from(facts.get("symbol_tables").is_some());
        if let Some(truncations) = facts.get("truncations") {
            self.truncations += 1;
            // The typed shape, held on the instance and not only in the definition: the
            // stripped fixture is what pins `{table, kind, detail}` on every host.
            for entry in truncations.as_array().expect("truncations is a list") {
                for key in ["table", "kind", "detail"] {
                    assert!(
                        entry.get(key).is_some_and(Value::is_string),
                        "{origin}: a truncation carries `{key}` as a string: {entry}"
                    );
                }
            }
        }
        self.versioned += usize::from(
            facts["watched_symbols"]
                .as_object()
                .is_some_and(|symbols| symbols.values().any(|s| s.get("versioned").is_some())),
        );
        self.elf32 += usize::from(facts["elf_class"] == 32);
        let nulls: Vec<&str> = NULLABLE_LINK_FACTS
            .iter()
            .copied()
            .filter(|name| facts.get(*name).is_some_and(Value::is_null))
            .collect();
        assert!(
            nulls.is_empty() || nulls.len() == NULLABLE_LINK_FACTS.len(),
            "{origin}: {} of the {} link facts are null and the rest carry a value: {nulls:?}",
            nulls.len(),
            NULLABLE_LINK_FACTS.len()
        );
        self.null_link_facts += usize::from(nulls.len() == NULLABLE_LINK_FACTS.len());
    }
}

/// The members of a definition whose `type` list admits `null`.
fn nullable_members(definition: &Value) -> BTreeSet<String> {
    definition["properties"]
        .as_object()
        .expect("the definition declares properties")
        .iter()
        .filter(|(_, property)| {
            property["type"]
                .as_array()
                .is_some_and(|types| types.iter().any(|t| t == "null"))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// The reader's facts of every synthetic object under `tests/fixtures/elf/`, read live and
/// serialized as a report carries them, labelled by file, in name order.
fn synthetic_elf_facts() -> Vec<(String, Value)> {
    let dir = repo_root().join("tests/fixtures/elf");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("tests/fixtures/elf is readable") {
        let path = entry.expect("a readable directory entry").path();
        let Some(stem) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".elf"))
        else {
            continue;
        };
        let facts = chard::elf::facts_for(&path)
            .unwrap_or_else(|e| panic!("{}: the synthetic object parses: {e}", path.display()));
        let facts = serde_json::to_value(&facts).expect("ElfFacts serializes");
        out.push((format!("fixtures/elf/{stem}"), facts));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// How many instances each source of [`gather_elf_facts`] contributed, for the frame a
/// failure prints.
struct ElfCorpusSources {
    synthetic: usize,
}

/// The facts of every synthetic object, with the pinned count of them.
fn gather_elf_facts() -> (Vec<(String, Value)>, ElfCorpusSources) {
    let fed = synthetic_elf_facts();
    assert_eq!(
        fed.len(),
        common::ELF_FIXTURE_COUNT,
        "the synthetic corpus changed size; update `common::ELF_FIXTURE_COUNT` and say why"
    );
    let synthetic = fed.len();
    (fed, ElfCorpusSources { synthetic })
}

#[test]
fn every_recorded_elf_fact_conforms_to_the_elf_facts_definition() {
    let schema = schema();
    let definition = resolve("#/$defs/elf_facts", &schema).expect("$defs/elf_facts is declared");
    let (fed, sources) = gather_elf_facts();
    assert_eq!(
        nullable_members(definition),
        NULLABLE_LINK_FACTS
            .iter()
            .chain(NULLABLE_OTHER_FACTS.iter())
            .map(|n| (*n).to_owned())
            .collect(),
        "the members whose type admits null are not NULLABLE_LINK_FACTS and NULLABLE_OTHER_FACTS"
    );

    let mut seen = ElfCorpusSeen::default();
    let mut errors = Vec::new();
    for (origin, facts) in &fed {
        seen.note(origin, facts);
        validate(
            facts,
            definition,
            &schema,
            &format!("{origin}/elf"),
            &mut errors,
        );
    }

    assert_eq!(seen.instances, fed.len(), "every instance fed was counted");
    assert_eq!(
        seen.instances, sources.synthetic,
        "the sources account for every instance"
    );
    for (member, count) in [
        ("gnu_property_notes", seen.property_notes),
        ("truncations", seen.truncations),
        ("symbol_tables", seen.symbol_tables),
        ("a symbol's versioned list", seen.versioned),
        ("an elf_class of 32", seen.elf32),
        ("a null link fact", seen.null_link_facts),
    ] {
        assert!(
            count > 0,
            "no instance carried {member}, so that declaration was validated against nothing"
        );
    }
    let shown: Vec<&String> = errors.iter().take(20).collect();
    assert!(
        errors.is_empty(),
        "{} elf_facts problems in {} instances ({} synthetic), first {}:\n{}",
        errors.len(),
        seen.instances,
        sources.synthetic,
        shown.len(),
        shown
            .iter()
            .map(|e| e.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// An `ElfFacts` written as an exhaustive literal, so the compiler refuses this test the
/// moment a field is added to or removed from the struct. With `populated` every optional
/// member carries a value: a property-note count, a truncation, a symbol table, a
/// `.comment` line and a `versioned` spelling on the one watched symbol. Without it each
/// is empty, which `skip_serializing_if` drops.
fn elf_facts_literal(populated: bool) -> chard::elf::ElfFacts {
    let filled = |value: &str| -> Vec<String> {
        if populated {
            vec![value.to_owned()]
        } else {
            Vec::new()
        }
    };
    let symbol = chard::elf::SymbolFact {
        defined: false,
        tables: vec![".dynsym".to_owned()],
        versioned: filled("__stack_chk_fail@GLIBC_2.4"),
    };
    chard::elf::ElfFacts {
        elf_class: 64,
        // Written by every live read; omitted by an archived record that lacks the field.
        elf_data: populated.then_some(chard::elf::ByteOrder::LittleEndian),
        elf_type: "ET_DYN".to_owned(),
        machine: "x86_64".to_owned(),
        has_interp: true,
        has_dynamic: true,
        pie: Some(true),
        df_1_pie: true,
        static_pie: Some(false),
        shared_object: Some(false),
        statically_linked: Some(false),
        relro: Some(chard::elf::RELRO_FULL.to_owned()),
        gnu_relro: Some(true),
        bind_now: Some(true),
        gnu_stack_present: Some(true),
        gnu_stack_executable: Some(false),
        // `skip_serializing_if` the `Option`, so the minimal shape omits the key.
        rwx_segment: populated.then_some(false),
        df_1_noopen: false,
        textrel: false,
        dt_relr: false,
        dt_debug: false,
        dt_soname: false,
        dynamic_tags: vec!["0x1e=0x8".to_owned()],
        needed: vec!["libc.so.6".to_owned()],
        rpath: Vec::new(),
        runpath: Vec::new(),
        gnu_property_types: filled("0xc0000002"),
        gnu_property_notes: filled("0xc0000002")
            .into_iter()
            .map(|type_| (type_, 1))
            .collect(),
        x86_ibt: false,
        x86_shstk: false,
        aarch64_bti: false,
        aarch64_pac: false,
        aarch64_gcs: false,
        openbsd_nobtcfi: populated,
        sections: vec![".text".to_owned()],
        data_in_code_pages: populated.then(|| vec![".rodata".to_owned()]),
        code_relocations: populated.then(|| vec!["R_X86_64_PLT32 chard_no_plt_callee".to_owned()]),
        function_references: populated.then(|| vec!["main:".to_owned()]),
        symbol_tables: filled(".dynsym"),
        symbol_count: 1,
        watched_symbols: BTreeMap::from([("__stack_chk_fail".to_owned(), symbol)]),
        truncations: filled("no section-header table: e_shoff past end of file")
            .into_iter()
            .map(|detail| chard::elf::Truncation {
                table: chard::elf::ElfTable::Symbols,
                kind: chard::elf::TruncationKind::Unread,
                detail,
            })
            .collect(),
        comment: filled("Linker: LLD 22.1.8"),
        code_scanned: filled("chard_ubsan_trap_probe:x86-ud2=1"),
        code_matches: filled("chard_ubsan_trap_probe:x86-ud2@0x1a"),
        run_witness: filled("000102030405060708090a0b0c0d0e0f"),
        self_report: String::new(),
        recorded_command_line: String::new(),
        function_entries: filled("chard_ibt_target_a=f30f1efa"),
    }
}

#[test]
fn the_rollup_keys_the_schema_declares_are_the_rollup_vocabulary() {
    let schema = schema();
    let counts = &schema["properties"]["defect_coverage"]["additionalProperties"]["properties"]["verdict_counts"];
    // Open as published, so a validator accepts a later chard's key; this chard's reader
    // refuses a nonzero count under one (`report::rollup_recount_disagrees`).
    assert_eq!(
        counts["additionalProperties"],
        serde_json::json!({"type": "integer", "minimum": 0})
    );
    let declared = member_names(counts, "properties");
    let vocabulary: BTreeSet<String> = chard::report::RollupKey::ALL
        .iter()
        .map(|k| k.as_str().to_owned())
        .collect();
    assert_eq!(declared, vocabulary);
}

/// The names a definition lists under `required`, or declares under `properties`.
fn member_names(definition: &Value, keyword: &str) -> BTreeSet<String> {
    match &definition[keyword] {
        Value::Array(names) => names
            .iter()
            .map(|n| n.as_str().expect("a member name is a string").to_owned())
            .collect(),
        Value::Object(members) => members.keys().cloned().collect(),
        other => panic!("`{keyword}` is neither a list nor an object: {other}"),
    }
}

/// How many fields of `struct_name` in `src/elf.rs` carry `skip_serializing_if`, counted in
/// the source text between `pub struct <name> {` and the brace that closes it at column
/// zero. A struct that cannot be found panics; a body with no public field is refused, so
/// the count is never zero for want of a struct to count over.
fn optional_fields_in_source(struct_name: &str) -> usize {
    let path = repo_root().join("src/elf.rs");
    let source = std::fs::read_to_string(&path).expect("src/elf.rs is readable");
    let opening = format!("pub struct {struct_name} {{");
    let start = source
        .find(&opening)
        .unwrap_or_else(|| panic!("`{opening}` is declared in {}", path.display()));
    let body = &source[start + opening.len()..];
    let end = body
        .find("\n}\n")
        .unwrap_or_else(|| panic!("`{struct_name}` closes at column zero"));
    let body = &body[..end];
    assert!(
        body.contains("pub "),
        "`{struct_name}` declares a public field, or the span read is not its body"
    );
    body.matches("skip_serializing_if").count()
}

#[test]
fn the_elf_facts_definition_partitions_the_struct_as_serde_serializes_it() {
    let schema = schema();
    let definition = resolve("#/$defs/elf_facts", &schema).expect("$defs/elf_facts is declared");
    let symbol_definition =
        resolve("#/$defs/symbol_fact", &schema).expect("$defs/symbol_fact is declared");
    let keys_of = |value: &Value| -> BTreeSet<String> {
        value
            .as_object()
            .expect("a serialized struct is an object")
            .keys()
            .cloned()
            .collect()
    };
    let mut compared = 0;
    for (populated, keyword) in [(false, "required"), (true, "properties")] {
        let facts =
            serde_json::to_value(elf_facts_literal(populated)).expect("ElfFacts serializes");
        for (what, actual, expected) in [
            (
                "elf_facts",
                keys_of(&facts),
                member_names(definition, keyword),
            ),
            (
                "symbol_fact",
                keys_of(&facts["watched_symbols"]["__stack_chk_fail"]),
                member_names(symbol_definition, keyword),
            ),
        ] {
            assert_eq!(
                actual,
                expected,
                "populated={populated}: `{what}` and `{keyword}` differ: struct {:?}, schema {:?}",
                actual.difference(&expected).collect::<Vec<_>>(),
                expected.difference(&actual).collect::<Vec<_>>(),
            );
            compared += 1;
        }
        let mut errors = Vec::new();
        validate(
            &facts,
            definition,
            &schema,
            &format!("literal(populated={populated})"),
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "the literal must validate against $defs/elf_facts, got: {errors:?}"
        );
    }
    assert_eq!(compared, 4, "two shapes of two definitions were compared");
    for (what, definition, struct_name) in [
        ("elf_facts", definition, "ElfFacts"),
        ("symbol_fact", symbol_definition, "SymbolFact"),
    ] {
        let declared = member_names(definition, "properties").len()
            - member_names(definition, "required").len();
        let in_source = optional_fields_in_source(struct_name);
        assert!(
            in_source > 0,
            "`{struct_name}` has a field under `skip_serializing_if`, or the count read nothing"
        );
        assert_eq!(
            declared, in_source,
            "`{what}` declares {declared} optional members but `{struct_name}` skips {in_source}"
        );
        compared += 1;
    }
    assert_eq!(
        compared, 6,
        "two definitions' optional counts were compared with the source"
    );
}

#[test]
fn the_validator_rejects_a_report_that_violates_the_schema() {
    let schema = schema();
    let mut errors = Vec::new();
    validate(&serde_json::json!({}), &schema, &schema, "", &mut errors);
    assert!(
        !errors.is_empty(),
        "an empty object must fail: the schema declares required top-level properties"
    );

    // An undeclared property must be caught, since chard's own reading closes every object
    // the schema declares: that is the keyword the `observations[].check` drift violated.
    let mut errors = Vec::new();
    validate(
        &serde_json::json!({"coverage": {"nonsense_key": 1}}),
        &schema,
        &schema,
        "",
        &mut errors,
    );
    assert!(
        errors.iter().any(|e| e.contains("nonsense_key")),
        "undeclared properties must be reported, got: {errors:?}"
    );

    // And a wrong enum value.
    let mut errors = Vec::new();
    validate(
        &serde_json::json!({"chard_schema": "999"}),
        &schema,
        &schema,
        "",
        &mut errors,
    );
    assert!(
        errors.iter().any(|e| e.contains("const")),
        "a wrong schema version must be reported, got: {errors:?}"
    );

    // Five keywords a small validator can parse and drop: `minimum`, `maximum`, `minItems`,
    // `pattern` and `format`.
    let cases: &[(&str, Value, &str)] = &[
        (
            "minimum",
            serde_json::json!({"coverage": {"checks_expected": -1}}),
            "below minimum",
        ),
        (
            "pattern",
            serde_json::json!({"profile": {"id": "not-a-profile"}}),
            "does not match pattern",
        ),
        (
            "format",
            serde_json::json!({"run": {"started_utc": "yesterday"}}),
            "date-time",
        ),
    ];
    for (keyword, document, expected) in cases {
        let mut errors = Vec::new();
        validate(document, &schema, &schema, "", &mut errors);
        assert!(
            errors.iter().any(|e| e.contains(expected)),
            "a `{keyword}` violation must be reported, got: {errors:?}"
        );
    }

    // `maximum` has had no use in the report schema since `percent_withheld` was
    // removed; the validator still implements it, so a schema that
    // uses it again is enforced, and this holds that over a schema of one property.
    let bounded = serde_json::json!({
        "type": "object",
        "properties": {"n": {"type": "number", "maximum": 100}}
    });
    let mut errors = Vec::new();
    validate(
        &serde_json::json!({"n": 101.0}),
        &bounded,
        &bounded,
        "",
        &mut errors,
    );
    assert!(
        errors.iter().any(|e| e.contains("above maximum")),
        "a `maximum` violation must be reported, got: {errors:?}"
    );

    // `minItems` sits behind a $ref inside observations, so it needs a real path.
    let mut errors = Vec::new();
    validate(
        &serde_json::json!({"observations": [{"boundary": {"requires_at_runtime": []}}]}),
        &schema,
        &schema,
        "",
        &mut errors,
    );
    assert!(
        errors.iter().any(|e| e.contains("minItems")),
        "a `minItems` violation must be reported, got: {errors:?}"
    );
}

/// An attestation carrying an installed disk, as the library serialises it, conforms.
/// malformed and the null forms of the field rather than passing them.
#[test]
fn an_installed_disk_attestation_conforms_and_its_malformed_forms_do_not() {
    if !can_run("that an installed-disk attestation validates against the schema") {
        return;
    }
    let text = format!(
        r#"{{"verdict":"signature-verified",
             "url":"https://example.invalid/alpine-virt.iso",
             "served_by":"example.invalid","origin":"recorded-at-fetch",
             "manifest_url":"https://example.invalid/alpine-virt.iso.sha256",
             "digest_kind":"sha256","digest":"{iso}","digest_matched":true,
             "signature":"detached .asc",
             "installed_disk":{{"sha256":"{disk}","installed_at":"2026-09-30T16:23:38Z",
                                "installed_from_digest":"{iso}"}}}}"#,
        iso = "ab".repeat(32),
        disk = "ef".repeat(32),
    );
    let attestation = chard::env::Attestation::from_json(&text).expect("well-formed");
    let record =
        chard::env::ImageAttestation::classify(chard::env::ExecutionMode::Vm, Some(attestation))
            .expect("a matched digest is attested");
    let spliced = serde_json::to_value(&record).expect("serialisable");
    assert_eq!(spliced["installed_disk"]["sha256"], "ef".repeat(32));

    let mut report = shared_report("bare");
    report["environment"]["execution"]["image_attestation"] = spliced.clone();
    assert_conforms(&report, "bare with an installed-disk attestation");

    let schema = schema();
    let cases: &[(&str, Value, &str)] = &[
        ("null", Value::Null, "installed_disk"),
        (
            "short digest",
            serde_json::json!({"sha256": "ef".repeat(31), "installed_at": "2026-09-30T16:23:38Z",
                               "installed_from_digest": "ab".repeat(32)}),
            "minLength",
        ),
        (
            "long digest",
            serde_json::json!({"sha256": "ef".repeat(33), "installed_at": "2026-09-30T16:23:38Z",
                               "installed_from_digest": "ab".repeat(32)}),
            "maxLength",
        ),
        (
            "upper-case digest",
            serde_json::json!({"sha256": "EF".repeat(32), "installed_at": "2026-09-30T16:23:38Z",
                               "installed_from_digest": "ab".repeat(32)}),
            "does not match pattern",
        ),
        (
            "date only",
            serde_json::json!({"sha256": "ef".repeat(32), "installed_at": "2026-09-30",
                               "installed_from_digest": "ab".repeat(32)}),
            "date-time",
        ),
        (
            "missing field",
            serde_json::json!({"sha256": "ef".repeat(32), "installed_at": "2026-09-30T16:23:38Z"}),
            "installed_from_digest",
        ),
    ];
    for (label, disk, expected) in cases {
        let mut bad = report.clone();
        bad["environment"]["execution"]["image_attestation"]["installed_disk"] = disk.clone();
        let mut errors = Vec::new();
        validate(&bad, &schema, &schema, "", &mut errors);
        assert!(
            errors.iter().any(|e| e.contains(expected)),
            "{label}: the schema must refuse it naming `{expected}`, got: {errors:?}"
        );
    }
}

#[test]
#[should_panic(expected = "is not implemented by this validator")]
fn the_validator_refuses_a_type_it_does_not_implement() {
    let schema = schema();
    let mut errors = Vec::new();
    validate(
        &serde_json::json!(1),
        &serde_json::json!({"type": "intger"}),
        &schema,
        "",
        &mut errors,
    );
}

#[test]
fn the_validator_rejects_evidence_the_contract_does_not_declare() {
    let schema = schema();
    let observation =
        |evidence: Value| serde_json::json!({"observations": [{"evidence": evidence}]});
    let stored = |entry: Value| serde_json::json!({"facts": {"0".repeat(64): entry}});
    let errors_under = |document: &Value, prefix: &str| -> Vec<String> {
        let mut errors = Vec::new();
        validate(document, &schema, &schema, "", &mut errors);
        errors
            .into_iter()
            .filter(|e| e.starts_with(prefix))
            .collect()
    };
    let evidence_errors = |document: &Value| errors_under(document, "/observations/0/evidence");
    let fact_errors = |document: &Value| errors_under(document, "/facts/");

    // An undeclared member of `evidence` itself.
    let errors = evidence_errors(&observation(serde_json::json!({"nonsense": 1})));
    assert!(
        errors.iter().any(|e| e.contains("nonsense")),
        "an undeclared evidence member must be reported, got: {errors:?}"
    );

    // The empty block: an observation that carries no evidence is a legal one.
    let errors = evidence_errors(&observation(serde_json::json!({})));
    assert!(errors.is_empty(), "`{{}}` must validate, got: {errors:?}");

    // A real serialization, so the failures below are the edits and never the record.
    let (_, facts) = synthetic_elf_facts()
        .into_iter()
        .find(|(origin, _)| origin.ends_with("elf64-le-x86_64-exec-relro-lazy"))
        .expect("the lazy-RELRO record is checked in");
    let errors = fact_errors(&stored(serde_json::json!({"kind": "elf", "elf": facts})));
    assert!(
        errors.is_empty(),
        "the untouched record must validate, got: {errors:?}"
    );

    // The inline shape, which the store replaced.
    let errors = evidence_errors(&observation(serde_json::json!({"elf": facts})));
    assert!(
        errors
            .iter()
            .any(|e| e.contains("property `elf` is not declared")),
        "`evidence.elf` must be refused now the facts live in `facts`, got: {errors:?}"
    );
    let errors = evidence_errors(&observation(serde_json::json!({"self_report": ""})));
    assert!(
        errors
            .iter()
            .any(|e| e.contains("property `self_report` is not declared")),
        "`evidence.self_report` must be refused, got: {errors:?}"
    );

    // The newest required fact, which an archived record can lack.
    let mut archived = facts.clone();
    archived
        .as_object_mut()
        .and_then(|m| m.remove("aarch64_gcs"))
        .expect("the record carries `aarch64_gcs`");
    let errors = fact_errors(&stored(serde_json::json!({"kind": "elf", "elf": archived})));
    assert!(
        errors
            .iter()
            .any(|e| e.contains("missing required property `aarch64_gcs`")),
        "an archive from before `aarch64_gcs` must fail `required` on it, got: {errors:?}"
    );

    // A renamed ELF fact: both the unknown key and the missing one are named.
    let mut renamed = facts.clone();
    let pie = renamed
        .as_object_mut()
        .and_then(|m| m.remove("pie"))
        .expect("the record carries `pie`");
    renamed["pie_renamed"] = pie;
    let errors = fact_errors(&stored(serde_json::json!({"kind": "elf", "elf": renamed})));
    assert!(
        errors.iter().any(|e| e.contains("pie_renamed")),
        "a renamed fact must be reported as undeclared, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("missing required property `pie`")),
        "a renamed fact must be reported as missing under its old name, got: {errors:?}"
    );

    // A RELRO level outside the vocabulary.
    let mut lazy = facts;
    lazy["relro"] = serde_json::json!("lazy");
    let errors = fact_errors(&stored(serde_json::json!({"kind": "elf", "elf": lazy})));
    assert!(
        errors
            .iter()
            .any(|e| e.contains("/relro") && e.contains("is not one of")),
        "a RELRO level outside the enum must be reported, got: {errors:?}"
    );
}

#[test]
fn an_unreadable_entry_carries_mach_o_as_an_optional_boolean() {
    let schema = schema();
    let fact_errors = |entry: Value| -> Vec<String> {
        let document = serde_json::json!({"facts": {"0".repeat(64): entry}});
        let mut errors = Vec::new();
        validate(&document, &schema, &schema, "", &mut errors);
        errors.extend(fact_entries_carry_their_kinds_members(&document));
        errors.retain(|e| e.starts_with("/facts/"));
        errors
    };
    assert!(
        fact_errors(serde_json::json!({"kind": "unreadable", "error": "x", "mach_o": true}))
            .is_empty(),
        "an entry recording a Mach-O refusal is refused"
    );
    assert!(
        !fact_errors(serde_json::json!({"kind": "unreadable", "error": "x", "mach_o": "yes"}))
            .is_empty(),
        "a `mach_o` that is not a boolean must be reported"
    );
    assert!(
        !fact_errors(serde_json::json!({"kind": "unreadable", "mach_o": true})).is_empty(),
        "`mach_o` does not stand in for `error`"
    );
}

#[test]
fn a_store_entry_outside_its_kind_is_refused() {
    let schema = schema();
    let fact_errors = |entry: Value| -> Vec<String> {
        let document = serde_json::json!({"facts": {"0".repeat(64): entry}});
        let mut errors = Vec::new();
        validate(&document, &schema, &schema, "", &mut errors);
        errors.extend(fact_entries_carry_their_kinds_members(&document));
        errors.retain(|e| e.starts_with("/facts/"));
        errors
    };
    let errors = fact_errors(serde_json::json!({"kind": "elf-v2", "error": "x"}));
    assert!(
        errors.iter().any(|e| e.contains("is not one of")),
        "a kind this revision does not write must be reported, got: {errors:?}"
    );
    let errors = fact_errors(serde_json::json!({"kind": "unreadable", "why": "x"}));
    assert!(
        errors
            .iter()
            .any(|e| e.contains("property `why` is not declared")),
        "an undeclared entry member must be reported, got: {errors:?}"
    );
    let errors = fact_errors(serde_json::json!({"kind": "elf", "error": "x"}));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].contains("a `elf` entry carries"),
        "an entry carrying another kind's members must be reported, got: {errors:?}"
    );
    assert!(
        fact_errors(serde_json::json!({"kind": "unreadable", "error": "x"})).is_empty(),
        "a well-formed entry is refused"
    );

    // An elf-delta resolves against an `elf` entry of the same store, and its changes are
    // `elf_facts` members of `elf_facts` types.
    let (_, facts) = synthetic_elf_facts()
        .into_iter()
        .find(|(origin, _)| origin.ends_with("elf64-le-x86_64-exec-relro-lazy"))
        .expect("the lazy-RELRO record is checked in");
    let delta_errors = |changes: Value, base: &str| -> Vec<String> {
        let document = serde_json::json!({"facts": {
            "a".repeat(64): {"kind": "elf", "elf": facts},
            "b".repeat(64): {"kind": "elf-delta", "base": base, "elf_changes": changes},
        }});
        let mut errors = Vec::new();
        validate(&document, &schema, &schema, "", &mut errors);
        errors.extend(fact_entries_carry_their_kinds_members(&document));
        errors.extend(fact_deltas_resolve(&document, &schema));
        errors.retain(|e| e.starts_with("/facts/"));
        errors
    };
    let a = "a".repeat(64);
    assert!(
        delta_errors(serde_json::json!({"bind_now": true}), &a).is_empty(),
        "a well-formed delta is refused: {:?}",
        delta_errors(serde_json::json!({"bind_now": true}), &a)
    );
    // A member omitted when empty and emptied where the base carries it resolves to its
    // absence, so a delta that empties a `minItems: 1` member of the base conforms; the
    // same change against a base without the member is the empty list itself, which
    // `$defs/elf_facts` refuses.
    let mut with_comment = facts.clone();
    with_comment["comment"] = serde_json::json!(["GCC: (GNU) 16.0.0"]);
    let emptied_errors = |changes: Value, base_facts: &Value| -> Vec<String> {
        let document = serde_json::json!({"facts": {
            "a".repeat(64): {"kind": "elf", "elf": base_facts},
            "b".repeat(64): {"kind": "elf-delta", "base": a, "elf_changes": changes},
        }});
        let mut errors = Vec::new();
        validate(&document, &schema, &schema, "", &mut errors);
        errors.extend(fact_entries_carry_their_kinds_members(&document));
        errors.extend(fact_deltas_resolve(&document, &schema));
        errors.retain(|e| e.starts_with("/facts/"));
        errors
    };
    for (member, empty) in [
        ("comment", serde_json::json!([])),
        ("symbol_tables", serde_json::json!([])),
        ("watched_symbols", serde_json::json!({})),
        ("gnu_property_types", serde_json::json!([])),
    ] {
        let changes = serde_json::json!({member: empty});
        let errors = emptied_errors(changes.clone(), &with_comment);
        assert!(
            errors.is_empty(),
            "a delta emptying the base's `{member}` is refused: {errors:?}"
        );
    }
    let errors = emptied_errors(serde_json::json!({"comment": []}), &facts);
    assert!(
        errors.len() == 1 && errors[0].contains("/comment"),
        "an empty `comment` against a base without one must be reported, got: {errors:?}"
    );
    for (changes, base, what) in [
        (serde_json::json!({"nonsense": 1}), a.clone(), "undeclared"),
        (
            serde_json::json!({"bind_now": "yes"}),
            a.clone(),
            "mistyped",
        ),
        (serde_json::json!({}), "c".repeat(64), "unresolved"),
    ] {
        assert_eq!(
            delta_errors(changes.clone(), &base).len(),
            1,
            "a delta {what}: {changes}"
        );
    }
}

#[test]
fn a_replay_that_does_not_account_for_its_readings_is_refused() {
    let replay = |value: Value| serde_json::json!({"consistency": {"replay": value}});
    assert!(
        replay_counts_add_up(&replay(serde_json::json!({
            "readings": 3, "replayed": 1, "unresolved": 1,
            "not_replayable": [{"check": "x"}]
        })))
        .is_empty(),
        "readings = replayed + unresolved + not_replayable is refused"
    );
    let errors = replay_counts_add_up(&replay(serde_json::json!({
        "readings": 67, "replayed": 0, "unresolved": 0
    })));
    assert_eq!(
        errors.len(),
        1,
        "a replay that fed itself readings it did not account for must be reported"
    );

    let schema = schema();
    let consistency = &schema["properties"]["consistency"];
    let required: Vec<&str> = consistency["required"]
        .as_array()
        .expect("consistency declares its required members")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        required.contains(&"replay"),
        "`consistency.replay` is always serialized and the schema must require it: {required:?}"
    );
}

#[test]
fn the_cxx_assertions_sources_match_the_code() {
    let schema = schema();
    let declared: BTreeSet<&str> = schema["$defs"]["observation"]["properties"]["evidence"]
        ["properties"]["cxx_assertions_source"]["enum"]
        .as_array()
        .expect("evidence.cxx_assertions_source declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::measure::CXX_ASSERTIONS_SOURCES
        .iter()
        .copied()
        .collect();
    assert_eq!(
        emitted, declared,
        "evidence.cxx_assertions_source disagrees between code and schema"
    );
}

#[test]
fn the_fact_entry_kinds_match_the_code() {
    let schema = schema();
    let declared: BTreeSet<&str> = schema["$defs"]["fact_entry"]["properties"]["kind"]["enum"]
        .as_array()
        .expect("fact_entry.kind declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::report::FactEntry::KINDS.iter().copied().collect();
    assert_eq!(
        emitted,
        declared,
        "facts[].kind: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );
    let listed: BTreeSet<&str> = FACT_KIND_MEMBERS.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        listed, emitted,
        "every kind has a member list, and no other does"
    );
    let union: BTreeSet<&str> = FACT_KIND_MEMBERS
        .iter()
        .chain(FACT_KIND_OPTIONAL.iter())
        .flat_map(|(_, members)| members.iter().copied())
        .chain(std::iter::once("kind"))
        .collect();
    let members: BTreeSet<&str> = schema["$defs"]["fact_entry"]["properties"]
        .as_object()
        .expect("fact_entry declares its members")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        members, union,
        "the definition declares exactly the kinds' members"
    );
}

#[test]
fn the_report_schema_carries_the_predicate_definitions() {
    let report = schema();
    let predicate = schema_at("schema/chard-predicate.schema.json");
    let defs = predicate["$defs"]
        .as_object()
        .expect("the predicate schema has definitions");
    assert!(defs.len() >= 10, "{:?}", defs.keys().collect::<Vec<_>>());
    for (name, definition) in defs {
        assert_eq!(
            &report["$defs"][name], definition,
            "$defs/{name} in the report schema is not the predicate schema's"
        );
    }
    assert_eq!(
        report["properties"]["decoders"]["properties"]["predicates"]["additionalProperties"]["properties"]
            ["predicate"]["$ref"],
        predicate["$ref"],
        "a published predicate is held to the definition the predicate schema names"
    );
    let mut errors = Vec::new();
    let decoders = serde_json::json!({
        "language": chard::predicate::LANGUAGE,
        "predicates": {"pie": {
            "sha256": "0".repeat(64),
            "predicate": chard::predicate::for_check("pie").expect("pie has a predicate"),
        }},
    });
    validate(
        &decoders,
        &report["properties"]["decoders"],
        &report,
        "/decoders",
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    let mut refused = decoders;
    refused["predicates"]["pie"]["predicate"]["clauses"][0]["id"] = serde_json::json!("@mine");
    validate(
        &refused,
        &report["properties"]["decoders"],
        &report,
        "/decoders",
        &mut errors,
    );
    assert!(
        errors.iter().any(|e| e.contains("clauses/0/id")),
        "a reserved clause id is refused inside a report too: {errors:?}"
    );
}

#[test]
fn the_gating_description_lists_each_rule_under_the_verdict_its_premise_reserves() {
    let schema = schema();
    let description = schema["$defs"]["observation"]["properties"]["gating"]["description"]
        .as_str()
        .expect("gating carries a description");
    for &premise in chard::report::gating_rule::Premise::ALL {
        let marker = format!("publishes `{}`:", premise.verdict().as_str());
        let listed: BTreeSet<&str> = description
            .split_once(marker.as_str())
            .unwrap_or_else(|| panic!("the gating description has no `{marker}` sentence"))
            .1
            .split_once('.')
            .map_or("", |(list, _)| list)
            .split('`')
            .skip(1)
            .step_by(2)
            .collect();
        let class: BTreeSet<&str> = chard::report::gating_rule::ALL
            .iter()
            .filter(|r| r.premise == premise)
            .map(|r| r.id)
            .collect();
        assert_eq!(
            listed, class,
            "the gating description's `{marker}` list is not the rules with that premise"
        );
    }
}

#[test]
fn the_rejection_rule_description_lists_the_tool_sentence_rows() {
    use chard::report::gating_rule::{ALL, Evidence};

    let schema = schema();
    let description =
        schema["properties"]["consistency"]["properties"]["rules_applied"]["description"]
            .as_str()
            .expect("rules_applied carries a description");
    let marker = "`gating-rejection-absent-from-arm-stderr`:";
    let listed: BTreeSet<&str> = description
        .split_once(marker)
        .unwrap_or_else(|| panic!("the rules_applied description has no `{marker}` entry"))
        .1
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map_or("", |(list, _)| list)
        .split('`')
        .skip(1)
        .step_by(2)
        .collect();
    let rows: BTreeSet<&str> = ALL
        .iter()
        .filter(|r| matches!(r.evidence, Evidence::ToolSentence { .. }))
        .map(|r| r.id)
        .collect();
    assert!(
        !rows.is_empty(),
        "the table declares no rule that quotes a tool's sentence"
    );
    assert_eq!(
        listed, rows,
        "the rules_applied description's rejection-rule list differs from the tool-sentence rows"
    );
}

/// Closed vocabularies in the schema are exactly the vocabularies in the code.
#[expect(
    clippy::too_many_lines,
    reason = "one pairing per closed vocabulary, the schema's set against the code's, each with why it is bound, read top to bottom"
)]
#[test]
fn the_schemas_closed_vocabularies_match_the_code() {
    let schema = schema();
    let declared: BTreeSet<&str> =
        vocabulary_of(&schema["properties"]["profile"]["properties"]["flags_source"])
            .as_array()
            .expect("flags_source declares an enum")
            .iter()
            .map(|v| v.as_str().expect("enum values are strings"))
            .collect();
    let emitted: BTreeSet<&str> = chard::report::flags_source::ALL.iter().copied().collect();
    assert_eq!(
        emitted,
        declared,
        "profile.flags_source: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );

    // `consistency.status`, pinned against the enum the serializer writes.
    let declared: BTreeSet<&str> =
        schema["properties"]["consistency"]["properties"]["status"]["enum"]
            .as_array()
            .expect("consistency.status declares an enum")
            .iter()
            .map(|v| v.as_str().expect("enum values are strings"))
            .collect();
    let emitted: Vec<Value> = chard::report::ConsistencyStatus::ALL
        .iter()
        .map(|s| serde_json::to_value(s).expect("a unit variant serializes"))
        .collect();
    let emitted: BTreeSet<&str> = emitted.iter().filter_map(Value::as_str).collect();
    assert_eq!(
        emitted, declared,
        "consistency.status disagrees between code and schema"
    );

    // A listing's linkage form, pinned against the enum the parser reads it into.
    let declared: BTreeSet<&str> =
        vocabulary_of(&schema["$defs"]["link_inputs"]["properties"]["form"])
            .as_array()
            .expect("link_inputs.form declares an enum")
            .iter()
            .map(|v| v.as_str().expect("enum values are strings"))
            .collect();
    let emitted: Vec<Value> = chard::link_inputs::LinkageForm::ALL
        .iter()
        .map(|f| serde_json::to_value(f).expect("a unit variant serializes"))
        .collect();
    let emitted: BTreeSet<&str> = emitted.iter().filter_map(Value::as_str).collect();
    assert_eq!(
        emitted, declared,
        "link_inputs.form disagrees between code and schema"
    );

    // `controls.withheld_because`, pinned against the enum that produces it.
    let declared: BTreeSet<&str> =
        vocabulary_of(&schema["$defs"]["controls"]["properties"]["withheld_because"])
            .as_array()
            .expect("withheld_because declares an enum")
            .iter()
            .map(|v| v.as_str().expect("enum values are strings"))
            .collect();
    let emitted: BTreeSet<&str> = chard::report::WithheldBecause::ALL
        .iter()
        .map(|c| c.as_str())
        .collect();
    assert_eq!(
        emitted,
        declared,
        "controls.withheld_because: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );

    // `gating.rule`, pinned against the module that names them.
    let declared: BTreeSet<&str> = vocabulary_of(
        &schema["$defs"]["observation"]["properties"]["gating"]["properties"]["rule"],
    )
    .as_array()
    .expect("gating.rule declares an enum")
    .iter()
    .map(|v| v.as_str().expect("enum values are strings"))
    .collect();
    let emitted: BTreeSet<&str> = chard::report::gating_rule::ALL
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(
        emitted,
        declared,
        "gating.rule: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );

    // `observations[].observes`, pinned against the enum the bearing table carries:
    // a value the schema omits is a key no consumer can validate, and one the
    // schema declares and no check carries is a class the rollup never tallies.
    let declared: BTreeSet<&str> = schema["$defs"]["observation"]["properties"]["observes"]["enum"]
        .as_array()
        .expect("observes declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::probe::Observes::ALL
        .iter()
        .map(|o| o.as_str())
        .collect();
    assert_eq!(
        emitted,
        declared,
        "observations[].observes: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );

    // `mode_evidence.basis`, where the two sets are deliberately NOT equal.
    let declared: BTreeSet<&str> = schema["properties"]["environment"]["properties"]
        ["execution"]["properties"]["mode_evidence"]["properties"]["basis"]["enum"]
        .as_array()
        .expect("mode_evidence.basis declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let publishable: BTreeSet<&str> = chard::env::ModeBasis::PUBLISHABLE
        .iter()
        .map(|b| b.as_str())
        .collect();
    assert_eq!(
        publishable,
        declared,
        "mode_evidence.basis: code alone can publish {:?}, schema alone declares {:?}",
        publishable.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&publishable).collect::<Vec<_>>(),
    );
    let all: BTreeSet<&str> = chard::env::ModeBasis::ALL
        .iter()
        .map(|b| b.as_str())
        .collect();
    assert_eq!(
        all.difference(&declared).copied().collect::<Vec<_>>(),
        vec!["asserted-and-contradicted"],
        "exactly one basis is emittable but unpublishable, and the schema omits exactly it"
    );

    // `kernel.ownership`: every attribution a run can carry is published, a contradicted
    // assertion included (it reads the mode, and the report is quarantined on the mode).
    let declared: BTreeSet<&str> = schema["properties"]["environment"]["properties"]["kernel"]
        ["properties"]["ownership"]["enum"]
        .as_array()
        .expect("kernel.ownership declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::env::KernelOwnership::ALL
        .iter()
        .map(|o| o.as_str())
        .collect();
    assert_eq!(
        emitted,
        declared,
        "environment.kernel.ownership: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );

    // `libc.impl`, which had drifted in both directions at once because nothing held it:
    // `openbsd` was returnable and undeclared, so the first OpenBSD report would have failed
    // the validation above, and `uclibc` and `other` were declared and unreachable.
    let declared: BTreeSet<&str> = vocabulary_of(
        &schema["properties"]["environment"]["properties"]["libc"]["properties"]["impl"],
    )
    .as_array()
    .expect("libc.impl declares an enum")
    .iter()
    .map(|v| v.as_str().expect("enum values are strings"))
    .collect();
    let emitted: BTreeSet<&str> = chard::env::LIBC_NAMES.iter().copied().collect();
    assert_eq!(
        emitted,
        declared,
        "environment.libc.impl: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );

    // `linker.path_source`, which says who resolved the published linker path.
    let declared: BTreeSet<&str> = schema["$defs"]["linker"]["properties"]["path_source"]["enum"]
        .as_array()
        .expect("linker.path_source declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::toolchain::PathSource::ALL
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(
        emitted,
        declared,
        "toolchain.linker.path_source: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );

    // The verdict vocabulary, by the same rule.
    let declared: BTreeSet<&str> = schema["$defs"]["verdict"]["enum"]
        .as_array()
        .expect("verdict declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::report::Verdict::ALL
        .iter()
        .map(|v| v.as_str())
        .collect();
    assert_eq!(
        emitted,
        declared,
        "observations[].verdict: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );
}

#[test]
fn the_premise_vocabulary_matches_the_code_and_names_each_verdict() {
    use chard::report::gating_rule::Premise;
    let schema = schema();
    let premise = &schema["$defs"]["observation"]["properties"]["gating"]["properties"]["premise"];
    let declared: BTreeSet<&str> = premise["enum"]
        .as_array()
        .expect("gating.premise declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = Premise::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(
        emitted, declared,
        "gating.premise disagrees between code and schema"
    );
    let description = premise["description"]
        .as_str()
        .expect("gating.premise carries a description");
    for &class in Premise::ALL {
        let sentence = format!(
            "`{}` publishes `{}`",
            class.as_str(),
            class.verdict().as_str()
        );
        assert!(
            description.contains(&sentence),
            "the gating.premise description does not say {sentence}"
        );
        assert_eq!(Premise::from_name(class.as_str()), Some(class));
    }
}

#[test]
fn every_published_gating_carries_its_rules_premise() {
    if !can_run("that every gating in a measured report carries its rule's premise class") {
        return;
    }
    let report = shared_report("bare");
    let mut fed = 0;
    for o in report["observations"].as_array().expect("observations") {
        let Some(gating) = o.get("gating") else {
            continue;
        };
        fed += 1;
        let rule = gating["rule"].as_str().expect("gating.rule is a string");
        let class = chard::report::gating_rule::by_id(rule)
            .unwrap_or_else(|| panic!("{rule} is in the table"))
            .premise;
        assert_eq!(
            gating["premise"].as_str(),
            Some(class.as_str()),
            "{}: gating.premise beside {rule}",
            o["check"]
        );
    }
    assert!(
        fed > 0,
        "the bare report carries no gating, so nothing was checked"
    );
}

#[test]
fn the_artifact_agreement_vocabulary_matches_the_code() {
    let schema = schema();
    let declared: BTreeSet<&str> = vocabulary_of(
        &schema["$defs"]["linker"]["properties"]["artifact"]["properties"]["agreement"],
    )
    .as_array()
    .expect("linker.artifact.agreement declares an enum")
    .iter()
    .map(|v| v.as_str().expect("enum values are strings"))
    .collect();
    let emitted: BTreeSet<&str> = chard::toolchain::Agreement::ALL
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(
        emitted,
        declared,
        "toolchain.linker.artifact.agreement: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );
}

#[test]
fn the_elf_data_vocabulary_matches_the_code() {
    let schema = schema();
    let declared: BTreeSet<String> = schema["$defs"]["elf_facts"]["properties"]["elf_data"]["enum"]
        .as_array()
        .expect("elf_data declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings").to_owned())
        .collect();
    let orders: BTreeSet<String> = chard::elf::ByteOrder::ALL
        .iter()
        .map(|o| o.as_str().to_owned())
        .collect();
    assert_eq!(orders, declared);
    for o in chard::elf::ByteOrder::ALL {
        assert_eq!(
            serde_json::to_value(o).expect("serializes"),
            Value::from(o.as_str()),
            "the published spelling is `as_str`"
        );
    }
}

#[test]
fn the_witness_source_vocabulary_matches_the_code() {
    let schema = schema();
    let declared: BTreeSet<String> = schema
        .pointer("/properties/run/properties/artifact_witness/properties/source/enum")
        .and_then(Value::as_array)
        .expect("artifact_witness.source declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings").to_owned())
        .collect();
    let sources: BTreeSet<String> = chard::compile::WitnessSource::ALL
        .iter()
        .map(|s| s.as_str().to_owned())
        .collect();
    assert_eq!(sources, declared);
    for source in chard::compile::WitnessSource::ALL {
        assert_eq!(
            serde_json::to_value(source).expect("serializes"),
            Value::from(source.as_str()),
            "the published spelling is `as_str`"
        );
    }
}

#[test]
fn a_report_naming_rejected_profile_flags_conforms() {
    if !can_run("that a report naming rejected profile flags conforms") {
        return;
    }
    let work = common::Work::new("schema", "rejected-flags");
    let report = report_for(
        "explicit",
        &[
            "--flags",
            "-O2 -fno-aaa-flag -fno-bbb-flag",
            "--probe",
            "no-plt",
        ],
        work.dir(),
    );
    assert_conforms(&report, "rejected flags");
    let rejections: Vec<&Value> = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter_map(|d| d.get("rejection"))
        .collect();
    assert_eq!(rejections.len(), 2, "{}", report["diagnostics"]);
    let schema = schema();
    let required =
        schema["properties"]["diagnostics"]["items"]["properties"]["rejection"]["required"]
            .as_array()
            .expect("rejection lists its required fields")
            .len();
    for r in rejections {
        assert_eq!(
            r.as_object().map(serde_json::Map::len),
            Some(required),
            "every field is required and none is extra: {r}"
        );
    }
}

#[test]
fn the_gate_allowance_vocabulary_matches_the_code() {
    let schema = schema();
    let gate = &schema["properties"]["coverage"]["properties"]["gate"]["properties"];
    let code: BTreeSet<String> = chard::report::Allowance::ALL
        .iter()
        .map(|a| {
            serde_json::to_value(a)
                .expect("serializes")
                .as_str()
                .expect("a string")
                .to_owned()
        })
        .collect();
    for node in [
        &gate["allowed"]["items"],
        &gate["excused"]["items"]["properties"]["rule"],
    ] {
        let declared: BTreeSet<String> = vocabulary_of(node)
            .as_array()
            .expect("an open enumeration")
            .iter()
            .map(|v| v.as_str().expect("enum values are strings").to_owned())
            .collect();
        assert_eq!(code, declared);
    }
}

#[test]
fn the_rejection_provenance_vocabulary_matches_the_code() {
    let schema = schema();
    let declared: BTreeSet<String> = schema["properties"]["diagnostics"]["items"]["properties"]
        ["rejection"]["properties"]["supplied_by"]["enum"]
        .as_array()
        .expect("supplied_by declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings").to_owned())
        .collect();
    let code: BTreeSet<String> = chard::report::SuppliedBy::ALL
        .iter()
        .map(|s| {
            serde_json::to_value(s)
                .expect("serializes")
                .as_str()
                .expect("a string")
                .to_owned()
        })
        .collect();
    assert_eq!(code, declared);
}

#[test]
fn the_target_abi_vocabulary_matches_the_code() {
    let schema = schema();
    let target = &schema["properties"]["toolchain"]["properties"]["target"]["properties"];
    let abi = &target["abi"]["properties"];
    let declared_abi = |field: &str| -> BTreeSet<String> {
        vocabulary_of(&abi[field])
            .as_array()
            .unwrap_or_else(|| panic!("toolchain.target.abi.{field} declares an enum"))
            .iter()
            .map(|v| v.as_str().expect("enum values are strings").to_owned())
            .collect()
    };
    let abi_agreements: BTreeSet<String> = chard::toolchain::AbiAgreement::ALL
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect();
    assert_eq!(abi_agreements, declared_abi("agreement"));
    for a in chard::toolchain::AbiAgreement::ALL {
        assert_eq!(
            serde_json::to_value(a).expect("serializes"),
            Value::from(a.as_str()),
            "the published spelling is `as_str`"
        );
    }
    // What each row stands for, as `Abi` publishes it: one spelling per table architecture.
    let expected: BTreeSet<String> = chard::mechanism::ARCHS
        .iter()
        .map(|arch| {
            chard::toolchain::Abi::of_arch(arch)
                .unwrap_or_else(|| panic!("{arch} has rows"))
                .to_string()
        })
        .collect();
    assert_eq!(expected, declared_abi("expected"));
}

#[test]
fn the_target_agreement_vocabulary_matches_the_code() {
    let schema = schema();
    let target = &schema["properties"]["toolchain"]["properties"]["target"]["properties"];
    let declared = |field: &str| -> BTreeSet<String> {
        vocabulary_of(&target[field])
            .as_array()
            .unwrap_or_else(|| panic!("toolchain.target.{field} declares an enum"))
            .iter()
            .map(|v| v.as_str().expect("enum values are strings").to_owned())
            .collect()
    };
    let agreements: BTreeSet<String> = chard::toolchain::ArchAgreement::ALL
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect();
    assert_eq!(agreements, declared("agreement"));
    let sources: BTreeSet<String> = chard::toolchain::ArchSource::ALL
        .iter()
        .map(|s| s.as_str().to_owned())
        .collect();
    assert_eq!(sources, declared("source"));
    for a in chard::toolchain::ArchAgreement::ALL {
        assert_eq!(
            serde_json::to_value(a).expect("serializes"),
            Value::from(a.as_str()),
            "the published spelling is `as_str`"
        );
    }

    let witness = &target["macros"]["properties"];
    let profile = &target["profile_macros"]["properties"];
    let cxx = &target["profile_macros_cxx"]["properties"];
    let enum_of = |v: &Value, at: &str| -> BTreeSet<String> {
        vocabulary_of(v)
            .as_array()
            .unwrap_or_else(|| panic!("toolchain.target.{at} declares an enum"))
            .iter()
            .map(|v| v.as_str().expect("enum values are strings").to_owned())
            .collect()
    };
    // A dump under profile flags never reads `superseded`: it is the flagless dump's reading
    // where the gate read the dump under the profile's C flags.
    let macro_agreements: BTreeSet<String> = chard::toolchain::MacroAgreement::ALL
        .iter()
        .filter(|a| **a != chard::toolchain::MacroAgreement::Superseded)
        .map(|a| a.as_str().to_owned())
        .collect();
    assert_eq!(
        macro_agreements,
        enum_of(&profile["agreement"], "profile_macros.agreement")
    );
    assert_eq!(
        macro_agreements,
        enum_of(&cxx["agreement"], "profile_macros_cxx.agreement")
    );
    // The flagless dump never reads `dump-failed`: `toolchain::detect` refuses a driver
    // whose intrinsic dump is empty, so the vocabulary it publishes omits it.
    let flagless: BTreeSet<String> = chard::toolchain::MacroAgreement::ALL
        .iter()
        .filter(|a| **a != chard::toolchain::MacroAgreement::DumpFailed)
        .map(|a| a.as_str().to_owned())
        .collect();
    assert_eq!(flagless, enum_of(&witness["agreement"], "macros.agreement"));
    for a in chard::toolchain::MacroAgreement::ALL {
        assert_eq!(
            serde_json::to_value(a).expect("serializes"),
            Value::from(a.as_str()),
            "the published spelling is `as_str`"
        );
    }
    let macros: BTreeSet<String> = chard::toolchain::ARCH_MACROS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    assert_eq!(
        macros,
        enum_of(&witness["defined"]["items"], "macros.defined")
    );
    assert_eq!(
        macros,
        enum_of(&profile["defined"]["items"], "profile_macros.defined")
    );
    assert_eq!(
        macros,
        enum_of(&cxx["defined"]["items"], "profile_macros_cxx.defined")
    );
}

#[test]
fn the_relro_vocabulary_is_pinned_against_the_reader() {
    let schema = schema();
    let options = schema["$defs"]["elf_facts"]["properties"]["relro"]["enum"]
        .as_array()
        .expect("relro declares an enum");
    assert!(
        options.contains(&Value::Null),
        "relro admits null for an object the loader cannot run"
    );
    let declared: BTreeSet<&str> = options.iter().filter_map(Value::as_str).collect();
    assert_eq!(
        options.len(),
        declared.len() + 1,
        "every enum member is a level or the one null: {options:?}"
    );
    let emitted: BTreeSet<&str> = chard::elf::RELRO_LEVELS.iter().copied().collect();
    assert_eq!(
        emitted,
        declared,
        "elf_facts.relro: code alone emits {:?}, schema alone declares {:?}",
        emitted.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&emitted).collect::<Vec<_>>(),
    );
}

#[test]
fn the_truncation_vocabulary_is_pinned_against_the_reader() {
    let schema = schema();
    let item = &schema["$defs"]["elf_facts"]["properties"]["truncations"]["items"];
    assert_eq!(
        item["required"],
        serde_json::json!(["table", "kind", "detail"]),
        "a truncation is exactly its table, its kind and the reader's sentence"
    );
    let declared = |member: &str| -> BTreeSet<&str> {
        vocabulary_of(&item["properties"][member])
            .as_array()
            .unwrap_or_else(|| panic!("truncations[].{member} declares an enum"))
            .iter()
            .map(|v| v.as_str().expect("an enum member is a string"))
            .collect()
    };
    let tables: BTreeSet<&str> = chard::elf::ElfTable::ALL
        .iter()
        .map(|t| t.as_str())
        .collect();
    let kinds: BTreeSet<&str> = chard::elf::TruncationKind::ALL
        .iter()
        .map(|k| k.as_str())
        .collect();
    for (member, emitted) in [("table", tables), ("kind", kinds)] {
        let declared = declared(member);
        assert_eq!(
            emitted,
            declared,
            "elf_facts.truncations[].{member}: code alone emits {:?}, schema alone declares {:?}",
            emitted.difference(&declared).collect::<Vec<_>>(),
            declared.difference(&emitted).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn the_pattern_subset_matches_what_it_claims_and_refuses_the_rest() {
    // Read from the schema rather than copied into the test.
    let schema = schema();
    let profile = schema["properties"]["profile"]["properties"]["id"]["pattern"]
        .as_str()
        .expect("profile.id declares a pattern");
    for good in [
        "bare",
        "bare-optimized",
        "openssf-tldr",
        "explicit:my_flags-1.2",
        "bare+env:0123456789ab",
        "explicit:0123456789ab+env:0123456789ab",
    ] {
        assert!(matches_pattern(profile, good), "{good} should match");
    }
    for bad in [
        "",
        "Bare",
        "bare ",
        "explicit:",
        "explicit:has space",
        "bare-optimized-extra",
        "bare+env:",
        "bare+env:0123456789abc",
        "bare+env:0123456789AB",
        "bare+env:0123456789ab+env:0123456789ab",
        "+env:0123456789ab",
    ] {
        assert!(!matches_pattern(profile, bad), "{bad:?} should not match");
    }

    assert!(matches_format("date-time", "2026-07-31T12:00:00Z"));
    assert!(matches_format("date-time", "2028-02-29T23:59:59Z"));
    for bad in [
        "2026-07-31T12:00:00+01:00",
        "2026-07-31 12:00:00Z",
        "2026-07-31T12:00:0AZ",
        "",
        // The shape with no instant behind it, which a shape-only check accepted.
        "2026-13-45T25:61:61Z",
        "2026-00-10T12:00:00Z",
        "2026-09-31T12:00:00Z",
        "2100-02-29T12:00:00Z",
        "2026-07-31T24:00:00Z",
    ] {
        assert!(
            !matches_format("date-time", bad),
            "{bad:?} is not a date-time"
        );
    }

    let unsupported = std::panic::catch_unwind(|| matches_pattern("[0-9]*", "123"));
    assert!(
        unsupported.is_err(),
        "an unsupported construct must panic, not silently match"
    );
}

#[test]
fn a_matrix_conforms_to_its_schema() {
    if !can_run("that a matrix validates against the schema chard ships") {
        return;
    }
    let binary = chard_binary();
    if !binary.exists() {
        cannot_run(&format!("{} not built", binary.display()));
    }
    let work = common::Work::new("schema", "matrix");
    let bare = shared_report("bare");
    let tldr = shared_report("openssf-tldr");
    let a = work.dir().join("bare.json");
    let b = work.dir().join("tldr.json");
    std::fs::write(&a, serde_json::to_string(&bare).expect("serialize")).expect("write");
    std::fs::write(&b, serde_json::to_string(&tldr).expect("serialize")).expect("write");

    let output = Command::new(&binary)
        .arg("matrix")
        .arg(&a)
        .arg(&b)
        .output()
        .expect("run matrix");
    let text = String::from_utf8_lossy(&output.stdout);
    let m: Value = serde_json::from_str(&text).expect("matrix emits JSON");
    assert!(m.get("error").is_none(), "matrix failed: {text}");

    let schema = schema_at("schema/chard-matrix.schema.json");
    let mut errors = Vec::new();
    validate(&m, &schema, &schema, "", &mut errors);
    assert!(
        errors.is_empty(),
        "matrix does not conform ({} problems):\n{}",
        errors.len(),
        errors.join("\n")
    );

    // Two reports differing only in profile: that axis varies, the rest do not.
    assert_eq!(
        m["varying_axes"],
        serde_json::json!(["profile"]),
        "only the profile should vary between these two"
    );
    assert!(
        m["invariant_axes"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == "arch")),
        "arch must be reported invariant so nobody generalises across architectures"
    );
}

/// The column key the schema names: distro id, version id, toolchain id, profile id.
type Column = (String, String, String, String);

/// Join `reports` on the documented keys: one column per tuple, one row per check,
/// each cell the verdict.
fn join(reports: &[&Value]) -> BTreeMap<Column, BTreeMap<String, String>> {
    let text = |report: &Value, path: &[&str]| -> String {
        let mut cur = report;
        for p in path {
            cur = cur.get(p).unwrap_or(&Value::Null);
        }
        cur.as_str()
            .unwrap_or_else(|| panic!("{path:?} is a string in every report"))
            .to_owned()
    };
    let mut table: BTreeMap<Column, BTreeMap<String, String>> = BTreeMap::new();
    for report in reports {
        let column = (
            text(report, &["environment", "distro", "id"]),
            text(report, &["environment", "distro", "version_id"]),
            text(report, &["toolchain", "id"]),
            text(report, &["profile", "id"]),
        );
        let rows = table.entry(column.clone()).or_default();
        for obs in report["observations"].as_array().expect("observations") {
            let check = obs["check"].as_str().expect("check is a string").to_owned();
            let verdict = obs["verdict"]
                .as_str()
                .expect("verdict is a string")
                .to_owned();
            assert!(
                rows.insert(check.clone(), verdict).is_none(),
                "{check} appeared twice in one column {column:?}: the row key is not a key"
            );
        }
    }
    table
}

#[test]
fn two_reports_join_on_the_keys_the_schema_names() {
    if !can_run("that two reports join on the documented column tuple and row key") {
        return;
    }
    let work = common::Work::new("schema", "join");
    let narrow = ["--probe", "toolchain-macros", "--probe", "stack-canary"];
    let plain = report_for(
        "explicit",
        &[&narrow[..], &["--flags", "-O2"]].concat(),
        &work.dir().join("plain"),
    );
    let hardened = report_for(
        "explicit",
        &[&narrow[..], &["--flags", "-O2 -fstack-protector-strong"]].concat(),
        &work.dir().join("hardened"),
    );

    let table = join(&[&plain, &hardened]);

    assert_eq!(
        table.len(),
        2,
        "two explicit flag lists must be two columns; got {:?}",
        table.keys().collect::<Vec<_>>()
    );
    let columns: Vec<&Column> = table.keys().collect();
    assert!(
        columns.iter().all(|c| c.3.starts_with("explicit:")),
        "both columns are explicit profiles: {columns:?}"
    );
    assert_ne!(columns[0].3, columns[1].3, "the profile ids differ");
    // The three environment and toolchain elements agree: only the profile varied.
    assert_eq!(
        (&columns[0].0, &columns[0].1, &columns[0].2),
        (&columns[1].0, &columns[1].1, &columns[1].2)
    );

    let rows: Vec<&BTreeMap<String, String>> = table.values().collect();
    assert_eq!(
        rows[0].keys().collect::<Vec<_>>(),
        rows[1].keys().collect::<Vec<_>>(),
        "both columns carry the same row set, since the same selection was measured"
    );
    // Read a joined cell: the same row in both columns, each a verdict.
    let verdicts: BTreeSet<&str> = chard::report::Verdict::ALL
        .iter()
        .map(|v| v.as_str())
        .collect();
    for row in ["ssp-level", "canary-emitted"] {
        for (column, cells) in &table {
            let cell = cells
                .get(row)
                .unwrap_or_else(|| panic!("{row} is missing from column {column:?}"));
            assert!(
                verdicts.contains(cell.as_str()),
                "{row} in {column:?} reads {cell}"
            );
        }
    }

    // And the run ids differ, since the two measured different flags.
    assert_ne!(plain["run"]["id"], hardened["run"]["id"]);
    assert_eq!(plain["run"]["id"].as_str().map(str::len), Some(16));
}

#[test]
fn the_published_toolchain_id_is_the_qualified_join_key() {
    if !can_run("that the published toolchain.id carries the libc and distribution halves") {
        return;
    }
    let work = common::Work::new("schema", "toolchain-id");
    let report = report_for("bare", &["--probe", "toolchain-macros"], work.dir());

    let field = |path: &[&str]| -> Option<String> {
        let mut cur = &report;
        for p in path {
            cur = cur.get(p)?;
        }
        cur.as_str().map(ToOwned::to_owned)
    };
    let kind = field(&["toolchain", "kind"]).expect("toolchain.kind is published");
    let version = field(&["toolchain", "version"]).expect("toolchain.version is published");
    let libc_impl = field(&["environment", "libc", "impl"]).expect("libc.impl is published");
    let libc_tag = match field(&["environment", "libc", "version"]) {
        Some(v) => format!("{libc_impl}{v}"),
        None => libc_impl,
    };
    let distro_id = field(&["environment", "distro", "id"]).expect("distro.id is published");
    let distro_version =
        field(&["environment", "distro", "version_id"]).expect("distro.version_id is published");
    let distro_tag = if distro_version == "unknown" {
        distro_id
    } else {
        format!("{distro_id}{distro_version}")
    };
    let expected = format!("{kind}-{version}-{libc_tag}-{distro_tag}");

    let published = field(&["toolchain", "id"]).expect("toolchain.id is published");
    assert_eq!(
        published, expected,
        "toolchain.id is not kind-version-libc-distro from the report's environment block"
    );
    // The oracle is non-degenerate: both halves the environment contributes are in the key,
    // so a key of the unqualified `kind-version` form is distinct from the expected one.
    assert_ne!(
        published,
        format!("{kind}-{version}"),
        "the key must carry more than the compiler's own name and version"
    );
}

#[test]
fn the_schema_names_the_invocation_paths_normalize_replaces() {
    let schema = schema();
    let description = schema
        .pointer("/properties/run/properties/invocation/description")
        .and_then(Value::as_str)
        .expect("run.invocation carries a description");
    let listed: BTreeSet<&str> = description
        .split_once("so the values of ")
        .and_then(|(_, rest)| rest.split_once(" are the paths"))
        .expect("the description lists the options as `so the values of ... are the paths`")
        .0
        .split([',', ' '])
        .filter(|word| word.starts_with('-'))
        .collect();
    let code: BTreeSet<&str> = chard::report::INVOCATION_PATH_OPTIONS
        .iter()
        .copied()
        .collect();
    assert!(!code.is_empty(), "an empty list would compare nothing");
    assert_eq!(code, listed);
}

#[test]
fn the_schema_marks_exactly_the_fields_normalize_zeroes() {
    fn walk(node: &Value, path: &str, found: &mut BTreeSet<String>) {
        match node {
            Value::Object(map) => {
                if map.contains_key("x-volatile") {
                    found.insert(path.to_owned());
                }
                for (key, value) in map {
                    walk(value, &format!("{path}/{key}"), found);
                }
            }
            Value::Array(items) => {
                for (i, value) in items.iter().enumerate() {
                    walk(value, &format!("{path}/{i}"), found);
                }
            }
            _ => {}
        }
    }
    let mut marked = BTreeSet::new();
    walk(&schema(), "", &mut marked);
    let declared: BTreeSet<String> = chard::report::VOLATILE_FIELDS
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    assert_eq!(
        marked,
        declared,
        "x-volatile: schema alone marks {:?}, report::VOLATILE_FIELDS alone declares {:?}",
        marked.difference(&declared).collect::<Vec<_>>(),
        declared.difference(&marked).collect::<Vec<_>>(),
    );
    assert!(
        !marked.is_empty(),
        "no field is marked, so two empty sets were compared"
    );
}

#[test]
fn the_schema_lists_exactly_the_readings_normalize_replaces() {
    let schema = schema();
    let listed: BTreeSet<(String, String)> = schema
        .pointer("/$defs/run_record/properties/stdout/x-volatile-readings")
        .and_then(Value::as_array)
        .expect("run_record.stdout carries x-volatile-readings")
        .iter()
        .map(|entry| {
            let field = |name: &str| {
                entry
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("an x-volatile-readings entry without {name}"))
                    .to_owned()
            };
            (field("check"), field("marker"))
        })
        .collect();
    let declared: BTreeSet<(String, String)> = chard::report::VOLATILE_READINGS
        .iter()
        .map(|r| (r.check.to_owned(), r.marker.to_owned()))
        .collect();
    assert_eq!(listed, declared);
    assert!(!listed.is_empty(), "two empty lists were compared");
    let checks: BTreeSet<String> = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter().map(|c| c.id.to_owned()))
        .collect();
    for (check, _) in &declared {
        assert!(checks.contains(check), "{check} is not a check chard runs");
    }
}

/// Every volatile reading a run printed is replaced, wherever the report quotes it.
/// Read off the whole rendered report rather than the one observation, so a copy of the
/// value somewhere `normalize` does not reach fails here.
fn assert_volatile_readings_replaced(report: &Value, text: &str) {
    for reading in chard::report::VOLATILE_READINGS {
        assert!(
            report["observations"]
                .as_array()
                .is_some_and(|all| all.iter().any(|o| o["check"] == reading.check)),
            "{} was not measured, so its reading went untested",
            reading.check
        );
        let masked = format!("{}{}", reading.marker, chard::report::NORMALIZED_READING);
        // Both counts are zero when the run never printed the reading (a probe that
        // reported `probe-invalid=` instead), and equal zeros would pass while testing
        // nothing.
        let spoken = text.matches(reading.marker).count();
        assert!(
            spoken > 0,
            "{} never printed `{}`, so its replacement went untested",
            reading.check,
            reading.marker
        );
        assert_eq!(
            text.matches(masked.as_str()).count(),
            spoken,
            "a `{}` value survived --normalize",
            reading.marker
        );
    }
}

/// The second run's work directory, longer than the first's by more than any cut's slack.
const LONGER_WORKDIR: &str =
    "second-in-a-work-directory-whose-name-is-longer-than-the-first-by-a-wide-margin";

#[test]
fn two_normalized_runs_of_one_measurement_are_byte_identical() {
    if !can_run("that two normalized runs of the same measurement produce identical bytes") {
        return;
    }
    let work = common::Work::new("schema", "normalize");
    let mut outputs = Vec::new();
    for tag in ["first", LONGER_WORKDIR] {
        let workdir = work.dir().join(tag);
        std::fs::create_dir_all(&workdir).expect("a work directory per run");
        let output = work.dir().join(format!("{tag}.json"));
        let status = Command::new(chard_binary())
            .arg("measure")
            .args(["--profile", "bare", "--normalize"])
            .args(["--probe", "toolchain-macros"])
            .args(["--probe", "stack-canary"])
            .args(["--probe", "fortify-known-object"])
            .args(["--probe", "stack-clash"])
            .arg("--workdir")
            .arg(&workdir)
            .arg("--output")
            .arg(&output)
            .output()
            .expect("spawning chard");
        assert!(
            status.status.success(),
            "chard failed:\n{}",
            String::from_utf8_lossy(&status.stderr)
        );
        outputs.push(std::fs::read_to_string(&output).expect("the report was written"));
    }
    let first: Value = serde_json::from_str(&outputs[0]).expect("a report");
    assert_conforms(&first, "normalized");
    assert_eq!(
        first["run"]["started_utc"],
        chard::report::NORMALIZED_STARTED_UTC
    );
    assert_eq!(first["run"]["duration_ms"], 0);
    assert!(
        first["run"]["invocation"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == chard::report::NORMALIZED_PATH)),
        "the invocation's paths are replaced: {}",
        first["run"]["invocation"]
    );
    assert_volatile_readings_replaced(&first, &outputs[0]);

    // Every difference chard is answerable for, and no tolerance beyond that.
    let (relabelled, moved) = relabel_moved_digests(&outputs);
    if let Some(witness) = first["run"].get("artifact_witness") {
        assert_eq!(
            witness["source"], "derived",
            "a normalized run did not derive its witness"
        );
    }
    assert!(
        cfg!(target_os = "macos") || moved == 0,
        "{moved} artifact digest(s) differ between two normalized runs of one measurement"
    );
    let differing: Vec<(&str, &str)> = relabelled[0]
        .lines()
        .zip(relabelled[1].lines())
        .filter(|(a, b)| a != b)
        .collect();
    let chards_own: Vec<String> = differing
        .iter()
        .filter(|(a, _)| !a.trim_start().starts_with("\"artifact_sha256\""))
        .take(20)
        .map(|(a, b)| format!("  - {a}\n  + {b}"))
        .collect();
    assert!(
        chards_own.is_empty(),
        "two normalized runs differ in chard's own lines, {} shown ({} vs {} lines in all):\n{}",
        chards_own.len(),
        outputs[0].lines().count(),
        outputs[1].lines().count(),
        chards_own.join("\n")
    );
    assert_eq!(
        outputs[0].lines().count(),
        outputs[1].lines().count(),
        "two normalized runs produced reports of different shape"
    );
    assert!(
        differing.is_empty(),
        "with the moved digests relabelled the two reports still differ: {differing:?}"
    );
    eprintln!(
        "schema_conformance: two normalized runs differ in {moved} artifact digest(s) \
         and nothing else"
    );
}

/// Two rendered reports with each pair of digests their `artifact_sha256` lines disagree on
/// replaced by one placeholder in both, re-rendered, and the number of pairs.
fn relabel_moved_digests(outputs: &[String]) -> (Vec<String>, usize) {
    let digest_of = |line: &str| -> Option<String> {
        let value = line.trim().strip_prefix("\"artifact_sha256\": ")?;
        Some(value.trim_end_matches(',').trim_matches('"').to_owned())
    };
    let moved: Vec<(String, String)> = outputs[0]
        .lines()
        .zip(outputs[1].lines())
        .filter(|(a, b)| a != b)
        .filter_map(|(a, b)| Some((digest_of(a)?, digest_of(b)?)))
        .collect();
    let relabelled = [0, 1]
        .map(|run| {
            let mut text = outputs[run].clone();
            for (i, pair) in moved.iter().enumerate() {
                let digest = if run == 0 { &pair.0 } else { &pair.1 };
                text = text.replace(digest.as_str(), &format!("nonreproducible-{i}"));
                // The sixteen digits a sentence quotes a digest by (`sha256:<prefix>`).
                if let Some(prefix) = digest.get(..16) {
                    text = text.replace(
                        &format!("sha256:{prefix}"),
                        &format!("sha256:nonreproducible-{i}"),
                    );
                }
            }
            let value: Value = serde_json::from_str(&text).expect("a report");
            serde_json::to_string_pretty(&value).expect("re-rendering a report")
        })
        .to_vec();
    (relabelled, moved.len())
}

/// How a leaf two reports disagree on is accounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Difference {
    /// Under a node the schema marks `x-volatile`.
    Volatile,
    /// A string equal in both once every `report::VOLATILE_READINGS` value is masked.
    Reading,
    /// Neither: a difference the schema does not declare.
    Undeclared,
}

/// `text` with the digits after every `report::VOLATILE_READINGS` marker removed.
fn mask_readings(text: &str) -> String {
    let mut text = text.to_owned();
    for reading in chard::report::VOLATILE_READINGS {
        let mut out = String::with_capacity(text.len());
        let mut rest = text.as_str();
        while let Some((before, after)) = rest.split_once(reading.marker) {
            out.push_str(before);
            out.push_str(reading.marker);
            rest = after.trim_start_matches(|c: char| c.is_ascii_digit());
        }
        out.push_str(rest);
        text = out;
    }
    text
}

/// Every leaf where `a` and `b` differ, with how it is accounted for.
fn differing_leaves(
    pair: (&Value, &Value),
    node: &Value,
    root: &Value,
    path: &str,
    volatile: bool,
    out: &mut Vec<(String, Difference)>,
) {
    let (left, right) = pair;
    if left == right {
        return;
    }
    let mut volatile = volatile || node.get("x-volatile").is_some();
    let node = match node.get("$ref").and_then(Value::as_str) {
        Some(reference) => resolve(reference, root).unwrap_or(&Value::Null),
        None => node,
    };
    volatile = volatile || node.get("x-volatile").is_some();
    let leaf = |out: &mut Vec<(String, Difference)>, path: String, volatile: bool| {
        out.push((
            path,
            if volatile {
                Difference::Volatile
            } else {
                Difference::Undeclared
            },
        ));
    };
    match (left, right) {
        (Value::Object(lmap), Value::Object(rmap)) => {
            let keys: BTreeSet<&String> = lmap.keys().chain(rmap.keys()).collect();
            for key in keys {
                let child = node
                    .get("properties")
                    .and_then(|p| p.get(key.as_str()))
                    .or_else(|| node.get("additionalProperties").filter(|n| n.is_object()))
                    .unwrap_or(&Value::Null);
                let at = format!("{path}/{key}");
                match (lmap.get(key.as_str()), rmap.get(key.as_str())) {
                    (Some(lv), Some(rv)) => {
                        differing_leaves((lv, rv), child, root, &at, volatile, out);
                    }
                    _ => leaf(out, at, volatile || child.get("x-volatile").is_some()),
                }
            }
        }
        (Value::Array(litems), Value::Array(ritems)) => {
            for i in 0..litems.len().max(ritems.len()) {
                let child = node
                    .get("prefixItems")
                    .and_then(|p| p.get(i))
                    .or_else(|| node.get("items"))
                    .unwrap_or(&Value::Null);
                let at = format!("{path}/{i}");
                match (litems.get(i), ritems.get(i)) {
                    (Some(lv), Some(rv)) => {
                        differing_leaves((lv, rv), child, root, &at, volatile, out);
                    }
                    _ => leaf(out, at, volatile),
                }
            }
        }
        (Value::String(x), Value::String(y))
            if !volatile && mask_readings(x) == mask_readings(y) =>
        {
            out.push((path.to_owned(), Difference::Reading));
        }
        _ => leaf(out, path.to_owned(), volatile),
    }
}

/// Every string in `report` that contains `needle`, by its path.
fn strings_containing(report: &Value, needle: &str, path: &str, out: &mut Vec<String>) {
    match report {
        Value::String(s) if s.contains(needle) => out.push(path.to_owned()),
        Value::Object(map) => {
            for (key, value) in map {
                strings_containing(value, needle, &format!("{path}/{key}"), out);
                if key.contains(needle) {
                    out.push(format!("{path}/{key} (the key)"));
                }
            }
        }
        Value::Array(items) => {
            for (i, value) in items.iter().enumerate() {
                strings_containing(value, needle, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// `report` conforms, records `argv[0]` as `chard`, and names `root` only in a value of
/// `report::INVOCATION_PATH_OPTIONS` in `run.invocation`, which `THREAT_MODEL.md` declares.
fn assert_names_its_directories_only_where_declared(report: &Value, root_text: &str) {
    assert_conforms(report, "raw");
    let invocation = report["run"]["invocation"]
        .as_array()
        .expect("run.invocation is an array");
    assert_eq!(
        invocation[0], "chard",
        "argv[0] keeps only the binary's name"
    );
    let mut named = Vec::new();
    strings_containing(report, root_text, "", &mut named);
    let declared = |path: &str| -> bool {
        let Some(i) = path
            .strip_prefix("/run/invocation/")
            .and_then(|i| i.parse::<usize>().ok())
        else {
            return false;
        };
        let options = chard::report::INVOCATION_PATH_OPTIONS;
        let joined = invocation[i]
            .as_str()
            .and_then(|a| a.split_once('='))
            .map(|p| p.0);
        let attached = invocation[i].as_str().is_some_and(|a| {
            options
                .iter()
                .filter(|o| !o.starts_with("--"))
                .any(|o| a.strip_prefix(o).is_some_and(|rest| !rest.is_empty()))
        });
        joined.is_some_and(|o| options.contains(&o))
            || attached
            || (i > 0
                && invocation[i - 1]
                    .as_str()
                    .is_some_and(|o| options.contains(&o)))
    };
    let undeclared: Vec<&String> = named.iter().filter(|p| !declared(p)).collect();
    assert!(
        undeclared.is_empty(),
        "the report names run directories outside the declared invocation values: {undeclared:?}"
    );
    assert!(
        !named.is_empty(),
        "the work directory's path appears nowhere, so the search found nothing to test"
    );
}

/// Two rendered reports differ only under `x-volatile` marks, in
/// `report::VOLATILE_READINGS` values and in what carries the run's witness, their
/// invocations among the differences. The comparison half of
/// `two_raw_runs_from_different_directories_differ_only_where_the_schema_says`.
fn assert_runs_differ_only_where_declared(outputs: &[String]) {
    let nonce_of = |text: &str| -> Option<String> {
        let report: Value = serde_json::from_str(text).expect("a report");
        let witness = report["run"].get("artifact_witness")?;
        assert_eq!(
            witness["source"], "os-random",
            "a run without --normalize did not draw its witness from the operating system"
        );
        Some(witness["nonce"].as_str().expect("a nonce").to_owned())
    };
    let nonces = [nonce_of(&outputs[0]), nonce_of(&outputs[1])];
    let witnessed = match (&nonces[0], &nonces[1]) {
        (Some(first), Some(second)) => {
            assert_ne!(first, second, "two runs drew one nonce");
            true
        }
        (None, None) => false,
        _ => panic!("one of two runs on one host carries a witness and the other none"),
    };
    assert_eq!(
        witnessed,
        !cfg!(target_os = "macos"),
        "a run carries a witness exactly where its artifacts are ELF"
    );
    let unwitnessed: Vec<String> = outputs
        .iter()
        .zip(&nonces)
        .map(|(text, nonce)| match nonce {
            Some(nonce) => text.replace(nonce.as_str(), "this-runs-nonce"),
            None => text.clone(),
        })
        .collect();
    let (relabelled, moved) = relabel_moved_digests(&unwitnessed);
    // A moved digest is excused where the run's nonce is in the artifact, and where a
    // linker is known not to reproduce its output (Apple's, under an explicit `-O0`).
    let digests = outputs[0]
        .lines()
        .filter(|l| l.trim_start().starts_with("\"artifact_sha256\""))
        .count();
    assert!(digests > 0, "the first report names no artifact digest");
    if witnessed {
        assert_eq!(
            moved, digests,
            "{moved} of {digests} artifact digest lines differ between two witnessed runs"
        );
    }
    let reports: Vec<Value> = relabelled
        .iter()
        .map(|text| serde_json::from_str(text).expect("a report"))
        .collect();
    let schema = schema();
    let mut differences = Vec::new();
    differing_leaves(
        (&reports[0], &reports[1]),
        &schema,
        &schema,
        "",
        false,
        &mut differences,
    );
    let undeclared: Vec<&String> = differences
        .iter()
        .filter(|(_, d)| *d == Difference::Undeclared)
        .map(|(p, _)| p)
        .take(20)
        .collect();
    assert!(
        undeclared.is_empty(),
        "two runs in different directories differ in undeclared fields ({} shown): {undeclared:?}",
        undeclared.len()
    );
    let volatile = differences
        .iter()
        .filter(|(_, d)| *d == Difference::Volatile)
        .count();
    assert!(
        differences
            .iter()
            .any(|(p, d)| p.starts_with("/run/invocation/") && *d == Difference::Volatile),
        "the two invocations name different directories and were not found to differ"
    );
    eprintln!(
        "schema_conformance: two raw runs differ in {volatile} volatile leaves, {} reading(s) \
         and {moved} artifact digest(s), and nothing else",
        differences.len() - volatile
    );
}

#[cfg(unix)]
#[test]
fn two_raw_runs_from_different_directories_differ_only_where_the_schema_says() {
    if !can_run("that two raw runs from different directories differ only in declared fields") {
        return;
    }
    let work = common::Work::new("schema", "raw-runs");
    let root_text = work
        .dir()
        .to_str()
        .expect("a UTF-8 temporary directory")
        .to_owned();
    let mut outputs = Vec::new();
    // The output path is passed in the two joined spellings, so the declared values the
    // directory search allows are exercised in both forms.
    for (bin_dir, workdir, output, spelling) in [
        ("bin", "first".to_owned(), "first.json", "--output="),
        (
            "binaries-in-a-longer-directory/nested",
            format!("deeper/{LONGER_WORKDIR}"),
            "a-second-output-name.json",
            "-o",
        ),
    ] {
        let bin_dir = work.dir().join(bin_dir);
        std::fs::create_dir_all(&bin_dir).expect("a directory for the binary");
        let binary = bin_dir.join("chard");
        std::os::unix::fs::symlink(chard_binary(), &binary).expect("linking the binary");
        let workdir = work.dir().join(workdir);
        std::fs::create_dir_all(&workdir).expect("a work directory per run");
        let output = work.dir().join(output);
        let status = Command::new(&binary)
            .arg("measure")
            .args(["--profile", "bare"])
            .args(["--probe", "toolchain-macros"])
            .args(["--probe", "stack-canary"])
            .args(["--probe", "fortify-known-object"])
            .args(["--probe", "stack-clash"])
            .arg("--workdir")
            .arg(&workdir)
            .arg({
                let mut joined = std::ffi::OsString::from(spelling);
                joined.push(&output);
                joined
            })
            .output()
            .expect("spawning chard");
        assert!(
            status.status.success(),
            "chard failed:\n{}",
            String::from_utf8_lossy(&status.stderr)
        );
        outputs.push(std::fs::read_to_string(&output).expect("the report was written"));
    }

    let raw: Vec<Value> = outputs
        .iter()
        .map(|text| serde_json::from_str(text).expect("a report"))
        .collect();
    for report in &raw {
        assert_names_its_directories_only_where_declared(report, &root_text);
    }
    assert_runs_differ_only_where_declared(&outputs);
}

#[test]
fn absent_beats_null_for_graded_fields() {
    if !can_run("that an unread graded field is absent rather than null") {
        return;
    }
    let report = shared_report("bare");
    let observations = report["observations"]
        .as_array()
        .expect("observations is an array");
    assert!(
        !observations.is_empty(),
        "the bare report has observations to check"
    );

    for obs in observations {
        for field in ["level", "recommended_level"] {
            if let Some(value) = obs.get(field) {
                assert!(
                    !value.is_null(),
                    "{}: {field} is an explicit null; omit the key instead",
                    obs["check"]
                );
            }
        }
    }
}

#[test]
fn one_unusable_driver_does_not_destroy_the_other_probes() {
    if !can_run("that one unusable driver does not take the whole run with it") {
        return;
    }
    let work = common::Work::new("schema", "unusable-driver");
    let fake = work.dir().join("toolchain");
    std::fs::create_dir_all(&fake).expect("create fake toolchain dir");

    // A working C driver that proxies to the real one...
    let cc = fake.join("gcc");
    let real = match Command::new("sh")
        .args(["-c", "command -v gcc || command -v cc"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        _ => cannot_run("no C compiler to proxy to"),
    };
    if real.is_empty() {
        cannot_run("no C compiler to proxy to");
    }
    std::fs::write(&cc, format!("#!/bin/sh\nexec {real} \"$@\"\n")).expect("write proxy");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cc, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    // ...and a C++ driver beside it that exists and cannot be executed.
    std::fs::write(fake.join("g++"), "not a program\n").expect("write broken g++");

    let report = report_for("bare", &["--cc", &cc.display().to_string()], work.dir());

    let observations = report["observations"]
        .as_array()
        .expect("observations is an array");
    assert!(
        observations.len() > 20,
        "the run collapsed to {} observations",
        observations.len()
    );

    // The affected checks are present and say why, rather than being absent.
    let contained: Vec<&str> = observations
        .iter()
        .filter(|o| {
            o["gating"]["reason"]
                .as_str()
                .is_some_and(|r| r.contains("could not be attempted"))
        })
        .map(|o| o["check"].as_str().unwrap_or("?"))
        .collect();
    assert!(
        !contained.is_empty(),
        "nothing was contained: no gating reason says a build could not be attempted"
    );
    for check in &contained {
        let obs = observations
            .iter()
            .find(|o| o["check"].as_str() == Some(check))
            .expect("the check we just found");
        assert_eq!(
            obs["verdict"].as_str(),
            Some("indeterminate"),
            "{check}: a probe that was not measured does not read `indeterminate`"
        );
    }

    // And the run says out loud that something went unmeasured.
    let errors: Vec<&Value> = report["diagnostics"]
        .as_array()
        .map(|d| {
            d.iter()
                .filter(|x| x["severity"].as_str() == Some("error"))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !errors.is_empty(),
        "a probe went unmeasured and no error diagnostic said so"
    );
    assert_conforms(&report, "report with an unusable C++ driver");
}

#[test]
fn a_constituents_opt_out_is_declared_and_its_header_is_the_codes() {
    let schema = schema();
    let declared: BTreeSet<&str> = schema["properties"]["composites"]["items"]["properties"]
        ["constituents"]["items"]["properties"]["opt_out"]["properties"]["header"]["enum"]
        .as_array()
        .expect("opt_out.header declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::composite::OPT_OUT_HEADERS.iter().copied().collect();
    assert_eq!(
        emitted, declared,
        "opt_out.header disagrees between code and schema"
    );

    let constituent = chard::composite::Constituent {
        flag: "-mbranch-protection=standard",
        check: "branch-protection-marked",
        applicable: true,
        verdict: Some(chard::report::Verdict::On),
        level: Some("full".to_owned()),
        state: chard::composite::ConstituentState::Absent,
        note: Some("n".to_owned()),
        opt_out: Some(chard::composite::OptOut {
            header: chard::composite::PT_OPENBSD_NOBTCFI,
            facts: "0".repeat(64),
        }),
        implementation: None,
        bar: None,
    };
    let document = serde_json::json!({"composites": [{
        "id": "cfi-effective", "title": "t", "derived_from": ["branch-protection-marked"],
        "verdict": "off", "reason": "r", "constituents": [constituent],
    }]});
    let mut errors = Vec::new();
    validate(&document, &schema, &schema, "", &mut errors);
    let errors: Vec<&String> = errors
        .iter()
        .filter(|e| e.starts_with("/composites"))
        .collect();
    assert!(
        errors.is_empty(),
        "the constituent must validate, got: {errors:?}"
    );

    let mut facts = serde_json::to_value(elf_facts_literal(true)).expect("ElfFacts serializes");
    assert_eq!(facts["openbsd_nobtcfi"], Value::Bool(true));
    facts["openbsd_nobtcfi"] = Value::Bool(false);
    let document = serde_json::json!({"facts": {"0".repeat(64): {"kind": "elf", "elf": facts}}});
    let mut errors = Vec::new();
    validate(&document, &schema, &schema, "", &mut errors);
    assert!(
        errors.iter().any(|e| e.contains("openbsd_nobtcfi")),
        "a written `false` is not what the reader writes and must be refused, got: {errors:?}"
    );
}

/// Every closed vocabulary in the schema is one somebody decided about.
const VOCABULARIES: &[(&str, &str)] = &[
    // Pinned against a code-side list by `the_schemas_closed_vocabularies_match_the_code`.
    ("/properties/consistency/properties/status", "pinned"),
    (
        "/properties/environment/properties/libc/properties/impl",
        "pinned",
    ),
    (
        "/properties/environment/properties/execution/properties/mode_evidence/properties/basis",
        "pinned",
    ),
    (
        "/properties/environment/properties/kernel/properties/ownership",
        "pinned",
    ),
    ("/properties/profile/properties/flags_source", "pinned"),
    ("/$defs/controls/properties/withheld_because", "pinned"),
    // Pinned by `the_fact_entry_kinds_match_the_code`.
    ("/$defs/fact_entry/properties/kind", "pinned"),
    // Pinned against `link_inputs::LinkageForm::ALL` by
    // `the_schemas_closed_vocabularies_match_the_code`.
    ("/$defs/link_inputs/properties/form", "pinned"),
    // Pinned against `build/revision.rs`'s `Source` by `tests/build_revision.rs`'s
    // `the_source_spellings_are_the_schemas_and_the_join_keys`.
    (
        "/properties/run/properties/harness_revision_source",
        "pinned",
    ),
    // Pinned by `the_witness_source_vocabulary_matches_the_code`.
    (
        "/properties/run/properties/artifact_witness/properties/source",
        "pinned",
    ),
    // Pinned by `the_cxx_assertions_sources_match_the_code`.
    (
        "/$defs/observation/properties/evidence/properties/cxx_assertions_source",
        "pinned",
    ),
    (
        "/$defs/observation/properties/gating/properties/rule",
        "pinned",
    ),
    // Pinned by `the_premise_vocabulary_matches_the_code_and_names_each_verdict`.
    (
        "/$defs/observation/properties/gating/properties/premise",
        "pinned",
    ),
    ("/$defs/verdict", "pinned"),
    (
        "/$defs/elf_facts/properties/truncations/items/properties/table",
        "pinned",
    ),
    (
        "/$defs/elf_facts/properties/truncations/items/properties/kind",
        "pinned",
    ),
    ("/$defs/linker/properties/path_source", "pinned"),
    (
        "/properties/corroboration/additionalProperties/properties/sources/additionalProperties/properties/witness",
        "pinned",
    ),
    (
        "/$defs/observation/properties/structured_diagnostics/properties/arms/additionalProperties/properties/prose",
        "pinned",
    ),
    (
        "/$defs/observation/properties/structured_diagnostics/properties/arms/additionalProperties/properties/structured",
        "pinned",
    ),
    (
        "/$defs/observation/properties/structured_diagnostics/properties/arms/additionalProperties/properties/outcome",
        "pinned",
    ),
    (
        "/$defs/observation/properties/structured_diagnostics/properties/arms_missing/items",
        "pinned",
    ),
    (
        "/$defs/linker/properties/artifact/properties/agreement",
        "pinned",
    ),
    // All eight pinned by `the_target_agreement_vocabulary_matches_the_code`.
    (
        "/properties/toolchain/properties/target/properties/agreement",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/source",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/macros/properties/agreement",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/abi/properties/agreement",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/abi/properties/expected",
        "pinned",
    ),
    // Pinned by `the_elf_data_vocabulary_matches_the_code`; the fixture corpora carry
    // both orders too (the big-endian ppc, ppc64 and aarch64 objects).
    ("/$defs/elf_facts/properties/elf_data", "pinned"),
    (
        "/properties/toolchain/properties/target/properties/macros/properties/defined/items",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/profile_macros/properties/agreement",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/profile_macros/properties/defined/items",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/profile_macros_cxx/properties/agreement",
        "pinned",
    ),
    (
        "/properties/toolchain/properties/target/properties/profile_macros_cxx/properties/defined/items",
        "pinned",
    ),
    // Pinned by `the_relro_vocabulary_is_pinned_against_the_reader`, kept beside the
    // comparison above because that function is already past clippy's length cap.
    ("/$defs/elf_facts/properties/relro", "pinned"),
    // Held by `every_recorded_elf_fact_conforms_to_the_elf_facts_definition` over the
    // checked-in fixture corpora, which carry both widths, on every host; a Darwin report
    // stores no `elf` fact for the live validation to see.
    (
        "/$defs/elf_facts/properties/elf_class",
        "validated-by-fixture-corpora",
    ),
    // Held by the conformance validator instead: every report the suite generates is
    // validated against this schema, and these fields are present in all of them, so a
    // code value the schema omits fails there.
    (
        "/properties/environment/properties/execution/properties/mode",
        "validated-in-every-report",
    ),
    (
        "/properties/toolchain/properties/kind",
        "validated-in-every-report",
    ),
    (
        "/properties/defect_coverage/additionalProperties/properties/status",
        "validated-in-every-report",
    ),
    ("/$defs/channel", "validated-in-every-report"),
    (
        "/$defs/observation/properties/language",
        "validated-in-every-report",
    ),
    (
        "/$defs/observation/properties/polarity",
        "validated-in-every-report",
    ),
    ("/$defs/observation/properties/observes", "pinned"),
    // The digest's three: its row's polarity copies the observation's, its status
    // the consistency block's, and a reason's standing is one of `report::Standing`'s two
    // that are not a measurement; `digest-disagrees-with-report` holds each to its source.
    (
        "/$defs/digest/properties/checks/items/properties/polarity",
        "validated-in-every-report",
    ),
    (
        "/$defs/digest/properties/consistency",
        "validated-in-every-report",
    ),
    (
        "/$defs/digest/properties/reasons/items/properties/standing",
        "validated-in-every-report",
    ),
    (
        "/$defs/observation/properties/evidence/properties/macro_source",
        "validated-in-every-report",
    ),
    (
        "/$defs/controls/properties/positive/properties/macro_source",
        "validated-in-every-report",
    ),
    (
        "/$defs/controls/properties/negative/properties/macro_source",
        "validated-in-every-report",
    ),
    (
        "/$defs/controls/properties/regime_negative/properties/macro_source",
        "validated-in-every-report",
    ),
    (
        "/$defs/observation/properties/confidence",
        "validated-in-every-report",
    ),
    // Open as `gating.rule` is, and pinned in `tests/schema_freeze.rs`'s OPEN list; every report carries observations, so the known
    // values' agreement with the corpus is held by the freeze test's vocabulary walk.
    (
        "/$defs/observation/properties/check",
        "validated-in-every-report",
    ),
    (
        "/$defs/controls/properties/positive/properties/outcome",
        "validated-in-every-report",
    ),
    (
        "/$defs/controls/properties/negative/properties/outcome",
        "validated-in-every-report",
    ),
    (
        "/$defs/controls/properties/regime_negative/properties/outcome",
        "validated-in-every-report",
    ),
    (
        "/$defs/decoded/properties/outcome",
        "validated-in-every-report",
    ),
    // The predicate language's own vocabularies, copied from
    // `schema/chard-predicate.schema.json` and pinned to that file by
    // `the_report_schema_carries_the_predicate_definitions`; `tests/predicate_language.rs`
    // pins that file to the code.
    ("/$defs/cmp", "pinned"),
    ("/$defs/conclusion/oneOf/0", "pinned"),
    ("/$defs/elf_field", "pinned"),
    ("/$defs/elf_table", "pinned"),
    ("/$defs/term/oneOf/0", "pinned"),
    (
        "/properties/composites/items/properties/constituents/items/properties/state",
        "validated-in-every-report",
    ),
    // Pinned by `a_constituents_opt_out_is_declared_and_its_header_is_the_codes`.
    (
        "/properties/composites/items/properties/constituents/items/properties/opt_out/properties/header",
        "pinned",
    ),
    // Pinned by `a_constituents_bar_source_is_the_codes`.
    (
        "/properties/composites/items/properties/constituents/items/properties/bar/properties/source",
        "pinned",
    ),
    (
        "/properties/diagnostics/items/properties/severity",
        "validated-in-every-report",
    ),
    // Pinned by `the_rejection_provenance_vocabulary_matches_the_code`.
    (
        "/properties/diagnostics/items/properties/rejection/properties/supplied_by",
        "pinned",
    ),
    // Pinned by `the_gate_allowance_vocabulary_matches_the_code`.
    (
        "/properties/coverage/properties/gate/properties/allowed/items",
        "pinned",
    ),
    (
        "/properties/coverage/properties/gate/properties/excused/items/properties/rule",
        "pinned",
    ),
    (
        "/$defs/reference/properties/kind",
        "validated-in-every-report",
    ),
    // Emitted only on hosts or runs this suite cannot produce here.
    (
        "/properties/environment/properties/execution/properties/image_attestation/properties/status",
        "unproduced-here",
    ),
    (
        "/properties/environment/properties/execution/properties/image_attestation/properties/origin",
        "unproduced-here",
    ),
    (
        "/properties/environment/properties/execution/properties/mode_evidence/properties/observed",
        "unproduced-here",
    ),
    ("/$defs/linker/properties/kind", "unproduced-here"),
    (
        "/properties/fortify_ratchet/properties/whole_object_level",
        "unproduced-here",
    ),
];

#[test]
fn a_constituents_bar_source_is_the_codes() {
    let schema = schema();
    let bar = &schema["properties"]["composites"]["items"]["properties"]["constituents"]["items"]["properties"]
        ["bar"];
    let declared: BTreeSet<&str> = bar["properties"]["source"]["enum"]
        .as_array()
        .expect("bar.source declares an enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::composite::BAR_SOURCES.iter().copied().collect();
    assert_eq!(
        emitted, declared,
        "bar.source disagrees between code and schema"
    );

    let constituent = chard::composite::Constituent {
        flag: "-D_FORTIFY_SOURCE",
        check: "fortify-effective",
        applicable: true,
        verdict: Some(chard::report::Verdict::Partial),
        level: Some("2".to_owned()),
        state: chard::composite::ConstituentState::Absent,
        note: Some("n".to_owned()),
        opt_out: None,
        implementation: None,
        bar: Some(chard::composite::FortifyBarReading {
            level: 3,
            source: chard::composite::BarSource::Driver,
        }),
    };
    let umbrella = |constituent: Value| {
        serde_json::json!({"composites": [{
            "id": "fhardened-effective", "title": "t", "derived_from": ["fortify-effective"],
            "verdict": "partial", "reason": "r", "constituents": [constituent],
        }]})
    };
    let mut errors = Vec::new();
    validate(
        &umbrella(serde_json::to_value(&constituent).expect("serializes")),
        &schema,
        &schema,
        "",
        &mut errors,
    );
    let errors: Vec<&String> = errors
        .iter()
        .filter(|e| e.starts_with("/composites"))
        .collect();
    assert!(
        errors.is_empty(),
        "a slot carrying its bar validates: {errors:?}"
    );

    // One document per constraint, each refused at the bar's own path: the level not an
    // integer, below zero, missing; the source outside the enumeration, missing.
    let mut fed = 0;
    for (name, bar) in [
        (
            "level a string",
            serde_json::json!({"level": "3", "source": "driver"}),
        ),
        (
            "level negative",
            serde_json::json!({"level": -1, "source": "driver"}),
        ),
        ("level missing", serde_json::json!({"source": "driver"})),
        (
            "source outside",
            serde_json::json!({"level": 3, "source": "headers"}),
        ),
        ("source missing", serde_json::json!({"level": 3})),
    ] {
        fed += 1;
        let mut errors = Vec::new();
        validate(
            &umbrella(serde_json::json!({
                "flag": "-D_FORTIFY_SOURCE", "check": "fortify-effective", "applicable": true,
                "state": "absent", "bar": bar,
            })),
            &schema,
            &schema,
            "",
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with("/composites/0/constituents/0/bar")),
            "{name}: a bar outside its shape is refused at its path: {errors:?}"
        );
    }
    assert_eq!(fed, 5);
}

#[test]
fn the_witness_vocabulary_is_pinned_against_the_code() {
    let schema = schema();
    let declared: BTreeSet<&str> = schema["properties"]["corroboration"]["additionalProperties"]
        ["properties"]["sources"]["additionalProperties"]["properties"]["witness"]["enum"]
        .as_array()
        .expect("corroboration sources declare a witness enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::report::WITNESSES.iter().copied().collect();
    assert_eq!(
        emitted, declared,
        "corroboration witness vocabulary drifted"
    );
}

#[test]
fn the_structured_diagnostics_vocabularies_are_pinned_against_the_code() {
    let schema = schema();
    let arm = &schema["$defs"]["observation"]["properties"]["structured_diagnostics"]["properties"]
        ["arms"]["additionalProperties"]["properties"];
    for (field, code) in [
        ("prose", &chard::structured::PROSE_READINGS[..]),
        ("structured", &chard::structured::STRUCTURED_READINGS[..]),
        ("outcome", &chard::structured::OUTCOMES[..]),
    ] {
        let declared: BTreeSet<&str> = vocabulary_of(&arm[field])
            .as_array()
            .unwrap_or_else(|| panic!("structured_diagnostics arms declare a {field} enum"))
            .iter()
            .map(|v| v.as_str().expect("enum values are strings"))
            .collect();
        let emitted: BTreeSet<&str> = code.iter().copied().collect();
        assert_eq!(emitted, declared, "structured_diagnostics {field} drifted");
    }
    let declared: BTreeSet<&str> = schema["$defs"]["observation"]["properties"]
        ["structured_diagnostics"]["properties"]["arms_missing"]["items"]["enum"]
        .as_array()
        .expect("structured_diagnostics.arms_missing declares an item enum")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings"))
        .collect();
    let emitted: BTreeSet<&str> = chard::structured::ARMS.iter().copied().collect();
    assert_eq!(
        emitted, declared,
        "structured_diagnostics arms_missing drifted"
    );
}

#[test]
fn a_structured_diagnostics_report_conforms_and_counts_its_work() {
    if !can_run("that a --structured-diagnostics report conforms and counts its work") {
        return;
    }
    let work = common::Work::new("schema", "structured");
    let report = report_for(
        "bare",
        &[
            "--probe",
            "warn-all",
            "--probe",
            "format-security",
            "--structured-diagnostics",
        ],
        work.dir(),
    );
    assert_conforms(&report, "structured-diagnostics");

    let summary = &report["structured_diagnostics"];
    let n = |k: &str| {
        summary[k]
            .as_u64()
            .unwrap_or_else(|| panic!("{k} is a count"))
    };
    let eligible = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| chard::probe::diag_needles(o["check"].as_str().unwrap_or("")).is_some())
        .count() as u64;
    assert_eq!(n("checks_eligible"), eligible);
    assert!(eligible >= 2, "both probes' checks are eligible");
    assert_eq!(
        n("arms_compared"),
        n("agreed") + n("disagreed") + n("undecodable"),
        "every compared arm has exactly one outcome"
    );
    let compared = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o.get("structured_diagnostics").is_some())
        .count() as u64;
    assert_eq!(n("checks_compared"), compared);
    assert_eq!(
        n("arms_compared") + n("arms_missing"),
        n("arms_expected"),
        "every arm fed to a comparison is compared or named missing"
    );
    assert!(
        !report["consistency"]["rules_applied"]
            .as_array()
            .expect("rules_applied")
            .is_empty()
            && report["consistency"]["contradictions"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && report["consistency"]["status"] == "consistent",
        "a gated report holds its summary to its comparisons without contradiction"
    );
    if summary.get("format").is_some() {
        assert!(compared > 0, "a gate with a format compared something");
    }
}

/// The known values of an enumeration: a closed one's `enum`, or an open one's, spelt `anyOf` of
/// the known values and any string. `Value::Null` where the node is neither.
fn vocabulary_of(node: &Value) -> &Value {
    if node.get("enum").is_some() {
        return &node["enum"];
    }
    match node
        .get("anyOf")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([known, any]) if any == &serde_json::json!({ "type": "string" }) => &known["enum"],
        _ => &Value::Null,
    }
}

/// Collect the JSON-pointer path of every enumeration in `node`, closed or open, at the node
/// that declares it: an open one's path is its own, not its `anyOf` branch's.
fn enum_paths(node: &Value, path: &str, found: &mut BTreeSet<String>) {
    match node {
        Value::Object(map) => {
            let open = map.get("enum").is_none() && vocabulary_of(node).is_array();
            if map.get("enum").is_some_and(Value::is_array) || open {
                found.insert(path.to_owned());
            }
            for (key, value) in map {
                if open && key == "anyOf" {
                    continue;
                }
                enum_paths(value, &format!("{path}/{key}"), found);
            }
        }
        Value::Array(items) => {
            for (i, value) in items.iter().enumerate() {
                enum_paths(value, &format!("{path}/{i}"), found);
            }
        }
        _ => {}
    }
}

#[test]
fn every_closed_vocabulary_in_the_schema_is_registered() {
    let mut found = BTreeSet::new();
    enum_paths(&schema(), "", &mut found);
    let registered: BTreeSet<String> = VOCABULARIES.iter().map(|(p, _)| (*p).to_owned()).collect();
    assert_eq!(
        found,
        registered,
        "closed vocabularies: schema alone declares {:?}, register alone lists {:?}",
        found.difference(&registered).collect::<Vec<_>>(),
        registered.difference(&found).collect::<Vec<_>>(),
    );
    assert!(
        !found.is_empty(),
        "no vocabulary was found, so this test compared two empty sets"
    );
}

/// The output schemas, which a consumer validates chard's documents against, and the one
/// input schema, which describes what chard reads.
const OUTPUT_SCHEMAS: &[&str] = &[
    "schema/chard-report.schema.json",
    "schema/chard-matrix.schema.json",
    "schema/chard-detect.schema.json",
    "schema/chard-error.schema.json",
];
const INPUT_SCHEMAS: &[&str] = &["schema/chard-predicate.schema.json"];

/// Every object a schema declares (`"type": "object"` beside `properties`), by JSON pointer,
/// with what it declares for `additionalProperties`. A `oneOf` branch that constrains some
/// of its parent's properties is not a declaration, and is open in every reading.
fn declared_objects(schema: &Value, path: &str, out: &mut Vec<(String, Option<Value>)>) {
    match schema {
        Value::Object(map) => {
            if map.contains_key("properties") && map.get("type") == Some(&Value::from("object")) {
                out.push((path.to_owned(), map.get("additionalProperties").cloned()));
            }
            for (key, value) in map {
                declared_objects(value, &format!("{path}/{key}"), out);
            }
        }
        Value::Array(items) => {
            for (i, value) in items.iter().enumerate() {
                declared_objects(value, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// Every node that declares `properties` without `"type": "object"`: a `oneOf` branch that
/// constrains its parent's members, and nothing else, or `declared_objects` misses an object.
fn property_nodes_outside_objects(schema: &Value, path: &str, out: &mut Vec<String>) {
    match schema {
        Value::Object(map) => {
            if map.contains_key("properties") && map.get("type") != Some(&Value::from("object")) {
                out.push(path.to_owned());
            }
            for (key, value) in map {
                property_nodes_outside_objects(value, &format!("{path}/{key}"), out);
            }
        }
        Value::Array(items) => {
            for (i, value) in items.iter().enumerate() {
                property_nodes_outside_objects(value, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn every_output_schema_object_admits_a_later_key_and_the_input_schema_admits_none() {
    // The predicate language's definitions, which the report schema carries as a copy
    // (`the_report_schema_carries_the_predicate_definitions`), are the input schema's.
    let language: Vec<String> = schema_at("schema/chard-predicate.schema.json")["$defs"]
        .as_object()
        .expect("the predicate schema has definitions")
        .keys()
        .map(|name| format!("/$defs/{name}"))
        .collect();
    let in_language = |path: &str| {
        language
            .iter()
            .any(|def| path == def || path.starts_with(&format!("{def}/")))
    };
    let mut frame = Vec::new();
    for name in OUTPUT_SCHEMAS {
        let mut all = Vec::new();
        declared_objects(&schema_at(name), "", &mut all);
        let mut shapes = Vec::new();
        property_nodes_outside_objects(&schema_at(name), "", &mut shapes);
        assert!(
            shapes.iter().all(|path| path.contains("/oneOf/")),
            "{name}: `properties` outside a `\"type\": \"object\"` node: {shapes:?}"
        );
        let (copied, objects): (Vec<_>, Vec<_>) =
            all.into_iter().partition(|(path, _)| in_language(path));
        assert!(!objects.is_empty(), "{name} declares no object");
        let open: Vec<&String> = copied
            .iter()
            .filter(|(_, extra)| !matches!(extra, Some(Value::Bool(false))))
            .map(|(path, _)| path)
            .collect();
        assert!(
            open.is_empty(),
            "{name}: the predicate language's copy admits unknown keys at {open:?}"
        );
        let wrong: Vec<String> = objects
            .iter()
            .filter(|(_, extra)| !matches!(extra, Some(Value::Bool(true) | Value::Object(_))))
            .map(|(path, extra)| format!("{path}: {extra:?}"))
            .collect();
        assert!(
            wrong.is_empty(),
            "{name}: objects that do not admit a key chard adds later:\n{}",
            wrong.join("\n")
        );
        frame.push(format!(
            "{name}: {} open, {} of the language closed",
            objects.len(),
            copied.len()
        ));
    }
    for name in INPUT_SCHEMAS {
        let mut objects = Vec::new();
        declared_objects(&schema_at(name), "", &mut objects);
        assert!(!objects.is_empty(), "{name} declares no object");
        let open: Vec<&String> = objects
            .iter()
            .filter(|(_, extra)| matches!(extra, Some(Value::Bool(true))))
            .map(|(path, _)| path)
            .collect();
        assert!(open.is_empty(), "{name} admits unknown keys at {open:?}");
        frame.push(format!("{name}: {}", objects.len()));
    }
    eprintln!("objects declared: {}", frame.join(", "));
}

#[test]
fn each_schema_pins_the_version_its_document_carries() {
    for (name, pointer, version) in [
        (
            "schema/chard-report.schema.json",
            "/properties/chard_schema/const",
            chard::report::SCHEMA_VERSION,
        ),
        (
            "schema/chard-matrix.schema.json",
            "/properties/chard_schema/const",
            chard::matrix::MATRIX_SCHEMA_VERSION,
        ),
        (
            "schema/chard-detect.schema.json",
            "/$defs/replay/properties/chard_schema/const",
            chard::detect::SCHEMA_VERSION,
        ),
        (
            "schema/chard-detect.schema.json",
            "/$defs/detection/properties/chard_schema/const",
            chard::detect::SCHEMA_VERSION,
        ),
        (
            "schema/chard-error.schema.json",
            "/properties/chard_schema/const",
            chard::error::SCHEMA_VERSION,
        ),
    ] {
        assert_eq!(
            schema_at(name).pointer(pointer),
            Some(&Value::from(version)),
            "{name}{pointer}"
        );
    }
}

#[test]
fn a_report_with_a_later_key_passes_the_published_schema_and_fails_chards_own_reading() {
    if !can_run("that a report with one more key passes the published schema") {
        return;
    }
    let mut report = shared_report("bare");
    report["a_later_key"] = Value::Bool(true);
    report["coverage"]["a_later_count"] = Value::from(7);
    let schema = schema();
    let mut errors = Vec::new();
    common::schema::validate_as_published(&report, &schema, &schema, "", &mut errors);
    assert!(
        errors.is_empty(),
        "the published schema refuses a report with one more key ({} problems):\n{}",
        errors.len(),
        errors.join("\n")
    );
    let mut errors = Vec::new();
    validate(&report, &schema, &schema, "", &mut errors);
    for key in ["a_later_key", "a_later_count"] {
        assert!(
            errors.iter().any(|e| e.contains(key)),
            "chard's own reading admits `{key}`: {errors:?}"
        );
    }
    assert_eq!(errors.len(), 2, "{errors:?}");
}

#[test]
fn every_envelope_conforms_to_the_error_schema() {
    let schema = schema_at("schema/chard-error.schema.json");
    let held = |envelope: &Value, label: &str| {
        let mut errors = Vec::new();
        validate(envelope, &schema, &schema, "", &mut errors);
        assert!(
            errors.is_empty(),
            "{label}: {envelope:#}\n{}",
            errors.join("\n")
        );
        assert_eq!(
            envelope["chard_schema"],
            chard::error::SCHEMA_VERSION,
            "{label}"
        );
    };
    let quarantine = Path::new("/nonexistent/r.json.contradicted");
    for (label, rendered) in [
        (
            "kept",
            chard::error::contradiction_envelope(2, Some(quarantine)),
        ),
        ("not kept", chard::error::contradiction_envelope(1, None)),
    ] {
        let envelope: Value = serde_json::from_str(&rendered).expect("JSON");
        held(&envelope, label);
        assert_eq!(envelope["error"]["code"], "INTERNAL", "{label}");
        assert_eq!(envelope["error"]["operation"], "measure", "{label}");
    }
    let kept: Value =
        serde_json::from_str(&chard::error::contradiction_envelope(2, Some(quarantine)))
            .expect("JSON");
    assert!(
        kept["error"]["hint"]
            .as_str()
            .is_some_and(|h| h.contains("/nonexistent/r.json.contradicted")),
        "{kept:#}"
    );
    let missing = "/nonexistent/chard-schema-test";
    for args in [
        vec!["measure", "--no-such-flag"],
        vec!["measure", "--cc", missing],
        vec!["table", missing],
    ] {
        let output = Command::new(chard_binary())
            .args(&args)
            .output()
            .expect("spawning chard");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?}: stdout is not one envelope ({e}): {}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        held(&envelope, &format!("{args:?}"));
    }
}

#[test]
fn every_json_document_but_elfs_carries_chard_schema() {
    if !can_run("that every JSON document carries chard_schema") {
        return;
    }
    let listing = Command::new(chard_binary())
        .arg("probes")
        .output()
        .expect("run probes");
    let listing: Value = serde_json::from_slice(&listing.stdout).expect("probes emits JSON");
    assert_eq!(
        listing["chard_schema"],
        chard::probe::LISTING_SCHEMA_VERSION,
        "the probe listing"
    );
    assert_eq!(
        shared_report("bare")["chard_schema"],
        chard::report::SCHEMA_VERSION
    );
    let work = common::Work::new("schema", "versions");
    let report = work.path("bare.json");
    std::fs::write(
        &report,
        serde_json::to_string(&shared_report("bare")).expect("serialize"),
    )
    .expect("write");
    for (label, args) in [
        ("detect", vec!["detect", "relro", "--evidence"]),
        ("matrix", vec!["matrix"]),
    ] {
        let output = Command::new(chard_binary())
            .args(&args)
            .arg(&report)
            .output()
            .expect("spawning chard");
        let document: Value = serde_json::from_slice(&output.stdout).expect("JSON");
        let expected = if label == "matrix" {
            chard::matrix::MATRIX_SCHEMA_VERSION
        } else {
            chard::detect::SCHEMA_VERSION
        };
        assert_eq!(document["chard_schema"], expected, "{label}: {document:#}");
        assert!(document.get("chard_matrix_schema").is_none(), "{label}");
    }
}

#[test]
fn the_arch_gate_description_names_the_cells_the_mechanism_table_decides() {
    use chard::mechanism::{ARCHS, Decision, decide};
    use std::collections::BTreeMap;

    type Cells = BTreeMap<String, BTreeSet<String>>;

    fn every<'a>(value: &'a Value, prefix: &str, found: &mut Vec<&'a str>) {
        match value {
            Value::String(s) if s.starts_with(prefix) => found.push(s),
            Value::Array(items) => items.iter().for_each(|v| every(v, prefix, found)),
            Value::Object(map) => map.values().for_each(|v| every(v, prefix, found)),
            _ => {}
        }
    }
    // `on ARCH a, b and c; on ARCH d`: each clause names one architecture once.
    fn clauses(list: &str) -> Cells {
        let mut cells = Cells::new();
        for clause in list.split("; ") {
            let (arch, ids) = clause
                .strip_prefix("on ")
                .and_then(|c| c.split_once(' '))
                .unwrap_or_else(|| panic!("a clause is `on ARCH checks`: {clause:?}"));
            let ids: BTreeSet<String> = ids
                .replace(" and ", ", ")
                .split(", ")
                .map(str::to_owned)
                .collect();
            assert!(
                cells.insert(arch.to_owned(), ids).is_none(),
                "{arch} has two clauses in {list:?}"
            );
        }
        cells
    }
    // The text after `after`, from its first `: ` to the next `. `.
    fn list<'a>(text: &'a str, after: &str) -> &'a str {
        let (_, rest) = text
            .split_once(after)
            .unwrap_or_else(|| panic!("the description says {after:?}"));
        let (_, rest) = rest.split_once(": ").expect("the list follows a colon");
        rest.split_once(". ").expect("the list ends a sentence").0
    }

    let schema = schema();
    let mut found = Vec::new();
    every(
        &schema,
        "Checks the target architecture puts out of reach",
        &mut found,
    );
    let [text] = found[..] else {
        panic!("one description of coverage.checks_not_applicable_here: {found:?}");
    };
    let gated = clauses(list(text, "publishes `arch-gated` only where"));
    let unread = clauses(list(text, "and is not counted here"));

    let (mut absent, mut withheld) = (Cells::new(), Cells::new());
    for check in chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .filter(|c| !c.gate.arch.is_empty())
    {
        for arch in ARCHS {
            let cells = match decide(check.id, arch) {
                Decision::Absent { .. } => &mut absent,
                Decision::Unread { .. } => &mut withheld,
                Decision::Measured | Decision::Outside => continue,
            };
            cells
                .entry((*arch).to_owned())
                .or_default()
                .insert(check.id.to_owned());
        }
    }
    assert!(
        !absent.is_empty() && !withheld.is_empty(),
        "the table gates or withholds nothing, and this test holds nothing"
    );
    assert_eq!(gated, absent, "the arch-gated list and the table disagree");
    assert_eq!(
        unread, withheld,
        "the no-check-on-target list and the table disagree"
    );
}
