// SPDX-License-Identifier: BSD-3-Clause

//! The predicate language held to its vectors, its schema, and itself.

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
use std::path::Path;

use chard::elf::{ElfFacts, ElfTable, SymbolFact, Truncation, TruncationKind};
use chard::predicate::{
    self, Clause, Cmp, Conclusion, Cond, ElfField, Evaluation, LANGUAGE, LevelOf, Live, Predicate,
    Published, ReadKey, Term,
};
use serde_json::Value;

mod common;

fn vectors_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/chard-predicate-vectors.json")
}

fn vectors_bytes() -> Vec<u8> {
    std::fs::read(vectors_path()).expect("the vectors file is readable")
}

fn outcome_str(eval: &Evaluation) -> &'static str {
    eval.outcome.as_str()
}

/// Vectors that must exist by name, each with the rule it pins.
const PINNED_CASES: &[(&str, &str)] = &[
    (
        "list-renders-as-compact-json",
        "the list rendering over quotes, backslashes, control and non-ASCII characters",
    ),
    (
        "elf-value-level-null-is-indeterminate",
        "the note an unrendered level adds to `observed`",
    ),
    (
        "elf-float-number-is-incomplete",
        "a number of the wrong shape read as Incomplete",
    ),
    (
        "absent-truncations-is-incomplete",
        "an absent truncation list read as Incomplete rather than as empty",
    ),
    (
        "unwatched-symbol-is-incomplete",
        "a symbol outside the watch list read as Incomplete rather than as undefined",
    ),
    (
        "symbol-inside-the-published-watch-list-and-absent-is-undefined",
        "a name the publication watched and did not find read as undefined",
    ),
    (
        "symbol-outside-the-published-watch-list-is-incomplete",
        "a name the publication did not watch read as Incomplete, though this chard watches it",
    ),
    (
        "symbol-with-no-published-watch-list-is-incomplete",
        "a symbol read over a publication with no watch list read as Incomplete",
    ),
    (
        "symbol-names-with-no-published-watch-list-is-incomplete",
        "the watched names over a publication with no watch list read as Incomplete",
    ),
    (
        "c-int-shift-past-bit-31-is-undefined",
        "a c-int shift that would carry a bit past bit 31 is Undefined",
    ),
    (
        "c-int-shift-to-bit-31-stays",
        "a c-int shift whose highest bit is bit 31 keeps its value",
    ),
    (
        "c-int-shift-that-loses-a-bit-is-not-a-mode",
        "a lost bit reads no libc++ mode where the bits that fit named one",
    ),
    (
        "unreadable-holds-of-parenthesised-text",
        "the idiom for a macro defined with text that has no integer reading",
    ),
    (
        "unreadable-fails-of-a-negative-integer",
        "that idiom does not hold of an integer reading, below zero included",
    ),
    (
        "unreadable-holds-of-the-decimal-c-types-as-unsigned",
        "that idiom holds of the one decimal the language reads and C types as unsigned",
    ),
    (
        "unreadable-request-is-not-no-request",
        "a request the language cannot read is not read as no request",
    ),
    (
        "integer-reading-accepts-a-leading-plus",
        "the integer reading of `+2`",
    ),
    (
        "c-int-text-holding-an-equals-sign-is-not-followed",
        "text that is not a macro's name read by c-int as Undefined, with no read of it",
    ),
    (
        "c-int-text-that-is-no-name-is-undefined-under-a-filter",
        "the same text over a trimmed map read as Undefined, not as Incomplete",
    ),
    (
        "c-int-text-that-is-no-name-is-not-looked-up-in-the-map",
        "a map key that is not a macro's name left unread by c-int",
    ),
    (
        "c-int-text-holding-a-space-is-not-followed",
        "text holding a space read by c-int as Undefined, with no read of it",
    ),
    (
        "c-int-suffixed-number-is-not-followed",
        "a suffixed number read by c-int as Undefined, though the map holds it as a key",
    ),
    (
        "c-int-follows-a-name-holding-a-dollar",
        "`$` in a macro's name",
    ),
    (
        "c-int-name-holding-a-dollar-outside-the-filter-is-incomplete",
        "a name outside the filter still read as Incomplete",
    ),
    (
        "c-int-follows-a-name-outside-ascii",
        "a letter outside ASCII in a macro's name",
    ),
    (
        "c-int-text-holding-a-no-break-space-is-not-followed",
        "white space outside ASCII in no macro's name",
    ),
    (
        "c-int-follows-a-name-spelt-as-a-universal-character-name",
        "a universal character name in a macro's name",
    ),
    (
        "c-int-text-holding-a-backslash-is-not-followed",
        "a backslash that opens no universal character name in no macro's name",
    ),
    (
        "c-int-looks-a-name-up-as-it-is-spelt",
        "a name holding a letter outside ASCII does not find a key that spells the letter \
         as a universal character name",
    ),
    (
        "c-int-short-universal-character-name-is-not-followed",
        "a universal character name's digit count: six after `\\U` is no name",
    ),
    (
        "macro-term-naming-no-macro-is-undefined-without-a-read",
        "a macro term naming text that is not a macro's name: refused by validate, and \
         Undefined to the evaluator",
    ),
];

/// The schema, read once per call; small enough that caching buys nothing.
fn predicate_schema() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/chard-predicate.schema.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("readable")).expect("JSON")
}

fn schema_errors(instance: &Value, schema: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    common::schema::validate(instance, schema, schema, "", &mut errors);
    errors
}

fn assert_schema_conforms(instance: &Value, label: &str) {
    let errors = schema_errors(instance, &predicate_schema());
    assert!(
        errors.is_empty(),
        "{label}: the predicate does not conform to chard-predicate.schema.json:\n{}",
        errors.join("\n")
    );
}

/// The watch list a publication of this chard's facts carries.
fn watch_list() -> Vec<String> {
    chard::elf::WATCHED_SYMBOLS
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

/// What a run over a vector file saw.
#[derive(Default)]
struct Tally {
    ran: usize,
    conformed: usize,
    names: BTreeSet<String>,
    clauses_seen: BTreeSet<String>,
    incomplete_seen: BTreeSet<String>,
    /// Each vector that did not evaluate to its expected result, by name, with what it
    /// did instead.
    failures: BTreeMap<String, Vec<String>>,
}

/// Evaluate every vector of `doc` and hold it to its expected result.
fn run_vectors(doc: &Value) -> Tally {
    let mut tally = Tally::default();
    for vector in doc["vectors"].as_array().expect("a vectors array") {
        let name = vector["name"].as_str().expect("a named vector");
        assert!(
            tally.names.insert(name.to_owned()),
            "vector name {name} appears twice"
        );
        let mut failures = Vec::new();
        let p: Predicate = serde_json::from_value(vector["predicate"].clone())
            .unwrap_or_else(|e| panic!("{name}: the predicate does not deserialize: {e}"));
        let refused = vector.get("refused_by_validate") == Some(&Value::Bool(true));
        match (predicate::validate(&p), refused) {
            (Ok(()), false) | (Err(_), true) => {}
            (Ok(()), true) => failures.push("validate accepts a vector marked refused".to_owned()),
            (Err(e), false) => failures.push(format!("validate refuses it: {e}")),
        }
        // Every vector's predicate is the shape the schema declares, the ones `validate`
        // refuses included: the rules it adds are the ones the schema cannot state.
        assert_schema_conforms(&vector["predicate"], name);
        tally.conformed += 1;
        let facts = &vector["facts"];
        let filter: Option<Vec<String>> = facts
            .get("macros_filter")
            .map(|f| serde_json::from_value(f.clone()).expect("a filter is a string list"));
        let watch_list: Option<Vec<String>> = facts
            .get("symbols_filter")
            .map(|f| serde_json::from_value(f.clone()).expect("a watch list is a string list"));
        let macros = facts.get("macros").filter(|m| !m.is_null());
        let elf = facts.get("elf").filter(|e| !e.is_null());
        let view =
            Published::new(macros, filter.as_deref(), elf, watch_list.as_deref()).expect("objects");
        let got = predicate::evaluate(&p, &view);
        tally.ran += 1;
        let expect = &vector["expect"];
        match (expect.as_str(), got) {
            (Some(key), Err(incomplete)) => {
                let expected = key.strip_prefix("incomplete:").expect("incomplete:<key>");
                tally.incomplete_seen.insert(expected.to_owned());
                if incomplete.0 != expected {
                    failures.push(format!("Incomplete({}) not {expected}", incomplete.0));
                }
            }
            (Some(key), Ok(eval)) => failures.push(format!("expected {key}, got {eval:?}")),
            (None, Err(incomplete)) => {
                failures.push(format!("unexpected Incomplete({})", incomplete.0));
            }
            (None, Ok(eval)) => {
                tally.clauses_seen.insert(eval.clause.clone());
                let level = eval.level.clone().map_or(Value::Null, Value::String);
                if expect["clause"] != eval.clause.as_str()
                    || expect["outcome"] != outcome_str(&eval)
                    || expect["level"] != level
                {
                    failures.push(format!("got {eval:?}"));
                }
                if let Some(observed) = expect.get("observed") {
                    let rendered = predicate::render_observed(&p, &eval);
                    if *observed != rendered.as_str() {
                        failures.push(format!("observed {rendered:?}"));
                    }
                }
            }
        }
        if !failures.is_empty() {
            tally.failures.insert(name.to_owned(), failures);
        }
    }
    tally
}

#[test]
fn every_vector_evaluates_to_its_expected_result() {
    let doc: Value = serde_json::from_slice(&vectors_bytes()).expect("the vectors are JSON");
    let vectors = doc["vectors"].as_array().expect("a vectors array");
    let Tally {
        ran,
        conformed,
        names,
        clauses_seen,
        incomplete_seen,
        failures,
    } = run_vectors(&doc);
    let names: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let failures: Vec<String> = failures
        .iter()
        .flat_map(|(name, why)| why.iter().map(move |w| format!("{name}: {w}")))
        .collect();
    println!(
        "{ran} of {} vectors evaluated, {conformed} predicates held to the schema",
        vectors.len()
    );
    assert_eq!(ran, vectors.len());
    assert_eq!(conformed, vectors.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // The cases the language's semantics turn on, each held to at least one vector.
    for reserved in [
        predicate::NO_SOURCE_MACROS,
        predicate::NO_SOURCE_ELF,
        predicate::TRUNCATED,
        predicate::OTHERWISE,
    ] {
        assert!(
            clauses_seen.contains(reserved),
            "no vector reaches {reserved}"
        );
    }
    assert!(
        incomplete_seen.iter().any(|k| k.starts_with("macros.")),
        "no vector shows a filtered macro read as Incomplete"
    );
    assert!(
        names.contains("c-int-shift-through-indirection"),
        "no vector exercises a c-int shift reached through a macro name"
    );
    for (name, what) in PINNED_CASES {
        assert!(names.contains(name), "no vector pins {what}");
    }
}

/// A small deterministic generator: the four-dependency rule covers dev-dependencies, and
/// a fixed seed keeps a failure reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).expect("small")).expect("small")
    }

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const MACRO_NAMES: &[&str] = &[
    "__SSP__",
    "__PIE__",
    "_FORTIFY_SOURCE",
    "_CXX_STDLIB",
    "_LIBCPP_VERSION",
    "__GLIBCXX__",
    "_LIBCPP_HARDENING_MODE",
    "_LIBCPP_HARDENING_MODE_FAST",
    "X",
];

const MACRO_VALUES: &[&str] = &[
    // Text that is no macro's name, so the two views are compared over it too.
    "B=1",
    "a b",
    "3L",
    "",
    "0",
    "1",
    "2",
    " 3",
    "-1",
    "(1 << 2)",
    "(1 << 40)",
    "_LIBCPP_HARDENING_MODE_FAST",
    "X",
    "libc++",
    "libstdc++",
    "yes",
];

const SYMBOLS: &[&str] = &[
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "_ZNK11__gnu_debug16_Error_formatter8_M_errorEv",
];

const WORDS: &[&str] = &["", "1", "true", "full", "libc++", "ET_DYN", "libm.", "chk"];

fn gen_macros(rng: &mut Rng) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for _ in 0..rng.below(6) {
        map.insert(
            (*rng.pick(MACRO_NAMES)).to_owned(),
            (*rng.pick(MACRO_VALUES)).to_owned(),
        );
    }
    map
}

fn gen_list(rng: &mut Rng, pool: &[&str]) -> Vec<String> {
    (0..rng.below(3))
        .map(|_| (*rng.pick(pool)).to_owned())
        .collect()
}

fn gen_opt_bool(rng: &mut Rng) -> Option<bool> {
    match rng.below(3) {
        0 => None,
        1 => Some(false),
        _ => Some(true),
    }
}

fn gen_elf(rng: &mut Rng) -> ElfFacts {
    let libs = &["libc.so.6", "libm.so.6", "libchk.so"];
    let watched = (0..rng.below(3))
        .map(|_| {
            (
                (*rng.pick(SYMBOLS)).to_owned(),
                SymbolFact {
                    defined: rng.coin(),
                    tables: vec![".dynsym".to_owned()],
                    versioned: Vec::new(),
                },
            )
        })
        .collect();
    let truncations = (0..rng.below(2))
        .map(|_| Truncation {
            table: *rng.pick(&ElfTable::ALL),
            kind: *rng.pick(&TruncationKind::ALL),
            detail: "cut".to_owned(),
        })
        .collect();
    ElfFacts {
        elf_class: *rng.pick(&[32u8, 64]),
        elf_data: Some(*rng.pick(chard::elf::ByteOrder::ALL)),
        elf_type: (*rng.pick(&["ET_DYN", "ET_EXEC", "ET_REL"])).to_owned(),
        machine: (*rng.pick(&["x86_64", "aarch64"])).to_owned(),
        has_interp: rng.coin(),
        has_dynamic: rng.coin(),
        pie: gen_opt_bool(rng),
        df_1_pie: rng.coin(),
        static_pie: gen_opt_bool(rng),
        shared_object: gen_opt_bool(rng),
        statically_linked: gen_opt_bool(rng),
        relro: rng
            .coin()
            .then(|| (*rng.pick(&["full", "partial", "none"])).to_owned()),
        gnu_relro: gen_opt_bool(rng),
        bind_now: gen_opt_bool(rng),
        gnu_stack_present: gen_opt_bool(rng),
        gnu_stack_executable: gen_opt_bool(rng),
        rwx_segment: gen_opt_bool(rng),
        df_1_noopen: rng.coin(),
        textrel: rng.coin(),
        dt_relr: rng.coin(),
        dt_debug: rng.coin(),
        dt_soname: rng.coin(),
        dynamic_tags: gen_list(rng, &["0x1e=0x8", "0x6ffffffb=0x8000001"]),
        needed: gen_list(rng, libs),
        rpath: gen_list(rng, &["/opt/lib"]),
        runpath: gen_list(rng, &["$ORIGIN"]),
        gnu_property_types: gen_list(rng, &["0xc0000002", "0xc0000000"]),
        gnu_property_notes: BTreeMap::new(),
        x86_ibt: rng.coin(),
        x86_shstk: rng.coin(),
        aarch64_bti: rng.coin(),
        aarch64_pac: rng.coin(),
        aarch64_gcs: rng.coin(),
        openbsd_nobtcfi: false,
        sections: gen_list(rng, &[".text", ".chard.report"]),
        data_in_code_pages: rng.coin().then(|| gen_list(rng, &[".rodata", ".eh_frame"])),
        code_relocations: rng.coin().then(|| {
            gen_list(
                rng,
                &[
                    "R_X86_64_PLT32 chard_no_plt_callee",
                    "R_X86_64_GOTPCRELX chard_no_plt_callee",
                    "R_X86_64_PC32 chard_pic_object_anchor",
                    "R_X86_64_REX_GOTPCRELX chard_pic_object_anchor",
                    "R_X86_64_PC32 chard_pic_object_anchor STV_HIDDEN",
                ],
            )
        }),
        function_references: rng
            .coin()
            .then(|| gen_list(rng, &["f:", "f:__stack_chk_fail"])),
        symbol_tables: Vec::new(),
        symbol_count: rng.below(40),
        watched_symbols: watched,
        truncations,
        run_witness: Vec::new(),
        self_report: String::new(),
        recorded_command_line: gen_list(rng, WORDS).join(" "),
        comment: Vec::new(),
        code_scanned: gen_list(
            rng,
            &[
                "chard_ubsan_trap_probe:x86-ud2=2",
                "chard_ubsan_trap_probe:x86-ud1=0",
            ],
        ),
        code_matches: gen_list(rng, &["chard_ubsan_trap_probe:x86-ud2@0x1a"]),
        function_entries: gen_list(
            rng,
            &[
                "chard_ibt_target_a=f30f1efa",
                "chard_ibt_target_b=f30f1efa",
                "chard_ibt_target_c=8d4703c3",
            ],
        ),
    }
}

fn gen_term(rng: &mut Rng) -> Term {
    match rng.below(6) {
        0 => Term::Macro((*rng.pick(MACRO_NAMES)).to_owned()),
        1 => Term::CInt((*rng.pick(MACRO_NAMES)).to_owned()),
        2 => Term::CxxStdlib,
        3 => Term::Elf(*rng.pick(&ElfField::ALL)),
        4 => Term::Symbol((*rng.pick(SYMBOLS)).to_owned()),
        _ => Term::SymbolNames,
    }
}

fn gen_cond(rng: &mut Rng, depth: u32) -> Cond {
    let word = |rng: &mut Rng| (*rng.pick(WORDS)).to_owned();
    let pick = if depth == 0 {
        3 + rng.below(8)
    } else {
        rng.below(11)
    };
    let members = |rng: &mut Rng| {
        (0..rng.below(3))
            .map(|_| gen_cond(rng, depth.saturating_sub(1)))
            .collect()
    };
    match pick {
        0 => Cond::All(members(rng)),
        1 => Cond::Any(members(rng)),
        2 => Cond::NoneOf(members(rng)),
        3 => Cond::Defined(gen_term(rng)),
        4 => Cond::Missing(gen_term(rng)),
        5 => Cond::Truth(gen_term(rng)),
        6 => Cond::Eq(gen_term(rng), word(rng)),
        7 => Cond::Int(
            gen_term(rng),
            *rng.pick(&Cmp::ALL),
            *rng.pick(&[-1i64, 0, 1, 2, 4, 64]),
        ),
        8 => Cond::AnyStartsWith(gen_term(rng), word(rng)),
        9 => Cond::AnyContains(gen_term(rng), word(rng)),
        _ => Cond::NonEmpty(gen_term(rng)),
    }
}

fn gen_conclusion(rng: &mut Rng) -> Conclusion {
    match rng.below(5) {
        0 => Conclusion::Absent,
        1 => Conclusion::Indeterminate,
        2 => Conclusion::Present(LevelOf::None),
        3 => Conclusion::Present(LevelOf::Word("full".to_owned())),
        _ => Conclusion::Present(LevelOf::Value(gen_term(rng))),
    }
}

fn gen_predicate(rng: &mut Rng) -> Predicate {
    Predicate {
        tables: (0..rng.below(2))
            .map(|_| *rng.pick(&ElfTable::ALL))
            .collect(),
        clauses: (0..=rng.below(3))
            .map(|i| Clause {
                id: format!("c{i}"),
                when: gen_cond(rng, 2),
                then: gen_conclusion(rng),
                because: format!("reason {i}"),
            })
            .collect(),
        otherwise: gen_conclusion(rng),
    }
}

/// A macro publication: the map, and a filter holding every name the map carries and
/// every name the Live evaluation read, as `relevant_macros` and its keep-list would.
fn published_macros(
    map: &BTreeMap<String, String>,
    live: &Evaluation,
    drop: Option<&str>,
) -> (Value, Vec<String>) {
    let mut filter: BTreeSet<String> = map.keys().cloned().collect();
    for read in &live.reads {
        if let ReadKey::Macro(name) = &read.key {
            filter.insert(name.as_str().to_owned());
        }
    }
    let mut object = serde_json::to_value(map).expect("a string map serializes");
    if let Some(name) = drop {
        filter.remove(name);
        object.as_object_mut().expect("an object").remove(name);
    }
    (object, filter.into_iter().collect())
}

/// A trimmed macro publication: the object and the filter it was cut to.
type MacroPublication = Option<(Value, Vec<String>)>;

/// A published `ElfFacts` object as a re-evaluated publication carries it: serialized, with
/// `truncations` written out even when empty, since `ElfFacts`' own serializer omits the
/// empty list and the Published view reads an absent one as `Incomplete`, and
/// `data_in_code_pages`, `code_relocations`, `function_references` and `rwx_segment`
/// written out as `null` where the serializer omits them, as `report::serialize_stored_elf`
/// states all four.
fn publish_elf(facts: &ElfFacts) -> Value {
    let mut json = serde_json::to_value(facts).expect("ElfFacts serializes");
    let map = json.as_object_mut().expect("an object");
    for stated in chard::report::STATED_WHEN_EMPTY {
        map.entry(stated)
            .or_insert_with(|| Value::Array(Vec::new()));
    }
    map.entry("data_in_code_pages").or_insert(Value::Null);
    map.entry("code_relocations").or_insert(Value::Null);
    map.entry("function_references").or_insert(Value::Null);
    map.entry("rwx_segment").or_insert(Value::Null);
    json
}

/// Remove each key `live` read from the publication in turn, and hold the Published
/// evaluation to stopping at that key. Returns how many reads were removed.
fn remove_each_read(
    p: &Predicate,
    macros: Option<&BTreeMap<String, String>>,
    elf_json: Option<&Value>,
    trimmed: &MacroPublication,
    watched: &[String],
    live: &Evaluation,
) -> usize {
    let mut removed = 0usize;
    for read in &live.reads {
        let key = read.key.published_key();
        let (macro_pub, elf_pub) = match &read.key {
            ReadKey::Macro(name) => (
                macros.map(|m| published_macros(m, live, Some(name.as_str()))),
                elf_json.cloned(),
            ),
            ReadKey::Elf(_) | ReadKey::Symbol(_) | ReadKey::SymbolNames | ReadKey::Truncations => {
                let mut e = elf_json.cloned().expect("an ELF read has ELF facts");
                let field = key.strip_prefix("elf.").expect("an elf key");
                e.as_object_mut().expect("an object").remove(field);
                (trimmed.clone(), Some(e))
            }
        };
        let view = Published::new(
            macro_pub.as_ref().map(|(o, _)| o),
            macro_pub.as_ref().map(|(_, f)| f.as_slice()),
            elf_pub.as_ref(),
            Some(watched),
        )
        .expect("objects");
        let got = predicate::evaluate(p, &view);
        removed += 1;
        assert_eq!(
            got.as_ref().map_err(|i| i.0.as_str()),
            Err(key.as_str()),
            "removing {key} from the publication of {p:?} did not stop at it"
        );
    }
    removed
}

/// A publication with no watch list answers no symbol read: an evaluation that read a
/// symbol stops at `symbols_filter`, and one that read none is unchanged. Returns whether
/// it stopped.
fn stops_without_a_watch_list(
    p: &Predicate,
    macros: Option<&Value>,
    elf_json: Option<&Value>,
    live: &Evaluation,
) -> bool {
    let unlisted = Published::new(macros, None, elf_json, None).expect("objects");
    let reads_symbols = live
        .reads
        .iter()
        .any(|r| matches!(r.key, ReadKey::Symbol(_) | ReadKey::SymbolNames));
    let got = predicate::evaluate(p, &unlisted);
    if reads_symbols {
        assert_eq!(
            got.as_ref().map_err(|i| i.0.as_str()),
            Err("symbols_filter"),
            "a publication with no watch list answered a symbol read for {p:?}"
        );
    } else {
        assert_eq!(got.as_ref(), Ok(live), "no symbol read, yet {p:?} differs");
    }
    reads_symbols
}

#[test]
fn the_published_view_concludes_what_the_live_view_concluded_and_a_removed_read_is_incomplete() {
    let mut rng = Rng(0x00c0_ffee_d00d_f00d);
    let mut cases = 0usize;
    let mut removed = 0usize;
    let mut truncation_reads = 0usize;
    let mut unlisted_stops = 0usize;
    let watched = watch_list();
    let mut outcomes = BTreeSet::new();
    for _ in 0..4000 {
        let p = gen_predicate(&mut rng);
        let macros = rng.below(8).ne(&0).then(|| gen_macros(&mut rng));
        let elf = rng.below(8).ne(&0).then(|| gen_elf(&mut rng));
        let live = predicate::evaluate(
            &p,
            &Live {
                macros: macros.as_ref(),
                elf: elf.as_ref(),
            },
        )
        .expect("a live view holds every key");
        outcomes.insert(live.clause.clone());
        cases += 1;

        let elf_json = elf.as_ref().map(publish_elf);
        let untrimmed = macros
            .as_ref()
            .map(|m| serde_json::to_value(m).expect("a string map serializes"));
        let whole = Published::new(
            untrimmed.as_ref(),
            None,
            elf_json.as_ref(),
            Some(watched.as_slice()),
        )
        .expect("objects");
        assert_eq!(
            predicate::evaluate(&p, &whole).as_ref(),
            Ok(&live),
            "untrimmed publication disagrees for {p:?}"
        );
        let trimmed = macros.as_ref().map(|m| published_macros(m, &live, None));
        let view = Published::new(
            trimmed.as_ref().map(|(o, _)| o),
            trimmed.as_ref().map(|(_, f)| f.as_slice()),
            elf_json.as_ref(),
            Some(watched.as_slice()),
        )
        .expect("objects");
        assert_eq!(
            predicate::evaluate(&p, &view).as_ref(),
            Ok(&live),
            "trimmed publication disagrees for {p:?}"
        );

        unlisted_stops += usize::from(stops_without_a_watch_list(
            &p,
            untrimmed.as_ref(),
            elf_json.as_ref(),
            &live,
        ));

        truncation_reads += live
            .reads
            .iter()
            .filter(|r| r.key == ReadKey::Truncations)
            .count();
        removed += remove_each_read(
            &p,
            macros.as_ref(),
            elf_json.as_ref(),
            &trimmed,
            &watched,
            &live,
        );
    }
    println!(
        "{cases} cases, {removed} reads removed, {truncation_reads} of them the truncation \
         list; {unlisted_stops} stopped for want of a watch list; clauses reached: \
         {outcomes:?}"
    );
    assert_eq!(cases, 4000);
    assert!(
        unlisted_stops > 0,
        "the generator never read a symbol over a publication with no watch list"
    );
    // The generator reaches every reserved clause and removes reads by the thousand; a
    // generator that stopped producing either would pass the loop above vacuously.
    for reserved in [
        predicate::NO_SOURCE_MACROS,
        predicate::NO_SOURCE_ELF,
        predicate::TRUNCATED,
        predicate::OTHERWISE,
    ] {
        assert!(
            outcomes.contains(reserved),
            "the generator never reached {reserved}"
        );
    }
    assert!(removed > 1000, "only {removed} reads were removed");
    // The truncation list is removed like every other key, empty or not.
    assert!(
        truncation_reads > 0,
        "the generator never read the truncation list"
    );
}

#[test]
fn every_generated_predicate_conforms_to_the_schema() {
    let schema = predicate_schema();
    let mut rng = Rng(0x00c0_ffee_d00d_f00d);
    let mut conformed = 0usize;
    for _ in 0..4000 {
        let p = gen_predicate(&mut rng);
        let json = serde_json::to_value(&p).expect("serializes");
        let errors = schema_errors(&json, &schema);
        assert!(errors.is_empty(), "{p:?}: {}", errors.join("; "));
        conformed += 1;
    }
    println!("{conformed} generated predicates held to the schema");
    assert_eq!(conformed, 4000);
}

#[test]
fn canonical_is_stable_and_round_trips() {
    let mut rng = Rng(7);
    for _ in 0..500 {
        let p = gen_predicate(&mut rng);
        let first = predicate::canonical(&p).expect("serializes");
        let second = predicate::canonical(&p).expect("serializes");
        assert_eq!(first, second);
        assert!(!first.contains('\n'), "canonical form is compact");
        let back: Predicate = serde_json::from_str(&first).expect("deserializes");
        assert_eq!(back, p);
    }
}

#[test]
fn validate_refuses_duplicate_reserved_and_unexplained_clauses() {
    let clause = |id: &str, because: &str| Clause {
        id: id.to_owned(),
        when: Cond::All(Vec::new()),
        then: Conclusion::Absent,
        because: because.to_owned(),
    };
    let p = |clauses| Predicate {
        tables: Vec::new(),
        clauses,
        otherwise: Conclusion::Absent,
    };
    assert!(predicate::validate(&p(vec![clause("a", "r"), clause("b", "r")])).is_ok());
    assert!(predicate::validate(&p(vec![clause("a", "r"), clause("a", "r")])).is_err());
    assert!(predicate::validate(&p(vec![clause("@otherwise", "r")])).is_err());
    assert!(predicate::validate(&p(vec![clause("", "r")])).is_err());
    assert!(predicate::validate(&p(vec![clause("a", " ")])).is_err());
    // An empty fixed word is no level, in a clause and in `otherwise` alike.
    let worded = |word: &str| Clause {
        then: Conclusion::Present(LevelOf::Word(word.to_owned())),
        ..clause("a", "r")
    };
    assert!(predicate::validate(&p(vec![worded("full")])).is_ok());
    assert!(predicate::validate(&p(vec![worded("")])).is_err());
    let empty_otherwise = Predicate {
        otherwise: Conclusion::Present(LevelOf::Word(String::new())),
        ..p(vec![clause("a", "r")])
    };
    assert!(predicate::validate(&empty_otherwise).is_err());

    // The watch list is the symbol channel's filter: a name on it is a valid term, and a
    // name off it (here a misspelling) is refused wherever it appears, a level included.
    let naming = |name: &str| Predicate {
        tables: Vec::new(),
        clauses: vec![clause("a", "r")],
        otherwise: Conclusion::Present(LevelOf::Value(Term::Symbol(name.to_owned()))),
    };
    assert!(predicate::validate(&naming("__stack_chk_fail")).is_ok());
    let refused = predicate::validate(&naming("__stack_chk_fal")).expect_err("an unwatched name");
    assert!(refused.contains("WATCHED_SYMBOLS"), "{refused}");
}

#[test]
fn the_predicate_schema_refuses_what_its_structure_forbids() {
    let schema = predicate_schema();
    let valid = serde_json::json!({
        "tables": ["symbols"],
        "clauses": [{
            "id": "a",
            "when": {"int": [{"c-int": "M"}, "ge", 2]},
            "then": {"present": {"value": {"elf": "relro"}}},
            "because": "r"
        }],
        "otherwise": "absent"
    });
    assert_eq!(schema_errors(&valid, &schema), Vec::<String>::new());
    let broken = |pointer: &str, replacement: Value| {
        let mut doc = valid.clone();
        *doc.pointer_mut(pointer)
            .expect("the pointer names a member") = replacement;
        doc
    };
    let cases = [
        (
            "a whitespace-only reason",
            broken("/clauses/0/because", " \t".into()),
        ),
        ("an empty reason", broken("/clauses/0/because", "".into())),
        (
            "a reserved clause id",
            broken("/clauses/0/id", "@otherwise".into()),
        ),
        ("an empty clause id", broken("/clauses/0/id", "".into())),
        (
            "an empty word level",
            broken(
                "/clauses/0/then",
                serde_json::json!({"present": {"word": ""}}),
            ),
        ),
        (
            "an int of two members",
            broken(
                "/clauses/0/when",
                serde_json::json!({"int": [{"c-int": "M"}, "ge"]}),
            ),
        ),
        (
            "an int whose bound is text",
            broken(
                "/clauses/0/when",
                serde_json::json!({"int": [{"c-int": "M"}, "ge", "2"]}),
            ),
        ),
        (
            "an eq of three members",
            broken(
                "/clauses/0/when",
                serde_json::json!({"eq": ["cxx-stdlib", "a", "b"]}),
            ),
        ),
        (
            "a condition of two members",
            broken(
                "/clauses/0/when",
                serde_json::json!({"defined": "cxx-stdlib", "missing": "cxx-stdlib"}),
            ),
        ),
        (
            "a present with a bare word",
            broken("/clauses/0/then", serde_json::json!({"present": "full"})),
        ),
        (
            "an unknown ELF field",
            broken("/clauses/0/then/present/value/elf", "relro_level".into()),
        ),
        ("an unknown table", broken("/tables/0", "symtab".into())),
        ("a clause without a reason", {
            let mut doc = valid.clone();
            doc["clauses"][0]
                .as_object_mut()
                .expect("an object")
                .remove("because");
            doc
        }),
    ];
    for (what, doc) in &cases {
        assert!(
            !schema_errors(doc, &schema).is_empty(),
            "the schema accepts {what}"
        );
        // Every case the schema refuses either fails to deserialize or `validate` refuses
        // it too, so the schema is never stricter than the code in a way a reader meets.
        if let Ok(p) = serde_json::from_value::<Predicate>(doc.clone()) {
            assert!(predicate::validate(&p).is_err(), "validate accepts {what}");
        }
    }
}

#[test]
fn validate_and_the_schema_agree_on_which_reasons_are_blank() {
    let schema = predicate_schema();
    let pattern = &schema["$defs"]["clause"]["properties"]["because"]["pattern"];
    assert_eq!(pattern, "\\S");
    let mut checked = 0usize;
    let mut blank = 0usize;
    for c in (0u32..=0x3000).chain([0xfeff]).filter_map(char::from_u32) {
        let reason = c.to_string();
        let schema_refuses =
            !common::schema::matches_pattern(pattern.as_str().expect("a string"), &reason);
        let p = Predicate {
            tables: Vec::new(),
            clauses: vec![Clause {
                id: "a".to_owned(),
                when: Cond::All(Vec::new()),
                then: Conclusion::Absent,
                because: reason,
            }],
            otherwise: Conclusion::Absent,
        };
        let validate_refuses = predicate::validate(&p).is_err();
        assert_eq!(
            schema_refuses,
            validate_refuses,
            "U+{:04X}: the schema refuses {schema_refuses}, validate {validate_refuses}",
            u32::from(c)
        );
        assert_eq!(
            common::schema::is_ecma_whitespace(c),
            predicate::is_schema_whitespace(c)
        );
        checked += 1;
        blank += usize::from(validate_refuses);
    }
    println!("{checked} characters checked, {blank} of them blank");
    // ECMA-262's `\s` has 25 code points, all at or below U+3000 or equal to U+FEFF.
    assert_eq!(blank, 25);
}

fn cond_key(cond: &Cond) -> &'static str {
    match cond {
        Cond::All(_) => "all",
        Cond::Any(_) => "any",
        Cond::NoneOf(_) => "none-of",
        Cond::Defined(_) => "defined",
        Cond::Missing(_) => "missing",
        Cond::Truth(_) => "truth",
        Cond::Eq(..) => "eq",
        Cond::Int(..) => "int",
        Cond::AnyStartsWith(..) => "any-starts-with",
        Cond::AnyContains(..) => "any-contains",
        Cond::NonEmpty(_) => "non-empty",
    }
}

fn one_of_each_cond() -> Vec<Cond> {
    let t = || Term::SymbolNames;
    vec![
        Cond::All(Vec::new()),
        Cond::Any(Vec::new()),
        Cond::NoneOf(Vec::new()),
        Cond::Defined(t()),
        Cond::Missing(t()),
        Cond::Truth(t()),
        Cond::Eq(t(), String::new()),
        Cond::Int(t(), Cmp::Eq, 0),
        Cond::AnyStartsWith(t(), String::new()),
        Cond::AnyContains(t(), String::new()),
        Cond::NonEmpty(t()),
    ]
}

fn serialized_keys<T: serde::Serialize>(items: &[T]) -> BTreeSet<String> {
    items
        .iter()
        .map(
            |item| match serde_json::to_value(item).expect("serializes") {
                Value::String(unit) => unit,
                Value::Object(map) => map.keys().next().expect("one key").clone(),
                other => panic!("unexpected serialization {other}"),
            },
        )
        .collect()
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|v| v.as_str().expect("a string").to_owned())
        .collect()
}

#[test]
fn the_predicate_schema_vocabularies_match_the_code() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/chard-predicate.schema.json");
    let schema: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("readable")).expect("JSON");
    let defs = &schema["$defs"];
    assert_eq!(defs["language"]["const"], LANGUAGE);

    let conds = one_of_each_cond();
    let from_match: BTreeSet<String> = conds.iter().map(|c| cond_key(c).to_owned()).collect();
    assert_eq!(
        from_match.len(),
        conds.len(),
        "one_of_each_cond repeats a variant"
    );
    assert_eq!(serialized_keys(&conds), from_match);
    let declared: BTreeSet<String> = defs["cond"]["properties"]
        .as_object()
        .expect("cond properties")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        declared, from_match,
        "the schema's conditions are not the code's"
    );

    let terms = [
        Term::Macro(String::new()),
        Term::CInt(String::new()),
        Term::CxxStdlib,
        Term::Elf(ElfField::Pie),
        Term::Symbol(String::new()),
        Term::SymbolNames,
    ];
    let mut declared = strings(&defs["term"]["oneOf"][0]["enum"]);
    declared.extend(
        defs["term"]["oneOf"][1]["properties"]
            .as_object()
            .expect("term properties")
            .keys()
            .cloned(),
    );
    assert_eq!(
        declared,
        serialized_keys(&terms),
        "the schema's terms are not the code's"
    );

    let fields: BTreeSet<String> = ElfField::ALL
        .iter()
        .map(|f| f.as_str().to_owned())
        .collect();
    // Open as the report schema's copy is: the known fields and any string, so a
    // predicate a later chard publishes validates, while chard's own reader refuses a
    // term naming a field it does not know
    // (`an_unknown_elf_field_validates_and_fails_the_predicate_on_read`).
    assert_eq!(
        defs["elf_field"]["anyOf"][1],
        serde_json::json!({"type": "string"}),
        "elf_field's second branch is any string"
    );
    assert_eq!(strings(&defs["elf_field"]["anyOf"][0]["enum"]), fields);
    let tables: BTreeSet<String> = ElfTable::ALL
        .iter()
        .map(|t| t.as_str().to_owned())
        .collect();
    assert_eq!(strings(&defs["elf_table"]["enum"]), tables);
    assert_eq!(strings(&defs["cmp"]["enum"]), serialized_keys(&Cmp::ALL));

    let conclusions = [
        Conclusion::Present(LevelOf::None),
        Conclusion::Absent,
        Conclusion::Indeterminate,
    ];
    let from_match: BTreeSet<String> = conclusions
        .iter()
        .map(|c| conclusion_key(c).to_owned())
        .collect();
    assert_eq!(from_match.len(), conclusions.len());
    assert_eq!(serialized_keys(&conclusions), from_match);
    assert_eq!(
        one_of_keys(&defs["conclusion"]),
        from_match,
        "the schema's conclusions are not the code's"
    );

    let levels = [
        LevelOf::None,
        LevelOf::Word(String::new()),
        LevelOf::Value(Term::CxxStdlib),
    ];
    let from_match: BTreeSet<String> = levels.iter().map(|l| level_key(l).to_owned()).collect();
    assert_eq!(from_match.len(), levels.len());
    assert_eq!(serialized_keys(&levels), from_match);
    assert_eq!(
        one_of_keys(&defs["level_of"]),
        from_match,
        "the schema's levels are not the code's"
    );
}

#[test]
fn an_unknown_elf_field_validates_and_fails_the_predicate_on_read() {
    fn rename_first_elf_term(value: &mut Value, to: &str) -> bool {
        match value {
            Value::Object(map) => {
                if map.len() == 1
                    && let Some(Value::String(field)) = map.get_mut("elf")
                {
                    *field = to.to_owned();
                    return true;
                }
                map.values_mut().any(|v| rename_first_elf_term(v, to))
            }
            Value::Array(items) => items.iter_mut().any(|v| rename_first_elf_term(v, to)),
            _ => false,
        }
    }
    let unknown = "a_field_no_chard_reads";
    assert!(
        ElfField::ALL.iter().all(|f| f.as_str() != unknown),
        "the stand-in for a later chard's field is a field this chard knows"
    );
    let schema = predicate_schema();
    let mut held = 0usize;
    let tables = || {
        predicate::macro_channel::table()
            .iter()
            .chain(predicate::elf_static::table())
    };
    for (check, published) in tables() {
        let mut json = serde_json::to_value(published()).expect("a predicate serializes");
        if !rename_first_elf_term(&mut json, unknown) {
            continue;
        }
        // As a consumer pinned to the published schema reads it: the producer reading holds
        // chard's own output to the known values, on purpose.
        let mut errors = Vec::new();
        common::schema::validate_as_published(&json, &schema, &schema, "", &mut errors);
        assert!(
            errors.is_empty(),
            "{check}: the open schema refuses a predicate naming an unknown elf field:\n{}",
            errors.join("\n")
        );
        let read = serde_json::from_value::<Predicate>(json);
        let err = read.expect_err("a predicate naming an unknown elf field deserializes");
        assert!(
            err.to_string().contains(unknown),
            "{check}: the refusal does not name the field: {err}"
        );
        held += 1;
    }
    assert!(
        tables().any(|(check, _)| *check == "rwx-segment-absent"),
        "rwx-segment-absent's predicate is in the table"
    );
    assert!(held > 0, "no corpus predicate reads an ELF field");
}

/// Exhaustive, so a new `Conclusion` fails to compile here before it can drift from the
/// schema.
fn conclusion_key(conclusion: &Conclusion) -> &'static str {
    match conclusion {
        Conclusion::Present(_) => "present",
        Conclusion::Absent => "absent",
        Conclusion::Indeterminate => "indeterminate",
    }
}

/// Exhaustive, as `conclusion_key` is.
fn level_key(level: &LevelOf) -> &'static str {
    match level {
        LevelOf::None => "none",
        LevelOf::Word(_) => "word",
        LevelOf::Value(_) => "value",
    }
}

/// The keys a `oneOf` of unit strings (`enum`, `const`) and one-member objects declares.
fn one_of_keys(def: &Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for branch in def["oneOf"].as_array().expect("a oneOf") {
        if let Some(unit) = branch.get("const") {
            keys.insert(unit.as_str().expect("a string").to_owned());
        } else if let Some(units) = branch.get("enum") {
            keys.extend(strings(units));
        } else {
            keys.extend(
                branch["properties"]
                    .as_object()
                    .expect("an object branch")
                    .keys()
                    .cloned(),
            );
        }
    }
    keys
}

#[test]
fn every_elf_facts_key_is_a_readable_field_or_a_named_exclusion() {
    const EXCLUDED: &[&str] = &[
        "gnu_property_notes",
        "symbol_tables",
        "watched_symbols",
        "truncations",
        "self_report",
        "comment",
        "openbsd_nobtcfi",
        // A header fact no check's predicate reads: the target witness
        // (`toolchain.target.abi`) and the execution witness (`env::runs_natively`) do.
        "elf_data",
    ];
    let mut rng = Rng(11);
    let mut facts = gen_elf(&mut rng);
    facts.gnu_property_notes.insert("0xc0000002".to_owned(), 1);
    facts.symbol_tables = vec![".dynsym".to_owned()];
    facts.comment = vec!["Linker: LLD 22.1.8".to_owned()];
    facts.openbsd_nobtcfi = true;
    facts.code_scanned = vec!["chard_ubsan_trap_probe:x86-ud2=1".to_owned()];
    facts.code_matches = vec!["chard_ubsan_trap_probe:x86-ud2@0x1a".to_owned()];
    facts.function_entries = vec!["chard_ibt_target_a=f30f1efa".to_owned()];
    facts.code_relocations = Some(Vec::new());
    // Omitted when `None`, which the generator may draw.
    facts.function_references = Some(vec!["f:".to_owned()]);
    facts.data_in_code_pages = Some(Vec::new());
    facts.truncations = vec![Truncation {
        table: ElfTable::Symbols,
        kind: TruncationKind::Unread,
        detail: "cut".to_owned(),
    }];
    let json = serde_json::to_value(&facts).expect("serializes");
    let keys: BTreeSet<String> = json
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    let mut accounted: BTreeSet<String> = ElfField::ALL
        .iter()
        .map(|f| f.as_str().to_owned())
        .collect();
    assert_eq!(accounted.len(), ElfField::ALL.len());
    accounted.extend(EXCLUDED.iter().map(|k| (*k).to_owned()));
    assert_eq!(keys, accounted);
}

/// Whether `cond` compares a macro's integer reading `gt 0`, and whether it compares one
/// `ne 0` or reads one under `truth`, the two tests C's "non-zero" names.
fn zero_tests(cond: &Cond, above: &mut bool, non_zero: &mut bool) {
    match cond {
        Cond::All(members) | Cond::Any(members) | Cond::NoneOf(members) => {
            for member in members {
                zero_tests(member, above, non_zero);
            }
        }
        Cond::Int(Term::Macro(_), Cmp::Gt, 0) => *above = true,
        Cond::Int(Term::Macro(_), Cmp::Ne, 0) | Cond::Truth(Term::Macro(_)) => *non_zero = true,
        Cond::Int(_, _, _)
        | Cond::Truth(_)
        | Cond::Defined(_)
        | Cond::Missing(_)
        | Cond::Eq(_, _)
        | Cond::AnyStartsWith(_, _)
        | Cond::AnyContains(_, _)
        | Cond::NonEmpty(_) => {}
    }
}

/// The clauses `a_clause_testing_a_macro_above_zero_does_not_say_non_zero` holds, as
/// `check clause`, in table order.
const HELD_ABOVE_ZERO: &[&str] = &[
    "fortify-requested requested-without-optimization",
    "fortify-requested requested",
    "fortify-effective freebsd-unoptimized",
    "pie-macro set",
    "pic-macro set",
    "gcs-macro set",
    "branch-protection-macro full",
    "branch-protection-macro branch",
    "branch-protection-macro return",
    "exceptions-macro set",
];

#[test]
fn a_clause_testing_a_macro_above_zero_does_not_say_non_zero() {
    let tables = predicate::macro_channel::table()
        .iter()
        .chain(predicate::elf_static::table());
    let mut held = Vec::new();
    let mut failures = Vec::new();
    for (check, predicate) in tables {
        for clause in &predicate().clauses {
            let (mut above, mut non_zero) = (false, false);
            zero_tests(&clause.when, &mut above, &mut non_zero);
            if !above || non_zero {
                continue;
            }
            held.push(format!("{check} {}", clause.id));
            let because = clause.because.to_lowercase();
            if ["non-zero", "nonzero", "non zero", "not zero"]
                .iter()
                .any(|word| because.contains(word))
            {
                failures.push(format!("{check} {}: {}", clause.id, clause.because));
            }
        }
    }
    // The clauses held, pinned, so one that stops comparing a macro above zero, or gains a
    // `ne 0` beside it, leaves the rule loudly.
    assert_eq!(
        held, HELD_ABOVE_ZERO,
        "the clauses comparing a macro above zero"
    );
    assert!(
        failures.is_empty(),
        "a clause testing gt 0 says non-zero: {failures:?}"
    );
}
