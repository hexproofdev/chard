// SPDX-License-Identifier: BSD-3-Clause
//! The predicate language over arbitrary JSON. The input is one vector, `{"predicate": ...,
//! "facts": ...}`, or a file of them under `vectors`, so `schema/chard-predicate-vectors.json`
//! seeds it as it stands. A predicate that deserializes is validated, and one that validates
//! is evaluated over the facts beside it through the Published view a report is read with;
//! each evaluation that concludes is rendered as the `observed` sentence a report carries.
//! The Live view a measurement reads with evaluates the sources that read as typed facts
//! (`ElfFacts`, a macro map), and renders what concludes. None of it panics.
//!
//! Where every source the input carries reads as typed facts, the evaluator's two promises
//! are held over them as `tests/predicate_language.rs`'s property test holds them
//! over generated facts, with that test's construction of a publication:
//!
//! - the facts serialized as a report publishes them (`truncations` written out, the macro
//!   map untrimmed, this chard's watch list) evaluate to exactly what the Live view
//!   evaluated to, a conclusion or the `Incomplete` key it stopped at;
//! - where the Live view concludes, the macro map trimmed to its own names and the names
//!   the evaluation read concludes the same; a publication with no watch list stops at
//!   `symbols_filter` exactly when a symbol was read and is otherwise unchanged; and
//!   removing any one key the evaluation read makes the evaluation stop at that key;
//! - where the input's own publication (its filter and watch list as given) and the Live
//!   view both conclude, they state the same clause, outcome and level. The input's own
//!   publication may stop where the Live view concludes: that is the `Incomplete` the
//!   language requires of a publication that lacks a key, not a disagreement.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use chard::elf::ElfFacts;
use chard::predicate::{self, Evaluation, Live, Predicate, Published, ReadKey};
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

#[path = "json_mutator.rs"]
mod json_mutator;

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    json_mutator::mutate(data, size, max_size, seed)
});
use serde_json::Value;

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// The watch list a publication of this chard's facts carries.
fn watch_list() -> Vec<String> {
    chard::elf::WATCHED_SYMBOLS
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

/// `ElfFacts` as a re-evaluated publication carries them: `truncations` written out even
/// when empty, since `ElfFacts`' own serializer omits the empty list and the Published view
/// reads an absent one as `Incomplete`.
fn publish_elf(facts: &ElfFacts) -> Value {
    let mut json = serde_json::to_value(facts).expect("ElfFacts serializes");
    json.as_object_mut()
        .expect("ElfFacts serializes as an object")
        .entry("truncations")
        .or_insert_with(|| Value::Array(Vec::new()));
    json
}

/// A macro publication trimmed to the map's names and every name `live` read, less `drop`.
fn published_macros(
    map: &BTreeMap<String, String>,
    live: &Evaluation,
    drop: Option<&str>,
) -> (Value, Vec<String>) {
    let mut filter: BTreeSet<String> = map.keys().cloned().collect();
    for read in &live.reads {
        if let ReadKey::Macro(name) = &read.key {
            filter.insert(name.clone());
        }
    }
    let mut object = serde_json::to_value(map).expect("a string map serializes");
    if let Some(name) = drop {
        filter.remove(name);
        object
            .as_object_mut()
            .expect("a string map serializes as an object")
            .remove(name);
    }
    (object, filter.into_iter().collect())
}

/// The clause, outcome and level: what a report states of an evaluation.
fn stated(eval: &Evaluation) -> (&str, &str, Option<&str>) {
    (
        eval.clause.as_str(),
        eval.outcome.as_str(),
        eval.level.as_deref(),
    )
}

/// The Live view against publications of the same facts (module documentation).
fn hold_live_to_published(
    p: &Predicate,
    macros: Option<&BTreeMap<String, String>>,
    elf: Option<&ElfFacts>,
    own: Option<&Evaluation>,
) {
    let live = predicate::evaluate(p, &Live { macros, elf });
    if let (Ok(live), Some(own)) = (&live, own) {
        assert_eq!(
            stated(own),
            stated(live),
            "the input's own publication concludes otherwise than the Live view for {p:?}"
        );
    }
    let watched = watch_list();
    let elf_json = elf.map(publish_elf);
    let untrimmed = macros.map(|m| serde_json::to_value(m).expect("a string map serializes"));
    let whole = Published::new(
        untrimmed.as_ref(),
        None,
        elf_json.as_ref(),
        Some(watched.as_slice()),
    )
    .expect("serialized facts are objects");
    assert_eq!(
        predicate::evaluate(p, &whole),
        live,
        "the untrimmed publication disagrees with the Live view for {p:?}"
    );
    let Ok(live) = live else {
        return;
    };

    let trimmed = macros.map(|m| published_macros(m, &live, None));
    let view = Published::new(
        trimmed.as_ref().map(|(o, _)| o),
        trimmed.as_ref().map(|(_, f)| f.as_slice()),
        elf_json.as_ref(),
        Some(watched.as_slice()),
    )
    .expect("serialized facts are objects");
    assert_eq!(
        predicate::evaluate(p, &view).as_ref(),
        Ok(&live),
        "the trimmed publication disagrees with the Live view for {p:?}"
    );

    let unlisted = Published::new(untrimmed.as_ref(), None, elf_json.as_ref(), None)
        .expect("serialized facts are objects");
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
        assert_eq!(
            got.as_ref(),
            Ok(&live),
            "no symbol read, yet a publication with no watch list differs for {p:?}"
        );
    }

    for read in &live.reads {
        let key = read.key.published_key();
        let (macro_pub, elf_pub) = match &read.key {
            ReadKey::Macro(name) => (
                macros.map(|m| published_macros(m, &live, Some(name))),
                elf_json.clone(),
            ),
            ReadKey::Elf(_) | ReadKey::Symbol(_) | ReadKey::SymbolNames | ReadKey::Truncations => {
                let mut e = elf_json.clone().expect("an ELF read has ELF facts");
                let field = key
                    .strip_prefix("elf.")
                    .expect("an ELF read has an elf key");
                e.as_object_mut()
                    .expect("serialized facts are objects")
                    .remove(field);
                (trimmed.clone(), Some(e))
            }
        };
        let removed = Published::new(
            macro_pub.as_ref().map(|(o, _)| o),
            macro_pub.as_ref().map(|(_, f)| f.as_slice()),
            elf_pub.as_ref(),
            Some(watched.as_slice()),
        )
        .expect("serialized facts are objects");
        assert_eq!(
            predicate::evaluate(p, &removed)
                .as_ref()
                .map_err(|i| i.0.as_str()),
            Err(key.as_str()),
            "removing {key} from the publication of {p:?} did not stop at it"
        );
    }
}

fn one(vector: &Value) {
    let Some(Ok(p)) = vector
        .get("predicate")
        .map(|p| serde_json::from_value::<Predicate>(p.clone()))
    else {
        return;
    };
    if predicate::validate(&p).is_err() {
        return;
    }
    let facts = vector.get("facts").unwrap_or(&Value::Null);
    let filter = strings(facts.get("macros_filter"));
    let watch = strings(facts.get("symbols_filter"));
    let macros = facts.get("macros").filter(|m| !m.is_null());
    let elf = facts.get("elf").filter(|e| !e.is_null());
    let mut own = None;
    if let Ok(view) = Published::new(macros, filter.as_deref(), elf, watch.as_deref())
        && let Ok(eval) = predicate::evaluate(&p, &view)
    {
        let _ = predicate::render_observed(&p, &eval);
        own = Some(eval);
    }
    // The Live view reads each source that types and reads one that does not as absent, so
    // evaluation and rendering reach partially typed input.
    let typed_elf: Option<Result<ElfFacts, _>> = elf.map(|e| serde_json::from_value(e.clone()));
    let typed_macros: Option<Result<BTreeMap<String, String>, _>> =
        macros.map(|m| serde_json::from_value(m.clone()));
    let elf_ok = typed_elf.as_ref().and_then(|r| r.as_ref().ok());
    let macros_ok = typed_macros.as_ref().and_then(|r| r.as_ref().ok());
    let live = Live {
        macros: macros_ok,
        elf: elf_ok,
    };
    if let Ok(eval) = predicate::evaluate(&p, &live) {
        let _ = predicate::render_observed(&p, &eval);
    }
    // A source the input carries that the typed facts cannot read has no Live view to hold a
    // publication to: reading it as absent would compare a publication against facts it does
    // not hold.
    if matches!(typed_elf, Some(Err(_))) || matches!(typed_macros, Some(Err(_))) {
        return;
    }
    hold_live_to_published(&p, macros_ok, elf_ok, own.as_ref());
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    match value.get("vectors").and_then(Value::as_array) {
        Some(vectors) => vectors.iter().for_each(one),
        None => one(&value),
    }
});
