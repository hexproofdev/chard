// SPDX-License-Identifier: BSD-3-Clause

//! The macro and elf-static predicates' rules, judged one input at a time.

use std::collections::{BTreeMap, BTreeSet};

use chard::elf::ElfFacts;
use chard::measure::{MACRO_EVIDENCE_KEEP, relevant_macros};
use chard::predicate::{
    self, Conclusion, Cond, Evaluation, Fact, LevelOf, Live, Predicate, Published, ReadKey, Term,
};
use chard::probe::Outcome;
use serde_json::Value;

/// `p` over `macros` in the Live view, which is complete.
pub fn live(p: &Predicate, macros: &BTreeMap<String, String>) -> Evaluation {
    predicate::evaluate(
        p,
        &Live {
            macros: Some(macros),
            elf: None,
        },
    )
    .expect("a live view is complete")
}

/// Every term `p` reads, in its clauses and its conclusions.
pub fn terms(p: &Predicate) -> Vec<&Term> {
    fn cond<'a>(c: &'a Cond, out: &mut Vec<&'a Term>) {
        match c {
            Cond::All(members) | Cond::Any(members) | Cond::NoneOf(members) => {
                for member in members {
                    cond(member, out);
                }
            }
            Cond::Defined(t)
            | Cond::Missing(t)
            | Cond::Truth(t)
            | Cond::Eq(t, _)
            | Cond::Int(t, _, _)
            | Cond::AnyStartsWith(t, _)
            | Cond::AnyContains(t, _)
            | Cond::NonEmpty(t) => out.push(t),
        }
    }
    fn conclusion<'a>(c: &'a Conclusion, out: &mut Vec<&'a Term>) {
        if let Conclusion::Present(LevelOf::Value(t)) = c {
            out.push(t);
        }
    }
    let mut out = Vec::new();
    for clause in &p.clauses {
        cond(&clause.when, &mut out);
        conclusion(&clause.then, &mut out);
    }
    conclusion(&p.otherwise, &mut out);
    out
}

/// Every macro name `p` names: its `macro` and `c-int` terms and the three the
/// `cxx-stdlib` ladder consults. The names a `c-int` goes on to follow are not here; they
/// come from the map.
pub fn names_read(p: &Predicate) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for t in terms(p) {
        match t {
            Term::Macro(name) | Term::CInt(name) => {
                out.insert(name.clone());
            }
            Term::CxxStdlib => {
                out.extend(
                    ["_CXX_STDLIB", "_LIBCPP_VERSION", "__GLIBCXX__"].map(ToOwned::to_owned),
                );
            }
            Term::Elf(_) | Term::Symbol(_) | Term::SymbolNames => {
                panic!("a macro-channel predicate reads the artifact: {t:?}")
            }
        }
    }
    out
}

/// Whether `p` reads any `c-int` term, and so follows macro values as names.
pub fn follows_names(p: &Predicate) -> bool {
    terms(p).iter().any(|t| matches!(t, Term::CInt(_)))
}

/// The first few failures and how many there were, so one broken rule is not ten
/// thousand lines.
pub fn first(failures: &[String]) -> String {
    let shown: Vec<&str> = failures.iter().take(8).map(String::as_str).collect();
    format!(
        "{} failures, the first {}:\n{}",
        failures.len(),
        shown.len(),
        shown.join("\n")
    )
}

/// What the Published view over `relevant_macros(m)` and the published filter concludes,
/// beside what the Live view concluded over `m`.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishedReading {
    /// The two views conclude the same.
    Agrees,
    /// The Published view declined at a `c-int` follow to a name the filter does not keep,
    /// which the map defines.
    DeclinedDefined,
    /// The same, to a name the map leaves undefined.
    DeclinedUndefined,
    /// Anything else: a different conclusion, or `Incomplete` at a name that is kept.
    Fails(String),
}

/// Judge `p` over `m` by the rule `tests/predicates.rs`'s `filtered_macros_suffice` states:
/// the Published view concludes what the Live view concluded, or declines at a `c-int`
/// follow to a name the filter does not keep, which no term names and the Live view read.
pub fn published_reading(
    id: &str,
    p: &Predicate,
    m: &BTreeMap<String, String>,
    filter: &[String],
) -> PublishedReading {
    let named = names_read(p);
    let whole = live(p, m);
    let published = serde_json::to_value(relevant_macros(m)).expect("a string map");
    let view = Published::new(Some(&published), Some(filter), None, None).expect("an object");
    match predicate::evaluate(p, &view) {
        Ok(eval) if eval == whole => PublishedReading::Agrees,
        Ok(eval) => PublishedReading::Fails(format!(
            "{id}: over {m:?} the published view concluded {eval:?}, the live view {whole:?}"
        )),
        Err(incomplete) => {
            let key = incomplete.0.strip_prefix("macros.").unwrap_or_default();
            // Reached only by following: no term names it, the filter does not keep it,
            // and the live evaluation read it.
            let unkept_follow = follows_names(p)
                && !named.contains(key)
                && !MACRO_EVIDENCE_KEEP.contains(&key)
                && whole
                    .reads
                    .iter()
                    .any(|r| matches!(&r.key, ReadKey::Macro(n) if n.as_str() == key));
            if !unkept_follow {
                PublishedReading::Fails(format!(
                    "{id}: over {m:?} the published view is Incomplete({})",
                    incomplete.0
                ))
            } else if m.contains_key(key) {
                PublishedReading::DeclinedDefined
            } else {
                PublishedReading::DeclinedUndefined
            }
        }
    }
}

/// The names `p` reads as integers through a `macro` term: in an `int` or `truth`
/// condition, or as a `value` level. A `c-int` term is not here: it reads by its own
/// rule, under which text that is no value is `Undefined`, and the predicates over it
/// withhold under a clause of their own (`libcxx-unrecognised`).
pub fn integer_names(p: &Predicate) -> BTreeSet<String> {
    fn cond(c: &Cond, out: &mut BTreeSet<String>) {
        match c {
            Cond::All(members) | Cond::Any(members) | Cond::NoneOf(members) => {
                for member in members {
                    cond(member, out);
                }
            }
            Cond::Int(Term::Macro(name), _, _) | Cond::Truth(Term::Macro(name)) => {
                out.insert(name.clone());
            }
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
    let mut out = BTreeSet::new();
    for clause in &p.clauses {
        cond(&clause.when, &mut out);
        if let Conclusion::Present(LevelOf::Value(Term::Macro(name))) = &clause.then {
            out.insert(name.clone());
        }
    }
    if let Conclusion::Present(LevelOf::Value(Term::Macro(name))) = &p.otherwise {
        out.insert(name.clone());
    }
    out
}

/// The integers `p` compares the macro `name` with, each beside its two neighbours, any
/// integer an `eq` over it names, and -1, 0 and 1, either side of zero and zero, where
/// `truth` decides: a value from
/// every interval its comparisons cut the integers into, so a reading the same at each
/// is the same at every integer.
/// `i64::MIN` is left out, the one integer `macro_channel::readable` leaves to the
/// `unreadable` clauses, since C's `#if` reads its text as above zero.
pub fn readable_values(p: &Predicate, name: &str) -> BTreeSet<i64> {
    fn cond(c: &Cond, name: &str, out: &mut BTreeSet<i64>) {
        match c {
            Cond::All(members) | Cond::Any(members) | Cond::NoneOf(members) => {
                for member in members {
                    cond(member, name, out);
                }
            }
            Cond::Int(Term::Macro(n), _, bound) if n == name => {
                out.extend(
                    [bound.checked_sub(1), Some(*bound), bound.checked_add(1)]
                        .into_iter()
                        .flatten(),
                );
            }
            Cond::Eq(Term::Macro(n), text) if n == name => {
                out.extend(text.parse::<i64>());
            }
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
    let mut out = BTreeSet::from([-1, 0, 1]);
    for clause in &p.clauses {
        cond(&clause.when, name, &mut out);
    }
    out.remove(&i64::MIN);
    out
}

/// The names among `names` that `m` defines with text the integer reading does not
/// read, `i64::MIN`'s decimal among them (`macro_channel::readable`).
pub fn unreadable_in(m: &BTreeMap<String, String>, names: &BTreeSet<String>) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            m.get(name.as_str()).is_some_and(|text| {
                Fact::Text(text.clone())
                    .integer()
                    .is_none_or(|i| i == i64::MIN)
            })
        })
        .cloned()
        .collect()
}

/// Where `eval`, over `m`, differs from the reading `m` gives with every name of
/// `names` defined as an integer instead, each of [`readable_values`] and all of them
/// at once, one line per assignment that moves it. The names are put in together, so a
/// clause that reads two of them, one behind the other, is held at every pair: put in
/// one at a time, `all [A gt 0, B gt 0]` over two unreadable names reads `A` alone and
/// never shows the `present` the pair gives. An integer put in replaces the text, so a
/// clause that also compares the same name's text (`eq`, `non-empty`) is not held by
/// this: no shipped predicate reads an integer name so.
pub fn moved_by(
    p: &Predicate,
    m: &BTreeMap<String, String>,
    eval: &Evaluation,
    names: &[String],
) -> Vec<String> {
    let values: Vec<Vec<i64>> = names
        .iter()
        .map(|name| readable_values(p, name).into_iter().collect())
        .collect();
    let mut moved = Vec::new();
    let mut digits = vec![0usize; names.len()];
    loop {
        let mut put = m.clone();
        for (i, name) in names.iter().enumerate() {
            put.insert(name.clone(), values[i][digits[i]].to_string());
        }
        let other = live(p, &put);
        if other.outcome != eval.outcome || other.level != eval.level {
            let at: Vec<String> = names
                .iter()
                .enumerate()
                .map(|(i, name)| format!("{name}={}", values[i][digits[i]]))
                .collect();
            moved.push(format!(
                "{} moves to {:?} at {:?} under {}",
                at.join(" "),
                other.outcome,
                other.level,
                other.clause
            ));
        }
        // The next assignment, the last name fastest; done when every name wrapped.
        let Some(i) = (0..names.len())
            .rev()
            .find(|&i| digits[i] + 1 < values[i].len())
        else {
            return moved;
        };
        digits[i] += 1;
        for later in &mut digits[i + 1..] {
            *later = 0;
        }
    }
}

/// The published form of a case's facts, with `truncations` stated.
pub fn published_elf(facts: &ElfFacts) -> Value {
    let mut value = serde_json::to_value(facts).expect("facts serialize");
    if let Some(map) = value.as_object_mut() {
        for stated in chard::report::STATED_WHEN_EMPTY {
            map.entry(stated)
                .or_insert_with(|| Value::Array(Vec::new()));
        }
        map.entry("data_in_code_pages").or_insert(Value::Null);
        map.entry("code_relocations").or_insert(Value::Null);
        map.entry("function_references").or_insert(Value::Null);
        map.entry("rwx_segment").or_insert(Value::Null);
    }
    value
}

/// How `p` reads `m` where `m` may define a name `p` reads as an integer with text that
/// has no integer reading.
#[derive(Debug, PartialEq, Eq)]
pub enum UnreadableReading {
    /// The evaluation read no such text.
    NotRead,
    /// It read such text and withheld.
    Withheld,
    /// It read such text and concluded, and every integer there gives the same reading.
    Stood,
    /// It read such text and concluded what some integer there would move.
    Fails(String),
}

/// Judge `p` over `m` by the rule `tests/predicates.rs`'s
/// `a_macro_with_no_integer_reading_decides_no_verdict` states, where `names` is
/// [`integer_names`] of `p`: a reading that read such text withholds, or is the reading
/// every integer put in for it gives ([`moved_by`]).
pub fn unreadable_reading(
    id: &str,
    p: &Predicate,
    names: &BTreeSet<String>,
    m: &BTreeMap<String, String>,
) -> UnreadableReading {
    let eval = live(p, m);
    // Defined text that is not readable, by the language's own reading and the one
    // decimal `readable` leaves out (`macro_channel::readable`).
    let unreadable: Vec<&str> = eval
        .reads
        .iter()
        .filter_map(|r| match (&r.key, &r.value) {
            (ReadKey::Macro(name), Fact::Text(_))
                if names.contains(name.as_str())
                    && r.value.integer().is_none_or(|i| i == i64::MIN) =>
            {
                Some(name.as_str())
            }
            _ => None,
        })
        .collect();
    if unreadable.is_empty() {
        return UnreadableReading::NotRead;
    }
    if eval.outcome == Outcome::Indeterminate {
        return UnreadableReading::Withheld;
    }
    let moved = moved_by(p, m, &eval, &unreadable_in(m, names));
    if moved.is_empty() {
        UnreadableReading::Stood
    } else {
        UnreadableReading::Fails(format!(
            "{id}: over {m:?} read {unreadable:?} with no integer reading and concluded {:?} \
             under {}, which {}",
            eval.outcome,
            eval.clause,
            moved.join(", ")
        ))
    }
}
