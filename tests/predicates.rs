// SPDX-License-Identifier: BSD-3-Clause

//! The macro and elf-static predicates, which are those checks' decoders.

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

use chard::predicate::{self, Conclusion, LevelOf, Predicate};
use chard::probe::{self, Channel, Check, Decoder};

mod common;
mod predicate_rules;

/// Write a `chard:` line to the real stderr, which libtest does not capture, so a passing
/// run's log carries the seed and the counts as plainly as a failing one; the same reason
/// as `tests/seeded`'s `announce`.
macro_rules! announce {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let line = format!("\n{}\n", format!($($arg)*));
        let mut stderr = std::io::stderr().lock();
        chard::error::best_effort(stderr.write_all(line.as_bytes()).and_then(|()| stderr.flush()));
    }};
}

fn corpus_checks() -> impl Iterator<Item = &'static Check> {
    probe::CORPUS.iter().flat_map(|p| p.checks.iter())
}

#[test]
fn every_macro_and_elf_static_check_has_a_predicate_and_no_predicate_is_orphaned() {
    let tables = [
        (Channel::Macro, predicate::macro_channel::table()),
        (Channel::ElfStatic, predicate::elf_static::table()),
    ];
    let mut decoded = 0usize;
    for check in corpus_checks() {
        let listed = tables
            .iter()
            .flat_map(|(channel, table)| table.iter().map(move |e| (*channel, e)))
            .filter(|(_, (id, _))| *id == check.id)
            .collect::<Vec<_>>();
        match check.decoder {
            Decoder::Macro(p) | Decoder::ElfStatic(p) => {
                decoded += 1;
                let [(channel, (_, entry))] = listed.as_slice() else {
                    panic!(
                        "{} is listed {} times in the tables",
                        check.id,
                        listed.len()
                    );
                };
                assert_eq!(
                    *channel,
                    check.channel(),
                    "{}: listed on its channel",
                    check.id
                );
                assert!(
                    std::ptr::eq(entry(), p()),
                    "{}: the table lists the predicate the check decodes with",
                    check.id
                );
                assert!(
                    predicate::for_check(check.id).is_some_and(|q| std::ptr::eq(q, p())),
                    "{}",
                    check.id
                );
                predicate::validate(p()).unwrap_or_else(|e| panic!("{}: {e}", check.id));
                if check.channel() == Channel::Macro {
                    assert!(
                        !predicate::needs_elf(p()),
                        "{} reads the artifact",
                        check.id
                    );
                }
            }
            Decoder::Runtime { .. } | Decoder::CompilerDiag { .. } => {
                assert!(check.predicate().is_none());
                assert!(
                    listed.is_empty(),
                    "{} decodes with code and is listed",
                    check.id
                );
            }
        }
    }
    let entries: usize = tables.iter().map(|(_, t)| t.len()).sum();
    announce!("chard: predicates: {decoded} checks decode through {entries} table entries");
    assert!(decoded > 0);
    assert_eq!(
        decoded, entries,
        "every table entry is some corpus check's decoder, so none is orphaned"
    );
}

#[test]
fn every_word_a_predicate_concludes_is_one_its_check_admits() {
    let mut words = 0usize;
    for check in corpus_checks() {
        let Some(p) = check.predicate() else {
            continue;
        };
        let conclusions = p.clauses.iter().map(|c| &c.then).chain([&p.otherwise]);
        for conclusion in conclusions {
            if let Conclusion::Present(LevelOf::Word(word)) = conclusion {
                words += 1;
                assert!(
                    check.levels.admits(word),
                    "{} concludes {word:?}, which its levels do not admit",
                    check.id
                );
            }
        }
    }
    announce!("chard: predicate words: {words} concluded words held to their checks' levels");
    assert!(words > 0);
}

fn predicate_of(check: &Check) -> &'static Predicate {
    check
        .predicate()
        .unwrap_or_else(|| panic!("{} has no predicate", check.id))
}

/// The macro channel: clause reach over a generated space of macro values, and the
/// published filter.
mod macro_channel {
    use chard::measure::MACRO_EVIDENCE_KEEP;
    use chard::predicate::{Cond, ReadKey, Term};
    use chard::probe::Outcome;

    use super::*;
    use crate::predicate_rules::{
        PublishedReading, UnreadableReading, first, follows_names, integer_names, live, moved_by,
        names_read, published_reading, unreadable_in, unreadable_reading,
    };

    /// The flag spelling that forwards libc++'s mode to a named constant.
    const MODE_FLAG: &str = "-D_LIBCPP_HARDENING_MODE=";

    /// The prefix libc++'s mode constants share.
    const MODE_PREFIX: &str = "_LIBCPP_HARDENING_MODE_";

    /// A libc++-shaped name the published filter does not keep, defined in the generated
    /// space so a `c-int` follow outside the filter is exercised rather than assumed absent.
    /// It stands for any caller's `-D_LIBCPP_HARDENING_MODE=MYMODE -DMYMODE=4`.
    const UNKEPT_TARGET: &str = "_LIBCPP_HARDENING_MODE_OTHER";

    /// The values every generated macro ranges over, besides being absent and naming a
    /// sibling: the integer readings' edge cases, the spellings a build's `-D` arrives in
    /// that have no integer reading (`(3)`, `3L`, `2UL`, each measured as the text of
    /// `_FORTIFY_SOURCE`), the one decimal C types as unsigned, and the words the detectors
    /// compare text to. A number with a leading zero is held by [`leading_zero_rows`]
    /// instead: a value added here moves which seeded draws are taken.
    const VALUES: &[&str] = &[
        "",
        "0",
        "1",
        "2",
        "3",
        "4",
        "8",
        "16",
        "-1",
        " 2 ",
        "+1",
        "(3)",
        "3L",
        "2UL",
        "-9223372036854775808",
        "1<<2",
        "(1 << 4)",
        "x",
        "fortify-headers",
        "libc++",
        "libstdc++",
    ];

    /// The three shapes of a name, enumerated whole beside the draws over a space too large
    /// to enumerate: undefined, an integer, and text with no integer reading.
    const SHAPES: [Option<&str>; 3] = [None, Some("2"), Some("x")];

    /// The largest space enumerated whole; a larger one is sampled.
    const EXHAUSTIVE_LIMIT: usize = 50_000;
    /// Draws taken from a space too large to enumerate.
    const DRAWS: usize = 20_000;
    /// The sampler's seed, printed with every sampled count so a failure is reproducible.
    const SEED: u64 = 0x6368_6172_645f_6d61;

    fn macro_checks() -> Vec<&'static Check> {
        probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.channel() == Channel::Macro)
            .collect()
    }

    /// The names libc++'s mode is forwarded to by something other than the filter under test:
    /// every `-D_LIBCPP_HARDENING_MODE=NAME` in the corpus's control flags. A control
    /// forwarding to a name the filter does not keep fails
    /// `every_name_a_predicate_reads_is_kept`.
    fn forwarded_mode_names() -> BTreeSet<String> {
        probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .flat_map(|c| c.positive.iter().chain(c.negative))
            .flat_map(|flag| {
                flag.split(',')
                    .filter_map(|piece| piece.trim().strip_prefix(MODE_FLAG).map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .filter(|name| name.starts_with(MODE_PREFIX))
            .collect()
    }

    /// The names the generated space defines for a `c-int` to follow: the forwarded names,
    /// the filter's own libc++ constants (so each kept one is exercised), and
    /// [`UNKEPT_TARGET`].
    fn mode_targets() -> BTreeSet<String> {
        let mut targets = forwarded_mode_names();
        targets.extend(
            MACRO_EVIDENCE_KEEP
                .iter()
                .filter(|n| n.starts_with(MODE_PREFIX))
                .map(|n| (*n).to_owned()),
        );
        targets.insert(UNKEPT_TARGET.to_owned());
        targets
    }

    /// xorshift64*, hand-written: the four-dependency rule covers dev-dependencies.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let draw = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
            usize::try_from(draw % u64::try_from(n).expect("small")).expect("small")
        }
    }

    /// One check's generated space: the names it reads and the values each ranges over.
    struct Space {
        names: Vec<String>,
        /// `None` is the macro left undefined.
        domain: Vec<Option<String>>,
    }

    impl Space {
        fn of(p: &Predicate) -> Self {
            let mut read = names_read(p);
            if follows_names(p) {
                read.extend(mode_targets());
            }
            let names: Vec<String> = read.into_iter().collect();
            let mut domain: Vec<Option<String>> = vec![None];
            domain.extend(VALUES.iter().map(|v| Some((*v).to_owned())));
            // Sibling references, which is how `c-int` reaches a forwarded mode.
            for name in &names {
                if !VALUES.contains(&name.as_str()) {
                    domain.push(Some(name.clone()));
                }
            }
            Self { names, domain }
        }

        fn map(&self, assignment: &[usize]) -> BTreeMap<String, String> {
            self.names
                .iter()
                .zip(assignment)
                .filter_map(|(name, i)| self.domain[*i].clone().map(|v| (name.clone(), v)))
                .collect()
        }

        /// Every assignment over `digits` of the domain, in mixed radix.
        fn product(&self, digits: &[usize]) -> Vec<Vec<usize>> {
            let radix = digits.len();
            let n = self.names.len();
            let size = radix.pow(u32::try_from(n).expect("small"));
            (0..size)
                .map(|mut index| {
                    (0..n)
                        .map(|_| {
                            let digit = index % radix;
                            index /= radix;
                            digits[digit]
                        })
                        .collect()
                })
                .collect()
        }

        /// Every assignment when the product is small enough; else every assignment over
        /// the three [`SHAPES`] of each name, then `DRAWS` seeded draws over the whole
        /// domain. A rung below several withholding rungs is reached by a draw only where
        /// every name above it took one shape of the twenty-odd, which the draws over six
        /// names miss (`fortify-effective`'s `requested-without-optimization` sits under
        /// three such rungs); the shapes alone walk every such ladder whole. Returns the
        /// assignments and a sentence saying which.
        fn assignments(&self) -> (Vec<Vec<usize>>, String) {
            let width = self.domain.len();
            let size = u32::try_from(self.names.len())
                .ok()
                .and_then(|n| width.checked_pow(n))
                .filter(|size| *size <= EXHAUSTIVE_LIMIT);
            if size.is_some() {
                let all = self.product(&(0..width).collect::<Vec<_>>());
                let points = all.len();
                return (all, format!("exhaustive, {points} points"));
            }
            let shapes: Vec<usize> = SHAPES
                .iter()
                .map(|shape| {
                    self.domain
                        .iter()
                        .position(|d| d.as_deref() == *shape)
                        .expect("the domain holds every shape")
                })
                .collect();
            let mut all = self.product(&shapes);
            let shaped = all.len();
            let mut rng = Rng(SEED);
            all.extend((0..DRAWS).map(|_| {
                (0..self.names.len())
                    .map(|_| rng.below(width))
                    .collect::<Vec<_>>()
            }));
            (
                all,
                format!(
                    "{shaped} points over three shapes, then {DRAWS} draws of {width}^{} \
                     points, seed {SEED:#018x}",
                    self.names.len()
                ),
            )
        }
    }

    /// Maps written out, each beside the generated space of its check, for a rung the draws
    /// miss: fortify-headers at a request above 2, under either of its marks, where three
    /// names must take one value each of the domain at once.
    const WRITTEN_MAPS: &[(&str, &[(&str, &str)])] = &[
        (
            "fortify-effective",
            &[
                ("_FORTIFY_IMPL", "fortify-headers"),
                ("_FORTIFY_SOURCE", "3"),
                ("__OPTIMIZE__", "1"),
            ],
        ),
        (
            "fortify-effective",
            &[
                ("_FORTIFY_HEADERS_H", ""),
                ("_FORTIFY_SOURCE", "3"),
                ("__OPTIMIZE__", "1"),
            ],
        ),
    ];

    /// Every macro map a check is exercised over: its [`WRITTEN_MAPS`], then its generated
    /// space.
    fn every_map(check: &Check) -> Vec<BTreeMap<String, String>> {
        let space = Space::of(predicate_of(check));
        WRITTEN_MAPS
            .iter()
            .filter(|(id, _)| *id == check.id)
            .map(|(_, map)| {
                map.iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect()
            })
            .chain(space.assignments().0.iter().map(|a| space.map(a)))
            .collect()
    }

    #[test]
    fn every_clause_is_reached() {
        let mut dead = Vec::new();
        for check in macro_checks() {
            let p = predicate_of(check);
            let mut reached: BTreeMap<String, usize> = BTreeMap::new();
            for m in every_map(check) {
                *reached.entry(live(p, &m).clause).or_default() += 1;
            }
            announce!("chard: clauses reached: {}: {reached:?}", check.id);
            for clause in &p.clauses {
                if !reached.contains_key(&clause.id) {
                    dead.push(format!("{}: {}", check.id, clause.id));
                }
            }
        }
        assert!(dead.is_empty(), "clauses no map reaches: {dead:?}");
    }

    #[test]
    fn filtered_macros_suffice() {
        let filter: Vec<String> = MACRO_EVIDENCE_KEEP
            .iter()
            .map(|n| (*n).to_owned())
            .collect();
        let mut failures = Vec::new();
        let mut declined_defined = 0usize;
        let mut declined_undefined = 0usize;
        for check in macro_checks() {
            let p = predicate_of(check);
            let mut fed = 0usize;
            let mut declined = 0usize;
            for m in every_map(check) {
                fed += 1;
                match published_reading(check.id, p, &m, &filter) {
                    PublishedReading::Agrees => {}
                    PublishedReading::DeclinedDefined => {
                        declined += 1;
                        declined_defined += 1;
                    }
                    PublishedReading::DeclinedUndefined => {
                        declined += 1;
                        declined_undefined += 1;
                    }
                    PublishedReading::Fails(failure) => failures.push(failure),
                }
            }
            announce!(
                "chard: filtered macros: {}: {fed} maps, {declined} declined at a c-int follow \
             to an unkept name",
                check.id
            );
            assert!(fed > 0);
        }
        announce!(
            "chard: filtered macros: declined follows, {declined_defined} to a defined name, \
         {declined_undefined} to an undefined one"
        );
        assert!(failures.is_empty(), "{}", first(&failures));
        assert!(
            declined_defined > 0 && declined_undefined > 0,
            "the generated space no longer exercises both halves of the unkept follow"
        );
    }

    #[test]
    fn every_name_a_predicate_reads_is_kept() {
        let forwarded = forwarded_mode_names();
        assert!(
            !MACRO_EVIDENCE_KEEP.contains(&UNKEPT_TARGET),
            "{UNKEPT_TARGET} is kept, so it no longer stands for a name outside the filter"
        );
        let mut missing = BTreeSet::new();
        let mut followed = BTreeSet::new();
        for check in macro_checks() {
            let p = predicate_of(check);
            let named = names_read(p);
            for name in &named {
                if !MACRO_EVIDENCE_KEEP.contains(&name.as_str()) {
                    missing.insert(name.clone());
                }
            }
            for m in every_map(check) {
                for read in live(p, &m).reads {
                    if let ReadKey::Macro(name) = read.key
                        && m.contains_key(name.as_str())
                        && !named.contains(name.as_str())
                    {
                        followed.insert(name.as_str().to_owned());
                    }
                }
            }
        }
        for name in &followed {
            if name != UNKEPT_TARGET && !MACRO_EVIDENCE_KEEP.contains(&name.as_str()) {
                missing.insert(name.clone());
            }
        }
        announce!(
            "chard: kept names: {} defined names followed by c-int, {} forwarded by the corpus's \
         controls: {forwarded:?}",
            followed.len(),
            forwarded.len()
        );
        assert!(
            !forwarded.is_empty(),
            "nothing forwards libc++'s mode by name"
        );
        for target in forwarded.iter().map(String::as_str).chain([UNKEPT_TARGET]) {
            assert!(
                followed.contains(target),
                "no map follows a mode to {target}"
            );
        }
        assert!(missing.is_empty(), "read and not kept: {missing:?}");
    }

    #[test]
    fn a_reading_some_integer_would_move_is_found() {
        let x = || Term::Macro("X".to_owned());
        let y = || Term::Macro("Y".to_owned());
        let maps = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        let one = Predicate {
            tables: Vec::new(),
            clauses: vec![predicate::Clause {
                id: "seven".to_owned(),
                when: Cond::Int(x(), predicate::Cmp::Eq, 7),
                then: Conclusion::Absent,
                because: "X is 7".to_owned(),
            }],
            otherwise: Conclusion::Present(LevelOf::None),
        };
        let m = maps(&[("X", "(7)")]);
        let eval = live(&one, &m);
        assert_eq!(eval.outcome, Outcome::Present);
        let names = unreadable_in(&m, &BTreeSet::from(["X".to_owned()]));
        assert_eq!(names, ["X"]);
        let moved = moved_by(&one, &m, &eval, &names);
        assert_eq!(moved.len(), 1, "{moved:?}");
        assert!(moved[0].starts_with("X=7 moves to Absent"), "{moved:?}");

        let pair = Predicate {
            tables: Vec::new(),
            clauses: vec![predicate::Clause {
                id: "both".to_owned(),
                when: Cond::All(vec![
                    Cond::Int(x(), predicate::Cmp::Gt, 0),
                    Cond::Int(y(), predicate::Cmp::Gt, 0),
                ]),
                then: Conclusion::Present(LevelOf::None),
                because: "X and Y are above zero".to_owned(),
            }],
            otherwise: Conclusion::Absent,
        };
        let m = maps(&[("X", "x"), ("Y", "y")]);
        let eval = live(&pair, &m);
        assert_eq!((eval.outcome, eval.reads.len()), (Outcome::Absent, 1));
        let names = unreadable_in(&m, &BTreeSet::from(["X".to_owned(), "Y".to_owned()]));
        let moved = moved_by(&pair, &m, &eval, &names);
        assert!(
            moved
                .iter()
                .any(|line| line.contains("X=1 Y=1 moves to Present")),
            "{moved:?}"
        );
        // The values tried hold each bound's neighbour and the three around zero: a reading
        // that moves only above a bound, or only where `truth` holds, is found.
        let shaped = |when: Cond| Predicate {
            clauses: vec![predicate::Clause {
                id: "shaped".to_owned(),
                when,
                ..pair.clauses[0].clone()
            }],
            ..pair.clone()
        };
        let x_only = maps(&[("X", "x")]);
        let x_name = ["X".to_owned()];
        for (when, at) in [
            (Cond::Int(x(), predicate::Cmp::Gt, 5), "X=6 "),
            (Cond::Truth(x()), "X=-1 "),
        ] {
            let p = shaped(when);
            let eval = live(&p, &x_only);
            assert_eq!(eval.outcome, Outcome::Absent);
            let moved = moved_by(&p, &x_only, &eval, &x_name);
            assert!(
                moved.iter().any(|line| line.starts_with(at)),
                "{at}: {moved:?}"
            );
        }
        // Every assignment is visited: under `any`, the five of nine where X or Y is 1 move.
        let either = Predicate {
            clauses: vec![predicate::Clause {
                id: "either".to_owned(),
                when: Cond::Any(vec![
                    Cond::Int(x(), predicate::Cmp::Gt, 0),
                    Cond::Int(y(), predicate::Cmp::Gt, 0),
                ]),
                ..pair.clauses[0].clone()
            }],
            ..pair.clone()
        };
        let eval = live(&either, &m);
        assert_eq!(eval.outcome, Outcome::Absent);
        assert_eq!(moved_by(&either, &m, &eval, &names).len(), 5);
        // One name at a time finds nothing: the shape the joint substitution is for.
        for name in &names {
            assert!(
                moved_by(&pair, &m, &eval, std::slice::from_ref(name))
                    .iter()
                    .all(|line| !line.contains("Present")),
                "{name} alone moved the pair"
            );
        }
    }

    #[test]
    fn a_macro_with_no_integer_reading_decides_no_verdict() {
        let mut failures = Vec::new();
        let mut held = Vec::new();
        for check in macro_checks() {
            let p = predicate_of(check);
            let names = integer_names(p);
            if names.is_empty() {
                continue;
            }
            held.push(check.id);
            let mut fed = 0usize;
            let mut withheld = 0usize;
            let mut stood = 0usize;
            for m in every_map(check) {
                fed += 1;
                match unreadable_reading(check.id, p, &names, &m) {
                    UnreadableReading::NotRead => {}
                    UnreadableReading::Withheld => withheld += 1,
                    UnreadableReading::Stood => stood += 1,
                    UnreadableReading::Fails(failure) => failures.push(failure),
                }
            }
            announce!(
                "chard: unreadable macros: {}: {} of {fed} maps read one of {names:?} as text \
                 with no integer reading: {withheld} withheld, {stood} the reading every \
                 integer there gives",
                check.id,
                withheld + stood
            );
            assert!(
                withheld > 0,
                "{}: no map reads a name among {names:?} as text with no integer reading",
                check.id
            );
            // The one predicate with a rung ahead of its unreadable one that holds at every
            // value: the rule's second side is held over maps that reach it.
            if check.id == "fortify-effective" {
                assert!(
                    stood > 0,
                    "fortify-effective: no reading stood at every value"
                );
            }
        }
        // The checks the rule holds, pinned, so one that stops reading an integer through a
        // `macro` term leaves the rule loudly rather than by a `continue`.
        held.sort_unstable();
        assert_eq!(
            held,
            [
                "branch-protection-macro",
                "cet-macro",
                "exceptions-macro",
                "fortify-effective",
                "fortify-requested",
                "gcs-macro",
                "pic-macro",
                "pie-macro",
            ]
        );
        assert!(failures.is_empty(), "{}", first(&failures));
    }

    /// One row of the spelling table: the check, the macros, the deciding clause, the
    /// outcome and the level.
    type Row = (
        &'static Check,
        BTreeMap<String, String>,
        String,
        Outcome,
        Option<String>,
    );

    /// One spelling, the check it reaches, and the clause that decides it.
    fn row(
        check: &str,
        macros: &[(&str, &str)],
        clause: &str,
        outcome: Outcome,
        level: Option<&str>,
    ) -> Row {
        let check = macro_checks()
            .into_iter()
            .find(|c| c.id == check)
            .unwrap_or_else(|| panic!("{check} is a macro check"));
        let macros = macros
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        (
            check,
            macros,
            clause.to_owned(),
            outcome,
            level.map(str::to_owned),
        )
    }

    /// FreeBSD's level macro beside its platform macro: unreadable text in either,
    /// the level, zero, an unoptimized instantiation, and a release below 15 with no level;
    /// the level macro without the platform macro is no FreeBSD and falls through, as does a
    /// 15 whose headers defined no level.
    fn freebsd_effective_rows() -> Vec<Row> {
        let fs = "_FORTIFY_SOURCE";
        let level = "__SSP_FORTIFY_LEVEL";
        let bsd = "__FreeBSD__";
        let opt = "__OPTIMIZE__";
        let w = Outcome::Indeterminate;
        let effective = "fortify-effective";
        vec![
            row(
                effective,
                &[(fs, "2"), (level, "2"), (bsd, "(15)"), (opt, "1")],
                "freebsd-release-unreadable",
                w,
                None,
            ),
            row(
                effective,
                &[(level, "(2)"), (bsd, "15"), (opt, "1")],
                "freebsd-unreadable",
                w,
                None,
            ),
            row(
                effective,
                &[(fs, "3"), (level, "2"), (bsd, "15"), (opt, "1")],
                "freebsd-level",
                Outcome::Present,
                Some("2"),
            ),
            row(
                effective,
                &[(fs, "2"), (level, "0"), (bsd, "15"), (opt, "1")],
                "freebsd-zero",
                Outcome::Absent,
                None,
            ),
            row(
                effective,
                &[(fs, "2"), (level, "2"), (bsd, "15")],
                "freebsd-unoptimized",
                w,
                None,
            ),
            row(
                effective,
                &[(fs, "2"), (bsd, "14"), (opt, "1")],
                "freebsd-without-ssp",
                Outcome::Absent,
                None,
            ),
            row(
                effective,
                &[(fs, "2"), (bsd, "15"), (opt, "1")],
                "@otherwise",
                w,
                None,
            ),
            row(
                effective,
                &[(fs, "2"), (level, "2"), (opt, "1")],
                "@otherwise",
                w,
                None,
            ),
        ]
    }

    /// The fortify spellings a measurement produced, each under the clause that withholds
    /// it, beside the readings that stay: an integer request, a library's own level read
    /// whatever the request's spelling, a library that identified itself read ahead of an
    /// unreadable request, and glibc's unreadable level ahead of Apple's readable one; and
    /// FreeBSD's rows, [`freebsd_effective_rows`].
    fn fortify_rows() -> Vec<Row> {
        let fs = "_FORTIFY_SOURCE";
        let glibc = "__USE_FORTIFY_LEVEL";
        let apple = "_USE_FORTIFY_LEVEL";
        let opt = "__OPTIMIZE__";
        let w = Outcome::Indeterminate;
        let unreadable = "requested-unreadable";
        let mut rows = freebsd_effective_rows();
        rows.extend(vec![
            row(
                "fortify-requested",
                &[(fs, "(3)"), (glibc, "3"), (opt, "2")],
                unreadable,
                w,
                None,
            ),
            row(
                "fortify-requested",
                &[(fs, "3L"), (apple, "2"), (opt, "2")],
                unreadable,
                w,
                None,
            ),
            row(
                "fortify-requested",
                &[(fs, "2UL"), (apple, "2"), (opt, "2")],
                unreadable,
                w,
                None,
            ),
            row(
                "fortify-requested",
                &[(fs, "-9223372036854775808")],
                unreadable,
                w,
                None,
            ),
            row(
                "fortify-requested",
                &[(fs, "3"), (glibc, "3"), (opt, "2")],
                "requested",
                Outcome::Present,
                Some("3"),
            ),
            row(
                "fortify-effective",
                &[(glibc, "(3)")],
                "glibc-unreadable",
                w,
                None,
            ),
            row(
                "fortify-effective",
                &[(glibc, "(3)"), (apple, "2")],
                "glibc-unreadable",
                w,
                None,
            ),
            row(
                "fortify-effective",
                &[(apple, "(2)")],
                "apple-unreadable",
                w,
                None,
            ),
            row(
                "fortify-effective",
                &[(fs, "(3)"), (opt, "2")],
                unreadable,
                w,
                None,
            ),
            row(
                "fortify-effective",
                &[(fs, "(3)"), (glibc, "3")],
                "glibc-level",
                Outcome::Present,
                Some("3"),
            ),
            row(
                "fortify-effective",
                &[(fs, "(3)"), ("_FORTIFY_HEADERS_H", "")],
                "fortify-headers-unread-request",
                w,
                None,
            ),
        ]);
        rows.extend(fortify_request_rows());
        rows
    }

    /// The request below the libraries' rungs, and the leading-zero spellings. At or below
    /// zero a request is no request, as glibc reads it. Without optimization, or on a
    /// FreeBSD with no `<ssp/ssp.h>`, no implementation instantiates at any request, so a
    /// request the language cannot read (`(3)`, `010`, empty text) is `absent` there. An
    /// optimized one beside no library is withheld. A leading zero, which C reads as octal,
    /// is withheld by `fortify-requested` and by glibc's level rung too.
    fn fortify_request_rows() -> Vec<Row> {
        let fs = "_FORTIFY_SOURCE";
        let opt = "__OPTIMIZE__";
        let w = Outcome::Indeterminate;
        let effective = "fortify-effective";
        let absent = |macros: &[(&str, &str)], clause: &str| {
            row(effective, macros, clause, Outcome::Absent, None)
        };
        vec![
            absent(&[(fs, "-1"), (opt, "2")], "not-requested"),
            absent(&[(fs, "0"), (opt, "2")], "not-requested"),
            absent(&[(opt, "2")], "not-requested"),
            absent(&[(fs, "(3)")], "requested-without-optimization"),
            absent(&[(fs, "3L")], "requested-without-optimization"),
            absent(&[(fs, "3")], "requested-without-optimization"),
            absent(&[(fs, "010")], "requested-without-optimization"),
            absent(&[(fs, "")], "requested-without-optimization"),
            row(
                effective,
                &[(fs, ""), (opt, "2")],
                "requested-unreadable",
                w,
                None,
            ),
            absent(
                &[(fs, "(3)"), ("__FreeBSD__", "14"), (opt, "1")],
                "freebsd-without-ssp",
            ),
            row(
                effective,
                &[(fs, "(3)"), (opt, "2")],
                "requested-unreadable",
                w,
                None,
            ),
            row(
                effective,
                &[(fs, "010"), (opt, "2")],
                "requested-unreadable",
                w,
                None,
            ),
            row(
                effective,
                &[(fs, "-01"), (opt, "2")],
                "requested-unreadable",
                w,
                None,
            ),
            row(
                "fortify-requested",
                &[(fs, "08"), (opt, "2")],
                "requested-unreadable",
                w,
                None,
            ),
            row(
                "fortify-effective",
                &[(fs, "2"), ("__USE_FORTIFY_LEVEL", "02"), (opt, "2")],
                "glibc-unreadable",
                w,
                None,
            ),
        ]
    }

    /// A number with a leading zero, which C reads as octal, in every other predicate that
    /// reads a macro as an integer, and in `c-int`: each withholds under its own clause.
    fn leading_zero_rows() -> Vec<Row> {
        let w = Outcome::Indeterminate;
        let bti = "__ARM_FEATURE_BTI_DEFAULT";
        let pac = "__ARM_FEATURE_PAC_DEFAULT";
        let mode = "_LIBCPP_HARDENING_MODE";
        let libcxx = ("_LIBCPP_VERSION", "220100");
        let cxx = "cxx-hardening-requested";
        vec![
            row("pic-macro", &[("__PIC__", "02")], "unreadable", w, None),
            row("cet-macro", &[("__CET__", "03")], "unrecognised", w, None),
            row(
                "gcs-macro",
                &[("__ARM_FEATURE_GCS_DEFAULT", "01")],
                "unreadable",
                w,
                None,
            ),
            row(
                "branch-protection-macro",
                &[(bti, "01"), (pac, "1")],
                "unreadable",
                w,
                None,
            ),
            row(
                "branch-protection-macro",
                &[(bti, "1"), (pac, "02")],
                "unreadable",
                w,
                None,
            ),
            row(
                "exceptions-macro",
                &[("__EXCEPTIONS", "01")],
                "unreadable",
                w,
                None,
            ),
            row(
                cxx,
                &[libcxx, (mode, "016")],
                "libcxx-unrecognised",
                w,
                None,
            ),
            row(
                cxx,
                &[libcxx, (mode, "(01 << 4)")],
                "libcxx-unrecognised",
                w,
                None,
            ),
            row(cxx, &[libcxx, (mode, "-0")], "libcxx-unrecognised", w, None),
            row(cxx, &[libcxx, (mode, "")], "libcxx-unrecognised", w, None),
        ]
    }

    /// The other predicates that read a macro as an integer, over a spelling the integer
    /// reading does not parse, beside the reading that stays: a `__CET__` of 0 is the mask saying
    /// neither.
    fn other_rows() -> Vec<Row> {
        let bti = "__ARM_FEATURE_BTI_DEFAULT";
        let pac = "__ARM_FEATURE_PAC_DEFAULT";
        let mode = "_LIBCPP_HARDENING_MODE";
        let libcxx = ("_LIBCPP_VERSION", "220100");
        let w = Outcome::Indeterminate;
        vec![
            row("pie-macro", &[("__PIE__", "(2)")], "unreadable", w, None),
            row("pie-macro", &[("__PIE__", "02")], "unreadable", w, None),
            row("pic-macro", &[("__PIC__", "2L")], "unreadable", w, None),
            row("cet-macro", &[("__CET__", "(3)")], "unrecognised", w, None),
            row("cet-macro", &[("__CET__", "4")], "unrecognised", w, None),
            row("cet-macro", &[("__CET__", "7")], "unrecognised", w, None),
            row("cet-macro", &[("__CET__", "-1")], "unrecognised", w, None),
            row(
                "cet-macro",
                &[("__CET__", "0")],
                "none",
                Outcome::Absent,
                None,
            ),
            row(
                "gcs-macro",
                &[("__ARM_FEATURE_GCS_DEFAULT", "(1)")],
                "unreadable",
                w,
                None,
            ),
            row(
                "branch-protection-macro",
                &[(bti, "(1)"), (pac, "1")],
                "unreadable",
                w,
                None,
            ),
            row(
                "branch-protection-macro",
                &[(bti, "1"), (pac, "1U")],
                "unreadable",
                w,
                None,
            ),
            row(
                "exceptions-macro",
                &[("__EXCEPTIONS", "1L")],
                "unreadable",
                w,
                None,
            ),
            row(
                "cxx-hardening-requested",
                &[libcxx, (mode, "(268435457 << 4)")],
                "libcxx-unrecognised",
                w,
                None,
            ),
            row(
                "cxx-hardening-requested",
                &[libcxx, (mode, "(3)")],
                "libcxx-unrecognised",
                w,
                None,
            ),
        ]
    }

    #[test]
    fn the_unreadable_spellings_withhold_under_a_named_clause() {
        let rows: Vec<Row> = fortify_rows()
            .into_iter()
            .chain(other_rows())
            .chain(leading_zero_rows())
            .collect();
        let mut fed = 0usize;
        let mut wrong = Vec::new();
        for (check, macros, clause, outcome, level) in &rows {
            fed += 1;
            let eval = live(predicate_of(check), macros);
            if (&eval.clause, eval.outcome, &eval.level) != (clause, *outcome, level) {
                wrong.push(format!(
                    "{}: over {macros:?} read {:?} at {:?} under {}, not {outcome:?} at \
                     {level:?} under {clause}",
                    check.id, eval.outcome, eval.level, eval.clause
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", first(&wrong));
        assert_eq!(fed, 58);
    }

    /// The clause each request decides under fortify-headers, written out per request rather
    /// than computed, so the test does not restate the predicate's comparison. `i64::MIN` is
    /// text C reads as above 2, and an absent request beside the mark is withheld, not read
    /// as `not-requested`.
    fn fortify_headers_expected(
        request: Option<&str>,
    ) -> (&'static str, Outcome, Option<&'static str>) {
        use chard::predicate::macro_channel::{
            FORTIFY_HEADERS_CLAUSE, FORTIFY_HEADERS_DYNAMIC_CLAUSE, FORTIFY_HEADERS_UNREAD_CLAUSE,
        };
        match request {
            Some("3" | "4") => (FORTIFY_HEADERS_DYNAMIC_CLAUSE, Outcome::Present, Some("1")),
            Some("1" | "2" | "0" | "-1") => (FORTIFY_HEADERS_CLAUSE, Outcome::Present, Some("1")),
            Some("(3)" | "3L" | "-9223372036854775808") | None => {
                (FORTIFY_HEADERS_UNREAD_CLAUSE, Outcome::Indeterminate, None)
            }
            Some(other) => panic!("no expectation written for {other}"),
        }
    }

    #[test]
    fn fortify_headers_clause_follows_the_request_under_either_mark() {
        use chard::predicate::macro_channel::{
            FORTIFY_HEADERS_CLAUSE, FORTIFY_HEADERS_CLAUSES, FORTIFY_HEADERS_DYNAMIC_CLAUSE,
            FORTIFY_HEADERS_UNREAD_CLAUSE,
        };
        let check = macro_checks()
            .into_iter()
            .find(|c| c.id == "fortify-effective")
            .expect("fortify-effective is a macro check");
        let expected = fortify_headers_expected;
        let mut fed = 0usize;
        let generated = [
            Some("1"),
            Some("2"),
            Some("3"),
            Some("4"),
            Some("0"),
            Some("-1"),
            Some("(3)"),
            Some("3L"),
            Some("-9223372036854775808"),
            None,
        ];
        for request in generated {
            for mark in [
                ("_FORTIFY_IMPL", "fortify-headers"),
                ("_FORTIFY_HEADERS_H", ""),
            ] {
                let macros = request
                    .map(|r| ("_FORTIFY_SOURCE", r))
                    .into_iter()
                    .chain([mark, ("__OPTIMIZE__", "1")])
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
                let eval = live(predicate_of(check), &macros);
                assert_eq!(
                    (eval.clause.as_str(), eval.outcome, eval.level.as_deref()),
                    expected(request),
                    "{mark:?} at {request:?}"
                );
                // A request is read, so `evidence.observed` names it beside the mark.
                assert!(
                    request.is_none()
                        || eval.reads.iter().any(|r| matches!(
                            &r.key,
                            ReadKey::Macro(n) if n.as_str() == "_FORTIFY_SOURCE"
                        )),
                    "{mark:?} at {request:?}: the request is read"
                );
                assert_eq!(
                    FORTIFY_HEADERS_CLAUSES.contains(&eval.clause.as_str()),
                    eval.outcome == Outcome::Present,
                    "a clause that reads the level is one the slot reads: {}",
                    eval.clause
                );
                fed += 1;
            }
        }
        // Without either mark no fortify-headers clause decides, whatever the request.
        for request in ["2", "3", "4"] {
            let macros = [("_FORTIFY_SOURCE", request), ("__OPTIMIZE__", "1")]
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            let eval = live(predicate_of(check), &macros);
            let ids = [
                FORTIFY_HEADERS_CLAUSE,
                FORTIFY_HEADERS_DYNAMIC_CLAUSE,
                FORTIFY_HEADERS_UNREAD_CLAUSE,
            ];
            assert!(
                !ids.contains(&eval.clause.as_str()),
                "no mark at {request}: {}",
                eval.clause
            );
            fed += 1;
        }
        assert_eq!(fed, 23);
    }
}

/// The elf-static channel: clause reach over a mutation space of the synthetic objects'
/// `ElfFacts`, the tables, the schema fields and the Published view.
mod elf_static {
    use std::path::Path;
    use std::sync::LazyLock;

    use chard::elf::{self, ElfFacts, ElfTable, SymbolFact, Truncation, TruncationKind};
    use chard::predicate::{Cond, ElfField, FactView as _, Incomplete, Live, Published, Term};
    use chard::probe::Evidence;
    use serde_json::Value;

    use super::*;
    use crate::predicate_rules::published_elf;

    /// The elf-static checks the corpus ships, in corpus order.
    fn elf_static_checks() -> Vec<&'static Check> {
        probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.channel() == Channel::ElfStatic)
            .collect()
    }

    fn live_evaluation(
        check: &Check,
        macros: &BTreeMap<String, String>,
        elf: Option<&ElfFacts>,
    ) -> predicate::Evaluation {
        let view = Live {
            macros: Some(macros),
            elf,
        };
        predicate::evaluate(predicate_of(check), &view)
            .unwrap_or_else(|Incomplete(key)| panic!("{}: a Live view lacked {key}", check.id))
    }

    /// The synthetic objects `tests/elf_builder` writes, read through the real reader, with
    /// their file names.
    fn synthetic_objects() -> Vec<(String, ElfFacts)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf");
        let mut out: Vec<(String, ElfFacts)> = std::fs::read_dir(&dir)
            .expect("tests/fixtures/elf is readable")
            .map(|entry| entry.expect("a directory entry").path())
            .filter(|path| path.extension().is_some_and(|e| e == "elf"))
            .map(|path| {
                let facts =
                    elf::facts_for(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (name, facts)
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            out.len(),
            common::ELF_FIXTURE_COUNT,
            "tests/fixtures/elf holds the catalogue's objects"
        );
        out
    }

    /// One case: a label, the macro map and the facts a check reads.
    struct Case {
        check: &'static Check,
        label: String,
        macros: BTreeMap<String, String>,
        elf: Option<ElfFacts>,
    }

    /// Every case: each synthetic object under every elf-static check, then each of
    /// [`written_bases`] under its own check.
    static CASES: LazyLock<Vec<Case>> = LazyLock::new(|| {
        let checks = elf_static_checks();
        let synthetic = synthetic_objects();
        let mut cases = Vec::new();
        for (name, facts) in &synthetic {
            for check in &checks {
                cases.push(Case {
                    check,
                    label: format!("tests/fixtures/elf/{name} under {}", check.id),
                    macros: BTreeMap::new(),
                    elf: Some(facts.clone()),
                });
            }
        }
        let written = written_bases(&object_in(&synthetic));
        for (id, label, facts) in &written {
            let check = checks
                .iter()
                .find(|c| c.id == *id)
                .unwrap_or_else(|| panic!("{id} is an elf-static check"));
            cases.push(Case {
                check,
                label: format!("written: {label} under {id}"),
                macros: BTreeMap::new(),
                elf: Some(facts.clone()),
            });
        }
        assert_eq!(
            cases.len(),
            synthetic.len() * checks.len() + written.len(),
            "every synthetic object was fed under every elf-static check"
        );
        cases
    });

    /// The relocatable object with functions, which the written bases and the tests that
    /// set `function_references` start from.
    const OBJECT_WITH_FUNCTIONS: &str = "elf64-le-x86_64-rel-functions.elf";

    fn object_in(objects: &[(String, ElfFacts)]) -> ElfFacts {
        objects
            .iter()
            .find(|(name, _)| name == OBJECT_WITH_FUNCTIONS)
            .map_or_else(
                || panic!("tests/fixtures/elf holds {OBJECT_WITH_FUNCTIONS}"),
                |(_, facts)| facts.clone(),
            )
    }

    fn object_with_functions() -> ElfFacts {
        object_in(&synthetic_objects())
    }

    /// `function_references` of `probes/optimization_applied.c`'s object at `-O0`: both calls.
    const UNOPTIMISED_CALLS: &[&str] = &[
        "chard_opt_probe:",
        "chard_opt_probe:chard_opt_anchor",
        "chard_opt_probe:chard_opt_dead",
    ];
    /// The same above `-O0`: the anchor alone.
    const OPTIMISED_CALLS: &[&str] = &["chard_opt_probe:", "chard_opt_probe:chard_opt_anchor"];

    /// Facts no synthetic object holds, each written on [`OBJECT_WITH_FUNCTIONS`] for the
    /// one check whose clause it reaches: a landing-pad table, a RETGUARD cookie section,
    /// printf's checking call with flag 1, and the optimization probe's calls at `-O0` and
    /// above it. The walk edits one other dimension at a time and leaves a check's own
    /// fields as the base has them, so each clause is reached from its base.
    fn written_bases(object: &ElfFacts) -> Vec<(&'static str, &'static str, ElfFacts)> {
        let with_section = |name: String| {
            let mut facts = object.clone();
            facts.sections.push(name);
            facts
        };
        let mut printf = object.clone();
        printf.code_scanned = vec!["chard_fortify_printf_probe:x86-mov-edi-1=1".to_owned()];
        printf.code_matches = vec!["chard_fortify_printf_probe:x86-mov-edi-1@0x8".to_owned()];
        printf.watched_symbols.insert(
            "__printf_chk".to_owned(),
            SymbolFact {
                defined: false,
                tables: vec![".symtab".to_owned()],
                versioned: Vec::new(),
            },
        );
        let with_calls = |calls: &[&str]| {
            let mut facts = object.clone();
            facts.function_references = Some(calls.iter().map(|s| (*s).to_owned()).collect());
            facts
        };
        vec![
            (
                "except-table-emitted",
                "a landing-pad table",
                with_section(predicate::elf_static::EXCEPT_TABLE_SECTION_PREFIX.to_owned()),
            ),
            (
                "ret-protector-emitted",
                "a RETGUARD cookie section",
                with_section(format!(
                    "{}chard_ret_probe",
                    predicate::elf_static::RETGUARD_SECTION_PREFIX
                )),
            ),
            ("fortify-printf-flag", "flag 1 beside __printf_chk", printf),
            (
                "optimization-applied",
                "both calls",
                with_calls(UNOPTIMISED_CALLS),
            ),
            (
                "optimization-applied",
                "the anchor alone",
                with_calls(OPTIMISED_CALLS),
            ),
        ]
    }

    // --- the mutation space ------------------------------------------------------------

    /// The macro maps `cxx-stdlib` is read over: each rung of the ladder alone, the named
    /// value in each spelling that matters, and a map whose `_CXX_STDLIB` overrides a
    /// `_LIBCPP_VERSION`.
    const STDLIB_MAPS: &[&[(&str, &str)]] = &[
        &[],
        &[("_CXX_STDLIB", "libc++")],
        &[("_CXX_STDLIB", "libstdc++")],
        &[("_CXX_STDLIB", "")],
        &[("_LIBCPP_VERSION", "220108")],
        &[("__GLIBCXX__", "20260515")],
        &[("_LIBCPP_VERSION", "220108"), ("_CXX_STDLIB", "libstdc++")],
    ];

    /// The items a list field is mutated to hold one of: a soname the `as-needed` prefix
    /// matches, one it does not, a name that is the prefix's library without its dot, a path,
    /// and the empty string, which is a non-empty list's one item, and two section
    /// names: 32-bit ARM's `.rel.ARM.extab`, which `except-table-emitted` reads as a landing-pad
    /// table, and the `.ARM.extab` it relocates, which unwind tables write without one. The walk
    /// reaches the clause with them; [`an_unwind_table_alone_is_no_landing_pad_table`] holds
    /// `.ARM.extab` alone to `absent`, which a prefix widened to `.ARM.extab` fails.
    const LIST_ITEMS: &[&str] = &[
        "libm.so.6",
        "libc.so.6",
        "libm",
        "/opt/lib",
        "",
        ".rel.ARM.extab",
        ".ARM.extab",
    ];

    /// The `no-plt` probe's call, relocated through the GOT and as a PLT call.
    const CALLEE_GOT: &str = "R_X86_64_GOTPCRELX chard_no_plt_callee";
    const CALLEE_PLT: &str = "R_AARCH64_CALL26 chard_no_plt_callee";
    /// The `function_references` lists the field is mutated to: one function missing, each
    /// of the four rows that are levels, a row that is none (a canary on the function only
    /// `-all` admits, alone), the guard and OpenBSD's handler as targets, gcc's `.cold`
    /// part carrying the reference, and a function whose name has a probe function's as a
    /// prefix, which the roll-call does not take for the probe's own. Each row read as a
    /// level also holds the four calls the probe functions make (`SSP_CALLEES`); the
    /// second row, every function present and none referring to anything, is what a
    /// relocation section the reader skipped left behind, and with the next, one call
    /// missing, reaches `unread-calls`. The last three carry unattributed references
    /// (`?:target`, `elf::UNATTRIBUTED_REFERENCE`): the shape clang's
    /// `-fbasic-block-sections=all` left, every function present with its call and the
    /// canary outside them, which reaches `unattributed-canary` rather than `none`; a
    /// `strong` row with the guard unattributed, which reaches it too, since the reference
    /// could be `ssp_any`'s; and the same row with only a call unattributed, which is no
    /// canary and reads `strong`.
    const FUNCTION_ROWS: &[&[&str]] = &[
        &["ssp_any:", "ssp_addr_taken:", "ssp_char_array:"],
        &[
            "ssp_any:",
            "ssp_addr_taken:",
            "ssp_char_array:",
            "ssp_alloca:",
        ],
        &[
            "ssp_any:",
            "ssp_addr_taken:",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_any:ssp_use",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:ssp_escape",
        ],
        &[
            "ssp_any:",
            "ssp_addr_taken:",
            "ssp_char_array:",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_any:ssp_use",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:ssp_escape",
        ],
        &[
            "ssp_any:",
            "ssp_addr_taken:",
            "ssp_addr_taken:__stack_chk_fail_local",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail_local",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail_local",
            "ssp_any:ssp_use",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:ssp_escape",
        ],
        &[
            "ssp_any:",
            "ssp_any:__stack_chk_guard",
            "ssp_addr_taken:",
            "ssp_addr_taken:__stack_chk_guard",
            "ssp_char_array:",
            "ssp_char_array:__stack_smash_handler",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_any:ssp_use",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:ssp_escape",
        ],
        &[
            "ssp_any:",
            "ssp_any:__stack_chk_fail",
            "ssp_addr_taken:",
            "ssp_char_array:",
            "ssp_alloca:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:ssp_escape",
        ],
        &[
            "ssp_any:",
            "ssp_addr_taken:",
            "ssp_char_array:",
            "ssp_alloca:",
            "ssp_alloca.cold:",
            "ssp_alloca.cold:__stack_chk_fail",
            "ssp_any:ssp_use",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:ssp_escape",
        ],
        &[
            "ssp_any_x:",
            "ssp_addr_taken:",
            "ssp_char_array:",
            "ssp_alloca:",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:ssp_escape",
            "?:__stack_chk_fail",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "?:__stack_chk_guard",
            "?:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "?:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__safestack_unsafe_stack_ptr",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__safestack_unsafe_stack_ptr",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__safestack_unsafe_stack_ptr",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__safestack_unsafe_stack_ptr",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__safestack_unsafe_stack_ptr",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__safestack_unsafe_stack_ptr",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:__safestack_unsafe_stack_ptr",
            "ssp_safe_array:__stack_chk_fail",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__safestack_unsafe_stack_ptr",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__safestack_unsafe_stack_ptr",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__safestack_unsafe_stack_ptr",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:__stack_chk_fail",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:__stack_chk_fail",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:__stack_chk_fail",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:__stack_chk_fail",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__safestack_unsafe_stack_ptr",
            "ssp_addr_taken:__stack_chk_fail",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__safestack_unsafe_stack_ptr",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__safestack_unsafe_stack_ptr",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:__stack_chk_fail",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__safestack_unsafe_stack_ptr",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__safestack_unsafe_stack_ptr",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__safestack_unsafe_stack_ptr",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:__safestack_unsafe_stack_ptr",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__safestack_unsafe_stack_ptr",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__safestack_unsafe_stack_ptr",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:__stack_chk_fail",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:__stack_chk_fail",
            "ssp_safe_array:ssp_use",
        ],
        &[
            "ssp_any:",
            "ssp_any:ssp_use",
            "ssp_addr_taken:",
            "ssp_addr_taken:ssp_escape",
            "ssp_char_array:",
            "ssp_char_array:ssp_escape",
            "ssp_alloca:",
            "ssp_alloca:__stack_chk_fail",
            "ssp_alloca:ssp_escape",
            "ssp_safe_array:",
            "ssp_safe_array:ssp_use",
        ],
    ];

    /// The `function_references` lists of `probes/optimization_applied.c`'s object beyond
    /// [`UNOPTIMISED_CALLS`] and [`OPTIMISED_CALLS`]: the function present with neither call, which is what a
    /// relocation section the reader skipped left behind and reaches `unread-call`; the
    /// unconditional call read and the dead one outside every function's range, the shape
    /// clang 22.1.8 left at `-O0 -fbasic-block-sections=all` (measured on Fedora 44 x86_64,
    /// 2026-11-09), which reaches `unattributed-call` rather than `@otherwise`; and a
    /// function whose name has the probe function's as a prefix holding both calls, which
    /// the roll-call does not take for the probe's own; and the unconditional call in the
    /// probe function with the dead one in a part split from it (gcc's `.cold` naming),
    /// which reaches `call-elsewhere` rather than `@otherwise`; the dead call both in the
    /// function and outside every range, which withholds under `unattributed-call` before
    /// `dead-call-kept` reads it; and the dead call outside every range with no call read in
    /// the function, which `unread-call` withholds first.
    const OPTIMIZATION_ROWS: &[&[&str]] = &[
        &["chard_opt_probe:"],
        &[
            "chard_opt_probe:",
            "chard_opt_probe:chard_opt_anchor",
            "?:chard_opt_dead",
        ],
        &[
            "chard_opt_probe_x:",
            "chard_opt_probe_x:chard_opt_anchor",
            "chard_opt_probe_x:chard_opt_dead",
        ],
        &[
            "chard_opt_probe:",
            "chard_opt_probe:chard_opt_anchor",
            "chard_opt_probe.cold:",
            "chard_opt_probe.cold:chard_opt_dead",
        ],
        &[
            "chard_opt_probe:",
            "chard_opt_probe:chard_opt_anchor",
            "chard_opt_probe:chard_opt_dead",
            "?:chard_opt_dead",
        ],
        &["chard_opt_probe:", "?:chard_opt_dead"],
    ];

    #[test]
    fn an_unwind_table_alone_is_no_landing_pad_table() {
        let check = elf_static_checks()
            .into_iter()
            .find(|c| c.id == "except-table-emitted")
            .expect("the corpus ships except-table-emitted");
        let base = object_with_functions();
        let rows: [(&[&str], &str, probe::Outcome); 3] = [
            (
                &[".text", ".ARM.extab"],
                "@otherwise",
                probe::Outcome::Absent,
            ),
            (
                &[".text", ".ARM.extab", ".rel.ARM.extab"],
                "ehabi-except-table",
                probe::Outcome::Present,
            ),
            (
                &[".text.f", ".ARM.extab.text.f", ".rel.ARM.extab.text.f"],
                "ehabi-except-table",
                probe::Outcome::Present,
            ),
        ];
        for (sections, clause, outcome) in rows {
            let mut facts = base.clone();
            facts.sections = sections.iter().map(|s| (*s).to_owned()).collect();
            let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
            assert_eq!(
                (got.clause.as_str(), got.outcome),
                (clause, outcome),
                "sections {sections:?}"
            );
        }
    }

    #[test]
    fn optimization_rows_read_their_clause_and_only_that() {
        let check = elf_static_checks()
            .into_iter()
            .find(|c| c.id == "optimization-applied")
            .expect("the corpus ships optimization-applied");
        let base = object_with_functions();
        let indeterminate = probe::Outcome::Indeterminate;
        let expected = [
            ("unread-call", indeterminate),
            ("unattributed-call", indeterminate),
            ("roll-call", indeterminate),
            ("call-elsewhere", indeterminate),
            ("unattributed-call", indeterminate),
            ("unread-call", indeterminate),
            ("dead-call-kept", probe::Outcome::Absent),
            ("@otherwise", probe::Outcome::Present),
        ];
        let rows: Vec<&[&str]> = OPTIMIZATION_ROWS
            .iter()
            .copied()
            .chain([UNOPTIMISED_CALLS, OPTIMISED_CALLS])
            .collect();
        assert_eq!(rows.len(), expected.len(), "one expectation per row");
        for (row, (clause, outcome)) in rows.iter().zip(expected) {
            let mut facts = base.clone();
            facts.function_references = Some(row.iter().map(|s| (*s).to_owned()).collect());
            let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
            assert_eq!(
                (got.clause.as_str(), got.outcome),
                (clause, outcome),
                "row {row:?}"
            );
        }
        let mut facts = base;
        facts.function_references = None;
        let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
        assert_eq!(
            (got.clause.as_str(), got.outcome),
            ("not-an-object", indeterminate)
        );
    }

    /// How many rows at the end of [`FUNCTION_ROWS`] hold `basic` to the marker and the
    /// fifth function, and before them how many are the `SafeStack`-era rows.
    const BASIC_ROWS: usize = 4;
    const SAFESTACK_ROWS: usize = 7;

    /// The `watched_symbols` names read through `symbol-names`: the two `__gnu_debug` entry
    /// points on the watch list.
    fn error_formatter_names() -> Vec<&'static str> {
        elf::WATCHED_SYMBOLS
            .iter()
            .copied()
            .filter(|n| n.contains("_Error_formatter"))
            .collect()
    }

    /// One edit to a fixture's facts or macros.
    #[derive(Debug, Clone)]
    enum Mutation {
        Bool(ElfField, bool),
        NullableBool(ElfField, Option<bool>),
        NullableText(ElfField, Option<&'static str>),
        Text(ElfField, &'static str),
        Int(ElfField, i64),
        List(ElfField, Vec<&'static str>),
        /// A list field that is `None` where the reader found no referent.
        NullableList(ElfField, Option<Vec<&'static str>>),
        /// A watched symbol absent (`None`) or present with its `defined`.
        Symbol(&'static str, Option<bool>),
        /// The truncation list: empty, or one entry on a table.
        Truncation(Option<(ElfTable, TruncationKind)>),
        /// The macro map, one of [`STDLIB_MAPS`].
        Macros(usize),
        /// One macro an elf-static predicate reads, absent or defined as `1`
        /// ([`ELF_STATIC_MACROS`]).
        Macro(&'static str, Option<&'static str>),
    }

    fn bool_slot(facts: &mut ElfFacts, field: ElfField) -> &mut bool {
        match field {
            ElfField::HasInterp => &mut facts.has_interp,
            ElfField::HasDynamic => &mut facts.has_dynamic,
            ElfField::Df1Pie => &mut facts.df_1_pie,
            ElfField::Df1Noopen => &mut facts.df_1_noopen,
            ElfField::Textrel => &mut facts.textrel,
            ElfField::DtRelr => &mut facts.dt_relr,
            ElfField::DtDebug => &mut facts.dt_debug,
            ElfField::DtSoname => &mut facts.dt_soname,
            ElfField::X86Ibt => &mut facts.x86_ibt,
            ElfField::X86Shstk => &mut facts.x86_shstk,
            ElfField::Aarch64Bti => &mut facts.aarch64_bti,
            ElfField::Aarch64Pac => &mut facts.aarch64_pac,
            ElfField::Aarch64Gcs => &mut facts.aarch64_gcs,
            other => panic!("{other:?} is not a bool field"),
        }
    }

    fn nullable_bool_slot(facts: &mut ElfFacts, field: ElfField) -> &mut Option<bool> {
        match field {
            ElfField::Pie => &mut facts.pie,
            ElfField::StaticPie => &mut facts.static_pie,
            ElfField::SharedObject => &mut facts.shared_object,
            ElfField::StaticallyLinked => &mut facts.statically_linked,
            ElfField::GnuRelro => &mut facts.gnu_relro,
            ElfField::BindNow => &mut facts.bind_now,
            ElfField::GnuStackPresent => &mut facts.gnu_stack_present,
            ElfField::GnuStackExecutable => &mut facts.gnu_stack_executable,
            ElfField::RwxSegment => &mut facts.rwx_segment,
            other => panic!("{other:?} is not a nullable bool field"),
        }
    }

    fn list_slot(facts: &mut ElfFacts, field: ElfField) -> &mut Vec<String> {
        match field {
            ElfField::DynamicTags => &mut facts.dynamic_tags,
            ElfField::Needed => &mut facts.needed,
            ElfField::Rpath => &mut facts.rpath,
            ElfField::Runpath => &mut facts.runpath,
            ElfField::GnuPropertyTypes => &mut facts.gnu_property_types,
            ElfField::Sections => &mut facts.sections,
            ElfField::CodeScanned => &mut facts.code_scanned,
            ElfField::CodeMatches => &mut facts.code_matches,
            ElfField::FunctionEntries => &mut facts.function_entries,
            other => panic!("{other:?} is not a list field"),
        }
    }

    fn apply(m: &Mutation, facts: &mut ElfFacts, macros: &mut BTreeMap<String, String>) {
        match m {
            Mutation::Bool(field, v) => *bool_slot(facts, *field) = *v,
            Mutation::NullableBool(field, v) => *nullable_bool_slot(facts, *field) = *v,
            Mutation::NullableText(field, v) => match field {
                ElfField::Relro => facts.relro = v.map(ToOwned::to_owned),
                other => panic!("{other:?} is not a nullable text field"),
            },
            Mutation::Text(field, v) => match field {
                ElfField::ElfType => (*v).clone_into(&mut facts.elf_type),
                ElfField::Machine => (*v).clone_into(&mut facts.machine),
                ElfField::RecordedCommandLine => (*v).clone_into(&mut facts.recorded_command_line),
                other => panic!("{other:?} is not a text field"),
            },
            Mutation::Int(field, v) => match field {
                ElfField::ElfClass => facts.elf_class = u8::try_from(*v).expect("a class fits u8"),
                ElfField::SymbolCount => {
                    facts.symbol_count = usize::try_from(*v).expect("a count fits usize");
                }
                other => panic!("{other:?} is not an integer field"),
            },
            Mutation::List(field, items) => {
                *list_slot(facts, *field) = items.iter().map(|s| (*s).to_owned()).collect();
            }
            Mutation::NullableList(field, items) => match field {
                ElfField::DataInCodePages => {
                    facts.data_in_code_pages = items
                        .as_ref()
                        .map(|items| items.iter().map(|s| (*s).to_owned()).collect());
                }
                ElfField::CodeRelocations => {
                    facts.code_relocations = items
                        .as_ref()
                        .map(|items| items.iter().map(|s| (*s).to_owned()).collect());
                }
                ElfField::FunctionReferences => {
                    facts.function_references = items
                        .as_ref()
                        .map(|items| items.iter().map(|s| (*s).to_owned()).collect());
                }
                other => panic!("{other:?} is not a nullable list field"),
            },
            Mutation::Symbol(name, state) => match state {
                None => {
                    facts.watched_symbols.remove(*name);
                }
                Some(defined) => {
                    facts.watched_symbols.insert(
                        (*name).to_owned(),
                        SymbolFact {
                            defined: *defined,
                            tables: vec![".symtab".to_owned()],
                            versioned: Vec::new(),
                        },
                    );
                }
            },
            Mutation::Truncation(entry) => {
                facts.truncations = entry
                    .iter()
                    .map(|(table, kind)| Truncation {
                        table: *table,
                        kind: *kind,
                        detail: format!("mutated: {} cut", table.as_str()),
                    })
                    .collect();
            }
            Mutation::Macros(i) => {
                *macros = STDLIB_MAPS[*i]
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect();
            }
            Mutation::Macro(name, value) => match value {
                Some(value) => {
                    macros.insert((*name).to_owned(), (*value).to_owned());
                }
                None => {
                    macros.remove(*name);
                }
            },
        }
    }

    /// A dimension of the space: a name and the edits along it.
    struct Dimension {
        name: String,
        values: Vec<Mutation>,
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match over field shapes, each list field's vocabulary beside the others; \
                  split, a field's values would be read in two places"
    )]
    fn field_dimension(field: ElfField) -> Dimension {
        let values = match field.shape() {
            predicate::FieldShape::Bool => {
                vec![Mutation::Bool(field, false), Mutation::Bool(field, true)]
            }
            predicate::FieldShape::NullableBool => vec![
                Mutation::NullableBool(field, None),
                Mutation::NullableBool(field, Some(false)),
                Mutation::NullableBool(field, Some(true)),
            ],
            // `relro`, whose domain is the reader's three words and `None`.
            predicate::FieldShape::NullableText => [
                None,
                Some(elf::RELRO_NONE),
                Some(elf::RELRO_PARTIAL),
                Some(elf::RELRO_FULL),
            ]
            .into_iter()
            .map(|v| Mutation::NullableText(field, v))
            .collect(),
            predicate::FieldShape::Text => match field {
                ElfField::ElfType => &["ET_DYN", "ET_EXEC", "ET_REL"][..],
                // `i386` is the machine `cet-endbr-emitted` reads endbr32 on.
                ElfField::Machine => &["x86_64", "aarch64", "i386"][..],
                _ => &["", "-O2 -fstack-protector-strong"][..],
            }
            .iter()
            .map(|v| Mutation::Text(field, v))
            .collect(),
            // The code reader's lists carry their own vocabulary, so a spelling a predicate
            // reads is in the space: one trap, clang's signed-overflow trap alone and beside a
            // trap with another check number, one call, a trap beside a call, one fortify
            // flag, and both flags at once.
            predicate::FieldShape::List => match field {
                ElfField::CodeScanned => vec![
                    vec![],
                    vec![
                        "chard_ubsan_trap_probe:x86-ud2=1",
                        "chard_ubsan_trap_probe:x86-ud1=0",
                    ],
                    // The first two of `ubsan-trap-mode`'s functions searched, from
                    // 2026-10-07: the list above, with the first alone, is an object from
                    // before the second, and this one an object from before the third and
                    // fourth (2026-10-07, later), which the list below has.
                    vec![
                        "chard_ubsan_trap_probe:x86-ud2=1",
                        "chard_ubsan_trap_probe:x86-ud1=0",
                        "chard_ubsan_trap_groups:x86-ud2=0",
                        "chard_ubsan_trap_groups:x86-ud1=0",
                    ],
                    vec![
                        "chard_ubsan_trap_probe:x86-ud2=1",
                        "chard_ubsan_trap_probe:x86-ud1=0",
                        "chard_ubsan_trap_groups:x86-ud2=0",
                        "chard_ubsan_trap_groups:x86-ud1=0",
                        "chard_ubsan_trap_sized:x86-ud2=0",
                        "chard_ubsan_trap_sized:x86-ud1=0",
                        "chard_ubsan_trap_indirect:x86-ud1=0",
                    ],
                    vec!["chard_fortify_printf_probe:x86-mov-edi-1=1"],
                ],
                ElfField::CodeMatches => vec![
                    vec![],
                    vec!["chard_ubsan_trap_probe:x86-ud2@0x2"],
                    vec!["chard_ubsan_trap_probe.cold:x86-ud2@0x0"],
                    vec!["chard_ubsan_trap_probe:x86-ud1@0x2"],
                    vec![
                        "chard_ubsan_trap_probe:x86-ud1@0x2",
                        "chard_ubsan_trap_probe:x86-ud1-check@0x2",
                    ],
                    vec![
                        "chard_ubsan_trap_probe:a64-brk@0x4",
                        "chard_ubsan_trap_probe:a64-brk-check@0x4",
                    ],
                    vec!["chard_ubsan_trap_probe:x86-call-rel32@0x4"],
                    vec![
                        "chard_ubsan_trap_probe:x86-ud2@0x2",
                        "chard_ubsan_trap_probe:x86-call-rel32@0x4",
                    ],
                    vec!["chard_fortify_printf_probe:x86-mov-edi-2@0x8"],
                    vec![
                        "chard_fortify_printf_probe:x86-mov-edi-1@0x8",
                        "chard_fortify_printf_probe:x86-mov-edi-2@0x10",
                    ],
                ],
                // `function_entries` carries its own vocabulary, so the spellings its predicate
                // reads are in the space: every function a landing pad of either width, none,
                // one function missing, and a landing pad at some functions only.
                ElfField::FunctionEntries => {
                    let entries = |pads: [&str; 3]| -> Vec<&'static str> {
                        elf::entry::ENTRY_FUNCTIONS
                            .iter()
                            .zip(pads)
                            .map(|(f, b)| &*format!("{f}={b}").leak())
                            .collect()
                    };
                    let endbr64 = predicate::elf_static::ENDBR64;
                    let endbr32 = predicate::elf_static::ENDBR32;
                    let mut two = entries([endbr64, endbr64, endbr64]);
                    two.pop();
                    vec![
                        vec![],
                        entries([endbr64, endbr64, endbr64]),
                        entries([endbr32, endbr32, endbr32]),
                        entries(["8d4701c3", "8d4702c3", "8d4703c3"]),
                        entries([endbr64, "8d4702c3", endbr64]),
                        two,
                    ]
                }
                _ => std::iter::once(Vec::new())
                    .chain(LIST_ITEMS.iter().map(|item| vec![*item]))
                    .collect(),
            }
            .into_iter()
            .map(|items| Mutation::List(field, items))
            .collect(),
            // `code_relocations` is read by symbol and type, which no generic item names, so
            // its values are the probe callee's two forms, both together, a type the reader
            // leaves unnamed, a named type on neither list, and a GOT type against another
            // symbol.
            predicate::FieldShape::NullableList if field == ElfField::CodeRelocations => [
                None,
                Some(Vec::new()),
                Some(vec![CALLEE_GOT]),
                Some(vec![CALLEE_PLT]),
                Some(vec![CALLEE_GOT, CALLEE_PLT]),
                Some(vec!["reloc-type-0x63 chard_no_plt_callee"]),
                Some(vec!["R_X86_64_GOT64 chard_no_plt_callee"]),
                Some(vec!["R_X86_64_GOTPCRELX chard_no_plt_caller"]),
                Some(vec!["R_X86_64_REX_GOTPCRELX chard_pic_object_anchor"]),
                Some(vec!["R_X86_64_PC32 chard_pic_object_anchor"]),
                Some(vec!["R_X86_64_PC32 chard_pic_object_anchor STV_HIDDEN"]),
                Some(vec![
                    "R_X86_64_PC32 chard_pic_object_anchor",
                    "R_X86_64_REX_GOTPCRELX chard_pic_object_anchor",
                ]),
                Some(vec!["R_X86_64_32 chard_pic_object_anchor"]),
                Some(vec!["R_X86_64_PC32 chard_pic_object_probe"]),
            ]
            .into_iter()
            .map(|items| Mutation::NullableList(field, items))
            .collect(),
            predicate::FieldShape::NullableList => std::iter::once(None)
                .chain(std::iter::once(Some(Vec::new())))
                .chain(match field {
                    ElfField::FunctionReferences => FUNCTION_ROWS
                        .iter()
                        .chain(OPTIMIZATION_ROWS)
                        .map(|row| Some(row.to_vec()))
                        .collect::<Vec<_>>(),
                    _ => LIST_ITEMS.iter().map(|item| Some(vec![*item])).collect(),
                })
                .map(|items| Mutation::NullableList(field, items))
                .collect(),
            predicate::FieldShape::Int => match field {
                ElfField::ElfClass => vec![Mutation::Int(field, 32), Mutation::Int(field, 64)],
                _ => vec![Mutation::Int(field, 0), Mutation::Int(field, 4096)],
            },
        };
        Dimension {
            name: format!("elf {}", field.as_str()),
            values,
        }
    }

    fn symbol_dimension(name: &'static str) -> Dimension {
        Dimension {
            name: format!("symbol {name}"),
            values: vec![
                Mutation::Symbol(name, None),
                Mutation::Symbol(name, Some(false)),
                Mutation::Symbol(name, Some(true)),
            ],
        }
    }

    fn truncation_dimension(tables: &[ElfTable]) -> Dimension {
        let mut values = vec![Mutation::Truncation(None)];
        values.extend(
            ElfTable::ALL
                .iter()
                .map(|t| Mutation::Truncation(Some((*t, TruncationKind::Unread)))),
        );
        values.extend(
            tables
                .iter()
                .map(|t| Mutation::Truncation(Some((*t, TruncationKind::Ignored)))),
        );
        Dimension {
            name: "truncations".to_owned(),
            values,
        }
    }

    fn cond_terms(cond: &Cond, out: &mut Vec<Term>) {
        match cond {
            Cond::All(members) | Cond::Any(members) | Cond::NoneOf(members) => {
                for member in members {
                    cond_terms(member, out);
                }
            }
            Cond::Defined(t)
            | Cond::Missing(t)
            | Cond::Truth(t)
            | Cond::Eq(t, _)
            | Cond::Int(t, _, _)
            | Cond::AnyStartsWith(t, _)
            | Cond::AnyContains(t, _)
            | Cond::NonEmpty(t) => out.push(t.clone()),
        }
    }

    fn conclusion_terms(conclusion: &Conclusion, out: &mut Vec<Term>) {
        if let Conclusion::Present(LevelOf::Value(t)) = conclusion {
            out.push(t.clone());
        }
    }

    /// Every term a predicate contains, deduplicated in first-seen order.
    fn terms_of(p: &Predicate) -> Vec<Term> {
        let mut out = Vec::new();
        for clause in &p.clauses {
            cond_terms(&clause.when, &mut out);
            conclusion_terms(&clause.then, &mut out);
        }
        conclusion_terms(&p.otherwise, &mut out);
        let mut seen = Vec::new();
        for term in out {
            if !seen.contains(&term) {
                seen.push(term);
            }
        }
        seen
    }

    fn macros_dimension() -> Dimension {
        Dimension {
            name: "macros".to_owned(),
            values: (0..STDLIB_MAPS.len()).map(Mutation::Macros).collect(),
        }
    }

    /// The dimensions a term spans.
    fn term_dimensions(term: &Term) -> Vec<Dimension> {
        match term {
            Term::Elf(field) => vec![field_dimension(*field)],
            Term::Symbol(name) => {
                let name = elf::WATCHED_SYMBOLS
                    .iter()
                    .copied()
                    .find(|n| n == name)
                    .unwrap_or_else(|| panic!("{name} is on the watch list"));
                vec![symbol_dimension(name)]
            }
            // The two `__gnu_debug` names `cxx-assertions-symbol` reads, and one
            // sanitizer handler, which `ubsan-trap-mode` reads through the same list.
            Term::SymbolNames => error_formatter_names()
                .into_iter()
                .chain(std::iter::once("__ubsan_handle_shift_out_of_bounds"))
                .map(symbol_dimension)
                .collect(),
            Term::CxxStdlib => vec![macros_dimension()],
            Term::Macro(name) => vec![macro_dimension(name)],
            Term::CInt(_) => {
                panic!("an elf-static predicate reads {term:?}, which this space does not span")
            }
        }
    }

    /// The macros an elf-static predicate may read beside the artifact, each spanned absent
    /// and defined: `fortify-printf-flag`'s `freebsd-unoptimized` clause
    /// reads the platform macro and the optimization macro to withhold a wrapper
    /// FreeBSD's clang references without optimization. A name outside the list is one the
    /// space does not span, and the walk says so rather than passing the clause unreached.
    /// A predicate reading one of these beside `cxx-stdlib`, whose dimension replaces the
    /// whole map, would need the two applied in a fixed order; none does.
    const ELF_STATIC_MACROS: &[&str] = &["__FreeBSD__", "__OPTIMIZE__"];

    fn macro_dimension(name: &str) -> Dimension {
        let name = ELF_STATIC_MACROS
            .iter()
            .copied()
            .find(|n| *n == name)
            .unwrap_or_else(|| {
                panic!(
                    "an elf-static predicate reads the macro {name}, which this space does not span"
                )
            });
        Dimension {
            name: format!("macros.{name}"),
            values: vec![
                Mutation::Macro(name, None),
                Mutation::Macro(name, Some("1")),
            ],
        }
    }

    /// The dimensions a check's own predicate reads, spanned as a product.
    fn own_dimensions(p: &Predicate) -> Vec<Dimension> {
        let mut dims: Vec<Dimension> = terms_of(p).iter().flat_map(term_dimensions).collect();
        if !p.tables.is_empty() {
            dims.push(truncation_dimension(&p.tables));
        }
        dims
    }

    /// Every field of `ElfFacts` a predicate may read, every watched symbol, and the macro
    /// maps; each is walked one value at a time over a case, outside the check's own product.
    /// The list is the whole domain rather than the union of what the predicates read, so a
    /// field a detector decides on and its predicate omits still moves under the walk.
    fn every_dimension() -> Vec<Dimension> {
        let mut out: Vec<Dimension> = ElfField::ALL.into_iter().map(field_dimension).collect();
        out.extend(elf::WATCHED_SYMBOLS.iter().copied().map(symbol_dimension));
        out.push(macros_dimension());
        out
    }

    /// What walking the space found: the clauses reached per check, and the evaluations made
    /// against the number the dimensions' sizes predict.
    struct Space {
        reached: BTreeMap<&'static str, BTreeSet<String>>,
        evaluations: usize,
        expected: usize,
    }

    fn applied(
        base: &ElfFacts,
        base_macros: &BTreeMap<String, String>,
        mutations: &[Mutation],
    ) -> (ElfFacts, BTreeMap<String, String>) {
        let mut facts = base.clone();
        let mut macros = base_macros.clone();
        for m in mutations {
            apply(m, &mut facts, &mut macros);
        }
        (facts, macros)
    }

    /// Evaluate one point of the space through the check's decoder, recording its clause.
    fn record(space: &mut Space, case: &Case, base: &ElfFacts, mutations: &[Mutation]) {
        let (facts, macros) = applied(base, &case.macros, mutations);
        let eval = live_evaluation(case.check, &macros, Some(&facts));
        let decoded = case.check.decode(&Evidence {
            macros: &macros,
            elf: Some(&facts),
            build: None,
            run: None,
            workdir: None,
        });
        assert_eq!(
            decoded.proof.as_ref(),
            Some(&eval),
            "{}: Check::decode evaluates the check's own predicate over the Live view",
            case.label
        );
        space.evaluations += 1;
        space
            .reached
            .entry(case.check.id)
            .or_default()
            .insert(eval.clause);
    }

    /// One case's share of the space: the product of its check's own dimensions, walked as
    /// an odometer, then every other dimension one value at a time.
    fn walk_case(space: &mut Space, case: &Case, base: &ElfFacts, all: &[Dimension]) {
        let p = predicate_of(case.check);
        let own = own_dimensions(p);
        let own_names: BTreeSet<&str> = own.iter().map(|d| d.name.as_str()).collect();
        let others: Vec<&Dimension> = all
            .iter()
            .filter(|d| !own_names.contains(d.name.as_str()))
            .collect();
        space.expected += own.iter().map(|d| d.values.len()).product::<usize>()
            + others.iter().map(|d| d.values.len()).sum::<usize>();
        // The product of the check's own dimensions, walked as an odometer.
        let mut index = vec![0usize; own.len()];
        loop {
            let mutations: Vec<Mutation> = own
                .iter()
                .zip(&index)
                .map(|(d, i)| d.values[*i].clone())
                .collect();
            record(space, case, base, &mutations);
            let mut carry = true;
            for (slot, dim) in index.iter_mut().zip(&own) {
                if !carry {
                    break;
                }
                *slot += 1;
                if *slot == dim.values.len() {
                    *slot = 0;
                } else {
                    carry = false;
                }
            }
            if carry {
                break;
            }
        }
        // Every other dimension, one value at a time.
        for dim in others {
            for value in &dim.values {
                record(space, case, base, std::slice::from_ref(value));
            }
        }
    }

    /// The whole space, its cases shared out over every thread the host offers and the
    /// shares merged: each case is walked whole by one thread, so the points evaluated, the
    /// clauses reached and the counts are the ones a single thread finds. One thread took
    /// three and a half minutes of the merge gate for 8.7 million evaluations.
    fn walk_space() -> Space {
        let all = every_dimension();
        let cases: Vec<(&Case, &ElfFacts)> = CASES
            .iter()
            .filter_map(|case| case.elf.as_ref().map(|base| (case, base)))
            .collect();
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        // Cases differ in size by orders of magnitude (a check's own dimensions multiply), so
        // a thread takes the next case not yet taken rather than a fixed share of them.
        let next = std::sync::atomic::AtomicUsize::new(0);
        let shares: Vec<Space> = std::thread::scope(|s| {
            let workers: Vec<_> = (0..threads.min(cases.len()).max(1))
                .map(|_| {
                    let (all, cases, next) = (&all, &cases, &next);
                    s.spawn(move || {
                        let mut space = Space {
                            reached: BTreeMap::new(),
                            evaluations: 0,
                            expected: 0,
                        };
                        while let Some((case, base)) =
                            cases.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                        {
                            walk_case(&mut space, case, base, all);
                        }
                        space
                    })
                })
                .collect();
            workers
                .into_iter()
                // A worker that panicked is a point whose decode disagreed with its
                // evaluation: the test fails with that assertion, as on one thread.
                .map(|w| w.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
                .collect()
        });
        let mut space = Space {
            reached: BTreeMap::new(),
            evaluations: 0,
            expected: 0,
        };
        for share in shares {
            space.evaluations += share.evaluations;
            space.expected += share.expected;
            for (id, clauses) in share.reached {
                space.reached.entry(id).or_default().extend(clauses);
            }
        }
        space
    }

    static SPACE: LazyLock<Space> = LazyLock::new(walk_space);

    #[test]
    fn the_mutation_space_is_walked_whole() {
        let space = &*SPACE;
        announce!(
            "chard: elf-static mutation space: {} evaluations over {} cases",
            space.evaluations,
            CASES.len()
        );
        assert!(space.evaluations > 0, "the mutation space was empty");
        assert_eq!(
            space.evaluations, space.expected,
            "every point of the space was evaluated"
        );
    }

    #[test]
    fn every_clause_is_reached() {
        let space = &*SPACE;
        let mut dead = Vec::new();
        for (id, p) in predicate::elf_static::table() {
            let p = p();
            let reached = space.reached.get(id).cloned().unwrap_or_default();
            let expected = p.clauses.iter().map(|c| c.id.clone()).chain([
                predicate::OTHERWISE.to_owned(),
                predicate::TRUNCATED.to_owned(),
            ]);
            for clause in expected {
                if !reached.contains(&clause) {
                    dead.push(format!("{id}: {clause}"));
                }
            }
        }
        assert!(
            dead.is_empty(),
            "clauses no case reached:\n{}",
            dead.join("\n")
        );
    }

    // --- tables, fields and the Published view -------------------------------------------

    /// The tables a field's value is read from, as `Elf::facts` derives it.
    fn field_tables(field: ElfField) -> &'static [ElfTable] {
        match field {
            ElfField::ElfClass | ElfField::ElfType | ElfField::Machine => &[ElfTable::Header],
            // `HasInterp` and `GnuRelro` are a program header apiece; a load or TLS
            // segment's flags (`RwxSegment`) are, among the program headers, the same
            // single table.
            ElfField::HasInterp | ElfField::GnuRelro | ElfField::RwxSegment => {
                &[ElfTable::ProgramHeaders]
            }
            // The stack header, among the program headers; a disagreeing pair is recorded
            // against `gnu-stack` (`elf::Elf::gnu_stack`).
            ElfField::GnuStackPresent | ElfField::GnuStackExecutable => {
                &[ElfTable::ProgramHeaders, ElfTable::GnuStack]
            }
            // `PT_DYNAMIC` or the `.dynamic` section; `relro` is `PT_GNU_RELRO` and `BIND_NOW`.
            ElfField::HasDynamic | ElfField::Relro => {
                &[ElfTable::ProgramHeaders, ElfTable::Dynamic]
            }
            // The link classification: `e_type`, `PT_INTERP`, and `DF_1_PIE` or `DT_DEBUG`.
            ElfField::Pie
            | ElfField::StaticPie
            | ElfField::SharedObject
            | ElfField::StaticallyLinked => &[
                ElfTable::Header,
                ElfTable::ProgramHeaders,
                ElfTable::Dynamic,
            ],
            ElfField::BindNow
            | ElfField::Df1Pie
            | ElfField::Df1Noopen
            | ElfField::Textrel
            | ElfField::DtRelr
            | ElfField::DtDebug
            | ElfField::DtSoname
            | ElfField::DynamicTags => &[ElfTable::Dynamic],
            ElfField::Needed | ElfField::Rpath | ElfField::Runpath => {
                &[ElfTable::Dynamic, ElfTable::DynStr]
            }
            ElfField::GnuPropertyTypes
            | ElfField::X86Ibt
            | ElfField::X86Shstk
            | ElfField::Aarch64Bti
            | ElfField::Aarch64Pac
            | ElfField::Aarch64Gcs => &[ElfTable::Notes],
            ElfField::Sections => &[ElfTable::SectionHeaders, ElfTable::SectionNames],
            // The executable `PT_LOAD`s' pages against each allocated section's bytes, the
            // sections named through the name table.
            ElfField::DataInCodePages => &[
                ElfTable::ProgramHeaders,
                ElfTable::SectionHeaders,
                ElfTable::SectionNames,
            ],
            // `e_type`, the relocation sections and their targets' flags, and the symbol
            // names the entries resolve through.
            ElfField::CodeRelocations => &[
                ElfTable::Header,
                ElfTable::SectionHeaders,
                ElfTable::Symbols,
                ElfTable::Relocations,
            ],
            // The function symbols and the relocation sections, found through the
            // section-header table and placed by section index, never by name.
            ElfField::FunctionReferences => &[
                ElfTable::SectionHeaders,
                ElfTable::Symbols,
                ElfTable::Relocations,
            ],
            ElfField::SymbolCount => &[ElfTable::Symbols],
            ElfField::RecordedCommandLine => &[ElfTable::SectionNames],
            // A function found through `.symtab`, its bytes through its section header.
            ElfField::CodeScanned | ElfField::CodeMatches => {
                &[ElfTable::SectionHeaders, ElfTable::Symbols, ElfTable::Code]
            }
            ElfField::FunctionEntries => &[
                ElfTable::SectionHeaders,
                ElfTable::Symbols,
                ElfTable::FunctionEntries,
            ],
        }
    }

    fn term_tables(term: &Term) -> &'static [ElfTable] {
        match term {
            Term::Elf(field) => field_tables(*field),
            Term::Symbol(_) | Term::SymbolNames => &[ElfTable::Symbols],
            // The macro source; an elf-static check's macros come from the build, not a table
            // its `reads` declares.
            Term::Macro(_) | Term::CInt(_) | Term::CxxStdlib => &[],
        }
    }

    #[test]
    fn every_predicate_names_the_tables_its_terms_read() {
        let mut fed = 0usize;
        for check in elf_static_checks() {
            fed += 1;
            let p = predicate_of(check);
            let tables: BTreeSet<ElfTable> = p.tables.iter().copied().collect();
            assert_eq!(tables.len(), p.tables.len(), "{}: a table twice", check.id);
            assert!(
                std::ptr::eq(check.reads(), p.tables.as_slice()),
                "{}: the check's tables are its predicate's",
                check.id
            );
            for term in terms_of(p) {
                for table in term_tables(&term) {
                    assert!(
                        tables.contains(table),
                        "{}: {term:?} reads {table:?}, which the predicate's tables omit",
                        check.id
                    );
                }
            }
        }
        assert!(fed > 0 && fed == predicate::elf_static::table().len());
    }

    #[test]
    fn checks_that_read_one_observable_share_a_predicate() {
        const SHARED: [(&str, &str); 3] = [
            ("canary-emitted", "ssp-covers-small-arrays"),
            ("cet-marked", "cet-marked-object"),
            ("linker-default-noexecstack", "noexecstack"),
        ];
        let named: BTreeSet<(&str, &str)> = SHARED.iter().copied().collect();
        let checks = elf_static_checks();
        let mut found = BTreeSet::new();
        for (i, a) in checks.iter().enumerate() {
            for b in &checks[i + 1..] {
                if std::ptr::eq(predicate_of(a), predicate_of(b)) {
                    found.insert(if a.id < b.id {
                        (a.id, b.id)
                    } else {
                        (b.id, a.id)
                    });
                }
            }
        }
        assert_eq!(
            found, named,
            "the elf-static checks that share a predicate are the pairs this test names"
        );
    }

    #[test]
    fn the_as_needed_prefix_is_the_probes_library() {
        let probe = probe::find("link-unused-library").expect("the as-needed probe ships");
        let [lib] = probe.link_libs else {
            panic!("the probe links {:?}", probe.link_libs);
        };
        let prefix = format!("lib{}.", lib.trim_start_matches("-l"));
        let p = predicate::for_check("as-needed").expect("a predicate");
        let starts: Vec<&str> = p
            .clauses
            .iter()
            .filter_map(|c| match &c.when {
                Cond::AnyStartsWith(Term::Elf(ElfField::Needed), s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(starts, [prefix.as_str()]);
    }

    #[test]
    fn as_needed_withholds_where_the_list_has_no_entry_and_reads_it_otherwise() {
        let objects: BTreeMap<String, ElfFacts> = synthetic_objects().into_iter().collect();
        let of = |name: &str| {
            objects
                .get(name)
                .unwrap_or_else(|| panic!("{name} is in the catalogue"))
        };
        let read = as_needed_reading;
        let withheld = |clause: &str| (clause.to_owned(), probe::Outcome::Indeterminate);

        let static_exec = of("elf64-le-x86_64-exec-static.elf");
        assert!(!static_exec.has_dynamic && static_exec.statically_linked == Some(true));
        assert_eq!(read(static_exec), withheld("no-dynamic"));
        let rel = of("elf64-le-x86_64-rel.elf");
        assert!(!rel.has_dynamic && rel.statically_linked.is_none());
        assert_eq!(read(rel), withheld("unclassified"));
        let mut forged_core = of("elf64-le-x86_64-pie-no-interp-needed.elf").clone();
        forged_core.elf_type = "ET_CORE".to_owned();
        assert!(forged_core.has_dynamic && !forged_core.needed.is_empty());
        assert_eq!(read(&forged_core), withheld("unclassified"));
        let mut exec_no_entry = of("elf64-le-x86_64-exec-relro-lazy.elf").clone();
        exec_no_entry.needed.clear();
        assert!(exec_no_entry.elf_type == "ET_EXEC" && exec_no_entry.pie == Some(false));
        assert_eq!(read(&exec_no_entry), withheld("no-c-library"));
        for (name, shared, clause) in [
            (
                "elf64-le-x86_64-static-pie-unmarked.elf",
                Some(true),
                "shared-output",
            ),
            (
                "elf64-le-x86_64-static-pie-interp.elf",
                Some(false),
                "no-c-library",
            ),
        ] {
            let pie = of(name);
            assert!(
                pie.has_dynamic
                    && pie.needed.is_empty()
                    && pie.statically_linked == Some(false)
                    && pie.shared_object == shared,
                "{name}"
            );
            assert_eq!(read(pie), withheld(clause), "{name}");
            let mut libz = pie.clone();
            libz.needed = vec!["libz.so.1".to_owned()];
            assert_eq!(
                read(&libz),
                withheld(clause),
                "{name} naming libz.so.1 alone"
            );
        }
        let libz = of("elf64-le-x86_64-static-pie-interp-libz.elf");
        assert!(libz.has_interp && libz.needed == ["libz.so.1"]);
        assert_eq!(read(libz), withheld("no-c-library"));
        for name in [
            "elf64-le-x86_64-static-pie-relr.elf",
            "elf64-le-x86_64-static-pie-dt-debug.elf",
        ] {
            let pie = of(name);
            assert!(
                pie.static_pie == Some(true) && pie.needed == ["libc.so.6"],
                "{name}"
            );
            assert_eq!(read(pie), withheld("no-loader-output"), "{name}");
        }
        let mut forged_static = static_exec.clone();
        forged_static.needed.push("libm.so.6".to_owned());
        assert_eq!(read(&forged_static), withheld("no-dynamic"));
        let mut interp_alone = of("elf64-le-x86_64-exec-relro-lazy.elf").clone();
        interp_alone.has_dynamic = false;
        interp_alone.needed.clear();
        assert_eq!(interp_alone.statically_linked, Some(false));
        assert_eq!(read(&interp_alone), withheld("no-dynamic"));
    }

    /// The deciding clause and outcome `as-needed` reads from `facts`.
    fn as_needed_reading(facts: &ElfFacts) -> (String, probe::Outcome) {
        let check = elf_static_checks()
            .into_iter()
            .find(|c| c.id == "as-needed")
            .expect("as-needed ships");
        let macros = BTreeMap::new();
        let decoded = check.decode(&Evidence {
            macros: &macros,
            elf: Some(facts),
            build: None,
            run: None,
            workdir: None,
        });
        let proof = decoded
            .proof
            .expect("an elf-static check decodes through its predicate");
        (proof.clause, decoded.detection.outcome)
    }

    #[test]
    fn as_needed_reads_the_list_of_every_link_that_records_a_library() {
        let objects: BTreeMap<String, ElfFacts> = synthetic_objects().into_iter().collect();
        let of = |name: &str| {
            objects
                .get(name)
                .unwrap_or_else(|| panic!("{name} is in the catalogue"))
        };
        let read = as_needed_reading;

        let dynamic = of("elf64-le-x86_64-exec-relro-lazy.elf");
        assert!(dynamic.statically_linked == Some(false) && dynamic.has_dynamic);
        assert_eq!(dynamic.needed, ["libc.so.6"]);
        assert_eq!(
            read(dynamic),
            (predicate::OTHERWISE.to_owned(), probe::Outcome::Present)
        );
        let mut recorded = dynamic.clone();
        recorded.needed.push("libm.so.6".to_owned());
        assert_eq!(
            read(&recorded),
            ("recorded".to_owned(), probe::Outcome::Absent)
        );
        let no_interp = of("elf64-le-x86_64-pie-no-interp-needed.elf");
        assert!(
            !no_interp.has_interp
                && no_interp.statically_linked == Some(true)
                && no_interp.needed == ["libc.so.6", "libm.so.6"]
        );
        assert_eq!(
            read(no_interp),
            ("recorded".to_owned(), probe::Outcome::Absent)
        );
        let mut no_interp_dropped = no_interp.clone();
        no_interp_dropped.needed.retain(|n| n != "libm.so.6");
        assert_eq!(
            read(&no_interp_dropped),
            ("no-loader-output".to_owned(), probe::Outcome::Indeterminate),
            "output with no dynamic loader may have taken the unused library from its archive"
        );
        let mut no_pie_twin = of("elf64-le-x86_64-exec-static.elf").clone();
        no_pie_twin.has_dynamic = true;
        no_pie_twin.needed = vec!["libc.so.6".to_owned()];
        assert!(no_pie_twin.elf_type == "ET_EXEC" && no_pie_twin.statically_linked == Some(true));
        assert_eq!(
            read(&no_pie_twin),
            ("no-loader-output".to_owned(), probe::Outcome::Indeterminate),
            "an ET_EXEC with no interpreter is linked with no dynamic loader too"
        );
    }

    fn schema_elf_properties() -> BTreeSet<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/chard-report.schema.json");
        let schema: Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("the schema is readable"))
                .expect("the schema is JSON");
        schema["$defs"]["elf_facts"]["properties"]
            .as_object()
            .expect("$defs/elf_facts has properties")
            .keys()
            .cloned()
            .collect()
    }

    /// Every synthetic object's facts, deduplicated by serialization.
    fn every_facts() -> Vec<(String, ElfFacts)> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for case in CASES.iter() {
            if let Some(facts) = &case.elf {
                let key = serde_json::to_string(facts).expect("facts serialize");
                if seen.insert(key) {
                    out.push((case.label.clone(), facts.clone()));
                }
            }
        }
        out
    }

    #[test]
    fn every_elf_field_is_a_schema_field() {
        let properties = schema_elf_properties();
        for field in ElfField::ALL {
            assert!(
                properties.contains(field.as_str()),
                "{} is not in $defs/elf_facts",
                field.as_str()
            );
        }
        let facts = every_facts();
        assert!(
            !facts.is_empty(),
            "the facts are not empty, so the loop below checks something"
        );
        for (label, facts) in &facts {
            let value = published_elf(facts);
            let live = Live {
                macros: None,
                elf: Some(facts),
            };
            let published =
                Published::new(None, None, Some(&value), None).expect("an object is a source");
            for field in ElfField::ALL {
                assert_eq!(
                    live.elf_field(field),
                    published.elf_field(field),
                    "{label}: {}",
                    field.as_str()
                );
            }
        }
    }

    #[test]
    fn safestack_rows_read_unsafe_frame_and_only_that() {
        let check = elf_static_checks()
            .into_iter()
            .find(|c| c.id == "ssp-level-emitted")
            .expect("the corpus ships ssp-level-emitted");
        let base = object_with_functions();
        let safestack_end = FUNCTION_ROWS.len() - BASIC_ROWS;
        let rows = &FUNCTION_ROWS[safestack_end - SAFESTACK_ROWS..safestack_end];
        let expected = [
            (
                "unsafe-frame",
                probe::Outcome::Present,
                Some("unsafe-frame"),
            ),
            (
                "unsafe-frame",
                probe::Outcome::Present,
                Some("unsafe-frame"),
            ),
            ("@otherwise", probe::Outcome::Indeterminate, None),
            ("@otherwise", probe::Outcome::Indeterminate, None),
            ("all", probe::Outcome::Present, Some("all")),
            ("@otherwise", probe::Outcome::Indeterminate, None),
            ("none", probe::Outcome::Absent, None),
        ];
        assert_eq!(expected.len(), SAFESTACK_ROWS, "one expectation per row");
        let mut read = 0usize;
        for (row, (clause, outcome, level)) in rows.iter().zip(expected) {
            let mut facts = base.clone();
            facts.function_references = Some(row.iter().map(|s| (*s).to_owned()).collect());
            let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
            assert_eq!(
                (got.clause.as_str(), got.outcome, got.level.as_deref()),
                (clause, outcome, level),
                "row {row:?}"
            );
            read += 1;
        }
        assert_eq!(read, SAFESTACK_ROWS, "every SafeStack row was read");
        // And the five-function `strong` row, the array canaried and no marker: `strong`.
        let mut facts = base;
        facts.function_references = Some(
            rows[3]
                .iter()
                .map(|s| (*s).to_owned())
                .chain(std::iter::once(
                    "ssp_safe_array:__stack_chk_fail".to_owned(),
                ))
                .collect(),
        );
        let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
        assert_eq!(
            (got.clause.as_str(), got.outcome, got.level.as_deref()),
            ("strong", probe::Outcome::Present, Some("strong"))
        );
    }

    #[test]
    fn basic_excludes_the_marker_and_pairs_the_arrays() {
        let check = elf_static_checks()
            .into_iter()
            .find(|c| c.id == "ssp-level-emitted")
            .expect("the corpus ships ssp-level-emitted");
        let base = object_with_functions();
        let rows = &FUNCTION_ROWS[FUNCTION_ROWS.len() - BASIC_ROWS..];
        let expected = [
            ("@otherwise", probe::Outcome::Indeterminate, None),
            ("@otherwise", probe::Outcome::Indeterminate, None),
            ("basic", probe::Outcome::Present, Some("basic")),
            ("basic", probe::Outcome::Present, Some("basic")),
        ];
        let mut read = 0usize;
        for (row, (clause, outcome, level)) in rows.iter().zip(expected) {
            let mut facts = base.clone();
            facts.function_references = Some(row.iter().map(|s| (*s).to_owned()).collect());
            let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
            assert_eq!(
                (got.clause.as_str(), got.outcome, got.level.as_deref()),
                (clause, outcome, level),
                "row {row:?}"
            );
            read += 1;
        }
        assert_eq!(read, BASIC_ROWS, "every basic row was read");
        // The first row is refused twice over, and each gate holds alone: with the in-range
        // array canaried beside `ssp_char_array` the pair is whole and the marker still
        // refuses it; with the marker's references removed as well, the row is plain
        // `-fstack-protector`'s own and reads `basic`.
        let paired: Vec<String> = rows[0]
            .iter()
            .map(|s| (*s).to_owned())
            .chain(std::iter::once(
                "ssp_safe_array:__stack_chk_fail".to_owned(),
            ))
            .collect();
        let mut facts = base.clone();
        facts.function_references = Some(paired.clone());
        let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
        assert_eq!(
            (got.clause.as_str(), got.outcome, got.level.as_deref()),
            ("@otherwise", probe::Outcome::Indeterminate, None)
        );
        let mut facts = base;
        facts.function_references = Some(
            paired
                .into_iter()
                .filter(|s| !s.ends_with(predicate::elf_static::SAFESTACK_MARKER))
                .collect(),
        );
        let got = live_evaluation(check, &BTreeMap::new(), Some(&facts));
        assert_eq!(
            (got.clause.as_str(), got.outcome, got.level.as_deref()),
            ("basic", probe::Outcome::Present, Some("basic"))
        );
    }

    #[test]
    fn the_published_view_concludes_what_the_live_view_concluded() {
        let watch_list: Vec<String> = elf::WATCHED_SYMBOLS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let mut fed = 0usize;
        let mut omitted = 0usize;
        for case in CASES.iter() {
            let p = predicate_of(case.check);
            let live = live_evaluation(case.check, &case.macros, case.elf.as_ref());
            let macros = serde_json::to_value(&case.macros).expect("macros serialize");
            let elf_value = case.elf.as_ref().map(published_elf);
            let view = Published::new(Some(&macros), None, elf_value.as_ref(), Some(&watch_list))
                .expect("objects are sources");
            let published = predicate::evaluate(p, &view)
                .unwrap_or_else(|Incomplete(key)| panic!("{}: Published lacked {key}", case.label));
            assert_eq!(published, live, "{}", case.label);
            fed += 1;

            if let Some(facts) = case.elf.as_ref().filter(|f| f.truncations.is_empty()) {
                let bare = serde_json::to_value(facts).expect("facts serialize");
                let view = Published::new(Some(&macros), None, Some(&bare), Some(&watch_list))
                    .expect("objects are sources");
                assert_eq!(
                    predicate::evaluate(p, &view).map(|e| e.clause),
                    Err(Incomplete("elf.truncations".to_owned())),
                    "{}",
                    case.label
                );
                omitted += 1;
            }
        }
        assert_eq!(fed, CASES.len());
        assert!(omitted > 0);
    }
}
