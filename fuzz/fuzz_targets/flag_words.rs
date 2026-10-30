// SPDX-License-Identifier: BSD-3-Clause
//! The readers of a profile's flag words over arbitrary word lists: the four `measure` refuses a
//! profile by (`compile::response_file_arguments`, `toolchain::runtime_removing_flags`,
//! `toolchain::driver_divided_pairs`, `compile::relative_path_arguments`, in the order
//! `refuse_unreadable_flags` asks them; the fifth it asks, `toolchain::unsupported_target_flags`,
//! is not read here: it finds `cc1`'s `-triple` and its value across clang's `-Xclang` list, two
//! words that need not be adjacent, so the laws below do not describe it) and the three whose
//! words the control arms carry
//! (`toolchain::target_selecting_flags`, `toolchain::runtime_selecting_flags` and
//! `toolchain::header_selecting_flags`, with `toolchain::selects_target`), and the two that
//! carry the profile's own words into the arms'
//! `-###` compile listing (`compile_inputs::macro_words` and `compile_inputs::optimization_words`,
//! with `compile_inputs::macro_name` asked of every word). The flags are the operator's own
//! (THREAT_MODEL.md, "The operator chose the toolchain"), so a failure here is a defect in chard's
//! reader and not an attack; but a reader that drops a refused word lets a profile through that the
//! refusal was written for, and one that invents a word hands the arms a flag the profile never
//! had.
//!
//! The input is the word list: the bytes decoded as UTF-8 lossily and split at every line
//! feed, so a word holds any character but a line feed, as an argv word holds any byte but
//! NUL. None of the readers treats a line feed specially, so a word holding one is read by
//! the same rules as any other, and leaving such words out loses no rule a reader applies.
//!
//! Held for every input, without a model of which spellings are which:
//!
//! - each reader returns, without a panic, and returns the same list twice;
//! - every word a reader returns is a word of the input, in the input's order: the four
//!   that return words return a subsequence of the input, and `relative_path_arguments`,
//!   which joins the words of one argument with a space, returns items that align, in order
//!   and without overlap, with up to four adjacent input words (an option and its separate
//!   argument, or the two pairs that hand a tool an option and its path, `-Xlinker -L
//!   -Xlinker <dir>`);
//! - a refused word is refused whatever surrounds it. `response_file_arguments` reads each word
//!   alone, so it is the input filtered by its verdict on each word alone, and that verdict is the
//!   word or nothing. `runtime_removing_flags` returns only refusals it makes alone: a word it
//!   refuses alone, or a word handing the next one on (`-Xpreprocessor`, `-Xarch_<arch>`) and that
//!   next word, which it refuses as that pair alone and not the first word alone (`-Xpreprocessor
//!   -nostdinc`). Over `A`, `-O2`, `B` returns what it returns over `A` and then
//!   over `B` (a word handed to another tool by the last word of `A` is `-O2`, which removes
//!   nothing). `relative_path_arguments` returns each item from that item's words alone, and over
//!   `A`, `/`, `B` returns what it returns over `A`, `/` and then over `B`, where over `A`, `/`
//!   it returns what it returns over `A` (an option left without its argument at the end of `A`
//!   takes `/`, which is absolute), or that without its last item where the item is the words
//!   before `A`'s last: a path option handed to a tool with no path after it, refused as
//!   unpaired, which `/` completes where `A`'s last word hands it to the tool (`-Xlinker -L
//!   -Xlinker`). `driver_divided_pairs` returns
//!   each pair from that pair's words alone, and over `A`, `-O2`, `B` returns what it returns
//!   over `A` and then over `B` (a longer option at the end of `A` is followed by `-O2`, which
//!   no reader takes, so the pair is no divided one);
//! - a refused word takes nothing from what follows it. At every position where
//!   `runtime_removing_flags` refuses the word alone or the word and its successor alone as
//!   a pair, or `relative_path_arguments` or `driver_divided_pairs` refuses the first words
//!   from there alone as one item (the most words, up to four, it so refuses: a path option
//!   handed to a tool is refused alone, as unpaired, and with its path handed after it, as
//!   one item; where the two words after an unpaired refusal hand it an absolute path, the
//!   reading from there leaves it out, as the reading of its words and those two does, and
//!   is that reading and then the reading from after them), the reading from that
//!   position is that refusal and then the reading from after its words. With the split law
//!   this is the converse of the first refusal law: a word refused alone and missing from a
//!   reading is missing only for its predecessor, since putting the neutral word in the
//!   predecessor's place reads the list from that word, which begins with its refusal. The
//!   split law alone cannot see a refusal that swallows its successor, because the
//!   successor it swallows there is the separator, which reads as nothing either way;
//! - a selected word is selected whatever follows it, and nothing it did not select is.
//!   `target_selecting_flags`, `runtime_selecting_flags` and `header_selecting_flags` over
//!   `A`, `-O2`, `-O2`, `B` return what they return over `A`, `-O2` and then over `B`, and
//!   over `A`, `-O2`, what they return over `A` and at most `A`'s last word with `-O2` as its
//!   value (a two-token spelling left without one at the end of `A`), or, for the target
//!   reader alone, `A`'s last three words `-Xpreprocessor -isysroot -Xpreprocessor` with
//!   `-O2` as the root they take through the preprocessor (`toolchain::LONGEST_SELECTION`
//!   words, the one selection longer than two). Each selects its own selection
//!   whole, and `selects_target` reads a target from a selection exactly when it reads one
//!   from the input, and only where the selection is not empty. `macro_words` and
//!   `optimization_words` are held to the same laws, with `/` as the neutral word for both
//!   (`optimization_words` carries `-O2`, and `macro_words` hands its last `-D` the word after
//!   it, as a two-token spelling takes its value);
//! - no two of the readers whose words the arms carry (`target_selecting_flags`,
//!   `runtime_selecting_flags`, `header_selecting_flags` and `linker_program_flags`) or
//!   whose words the arms' stand-in listing carries (`macro_words`, `optimization_words`)
//!   read one word of the input: at every position where one of them takes the first words
//!   from there whole (up to four, the longest selection, `-Xpreprocessor -isysroot
//!   -Xpreprocessor <dir>`), every other reads the list from there as it reads it from after
//!   those words, so a word one takes as the value of its two-token option (`-L -B/x`,
//!   `-L -DX`, `-isystem -D X`, `-B -O2`) is no other's option; and over the whole list,
//!   what the six return together is the input with words left out, counted by spelling.
//!   The six are projections of the one classifier (`toolchain::read`), which gives each
//!   word one reader whatever gcc's spelling of it (`--li -DX` is a directory named `-DX`,
//!   `--def X` a macro operation, `--machine 32` the target `-m32` as the pair);
//! - a word the driver takes the next one as the value of, selecting nothing
//!   (`toolchain::takes_a_value`: `-u`, `-MF`, `-o`, `-D`, `-z` and the rest of its tables,
//!   and gcc's long spellings of them, `--forc`, `--def`), takes it from every reader: at
//!   every position where that holds of the word, the six carried readers, `selects_target`,
//!   `runtime_removing_flags` and `driver_divided_pairs` read the list from there as they
//!   read it from after the pair (from after the word alone where it ends the list), so a
//!   selection spelled as the value (`-u -B/x`, the symbol named `-B/x`) is none of those
//!   readers' and neither refusal's; the one exception is the macro reader's own two-token
//!   spelling, `-D` or `-U` in any of gcc's spellings, which `macro_words` carries as the
//!   pair and which this law recognises by that carrying alone (the pair read on its own
//!   comes back whole). The classifier is the crate's, as `LONGEST_SELECTION` is, so this
//!   law holds the readers to the walk's class and not the class to the drivers (the unit
//!   tests do that): without it such a word reads exactly as `-Xlinker` reads (the
//!   paragraph after the laws), and the seed `value-taking-words` spells the pairs;
//! - `optimization_words` carries alone, and carries only, a word beginning `-O` or gcc's
//!   long `--optimize`: spelled whole or abbreviated to a prefix of at least `--op`, alone, or
//!   spelled whole with `=N` (`toolchain::LONG_ALIASES`), which is what gcc 16.1.1 took: every
//!   prefix of `--optimize` from `--op`, and `--optimize=` with or without a level; it
//!   refused `--o`, an abbreviation with `=N` and `--optimizex` (measured 2026-10-28 on
//!   Fedora 44 x86_64 under `-###`), and a word it refuses fails the measured build before
//!   any reading (`--profile explicit --flags "-O2 --o"` read `canary-emitted`
//!   `build-failed`), and is carried as no level; and `macro_words` carries any `-D` or `-U`
//!   word with an operand joined;
//! - `macro_name` names a macro exactly for a word beginning `-D` or `-U` with a name after
//!   it, and the name is that word's text up to its first `=` or `(`.
//!
//! The separator laws are checked at every split of a list of up to 16 words, and at 17
//! splits of a longer one (both ends and 15 between), and the target counts the splits it
//! checked against that number. The head law is asked at every position of the list, and the
//! target counts the positions it asked against the number of words.
//!
//! What no law here can see without a model of the spellings is a word that refuses nothing
//! and wrongly takes its successor: it reads exactly as `-Xlinker` reads, and only the unit
//! tests, whose spellings are the seeds, say which words are which.
//!
//! Which spellings each reader takes, and why, is what the unit tests beside each function
//! hold; the seeds under `seeds/flag_words/` are their spellings.

#![no_main]

use chard::compile::{
    PathReading, relative_path_arguments, relative_path_readings, response_file_arguments,
};
use chard::compile_inputs::{is_macro_option, macro_name, macro_words, optimization_words};
use chard::toolchain::{
    LONGEST_SELECTION, driver_divided_pairs, header_selecting_flags, linker_program_flags,
    runtime_removing_flags, runtime_selecting_flags, selects_target, takes_a_value,
    target_selecting_flags,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// A word none of the readers takes or refuses, and none consumes as an option of its own.
const NEUTRAL: &str = "-O2";
/// An absolute path: `relative_path_arguments` lets an option take it and refuses nothing,
/// and the compile listing's two readers carry nothing of it.
const ABSOLUTE: &str = "/";
/// Every split is checked up to this many words.
const EVERY_SPLIT_UP_TO: usize = 16;
/// The splits checked of a longer list: both ends and this many minus two between.
const SPLITS_OF_A_LONG_LIST: usize = 17;
/// The most input words one item of a pair reader comes from: `relative_path_arguments`'
/// path option handed to a tool and its path handed after it, two pairs
/// (`-Xlinker -L -Xlinker <dir>`).
const LONGEST_ITEM: usize = 4;

/// Whether `relative_path_readings` reads the last relative path of `words` as a path option
/// handed to a tool with no path after it, the one reading another word can complete.
fn ends_unpaired(words: &[String]) -> bool {
    relative_path_readings(words)
        .last()
        .is_some_and(|found| found.reading == PathReading::Unpaired)
}

type Reader = fn(&[String]) -> Vec<String>;

/// The readers whose words the control arms carry, by name: the three selections and the
/// linker's program flags, which `measure::arm_flags` concatenates, and the two whose words
/// the arms' stand-in compile listing carries beside them.
const CARRIED: [(&str, Reader); 6] = [
    ("target_selecting_flags", target_selecting_flags),
    ("runtime_selecting_flags", runtime_selecting_flags),
    ("header_selecting_flags", header_selecting_flags),
    ("linker_program_flags", linker_program_flags),
    ("macro_words", macro_words),
    ("optimization_words", optimization_words),
];
/// The one selection longer than two words, `toolchain::LONGEST_SELECTION` words of the
/// target reader's: a system root through the preprocessor.
const ROOT_THROUGH_PREPROCESSOR: [&str; 3] = ["-Xpreprocessor", "-isysroot", "-Xpreprocessor"];

fn owned(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

fn joined(parts: &[&[String]]) -> Vec<String> {
    parts.iter().flat_map(|p| p.iter().cloned()).collect()
}

/// Whether `found` is `input` with words left out, the rest in order.
fn is_subsequence(found: &[String], input: &[String]) -> bool {
    let mut rest = input.iter();
    found.iter().all(|f| rest.any(|w| w == f))
}

/// The input words each item of a pair reader (`relative_path_arguments`,
/// `driver_divided_pairs`) came from, aligned in order and without overlap: up to
/// [`LONGEST_ITEM`] adjacent words that, joined by a space, equal the item, and from which
/// the reader returns the item alone. `None` where some item aligns with none. The earliest
/// alignment is taken, and at one position the fewest words, which finds one wherever one
/// exists, since words joined by a space equal an item at one count of them only where a
/// word holds a space, and then only one count is refused alone.
///
/// Both conditions, not the text alone: the word `--sysroot sr` and the pair `--sysroot`,
/// `sr` spell the same item, and only the pair is refused, since `--sysroot` joins its
/// argument only after `=`.
fn align_items<'a>(
    read: Reader,
    items: &[String],
    input: &'a [String],
) -> Option<Vec<&'a [String]>> {
    let mut at = 0usize;
    let mut aligned = Vec::new();
    for item in items {
        let found = (at..input.len()).find_map(|j| {
            (1..=LONGEST_ITEM.min(input.len() - j)).find_map(|k| {
                let words = &input[j..j + k];
                (words.join(" ") == *item && read(words) == [item.clone()]).then_some((j, j + k))
            })
        })?;
        aligned.push(&input[found.0..found.1]);
        at = found.1;
    }
    Some(aligned)
}

/// Whether the words `runtime_removing_flags` returned align, in order and without overlap,
/// with refusals it makes alone: one word it refuses alone, or two adjacent words it refuses
/// as that pair alone and whose first it does not refuse alone.
fn align_removals(found: &[String], input: &[String]) -> bool {
    let mut at = 0usize;
    let mut k = 0usize;
    while k < found.len() {
        let next = (at..input.len()).find_map(|j| {
            if input[j] != found[k] {
                return None;
            }
            if removal_at(&input[j..]).is_some_and(|(r, _)| r == found[k..k + 1]) {
                Some((j + 1, 1))
            } else if removal_at(&input[j..])
                .is_some_and(|(r, span)| span == 2 && found.get(k..k + 2) == Some(&r[..]))
            {
                Some((j + 2, 2))
            } else {
                None
            }
        });
        let Some((end, taken)) = next else {
            return false;
        };
        at = end;
        k += taken;
    }
    true
}

/// The split points of `n` words the separator laws are checked at.
fn splits(n: usize) -> Vec<usize> {
    if n <= EVERY_SPLIT_UP_TO {
        (0..=n).collect()
    } else {
        let between = SPLITS_OF_A_LONG_LIST - 1;
        (0..=between).map(|i| i * n / between).collect()
    }
}

fn expected_splits(n: usize) -> usize {
    if n <= EVERY_SPLIT_UP_TO {
        n + 1
    } else {
        SPLITS_OF_A_LONG_LIST
    }
}

/// A selector's law at one split: over `A`, `N`, `N`, `B` it returns its reading of `A`,
/// `N` and then of `B`, and its reading of `A`, `N` is its reading of `A` and at most `A`'s
/// last words, fewer than [`LONGEST_SELECTION`], with `N` as their value, where `N` is a
/// word it neither takes nor consumes (`neutral`).
fn selector_splits(name: &str, read: Reader, neutral: &str, a: &[String], b: &[String]) {
    let sep = owned(&[neutral]);
    let a_sep = joined(&[a, &sep]);
    let of_a = read(a);
    let of_a_sep = read(&a_sep);
    assert!(
        of_a_sep.starts_with(&of_a),
        "{name}: a word after {a:?} changed what was selected before it: {of_a:?} became \
         {of_a_sep:?}"
    );
    let extra = &of_a_sep[of_a.len()..];
    // A value for A's last word (any reader), or the root through the preprocessor that
    // A's last three words take (the target reader alone).
    let a_value_for_a_last_word =
        extra.len() == 2 && extra[0] == *a.last().expect("A is not empty") && extra[1] == neutral;
    let a_root_through_the_preprocessor = name == "target_selecting_flags"
        && extra.len() == LONGEST_SELECTION
        && extra[..3] == ROOT_THROUGH_PREPROCESSOR
        && a.ends_with(&extra[..3])
        && extra[3] == neutral;
    assert!(
        extra.is_empty() || a_value_for_a_last_word || a_root_through_the_preprocessor,
        "{name}: {neutral} after {a:?} selected {extra:?}, more than a value for A's last word"
    );
    let whole = read(&joined(&[a, &sep, &sep, b]));
    let parts = joined(&[&of_a_sep, &read(b)]);
    assert_eq!(
        whole, parts,
        "{name}: {a:?}, {neutral}, {neutral}, {b:?} is not read as its two halves"
    );
}

fn check_selector(name: &str, read: Reader, neutral: &str, input: &[String]) -> usize {
    let found = read(input);
    assert_eq!(read(input), found, "{name}: a second reading differs");
    assert!(
        is_subsequence(&found, input),
        "{name}: {found:?} is not words of {input:?} in order"
    );
    assert_eq!(
        read(&found),
        found,
        "{name}: the selection {found:?} does not select itself whole"
    );
    let mut checked = 0;
    for k in splits(input.len()) {
        selector_splits(name, read, neutral, &input[..k], &input[k..]);
        checked += 1;
    }
    checked
}

fn check_response_files(input: &[String]) {
    let found = response_file_arguments(input);
    assert_eq!(
        response_file_arguments(input),
        found,
        "a second reading differs"
    );
    let mut alone = Vec::new();
    for word in input {
        let verdict = response_file_arguments(std::slice::from_ref(word));
        assert!(
            verdict.is_empty() || verdict == [word.clone()],
            "{word:?} alone came back as {verdict:?}"
        );
        if word.starts_with('@') {
            assert_eq!(
                verdict,
                std::slice::from_ref(word),
                "{word:?} begins with @ and passed"
            );
        }
        alone.extend(verdict);
    }
    assert_eq!(
        found, alone,
        "the response files of {input:?} are not its words each read alone"
    );
}

fn check_removals(input: &[String]) -> usize {
    let found = runtime_removing_flags(input);
    assert_eq!(
        runtime_removing_flags(input),
        found,
        "a second reading differs"
    );
    assert!(
        is_subsequence(&found, input),
        "{found:?} is not words of {input:?} in order"
    );
    assert!(
        align_removals(&found, input),
        "{found:?} does not align with refusals of {input:?} made alone, in order"
    );
    let sep = owned(&[NEUTRAL]);
    let mut checked = 0;
    for k in splits(input.len()) {
        let (a, b) = input.split_at(k);
        let whole = runtime_removing_flags(&joined(&[a, &sep, b]));
        let parts = joined(&[&runtime_removing_flags(a), &runtime_removing_flags(b)]);
        assert_eq!(
            whole, parts,
            "{a:?}, {NEUTRAL}, {b:?} is not read as its two halves"
        );
        checked += 1;
    }
    checked
}

/// The laws of a pair reader (`relative_path_arguments` with `/` as its neutral word,
/// `driver_divided_pairs` with `-O2`): a second reading agrees, every item aligns with up to
/// [`LONGEST_ITEM`] adjacent input words, and a list split by the neutral word is read as its
/// two halves. For `relative_path_arguments` (`completes`) the first half is `A` and the
/// neutral word, which is `A`'s reading, or that reading without its last item where that
/// item is the words before `A`'s last: a path option handed to a tool at the end of `A` with
/// no path after it (`-Xlinker -L -Xlinker`), which the neutral word, handed to the tool by
/// `A`'s last word, completes with an absolute path. Returns the splits checked.
fn check_pairs(
    name: &str,
    read: Reader,
    neutral: &str,
    completes: bool,
    input: &[String],
) -> usize {
    let found = read(input);
    assert_eq!(read(input), found, "{name}: a second reading differs");
    let aligned = align_items(read, &found, input).unwrap_or_else(|| {
        panic!(
            "{name}: {found:?} does not align with words of {input:?} that are refused alone, \
             in order"
        )
    });
    assert_eq!(aligned.len(), found.len(), "{name}: every item aligned");
    let sep = owned(&[neutral]);
    let mut checked = 0;
    for k in splits(input.len()) {
        let (a, b) = input.split_at(k);
        let of_a = read(a);
        let of_a_sep = read(&joined(&[a, &sep]));
        let completed = completes
            && of_a_sep.len() + 1 == of_a.len()
            && of_a.starts_with(&of_a_sep)
            && ends_unpaired(a)
            && (1..=LONGEST_ITEM).any(|n| {
                a.len()
                    .checked_sub(n + 1)
                    .is_some_and(|from| of_a.last() == Some(&a[from..a.len() - 1].join(" ")))
            });
        assert!(
            of_a_sep == of_a || completed,
            "{name}: {neutral} after {a:?} changed its reading {of_a:?} to {of_a_sep:?}"
        );
        let whole = read(&joined(&[a, &sep, b]));
        let parts = joined(&[&of_a_sep, &read(b)]);
        assert_eq!(
            whole, parts,
            "{name}: {a:?}, {neutral}, {b:?} is not read as its two halves"
        );
        checked += 1;
    }
    checked
}

/// The head law over every position of `input`: where `read` refuses a refusal that begins
/// there (`refusal` gives what it returns for it and the number of words it spans), the
/// reading from there is that refusal and then the reading from after it. For
/// `relative_path_arguments` (`completes`) a refusal that the reading of its words and the two
/// after them leaves out is a path option handed to a tool with no path after it, refused as
/// unpaired, which those two words complete (`-Xlinker -L` before `-Xlinker /abs`), and the
/// reading from there is that reading and then the reading from after them. Returns the
/// positions asked.
fn check_heads(
    name: &str,
    read: Reader,
    completes: bool,
    input: &[String],
    refusal: impl Fn(&[String]) -> Option<(Vec<String>, usize)>,
) -> usize {
    let mut asked = 0;
    for i in 0..input.len() {
        asked += 1;
        let Some((refused, span)) = refusal(&input[i..]) else {
            continue;
        };
        let from = read(&input[i..]);
        let end = i + span + 2;
        let completed = (completes && end <= input.len())
            .then(|| read(&input[i..end]))
            .filter(|completed| {
                !completed.starts_with(&refused) && ends_unpaired(&input[i..i + span])
            });
        if let Some(completed) = completed {
            assert_eq!(
                from,
                joined(&[&completed, &read(&input[end..])]),
                "{name}: {refused:?}, completed by the two words after it, took something more \
                 from what follows them in {:?}",
                &input[i..]
            );
            continue;
        }
        let after = read(&input[i + span..]);
        assert_eq!(
            from,
            joined(&[&refused, &after]),
            "{name}: {refused:?}, refused alone, took something from what follows it in {:?}",
            &input[i..]
        );
    }
    asked
}

/// The one-reader law at every position of `input`: where a carried reader takes the first
/// `k` words from there whole (`k` up to [`LONGEST_SELECTION`]; the smallest such `k` for
/// each reader, since a longer head it also takes whole is that head and then a head the
/// law asks at its own position), every other carried reader reads the list from there as
/// it reads it from after those words. Returns the positions asked.
fn check_one_reader_per_word(input: &[String]) -> usize {
    let mut asked = 0;
    for i in 0..input.len() {
        asked += 1;
        for (name, read) in CARRIED {
            let Some(k) = (1..=LONGEST_SELECTION.min(input.len() - i))
                .find(|k| read(&input[i..i + k]) == input[i..i + k])
            else {
                continue;
            };
            for (other, read_other) in CARRIED {
                if other == name {
                    continue;
                }
                assert_eq!(
                    read_other(&input[i..]),
                    read_other(&input[i + k..]),
                    "{other} reads a word of {:?}, which {name} takes whole, in {:?}",
                    &input[i..i + k],
                    &input[i..]
                );
            }
        }
    }
    asked
}

/// The value law at every position of `input`: where the word takes the next one as its own
/// value and selects nothing (`toolchain::takes_a_value`), every carried reader,
/// `selects_target`, `runtime_removing_flags` and `driver_divided_pairs` read the list from
/// there as they read it from after the pair (from after the word alone where it ends the
/// list), so a selection spelled as the value is no reader's and no refusal's. Returns the
/// positions asked.
fn check_value_pairs(input: &[String]) -> usize {
    const REFUSING: [(&str, Reader); 2] = [
        ("runtime_removing_flags", runtime_removing_flags),
        ("driver_divided_pairs", driver_divided_pairs),
    ];
    let mut asked = 0;
    for i in 0..input.len() {
        asked += 1;
        if !takes_a_value(&input[i]) {
            continue;
        }
        let after = (i + 2).min(input.len());
        // The macro reader's own two-token spelling (`-D X`, `--def X`), told by the crate's
        // classifier and not by the carrying: `macro_words` carries exactly that pair, whole,
        // and reads the rest from after it; every other reader reads it as a value pair.
        let macro_pair = is_macro_option(&input[i]);
        if macro_pair && after == i + 2 {
            assert_eq!(
                macro_words(&input[i..after]),
                input[i..after],
                "macro_words carries its own pair {:?} whole",
                &input[i..after]
            );
            assert_eq!(
                macro_words(&input[i..]),
                joined(&[&input[i..after], &macro_words(&input[after..])]),
                "macro_words reads {:?} as its pair and then the rest",
                &input[i..]
            );
        }
        for (name, read) in CARRIED.iter().chain(REFUSING.iter()) {
            if macro_pair && *name == "macro_words" {
                continue;
            }
            assert_eq!(
                read(&input[i..]),
                read(&input[after..]),
                "{name} reads the value of {:?}, which takes it, in {:?}",
                input[i],
                &input[i..]
            );
        }
        assert_eq!(
            selects_target(&input[i..]),
            selects_target(&input[after..]),
            "selects_target reads the value of {:?} in {:?}",
            input[i],
            &input[i..]
        );
    }
    asked
}

/// The refusal `runtime_removing_flags` makes of a list's first word alone, or of its first
/// two words alone as a pair where it refuses nothing of the first alone.
fn removal_at(words: &[String]) -> Option<(Vec<String>, usize)> {
    let first = words.first()?;
    let alone = runtime_removing_flags(std::slice::from_ref(first));
    if alone == [first.clone()] {
        return Some((alone, 1));
    }
    let pair = words.get(..2)?;
    (alone.is_empty() && runtime_removing_flags(pair) == pair).then(|| (pair.to_vec(), 2))
}

/// The refusal a pair reader (`read`) makes of a list's first words alone as one item, those
/// words joined by a space: the most words, up to [`LONGEST_ITEM`], it so refuses. The most
/// and not the fewest, since `relative_path_arguments` refuses a path option handed to a tool
/// with no path after it (`-Xlinker -L`) and the same option with its path handed after it
/// (`-Xlinker -L -Xlinker rel`) as one item, which is the refusal that begins there.
fn pair_at(read: Reader, words: &[String]) -> Option<(Vec<String>, usize)> {
    (1..=LONGEST_ITEM.min(words.len())).rev().find_map(|k| {
        let item = words[..k].join(" ");
        (read(&words[..k]) == [item.clone()]).then_some((vec![item], k))
    })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let input: Vec<String> = text.split('\n').map(str::to_owned).collect();
    assert_eq!(
        input.len(),
        text.matches('\n').count() + 1,
        "the words fed are the lines of the input"
    );

    check_response_files(&input);
    let mut checked = check_removals(&input);
    checked += check_pairs(
        "relative_path_arguments",
        relative_path_arguments,
        ABSOLUTE,
        true,
        &input,
    );
    checked += check_pairs(
        "driver_divided_pairs",
        driver_divided_pairs,
        NEUTRAL,
        false,
        &input,
    );
    let heads = check_heads(
        "runtime_removing_flags",
        runtime_removing_flags,
        false,
        &input,
        removal_at,
    ) + check_heads(
        "relative_path_arguments",
        relative_path_arguments,
        true,
        &input,
        |words| pair_at(relative_path_arguments, words),
    ) + check_heads(
        "driver_divided_pairs",
        driver_divided_pairs,
        false,
        &input,
        |words| pair_at(driver_divided_pairs, words),
    );
    assert_eq!(
        heads,
        3 * input.len(),
        "the positions asked over {} words",
        input.len()
    );
    checked += check_selector(
        "target_selecting_flags",
        target_selecting_flags,
        NEUTRAL,
        &input,
    );
    checked += check_selector(
        "runtime_selecting_flags",
        runtime_selecting_flags,
        NEUTRAL,
        &input,
    );
    checked += check_selector(
        "header_selecting_flags",
        header_selecting_flags,
        NEUTRAL,
        &input,
    );
    checked += check_selector("macro_words", macro_words, ABSOLUTE, &input);
    checked += check_selector("optimization_words", optimization_words, ABSOLUTE, &input);
    assert_eq!(
        checked,
        8 * expected_splits(input.len()),
        "the splits checked over {} words",
        input.len()
    );

    assert_eq!(
        check_one_reader_per_word(&input),
        input.len(),
        "the positions asked of the one-reader law over {} words",
        input.len()
    );
    assert_eq!(
        check_value_pairs(&input),
        input.len(),
        "the positions asked of the value law over {} words",
        input.len()
    );
    // The same law over the whole list: what the carried readers return together is the
    // input with words left out, counted by spelling, so no word reaches the arms twice.
    let mut budget: HashMap<&str, usize> = HashMap::new();
    for word in &input {
        *budget.entry(word.as_str()).or_default() += 1;
    }
    for (name, read) in CARRIED {
        for word in read(&input) {
            let left = budget.get_mut(word.as_str()).filter(|left| **left > 0);
            let Some(left) = left else {
                panic!(
                    "{name} returned {word:?} once more than {input:?} holds it, counting \
                     every carried reader"
                );
            };
            *left -= 1;
        }
    }

    let targets = target_selecting_flags(&input);
    assert_eq!(
        selects_target(&targets),
        selects_target(&input),
        "the target selection {targets:?} reads a target differently from {input:?}"
    );
    assert!(
        !selects_target(&input) || !targets.is_empty(),
        "{input:?} selects a target and target_selecting_flags returned nothing"
    );

    for word in &input {
        check_macro_name(word);
        // A word of their own, alone, is carried: the laws above hold of a reader that
        // carries nothing, and this does not.
        let alone = std::slice::from_ref(word);
        if optimization_word(word) {
            assert_eq!(optimization_words(alone), alone, "{word:?} alone");
        }
        if (word.starts_with("-D") || word.starts_with("-U")) && word.len() > 2 {
            assert_eq!(macro_words(alone), alone, "{word:?} alone");
        }
    }
    for word in optimization_words(&input) {
        assert!(
            optimization_word(&word),
            "optimization_words carried {word:?}"
        );
    }
});

/// Whether `optimization_words` reads `word` as an optimisation word: a word beginning `-O`, or
/// gcc's `--optimize` spelled whole or abbreviated to a prefix of at least `--op`, alone, or
/// spelled whole with `=N`. The reading `toolchain::LONG_ALIASES` states, written here because
/// the classifier keeps it to the crate.
fn optimization_word(word: &str) -> bool {
    word.starts_with("-O")
        || match word.split_once('=') {
            None => word.len() >= "--op".len() && "--optimize".starts_with(word),
            Some((name, _)) => name == "--optimize",
        }
}

fn check_macro_name(word: &str) {
    let read = macro_name(word);
    assert_eq!(macro_name(word), read, "a second reading differs");
    let rest = word.strip_prefix("-D").or_else(|| word.strip_prefix("-U"));
    let expected = rest
        .map(|r| r.split(['=', '(']).next().unwrap_or(r))
        .filter(|n| !n.is_empty());
    assert_eq!(read, expected, "the macro {word:?} operates on");
    if let (Some(name), Some(rest)) = (read, rest) {
        let after = rest
            .strip_prefix(name)
            .expect("the name begins the operand");
        assert!(
            after.is_empty() || after.starts_with('=') || after.starts_with('('),
            "{word:?}: {name:?} is followed by {after:?}"
        );
    }
}
