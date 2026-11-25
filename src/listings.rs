// SPDX-License-Identifier: BSD-3-Clause

//! The driver's answers the listing rules read, as a record a report publishes, and the one
//! function from that record to the rules' verdicts.

use std::cell::RefCell;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::compile_inputs::CompileInputs;
use crate::link_inputs::{LinkInputs, PathAnswers, Resolve, SearchDirs};
use crate::probe::{Channel, Check, Probe};
use crate::report::{self, Gating, Verdict, gating_rule};

/// One answer of the driver, or the sentence saying why it could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer<T> {
    Answer(T),
    Error(String),
}

impl<T> From<Result<T, String>> for Answer<T> {
    fn from(result: Result<T, String>) -> Self {
        match result {
            Ok(answer) => Self::Answer(answer),
            Err(why) => Self::Error(why),
        }
    }
}

/// One question put to the driver: the flags it was asked under, as asked, and its answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AskedWire<T>")]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct Asked<T> {
    pub flags: Vec<String>,
    #[serde(flatten)]
    pub answer: Answer<T>,
}

/// [`Asked`] as a published record spells it, before the one-of rule is held.
#[derive(Debug, Deserialize)]
pub struct AskedWire<T> {
    flags: Vec<String>,
    answer: Option<T>,
    error: Option<String>,
}

impl<T> TryFrom<AskedWire<T>> for Asked<T> {
    type Error = String;

    fn try_from(wire: AskedWire<T>) -> Result<Self, String> {
        let answer = match (wire.answer, wire.error) {
            (Some(answer), None) => Answer::Answer(answer),
            (None, Some(why)) => Answer::Error(why),
            (Some(_), Some(_)) => {
                return Err("an answer holds both `answer` and `error`".to_owned());
            }
            (None, None) => return Err("an answer holds neither `answer` nor `error`".to_owned()),
        };
        Ok(Self {
            flags: wire.flags,
            answer,
        })
    }
}

/// The two `-###` link lines `link-inputs-unmatched-by-arms` compares: the measured build's,
/// and the arms' selection under the measured line's linkage form. `arms` is absent where the
/// measured listing could not be read, since its form is what the arms' question carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkAsked {
    pub measured: Asked<LinkInputs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arms: Option<Asked<LinkInputs>>,
}

/// The four answers `clean-link-unmatched-by-measured` compares, asked in this order; each is
/// absent after the first that could not be read, which decides the rule alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanLinkAsked {
    pub measured: Asked<LinkInputs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footing: Option<Asked<LinkInputs>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_dirs: Option<Asked<SearchDirs>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_dirs: Option<Asked<SearchDirs>>,
}

/// One arm class's compile listing ([`owed_classes`]): the class's optimisation words and the
/// listing at its level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassAsked {
    pub words: Vec<String>,
    pub listing: Asked<CompileInputs>,
}

/// The compile listings `compile-inputs-unmatched-by-arms` compares: the measured compile's,
/// the stand-in's (absent where the measured one could not be read), and one per arm class
/// ([`owed_classes`]), asked only where the measured listing and the stand-in agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileAsked {
    pub measured: Asked<CompileInputs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stand_in: Option<Asked<CompileInputs>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<ClassAsked>,
}

/// Every answer the listing rules read for one probe, and what their comparisons read of the
/// filesystem. A comparison the probe does not owe ([`Owed`]) is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<LinkAsked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_link: Option<CleanLinkAsked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile: Option<CompileAsked>,
    /// The measured compile's listing, for its sanitizer and LTO words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_compile: Option<Asked<CompileInputs>>,
    pub paths: PathAnswers,
}

/// Which of the driver's answers a probe owes: one per comparison, asked where it can decide
/// something for a check of the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owed {
    /// A check of the probe reads the measured link ([`report::LINK_INPUT_READINGS`]), under
    /// a profile adding flags, on a probe that links.
    pub link: bool,
    /// A check reads the clean build's link ([`report::reads_the_clean_link`]), under the
    /// same two conditions.
    pub clean_link: bool,
    /// A check reads the measured compile's headers, macros or exception model, under a
    /// profile adding flags.
    pub compile: bool,
    /// A check reads the measured compile's sanitizer or LTO words, under any profile.
    pub measured_compile: bool,
}

impl Owed {
    /// What `probe` owes under a profile that adds flags or not.
    #[must_use]
    pub fn of(probe: &Probe, profile_is_clean: bool) -> Self {
        let links = !profile_is_clean && probe.link_mode != crate::probe::LinkMode::Object;
        Self {
            link: links && link_reading_check(probe).is_some(),
            clean_link: links && probe.checks.iter().any(report::reads_the_clean_link),
            compile: !profile_is_clean && probe.checks.iter().any(reads_compile_inputs),
            measured_compile: probe.checks.iter().any(|c| {
                report::SANITIZER_GROUP_CHECKS.contains(&c.id)
                    || report::SIGNED_OVERFLOW_SANITIZER_CHECKS.contains(&c.id)
                    || report::LTO_CODEGEN_CHECKS.contains(&c.id)
            }),
        }
    }

    /// Whether the probe owes any answer at all.
    #[must_use]
    pub const fn any(self) -> bool {
        let Self {
            link,
            clean_link,
            compile,
            measured_compile,
        } = self;
        link || clean_link || compile || measured_compile
    }

    /// Whether `listings` holds exactly the comparisons owed: each it does not, by name and
    /// which way (`link (owed, absent)`, `compile (present, not owed)`).
    #[must_use]
    pub fn unmet_by(self, listings: &Listings) -> Vec<String> {
        let Self {
            link,
            clean_link,
            compile,
            measured_compile,
        } = self;
        let Listings {
            link: held_link,
            clean_link: held_clean,
            compile: held_compile,
            measured_compile: held_measured,
            paths: _,
        } = listings;
        [
            ("link", link, held_link.is_some()),
            ("clean_link", clean_link, held_clean.is_some()),
            ("compile", compile, held_compile.is_some()),
            (
                "measured_compile",
                measured_compile,
                held_measured.is_some(),
            ),
        ]
        .into_iter()
        .filter(|(_, owed, held)| owed != held)
        .map(|(name, owed, _)| {
            if owed {
                format!("{name} (owed, absent)")
            } else {
                format!("{name} (present, not owed)")
            }
        })
        .collect()
    }
}

/// The first check of `probe` that reads the measured link: the one whose arms' selection
/// the link comparison asks under.
#[must_use]
pub fn link_reading_check(probe: &Probe) -> Option<&Check> {
    probe.checks.iter().find(|c| {
        report::LINK_INPUT_READINGS.contains(&c.id)
            && !c.measures_toolchain_default
            && c.channel() != Channel::Macro
    })
}

/// Whether `check` is one the compile comparison speaks for.
#[must_use]
pub fn reads_compile_inputs(check: &Check) -> bool {
    (report::COMPILE_INPUT_READINGS.contains(&check.id)
        || report::EXCEPTION_MODEL_READINGS.contains(&check.id))
        && !check.measures_toolchain_default
}

/// The distinct optimisation-word classes of a check's arms: the `-O` words of its
/// positive and negative lists (none for a check whose controls carry no `-O`), and the
/// regime arm's where one is owed, which are the measured flags (`measured`,
/// `measure::variant_flags` with no extra) followed by the arm's own.
#[must_use]
pub fn arm_optimization_classes(
    check: &Check,
    measured: &[String],
    profile_is_clean: bool,
) -> Vec<Vec<String>> {
    let mut classes: Vec<Vec<String>> = Vec::new();
    let mut push = |words: Vec<String>| {
        if !classes.contains(&words) {
            classes.push(words);
        }
    };
    push(crate::compile_inputs::optimization_words(
        &crate::measure::control_flags(check.positive),
    ));
    push(crate::compile_inputs::optimization_words(
        &crate::measure::control_flags(check.negative),
    ));
    if let Some(arm) = check
        .regime_arm()
        .filter(|_| check.owes_regime_control(profile_is_clean))
    {
        let mut flags = measured.to_vec();
        flags.extend(arm.iter().map(|s| (*s).to_owned()));
        push(crate::compile_inputs::optimization_words(&flags));
    }
    classes
}

/// The arm classes the compile comparison asks a listing at, in order: each class of a
/// listed check's arms ([`arm_optimization_classes`]) other than the profile's own words,
/// once.
#[must_use]
pub fn owed_classes(
    probe: &Probe,
    measured: &[String],
    profile_is_clean: bool,
) -> Vec<Vec<String>> {
    let profile_words = crate::compile_inputs::optimization_words(measured);
    let mut classes: Vec<Vec<String>> = Vec::new();
    for check in probe.checks.iter().filter(|c| reads_compile_inputs(c)) {
        for class in arm_optimization_classes(check, measured, profile_is_clean) {
            if class != profile_words && !classes.contains(&class) {
                classes.push(class);
            }
        }
    }
    classes
}

/// What the compile comparison found for one probe: a difference between the measured
/// compile's listing and the stand-in under the profile's words, which withholds every
/// listed check of the probe but those an exception model reads (`exception_model`); and,
/// per class of optimisation words the arms carry, a
/// difference the driver makes with the level between the stand-in and a listing at that
/// class's level, which withholds the checks whose arms are in the class.
/// [`CompileFindings::for_check`] answers for one check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompileFindings {
    pub whole: Option<String>,
    pub by_class: Vec<(Vec<String>, String)>,
    /// Where the measured compile's exception model is not the arms'
    /// ([`crate::compile_inputs::exception_model_difference`]), or why it could not be told:
    /// the one sentence a check in [`report::EXCEPTION_MODEL_READINGS`] is withheld by.
    pub exception_model: Option<String>,
}

impl CompileFindings {
    /// The sentence that withholds `check`, if any: for a check in
    /// [`report::EXCEPTION_MODEL_READINGS`], the exception model's alone; otherwise the whole
    /// probe's, or the first of the check's arm classes (`classes`,
    /// [`arm_optimization_classes`]) the driver answers otherwise than the stand-in.
    #[must_use]
    pub fn for_check(&self, check: &Check, classes: &[Vec<String>]) -> Option<&str> {
        if report::EXCEPTION_MODEL_READINGS.contains(&check.id) {
            return self.exception_model.as_deref();
        }
        if let Some(whole) = &self.whole {
            return Some(whole);
        }
        classes.iter().find_map(|class| {
            self.by_class
                .iter()
                .find(|(words, _)| words == class)
                .map(|(_, why)| why.as_str())
        })
    }
}

/// What the listing rules read, derived from one probe's [`Listings`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Findings {
    /// The sentence that withholds a check reading the measured link, if any.
    pub link: Option<String>,
    /// The sentence that withholds a check reading the clean build's link, if any.
    pub clean_link: Option<String>,
    pub compile: CompileFindings,
    /// The measured compile's sanitizer words ([`report::SanitizerWords`]).
    pub sanitizers: Option<report::SanitizerWords>,
    /// The measured compile's LTO words ([`report::LtoWords`]).
    pub lto: Option<report::LtoWords>,
}

/// A record that cannot be what `measure` writes: an answer present after the one that
/// decided its comparison, or absent where the comparison needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed(pub String);

fn needed<'a, T>(value: Option<&'a Asked<T>>, what: &str) -> Result<&'a Asked<T>, Malformed> {
    value.ok_or_else(|| Malformed(format!("{what} is absent after an answer that needs it")))
}

fn extra<T>(value: Option<&Asked<T>>, what: &str) -> Result<(), Malformed> {
    match value {
        Some(_) => Err(Malformed(format!(
            "{what} is present after an answer that could not be read"
        ))),
        None => Ok(()),
    }
}

/// The listing rules' inputs from `listings`, every path read through `paths`: what
/// `measure` hands each check, and what a replay re-derives.
///
/// # Errors
///
/// [`Malformed`] where an answer the comparison's order puts after a failed one is present,
/// or one it needs is absent.
pub fn findings(listings: &Listings, paths: &dyn Resolve) -> Result<Findings, Malformed> {
    Ok(Findings {
        link: listings
            .link
            .as_ref()
            .map(|l| link_finding(l, paths))
            .transpose()?
            .flatten(),
        clean_link: listings
            .clean_link
            .as_ref()
            .map(|l| clean_link_finding(l, paths))
            .transpose()?
            .flatten(),
        compile: match listings.compile.as_ref() {
            Some(asked) => compile_finding(asked, paths)?,
            None => CompileFindings::default(),
        },
        sanitizers: listings
            .measured_compile
            .as_ref()
            .map(|asked| measured_words(asked, |inputs| inputs.sanitizers.clone())),
        lto: listings.measured_compile.as_ref().map(|asked| {
            measured_words(asked, |inputs| report::LtoListing {
                lto: inputs.lto.clone(),
                relocation: inputs.relocation.clone(),
            })
        }),
    })
}

fn measured_words<T>(
    asked: &Asked<CompileInputs>,
    read: impl Fn(&CompileInputs) -> T,
) -> Result<T, String> {
    match &asked.answer {
        Answer::Answer(inputs) => Ok(read(inputs)),
        Answer::Error(why) => Err(format!("for the measured build, {why}")),
    }
}

fn link_finding(asked: &LinkAsked, paths: &dyn Resolve) -> Result<Option<String>, Malformed> {
    let measured = match &asked.measured.answer {
        Answer::Answer(inputs) => inputs,
        Answer::Error(why) => {
            extra(asked.arms.as_ref(), "the arms' link listing")?;
            return Ok(Some(format!("for the measured build, {why}")));
        }
    };
    let arms_asked = needed(asked.arms.as_ref(), "the arms' link listing")?;
    let arms = match &arms_asked.answer {
        Answer::Answer(inputs) => inputs,
        Answer::Error(why) => return Ok(Some(format!("for the arms' selection, {why}"))),
    };
    Ok(
        crate::link_inputs::difference(measured, arms, paths).map(|d| {
            format!(
                "the driver's -### listing for the measured link ({}) and for the arms' \
                 selection under the same linkage form ({}) differ: {d}",
                asked.measured.flags.join(" "),
                arms_asked.flags.join(" ")
            )
        }),
    )
}

fn clean_link_finding(
    asked: &CleanLinkAsked,
    paths: &dyn Resolve,
) -> Result<Option<String>, Malformed> {
    // Each answer in the order `measure` asks them; the first that could not be read decides,
    // and nothing after it was asked.
    let rest_absent = |from: usize| -> Result<(), Malformed> {
        if from <= 1 {
            extra(asked.footing.as_ref(), "the clean build's link listing")?;
        }
        if from <= 2 {
            extra(
                asked.measured_dirs.as_ref(),
                "the measured search directories",
            )?;
        }
        extra(asked.clean_dirs.as_ref(), "the clean search directories")
    };
    let measured = match &asked.measured.answer {
        Answer::Answer(inputs) => inputs,
        Answer::Error(why) => {
            rest_absent(1)?;
            return Ok(Some(format!("for the measured build, {why}")));
        }
    };
    let footing_asked = needed(asked.footing.as_ref(), "the clean build's link listing")?;
    let footing = match &footing_asked.answer {
        Answer::Answer(inputs) => inputs,
        Answer::Error(why) => {
            rest_absent(2)?;
            return Ok(Some(format!("for the clean build's link, {why}")));
        }
    };
    let measured_dirs = match &needed(
        asked.measured_dirs.as_ref(),
        "the measured search directories",
    )?
    .answer
    {
        Answer::Answer(dirs) => dirs,
        Answer::Error(why) => {
            rest_absent(3)?;
            return Ok(Some(format!("for the measured build, {why}")));
        }
    };
    let clean_asked = needed(asked.clean_dirs.as_ref(), "the clean search directories")?;
    let clean_dirs = match &clean_asked.answer {
        Answer::Answer(dirs) => dirs,
        Answer::Error(why) => return Ok(Some(format!("for the clean build, {why}"))),
    };
    let (measured_flags, footing_flags, clean_build_flags) = (
        &asked.measured.flags,
        &footing_asked.flags,
        &clean_asked.flags,
    );
    Ok(crate::link_inputs::clean_link_difference(
        (measured, measured_dirs),
        (footing, clean_dirs),
        paths,
    )
    .map(|d| {
        format!(
            "the driver's answers for the measured build ({}) and for the clean build \
             ({}; its link line {}) differ: {d}",
            crate::link_inputs::under(measured_flags),
            crate::link_inputs::under_named(clean_build_flags, "selection flag"),
            if footing_flags == clean_build_flags {
                "under the same flags".to_owned()
            } else {
                format!(
                    "{}, the measured line's linker selection among them",
                    crate::link_inputs::under_named(footing_flags, "selection flag")
                )
            }
        )
    }))
}

fn compile_finding(
    asked: &CompileAsked,
    paths: &dyn Resolve,
) -> Result<CompileFindings, Malformed> {
    let whole = |why: String| CompileFindings {
        whole: Some(why.clone()),
        by_class: Vec::new(),
        exception_model: Some(why),
    };
    let no_classes = || -> Result<(), Malformed> {
        if asked.classes.is_empty() {
            Ok(())
        } else {
            Err(Malformed(
                "class listings are present after a whole-probe answer".to_owned(),
            ))
        }
    };
    let measured_flags = &asked.measured.flags;
    let measured = match &asked.measured.answer {
        Answer::Answer(inputs) => inputs,
        Answer::Error(why) => {
            extra(asked.stand_in.as_ref(), "the stand-in listing")?;
            no_classes()?;
            return Ok(whole(format!("for the measured build, {why}")));
        }
    };
    let stand_in_asked = needed(asked.stand_in.as_ref(), "the stand-in listing")?;
    let stand_in_flags = &stand_in_asked.flags;
    let stand_in = match &stand_in_asked.answer {
        Answer::Answer(inputs) => inputs,
        Answer::Error(why) => {
            no_classes()?;
            return Ok(whole(format!("for the arms' selection, {why}")));
        }
    };
    let exception_model = crate::compile_inputs::exception_model_difference(measured, stand_in)
        .map(|d| {
            format!(
                "the driver's -### listing for the measured compile ({}) and for the arms' \
                 selection ({}) differ: {d}",
                measured_flags.join(" "),
                stand_in_flags.join(" ")
            )
        });
    if let Some(d) = crate::compile_inputs::difference(measured, stand_in, paths) {
        no_classes()?;
        return Ok(CompileFindings {
            whole: Some(format!(
                "the driver's -### listing for the measured compile ({}) and for the arms' \
                 selection with the profile's own optimisation and macro words ({}) differ: \
                 {d}",
                measured_flags.join(" "),
                stand_in_flags.join(" ")
            )),
            by_class: Vec::new(),
            exception_model,
        });
    }
    let owned = crate::measure::macros_the_controls_set();
    let mut by_class = Vec::new();
    for class in &asked.classes {
        let class_flags = &class.listing.flags;
        let why = match &class.listing.answer {
            Answer::Answer(at_class) => level_bound_difference(
                (stand_in, stand_in_flags),
                (at_class, class_flags),
                &owned,
                paths,
            ),
            Answer::Error(why) => Some(format!(
                "for the arms at their own optimisation level ({}), {why}",
                class_flags.join(" ")
            )),
        };
        if let Some(why) = why {
            by_class.push((class.words.clone(), why));
        }
    }
    Ok(CompileFindings {
        whole: None,
        by_class,
        exception_model,
    })
}

/// The macro operations of a listing that name no macro a control arm sets (`owned`), as
/// a sequence: what the per-level comparison holds the two listings to, since a request
/// macro the controls set is the admitted difference and everything else is not.
fn unowned_macro_operations<'a>(list: &'a [String], owned: &BTreeSet<String>) -> Vec<&'a str> {
    list.iter()
        .map(String::as_str)
        .filter(|w| crate::compile_inputs::macro_name(w).is_none_or(|name| !owned.contains(name)))
        .collect()
}

/// Where the driver answers a compile at the profile's optimisation level (`stand_in`,
/// under `stand_in_flags`) otherwise than one at an arm class's level (`at_class`, under
/// `class_flags`): a sentence that withholds the class's checks, or `None` where the two
/// listings agree, or differ only in macro operations naming macros the controls set
/// (`owned`), the admission the register entry
/// `optimization-level-defaults-decide-only-their-own-checks` rests on. The macro
/// operations are compared as sequences with the owned ones removed, so the same unowned
/// words in another order or number differ too.
pub(crate) fn level_bound_difference(
    (stand_in, stand_in_flags): (&CompileInputs, &[String]),
    (at_class, class_flags): (&CompileInputs, &[String]),
    owned: &BTreeSet<String>,
    paths: &dyn Resolve,
) -> Option<String> {
    let differing = crate::compile_inputs::differences(stand_in, at_class, paths);
    if differing.is_empty() {
        return None;
    }
    let (at_profile, at_arms) = (
        unowned_macro_operations(&stand_in.macros, owned),
        unowned_macro_operations(&at_class.macros, owned),
    );
    let other_kinds = differing.iter().any(|d| d.what != "macro operations");
    if !other_kinds && at_profile == at_arms {
        return None;
    }
    let sentence = crate::compile_inputs::sentence(&differing);
    let words = |list: &[&str]| -> String {
        if list.is_empty() {
            "none".to_owned()
        } else {
            list.join(", ")
        }
    };
    let unowned_note = if at_profile == at_arms {
        String::new()
    } else {
        format!(
            " (macro operations no control arm sets: {} at the profile's level, {} at these \
             arms')",
            words(&at_profile),
            words(&at_arms)
        )
    };
    Some(format!(
        "the driver's -### listing at the profile's optimisation level ({}) and at these \
         arms' own ({}) differ in what the driver changes with the level, which reached one \
         side and not the other: {sentence}{unowned_note}",
        stand_in_flags.join(" "),
        class_flags.join(" ")
    ))
}

/// What one check of a probe reads of the probe's [`Findings`]: each a sentence that
/// withholds the check, or the listing's words a rule reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeListings<'a> {
    /// The link comparison's sentence, for a check that reads the measured link.
    pub link: Option<&'a str>,
    /// The clean-link comparison's sentence, for a check that reads the clean build.
    pub clean_link: Option<&'a str>,
    /// The compile comparison's sentence for this check ([`CompileFindings::for_check`]).
    pub compile: Option<&'a str>,
    /// The measured compile's sanitizer words.
    pub sanitizers: Option<&'a report::SanitizerWords>,
    /// The measured compile's LTO words.
    pub lto: Option<&'a report::LtoWords>,
}

impl Findings {
    /// What `check` reads of these findings, its arms in `classes`
    /// ([`arm_optimization_classes`]).
    #[must_use]
    pub fn for_check<'a>(&'a self, check: &Check, classes: &[Vec<String>]) -> ProbeListings<'a> {
        ProbeListings {
            link: self.link.as_deref(),
            clean_link: self.clean_link.as_deref(),
            compile: self.compile.for_check(check, classes),
            sanitizers: self.sanitizers.as_ref(),
            lto: self.lto.as_ref(),
        }
    }
}

/// The listing rules over `verdict`, the one the ladder's earlier stages left, in the order
/// `measure` consults them (the link, compile, sanitizer and LTO stages), each overwriting
/// what fired before it and reading the verdict the one before it left: the gating of the
/// last that fires, or `None` where none does.
#[must_use]
pub fn chain<'a>(check: &Check, verdict: Verdict, listings: &ProbeListings<'a>) -> Option<Gating> {
    let own = |s: Option<&'a str>| s.filter(|_| !check.measures_toolchain_default);
    let mut gating: Option<Gating> = None;
    let mut verdict = verdict;
    let mut fired = |g: Option<Gating>, verdict: &mut Verdict| {
        if let Some(g) = g {
            *verdict = g.rule.verdict();
            gating = Some(g);
        }
    };
    fired(
        report::link_inputs_limitation(check, own(listings.link)),
        &mut verdict,
    );
    fired(
        report::clean_link_limitation(check, listings.clean_link),
        &mut verdict,
    );
    fired(
        report::compile_inputs_limitation(check, own(listings.compile)),
        &mut verdict,
    );
    let sanitizer = report::sanitizer_group_limitation(check, verdict, listings.sanitizers)
        .or_else(|| {
            report::signed_overflow_sanitizer_limitation(check, verdict, listings.sanitizers)
        });
    fired(sanitizer, &mut verdict);
    fired(
        report::lto_codegen_limitation(check, verdict, listings.lto),
        &mut verdict,
    );
    gating
}

/// The rules [`chain`] can publish.
pub const LISTING_RULES: [gating_rule::Rule; 6] = [
    gating_rule::LINK_INPUTS_UNMATCHED,
    gating_rule::CLEAN_LINK_UNMATCHED,
    gating_rule::COMPILE_INPUTS_UNMATCHED,
    gating_rule::SANITIZER_GROUP_UNMEASURED,
    gating_rule::SIGNED_OVERFLOW_SANITIZED,
    gating_rule::LTO_CODEGEN_AT_LINK,
];

/// The verdicts the earlier stages of the ladder can hand [`chain`], as the listing rules
/// tell them apart: the sanitizer rules read `on`, `partial` and `off`, the LTO rule `on`, and
/// none of them anything else, which `indeterminate` stands for.
const CHAIN_INPUTS: [Verdict; 4] = [
    Verdict::On,
    Verdict::Partial,
    Verdict::Off,
    Verdict::Indeterminate,
];

/// What a replay of one observation's gating found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateReplay {
    /// The published gating, or its absence, is what [`chain`] gives over the published
    /// listings.
    Agrees,
    /// It is not.
    Disagrees,
    /// The observation was settled before the listing rules are consulted: its rule's stage
    /// is before [`gating_rule::Stage::Level`], which returns before `decide`.
    NotReached,
    /// Its rule overwrites whatever the ladder published ([`gating_rule::Stage::Target`],
    /// [`gating_rule::Stage::Twin`]), so the listing rules' result is not in the report.
    Overwritten,
}

/// What a published observation shows of its control triple: none (`controls` absent), one
/// that withheld, or one that discriminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripleSeen {
    Absent,
    Withheld,
    Discriminating,
}

/// Where a published gating stands on the ladder before any listing is read: `Some` where
/// that alone decides the replay, `None` where [`replay_gate`] must read the listings.
///
/// # Errors
///
/// The published rule's id, where this binary does not know it: such a gating cannot be
/// placed on the ladder.
pub fn before_listings(
    verdict: Verdict,
    rule: Option<&str>,
    triple: TripleSeen,
) -> Result<Option<GateReplay>, String> {
    use gating_rule::Triple;
    let Some(id) = rule else {
        return Ok((triple == TripleSeen::Absent).then_some(GateReplay::NotReached));
    };
    let rule = gating_rule::by_id(id).ok_or_else(|| id.to_owned())?;
    let fits = match (rule.stage.triple(), triple) {
        (Triple::None, TripleSeen::Absent)
        | (Triple::Withheld, TripleSeen::Withheld)
        | (Triple::Discriminating, TripleSeen::Discriminating)
        | (Triple::Built, TripleSeen::Withheld | TripleSeen::Discriminating)
        | (Triple::Any, _) => true,
        (Triple::None, _)
        | (_, TripleSeen::Absent)
        | (Triple::Withheld, TripleSeen::Discriminating)
        | (Triple::Discriminating, TripleSeen::Withheld) => false,
    };
    if verdict != rule.verdict() || !fits {
        return Ok(Some(GateReplay::Disagrees));
    }
    if rule.stage < gating_rule::Stage::Level {
        return Ok(Some(GateReplay::NotReached));
    }
    if matches!(
        rule.stage,
        gating_rule::Stage::Target | gating_rule::Stage::Twin
    ) {
        return Ok(Some(GateReplay::Overwritten));
    }
    Ok(None)
}

/// The listing rules' result for one observation that [`before_listings`] left to them, held
/// to its published `verdict` and gating `rule`: the rules [`chain`] gives (one per verdict
/// tried), and whether the published one is among them.
///
/// # Errors
///
/// The published rule's id, where this binary does not know it.
pub fn replay_gate(
    check: &Check,
    verdict: Verdict,
    rule: Option<&str>,
    branches_on_macros: bool,
    listings: &ProbeListings<'_>,
) -> Result<(GateReplay, Vec<Option<&'static str>>), String> {
    let published = match rule {
        None => None,
        Some(id) => Some(gating_rule::by_id(id).ok_or_else(|| id.to_owned())?),
    };
    let rule_of = |v: Verdict| chain(check, v, listings).map(|g| g.rule.id);
    let listing_rule = published.filter(|r| LISTING_RULES.iter().any(|l| l.id == r.id));
    if listing_rule.is_none() {
        let mut rederived = rule_of(verdict);
        let withheld_by_branch = rederived.is_none()
            && published.is_none()
            && branches_on_macros
            && verdict.is_measurement()
            && check.channel() != Channel::Macro
            && listings
                .compile
                .is_some_and(|_| !check.measures_toolchain_default);
        if withheld_by_branch {
            rederived = Some(gating_rule::MACRO_SPOOFED.id);
        }
        let agrees = rederived.is_none();
        return Ok((
            if agrees {
                GateReplay::Agrees
            } else {
                GateReplay::Disagrees
            },
            vec![rederived],
        ));
    }
    let mut all = Vec::new();
    for v in CHAIN_INPUTS {
        let r = rule_of(v);
        if !all.contains(&r) {
            all.push(r);
        }
    }
    let agrees = listing_rule.is_some_and(|r| all.contains(&Some(r.id)));
    Ok((
        if agrees {
            GateReplay::Agrees
        } else {
            GateReplay::Disagrees
        },
        all,
    ))
}

/// The path answers a published record holds, read in place of the filesystem: a path the
/// record does not answer is read as written, and named in [`Recorded::unanswered`], so a
/// comparison that read one is not a replay of the one `measure` made.
#[derive(Debug)]
pub struct Recorded<'a> {
    answers: &'a PathAnswers,
    unanswered: RefCell<BTreeSet<String>>,
}

impl<'a> Recorded<'a> {
    #[must_use]
    pub fn new(answers: &'a PathAnswers) -> Self {
        Self {
            answers,
            unanswered: RefCell::new(BTreeSet::new()),
        }
    }

    /// Every path a comparison asked of that the record does not answer.
    #[must_use]
    pub fn unanswered(self) -> BTreeSet<String> {
        self.unanswered.into_inner()
    }
}

impl Resolve for Recorded<'_> {
    fn resolved(&self, path: &str) -> String {
        if let Some(answer) = self.answers.resolved.get(path) {
            return answer.clone();
        }
        self.unanswered.borrow_mut().insert(path.to_owned());
        path.to_owned()
    }

    fn is_dir(&self, path: &str) -> bool {
        if let Some(answer) = self.answers.directories.get(path) {
            return *answer;
        }
        self.unanswered.borrow_mut().insert(path.to_owned());
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::CORPUS;

    fn check(id: &str) -> &'static Check {
        CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("{id} is a corpus check"))
    }

    fn lto(words: &[&str]) -> report::LtoListing {
        report::LtoListing {
            lto: words.iter().map(|w| (*w).to_owned()).collect(),
            relocation: vec!["-mrelocation-model static".to_owned()],
        }
    }

    fn with(words: &report::LtoWords) -> ProbeListings<'_> {
        ProbeListings {
            lto: Some(words),
            ..ProbeListings::default()
        }
    }

    #[test]
    fn a_published_gating_is_held_to_the_chain_over_its_listing() {
        let pic = check("pic-shared-link");
        let under: report::LtoWords = Ok(lto(&["-flto=full"]));
        let plain: report::LtoWords = Ok(lto(&[]));
        let lto_rule = Some(gating_rule::LTO_CODEGEN_AT_LINK.id);
        let rows: [(Verdict, Option<&str>, &ProbeListings<'_>, GateReplay); 4] = [
            (Verdict::On, None, &with(&under), GateReplay::Disagrees),
            (
                Verdict::Indeterminate,
                lto_rule,
                &with(&under),
                GateReplay::Agrees,
            ),
            (
                Verdict::Indeterminate,
                lto_rule,
                &with(&plain),
                GateReplay::Disagrees,
            ),
            (Verdict::On, None, &with(&plain), GateReplay::Agrees),
        ];
        let mut held = 0;
        for (verdict, rule, listings, expected) in rows {
            let (found, rederived) =
                replay_gate(pic, verdict, rule, false, listings).expect("a known rule");
            assert_eq!(found, expected, "{verdict:?} {rule:?}: {rederived:?}");
            held += 1;
        }
        assert_eq!(held, 4);
        assert_eq!(
            replay_gate(
                pic,
                Verdict::Indeterminate,
                Some("no-such-rule"),
                false,
                &with(&under)
            ),
            Err("no-such-rule".to_owned())
        );
    }

    /// One placement row: a verdict, a rule, the triple beside them, and where they are placed.
    type Placement = (
        Verdict,
        Option<&'static str>,
        TripleSeen,
        Option<GateReplay>,
    );

    const fn row(
        verdict: Verdict,
        rule: Option<&'static str>,
        triple: TripleSeen,
        placed: Option<GateReplay>,
    ) -> Placement {
        (verdict, rule, triple, placed)
    }

    /// The rows the placement test reads.
    fn placement_rows() -> [Placement; 19] {
        use TripleSeen::{Absent, Discriminating as Disc, Withheld};
        let rule_at = |stage: gating_rule::Stage| -> &'static str {
            gating_rule::ALL
                .iter()
                .find(|r| r.stage == stage)
                .unwrap_or_else(|| panic!("a rule of stage {stage:?}"))
                .id
        };
        let premise = |id: &str| gating_rule::by_id(id).expect("a rule").verdict();
        let other = |v: Verdict| {
            if v == Verdict::On {
                Verdict::Off
            } else {
                Verdict::On
            }
        };
        let lto_rule = gating_rule::LTO_CODEGEN_AT_LINK.id;
        let early = rule_at(gating_rule::Stage::Applicability);
        let level = rule_at(gating_rule::Stage::Level);
        let declared = gating_rule::COMPILER_DECLARED.id;
        let target = rule_at(gating_rule::Stage::Target);
        let twin = rule_at(gating_rule::Stage::Twin);
        let (dis, unreached, over) = (
            Some(GateReplay::Disagrees),
            Some(GateReplay::NotReached),
            Some(GateReplay::Overwritten),
        );
        let (lto, e, lv, dc, tg, tw) = (
            Some(lto_rule),
            Some(early),
            Some(level),
            Some(declared),
            Some(target),
            Some(twin),
        );
        let (p_lto, p_e, p_lv) = (premise(lto_rule), premise(early), premise(level));
        let (p_dc, p_tg, p_tw) = (premise(declared), premise(target), premise(twin));
        let not_e = other(p_e);
        [
            row(Verdict::On, lto, Disc, dis),
            row(Verdict::On, tw, Disc, dis),
            row(not_e, e, Absent, dis),
            row(p_e, e, Absent, unreached),
            row(p_e, e, Disc, dis),
            row(p_e, e, Withheld, dis),
            row(p_dc, dc, Disc, dis),
            row(p_dc, dc, Withheld, None),
            row(p_lv, lv, Withheld, dis),
            row(p_lv, lv, Disc, None),
            row(p_tg, tg, Absent, over),
            row(p_tg, tg, Disc, over),
            row(p_tw, tw, Withheld, over),
            row(Verdict::Indeterminate, None, Absent, unreached),
            row(p_lto, lto, Absent, dis),
            row(p_lto, lto, Withheld, None),
            row(p_lto, lto, Disc, None),
            row(Verdict::On, None, Disc, None),
            row(Verdict::ProbeInvalid, None, Withheld, None),
        ]
    }

    #[test]
    fn a_gating_is_placed_on_the_ladder_by_its_verdict_its_stage_and_the_triple() {
        use TripleSeen::Discriminating;
        let rows = placement_rows();
        let mut placed = 0;
        for (verdict, rule, triple, expected) in rows {
            assert_eq!(
                before_listings(verdict, rule, triple),
                Ok(expected),
                "{verdict:?} {rule:?} {triple:?}"
            );
            placed += 1;
        }
        assert_eq!(placed, 19);
        assert_eq!(
            before_listings(Verdict::Indeterminate, Some("no-such-rule"), Discriminating),
            Err("no-such-rule".to_owned())
        );
    }

    #[test]
    fn the_chain_reads_no_verdict_but_on_partial_and_off() {
        let handler: report::SanitizerWords = Ok(vec![
            "-fsanitize=alignment,enum,shift-base".to_owned(),
            "-fsanitize-trap=alignment,shift-base".to_owned(),
        ]);
        let trapped: report::SanitizerWords = Ok(vec![
            "-fsanitize=enum".to_owned(),
            "-fsanitize-trap=enum".to_owned(),
        ]);
        let overflow: report::SanitizerWords =
            Ok(vec!["-fsanitize=signed-integer-overflow".to_owned()]);
        let under: report::LtoWords = Ok(lto(&["-flto=full"]));
        let san = |w| ProbeListings {
            sanitizers: Some(w),
            ..ProbeListings::default()
        };
        let cases = [
            (check("ubsan-trap-mode"), san(&handler)),
            (check("ubsan-trap-mode"), san(&trapped)),
            (check("no-strict-overflow"), san(&overflow)),
            (check("pic-shared-link"), with(&under)),
        ];
        let stand_in = |v: Verdict| {
            if CHAIN_INPUTS.contains(&v) {
                v
            } else {
                Verdict::Indeterminate
            }
        };
        let mut compared = 0;
        for (c, listings) in &cases {
            for v in Verdict::ALL {
                assert_eq!(
                    chain(c, *v, listings).map(|g| g.rule.id),
                    chain(c, stand_in(*v), listings).map(|g| g.rule.id),
                    "{} {v:?}",
                    c.id
                );
                compared += 1;
            }
        }
        assert_eq!(compared, cases.len() * Verdict::ALL.len());
    }

    #[test]
    fn a_ladder_rule_and_a_swapped_listing_rule_are_held_to_the_chain() {
        let detector = gating_rule::ALL
            .iter()
            .find(|r| r.stage == gating_rule::Stage::Detector)
            .expect("a detector-stage rule");
        assert_eq!(
            replay_gate(
                check("cet-marked"),
                detector.verdict(),
                Some(detector.id),
                false,
                &ProbeListings::default()
            ),
            Ok((GateReplay::Agrees, vec![None]))
        );
        let link = ProbeListings {
            link: Some("its inputs include /srv/x.o"),
            ..ProbeListings::default()
        };
        assert_eq!(
            replay_gate(
                check("cet-marked"),
                detector.verdict(),
                Some(detector.id),
                false,
                &link
            )
            .map(|r| r.0),
            Ok(GateReplay::Disagrees)
        );
        let under: report::LtoWords = Ok(lto(&["-flto=full"]));
        assert_eq!(
            replay_gate(
                check("pic-shared-link"),
                gating_rule::LINK_INPUTS_UNMATCHED.verdict(),
                Some(gating_rule::LINK_INPUTS_UNMATCHED.id),
                false,
                &with(&under)
            )
            .map(|r| r.0),
            Ok(GateReplay::Disagrees)
        );
        let trapped: report::SanitizerWords = Ok(vec![
            "-fsanitize=enum".to_owned(),
            "-fsanitize-trap=enum".to_owned(),
        ]);
        let ubsan = check("ubsan-trap-mode");
        let words = ProbeListings {
            sanitizers: Some(&trapped),
            ..ProbeListings::default()
        };
        assert!(
            chain(ubsan, Verdict::On, &words).is_none(),
            "trapped words do not withhold an on"
        );
        assert_eq!(
            replay_gate(
                ubsan,
                gating_rule::SANITIZER_GROUP_UNMEASURED.verdict(),
                Some(gating_rule::SANITIZER_GROUP_UNMEASURED.id),
                false,
                &words
            )
            .map(|r| r.0),
            Ok(GateReplay::Agrees)
        );
    }

    #[test]
    fn every_listing_rule_fires_through_the_chain_on_a_check_it_holds() {
        let words: report::SanitizerWords = Ok(vec![
            "-fsanitize=alignment,enum,shift-base".to_owned(),
            "-fsanitize-trap=alignment,shift-base".to_owned(),
        ]);
        let overflow: report::SanitizerWords =
            Ok(vec!["-fsanitize=signed-integer-overflow".to_owned()]);
        let under: report::LtoWords = Ok(lto(&["-flto=full"]));
        let said = Some("its inputs include /srv/x.o");
        let clean_reader = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| report::reads_the_clean_link(c))
            .expect("a check reads the clean link");
        let rows: [(&Check, Verdict, ProbeListings<'_>, gating_rule::Rule); 6] = [
            (
                check("cet-marked"),
                Verdict::Off,
                ProbeListings {
                    link: said,
                    ..ProbeListings::default()
                },
                gating_rule::LINK_INPUTS_UNMATCHED,
            ),
            (
                clean_reader,
                Verdict::Off,
                ProbeListings {
                    clean_link: said,
                    ..ProbeListings::default()
                },
                gating_rule::CLEAN_LINK_UNMATCHED,
            ),
            (
                check("fortify-effective"),
                Verdict::Off,
                ProbeListings {
                    compile: said,
                    ..ProbeListings::default()
                },
                gating_rule::COMPILE_INPUTS_UNMATCHED,
            ),
            (
                check("ubsan-trap-mode"),
                Verdict::On,
                ProbeListings {
                    sanitizers: Some(&words),
                    ..ProbeListings::default()
                },
                gating_rule::SANITIZER_GROUP_UNMEASURED,
            ),
            (
                check("no-strict-overflow"),
                Verdict::On,
                ProbeListings {
                    sanitizers: Some(&overflow),
                    ..ProbeListings::default()
                },
                gating_rule::SIGNED_OVERFLOW_SANITIZED,
            ),
            (
                check("pic-shared-link"),
                Verdict::On,
                with(&under),
                gating_rule::LTO_CODEGEN_AT_LINK,
            ),
        ];
        let mut fired = 0;
        for (c, verdict, listings, rule) in &rows {
            assert_eq!(
                chain(c, *verdict, listings).map(|g| g.rule.id),
                Some(rule.id),
                "{}",
                c.id
            );
            fired += 1;
        }
        assert_eq!(fired, LISTING_RULES.len());
    }

    #[test]
    fn a_branching_probes_measurement_beside_a_compile_sentence_is_withheld() {
        let said = Some("its inputs include /srv/x.o");
        let branching = CORPUS
            .iter()
            .filter(|p| crate::measure::branches_on_macros(p.id))
            .flat_map(|p| p.checks)
            .find(|c| c.channel() != Channel::Macro && !c.measures_toolchain_default)
            .expect("a branching probe holds a check off the macro channel");
        let compile = ProbeListings {
            compile: said,
            ..ProbeListings::default()
        };
        let (found, rederived) =
            replay_gate(branching, Verdict::On, None, true, &compile).expect("no rule");
        assert_eq!(
            (found, rederived),
            (
                GateReplay::Disagrees,
                vec![Some(gating_rule::MACRO_SPOOFED.id)]
            ),
            "{}",
            branching.id
        );
        assert_eq!(
            replay_gate(branching, Verdict::On, None, false, &compile).map(|r| r.0),
            Ok(GateReplay::Agrees),
            "a probe that does not branch is not held to the rule"
        );
        // Each other clause of the rule, alone false, leaves the measurement standing.
        let spoofed = Some(gating_rule::MACRO_SPOOFED.id);
        // No branching probe holds a macro-channel check off the compile readings, so the
        // channel and toolchain-default clauses are held on altered copies of the branching
        // check.
        let macro_decoder = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.channel() == Channel::Macro)
            .expect("a macro-channel check")
            .decoder;
        let macro_check = Check {
            decoder: macro_decoder,
            ..*branching
        };
        let toolchain_default = Check {
            measures_toolchain_default: true,
            ..*branching
        };
        let standing = [
            replay_gate(branching, Verdict::Indeterminate, None, true, &compile),
            replay_gate(
                branching,
                gating_rule::MACRO_SPOOFED.verdict(),
                spoofed,
                true,
                &compile,
            ),
            replay_gate(
                branching,
                Verdict::On,
                None,
                true,
                &ProbeListings::default(),
            ),
            replay_gate(&macro_check, Verdict::On, None, true, &compile),
            replay_gate(&toolchain_default, Verdict::On, None, true, &compile),
        ];
        for found in standing {
            assert_eq!(found.map(|r| r.0), Ok(GateReplay::Agrees));
        }
        assert!(crate::measure::branches_on_macros("ubsan-trap"));
        let plain = CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.id == "cet-marked"))
            .expect("a probe holds cet-marked");
        assert!(!crate::measure::branches_on_macros(plain.id));
    }

    #[test]
    fn no_check_is_held_by_two_listing_rules() {
        let own = |ids: Vec<&'static str>| -> Vec<&'static str> {
            ids.into_iter()
                .filter(|id| !check(id).measures_toolchain_default)
                .collect()
        };
        let link = own(report::LINK_INPUT_READINGS.to_vec());
        let clean: Vec<&str> = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| report::reads_the_clean_link(c))
            .map(|c| c.id)
            .collect();
        let compile = own(report::COMPILE_INPUT_READINGS
            .iter()
            .chain(report::EXCEPTION_MODEL_READINGS)
            .copied()
            .collect());
        let sets: [(&str, &[&str]); 6] = [
            ("link", &link),
            ("clean link", &clean),
            ("compile", &compile),
            ("sanitizer group", report::SANITIZER_GROUP_CHECKS),
            ("signed overflow", report::SIGNED_OVERFLOW_SANITIZER_CHECKS),
            ("lto", report::LTO_CODEGEN_CHECKS),
        ];
        for (a, (name_a, set_a)) in sets.iter().enumerate() {
            for (name_b, set_b) in sets.iter().skip(a + 1) {
                for id in *set_a {
                    assert!(
                        !set_b.contains(id),
                        "{id} is held by the {name_a} and the {name_b} rules"
                    );
                }
            }
        }
    }

    #[test]
    fn the_rules_that_move_a_verdict_late_hold_no_check_the_chain_reads_by_verdict() {
        let by_verdict: Vec<&str> = report::SANITIZER_GROUP_CHECKS
            .iter()
            .chain(report::SIGNED_OVERFLOW_SANITIZER_CHECKS)
            .chain(report::LTO_CODEGEN_CHECKS)
            .copied()
            .collect();
        assert!(
            !by_verdict.is_empty(),
            "the checks listed by verdict are not empty, so the loop below checks something"
        );
        let late: Vec<&str> = report::LADDER
            .iter()
            .map(|(id, _)| *id)
            .chain(crate::measure::HELD_BY_INPUT_WITHOUT_TWIN.iter().copied())
            .collect();
        assert!(
            !late.is_empty(),
            "the late checks are not empty, so the loop below checks something"
        );
        for id in &late {
            assert!(
                !by_verdict.contains(id),
                "{id} is moved late and read by verdict"
            );
        }
    }

    #[test]
    fn a_recorded_answer_stands_in_for_the_filesystem_and_a_missing_one_is_named() {
        let mut answers = PathAnswers::default();
        answers
            .resolved
            .insert("/usr/bin/../lib/x".to_owned(), "/usr/lib/x".to_owned());
        answers.directories.insert("/srv/inc".to_owned(), true);
        let recorded = Recorded::new(&answers);
        assert_eq!(recorded.resolved("/usr/bin/../lib/x"), "/usr/lib/x");
        assert!(recorded.is_dir("/srv/inc"));
        assert_eq!(recorded.resolved("/srv/unasked"), "/srv/unasked");
        assert!(!recorded.is_dir("/srv/unasked-dir"));
        assert_eq!(
            recorded.unanswered().into_iter().collect::<Vec<_>>(),
            ["/srv/unasked", "/srv/unasked-dir"]
        );
    }

    #[test]
    fn a_record_out_of_the_comparisons_order_is_malformed() {
        let failed = Asked {
            flags: vec!["-O2".to_owned()],
            answer: Answer::Error("the driver exited 1".to_owned()),
        };
        let read = Asked {
            flags: vec!["-O2".to_owned()],
            answer: Answer::Answer(LinkInputs {
                program: "/usr/bin/ld".to_owned(),
                objects: Vec::new(),
                library_dirs: Vec::new(),
                sysroot: None,
                form: crate::link_inputs::LinkageForm::Pie,
            }),
        };
        let none = PathAnswers::default();
        let paths = Recorded::new(&none);
        let after_failure = Listings {
            link: Some(LinkAsked {
                measured: failed.clone(),
                arms: Some(read.clone()),
            }),
            ..Listings::default()
        };
        assert!(findings(&after_failure, &paths).is_err());
        let missing = Listings {
            link: Some(LinkAsked {
                measured: read,
                arms: None,
            }),
            ..Listings::default()
        };
        assert!(findings(&missing, &paths).is_err());
        let decided = Listings {
            link: Some(LinkAsked {
                measured: failed,
                arms: None,
            }),
            ..Listings::default()
        };
        assert_eq!(
            findings(&decided, &paths).map(|f| f.link),
            Ok(Some(
                "for the measured build, the driver exited 1".to_owned()
            ))
        );
    }

    fn read_inputs() -> CompileInputs {
        CompileInputs {
            programs: vec!["/usr/libexec/cc1".to_owned()],
            headers: vec![("-isystem".to_owned(), "/srv/inc".to_owned())],
            macros: Vec::new(),
            removals: Vec::new(),
            targets: Vec::new(),
            sanitizers: Vec::new(),
            lto: Vec::new(),
            relocation: Vec::new(),
            exception_models: Vec::new(),
        }
    }

    #[test]
    fn a_record_reads_back_as_written_and_an_answer_is_one_of_two() {
        let asked = Asked {
            flags: vec!["-O2".to_owned()],
            answer: Answer::Answer(read_inputs()),
        };
        let record = Listings {
            compile: Some(CompileAsked {
                measured: asked.clone(),
                stand_in: Some(asked.clone()),
                classes: vec![ClassAsked {
                    words: vec!["-O0".to_owned()],
                    listing: Asked {
                        flags: vec!["-O0".to_owned()],
                        answer: Answer::Error("the driver exited 1".to_owned()),
                    },
                }],
            }),
            measured_compile: Some(asked),
            ..Listings::default()
        };
        let text = serde_json::to_string(&record).expect("serializes");
        let back: Listings = serde_json::from_str(&text).expect("reads back");
        assert_eq!(back, record);
        let mut both = serde_json::to_value(&record).expect("a value");
        both["measured_compile"]["error"] = serde_json::Value::from("and an error");
        assert!(serde_json::from_value::<Listings>(both).is_err());
        let mut neither = serde_json::to_value(&record).expect("a value");
        neither["measured_compile"]
            .as_object_mut()
            .expect("an object")
            .remove("answer");
        assert!(serde_json::from_value::<Listings>(neither).is_err());
    }

    #[test]
    fn a_probe_owes_the_comparisons_its_checks_read_under_its_profile() {
        let holding = |id: &str| -> &'static Probe {
            CORPUS
                .iter()
                .find(|p| p.checks.iter().any(|c| c.id == id))
                .unwrap_or_else(|| panic!("a probe holds {id}"))
        };
        let none = Owed {
            link: false,
            clean_link: false,
            compile: false,
            measured_compile: false,
        };
        let clean_reader = CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| report::reads_the_clean_link(c))
            .expect("a check reads the clean link")
            .id;
        let rows: [(&str, bool, Owed); 8] = [
            ("cet-marked", false, Owed { link: true, ..none }),
            ("cet-marked", true, none),
            (
                clean_reader,
                false,
                Owed {
                    clean_link: true,
                    ..none
                },
            ),
            (clean_reader, true, none),
            (
                "fortify-effective",
                false,
                Owed {
                    compile: true,
                    ..none
                },
            ),
            (
                "pic-shared-link",
                true,
                Owed {
                    measured_compile: true,
                    ..none
                },
            ),
            (
                "ubsan-trap-mode",
                true,
                Owed {
                    measured_compile: true,
                    ..none
                },
            ),
            (
                "no-strict-overflow",
                true,
                Owed {
                    measured_compile: true,
                    ..none
                },
            ),
        ];
        for (id, clean, expected) in rows {
            let found = Owed::of(holding(id), clean);
            for (field, owed, held) in [
                ("link", expected.link, found.link),
                ("clean_link", expected.clean_link, found.clean_link),
                ("compile", expected.compile, found.compile),
                (
                    "measured_compile",
                    expected.measured_compile,
                    found.measured_compile,
                ),
            ] {
                // A probe may hold other checks that owe more; what the row names is owed.
                assert!(!owed || held, "{id} clean={clean}: {field} is not owed");
            }
            if clean {
                assert!(!found.link && !found.clean_link && !found.compile, "{id}");
            }
        }
    }

    #[test]
    fn a_record_is_held_to_what_its_probe_owes_both_ways() {
        let lto_probe = CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.id == "pic-shared-link"))
            .expect("a probe holds pic-shared-link");

        let owed = Owed::of(lto_probe, true);
        assert_eq!(
            owed.unmet_by(&Listings::default()),
            ["measured_compile (owed, absent)"]
        );
        let unowed = Listings {
            measured_compile: Some(Asked {
                flags: Vec::new(),
                answer: Answer::Answer(read_inputs()),
            }),
            compile: Some(CompileAsked {
                measured: Asked {
                    flags: Vec::new(),
                    answer: Answer::Error("x".to_owned()),
                },
                stand_in: None,
                classes: Vec::new(),
            }),
            ..Listings::default()
        };
        assert_eq!(
            owed.unmet_by(&unowed),
            ["compile (present, not owed)"],
            "an unowed comparison is named"
        );
    }

    #[test]
    fn every_comparison_out_of_its_order_is_malformed() {
        let link_read = || Asked {
            flags: Vec::new(),
            answer: Answer::Answer(LinkInputs {
                program: "/usr/bin/ld".to_owned(),
                objects: Vec::new(),
                library_dirs: Vec::new(),
                sysroot: None,
                form: crate::link_inputs::LinkageForm::Pie,
            }),
        };
        let failed = || Asked::<LinkInputs> {
            flags: Vec::new(),
            answer: Answer::Error("exited 1".to_owned()),
        };
        let dirs = || Asked {
            flags: Vec::new(),
            answer: Answer::Answer(SearchDirs::default()),
        };
        let clean = |measured, footing, measured_dirs, clean_dirs| Listings {
            clean_link: Some(CleanLinkAsked {
                measured,
                footing,
                measured_dirs,
                clean_dirs,
            }),
            ..Listings::default()
        };
        let none = PathAnswers::default();
        let paths = Recorded::new(&none);
        let malformed = [
            clean(failed(), Some(link_read()), None, None),
            clean(link_read(), None, Some(dirs()), None),
            clean(link_read(), Some(failed()), Some(dirs()), None),
            clean(link_read(), Some(link_read()), None, Some(dirs())),
            Listings {
                compile: Some(CompileAsked {
                    measured: Asked {
                        flags: Vec::new(),
                        answer: Answer::Error("exited 1".to_owned()),
                    },
                    stand_in: Some(Asked {
                        flags: Vec::new(),
                        answer: Answer::Answer(read_inputs()),
                    }),
                    classes: Vec::new(),
                }),
                ..Listings::default()
            },
            Listings {
                compile: Some(CompileAsked {
                    measured: Asked {
                        flags: Vec::new(),
                        answer: Answer::Answer(read_inputs()),
                    },
                    stand_in: None,
                    classes: Vec::new(),
                }),
                ..Listings::default()
            },
        ];
        let mut refused = 0;
        for record in &malformed {
            assert!(findings(record, &paths).is_err(), "{record:?}");
            refused += 1;
        }
        assert_eq!(refused, malformed.len());
        let decided = clean(link_read(), Some(failed()), None, None);
        assert_eq!(
            findings(&decided, &paths).map(|f| f.clean_link),
            Ok(Some("for the clean build's link, exited 1".to_owned()))
        );
    }
}
