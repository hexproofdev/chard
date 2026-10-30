// SPDX-License-Identifier: BSD-3-Clause

//! Verdicts derived from other verdicts, rather than measured.
//!
//! `-fhardened` is an umbrella: GCC 14 introduced it to turn on a fixed set of
//! options at once. Measuring whether the *token* was passed would be close to
//! useless, and would be the mistake this project exists to avoid — what matters is
//! whether the protections it names are in force, however they got there.
//!
//! Both directions of that matter, and they are why this is a reduction rather than a
//! probe:
//!
//!   - A toolchain that sets all eight constituents individually is **effectively**
//!     `-fhardened` even on gcc 13, which has no such option at all. Several
//!     distributions are in exactly this position.
//!   - A build that passes `-fhardened` and then downgrades one constituent is **not**.
//!     GCC itself concedes the point by shipping `-Whardened` to warn when that
//!     happens, and the guide documents that a later `-fstack-protector` silently
//!     weakens the `-fstack-protector-strong` the umbrella asked for.
//!
//! So the composite is an AND-reduction over checks chard already makes, and it is
//! kept out of `observations` on purpose. An observation is something a probe
//! measured; this is arithmetic over those measurements. Publishing them in one list
//! would let a derived cell be read as evidence in its own right, and it is not — it
//! carries exactly the confidence of its weakest constituent.
//!
//! Three-valued AND. A constituent *measured* absent settles the question on its own,
//! since `false AND unknown` is `false`. Only when everything measurable is in force
//! does an unmeasurable constituent make the whole thing `indeterminate` — never `on`.

use serde::{Deserialize, Serialize};

use crate::report::{Observation, Verdict};

/// One requirement of an umbrella option, and how the measurement answered it.
#[derive(Debug, Clone)]
pub struct Constituent {
    /// The flag as the umbrella's own documentation names it.
    pub flag: &'static str,
    /// The chard check consulted for it.
    pub check: &'static str,
    /// Whether this requirement applies here at all. `-fcf-protection=full` is
    /// x86-specific, so on other architectures it is not a shortfall.
    pub applicable: bool,
    /// Absent when the constituent's check is not in this report at all — a filtered
    /// run, or a check gated out. `note` says which; emitting an explicit null would
    /// invite a reader to treat "not asked" as a verdict.
    pub verdict: Option<Verdict>,
    /// The measured level, where the requirement is about strength rather than
    /// presence: fortify's level, relro's `full` versus `partial`, the protector's rule
    /// (`explicit`, `basic`, `strong`, `all`, or `SafeStack`'s `unsafe-frame`, on no rung).
    pub level: Option<String>,
    /// Three-valued, plus inapplicable. `satisfied` alone cannot distinguish a
    /// constituent measured *absent* from one that could not be measured at all, and
    /// this is the block most likely to be read as a summary, so the distinction the
    /// reduction depends on would be the one discarded.
    pub state: ConstituentState,
    ///
    /// Why, when it is not satisfied or not applicable.
    pub note: Option<String>,
    /// A program header in the measured artifact by which the program opts out of what
    /// the constituent's marking asks for. Only `cfi-effective` reads one; see [`OptOut`].
    pub opt_out: Option<OptOut>,
    /// The fortify implementation the slot was read under, where its reading depends on it
    /// (fortify-headers). Only the fortify slot carries one; see
    /// [`FortifyImplementation`].
    pub implementation: Option<FortifyImplementation>,
    /// The bar the fortify slot was held to, where a reading set one: the level
    /// `-fhardened` asks and which reading set it, as a value beside the `note` that names
    /// it in words. Only the fortify slot carries one, and none where no reading
    /// set a bar; see [`FortifyBarReading`].
    pub bar: Option<FortifyBarReading>,
}

/// The program's own opt-out from forward-edge enforcement, read from the artifact the
/// constituent's check measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OptOut {
    /// The program header, as the system that defines it names it.
    pub header: &'static str,
    /// The `facts` key of the artifact carrying it: the cited observation's
    /// `build.artifact_sha256`, so a reader resolves the header from the report alone.
    pub facts: String,
}

/// OpenBSD's name for the header [`crate::elf::ElfFacts::openbsd_nobtcfi`] records.
pub const PT_OPENBSD_NOBTCFI: &str = "PT_OPENBSD_NOBTCFI";

/// The marking checks whose artifact an applicable constituent reads the opt-out from:
/// `cfi-effective`'s constituent on either architecture, and `fhardened-effective`'s CET
/// slot on x86. `report::composite_agrees` holds every applicable constituent citing one of
/// these to name the header its artifact carries.
pub const FORWARD_EDGE_MARKINGS: [&str; 2] = ["cet-marked", "branch-protection-marked"];

/// Every [`OptOut::header`] this revision writes, which the schema's enumeration is pinned
/// to.
pub const OPT_OUT_HEADERS: [&str; 1] = [PT_OPENBSD_NOBTCFI];

impl serde::Serialize for Constituent {
    /// Written by hand so `satisfied` can be *derived* while the JSON keeps carrying it.
    ///
    /// The field order and the `skip_serializing_if` behaviour match what the derive produced, so
    /// this is not a schema change: `level` and `note` stay absent rather than null.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        // `verdict`, `level` and `note` are absent rather than null, as `skip_serializing_if` on
        // a derive writes them. The conformance test holds this, since its schema does not admit
        // a null verdict.
        let fields = [
            self.verdict.is_some(),
            self.level.is_some(),
            self.note.is_some(),
            self.opt_out.is_some(),
            self.implementation.is_some(),
            self.bar.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
        .saturating_add(4);
        let mut out = s.serialize_struct("Constituent", fields)?;
        out.serialize_field("flag", self.flag)?;
        out.serialize_field("check", self.check)?;
        out.serialize_field("applicable", &self.applicable)?;
        if let Some(verdict) = &self.verdict {
            out.serialize_field("verdict", verdict)?;
        }
        if let Some(level) = &self.level {
            out.serialize_field("level", level)?;
        }
        out.serialize_field("state", &self.state)?;
        out.serialize_field("satisfied", &self.satisfied())?;
        if let Some(note) = &self.note {
            out.serialize_field("note", note)?;
        }
        if let Some(opt_out) = &self.opt_out {
            out.serialize_field("opt_out", opt_out)?;
        }
        if let Some(implementation) = &self.implementation {
            out.serialize_field("implementation", implementation)?;
        }
        if let Some(bar) = &self.bar {
            out.serialize_field("bar", bar)?;
        }
        out.end()
    }
}

impl Constituent {
    /// Whether this constituent is confirmed: in force, or marked where its check reads a
    /// marking (see [`ConstituentState::Marked`]).
    ///
    /// A method, not a field. A `satisfied: bool` field beside `state` would be two encodings of
    /// one fact, free to disagree. A `satisfied = !x86`, **true** off x86, beside a
    /// `ConstituentState::of` returning `NotApplicable` gives on any aarch64 host the pair
    /// `satisfied: true, state: NotApplicable`, which fails the consistency rule that compares
    /// them, and `measure` would refuse to publish *any* report, for a reason having nothing to
    /// do with the measurement.
    ///
    /// The JSON carries `satisfied`, written by this crate's `Serialize` impl below, so a
    /// consumer reading it keeps working. It cannot disagree with `state` because there is
    /// nothing to disagree.
    pub fn satisfied(&self) -> bool {
        self.state.is_confirmed()
    }
}

/// How a constituent answered, preserving the difference the reduction turns on. Read back
/// from a report as written by `report::reread_contradictions` (the fortify slot rule), where a
/// spelling outside the four is a subtree that does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConstituentState {
    /// Measured and in force.
    InForce,
    /// Measured and marked: the constituent's check reads a marking the artifact carries
    /// (`cet-marked`, `branch-protection-marked`), by which the program asks the kernel,
    /// CPU and C library for a protection whose enforcement the constituent does not
    /// measure. Confirmed in the reduction as `InForce` is, so an umbrella reads `on` over
    /// it; the note names what the report measured of enforcement (which replaced
    /// `InForce` on the two marking constituents; `DESIGN.md`, "Two umbrellas").
    Marked,
    /// Measured and absent — settles the umbrella on its own.
    Absent,
    /// Could not be established, so the umbrella cannot be confirmed either way: the check
    /// was not measured, or was measured against a premise this run could not settle (an
    /// opt-out header no measured kernel reads, a fortify bar the C library reading does
    /// not set). The constituent's note says which.
    NotEstablished,
    /// Does not apply here, e.g. `-fcf-protection` off x86. Drops out of the reduction.
    NotApplicable,
}

impl ConstituentState {
    /// The spelling serde writes, for a contradiction's claim to quote without a
    /// serialization that could fail; `the_state_spelling_is_the_serialized_one` holds it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InForce => "in-force",
            Self::Marked => "marked",
            Self::Absent => "absent",
            Self::NotEstablished => "not-established",
            Self::NotApplicable => "not-applicable",
        }
    }

    /// Whether the state confirms its constituent: the two measured-and-present states.
    /// Exhaustive, so a state added later must say which side it is on here, and the
    /// reduction and the composite rule, which read this, decide it rather than confirm
    /// it by default (an assurance review).
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        match self {
            Self::InForce | Self::Marked => true,
            Self::Absent | Self::NotEstablished | Self::NotApplicable => false,
        }
    }

    fn of(applicable: bool, satisfied: bool, verdict: Option<Verdict>) -> Self {
        if !applicable {
            return Self::NotApplicable;
        }
        if satisfied {
            return Self::InForce;
        }
        // Absence is only claimed when something was actually measured. Anything else
        // — probe-invalid, indeterminate, a check missing from the report — is unknown,
        // and calling it absent is the error this enum exists to prevent.
        if verdict.is_some_and(Verdict::is_measurement) {
            Self::Absent
        } else {
            Self::NotEstablished
        }
    }

    /// [`Self::of`] for a marking check: where a presence check would be in force, a
    /// marking is `Marked`, since what the check read is the program's request and not
    /// its enforcement. The other three states are the same.
    pub(crate) fn of_marking(applicable: bool, satisfied: bool, verdict: Option<Verdict>) -> Self {
        match Self::of(applicable, satisfied, verdict) {
            Self::InForce => Self::Marked,
            other => other,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Composite {
    pub id: &'static str,
    pub title: &'static str,
    /// Named so no reader mistakes this for a measurement.
    pub derived_from: Vec<&'static str>,
    pub verdict: Verdict,
    pub constituents: Vec<Constituent>,
    pub reason: String,
}

/// Was this observation withheld because a witness contradicted the architecture its
/// arch gate read, or the width and byte order that architecture stands for? See
/// `report::withhold_on_contradicted_target`.
fn target_contradicted(o: &Observation) -> bool {
    use crate::report::gating_rule::{TARGET_ABI_CONTRADICTED, TARGET_CONTRADICTED};
    o.gating
        .as_ref()
        .is_some_and(|g| g.rule == TARGET_CONTRADICTED || g.rule == TARGET_ABI_CONTRADICTED)
}

/// Look up a check's verdict and level among the measured observations.
fn find<'a>(obs: &'a [Observation], check: &str) -> Option<&'a Observation> {
    obs.iter().find(|o| o.check == check)
}

/// An observation as the fortify slot reads it: the four fields its derivation turns on.
///
/// One derivation, two callers. [`fortify_constituent`] runs over the typed observations
/// `measure` holds, and `report::reread_contradictions` runs it again over the
/// observations a report is read back as, so the consistency rule
/// `fhardened-fortify-slot-disagrees-with-inputs` holds the published slot to the same
/// function at publication and on read, and no second reading of the bar exists to drift
/// from the first. [`ssp_constituent`] and its rule
/// `fhardened-ssp-slot-disagrees-with-input` have the same two callers.
pub(crate) trait SlotObservation {
    fn check(&self) -> &str;
    fn verdict(&self) -> Verdict;
    fn level(&self) -> Option<&str>;
    /// `evidence.decoded.clause`, the deciding clause of a predicate-decoded check, by
    /// which [`fortify_headers_reading`] tells a fortify-headers build.
    fn deciding_clause(&self) -> Option<&str>;
}

impl SlotObservation for Observation {
    fn check(&self) -> &str {
        &self.check
    }
    fn verdict(&self) -> Verdict {
        self.verdict
    }
    fn level(&self) -> Option<&str> {
        self.level.as_deref()
    }
    fn deciding_clause(&self) -> Option<&str> {
        self.evidence.decoded.as_ref().map(|d| d.clause.as_str())
    }
}

/// [`find`] over any observations the fortify and protector slots read.
fn find_slot_input<'a, O: SlotObservation>(obs: &'a [O], check: &str) -> Option<&'a O> {
    obs.iter().find(|o| o.check() == check)
}

/// Does a fortify level string meet `want`?
///
/// Levels arrive as the string glibc settled on, so `"3"` and `"2"` rather than a
/// number. Anything unparseable is treated as not meeting the bar, which is the
/// conservative direction. The consistency rule's statement over a published level and bar
/// reads it through this one predicate.
pub(crate) fn fortify_meets(level: Option<&str>, want: u32) -> bool {
    level
        .and_then(|l| l.trim().parse::<u32>().ok())
        .is_some_and(|n| n >= want)
}

/// The glibc `(major, minor)` the C library reading establishes, or `None` where it
/// establishes none.
///
/// [`FHARDENED_FORTIFY`]'s threshold is a glibc version, so only a glibc whose major and
/// minor were both read can be placed against it: a glibc with no version, or with a bare or
/// unparseable minor, places none, and a bare `2` is not read as 2.0. A musl's `1.2.6` is
/// another scale, never a smaller glibc (read as one, it publishes "needs level >= 2 on
/// glibc 1.2.6" about a musl system); [`fortify_bar`] reads musl by name instead.
fn established_glibc(libc: &crate::env::Libc) -> Option<(u32, u32)> {
    if libc.impl_name != "glibc" {
        return None;
    }
    let mut parts = libc.version.as_deref()?.trim().split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    // The minor's leading digits, so a packaging suffix (`2.39-r2`) still reads as 2.39; a
    // bare `2` or a `2.x` establishes no minor, and is not read as 2.0.
    let minor = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse::<u32>()
        .ok()?;
    Some((major, minor))
}

/// The fortify level `-fhardened` asks on this toolchain, and the reading it rests on as the
/// note names it; or, where nothing sets the bar, why not.
///
/// gcc picks the level in `linux_fortify_source_default_level` (gcc/config/linux.cc, read at
/// trunk 2026-10-15): 3 where it was configured for glibc 2.35 or later, 2 for any other
/// Linux library. What gcc was configured for is not what the headers say. On Fedora 44,
/// `musl-gcc` (gcc 16.1.1 behind musl's headers, `-dumpmachine` `x86_64-redhat-linux`)
/// defines `_FORTIFY_SOURCE 3` under `-fhardened -O2`, while Alpine's gcc 15.2.0
/// (`x86_64-alpine-linux-musl`) defines 2 (both measured 2026-10-20). So the headers'
/// library and the target triple, the one record chard keeps of gcc's configured library,
/// must agree before either sets the bar:
///
/// - a glibc [`established_glibc`] places, under a triple that names no musl, gets
///   `rule.level` or `rule.fallback` by its version;
/// - musl, identified by its own `__NEED_*` header guards (`env::detect_libc`), under a
///   triple that names musl, gets `rule.fallback` whatever its version: musl is a library
///   the rule names, not a gap in it;
/// - anything else sets none: musl headers under a glibc-configured driver, a glibc under a
///   musl triple, a glibc with no major and minor, an OpenBSD, an `unknown`, a musl whose
///   triple was not read.
///
/// An unplaced reading sets no bar. Holding it to the fallback would be the conservative
/// direction for a shortfall and not for the umbrella, whose question is "effectively
/// `-fhardened`", and a bar chard cannot set is not a bar met. The glibc arm places a glibc
/// under a triple that was not read by its version, and says in the reading that the triple
/// was not read.
///
/// This is the second reading, taken only where the driver does not offer `-fhardened`
/// ([`fhardened_bar`]).
pub(crate) fn fortify_bar(
    libc: &crate::env::Libc,
    target_triple: Option<&str>,
    rule: FortifyRule,
) -> Result<(u32, String), String> {
    let musl_triple = target_triple.is_some_and(names_musl);
    match (
        established_glibc(libc),
        libc.impl_name.as_str(),
        target_triple,
    ) {
        (Some(version), _, _) if !musl_triple => {
            let want = if version >= rule.glibc {
                rule.level
            } else {
                rule.fallback
            };
            // The acceptance of a glibc under a triple that was not read is carried in the
            // reading, so the note says what the bar was set without.
            let unread = if target_triple.is_none() {
                "; toolchain.target_triple not read"
            } else {
                ""
            };
            Ok((want, format!("glibc {}.{}{unread}", version.0, version.1)))
        }
        (_, "musl", _) if musl_triple => Ok((rule.fallback, library_reading(libc))),
        (Some(_), _, Some(triple)) => Err(format!(
            "environment.libc reads {} under toolchain.target_triple {triple}, a driver \
             configured for musl",
            library_reading(libc)
        )),
        (_, "musl", Some(triple)) => Err(format!(
            "environment.libc reads {} under toolchain.target_triple {triple}, which names \
             no driver configured for musl",
            library_reading(libc)
        )),
        (_, "musl", None) => Err(format!(
            "environment.libc reads {} and toolchain.target_triple was not read, so it is \
             not established that the driver is configured for musl",
            library_reading(libc)
        )),
        _ => Err(format!(
            "environment.libc reads {}, which names neither musl nor a glibc major and minor",
            library_reading(libc)
        )),
    }
}

/// The bar a fortify slot is held to, and the reading that set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FortifyBar {
    /// The level asked.
    pub want: u32,
    /// Where it was asked, as the note's "needs level >= N ..." continues: `by the driver's
    /// -fhardened -O2 dump` or `on glibc 2.43`.
    pub on: String,
    /// Why the library set the bar rather than the driver, appended to the note; empty where
    /// the driver set it.
    pub because: String,
    /// Which reading set it, as the slot publishes it.
    pub source: BarSource,
}

/// Which reading set a fortify slot's bar: the driver's own `-fhardened -O2` dump, or the
/// C library and target triple where the dump did not answer ([`fhardened_bar`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BarSource {
    Driver,
    Library,
}

impl BarSource {
    /// Every source this revision writes, in the schema's order.
    pub const ALL: [Self; 2] = [Self::Driver, Self::Library];

    /// The spelling serde writes, for a contradiction's claim to quote.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Driver => "driver",
            Self::Library => "library",
        }
    }
}

/// Every [`BarSource`] spelling this revision writes, spelled from [`BarSource::ALL`] so
/// the two cannot disagree, which the schema's enumeration is pinned to
/// (`tests/schema_conformance.rs`).
pub const BAR_SOURCES: [&str; 2] = [BarSource::ALL[0].as_str(), BarSource::ALL[1].as_str()];

/// The bar a fortify slot was held to, published on `fhardened-effective`'s fortify slot
/// beside the `note` that names it in words, so a reader holds the slot to its bar without
/// parsing prose: the consistency rule `fhardened-fortify-slot-disagrees-with-inputs`
/// recomputes the slot from the inputs the report publishes and compares this value, at
/// publication and on read. Absent where no reading set a bar, which the note
/// then says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FortifyBarReading {
    /// The level asked ([`FortifyBar::want`]).
    pub level: u32,
    /// Which reading set it.
    pub source: BarSource,
}

/// The fortify level `-fhardened` asks on this toolchain, read from the driver itself where it
/// offers the option, and from the library only where it does not.
///
/// Where the dump answers ([`crate::toolchain::FhardenedFortify::refusal`] names nothing), the
/// bar is the `_FORTIFY_SOURCE` it defined, whatever the headers name: gcc's own choice, so a
/// cross or an in-place upgrade where the configured glibc and the headers differ reads the
/// level the driver asks. A dump that defined no level, a level that is not an integer, or one
/// outside `rule.fallback..=rule.level` (gcc's `-fhardened` asks no other level on any library,
/// so another was set by something besides the option) sets no bar: the reading is neither
/// lowered nor raised to whatever the driver printed.
///
/// Where it does not answer (clang; gcc before 14; a target gcc does not support it for; a
/// driver whose own `-D` overrode it; one that defines the level whatever is asked),
/// [`fortify_bar`]'s library reading stands, and the note says why the driver's did not.
pub(crate) fn fhardened_bar(
    driver: &crate::toolchain::FhardenedFortify,
    libc: &crate::env::Libc,
    target_triple: Option<&str>,
    rule: FortifyRule,
) -> Result<FortifyBar, String> {
    const DUMP: &str = "the driver's -fhardened -O2 dump";
    let Some(refusal) = driver.refusal() else {
        let Some(value) = driver.fortify_source.as_deref() else {
            return Err(format!("{DUMP} defined no _FORTIFY_SOURCE"));
        };
        return match value.trim().parse::<u32>() {
            Ok(want) if (rule.fallback..=rule.level).contains(&want) => Ok(FortifyBar {
                want,
                on: format!("by {DUMP}"),
                because: String::new(),
                source: BarSource::Driver,
            }),
            Ok(level) => Err(format!(
                "{DUMP} defines _FORTIFY_SOURCE {level}, outside the levels {} to {} \
                 -fhardened asks on any library, so something besides the option set it",
                rule.fallback, rule.level
            )),
            Err(_) => Err(format!(
                "{DUMP} defines _FORTIFY_SOURCE as `{value}`, which is not a level"
            )),
        };
    };
    match fortify_bar(libc, target_triple, rule) {
        Ok((want, on)) => Ok(FortifyBar {
            want,
            on: format!("on {on}"),
            because: format!("; the library sets the bar because {refusal}"),
            source: BarSource::Library,
        }),
        Err(unset) => Err(format!("{unset}, and {refusal}")),
    }
}

/// Does a target triple name musl as its environment (`x86_64-alpine-linux-musl`,
/// `arm-linux-musleabihf`, `x86_64-linux-muslx32`)?
fn names_musl(triple: &str) -> bool {
    triple
        .split('-')
        .skip(1)
        .any(|part| part.starts_with("musl"))
}

/// The C library reading as a note names it: `musl 1.2.6`, `unknown (no version)`.
fn library_reading(libc: &crate::env::Libc) -> String {
    match libc.version.as_deref() {
        Some(v) => format!("{} {v}", libc.impl_name),
        None => format!("{} (no version)", libc.impl_name),
    }
}

/// Fortify is the one constituent judged on strength rather than presence, and the
/// bar moves with the libc: GCC drops the umbrella's request from level 3 to 2 below
/// glibc 2.35, where `__builtin_dynamic_object_size` is unavailable, and asks 2 on musl.
///
/// The bar is the one [`fortify_bar`] sets, and none where it sets none. There a level
/// meeting `rule.level` meets either bar and is in force, one measured under
/// `rule.fallback` meets neither and is absent, and one between the two, or none measured,
/// is `not-established` with a note naming the readings that left the bar unset.
///
/// On fortify-headers a level is met where it was requested ([`fortify_headers_reading`]): the
/// library enforces level 1 whatever was asked, which is the highest rung it implements, so a
/// request that reached it is in force as far as the library can take it.
///
/// The one derivation of the slot. [`fhardened_constituents`] runs it at measure, and the
/// consistency rule `fhardened-fortify-slot-disagrees-with-inputs` (`report.rs`) runs it
/// again over the inputs the report publishes, at publication and on read, and refuses a
/// slot that disagrees; that is why it takes any [`SlotObservation`] rather
/// than leaving the rule a second reading of the bar to drift from this one.
pub(crate) fn fortify_constituent<O: SlotObservation>(
    obs: &[O],
    rule: FortifyRule,
    driver: &crate::toolchain::FhardenedFortify,
    libc: &crate::env::Libc,
    target_triple: Option<&str>,
) -> Constituent {
    let o = find_slot_input(obs, "fortify-effective");
    let implementation = fortify_headers_reading(obs);
    let requested = implementation
        .as_ref()
        .and_then(|i| i.requested_level.as_deref());
    let level = slot_fortify_level(obs);
    let measured = level.as_deref().unwrap_or("nothing");
    // `On` *or* `Partial`, and the difference is the umbrella's whole question. A
    // check's `on` is graded against its own `recommended_level`, which for
    // `fortify-effective` is 3, so demanding `On` here would silently re-impose level 3 for
    // every value of `want`, and the glibc<2.35 lowering to 2 just above could never
    // take effect. A fortify measured in force at exactly the level this umbrella asks
    // for would be published as `state: absent` and subtracted from the composite, on
    // Ubuntu 20.04, Debian 11 and the AlmaLinux 8 and 9 lines among others.
    let in_force = o.is_some_and(|o| matches!(o.verdict(), Verdict::On | Verdict::Partial));
    let meets = |want| {
        in_force && (fortify_meets(level.as_deref(), want) || fortify_meets(requested, want))
    };
    let verdict = o.map(SlotObservation::verdict);
    let (established, withheld_note) = withheld_request(obs, implementation.as_ref(), verdict);
    let (state, note, bar) = match fhardened_bar(driver, libc, target_triple, rule) {
        Ok(FortifyBar {
            want,
            on,
            because,
            source,
        }) => {
            let satisfied = meets(want);
            // Every reading names the bar's source in the constituent's note, in force or not.
            let note = if !satisfied {
                format!("needs level >= {want} {on}; measured {measured}{withheld_note}{because}")
            } else if let Some(r) = requested.filter(|_| !fortify_meets(level.as_deref(), want)) {
                // Met by the request alone: say so, since the level beside it is lower.
                format!("{}{because}", top_rung_note(r, want, &on))
            } else {
                format!("in force: level >= {want} {on}; measured {measured}{because}")
            };
            (
                ConstituentState::of(true, satisfied, established),
                Some(note),
                Some(FortifyBarReading {
                    level: want,
                    source,
                }),
            )
        }
        Err(unset) => {
            let (major, minor) = rule.glibc;
            let state = ConstituentState::of(true, meets(rule.level), established);
            let note = if meets(rule.level) {
                Some(if fortify_meets(level.as_deref(), rule.level) {
                    format!("in force: measured level {measured} meets either bar, and {unset}")
                } else {
                    format!(
                        "{}, and {unset}",
                        top_rung_note(
                            requested.unwrap_or("nothing"),
                            rule.level,
                            "whichever bar applies",
                        )
                    )
                })
            } else if meets(rule.fallback) {
                // The level or, on fortify-headers, the request is what meets the lower bar.
                let reading = match requested {
                    Some(r) if !fortify_meets(level.as_deref(), rule.fallback) => {
                        format!("fortify-headers' requested level {r}")
                    }
                    _ => format!("measured level {measured}"),
                };
                Some(format!(
                    "not established: {reading} meets the level {} asked below glibc \
                     {major}.{minor} and on musl and not the level {} asked from glibc \
                     {major}.{minor}, and {unset}",
                    rule.fallback, rule.level
                ))
            } else if state == ConstituentState::Absent {
                Some(format!(
                    "needs level >= {} whichever bar applies ({} below glibc {major}.{minor} \
                     and on musl, {} from glibc {major}.{minor}); measured {measured}; \
                     {unset}",
                    rule.fallback, rule.fallback, rule.level
                ))
            } else {
                // Nothing was measured, or the request that decides the bar was withheld,
                // so no requirement is stated against it.
                Some(format!(
                    "not established: fortify-effective {}{withheld_note}; {unset}",
                    verdict.map_or("is not present in this report", |v| v.as_str())
                ))
            };
            // A level between the bars is the one the unset bar decides.
            let state = if meets(rule.fallback) && !meets(rule.level) {
                ConstituentState::NotEstablished
            } else {
                state
            };
            (state, note, None)
        }
    };
    Constituent {
        flag: "-D_FORTIFY_SOURCE",
        check: "fortify-effective",
        applicable: true,
        verdict,
        level,
        state,
        opt_out: None,
        implementation,
        bar,
        note,
    }
}

/// The level `fortify-effective` measured, as the slot copies it: the one reading of it,
/// shared with the consistency rule's read side where no driver's record lets the slot be
/// recomputed and the level is held on its own. (`report::measured_fortify_level` is the
/// ratchet's number; this is the slot's string.)
pub(crate) fn slot_fortify_level<O: SlotObservation>(obs: &[O]) -> Option<String> {
    find_slot_input(obs, "fortify-effective").and_then(|o| o.level().map(str::to_owned))
}

/// The note of a fortify slot met by fortify-headers' request rather than its level.
fn top_rung_note(requested: &str, want: u32, on: &str) -> String {
    format!(
        "in force at fortify-headers' top rung: level {requested} requested against \
         level >= {want} {on}, enforced as level {FORTIFY_HEADERS_TOP_LEVEL}, the highest \
         fortify-headers implements (its checks never ask a subobject's bounds)"
    )
}

/// The name a fortify slot's `implementation` publishes for fortify-headers, whichever of
/// `fortify-effective`'s level clauses decided the reading.
pub const FORTIFY_HEADERS_IMPLEMENTATION: &str = "fortify-headers";

/// The highest fortify level fortify-headers implements, by construction: its wrappers never
/// ask a subobject's bounds, which is what level 2 adds (`predicate::macro_channel`'s
/// `fortify-effective` ladder).
pub const FORTIFY_HEADERS_TOP_LEVEL: &str = "1";

/// The C library fortify implementation a fortify slot was read under, published where the
/// slot's reading depends on it: fortify-headers, whose level is not the level requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FortifyImplementation {
    /// The implementation `fortify-effective`'s deciding clause identifies.
    pub name: &'static str,
    /// The highest level it implements ([`FORTIFY_HEADERS_TOP_LEVEL`]).
    pub top_level: &'static str,
    /// The level `fortify-requested` read, verbatim; absent where that check read none in
    /// force (not in the report, withheld, or no request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_level: Option<String>,
}

/// The note a fortify slot carries where the request that decides its bar was withheld.
const WITHHELD_NOTE: &str =
    "; the request's level is withheld, so whether it reaches the bar is not established";

/// The verdict a fortify slot may claim absence from, and the note it carries: `verdict`
/// and none, unless the request that decides a fortify-headers bar was withheld rather
/// than measured, which is none and [`WITHHELD_NOTE`]. On fortify-headers the request is
/// what meets the bar, since the library's own rung is 1 whatever was asked, so a request
/// withheld leaves the slot not established: `absent` there would read a request chard
/// could not read as no request (`-D_FORTIFY_SOURCE=(3)` reads `fortify-requested`
/// `indeterminate` beside the library's level 1). A request measured `off` keeps the
/// absence it earned, and on another implementation the request decides nothing.
fn withheld_request<O: SlotObservation>(
    obs: &[O],
    implementation: Option<&FortifyImplementation>,
    verdict: Option<Verdict>,
) -> (Option<Verdict>, &'static str) {
    let withheld = implementation.is_some()
        && find_slot_input(obs, "fortify-requested").is_some_and(|r| !r.verdict().is_measurement());
    if withheld {
        (None, WITHHELD_NOTE)
    } else {
        (verdict, "")
    }
}

/// The fortify-headers reading, where `fortify-effective`'s measured build was decided by one
/// of the predicate's fortify-headers clauses, with the level `fortify-requested` read beside
/// it.
///
/// The request counts only where `fortify-requested` is itself in force (`on` or `partial`): a
/// withheld or `off` request is no level reaching the library.
pub(crate) fn fortify_headers_reading<O: SlotObservation>(
    obs: &[O],
) -> Option<FortifyImplementation> {
    use crate::predicate::macro_channel::FORTIFY_HEADERS_CLAUSES;
    let decided = find_slot_input(obs, "fortify-effective")?.deciding_clause()?;
    FORTIFY_HEADERS_CLAUSES
        .contains(&decided)
        .then(|| FortifyImplementation {
            name: FORTIFY_HEADERS_IMPLEMENTATION,
            top_level: FORTIFY_HEADERS_TOP_LEVEL,
            requested_level: find_slot_input(obs, "fortify-requested")
                .filter(|r| matches!(r.verdict(), Verdict::On | Verdict::Partial))
                .and_then(|r| r.level().map(str::to_owned)),
        })
}

/// Decide the `-ftrivial-auto-var-init=zero` requirement from its two sub-verdicts.
///
/// Pure, and separated out because the rule is subtle enough to be worth testing on
/// its own. The umbrella wants zero-initialization specifically, which chard measures
/// as two checks: is initialization active at all, and is the fill the pattern byte.
///
/// The trap is that "not pattern" must mean *measured* not-pattern. An unmeasurable
/// pattern check collapses to `false`, and `false` is the value that grants
/// satisfaction — so the mode has to be established, not merely un-refuted. Returns
/// the verdict to publish alongside, which downgrades to `indeterminate` when
/// initialization is active but the mode is unknown, so the reduction treats it as
/// unmeasured rather than as a shortfall.
fn zero_init_decision(
    active: Option<Verdict>,
    pattern: Option<Verdict>,
) -> (bool, Option<Verdict>) {
    let is_active = active == Some(Verdict::On);
    let is_pattern = pattern == Some(Verdict::On);
    let mode_known = pattern.is_some_and(Verdict::is_measurement);
    let satisfied = is_active && mode_known && !is_pattern;
    let verdict = match (active, mode_known) {
        (Some(Verdict::On), false) => Some(Verdict::Indeterminate),
        (v, _) => v,
    };
    (satisfied, verdict)
}

/// Control-flow protection, which the umbrella names only in its x86 spelling.
///
/// On any other architecture this is not a shortfall — the equivalent there is
/// `-mbranch-protection`, which `-fhardened` does not enable — so the constituent is
/// marked inapplicable rather than unsatisfied, and drops out of the reduction.
///
/// Nothing takes its place *here*, and that is the point: substituting
/// `branch-protection-marked` into this slot would report an aarch64 build compiled with
/// `-fhardened` as falling short of `-fhardened`, which the umbrella never promised. The
/// cross-architecture question belongs to [`cfi`], which asks it without pretending the
/// answer is part of this set.
///
/// On x86 the slot reads the program's own opt-out the way [`cfi_constituent`] does, and through
/// the same [`opted_out_constituent`]: `-fcf-protection=full` marks IBT and SHSTK, and an artifact
/// carrying `PT_OPENBSD_NOBTCFI` asks for the forward edge not to be enforced, so a marking read
/// `on` beside it is not the umbrella's member confirmed. A slot that did not read the header would
/// let the two composites disagree about one artifact: `cfi-effective` `off` or `indeterminate`,
/// this slot `in-force`. The argument for `absent` over withholding is [`cfi_constituent`]'s, and
/// on OpenBSD amd64 it rests on the same registered assumption,
/// `nobtcfi-switches-off-ibt-on-amd64`. Off x86 the slot is inapplicable whatever the artifact
/// carries, so the header is not read there.
fn cet_constituent(
    obs: &[Observation],
    arch: &str,
    libc: &crate::env::Libc,
    facts: &crate::report::FactStore,
) -> Constituent {
    let o = find(obs, "cet-marked");
    // Whether the slot applies is the arch gate's own question, so where a witness in
    // toolchain.target contradicted the architecture it was asked about, the slot is held
    // applicable and unestablished rather than dropped on that premise.
    let contradicted = o.is_some_and(target_contradicted);
    let x86 = matches!(arch, "x86_64" | "x86" | "i686") || contradicted;
    let satisfied = !x86 || o.is_some_and(|o| o.verdict == Verdict::On);
    if x86 && let Some(opt_out) = measured_opt_out(o, facts) {
        return opted_out_constituent(
            "-fcf-protection=full",
            "cet-marked",
            o,
            satisfied,
            opt_out,
            libc,
        );
    }
    Constituent {
        flag: "-fcf-protection=full",
        check: "cet-marked",
        applicable: x86,
        verdict: o.map(|o| o.verdict),
        level: o.and_then(|o| o.level.clone()),
        state: ConstituentState::of_marking(x86, satisfied, o.map(|o| o.verdict)),
        opt_out: None,
        implementation: None,
        bar: None,
        note: if contradicted {
            Some(format!(
                "not established: a witness contradicts {arch}, the architecture \
                 cet-marked was gated on (toolchain.target)"
            ))
        } else if x86 {
            // The measured verdict, not a summary of it: "no CET markings" stood here for
            // every shortfall, and OpenBSD 7.9 amd64's `partial` (IBT marked, SHSTK not)
            // and a withheld `probe-invalid` read as an artifact with no marking at all.
            // A marking `on` is the `marked` state, and its note says what that is.
            Some(if satisfied {
                marked_note("-fcf-protection=full", obs, arch, libc, false)
            } else {
                match o.map(|o| o.verdict) {
                    Some(Verdict::Off) => "no CET markings in the artifact".to_owned(),
                    Some(v) => format!("cet-marked measured {}", v.as_str()),
                    None => "cet-marked is not present in this report".to_owned(),
                }
            })
        } else {
            Some(format!(
                "not applicable on {arch}: control-flow protection here is \
                 -mbranch-protection, which the umbrella does not name; the \
                 `cfi-effective` composite answers it for this architecture"
            ))
        },
    }
}

/// The flags of the `-fhardened` set as [`fhardened_constituents`] spells them, in the
/// order it builds them.
///
/// One list: the unit test `the_umbrella_reduces_over_exactly_the_published_flag_list`
/// holds the constituents' `flag` fields to it on x86_64 and aarch64, and
/// `tests/fhardened_set.rs` holds it to the host gcc's `--help=hardened`. The fortify slot
/// carries no level because the level is picked at run time from the C library and target
/// triple by [`fortify_bar`] under [`FHARDENED_FORTIFY`]; the
/// CET slot is applicable on x86 only (see [`cet_constituent`]). gcc prints the CET line on
/// aarch64 too (16.2.1, Fedora 44, under qemu-user), although `-fhardened` does not apply it
/// there, so the list keeps the slot on every target and the composite marks it inapplicable.
pub const FHARDENED_FLAGS: [&str; 8] = [
    "-D_FORTIFY_SOURCE",
    "-D_GLIBCXX_ASSERTIONS",
    "-fPIE -pie",
    "-fstack-protector-strong",
    "-fstack-clash-protection",
    "-Wl,-z,relro -Wl,-z,now",
    "-ftrivial-auto-var-init=zero",
    "-fcf-protection=full",
];

/// The fortify level `-fhardened` asks for, as `gcc --help=hardened` states it on 16.1.1:
/// `-D_FORTIFY_SOURCE=3 (or =2 for glibc < 2.35)`.
///
/// [`fhardened_constituents`] picks its bar from these three numbers and the C library
/// reading, and sets none where that reading names neither musl nor a glibc version (see
/// [`fortify_bar`]); `tests/fhardened_set.rs` formats gcc's fortify line from them,
/// so a change to the composite's rule and a change to gcc's text both fail that test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FortifyRule {
    /// The level asked for on a glibc at or above `glibc`.
    pub level: u32,
    /// The level asked for on a glibc below `glibc`, and on musl (see [`fortify_bar`]). A
    /// library reading that names neither sets no bar (see [`fortify_constituent`]).
    pub fallback: u32,
    /// The glibc `(major, minor)` from which `level` applies.
    pub glibc: (u32, u32),
}

/// The rule [`fhardened_constituents`] applies to the fortify slot of [`FHARDENED_FLAGS`].
pub const FHARDENED_FORTIFY: FortifyRule = FortifyRule {
    level: 3,
    fallback: 2,
    glibc: (2, 35),
};

// [`fortify_constituent`]'s unset-bar arm reads a level meeting `level` as meeting either bar
// and one under `fallback` as meeting neither, which holds only where the fallback is lower.
const _: () = assert!(FHARDENED_FORTIFY.fallback < FHARDENED_FORTIFY.level);

/// The set GCC means by `-fhardened`, as reported by `gcc --help=hardened` on 16.1.1.
///
/// Nine lines of output reduce to eight constituents here, because `-Wl,-z,relro` and
/// `-Wl,-z,now` are one chard check (`relro`, whose level distinguishes them).
///
/// Transcribed by hand from the compiler's own output rather than from documentation,
/// because the guide warns the set "may change between major releases of GCC". chard
/// does not run `--help=hardened` at run time: this list is a constant, and the only
/// run-time input is the C library reading that picks the fortify level, or, where it names
/// neither musl nor a glibc version, withholds the fortify slot (see [`fortify_bar`]). If a
/// future release adds a constituent, this list is wrong in the direction of claiming too
/// much, which is the direction that matters. `tests/fhardened_set.rs` re-reads it against the host
/// gcc's `--help=hardened` on every run where an x86_64 or aarch64 Linux gcc 14 or later is
/// on `PATH`, and
/// fails on a line either side lacks; the flag spellings it compares are
/// [`FHARDENED_FLAGS`].
fn fhardened_constituents(
    obs: &[Observation],
    arch: &str,
    driver: &crate::toolchain::FhardenedFortify,
    libc: &crate::env::Libc,
    target_triple: Option<&str>,
    facts: &crate::report::FactStore,
) -> Vec<Constituent> {
    // The umbrella asks for level 3, but drops to 2 below glibc 2.35 because
    // __builtin_dynamic_object_size support is not there, and asks 2 on musl. Reproducing
    // that conditional is the difference between measuring the guide's recommendation and
    // measuring GCC's actual behaviour; we want the latter. The driver says which where it
    // offers the option, and `fortify_bar` reads it from the library where it does not.
    let mut constituents = vec![fortify_constituent(
        obs,
        FHARDENED_FORTIFY,
        driver,
        libc,
        target_triple,
    )];

    // The presence-only requirements, and between them the protector's, which is graded.
    for (flag, check) in [
        ("-D_GLIBCXX_ASSERTIONS", "cxx-stdlib-assertions"),
        ("-fPIE -pie", "pie"),
    ] {
        constituents.push(presence_constituent(obs, flag, check));
    }
    constituents.push(ssp_constituent(obs));
    constituents.push(presence_constituent(
        obs,
        "-fstack-clash-protection",
        "stack-clash-guard-page",
    ));

    // relro must be *full*: the umbrella asks for -Wl,-z,relro AND -Wl,-z,now, and
    // chard's single relro check reports `partial` when only the first is in force.
    {
        let o = find(obs, "relro");
        let level = o.and_then(|o| o.level.clone());
        let satisfied =
            o.is_some_and(|o| o.verdict == Verdict::On) && level.as_deref() == Some("full");
        constituents.push(Constituent {
            flag: "-Wl,-z,relro -Wl,-z,now",
            check: "relro",
            applicable: true,
            verdict: o.map(|o| o.verdict),
            level: level.clone(),
            state: ConstituentState::of(true, satisfied, o.map(|o| o.verdict)),
            opt_out: None,
            implementation: None,
            bar: None,
            note: (!satisfied).then(|| {
                format!(
                    "needs full relro (relro + bindnow); measured {}",
                    level.as_deref().unwrap_or("nothing")
                )
            }),
        });
    }

    // Auto-var-init, specifically =zero. chard measures "initialization is active"
    // and "the fill is the pattern byte" separately, so zero is the conjunction of
    // active and not-pattern. A `pattern` build is hardened, but it is not what this
    // umbrella specifies, and silently accepting it would overstate the match.
    {
        let active = find(obs, "auto-var-init-active");
        let pattern = find(obs, "auto-var-init-pattern");
        // See `zero_init_decision`: the fill mode must be *established*, not merely
        // un-refuted. The hole this closes is reachable wherever `auto-var-init-active`
        // itself discriminates, clang included.
        let (satisfied, verdict) =
            zero_init_decision(active.map(|o| o.verdict), pattern.map(|o| o.verdict));
        let is_active = active.is_some_and(|o| o.verdict == Verdict::On);
        let is_pattern = pattern.is_some_and(|o| o.verdict == Verdict::On);

        constituents.push(Constituent {
            flag: "-ftrivial-auto-var-init=zero",
            check: "auto-var-init-active",
            applicable: true,
            verdict,
            level: is_pattern.then(|| "pattern".to_owned()),
            state: ConstituentState::of(true, satisfied, verdict),
            opt_out: None,
            implementation: None,
            bar: None,
            // A note must not assert more than the verdict supports. Saying "automatic
            // variables are not initialized" whenever the constituent is unsatisfied would
            // read as a measurement, but the common case here is `probe-invalid`, meaning the
            // controls did not discriminate and nothing was established either way.
            note: if is_active && is_pattern {
                Some(
                    "initialization is active but fills the pattern byte, and the \
                     umbrella specifies =zero"
                        .to_owned(),
                )
            } else if !satisfied {
                Some(match active.map(|o| o.verdict) {
                    Some(Verdict::Off) => "automatic variables are not initialized".to_owned(),
                    Some(v) => format!(
                        "not established: auto-var-init-active measured {}, so whether \
                         this constituent holds is unknown rather than absent",
                        v.as_str()
                    ),
                    None => "check not present in this report".to_owned(),
                })
            } else {
                None
            },
        });
    }

    constituents.push(cet_constituent(obs, arch, libc, facts));

    // Reduce. Unknown poisons: a constituent that could not be measured makes the
    // whole composite indeterminate, never `off`. Only a constituent measured and
    // found absent can produce `off`.
    constituents
}

/// A presence-only slot of [`FHARDENED_FLAGS`]: in force where `check` reads `on`, absent
/// where it reads `off` or `partial`, not established where it withholds or is not in the
/// report.
fn presence_constituent(
    obs: &[Observation],
    flag: &'static str,
    check: &'static str,
) -> Constituent {
    let o = find(obs, check);
    let satisfied = o.is_some_and(|o| o.verdict == Verdict::On);
    Constituent {
        flag,
        check,
        applicable: true,
        verdict: o.map(|o| o.verdict),
        level: o.and_then(|o| o.level.clone()),
        state: ConstituentState::of(true, satisfied, o.map(|o| o.verdict)),
        opt_out: None,
        implementation: None,
        bar: None,
        note: (!satisfied).then(|| match o {
            Some(o) => format!("measured {}", o.verdict.as_str()),
            None => "check not present in this report".to_owned(),
        }),
    }
}

/// The check the `-fstack-protector-strong` slot of [`FHARDENED_FLAGS`] reads.
pub const SSP_SLOT_CHECK: &str = "ssp-level-emitted";

/// The flag of that slot, as [`FHARDENED_FLAGS`] spells it. The slot is found by it, since
/// a report's slot may name either of two checks (see [`ssp_constituent`]).
pub const SSP_SLOT_FLAG: &str = "-fstack-protector-strong";

/// The presence-only check a report's slot may cite in place of [`SSP_SLOT_CHECK`].
/// Such a slot carries no `level`, since that check publishes none, so the consistency rule
/// holds its `level` only where one is written (`report::ssp_slot_disagreements`).
pub const SSP_SLOT_RETIRED_CHECK: &str = "canary-emitted";

/// The one derivation of the `-fstack-protector-strong` slot. [`fhardened_constituents`]
/// runs it at measure, and the consistency rule `fhardened-ssp-slot-disagrees-with-input`
/// (`report.rs`) runs it again over the published `ssp-level-emitted` observation, at
/// publication and on read, and holds the slot to it; that is why it takes any
/// [`SlotObservation`].
///
/// The slot reads the graded check, `ssp-level-emitted`, which says which protector rule
/// instrumented the probe's functions, and not `canary-emitted`, whose `on` says that some
/// function got a canary and not which rule admitted it. Read from the presence-only check,
/// the `-fhardened` set with plain `-fstack-protector` in place of `-strong` reads the slot in
/// force and the umbrella `on` while `ssp-level-emitted` reads `partial` at `basic` in the
/// same report (gcc 16.1.1, Fedora 44 x86_64, `--profile explicit`): the downgrade the module
/// comment names as the reason the composite exists, published as a match.
///
/// The rule, on [`crate::probe::SSP_GRADE`]'s scale (`explicit < basic < strong < all`, the
/// ask `strong`): the check measured `on` at a level meeting the ask is in force; measured
/// `off` with no level, or `partial` at a level the scale grades below the ask, is absent, which settles the
/// umbrella; withheld, not in the report, measured with no level, measured at a word on no
/// rung (`SafeStack`'s `unsafe-frame`, which the check publishes beside `on` and grades
/// against nothing, since the selection it names is neither `strong`'s nor below it), or
/// measured at a level its verdict disagrees with (`partial` at a level meeting the ask, `on`
/// at one below it: pairs `level-disagrees-with-check-scale` refuses at publication, so only
/// an edited file carries them) is not established: the slot
/// decides nothing the check declined to decide, in either direction. The level the check
/// published is the slot's `level` in every state, as the relro slot publishes `partial`;
/// where the check is withheld or not in the report there is none.
pub(crate) fn ssp_constituent<O: SlotObservation>(obs: &[O]) -> Constituent {
    use crate::probe::SSP_GRADE;
    let o = find_slot_input(obs, SSP_SLOT_CHECK);
    let verdict = o.map(SlotObservation::verdict);
    let level = o.and_then(|o| o.level().map(str::to_owned));
    let ask = format!(
        "needs the {} rule or above ({}); measured",
        SSP_GRADE.recommended,
        SSP_GRADE.scale.spelled()
    );
    let unknown = |what: String| {
        format!(
            "not established: {SSP_SLOT_CHECK} {what}, so whether the {} rule is in force is \
             unknown rather than absent",
            SSP_GRADE.recommended
        )
    };
    let (state, note) = match (verdict, level.as_deref()) {
        (None, _) => (
            ConstituentState::NotEstablished,
            Some("check not present in this report".to_owned()),
        ),
        (Some(v), _) if !v.is_measurement() => (
            ConstituentState::NotEstablished,
            Some(unknown(v.as_str().to_owned())),
        ),
        (Some(Verdict::Off), None) => (ConstituentState::Absent, Some(format!("{ask} off"))),
        (Some(Verdict::Off), Some(l)) => (
            ConstituentState::NotEstablished,
            Some(unknown(format!(
                "off at {l}, a level beside a verdict that says no function was instrumented"
            ))),
        ),
        (Some(v), None) => (
            ConstituentState::NotEstablished,
            Some(unknown(format!("{} with no level", v.as_str()))),
        ),
        (Some(v), Some(l)) => match SSP_GRADE.meets(l) {
            Some(true) if v == Verdict::On => (ConstituentState::InForce, None),
            Some(false) if v == Verdict::Partial => {
                (ConstituentState::Absent, Some(format!("{ask} {l}")))
            }
            Some(true) => (
                ConstituentState::NotEstablished,
                Some(unknown(format!(
                    "{} at {l}, a level its scale grades as meeting {} beside a verdict that \
                     says it does not",
                    v.as_str(),
                    SSP_GRADE.recommended
                ))),
            ),
            Some(false) => (
                ConstituentState::NotEstablished,
                Some(unknown(format!(
                    "{} at {l}, a level its scale grades below {} beside a verdict that says \
                     it meets it",
                    v.as_str(),
                    SSP_GRADE.recommended
                ))),
            ),
            None => (
                ConstituentState::NotEstablished,
                Some(unknown(format!(
                    "{} at {l}, a word on no rung of {}, which the check grades against \
                     nothing",
                    v.as_str(),
                    SSP_GRADE.scale.spelled()
                ))),
            ),
        },
    };
    Constituent {
        flag: SSP_SLOT_FLAG,
        check: SSP_SLOT_CHECK,
        applicable: true,
        verdict,
        level,
        state,
        note,
        opt_out: None,
        implementation: None,
        bar: None,
    }
}

/// The architecture's control-flow protection, whichever mechanism that is here.
///
/// `cet_constituent` answers a narrower question — does this build have the CFI member of
/// the `-fhardened` set — and the answer off x86 is that the set has no such member, so it
/// reports inapplicable. That is faithful and it is also why `fhardened-effective` is not
/// comparable across architectures: the denominator is 8 on x86_64 and 7 on aarch64, and a
/// build with BTI and PAC fully in force scores the same on that slot as one built with
/// `-mbranch-protection=none`.
///
/// This asks the comparable question instead. The pairing is by *edge* rather than by
/// spelling: x86's `-fcf-protection=full` marks IBT and SHSTK, forward and backward, and
/// aarch64's `-mbranch-protection=standard` marks BTI and PAC, forward and backward. One
/// constituent on each side, so the denominator is 1 everywhere and two rows of a
/// cross-image table mean the same thing.
///
/// The artifact channel only, matching `cet-marked`: the ELF property note is what the
/// binary actually carries, and the macro channel already has its own corroboration
/// reported separately. GCS is deliberately not a second constituent — it is a third
/// mechanism with no x86 counterpart under this flag, and requiring it would make the
/// verdict depend on the compiler's vintage rather than on the build. It is named in the
/// note when present, because a reader should not have to infer that the artifact carries
/// more than the verdict counts.
///
/// **The program's own opt-out.** On OpenBSD the marking is not what enforcement waits
/// for, and a program header is what turns it off. Measured 2026-10-01 in an OpenBSD 7.9
/// arm64 guest under qemu TCG (`-cpu max,pauth-impdef=on,sve=off,sme=off`, clang 19.1.7):
/// an indirect call into a target compiled `-mbranch-protection=none`, so linked with no
/// feature note at all, took SIGILL, and the same program linked `-Wl,-z,nobtcfi` returned.
/// Both held in a second run, where the reader recorded the header on exactly the two of
/// four test programs linked that way, as OpenBSD's own `readelf -lW` did. The header that
/// flag writes, `PT_OPENBSD_NOBTCFI` ([`crate::elf::ElfFacts::openbsd_nobtcfi`]), disables
/// the forward edge for the whole process, and `branch-protection-marked` reads `on` beside
/// it, correctly as scoped to marking. Without this reading the composite would be `on`
/// there, a protection the program had switched off read as in force.
///
/// The constituent is `absent`, so the composite reads `off`, rather than withheld. The
/// header is a positive read from the artifact chard built, not a silence: the program
/// states in its own headers that the forward edge is not to be enforced, and the
/// constituent asks for both edges. That is the same kind of fact as a missing BTI bit,
/// with the measured effect behind it, so `off` is earned the way the marking's `off` is.
/// What it does not claim is that PAC is off; the backward edge is what the header leaves
/// alone, and the note says which edge went. On amd64 the same header names IBT, and the
/// reading there rests on the registered assumption `nobtcfi-switches-off-ibt-on-amd64`:
/// the only amd64 guest measured exposed no IBT, so its kernel enforced nothing to turn
/// off. Where the target's C library is not OpenBSD's, no kernel chard has measured reads
/// the header, so a marked artifact carrying it is `not-established` rather than `absent`.
/// That case is reached on Linux: lld 22.1.8 writes the header under `-z nobtcfi` for a
/// Linux target as for an OpenBSD one, and only GNU ld ignores the flag (measurements in
/// [`crate::elf::ElfFacts::openbsd_nobtcfi`]).
/// `composite-verdict-disagrees-with-constituents` holds both directions: a constituent
/// that names the header names an artifact whose stored facts carry it, and one whose
/// artifact carries it names it.
fn cfi_constituent(
    obs: &[Observation],
    arch: &str,
    libc: &crate::env::Libc,
    facts: &crate::report::FactStore,
) -> Constituent {
    let Some((flag, check)) = (match arch {
        "x86_64" | "x86" | "i686" => Some(("-fcf-protection=full", "cet-marked")),
        "aarch64" => Some(("-mbranch-protection=standard", "branch-protection-marked")),
        _ => None,
    }) else {
        // A witness in toolchain.target contradicted the architecture this slot was chosen
        // by, so which mechanism applies is itself unestablished: held applicable and withheld,
        // citing the check whose withholding says so.
        if let Some((flag, check, o)) = [
            ("-fcf-protection=full", "cet-marked"),
            ("-mbranch-protection=standard", "branch-protection-marked"),
        ]
        .into_iter()
        .find_map(|(flag, check)| {
            find(obs, check)
                .filter(|o| target_contradicted(o))
                .map(|o| (flag, check, o))
        }) {
            return Constituent {
                flag,
                check,
                applicable: true,
                verdict: Some(o.verdict),
                level: None,
                state: ConstituentState::of(true, false, Some(o.verdict)),
                opt_out: None,
                implementation: None,
                bar: None,
                note: Some(format!(
                    "not established: a witness contradicts {arch}, the architecture \
                     this slot is chosen by (toolchain.target)"
                )),
            };
        }
        // No check here rather than no protection here. riscv64 has Zicfilp/Zicfiss and
        // s390x has nothing comparable, and chard measures neither; saying `off` would
        // publish an absence it never looked for.
        //
        // It still cites `cet-marked`, because `derived_from` is documented as check ids
        // and there is no id for "nothing applies" — the same citation `fhardened` makes
        // for this slot on aarch64, with the same `verdict: None` beside it. The note is
        // what carries the meaning; a reader who takes the citation for a measurement
        // would be misreading a constituent that says `applicable: false`.
        return Constituent {
            flag: "-fcf-protection=full",
            check: "cet-marked",
            applicable: false,
            verdict: None,
            level: None,
            state: ConstituentState::NotApplicable,
            opt_out: None,
            implementation: None,
            bar: None,
            note: Some(format!(
                "chard has no control-flow check for {arch}: the CET pair is gated to x86 \
                 and the branch-protection pair to aarch64, so this is unmeasured rather \
                 than absent"
            )),
        };
    };

    let o = find(obs, check);
    let satisfied = o.is_some_and(|o| o.verdict == Verdict::On);
    let gcs = find(obs, "gcs-marked").is_some_and(|o| o.verdict == Verdict::On);

    if let Some(opt_out) = measured_opt_out(o, facts) {
        return opted_out_constituent(flag, check, o, satisfied, opt_out, libc);
    }

    Constituent {
        flag,
        check,
        applicable: true,
        verdict: o.map(|o| o.verdict),
        level: o.and_then(|o| o.level.clone()),
        state: ConstituentState::of_marking(true, satisfied, o.map(|o| o.verdict)),
        opt_out: None,
        implementation: None,
        bar: None,
        note: Some(if satisfied {
            marked_note(flag, obs, arch, libc, gcs)
        } else {
            match o {
                Some(o) => format!("{check} measured {}", o.verdict.as_str()),
                None => format!("{check} is not present in this report"),
            }
        }),
    }
}

/// The note of a constituent in the `marked` state: what the marking is, that the
/// constituent measures the marking alone, and what the report measured of enforcement
/// ([`enforcement_reading`]); `gcs` adds that the artifact carries GCS too. "Not shown in
/// force" claims no absence: the constituent did not measure enforcement, and the clause
/// after it says what did.
fn marked_note(
    flag: &str,
    obs: &[Observation],
    arch: &str,
    libc: &crate::env::Libc,
    gcs: bool,
) -> String {
    let mut note = format!(
        "marked, not shown in force: the artifact carries the markings {flag} writes; this \
         constituent measures the marking alone, and {}",
        enforcement_reading(obs, arch, libc)
    );
    if gcs {
        note.push_str(
            "; the artifact also carries GCS, which is beyond what this constituent requires",
        );
    }
    note
}

/// What the report says about the enforcement of a control-flow marking on `arch` under
/// the kernel `libc` names, for [`marked_note`] and `cfi-effective`'s reason.
///
/// Under every kernel but OpenBSD's the marking is a request: on x86 the clause quotes
/// `shadow-stack-enforced`, the one check that measures an edge's enforcement (the backward
/// edge, for a program built with the same flags), with its level glossed and its gating
/// rule where it has them, and says no check measures IBT's; on aarch64 it says no check
/// measures BTI's or PAC's (not yet checks: the ledger's bti-enforced and pac-ret-enforced).
/// On OpenBSD arm64 the forward edge is enforced for every program that does not carry
/// `PT_OPENBSD_NOBTCFI`, marked or not (measured on OpenBSD 7.9 arm64), and on amd64 the
/// header turns IBT enforcement off where the CPU exposes it (the registered assumption
/// `nobtcfi-switches-off-ibt-on-amd64`, which says no more than that: an unmarked program's
/// enforcement there is unmeasured); the constituent reads that header
/// ([`opted_out_constituent`]), so the clause says what the kernel does instead of
/// "request".
/// Named beside the marking and never reduced into the constituent: a backward edge
/// enforced is not both edges, and an edge chard has no check for cannot read `off`.
/// `the_enforcement_sentences_name_every_enforcement_check` pins the corpus's enforcement
/// checks, so one added for IBT, BTI or PAC fails until this clause quotes it.
fn enforcement_reading(obs: &[Observation], arch: &str, libc: &crate::env::Libc) -> String {
    let openbsd = honours_forward_edge_opt_out(libc);
    let request = if openbsd {
        ""
    } else {
        "the marking is a request the kernel, CPU and C library may or may not act on; "
    };
    match arch {
        "x86_64" | "x86" | "i686" => {
            let forward = if openbsd {
                "on OpenBSD amd64 PT_OPENBSD_NOBTCFI turns IBT enforcement off for the whole \
                 program where the CPU exposes it (the registered assumption \
                 nobtcfi-switches-off-ibt-on-amd64), and this constituent reads that header \
                 beside the marking; "
            } else {
                ""
            };
            format!(
                "{request}{forward}shadow-stack-enforced, which runs a program built with the \
                 same flags and measures the backward edge's enforcement, {}; no check \
                 measures IBT enforcement",
                shadow_stack_reading(obs)
            )
        }
        "aarch64" if openbsd => "OpenBSD enforces BTI, the forward edge, for every program \
                                 that does not carry PT_OPENBSD_NOBTCFI, marked or not (as \
                                 measured on OpenBSD 7.9 arm64), and this constituent reads \
                                 that header beside the marking; no check measures PAC \
                                 enforcement"
            .to_owned(),
        "aarch64" => format!("{request}no check measures BTI or PAC enforcement"),
        // Unreachable today: `cfi_constituent` selects a mechanism on x86 and aarch64
        // alone, and the CET slot applies on x86 alone. Claims nothing a check measured.
        other => format!("chard has no control-flow enforcement check for {other}"),
    }
}

/// `shadow-stack-enforced`'s reading as [`enforcement_reading`] quotes it: the verdict,
/// the level with its meaning (the scale is `probe::SHADOW_STACK_DEFAULT`'s), and the
/// gating rule where there is one; or that the check is not in the report.
fn shadow_stack_reading(obs: &[Observation]) -> String {
    match find(obs, "shadow-stack-enforced") {
        None => "is not in this report".to_owned(),
        Some(o) => {
            let level = o.level.as_deref().map_or_else(String::new, |l| {
                let gloss = match l {
                    "opt-in" => " (enforced only under glibc's opt-in tunable)",
                    "default" => " (enforced without the opt-in tunable)",
                    _ => "",
                };
                format!(" at {l}{gloss}")
            });
            let rule = o
                .gating
                .as_ref()
                .map_or_else(String::new, |g| format!(" under {}", g.rule.id));
            format!("reads {}{level}{rule}", o.verdict.as_str())
        }
    }
}

/// The opt-out header the marking check's measured artifact carries, keyed by that
/// artifact's `facts` entry.
///
/// Read only where the marking was measured: a check withheld is `not-established` with or
/// without it, and the store holds no artifact to read for a check that built nothing.
fn measured_opt_out(o: Option<&Observation>, facts: &crate::report::FactStore) -> Option<OptOut> {
    let o = o.filter(|o| o.verdict.is_measurement())?;
    let elf = facts.elf_of(o.build.as_ref())?;
    let key = o.build.as_ref()?.artifact_sha256.clone()?;
    forward_edge_opt_out(elf).map(|header| OptOut { header, facts: key })
}

/// The control-flow constituent where the measured artifact carries the program's own
/// opt-out, for `cfi-effective` and for `fhardened-effective`'s CET slot alike;
/// [`cfi_constituent`] says why it reads `absent` on OpenBSD.
fn opted_out_constituent(
    flag: &'static str,
    check: &'static str,
    o: Option<&Observation>,
    satisfied: bool,
    opt_out: OptOut,
    libc: &crate::env::Libc,
) -> Constituent {
    let honoured = honours_forward_edge_opt_out(libc);
    // Off OpenBSD a marking already measured absent stays absent: the header can only
    // take away, so it cannot rescue the constituent and need not be understood to
    // settle it.
    let state = if honoured || !satisfied {
        ConstituentState::Absent
    } else {
        ConstituentState::NotEstablished
    };
    let header = opt_out.header;
    // Where the marking is already short the header decides nothing, so the note leads
    // with the measured shortfall and names the header after it. On OpenBSD amd64, whose
    // clang marks IBT alone, that is every report with the header: leading with it would
    // explain a measured `off` by the unmeasured `nobtcfi-switches-off-ibt-on-amd64`.
    let note = if !satisfied {
        format!(
            "{check} measured {}, which leaves the constituent absent on its own; the \
             artifact also carries {header}, OpenBSD's per-program opt-out from \
             branch-target enforcement",
            o.map_or("nothing", |o| o.verdict.as_str())
        )
    } else if honoured {
        format!(
            "the artifact carries {header}, by which the program asks OpenBSD not to enforce \
             branch-target CFI on it, so the forward edge {check} reads is not enforced \
             whatever the marking says"
        )
    } else {
        format!(
            "the artifact carries {header}, OpenBSD's per-program opt-out from branch-target \
             enforcement, and the C library here is {}; chard has measured the header's \
             effect on OpenBSD only, so whether the marking is enforced is not established",
            libc.impl_name
        )
    };
    Constituent {
        flag,
        check,
        applicable: true,
        verdict: o.map(|o| o.verdict),
        level: o.and_then(|o| o.level.clone()),
        state,
        opt_out: Some(opt_out),
        implementation: None,
        bar: None,
        note: Some(note),
    }
}

/// The program header by which `elf` opts out of forward-edge enforcement, if it carries
/// one: OpenBSD's `PT_OPENBSD_NOBTCFI`, which covers BTI on arm64 and IBT on amd64.
#[must_use]
pub fn forward_edge_opt_out(elf: &crate::elf::ElfFacts) -> Option<&'static str> {
    elf.openbsd_nobtcfi.then_some(PT_OPENBSD_NOBTCFI)
}

/// Whether the target's kernel is one whose reading of [`forward_edge_opt_out`]'s header
/// chard has measured: OpenBSD's, identified by its C library as everywhere else in a
/// report.
#[must_use]
pub fn honours_forward_edge_opt_out(libc: &crate::env::Libc) -> bool {
    libc.impl_name == "openbsd"
}

/// Does the artifact ask for control-flow protection on both edges, in whatever form this
/// architecture has?
///
/// The question is the program's request: the marking its constituent reads, less an
/// opt-out header the program carries. Marked, not in force: a marking is a request, and
/// whether the kernel, CPU and C library act on it is not what the constituent measures.
/// A title asking "in force" would overstate 103 of the 311 reports of a fleet sweep: 95
/// x86_64 Linux reports whose `shadow-stack-enforced` read `indeterminate` or `unsupported`,
/// and 8 OpenBSD aarch64 reports with no enforcement check. `on` means both edges marked and
/// no opt-out, and what the report measured of enforcement is named in the reason and the
/// constituent's note ([`enforcement_reading`]); the id `cfi-effective` stands for consumers
/// keyed on it. The choice and its
/// reason are in `DESIGN.md`, "Two umbrellas".
///
/// Separate from `fhardened-effective` on purpose. That one measures fidelity to a
/// specific GCC umbrella, which does not enable `-mbranch-protection` — so folding
/// aarch64 CFI into it would report a build compiled *with* `-fhardened` as falling short
/// of `-fhardened`, which is a worse answer than silence. This composite
/// carries the cross-architecture claim and leaves that one alone.
pub fn cfi(
    obs: &[Observation],
    arch: &str,
    libc: &crate::env::Libc,
    facts: &crate::report::FactStore,
) -> Composite {
    cfi_for(obs, arch, libc, facts)
}

/// The body of [`cfi`], taking the architecture directly.
///
/// Split for the same reason `cet_constituent` takes one: the whole point of this
/// composite is that it answers differently per architecture, and a test that cannot vary
/// the architecture without an aarch64 host would assert the gating by inspection. That is
/// exactly how the last defect in this file survived.
#[cfg(test)]
fn cfi_for_arch(obs: &[Observation], arch: &str) -> Composite {
    let libc = crate::env::Libc {
        impl_name: "glibc".to_owned(),
        version: None,
        detection: "test".to_owned(),
    };
    cfi_for(obs, arch, &libc, &crate::report::FactStore::default())
}

/// [`cfi`] itself; [`cfi_for_arch`] is the test shorthand for a glibc target with an
/// empty store.
fn cfi_for(
    obs: &[Observation],
    arch: &str,
    libc: &crate::env::Libc,
    facts: &crate::report::FactStore,
) -> Composite {
    let constituents = vec![cfi_constituent(obs, arch, libc, facts)];
    // The header explains the verdict only where the marking it overrides was measured on;
    // beside a marking already short, the shortfall does, and the constituent's note
    // names the header.
    let opted_out = constituents
        .iter()
        .any(|c| c.opt_out.is_some() && c.verdict == Some(Verdict::On));
    let short_beside_header = constituents
        .iter()
        .find(|c| c.opt_out.is_some() && c.verdict != Some(Verdict::On))
        .map(|c| (c.check, c.verdict.map_or("nothing", Verdict::as_str)));
    let Reduction {
        applicable,
        unmeasured,
        missing,
        verdict,
    } = reduce(&constituents);

    let mechanism = constituents.first().map_or("", |c| c.flag);
    // A marking for one edge alone is `off` here, as no marking is, but the reason must
    // not say the artifact is unmarked: the same report's `cet-marked` reads `partial`.
    let one_edge = constituents
        .iter()
        .find(|c| c.verdict == Some(Verdict::Partial))
        .map(|c| (c.check, c.level.as_deref().unwrap_or("one edge")));
    let reason = match verdict {
        Verdict::NotApplicable => format!(
            "chard measures no control-flow protection on {arch}, so this is unmeasured \
             rather than absent"
        ),
        Verdict::Off if opted_out => format!(
            "the artifact carries {PT_OPENBSD_NOBTCFI}, which turns off OpenBSD's forward-edge \
             enforcement for the whole program, so the marking {mechanism} wrote is not what \
             the program asks for on both edges"
        ),
        Verdict::Off if short_beside_header.is_some() => {
            // Guarded by `is_some` above; the empty pair is never written.
            let (check, measured) = short_beside_header.unwrap_or(("", ""));
            format!(
                "{check} measured {measured}, so the artifact is not marked for {mechanism} \
                 on both edges; the artifact also carries {PT_OPENBSD_NOBTCFI}, which that \
                 verdict does not rest on"
            )
        }
        Verdict::Indeterminate if opted_out => format!(
            "the artifact is marked and carries {PT_OPENBSD_NOBTCFI}, OpenBSD's opt-out from \
             forward-edge enforcement, whose effect chard has measured on OpenBSD only, so \
             whether the program asks for control-flow protection on both edges is neither \
             confirmed nor refuted here"
        ),
        Verdict::Off if one_edge.is_some() => {
            // Guarded by `is_some` above; the empty pair is never written.
            let (check, level) = one_edge.unwrap_or(("", ""));
            format!(
                "{check} measured partial, the artifact marked for {level} alone, so the \
                 artifact is not marked for {mechanism} on both edges"
            )
        }
        Verdict::Off => format!(
            "the artifact carries no control-flow markings, so it is not marked for \
             {mechanism} on either edge"
        ),
        // One constituent, so this cannot be reached: `missing` is either empty or the
        // whole of `applicable`. Kept because the reduction is shared and a future
        // second constituent would make it live.
        Verdict::Partial => format!(
            "{} of {} control-flow constituents are marked; missing: {}",
            applicable.len().saturating_sub(missing.len()),
            applicable.len(),
            missing
                .iter()
                .map(|c| c.flag)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Verdict::Indeterminate => format!(
            "the control-flow marking could not be measured here ({}), so it is neither \
             confirmed nor refuted",
            unmeasured
                .iter()
                .map(|c| c.check)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Verdict::On => format!(
            "the artifact is marked for control-flow protection on both edges, via \
             {mechanism}; this composite measures the marking alone, and {}",
            enforcement_reading(obs, arch, libc)
        ),
        other => format!(
            "no reason could be derived for a {} verdict",
            other.as_str()
        ),
    };

    Composite {
        id: "cfi-effective",
        title: "Does the artifact ask for control-flow protection on both edges, in whatever \
                form this architecture has?",
        derived_from: constituents.iter().map(|c| c.check).collect(),
        verdict,
        constituents,
        reason,
    }
}

/// One umbrella's constituents, reduced — the arithmetic, kept apart from the prose.
///
/// A second umbrella arrived (`cfi-effective`) and the three-valued AND below is the part
/// the two must not disagree about: `dataset.rs` checks every composite in a report against
/// its own constituents under one rule, so two reductions that drift would show up as a
/// contradiction in chard rather than a finding about the toolchain. The prose stays with
/// each composite, because a reason that reads well for `-fhardened` does not for a
/// protection family.
struct Reduction<'a> {
    applicable: Vec<&'a Constituent>,
    unmeasured: Vec<&'a Constituent>,
    missing: Vec<&'a Constituent>,
    verdict: Verdict,
}

/// Three-valued AND, and the order matters. A constituent `marked` is confirmed as one
/// `in-force` is: neither is unmeasured nor missing, so the two differ in what the umbrella's
/// reason says and not in the arithmetic. A constituent *measured* absent settles
/// the question on its own — `false AND unknown` is `false`, so an unmeasurable
/// sibling cannot rescue it — while `true AND unknown` is `unknown`. Checking the
/// unmeasured arm first would let one withheld constituent mask a definite failure and
/// report indeterminate for a build that is plainly not hardened. With eight constituents
/// that is not a corner case: `bare` withholds cxx-stdlib-assertions at -O0 by design,
/// which would make that composite indeterminate on every bare run of a sweep.
///
/// Nothing applicable at all is `not-applicable`, not `off`. `-fhardened` cannot reach
/// that state — seven of its constituents apply unconditionally — but a composite whose
/// only constituent is architecture-specific can, and `missing.len() == applicable.len()`
/// is vacuously true at zero, so without this arm an architecture chard has no
/// control-flow check for would publish "no constituent is in force" as a measurement.
fn reduce(constituents: &[Constituent]) -> Reduction<'_> {
    let applicable: Vec<&Constituent> = constituents.iter().filter(|c| c.applicable).collect();
    // By `state`, which every constructor derives from the verdict through
    // `ConstituentState::of` except where a program's opt-out decides it: a marking
    // measured `on` beside a header no measured kernel reads is `not-established`, and
    // re-deriving from the copied verdict here counted it missing.
    let mut unmeasured: Vec<&Constituent> = Vec::new();
    let mut missing: Vec<&Constituent> = Vec::new();
    for c in applicable.iter().copied() {
        // Exhaustive, so a state added later is decided here rather than confirmed by
        // falling through. `NotApplicable` on an applicable constituent is a shape no
        // constructor writes; read as unmeasured, it cannot confirm or deny.
        match c.state {
            ConstituentState::InForce | ConstituentState::Marked => {}
            ConstituentState::NotEstablished | ConstituentState::NotApplicable => {
                unmeasured.push(c);
            }
            ConstituentState::Absent => missing.push(c),
        }
    }

    let verdict = if applicable.is_empty() {
        Verdict::NotApplicable
    } else if missing.len() == applicable.len() {
        Verdict::Off
    } else if !missing.is_empty() {
        Verdict::Partial
    } else if !unmeasured.is_empty() {
        Verdict::Indeterminate
    } else {
        Verdict::On
    };

    Reduction {
        applicable,
        unmeasured,
        missing,
        verdict,
    }
}

/// The `not-established` constituents of a reduction, worded by why each is short.
///
/// A constituent can be `not-established` without being unmeasured: a marking measured `on`
/// beside an opt-out header no measured kernel reads (see [`opted_out_constituent`]). Listing
/// it among those that "could not be measured" would describe a measured marking as
/// unmeasured, so it is named apart, as measured with its effect unestablished. The fortify
/// slot measured against a bar the C library reading does not set (see
/// [`fortify_constituent`]) is named apart the same way, and so is the protector slot
/// measured and not graded (see [`ssp_constituent`]).
fn unconfirmed(unmeasured: &[&Constituent]) -> String {
    let (opted, rest): (Vec<&Constituent>, Vec<&Constituent>) = unmeasured
        .iter()
        .copied()
        .partition(|c| c.opt_out.is_some() && c.verdict == Some(Verdict::On));
    // Keyed on the slot, not on the shape: a measured verdict beside `not-established` is the
    // unset bar only for fortify, and another constituent reaching that shape for another
    // cause would otherwise publish this sentence about the C library.
    let (unbarred, unread): (Vec<&Constituent>, Vec<&Constituent>) =
        rest.into_iter().partition(|c| {
            c.check == "fortify-effective" && c.verdict.is_some_and(Verdict::is_measurement)
        });
    // The protector slot measured and not graded (`ssp_constituent`): "could not be
    // measured" would describe a measured reading as none.
    let (ungraded, unread): (Vec<&Constituent>, Vec<&Constituent>) = unread
        .into_iter()
        .partition(|c| c.check == SSP_SLOT_CHECK && c.verdict.is_some_and(Verdict::is_measurement));
    let list = |cs: &[&Constituent]| cs.iter().map(|c| c.check).collect::<Vec<_>>().join(", ");
    let mut parts = Vec::new();
    if !unbarred.is_empty() {
        parts.push(format!(
            "{} {} measured against a bar the C library reading does not set ({})",
            unbarred.len(),
            if unbarred.len() == 1 { "was" } else { "were" },
            list(&unbarred)
        ));
    }
    if !ungraded.is_empty() {
        parts.push(format!(
            "{} {} measured but not graded against the {} rule ({})",
            ungraded.len(),
            if ungraded.len() == 1 { "was" } else { "were" },
            crate::probe::SSP_GRADE.recommended,
            list(&ungraded)
        ));
    }
    if !unread.is_empty() {
        parts.push(format!(
            "{} could not be measured ({})",
            unread.len(),
            list(&unread)
        ));
    }
    if !opted.is_empty() {
        parts.push(format!(
            "{} {} measured but {} effect is not established ({})",
            opted.len(),
            if opted.len() == 1 { "was" } else { "were" },
            if opted.len() == 1 { "its" } else { "their" },
            list(&opted)
        ));
    }
    parts.join(" and ")
}

/// Reduce the constituents to one verdict for the umbrella.
///
/// `facts` is read for one thing: the program header by which the CET slot's measured
/// artifact opts out of forward-edge enforcement (see [`cet_constituent`]). `driver` is the
/// driver's own `-fhardened -O2` dump, which sets the fortify bar where the driver offers the
/// option, and `target_triple` the driver's `-dumpmachine`, read beside `libc` for the bar
/// where it does not (see [`fhardened_bar`]).
pub fn fhardened(
    obs: &[Observation],
    arch: &str,
    driver: &crate::toolchain::FhardenedFortify,
    libc: &crate::env::Libc,
    target_triple: Option<&str>,
    facts: &crate::report::FactStore,
) -> Composite {
    fhardened_with(obs, arch, driver, libc, target_triple, facts)
}

/// [`fhardened`] over an empty fact store, so no artifact carries an opt-out header.
///
/// Same reason as [`cfi_for_arch`]: a test that cannot vary the architecture and the libc
/// without constructing a whole `Environment` ends up testing the helpers and not the
/// umbrella. Tests of the helpers alone leave mutants of the constituent builders below
/// alive, one of them replacing the entire list with `vec![]`.
///
/// The triple is `<arch>-linux-musl` for musl and `<arch>-linux-gnu` for every other
/// library: a native toolchain's for musl and glibc, and for the rest a triple under which
/// [`fortify_bar`] still sets no bar, since they name neither library. The driver refuses
/// `-fhardened`, as clang does, so the library reading is the one these tests exercise.
#[cfg(test)]
fn fhardened_for(obs: &[Observation], arch: &str, libc: &crate::env::Libc) -> Composite {
    let env = if libc.impl_name == "musl" {
        "musl"
    } else {
        "gnu"
    };
    let triple = format!("{arch}-linux-{env}");
    fhardened_with(
        obs,
        arch,
        &crate::toolchain::FhardenedFortify::refused(),
        libc,
        Some(&triple),
        &crate::report::FactStore::default(),
    )
}

/// The body of [`fhardened`].
fn fhardened_with(
    obs: &[Observation],
    arch: &str,
    driver: &crate::toolchain::FhardenedFortify,
    libc: &crate::env::Libc,
    target_triple: Option<&str>,
    facts: &crate::report::FactStore,
) -> Composite {
    let constituents = fhardened_constituents(obs, arch, driver, libc, target_triple, facts);
    let Reduction {
        applicable,
        unmeasured,
        missing,
        verdict,
    } = reduce(&constituents);
    // A constituent whose marking reads `on` and whose artifact opts out of what it marks
    // is short for the header alone, and the reason says so: a bare flag in the `missing`
    // list would read as a marking the artifact lacks.
    let opted_out: Vec<String> = constituents
        .iter()
        .filter(|c| c.opt_out.is_some() && c.verdict == Some(Verdict::On))
        .filter_map(|c| {
            c.opt_out
                .as_ref()
                .map(|o| format!("{} is marked and the artifact carries {}", c.flag, o.header))
        })
        .collect();
    let opted_out = if opted_out.is_empty() {
        String::new()
    } else {
        format!("; {}", opted_out.join("; "))
    };
    // A slot confirmed as a marking is confirmed, not in force: the reason says
    // which, so "in force" is never written over the CET slot.
    let marked: Vec<&str> = constituents
        .iter()
        .filter(|c| c.state == ConstituentState::Marked)
        .map(|c| c.flag)
        .collect();
    let confirmed = if marked.is_empty() {
        "in force".to_owned()
    } else {
        format!(
            "in force or marked ({} as a marking the artifact carries, not as enforcement)",
            marked.join(", ")
        )
    };

    let reason = match verdict {
        Verdict::Off => format!("no constituent of -fhardened is in force{opted_out}"),
        Verdict::Partial => {
            format!(
                "{} of {} constituents are confirmed {confirmed}, so this build is not \
                 -fhardened whatever the remaining checks say; missing: {}{}{opted_out}",
                applicable
                    .len()
                    .saturating_sub(missing.len())
                    .saturating_sub(unmeasured.len()),
                applicable.len(),
                missing
                    .iter()
                    .map(|c| c.flag)
                    .collect::<Vec<_>>()
                    .join(", "),
                if unmeasured.is_empty() {
                    String::new()
                } else {
                    format!("; {}", unconfirmed(&unmeasured))
                }
            )
        }
        Verdict::Indeterminate => {
            format!(
                "every constituent that could be confirmed is {confirmed}, but of {}, {}, so \
                 `-fhardened` cannot be confirmed; a reduction must not turn missing evidence \
                 into a positive result either{opted_out}",
                applicable.len(),
                unconfirmed(&unmeasured)
            )
        }
        // Everything applicable was measured and satisfied.
        Verdict::On => {
            format!(
                "all {} applicable constituents are {confirmed}, so this build is \
                 effectively -fhardened whether or not the option was passed",
                applicable.len()
            )
        }
        // Unreachable rather than impossible: seven of this umbrella's constituents
        // apply on every architecture, so `reduce` cannot return anything else here.
        // Stated as text rather than a panic, because a composite that cannot be
        // described is still not a reason to abandon a measurement that succeeded.
        other => format!(
            "no reason could be derived for a {} verdict",
            other.as_str()
        ),
    };

    Composite {
        id: "fhardened-effective",
        title: "Is this build effectively -fhardened, however it got there?",
        derived_from: constituents.iter().map(|c| c.check).collect(),
        verdict,
        constituents,
        reason,
    }
}

#[cfg(test)]
mod tests {
    /// [`ConstituentState::as_str`] is the spelling serde writes, for every variant.
    #[test]
    fn the_state_spelling_is_the_serialized_one() {
        use ConstituentState as S;
        for state in [
            S::InForce,
            S::Marked,
            S::Absent,
            S::NotEstablished,
            S::NotApplicable,
        ] {
            assert_eq!(
                serde_json::to_value(state).expect("a unit variant serializes"),
                serde_json::json!(state.as_str()),
                "{state:?}"
            );
        }
    }

    use super::*;

    /// [`cet_constituent`] for a glibc target over an empty store, so no artifact carries
    /// an opt-out header.
    fn cet_for(obs: &[Observation], arch: &str) -> Constituent {
        cet_constituent(obs, arch, &glibc(), &crate::report::FactStore::default())
    }

    /// Off x86 the CET constituent is inapplicable, and `satisfied` must agree with that.
    ///
    /// Needs no ARM hardware: the gating on `arch` is run here rather than asserted by
    /// inspection. A `satisfied` computed as `!x86`, **true** off x86, beside a
    /// `ConstituentState::of` returning `NotApplicable` fails the consistency rule comparing the
    /// two, which makes `measure` exit 3 and publish nothing. Every report on an aarch64 host
    /// would be refused for a reason having nothing to do with the measurement.
    #[test]
    fn off_x86_the_cet_constituent_is_inapplicable_and_says_so_consistently() {
        for arch in ["aarch64", "riscv64", "s390x"] {
            let k = cet_for(&[], arch);
            assert!(!k.applicable, "{arch}: CET is x86-only");
            assert_eq!(k.state, ConstituentState::NotApplicable, "{arch}");
            assert!(
                !k.satisfied(),
                "{arch}: an inapplicable constituent is not a satisfied one, and claiming both \
                 would refuse every report"
            );
            assert!(k.note.is_some(), "{arch}: inapplicability must say why");
        }
        // And the x86 side still behaves: no observation means not in force.
        let k = cet_for(&[], "x86_64");
        assert!(k.applicable);
        assert!(!k.satisfied());
        assert_eq!(
            k.note.as_deref(),
            Some("cet-marked is not present in this report")
        );
    }

    /// The x86 slot's note states what `cet-marked` measured: a marking on one edge or a
    /// withheld check is not an artifact with no marking.
    #[test]
    fn the_cet_slot_note_names_the_measured_shortfall() {
        for (verdict, note) in [
            (Verdict::Off, "no CET markings in the artifact"),
            (Verdict::Partial, "cet-marked measured partial"),
            (Verdict::ProbeInvalid, "cet-marked measured probe-invalid"),
        ] {
            let k = cet_for(&[obs("cet-marked", verdict, None)], "x86_64");
            assert_eq!(k.note.as_deref(), Some(note), "{verdict:?}");
        }
        let k = cet_for(&[obs("cet-marked", Verdict::On, None)], "x86_64");
        assert!(
            k.note
                .as_deref()
                .is_some_and(|n| n.starts_with("marked, not shown in force: ")),
            "{:?}",
            k.note
        );
    }

    /// A marking measured `on` is `marked`, not `in-force`: both composites read
    /// the marking checks, which read the request the artifact carries and not what a
    /// kernel, CPU or C library does with it. The constituent is confirmed, so the umbrella
    /// and `cfi-effective` read `on` over it and the deprecated `satisfied` is true; the
    /// title, the reason and the note say marked, and none says in force.
    #[test]
    fn a_marking_measured_on_reads_marked_not_in_force() {
        use ConstituentState as S;
        let x86 = [obs("cet-marked", Verdict::On, None)];
        let arm = [obs("branch-protection-marked", Verdict::On, Some("full"))];
        let first = |c: Composite| c.constituents.into_iter().next().expect("one constituent");
        for (label, k) in [
            ("cfi x86_64", first(cfi_for_arch(&x86, "x86_64"))),
            ("cfi aarch64", first(cfi_for_arch(&arm, "aarch64"))),
            ("the CET slot", cet_for(&x86, "x86_64")),
        ] {
            assert_eq!(k.state, S::Marked, "{label}: {:?}", k.note);
            assert!(k.satisfied(), "{label}");
            assert_eq!(k.verdict, Some(Verdict::On), "{label}");
            assert!(
                k.note
                    .as_deref()
                    .is_some_and(|n| n.starts_with("marked, not shown in force: ")),
                "{label}: {:?}",
                k.note
            );
            let json = serde_json::to_value(&k).expect("serializes");
            assert_eq!(json["state"], "marked", "{label}");
            assert_eq!(json["satisfied"], true, "{label}");
        }
        let cfi = cfi_for_arch(&x86, "x86_64");
        assert_eq!(cfi.verdict, Verdict::On, "{}", cfi.reason);
        assert!(
            cfi.title
                .starts_with("Does the artifact ask for control-flow protection on both edges"),
            "{}",
            cfi.title
        );
        assert!(
            cfi.reason.starts_with(
                "the artifact is marked for control-flow protection on both edges, via \
                 -fcf-protection=full; "
            ),
            "{}",
            cfi.reason
        );
        for text in [cfi.title, cfi.reason.as_str()] {
            assert!(!text.contains("in force"), "{text}");
        }
    }

    /// The `marked` note and `cfi-effective`'s reason name what the report measured of
    /// enforcement, and the state does not move with it. On x86 that is
    /// `shadow-stack-enforced`, the backward edge: absent from a filtered run, withheld
    /// under a container, measured `partial` at `opt-in` (upstream glibc 2.39 and later;
    /// the Fedora 44 rows of `tests/fixtures/detectors.json` are the recorded case,
    /// replayed in `tests/detector_replay.rs`), or measured `on` at `default`, which no
    /// recorded report shows and this shape stands in for. IBT has no check, so even an
    /// enforced shadow stack leaves the constituent `marked`; the three x86 spellings the
    /// constituents accept read the same clause. On aarch64 no check measures either edge.
    /// Under OpenBSD's C library the clause says what the kernel does (on arm64 BTI is
    /// enforced marked or not; on amd64 the header turns IBT off), and calls the marking
    /// no request.
    #[test]
    fn the_marked_note_names_the_enforcement_reading_and_stays_marked() {
        use ConstituentState as S;
        let marking = obs("cet-marked", Verdict::On, None);
        let gated = |verdict, rule: crate::report::gating_rule::Rule| {
            let mut o = obs("shadow-stack-enforced", verdict, None);
            o.gating = Some(crate::report::Gating {
                rule,
                arch: None,
                libc: None,
                needs_vm: true,
                reason: "test".to_owned(),
            });
            o
        };
        let ibt = "; no check measures IBT enforcement";
        let shapes: Vec<(&str, Option<Observation>, String)> = vec![
            (
                "absent from the report",
                None,
                format!("is not in this report{ibt}"),
            ),
            (
                "withheld under a container",
                Some(gated(
                    Verdict::Indeterminate,
                    crate::report::gating_rule::NEEDS_VM,
                )),
                format!("reads indeterminate under needs-vm{ibt}"),
            ),
            (
                "enforced under the opt-in",
                Some(obs(
                    "shadow-stack-enforced",
                    Verdict::Partial,
                    Some("opt-in"),
                )),
                format!(
                    "reads partial at opt-in (enforced only under glibc's opt-in tunable){ibt}"
                ),
            ),
            (
                "enforced by default",
                Some(obs("shadow-stack-enforced", Verdict::On, Some("default"))),
                format!("reads on at default (enforced without the opt-in tunable){ibt}"),
            ),
            (
                "turned off for this build",
                Some(obs("shadow-stack-enforced", Verdict::Off, None)),
                format!("reads off{ibt}"),
            ),
        ];
        let request = "the marking is a request the kernel, CPU and C library may or may not \
                       act on; ";
        let mut fed = 0;
        for (label, enforcement, want) in shapes {
            let want = format!(
                "{request}shadow-stack-enforced, which runs a program built with the same \
                 flags and measures the backward edge's enforcement, {want}"
            );
            let mut report = vec![marking.clone()];
            report.extend(enforcement);
            for arch in ["x86_64", "x86", "i686"] {
                fed += 1;
                let cfi = cfi_for_arch(&report, arch);
                assert_eq!(
                    cfi.verdict,
                    Verdict::On,
                    "{label} on {arch}: {}",
                    cfi.reason
                );
                let k = &cfi.constituents[0];
                assert_eq!(k.state, S::Marked, "{label} on {arch}: {:?}", k.note);
                assert!(
                    k.note.as_deref().is_some_and(|n| n.ends_with(&want)),
                    "{label} on {arch}: {:?}",
                    k.note
                );
                assert!(
                    cfi.reason.ends_with(&want),
                    "{label} on {arch}: {}",
                    cfi.reason
                );
                let slot = cet_for(&report, arch);
                assert_eq!(slot.state, S::Marked, "{label} on {arch}");
                assert!(
                    slot.note.as_deref().is_some_and(|n| n.ends_with(&want)),
                    "{label} on {arch}: {:?}",
                    slot.note
                );
            }
        }
        assert_eq!(fed, 15);
    }

    /// On aarch64 under a Linux C library the clause says no check measures either edge,
    /// and calls the marking a request.
    #[test]
    fn on_aarch64_linux_the_clause_says_no_check_measures_either_edge() {
        use ConstituentState as S;
        let arm = cfi_for_arch(
            &[obs("branch-protection-marked", Verdict::On, Some("full"))],
            "aarch64",
        );
        assert_eq!(arm.constituents[0].state, S::Marked);
        for text in [
            arm.reason.as_str(),
            arm.constituents[0].note.as_deref().unwrap_or(""),
        ] {
            assert!(
                text.ends_with(
                    "the marking is a request the kernel, CPU and C library may or may not \
                     act on; no check measures BTI or PAC enforcement"
                ),
                "{text}"
            );
        }
    }

    /// Under OpenBSD's C library the clause says what the kernel does, on arm64 that BTI is
    /// enforced for every program without the opt-out header, marked or not, and on amd64
    /// that the header turns IBT enforcement off, and calls the marking no request; the
    /// state is `marked` as elsewhere.
    #[test]
    fn under_openbsd_the_clause_says_what_the_kernel_does() {
        use ConstituentState as S;
        let marking = obs("cet-marked", Verdict::On, None);
        let openbsd = crate::env::Libc {
            impl_name: "openbsd".to_owned(),
            version: None,
            detection: "test".to_owned(),
        };
        let store = crate::report::FactStore::default();
        let bsd_arm = cfi_for(
            &[obs("branch-protection-marked", Verdict::On, Some("full"))],
            "aarch64",
            &openbsd,
            &store,
        );
        assert_eq!(bsd_arm.constituents[0].state, S::Marked);
        for text in [
            bsd_arm.reason.as_str(),
            bsd_arm.constituents[0].note.as_deref().unwrap_or(""),
        ] {
            assert!(
                text.ends_with(
                    "OpenBSD enforces BTI, the forward edge, for every program that does not \
                     carry PT_OPENBSD_NOBTCFI, marked or not (as measured on OpenBSD 7.9 \
                     arm64), and this constituent reads that header beside the marking; no \
                     check measures PAC enforcement"
                ) && !text.contains("request"),
                "{text}"
            );
        }
        let bsd_x86 = cfi_for(std::slice::from_ref(&marking), "x86_64", &openbsd, &store);
        assert!(
            bsd_x86
                .reason
                .contains("on OpenBSD amd64 PT_OPENBSD_NOBTCFI turns IBT enforcement off")
                && bsd_x86.reason.contains("nobtcfi-switches-off-ibt-on-amd64")
                && bsd_x86
                    .reason
                    .ends_with("; no check measures IBT enforcement")
                && !bsd_x86.reason.contains("request"),
            "{}",
            bsd_x86.reason
        );
        let bsd_slot = cet_constituent(&[marking], "x86_64", &openbsd, &store);
        assert_eq!(bsd_slot.state, S::Marked);
        assert!(
            bsd_slot
                .note
                .as_deref()
                .is_some_and(|n| n.contains("turns IBT enforcement off")),
            "{:?}",
            bsd_slot.note
        );
    }

    /// For every verdict a marking check can publish, on either architecture, the
    /// constituent never reads `in-force`, and reads `marked` over `on` alone.
    #[test]
    fn a_marking_reads_marked_over_on_alone_and_never_in_force() {
        use ConstituentState as S;
        let verdicts = [
            Verdict::On,
            Verdict::Off,
            Verdict::Partial,
            Verdict::Unsupported,
            Verdict::NotApplicable,
            Verdict::Indeterminate,
            Verdict::ProbeInvalid,
            Verdict::BuildFailed,
            Verdict::RunFailed,
        ];
        let mut fed = 0;
        for v in verdicts {
            for (check, arch, level) in [
                ("cet-marked", "x86_64", None),
                ("branch-protection-marked", "aarch64", Some("full")),
            ] {
                let report = [obs(check, v, level)];
                let mut states = vec![cfi_for_arch(&report, arch).constituents[0].state];
                if arch == "x86_64" {
                    states.push(cet_for(&report, arch).state);
                }
                for state in states {
                    fed += 1;
                    assert_ne!(state, S::InForce, "{check} {v:?} on {arch}");
                    assert_eq!(
                        state == S::Marked,
                        v == Verdict::On,
                        "{check} {v:?} on {arch}: {state:?}"
                    );
                }
            }
        }
        assert_eq!(fed, 27);
    }

    /// No title or reason of `cfi-effective` says "in force": the `off` and `indeterminate`
    /// reasons say the marking, as the `on` reason does, and the plain `off` says
    /// what the artifact lacks, in these words.
    #[test]
    fn no_cfi_reason_says_in_force() {
        let shapes: Vec<(&str, Vec<Observation>, &str)> = vec![
            (
                "no marking",
                vec![obs("cet-marked", Verdict::Off, None)],
                "x86_64",
            ),
            (
                "one edge",
                vec![obs("cet-marked", Verdict::Partial, Some("branch"))],
                "x86_64",
            ),
            (
                "withheld",
                vec![obs("cet-marked", Verdict::Indeterminate, None)],
                "x86_64",
            ),
            ("absent", vec![], "x86_64"),
            (
                "aarch64 none",
                vec![obs("branch-protection-marked", Verdict::Off, None)],
                "aarch64",
            ),
            ("no mechanism", vec![], "riscv64"),
        ];
        for (label, report, arch) in shapes {
            let cfi = cfi_for_arch(&report, arch);
            for text in [cfi.title, cfi.reason.as_str()] {
                assert!(!text.to_lowercase().contains("in force"), "{label}: {text}");
            }
        }
        let none = cfi_for_arch(&[obs("cet-marked", Verdict::Off, None)], "x86_64");
        assert_eq!(
            none.reason,
            "the artifact carries no control-flow markings, so it is not marked for \
             -fcf-protection=full on either edge"
        );
    }

    /// The sentences "no check measures IBT enforcement", "no check measures BTI or PAC
    /// enforcement" and "no check measures PAC enforcement" in [`enforcement_reading`] are
    /// claims about the corpus, pinned here: the checks whose id names enforcement are
    /// these five, and none measures IBT, BTI or PAC. A check added for one of them fails
    /// this test until the clause quotes its reading.
    #[test]
    fn the_enforcement_sentences_name_every_enforcement_check() {
        let mut enforced: Vec<&str> = crate::probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .map(|c| c.id)
            .filter(|id| id.contains("-enforced"))
            .collect();
        enforced.sort_unstable();
        assert_eq!(
            enforced,
            [
                "fortify-enforced-dynamic",
                "fortify-enforced-known",
                "noexecstack-enforced",
                "shadow-stack-enforced",
                "strict-flex-arrays-enforced",
            ]
        );
    }

    /// The umbrella's reason says the CET slot is confirmed as a marking wherever it is,
    /// before its conclusion, and says "in force" alone where no slot is marked.
    #[test]
    fn the_umbrella_names_its_marked_slot_in_every_verdict() {
        let confirmed = "in force or marked (-fcf-protection=full as a marking the artifact \
                         carries, not as enforcement)";
        let on = fhardened_for(&fully_hardened(), "x86_64", &glibc());
        assert_eq!(on.verdict, Verdict::On, "{}", on.reason);
        assert!(
            on.reason.starts_with(&format!(
                "all 8 applicable constituents are {confirmed}, so "
            )),
            "{}",
            on.reason
        );

        let partial = fhardened_for(&degraded("pie", Verdict::Off, None), "x86_64", &glibc());
        assert_eq!(partial.verdict, Verdict::Partial, "{}", partial.reason);
        assert!(
            partial.reason.starts_with(&format!(
                "7 of 8 constituents are confirmed {confirmed}, so "
            )),
            "{}",
            partial.reason
        );

        let unmeasured = fhardened_for(
            &degraded("pie", Verdict::Indeterminate, None),
            "x86_64",
            &glibc(),
        );
        assert_eq!(
            unmeasured.verdict,
            Verdict::Indeterminate,
            "{}",
            unmeasured.reason
        );
        assert!(
            unmeasured.reason.starts_with(&format!(
                "every constituent that could be confirmed is {confirmed}, "
            )),
            "{}",
            unmeasured.reason
        );

        // Off aarch64's umbrella the slot is inapplicable, so nothing is marked and the
        // reason reads as before.
        let arm = fhardened_for(&fully_hardened(), "aarch64", &glibc());
        assert_eq!(arm.verdict, Verdict::On, "{}", arm.reason);
        assert!(
            arm.reason
                .starts_with("all 7 applicable constituents are in force, so "),
            "{}",
            arm.reason
        );
        assert!(!arm.reason.contains("marked"), "{}", arm.reason);
        // A CET slot short of a marking is not marked either.
        let short = fhardened_for(
            &degraded("cet-marked", Verdict::Off, None),
            "x86_64",
            &glibc(),
        );
        assert!(!short.reason.contains("marked"), "{}", short.reason);
    }

    /// Every constituent note that names a measured verdict spells it as the report does,
    /// so `cfi-effective` and `fhardened-effective` describe one `cet-marked` observation
    /// in the same words, and no note carries a Rust debug spelling such as `Partial`.
    #[test]
    fn constituent_notes_spell_verdicts_as_the_report_does() {
        for verdict in [
            Verdict::Partial,
            Verdict::ProbeInvalid,
            Verdict::Indeterminate,
        ] {
            let marking = [obs("cet-marked", verdict, None)];
            let cfi = cfi_for_arch(&marking, "x86_64");
            let slot = cet_for(&marking, "x86_64");
            let want = format!("cet-marked measured {}", verdict.as_str());
            assert_eq!(cfi.constituents[0].note.as_deref(), Some(want.as_str()));
            assert_eq!(slot.note.as_deref(), Some(want.as_str()));

            let all = [
                obs("stack-clash-guard-page", verdict, None),
                obs("ssp-level-emitted", verdict, None),
                obs("auto-var-init-active", verdict, None),
            ];
            let umbrella = fhardened_for(&all, "x86_64", &glibc());
            let note = |check: &str| {
                umbrella
                    .constituents
                    .iter()
                    .find(|c| c.check == check)
                    .and_then(|c| c.note.clone())
                    .expect("an unsatisfied constituent carries a note")
            };
            assert_eq!(
                note("stack-clash-guard-page"),
                format!("measured {}", verdict.as_str())
            );
            assert!(
                note("ssp-level-emitted")
                    .contains(&format!("ssp-level-emitted {}", verdict.as_str())),
                "{}",
                note("ssp-level-emitted")
            );
            assert!(
                note("auto-var-init-active").contains(&format!(
                    "auto-var-init-active measured {},",
                    verdict.as_str()
                )),
                "{}",
                note("auto-var-init-active")
            );
        }
    }

    /// Where a witness contradicted the architecture a control-flow slot was chosen by,
    /// the slot is held applicable and unestablished rather than dropped on that premise.
    ///
    /// Dropped, a driver answering `aarch64` for an x86_64 compiler would leave
    /// `-fhardened-effective` without its CET constituent and able to read `on` with CET
    /// never established, the reverse of the clean-looking zero.
    #[test]
    fn a_slot_chosen_by_a_contradicted_architecture_is_not_established() {
        use crate::report::gating_rule::{TARGET_ABI_CONTRADICTED, TARGET_CONTRADICTED};
        // Both target rules: the machine's, and the width and byte order's,
        // under which an x32 or aarch64_be read would otherwise lose its CET slot.
        for rule in [TARGET_CONTRADICTED, TARGET_ABI_CONTRADICTED] {
            let withheld = |check: &str| {
                let mut o = obs(check, Verdict::Indeterminate, None);
                o.gating = Some(crate::report::Gating {
                    rule,
                    arch: Some("aarch64".to_owned()),
                    libc: None,
                    needs_vm: false,
                    reason: "r".to_owned(),
                });
                o
            };
            let cet = cet_for(&[withheld("cet-marked")], "aarch64");
            assert!(cet.applicable, "{}", rule.id);
            assert_eq!(cet.state, ConstituentState::NotEstablished, "{}", rule.id);

            let cfi = cfi_for_arch(&[withheld("cet-marked")], "sparc64");
            assert_eq!(
                cfi.verdict,
                Verdict::Indeterminate,
                "{}: {}",
                rule.id,
                cfi.reason
            );
            assert_eq!(cfi.constituents[0].check, "cet-marked");

            let cfi = cfi_for_arch(&[withheld("branch-protection-marked")], "aarch64");
            assert_eq!(
                cfi.verdict,
                Verdict::Indeterminate,
                "{}: {}",
                rule.id,
                cfi.reason
            );
        }
    }

    /// A fortify at exactly the level the umbrella asks for satisfies it.
    ///
    /// The defect this pins: `satisfied` demanded `Verdict::On`, and `fortify-effective`
    /// is `On` only when its level meets its *own* `recommended_level` of 3 — so the
    /// requirement collapsed to `level >= 3` for every value of `want`, and the glibc<2.35
    /// lowering to 2 could never take effect. Every such toolchain published
    /// `state: absent` for a fortify measured in force at the level asked of it, and the
    /// composite subtracted it.
    #[test]
    fn a_fortify_at_the_level_the_umbrella_asks_for_satisfies_it() {
        let old_glibc = crate::env::Libc {
            impl_name: "glibc".to_owned(),
            version: Some("2.31".to_owned()),
            detection: "test".to_owned(),
        };
        let measured = [obs("fortify-effective", Verdict::Partial, Some("2"))];

        let k = fortify_constituent(
            &measured,
            FHARDENED_FORTIFY,
            &crate::toolchain::FhardenedFortify::refused(),
            &old_glibc,
            GNU,
        );
        assert!(
            k.satisfied(),
            "level 2 measured in force, and 2 is what this libc's umbrella asks for"
        );
        assert_eq!(k.state, ConstituentState::InForce);
        // The fortify slot names its bar's reading in force too; every other constituent
        // explains only a shortfall.
        assert!(
            k.note
                .as_deref()
                .is_some_and(|n| n.starts_with("in force: level >= 2 on glibc 2.31")),
            "{:?}",
            k.note
        );

        // The bar still bites where it should: the same reading against a want of 3.
        let short = fortify_constituent(
            &measured,
            FHARDENED_FORTIFY,
            &crate::toolchain::FhardenedFortify::refused(),
            &glibc(),
            GNU,
        );
        assert!(!short.satisfied(), "level 2 does not meet a want of 3");
        assert!(short.note.is_some());

        // And a fortify that is not in force at all is not satisfied by its level alone.
        let off = [obs("fortify-effective", Verdict::Off, Some("2"))];
        assert!(
            !fortify_constituent(
                &off,
                FHARDENED_FORTIFY,
                &crate::toolchain::FhardenedFortify::refused(),
                &old_glibc,
                GNU
            )
            .satisfied(),
            "a level recorded beside an `off` verdict is not a measurement of protection"
        );
    }

    /// The driver's own `-fhardened -O2` dump sets the bar wherever the driver takes the
    /// option, whatever the headers name, both ways: a driver configured against a
    /// glibc older than 2.35 asks 2 over 2.43 headers, where the library reading asks 3, and one
    /// configured against a newer glibc asks 3 over 2.34 headers, where the library reading
    /// asks 2.
    #[test]
    fn the_driver_s_own_fhardened_dump_sets_the_bar_over_the_headers() {
        use crate::toolchain::FhardenedFortify;
        let old_glibc = crate::env::Libc {
            version: Some("2.34".to_owned()),
            ..glibc()
        };
        let two = [obs("fortify-effective", Verdict::Partial, Some("2"))];

        let configured_old = FhardenedFortify::defining("2");
        let k = fortify_constituent(&two, FHARDENED_FORTIFY, &configured_old, &glibc(), GNU);
        assert_eq!(k.state, ConstituentState::InForce, "{:?}", k.note);
        let library = fortify_constituent(
            &two,
            FHARDENED_FORTIFY,
            &FhardenedFortify::refused(),
            &glibc(),
            GNU,
        );
        assert_eq!(library.state, ConstituentState::Absent);
        let note = library.note.expect("a shortfall names its bar");
        assert!(
            note.contains("on glibc 2.43") && note.contains("the library sets the bar because"),
            "the library's reading names itself and why the driver's was not used: {note}"
        );

        let configured_new = FhardenedFortify::defining("3");
        let k = fortify_constituent(&two, FHARDENED_FORTIFY, &configured_new, &old_glibc, GNU);
        assert_eq!(k.state, ConstituentState::Absent);
        let note = k.note.expect("a shortfall names its bar");
        assert!(
            note.starts_with("needs level >= 3 by the driver's -fhardened -O2 dump"),
            "{note}"
        );
        assert_eq!(
            fortify_constituent(
                &two,
                FHARDENED_FORTIFY,
                &FhardenedFortify::refused(),
                &old_glibc,
                GNU
            )
            .state,
            ConstituentState::InForce,
            "the library reading of 2.34 asks 2"
        );
    }

    /// A dump the driver did not take as asked never sets the bar, and one it took sets none
    /// from a level `-fhardened` would not ask: the control, both ways.
    #[test]
    fn a_driver_dump_that_did_not_take_fhardened_sets_no_bar() {
        use crate::toolchain::FhardenedFortify;
        let one = [obs("fortify-effective", Verdict::Partial, Some("1"))];
        let three = [obs("fortify-effective", Verdict::On, Some("3"))];
        let two = [obs("fortify-effective", Verdict::Partial, Some("2"))];
        // A specs file's `-D_FORTIFY_SOURCE=2` under -fhardened: gcc warns and defines 2. Read
        // without the warning, the bar would be 2 and the level-2 build in force.
        let yielded = FhardenedFortify {
            diagnostic: Some(
                "cc1: warning: '_FORTIFY_SOURCE' is not enabled by '-fhardened' because it \
                 was specified in '-D' or '-U' [-Whardened]"
                    .to_owned(),
            ),
            ..FhardenedFortify::defining("2")
        };
        assert!(yielded.refusal().is_some());
        let k = fortify_constituent(&two, FHARDENED_FORTIFY, &yielded, &glibc(), GNU);
        assert_eq!(
            k.state,
            ConstituentState::Absent,
            "the library's 3 stands, not the overridden 2: {:?}",
            k.note
        );
        let cut = FhardenedFortify {
            stdout_unterminated: true,
            ..FhardenedFortify::defining("2")
        };
        let failed = FhardenedFortify {
            exit_status: 1,
            ..FhardenedFortify::defining("2")
        };
        let silent = FhardenedFortify {
            macros_defined: 0,
            ..FhardenedFortify::defining("2")
        };
        for refused in [cut, failed, silent] {
            assert!(refused.refusal().is_some(), "{refused:?}");
            let k = fortify_constituent(&two, FHARDENED_FORTIFY, &refused, &glibc(), GNU);
            assert_eq!(
                k.state,
                ConstituentState::Absent,
                "{refused:?}: {:?}",
                k.note
            );
        }

        // Taken, but no level `-fhardened` asks: the bar is unset, never lowered.
        for (driver, says) in [
            (FhardenedFortify::defining("1"), "outside the levels 2 to 3"),
            (FhardenedFortify::defining("0"), "outside the levels 2 to 3"),
            (FhardenedFortify::defining("4"), "outside the levels 2 to 3"),
            (FhardenedFortify::defining("x"), "which is not a level"),
            (
                FhardenedFortify {
                    fortify_source: None,
                    ..FhardenedFortify::defining("3")
                },
                "defined no _FORTIFY_SOURCE",
            ),
        ] {
            let k = fortify_constituent(&one, FHARDENED_FORTIFY, &driver, &glibc(), GNU);
            assert_eq!(k.state, ConstituentState::Absent, "{driver:?}");
            assert!(
                k.note.as_deref().is_some_and(|n| n.contains(says)),
                "{driver:?}: {:?}",
                k.note
            );
            let k = fortify_constituent(&three, FHARDENED_FORTIFY, &driver, &glibc(), GNU);
            assert_eq!(
                k.state,
                ConstituentState::InForce,
                "level 3 meets either bar: {driver:?}"
            );
            assert!(
                k.note.as_deref().is_some_and(|n| n
                    .starts_with("in force: measured level 3 meets either bar, and ")
                    && n.contains(says)),
                "an unset bar's in-force slot names why the bar is unset: {:?}",
                k.note
            );
        }
    }

    /// The control arm of the driver's reading: a level the `-O2` dump defines too is not the
    /// option's own, and a control that failed, was cut or defined nothing attributes nothing;
    /// a control that differs leaves the reading standing.
    #[test]
    fn a_level_the_control_defines_too_sets_no_bar() {
        use crate::toolchain::FhardenedFortify;
        let two = [obs("fortify-effective", Verdict::Partial, Some("2"))];
        // The same 2 with the warning silenced (`-w`) or the token dropped by a wrapper: the
        // control defines it too, so the option showed nothing.
        let silenced = FhardenedFortify {
            baseline: crate::toolchain::FortifyBaseline {
                fortify_source: Some("2".to_owned()),
                ..FhardenedFortify::defining("2").baseline
            },
            ..FhardenedFortify::defining("2")
        };
        let k = fortify_constituent(&two, FHARDENED_FORTIFY, &silenced, &glibc(), GNU);
        assert_eq!(k.state, ConstituentState::Absent, "{:?}", k.note);
        assert!(
            k.note
                .as_deref()
                .is_some_and(|n| n.contains("defines _FORTIFY_SOURCE 2 as well")),
            "{:?}",
            k.note
        );
        // A control that differs (a default of 2 that `-fhardened` raises to 3) leaves the
        // option's reading standing.
        let raised = FhardenedFortify {
            baseline: crate::toolchain::FortifyBaseline {
                fortify_source: Some("2".to_owned()),
                ..FhardenedFortify::defining("3").baseline
            },
            ..FhardenedFortify::defining("3")
        };
        assert_eq!(raised.refusal(), None);
        let failed_control = FhardenedFortify {
            baseline: crate::toolchain::FortifyBaseline {
                exit_status: 1,
                ..FhardenedFortify::defining("2").baseline
            },
            ..FhardenedFortify::defining("2")
        };
        let cut_control = FhardenedFortify {
            baseline: crate::toolchain::FortifyBaseline {
                stdout_unterminated: true,
                ..FhardenedFortify::defining("2").baseline
            },
            ..FhardenedFortify::defining("2")
        };
        let empty_control = FhardenedFortify {
            baseline: crate::toolchain::FortifyBaseline {
                macros_defined: 0,
                ..FhardenedFortify::defining("2").baseline
            },
            ..FhardenedFortify::defining("2")
        };
        for refused in [failed_control, cut_control, empty_control] {
            assert!(refused.refusal().is_some(), "{refused:?}");
            let k = fortify_constituent(&two, FHARDENED_FORTIFY, &refused, &glibc(), GNU);
            assert_eq!(
                k.state,
                ConstituentState::Absent,
                "{refused:?}: {:?}",
                k.note
            );
        }
    }

    /// `fortify-effective` decided by the fortify-headers clause the request selects, as the
    /// producer does (above 2, the dynamic-request clause), at the level that library enforces
    /// whatever is asked, with `fortify-requested` beside it.
    fn fortify_headers_build(requested: Option<(Verdict, &str)>) -> Vec<Observation> {
        use crate::predicate::macro_channel::{
            FORTIFY_HEADERS_CLAUSE, FORTIFY_HEADERS_DYNAMIC_CLAUSE,
        };
        let above_two = requested.is_some_and(|(_, l)| l.parse::<u32>().is_ok_and(|n| n > 2));
        let clause = if above_two {
            FORTIFY_HEADERS_DYNAMIC_CLAUSE
        } else {
            FORTIFY_HEADERS_CLAUSE
        };
        let mut effective = obs("fortify-effective", Verdict::Partial, Some("1"));
        effective.evidence.decoded = Some(crate::report::Decoded {
            facts: "0".repeat(64),
            macros: None,
            clause: clause.to_owned(),
            outcome: crate::probe::Outcome::Present,
            level: Some("1".to_owned()),
        });
        let mut out = vec![effective];
        if let Some((verdict, level)) = requested {
            out.push(obs("fortify-requested", verdict, Some(level)));
        }
        out
    }

    /// Each clause that reads fortify-headers' level identifies the implementation, the
    /// request's split among them included; the clause that withholds an unreadable
    /// request under it does not, since no level was read, and another clause's level 1 is
    /// not fortify-headers'.
    #[test]
    fn every_fortify_headers_level_clause_identifies_the_implementation() {
        use crate::predicate::macro_channel::{
            FORTIFY_HEADERS_CLAUSE, FORTIFY_HEADERS_DYNAMIC_CLAUSE, FORTIFY_HEADERS_UNREAD_CLAUSE,
        };
        let decided_by = |clause: &str| {
            let mut build = fortify_headers_build(Some((Verdict::On, "3")));
            let decoded = build[0].evidence.decoded.as_mut();
            clause.clone_into(&mut decoded.expect("the build is decoded").clause);
            fortify_headers_reading(&build)
        };
        let mut fed = 0usize;
        // The ids by name, not the list the function reads, which would pin itself.
        for clause in [FORTIFY_HEADERS_DYNAMIC_CLAUSE, FORTIFY_HEADERS_CLAUSE] {
            let reading = decided_by(clause).unwrap_or_else(|| panic!("{clause} identifies it"));
            assert_eq!(reading.name, "fortify-headers");
            assert_eq!(reading.requested_level.as_deref(), Some("3"));
            fed += 1;
        }
        assert_eq!(fed, 2);
        for other in [FORTIFY_HEADERS_UNREAD_CLAUSE, "glibc-level", "apple-level"] {
            assert!(decided_by(other).is_none(), "{other}");
        }
    }

    /// On fortify-headers the slot is in force where the request reached the library at the
    /// bar, since level 1 is the highest rung it implements; the request and the
    /// implementation are published, and a request under the bar, a request measured `off`,
    /// or none, leaves the slot absent, while a request withheld leaves it not established.
    #[test]
    fn fortify_headers_is_in_force_where_the_request_reached_it() {
        use crate::toolchain::FhardenedFortify;
        let musl = crate::env::Libc {
            impl_name: "musl".to_owned(),
            version: Some("1.2.6".to_owned()),
            detection: "test".to_owned(),
        };
        let alpine = Some("x86_64-alpine-linux-musl");
        let asks_two = FhardenedFortify::defining("2");

        let k = fortify_constituent(
            &fortify_headers_build(Some((Verdict::Partial, "2"))),
            FHARDENED_FORTIFY,
            &asks_two,
            &musl,
            alpine,
        );
        assert_eq!(k.state, ConstituentState::InForce, "{:?}", k.note);
        assert_eq!(
            k.level.as_deref(),
            Some("1"),
            "the library's own level stays"
        );
        let implementation = k.implementation.clone().expect("published");
        assert_eq!(implementation.name, "fortify-headers");
        assert_eq!(implementation.top_level, "1");
        assert_eq!(implementation.requested_level.as_deref(), Some("2"));
        assert!(
            k.note
                .as_deref()
                .is_some_and(|n| n.contains("top rung") && n.contains("level 2 requested")),
            "{:?}",
            k.note
        );
        // The parenthesis says what holds at every request: above 2 the checks size
        // objects dynamically, so "whole-object bounds only" would read as no dynamic sizing.
        assert!(
            k.note
                .as_deref()
                .is_some_and(|n| n.contains("(its checks never ask a subobject's bounds)")),
            "{:?}",
            k.note
        );
        let json = serde_json::to_value(&k).expect("serializes");
        assert_eq!(json["implementation"]["requested_level"], "2");

        // The library reading (a driver refusing the option) reaches the same bar on musl.
        let k = fortify_constituent(
            &fortify_headers_build(Some((Verdict::Partial, "2"))),
            FHARDENED_FORTIFY,
            &FhardenedFortify::refused(),
            &musl,
            alpine,
        );
        assert_eq!(k.state, ConstituentState::InForce, "{:?}", k.note);

        for (requested, state) in [
            (Some((Verdict::Partial, "1")), ConstituentState::Absent),
            (Some((Verdict::Off, "2")), ConstituentState::Absent),
            // A request withheld rather than measured is not no request: the slot is not
            // established (absence is claimed only from a
            // measurement, so a withheld request leaves the slot open).
            (
                Some((Verdict::Indeterminate, "2")),
                ConstituentState::NotEstablished,
            ),
            (None, ConstituentState::Absent),
        ] {
            let k = fortify_constituent(
                &fortify_headers_build(requested),
                FHARDENED_FORTIFY,
                &asks_two,
                &musl,
                alpine,
            );
            assert_eq!(k.state, state, "{requested:?}");
            assert!(k.implementation.is_some(), "published either way");
        }

        // A level-3 bar is met only by a level-3 request.
        let asks_three = FhardenedFortify::defining("3");
        for (requested, state) in [
            ("2", ConstituentState::Absent),
            ("3", ConstituentState::InForce),
        ] {
            let k = fortify_constituent(
                &fortify_headers_build(Some((Verdict::On, requested))),
                FHARDENED_FORTIFY,
                &asks_three,
                &musl,
                alpine,
            );
            assert_eq!(k.state, state, "requested {requested}: {:?}", k.note);
        }

        // Another clause's level 1 is not met by a request: only fortify-headers enforces
        // its top rung whatever is asked.
        let mut glibc_one = fortify_headers_build(Some((Verdict::Partial, "2")));
        if let Some(d) = glibc_one[0].evidence.decoded.as_mut() {
            d.clause = "glibc-level".to_owned();
        }
        let k = fortify_constituent(&glibc_one, FHARDENED_FORTIFY, &asks_two, &glibc(), GNU);
        assert_eq!(k.state, ConstituentState::Absent);
        assert!(k.implementation.is_none());
    }

    /// A request withheld rather than measured leaves a fortify-headers slot not
    /// established, under a bar and under none, where a request measured `off` leaves it
    /// absent: the request is what meets the bar there, and a request chard could not read
    /// (`-D_FORTIFY_SOURCE=(3)` reads `fortify-requested` `indeterminate`) is not no
    /// request.
    #[test]
    fn a_withheld_request_on_fortify_headers_is_not_no_request() {
        use crate::toolchain::FhardenedFortify;
        let musl = crate::env::Libc {
            impl_name: "musl".to_owned(),
            version: Some("1.2.6".to_owned()),
            detection: "test".to_owned(),
        };
        let alpine = Some("x86_64-alpine-linux-musl");
        let asks_two = FhardenedFortify::defining("2");
        for (verdict, state) in [
            (Verdict::Indeterminate, ConstituentState::NotEstablished),
            (Verdict::ProbeInvalid, ConstituentState::NotEstablished),
            (Verdict::Off, ConstituentState::Absent),
        ] {
            let k = fortify_constituent(
                &fortify_headers_build(Some((verdict, ""))),
                FHARDENED_FORTIFY,
                &asks_two,
                &musl,
                alpine,
            );
            assert_eq!(k.state, state, "requested {verdict:?}: {:?}", k.note);
            assert_eq!(
                k.note.as_deref().is_some_and(|n| n.contains("withheld")),
                !verdict.is_measurement(),
                "requested {verdict:?}: {:?}",
                k.note
            );
            assert_eq!(
                k.verdict,
                Some(Verdict::Partial),
                "the slot's verdict is still published"
            );
        }
        // Under no bar the same request leaves the slot not established, and says so.
        let unset = fortify_constituent(
            &fortify_headers_build(Some((Verdict::Indeterminate, ""))),
            FHARDENED_FORTIFY,
            &FhardenedFortify::refused(),
            &musl,
            GNU,
        );
        assert_eq!(unset.bar, None, "{:?}", unset.note);
        assert_eq!(
            unset.state,
            ConstituentState::NotEstablished,
            "{:?}",
            unset.note
        );
        assert!(
            unset
                .note
                .as_deref()
                .is_some_and(|n| n.contains("withheld")),
            "{:?}",
            unset.note
        );
    }

    /// Under an unset bar, a fortify-headers request between the two levels is what meets the
    /// lower one, and the note says so rather than crediting the library's level 1.
    #[test]
    fn an_unset_bar_names_the_request_that_meets_it_on_fortify_headers() {
        use crate::toolchain::FhardenedFortify;
        let musl = crate::env::Libc {
            impl_name: "musl".to_owned(),
            version: Some("1.2.6".to_owned()),
            detection: "test".to_owned(),
        };
        // A taken dump defining 1 sets no bar.
        let k = fortify_constituent(
            &fortify_headers_build(Some((Verdict::Partial, "2"))),
            FHARDENED_FORTIFY,
            &FhardenedFortify::defining("1"),
            &musl,
            Some("x86_64-alpine-linux-musl"),
        );
        assert_eq!(k.state, ConstituentState::NotEstablished, "{:?}", k.note);
        let note = k.note.expect("an unset bar names why");
        assert!(
            note.starts_with("not established: fortify-headers' requested level 2 meets"),
            "{note}"
        );
        assert!(!note.contains("measured level 1 meets"), "{note}");
    }

    /// The slot publishes the bar it was held to as a value beside the note: the level and
    /// which reading set it, the driver's where the dump answered and the library's where it
    /// did not, and none where no reading set a bar. The spelling serde writes is
    /// [`BarSource::as_str`]'s, and [`BAR_SOURCES`] lists every one.
    #[test]
    fn the_fortify_slot_publishes_its_bar_as_a_value() {
        use crate::toolchain::FhardenedFortify;
        let two = [obs("fortify-effective", Verdict::Partial, Some("2"))];
        let bar_of = |driver: &FhardenedFortify, libc: &crate::env::Libc, triple: Option<&str>| {
            fortify_constituent(&two, FHARDENED_FORTIFY, driver, libc, triple).bar
        };
        let bar = |level: u32, source: BarSource| Some(FortifyBarReading { level, source });
        assert_eq!(
            bar_of(&FhardenedFortify::defining("3"), &glibc(), GNU),
            bar(3, BarSource::Driver)
        );
        assert_eq!(
            bar_of(&FhardenedFortify::defining("2"), &glibc(), GNU),
            bar(2, BarSource::Driver)
        );
        let old_glibc = crate::env::Libc {
            version: Some("2.34".to_owned()),
            ..glibc()
        };
        assert_eq!(
            bar_of(&FhardenedFortify::refused(), &old_glibc, GNU),
            bar(2, BarSource::Library)
        );
        assert_eq!(
            bar_of(&FhardenedFortify::refused(), &glibc(), GNU),
            bar(3, BarSource::Library)
        );

        // Musl headers under a glibc-configured driver set no bar, so none is published.
        let musl = crate::env::Libc {
            impl_name: "musl".to_owned(),
            version: Some("1.2.6".to_owned()),
            detection: "test".to_owned(),
        };
        let unset = fortify_constituent(
            &two,
            FHARDENED_FORTIFY,
            &FhardenedFortify::refused(),
            &musl,
            GNU,
        );
        assert_eq!(unset.bar, None, "{:?}", unset.note);
        assert_eq!(unset.state, ConstituentState::NotEstablished);

        let set = fortify_constituent(
            &two,
            FHARDENED_FORTIFY,
            &FhardenedFortify::defining("3"),
            &glibc(),
            GNU,
        );
        let json = serde_json::to_value(&set).expect("serializes");
        assert_eq!(
            json["bar"],
            serde_json::json!({"level": 3, "source": "driver"})
        );
        let json = serde_json::to_value(&unset).expect("serializes");
        assert!(json.get("bar").is_none(), "{json}");

        let mut fed = 0;
        for source in BarSource::ALL {
            fed += 1;
            assert_eq!(
                serde_json::to_value(source).expect("a unit variant serializes"),
                serde_json::json!(source.as_str())
            );
            assert!(BAR_SOURCES.contains(&source.as_str()), "{source:?}");
        }
        assert_eq!(fed, BAR_SOURCES.len());
    }

    /// A native glibc toolchain's triple.
    const GNU: Option<&str> = Some("x86_64-linux-gnu");

    /// What a library-read bar's note ends with under
    /// [`crate::toolchain::FhardenedFortify::refused`]: why the driver's own reading was not
    /// used, after a bar the library set and after one it could not.
    const REFUSED_OK: &str = "; the library sets the bar because the driver's -fhardened -O2 \
                              dump said `clang: error: unknown argument: '-fhardened'`";
    const REFUSED_ERR: &str = ", and the driver's -fhardened -O2 dump said `clang: error: \
                               unknown argument: '-fhardened'`";

    /// An observation carrying just enough for the composites to reduce over.
    fn obs(check: &str, verdict: Verdict, level: Option<&str>) -> Observation {
        Observation {
            probe: "test".to_owned(),
            check: check.to_owned(),
            flag: "test".to_owned(),
            channel: crate::probe::Channel::ElfStatic,
            polarity: crate::probe::Polarity::Harden,
            verdict,
            level: level.map(ToOwned::to_owned),
            recommended_level: None,
            confidence: "high".to_owned(),
            observable: "test".to_owned(),
            boundary: None,
            defects: Vec::new(),
            observes: crate::probe::Observes::Protection,
            references: Vec::new(),
            evidence: crate::report::EvidenceOut::default(),
            build: None,
            run: None,
            controls: None,
            gating: None,
            build_rejection: None,
            structured_diagnostics: None,
            notes: String::new(),
        }
    }

    fn glibc() -> crate::env::Libc {
        crate::env::Libc {
            impl_name: "glibc".to_owned(),
            version: Some("2.43".to_owned()),
            detection: "test".to_owned(),
        }
    }

    /// Every observation the umbrella reduces over, each one satisfying its constituent.
    fn fully_hardened() -> Vec<Observation> {
        vec![
            obs("fortify-effective", Verdict::On, Some("3")),
            obs("cxx-stdlib-assertions", Verdict::On, None),
            obs("pie", Verdict::On, None),
            obs("ssp-level-emitted", Verdict::On, Some("strong")),
            obs("stack-clash-guard-page", Verdict::On, None),
            obs("relro", Verdict::On, Some("full")),
            obs("auto-var-init-active", Verdict::On, None),
            // The umbrella specifies `=zero`, so the *pattern* fill must be measured off.
            obs("auto-var-init-pattern", Verdict::Off, None),
            obs("cet-marked", Verdict::On, None),
        ]
    }

    /// Replace one observation, leaving the rest satisfied.
    fn degraded(check: &str, verdict: Verdict, level: Option<&str>) -> Vec<Observation> {
        let mut set = fully_hardened();
        for o in &mut set {
            if o.check == check {
                o.verdict = verdict;
                o.level = level.map(ToOwned::to_owned);
            }
        }
        set
    }

    /// Every constituent of the umbrella can fail it, and says so when it does.
    ///
    /// Tests of the umbrella's helpers alone do not hold the umbrella: under them `cargo
    /// mutants` leaves seventeen survivors across `fortify_constituent`, `cet_constituent` and
    /// `fhardened_constituents`, one replacing the entire constituent list with `vec![]`. Each
    /// survivor is a way for a constituent to
    /// stop discriminating — `== On` becoming `!= On`, an `&&` becoming `||`, a dropped
    /// `!` — which in a composite that publishes a verdict is a wrong answer about a
    /// build, not a style problem.
    ///
    /// So this drives the umbrella end to end: one satisfied set, then each constituent
    /// degraded in turn, asserting the composite notices *and* that the constituent whose
    /// evidence moved is the one carrying the explanation.
    #[test]
    fn every_constituent_of_the_umbrella_can_fail_it() {
        let all_on = fhardened_for(&fully_hardened(), "x86_64", &glibc());
        assert_eq!(
            all_on.verdict,
            Verdict::On,
            "a fully satisfied set must read on: {}",
            all_on.reason
        );
        assert_eq!(
            all_on.constituents.iter().filter(|c| c.applicable).count(),
            8,
            "the x86_64 umbrella reduces over eight constituents"
        );
        for c in &all_on.constituents {
            // The fortify slot names its bar's reading in force too, and the CET
            // slot says it is a marking and what was measured of enforcement.
            let explained = (c.check == "fortify-effective"
                && c.note
                    .as_deref()
                    .is_some_and(|n| n.starts_with("in force: ")))
                || (c.state == ConstituentState::Marked
                    && c.note
                        .as_deref()
                        .is_some_and(|n| n.starts_with("marked, not shown in force: ")));
            assert!(
                c.note.is_none() || explained,
                "{}: a satisfied constituent has nothing to explain but its bar or its \
                 marking, got {:?}",
                c.check,
                c.note
            );
        }

        // Each way a single constituent falls short, and the check that must carry it.
        for (check, verdict, level, carrier) in [
            // Fortify is judged on strength: level 2 is on, and below the umbrella's bar.
            (
                "fortify-effective",
                Verdict::On,
                Some("2"),
                "fortify-effective",
            ),
            ("fortify-effective", Verdict::Off, None, "fortify-effective"),
            (
                "cxx-stdlib-assertions",
                Verdict::Off,
                None,
                "cxx-stdlib-assertions",
            ),
            ("pie", Verdict::Off, None, "pie"),
            // The protector is judged on its rule: plain -fstack-protector reads partial
            // at basic, and is short of strong.
            (
                "ssp-level-emitted",
                Verdict::Partial,
                Some("basic"),
                "ssp-level-emitted",
            ),
            ("ssp-level-emitted", Verdict::Off, None, "ssp-level-emitted"),
            (
                "stack-clash-guard-page",
                Verdict::Off,
                None,
                "stack-clash-guard-page",
            ),
            // relro must be full: partial is `on` and still short.
            ("relro", Verdict::On, Some("partial"), "relro"),
            // A pattern fill is hardened, and is not the `=zero` the umbrella specifies.
            (
                "auto-var-init-pattern",
                Verdict::On,
                None,
                "auto-var-init-active",
            ),
            (
                "auto-var-init-active",
                Verdict::Off,
                None,
                "auto-var-init-active",
            ),
            ("cet-marked", Verdict::Off, None, "cet-marked"),
        ] {
            let c = fhardened_for(&degraded(check, verdict, level), "x86_64", &glibc());
            assert_ne!(
                c.verdict,
                Verdict::On,
                "{check} at {verdict:?}/{level:?} left the umbrella reading on: {}",
                c.reason
            );
            let k = c
                .constituents
                .iter()
                .find(|k| k.check == carrier)
                .unwrap_or_else(|| panic!("{carrier} is not a constituent"));
            assert!(
                !k.satisfied(),
                "{check} moved and {carrier} still reports satisfied"
            );
            assert!(
                k.note.is_some(),
                "{carrier} is unsatisfied and says nothing about why"
            );
        }
    }

    /// A pattern fill is reported as a pattern fill, not as "not established".
    ///
    /// `is_active` reaches only the note, so every assertion about the *verdict* is blind
    /// to it. Mutating its `== On` to `!= On` survives every one of them, and it swaps a
    /// constituent that says "initialization is active but fills the pattern byte" for one
    /// that says the fill mode is unknown. Both are unsatisfied, so only the words
    /// differ, and the words are the whole difference between a build that hardens
    /// differently than the umbrella asks and a build nobody could measure.
    #[test]
    fn a_pattern_fill_is_described_as_one() {
        let c = fhardened_for(
            &degraded("auto-var-init-pattern", Verdict::On, None),
            "x86_64",
            &glibc(),
        );
        let k = c
            .constituents
            .iter()
            .find(|k| k.check == "auto-var-init-active")
            .expect("the constituent exists");
        assert!(!k.satisfied(), "=zero is not what this build did");
        let note = k
            .note
            .as_deref()
            .expect("an unsatisfied constituent explains itself");
        assert!(
            note.contains("pattern byte"),
            "an active pattern fill must be named as one, got {note:?}"
        );
        assert_eq!(
            k.level.as_deref(),
            Some("pattern"),
            "and the level carries it too"
        );

        // Where initialization is genuinely unmeasurable, the note must *not* claim a
        // pattern fill — the same field, the opposite failure.
        let c = fhardened_for(
            &degraded("auto-var-init-active", Verdict::ProbeInvalid, None),
            "x86_64",
            &glibc(),
        );
        let k = c
            .constituents
            .iter()
            .find(|k| k.check == "auto-var-init-active")
            .expect("the constituent exists");
        let note = k
            .note
            .as_deref()
            .expect("an unsatisfied constituent explains itself");
        assert!(
            note.contains("not established"),
            "an unmeasurable fill must say so, got {note:?}"
        );
    }

    /// The umbrella's own constituent list is what it reduces over.
    ///
    /// Replacing `fhardened_constituents` with `vec![]` survived every test in this file.
    /// An umbrella with nothing to reduce is not a hardened build; it is a broken report.
    #[test]
    fn an_umbrella_with_no_constituents_is_not_a_verdict_about_a_build() {
        let c = fhardened_for(&fully_hardened(), "x86_64", &glibc());
        assert!(
            !c.constituents.is_empty(),
            "the umbrella reduced over nothing"
        );
        assert!(
            c.derived_from.contains(&"cet-marked") && c.derived_from.contains(&"pie"),
            "derived_from must name the checks reduced over, got {:?}",
            c.derived_from
        );
    }

    /// The shape measured 2026-10-23: the `-fhardened` set with plain `-fstack-protector`
    /// in place of `-strong`, where `ssp-level-emitted` reads `partial` at `basic` and
    /// `canary-emitted`, beside it, reads `on`.
    fn plain_stack_protector() -> Vec<Observation> {
        let mut set = degraded("ssp-level-emitted", Verdict::Partial, Some("basic"));
        set.push(obs("canary-emitted", Verdict::On, None));
        set
    }

    /// `fully_hardened` without `check`.
    fn without(check: &str) -> Vec<Observation> {
        fully_hardened()
            .into_iter()
            .filter(|o| o.check != check)
            .collect()
    }

    /// The protector slot reads the graded check and nothing else: under plain
    /// `-fstack-protector` the umbrella is not `on`, the slot is absent at `basic` and names
    /// `ssp-level-emitted`, and a `canary-emitted` `on` in the same report rescues nothing.
    #[test]
    fn plain_stack_protector_is_not_the_strong_the_umbrella_asks() {
        let c = fhardened_for(&plain_stack_protector(), "x86_64", &glibc());
        assert_eq!(c.verdict, Verdict::Partial, "{}", c.reason);
        assert!(
            c.reason.contains("missing: -fstack-protector-strong"),
            "{}",
            c.reason
        );
        let k = c
            .constituents
            .iter()
            .find(|k| k.flag == SSP_SLOT_FLAG)
            .expect("the protector slot");
        assert_eq!(k.check, SSP_SLOT_CHECK);
        assert_eq!(k.state, ConstituentState::Absent);
        assert_eq!(k.verdict, Some(Verdict::Partial));
        assert_eq!(k.level.as_deref(), Some("basic"));
        assert_eq!(
            k.note.as_deref(),
            Some(
                "needs the strong rule or above (explicit < basic < strong < all); measured basic"
            )
        );
        assert!(
            c.derived_from.contains(&SSP_SLOT_CHECK) && !c.derived_from.contains(&"canary-emitted"),
            "{:?}",
            c.derived_from
        );
    }

    /// Each reading of `ssp-level-emitted` and the state the slot takes from it, both
    /// ways, with the words: in force at the ask or above, absent below it or at `off`, and
    /// not established wherever the check decided nothing the slot could read (withheld,
    /// absent from the report, no level, a word on no rung, a level its verdict denies);
    /// and the umbrella's verdict over each
    /// (`the_protector_slot_reads_each_level_of_the_graded_check`).
    fn protector_rows() -> Vec<(Option<Verdict>, Option<String>, ConstituentState, String)> {
        use ConstituentState as S;
        const ASK: &str =
            "needs the strong rule or above (explicit < basic < strong < all); measured";
        const NOT: &str = "not established: ssp-level-emitted";
        const SO: &str = ", so whether the strong rule is in force is unknown rather than absent";
        const NO_RUNG: &str = ", a word on no rung of explicit < basic < strong < all, which the check grades \
             against nothing";
        let row = |verdict: Option<Verdict>, level: Option<&str>, state: S, note: String| {
            (verdict, level.map(str::to_owned), state, note)
        };
        vec![
            row(Some(Verdict::On), Some("strong"), S::InForce, String::new()),
            row(Some(Verdict::On), Some("all"), S::InForce, String::new()),
            row(
                Some(Verdict::Partial),
                Some("basic"),
                S::Absent,
                format!("{ASK} basic"),
            ),
            row(
                Some(Verdict::Partial),
                Some("explicit"),
                S::Absent,
                format!("{ASK} explicit"),
            ),
            row(Some(Verdict::Off), None, S::Absent, format!("{ASK} off")),
            row(
                Some(Verdict::Off),
                Some("strong"),
                S::NotEstablished,
                format!(
                    "{NOT} off at strong, a level beside a verdict that says no function was \
                     instrumented{SO}"
                ),
            ),
            row(
                Some(Verdict::On),
                Some("unsafe-frame"),
                S::NotEstablished,
                format!("{NOT} on at unsafe-frame{NO_RUNG}{SO}"),
            ),
            row(
                Some(Verdict::On),
                Some("medium"),
                S::NotEstablished,
                format!("{NOT} on at medium{NO_RUNG}{SO}"),
            ),
            row(
                Some(Verdict::On),
                None,
                S::NotEstablished,
                format!("{NOT} on with no level{SO}"),
            ),
            row(
                Some(Verdict::Partial),
                Some("strong"),
                S::NotEstablished,
                format!(
                    "{NOT} partial at strong, a level its scale grades as meeting strong \
                     beside a verdict that says it does not{SO}"
                ),
            ),
            row(
                Some(Verdict::Indeterminate),
                None,
                S::NotEstablished,
                format!("{NOT} indeterminate{SO}"),
            ),
            row(
                Some(Verdict::ProbeInvalid),
                None,
                S::NotEstablished,
                format!("{NOT} probe-invalid{SO}"),
            ),
            row(
                Some(Verdict::On),
                Some("basic"),
                S::NotEstablished,
                format!(
                    "{NOT} on at basic, a level its scale grades below strong beside a verdict \
                     that says it meets it{SO}"
                ),
            ),
            row(
                Some(Verdict::Indeterminate),
                Some("strong"),
                S::NotEstablished,
                format!("{NOT} indeterminate{SO}"),
            ),
            row(
                None,
                None,
                S::NotEstablished,
                "check not present in this report".to_owned(),
            ),
        ]
    }

    /// Each row of [`protector_rows`] through the derivation and the umbrella.
    #[test]
    fn the_protector_slot_reads_each_level_of_the_graded_check() {
        use ConstituentState as S;
        let mut fed = 0;
        for (verdict, level, state, note) in protector_rows() {
            let set = match verdict {
                Some(v) => degraded("ssp-level-emitted", v, level.as_deref()),
                None => without("ssp-level-emitted"),
            };
            let k = ssp_constituent(&set);
            fed += 1;
            assert_eq!(k.state, state, "{verdict:?} at {level:?}: {:?}", k.note);
            assert_eq!(k.verdict, verdict);
            assert_eq!(k.level, level);
            let want = (!note.is_empty()).then_some(note.as_str());
            assert_eq!(k.note.as_deref(), want, "{verdict:?} at {level:?}");
            let umbrella = fhardened_for(&set, "x86_64", &glibc()).verdict;
            let want = match state {
                S::InForce => Verdict::On,
                S::Absent => Verdict::Partial,
                S::NotEstablished | S::NotApplicable => Verdict::Indeterminate,
                S::Marked => unreachable!("the protector slot reads no marking"),
            };
            assert_eq!(umbrella, want, "{verdict:?} at {level:?}");
        }
        assert_eq!(fed, 15);
    }

    /// The umbrella's reason names a protector reading it could not grade apart from one it
    /// could not measure: `SafeStack`'s `unsafe-frame` is a measurement, and "could not be
    /// measured" would describe it as none.
    #[test]
    fn the_umbrella_names_a_protector_reading_it_could_not_grade() {
        let c = fhardened_for(
            &degraded("ssp-level-emitted", Verdict::On, Some("unsafe-frame")),
            "x86_64",
            &glibc(),
        );
        assert_eq!(c.verdict, Verdict::Indeterminate, "{}", c.reason);
        assert!(
            c.reason.contains(
                "1 was measured but not graded against the strong rule (ssp-level-emitted)"
            ) && !c.reason.contains("could not be measured"),
            "{}",
            c.reason
        );
        let c = fhardened_for(
            &degraded("ssp-level-emitted", Verdict::Indeterminate, None),
            "x86_64",
            &glibc(),
        );
        assert_eq!(c.verdict, Verdict::Indeterminate, "{}", c.reason);
        assert!(
            c.reason
                .contains("1 could not be measured (ssp-level-emitted)")
                && !c.reason.contains("not graded"),
            "{}",
            c.reason
        );
    }

    /// The umbrella's constituents are [`FHARDENED_FLAGS`], in order, on both sides of the
    /// x86 gate: off x86 the CET slot is inapplicable, not missing.
    #[test]
    fn the_umbrella_reduces_over_exactly_the_published_flag_list() {
        for arch in ["x86_64", "aarch64"] {
            let c = fhardened_for(&fully_hardened(), arch, &glibc());
            let flags: Vec<&str> = c.constituents.iter().map(|c| c.flag).collect();
            assert_eq!(
                flags, FHARDENED_FLAGS,
                "on {arch} the constituents' flags are not FHARDENED_FLAGS"
            );
        }
        assert!(
            FHARDENED_FLAGS.contains(&SSP_SLOT_FLAG),
            "the protector slot's flag is one of the list"
        );
    }

    /// The umbrella's fortify bar moves at [`FHARDENED_FORTIFY`]'s glibc and nowhere else:
    /// a fortify in force at the fallback level satisfies it one minor below the threshold
    /// and not at it, and one at the full level satisfies it on both. `tests/fhardened_set.rs`
    /// holds the constant to gcc's text; this holds the composite to the constant, so a
    /// literal threshold at the call site that disagrees with it fails here.
    #[test]
    fn the_umbrella_s_fortify_bar_moves_at_the_published_glibc() {
        let rule = FHARDENED_FORTIFY;
        let (major, minor) = rule.glibc;
        let at = format!("{major}.{minor}");
        let below = format!("{major}.{}", minor.saturating_sub(1));
        let fallback = rule.fallback.to_string();
        let full = rule.level.to_string();
        let cases = [
            (&below, &fallback, true),
            (&at, &fallback, false),
            (&below, &full, true),
            (&at, &full, true),
        ];
        let mut examined = 0_usize;
        for (version, level, want) in cases {
            let libc = crate::env::Libc {
                version: Some(version.clone()),
                ..glibc()
            };
            let set = degraded("fortify-effective", Verdict::Partial, Some(level));
            let c = fhardened_for(&set, "x86_64", &libc);
            let fortify = c
                .constituents
                .iter()
                .find(|c| c.check == "fortify-effective")
                .expect("the umbrella has a fortify constituent");
            assert_eq!(
                fortify.satisfied(),
                want,
                "fortify level {level} on glibc {version}: {:?}",
                fortify.note
            );
            examined = examined.saturating_add(1);
        }
        assert_eq!(examined, 4, "four (glibc, level) cases examined");
    }

    /// The umbrella's fortify constituent.
    fn fortify_slot(c: &Composite) -> Constituent {
        c.constituents
            .iter()
            .find(|k| k.check == "fortify-effective")
            .cloned()
            .expect("the umbrella has a fortify constituent")
    }

    /// The established half of the library-bar rule: on glibc 2.43 a build in force at
    /// [`FHARDENED_FORTIFY`]'s fallback level is short of the level asked, the slot `absent`
    /// and the umbrella `partial`, as before the change.
    #[test]
    fn an_established_glibc_holds_a_fallback_level_build_short_as_before() {
        let fallback = FHARDENED_FORTIFY.fallback.to_string();
        let c = fhardened_for(
            &degraded("fortify-effective", Verdict::Partial, Some(&fallback)),
            "x86_64",
            &glibc(),
        );
        let k = fortify_slot(&c);
        assert_eq!(k.state, ConstituentState::Absent, "{k:?}");
        assert_eq!(
            k.note.as_deref(),
            Some(
                format!("needs level >= 3 on glibc 2.43; measured {fallback}{REFUSED_OK}").as_str()
            )
        );
        assert_eq!(c.verdict, Verdict::Partial, "{}", c.reason);
    }

    /// The umbrella's reason names an unset C library bar for the fortify slot alone: another
    /// constituent reaching `not-established` beside a measured verdict is not described as
    /// short of a library's bar.
    #[test]
    fn only_the_fortify_slot_is_named_short_of_an_unset_bar() {
        let k = |check: &'static str| Constituent {
            flag: "test",
            check,
            applicable: true,
            verdict: Some(Verdict::Partial),
            level: None,
            state: ConstituentState::NotEstablished,
            note: None,
            opt_out: None,
            implementation: None,
            bar: None,
        };
        let (fortify, other) = (k("fortify-effective"), k("canary-emitted"));
        assert_eq!(
            unconfirmed(&[&fortify, &other]),
            "1 was measured against a bar the C library reading does not set \
             (fortify-effective) and 1 could not be measured (canary-emitted)"
        );
    }

    /// musl is a library gcc's rule names: `-fhardened` asks level 2 there, so a build in force
    /// at level 2 meets the umbrella's fortify slot on musl, with or without a version read,
    /// and one at level 1 falls short of it, the note naming musl.
    #[test]
    fn musl_is_held_to_the_level_gcc_asks_there() {
        let rule = FHARDENED_FORTIFY;
        let fallback = rule.fallback.to_string();
        let below = rule.fallback.saturating_sub(1).to_string();
        let mut examined = 0_usize;
        for version in [Some("1.2.6"), None] {
            let musl = crate::env::Libc {
                impl_name: "musl".to_owned(),
                version: version.map(ToOwned::to_owned),
                detection: "test".to_owned(),
            };
            let met = fhardened_for(
                &degraded("fortify-effective", Verdict::Partial, Some(&fallback)),
                "x86_64",
                &musl,
            );
            let k = fortify_slot(&met);
            assert_eq!(k.state, ConstituentState::InForce, "{k:?}");
            assert_eq!(met.verdict, Verdict::On, "{}", met.reason);

            let short = fhardened_for(
                &degraded("fortify-effective", Verdict::Partial, Some(&below)),
                "x86_64",
                &musl,
            );
            let k = fortify_slot(&short);
            assert_eq!(k.state, ConstituentState::Absent, "{k:?}");
            assert_eq!(
                k.note.as_deref(),
                Some(
                    format!(
                        "needs level >= {fallback} on {}; measured {below}{REFUSED_OK}",
                        library_reading(&musl)
                    )
                    .as_str()
                )
            );
            examined = examined.saturating_add(1);
        }
        assert_eq!(examined, 2, "musl with and without a version");
    }

    /// The headers' library and the triple of the driver gcc was configured for must agree
    /// before either sets the fortify bar. Fedora's `musl-gcc` reads musl's headers under
    /// `x86_64-redhat-linux` and its `-fhardened` defines `_FORTIFY_SOURCE 3`, so a level-2
    /// build there is not established, never in force on musl's level 2; a glibc under a
    /// musl triple, and a musl whose triple was not read, set no bar either. The notes are
    /// held by their literal tails, so the library reading cannot drop out of them unseen.
    #[test]
    fn the_headers_library_and_the_driver_s_triple_must_agree_to_set_the_bar() {
        let rule = FHARDENED_FORTIFY;
        let libc = |name: &str, version: Option<&str>| crate::env::Libc {
            impl_name: name.to_owned(),
            version: version.map(ToOwned::to_owned),
            detection: "test".to_owned(),
        };
        let cases = [
            (
                libc("musl", Some("1.2.5")),
                Some("x86_64-redhat-linux"),
                "environment.libc reads musl 1.2.5 under toolchain.target_triple \
                 x86_64-redhat-linux, which names no driver configured for musl",
            ),
            (
                libc("musl", None),
                None,
                "environment.libc reads musl (no version) and toolchain.target_triple was not \
                 read, so it is not established that the driver is configured for musl",
            ),
            (
                libc("glibc", Some("2.43")),
                Some("x86_64-alpine-linux-musl"),
                "environment.libc reads glibc 2.43 under toolchain.target_triple \
                 x86_64-alpine-linux-musl, a driver configured for musl",
            ),
            (
                libc("unknown", None),
                Some("x86_64-linux-gnu"),
                "environment.libc reads unknown (no version), which names neither musl nor a \
                 glibc major and minor",
            ),
            (
                libc("glibc", Some("2")),
                Some("x86_64-linux-gnu"),
                "environment.libc reads glibc 2, which names neither musl nor a glibc major \
                 and minor",
            ),
        ];
        for (l, triple, want) in &cases {
            assert_eq!(fortify_bar(l, *triple, rule), Err((*want).to_owned()));
            let measured = [obs("fortify-effective", Verdict::Partial, Some("2"))];
            let k = fortify_constituent(
                &measured,
                rule,
                &crate::toolchain::FhardenedFortify::refused(),
                l,
                *triple,
            );
            assert_eq!(
                k.state,
                ConstituentState::NotEstablished,
                "{l:?} {triple:?}"
            );
            assert!(
                k.note
                    .as_deref()
                    .is_some_and(|n| n.ends_with(&format!("{want}{REFUSED_ERR}"))),
                "{:?}",
                k.note
            );
        }
        assert_eq!(
            fortify_bar(
                &libc("musl", Some("1.2.6")),
                Some("aarch64-linux-musl"),
                rule
            ),
            Ok((2, "musl 1.2.6".to_owned()))
        );
        assert_eq!(
            fortify_bar(&libc("musl", None), Some("arm-linux-musleabihf"), rule),
            Ok((2, "musl (no version)".to_owned()))
        );
        assert_eq!(
            fortify_bar(&libc("glibc", Some("2.43")), None, rule),
            Ok((3, "glibc 2.43; toolchain.target_triple not read".to_owned())),
            "a glibc under an unread triple is placed by version, and the reading says so"
        );
        assert_eq!(
            fortify_bar(&libc("glibc", Some("2.43")), Some("x86_64-linux-gnu"), rule),
            Ok((3, "glibc 2.43".to_owned())),
            "a glibc under a read triple names no unread one"
        );
        assert_eq!(
            cases.len(),
            5,
            "five disagreeing or unplaced readings examined"
        );
    }

    /// C library readings that set no fortify bar: neither musl nor a glibc major and minor.
    fn unset_readings() -> Vec<crate::env::Libc> {
        let libc = |name: &str, version: Option<&str>| crate::env::Libc {
            impl_name: name.to_owned(),
            version: version.map(ToOwned::to_owned),
            detection: "test".to_owned(),
        };
        vec![
            libc("glibc", None),
            libc("glibc", Some("2")),
            libc("glibc", Some("2.x")),
            libc("glibc", Some("")),
            libc("openbsd", None),
            libc("unknown", None),
            libc("bionic", Some("1")),
            libc("apple", None),
        ]
    }

    /// Under a reading that sets no bar, a fortify measured off is absent whatever the bar,
    /// and one never measured is not established, the reason calling it unmeasured rather
    /// than short of an unset bar.
    #[test]
    fn an_unset_bar_leaves_an_off_fortify_absent_and_an_unmeasured_one_unmeasured() {
        use ConstituentState as S;
        let fallback = FHARDENED_FORTIFY.fallback.to_string();
        let slot = fortify_slot;
        let readings = unset_readings();
        for l in &readings {
            // A fortify measured off is absent whatever the bar; one never measured is not
            // established, and the reason calls it unmeasured, not short of an unset bar.
            let off = fhardened_for(
                &degraded("fortify-effective", Verdict::Off, Some(&fallback)),
                "x86_64",
                l,
            );
            assert_eq!(slot(&off).state, S::Absent, "off under {l:?}");
            let unread = fhardened_for(
                &degraded("fortify-effective", Verdict::Indeterminate, None),
                "x86_64",
                l,
            );
            assert_eq!(
                slot(&unread).state,
                S::NotEstablished,
                "unmeasured under {l:?}"
            );
            assert!(
                unread
                    .reason
                    .contains("could not be measured (fortify-effective)"),
                "{}",
                unread.reason
            );
            let note = slot(&unread)
                .note
                .expect("an unset bar's slot carries a note");
            assert_eq!(
                note,
                format!(
                    "not established: fortify-effective indeterminate; environment.libc reads \
                     {}, which names neither musl nor a glibc major and minor{REFUSED_ERR}",
                    library_reading(l)
                ),
                "an unmeasured fortify is held to no stated requirement"
            );
        }
        assert_eq!(readings.len(), 8, "eight readings that set no bar examined");
    }

    /// Where the C library is not established by version, the umbrella's fortify slot is held
    /// to no bar chard cannot set. A level that meets [`FHARDENED_FORTIFY`]'s fallback
    /// and not its level withholds the slot, and the note names the library reading that left
    /// the bar unset, where an established glibc reads the same level `absent`
    /// (`an_established_glibc_holds_a_fallback_level_build_short_as_before`). A level that
    /// meets both bars is in force, and one that meets neither is absent, under any library.
    /// Lowering the bar to the fallback for an unestablished library would read the
    /// fallback-level build `in-force`.
    #[test]
    fn an_unestablished_libc_withholds_the_fortify_slot_rather_than_lowering_its_bar() {
        use ConstituentState as S;
        let rule = FHARDENED_FORTIFY;
        let full = rule.level.to_string();
        let fallback = rule.fallback.to_string();
        let neither = rule.fallback.saturating_sub(1).to_string();
        let slot = fortify_slot;
        let unestablished = unset_readings();
        let mut examined = 0_usize;
        for l in &unestablished {
            let at_fallback = fhardened_for(
                &degraded("fortify-effective", Verdict::Partial, Some(&fallback)),
                "x86_64",
                l,
            );
            let k = slot(&at_fallback);
            assert_eq!(
                k.state,
                S::NotEstablished,
                "level {fallback} under {l:?}: {k:?}"
            );
            assert_eq!(
                at_fallback.verdict,
                Verdict::Indeterminate,
                "{}",
                at_fallback.reason
            );
            let reading = format!(
                "environment.libc reads {}, which names neither musl nor a glibc major and minor",
                library_reading(l)
            );
            assert_eq!(
                k.note.as_deref(),
                Some(
                    format!(
                        "not established: measured level {fallback} meets the level {fallback} \
                         asked below glibc 2.35 and on musl and not the level {full} asked \
                         from glibc 2.35, and {reading}{REFUSED_ERR}"
                    )
                    .as_str()
                ),
                "under {l:?}"
            );
            assert!(
                !at_fallback.reason.contains("could not be measured"),
                "a fortify measured at level {fallback} is not unmeasured: {}",
                at_fallback.reason
            );

            let at_full = fhardened_for(
                &degraded("fortify-effective", Verdict::On, Some(&full)),
                "x86_64",
                l,
            );
            assert_eq!(slot(&at_full).state, S::InForce, "level {full} under {l:?}");
            assert_eq!(at_full.verdict, Verdict::On, "{}", at_full.reason);

            let at_neither = fhardened_for(
                &degraded("fortify-effective", Verdict::Partial, Some(&neither)),
                "x86_64",
                l,
            );
            assert_eq!(
                slot(&at_neither).state,
                S::Absent,
                "level {neither} under {l:?}"
            );
            assert_eq!(
                at_neither.verdict,
                Verdict::Partial,
                "{}",
                at_neither.reason
            );
            assert_eq!(
                slot(&at_neither).note.as_deref(),
                Some(
                    format!(
                        "needs level >= {fallback} whichever bar applies ({fallback} below \
                         glibc 2.35 and on musl, {full} from glibc 2.35); measured {neither}; \
                         {reading}{REFUSED_ERR}"
                    )
                    .as_str()
                ),
                "under {l:?}"
            );
            examined = examined.saturating_add(1);
        }
        assert_eq!(
            examined,
            unestablished.len(),
            "every unestablished library examined"
        );
        assert_eq!(examined, 8, "eight unestablished library readings examined");
    }

    /// Off x86 the umbrella loses its control-flow slot, and only that.
    #[test]
    fn the_umbrella_reduces_over_one_fewer_constituent_on_aarch64() {
        let x86 = fhardened_for(&fully_hardened(), "x86_64", &glibc());
        let arm = fhardened_for(&fully_hardened(), "aarch64", &glibc());
        assert_eq!(
            x86.constituents.iter().filter(|c| c.applicable).count(),
            arm.constituents
                .iter()
                .filter(|c| c.applicable)
                .count()
                .saturating_add(1),
            "exactly one constituent drops out off x86"
        );
        let dropped = arm
            .constituents
            .iter()
            .find(|c| !c.applicable)
            .expect("a constituent drops out");
        assert_eq!(dropped.check, "cet-marked");
        // And this is precisely why `cfi-effective` exists: the umbrella cannot see
        // branch protection, so the same evidence must still move a verdict somewhere.
        assert_eq!(
            cfi_for_arch(
                &[obs("branch-protection-marked", Verdict::On, Some("full"))],
                "aarch64"
            )
            .verdict,
            Verdict::On
        );
    }

    /// The two architectures answer the CFI question with the same denominator.
    ///
    /// This is the whole reason the composite exists. `fhardened-effective` reduces over
    /// eight constituents on x86_64 and seven on aarch64, because its control-flow slot is
    /// the x86 spelling and drops out elsewhere — so two rows of a cross-image table were
    /// not measuring the same thing. Here both sides have exactly one applicable
    /// constituent, and a build with control-flow protection in force reads `on` on either.
    ///
    /// The verdicts are the ones actually recorded on the aarch64 bring-up run and its
    /// same-compiler x86_64 control, gcc 16.1.1 / Fedora 44 / glibc 2.43 under
    /// `openssf-tldr`.
    #[test]
    fn both_architectures_answer_control_flow_with_the_same_denominator() {
        let arm = cfi_for_arch(
            &[obs("branch-protection-marked", Verdict::On, Some("full"))],
            "aarch64",
        );
        let x86 = cfi_for_arch(&[obs("cet-marked", Verdict::On, None)], "x86_64");

        for (label, c) in [("aarch64", &arm), ("x86_64", &x86)] {
            assert_eq!(c.verdict, Verdict::On, "{label}: {}", c.reason);
            assert_eq!(
                c.constituents.iter().filter(|k| k.applicable).count(),
                1,
                "{label}: one applicable constituent, so the denominator is comparable"
            );
        }
        assert_eq!(arm.constituents[0].check, "branch-protection-marked");
        assert_eq!(x86.constituents[0].check, "cet-marked");
    }

    /// A branch-protected aarch64 build and one built with `-mbranch-protection=none`
    /// must not read the same.
    ///
    /// Without this composite they would: the CFI slot of `fhardened-effective` is removed on
    /// aarch64 rather than failed, so both builds score identically on it. Measured on a run
    /// where `openssf-tldr` had BTI and PAC in force and corroborated on two channels while
    /// `bare` had neither. A marking for one edge reads `off`, as none does, but its reason
    /// must not say the artifact is unmarked. The case is the OpenBSD 7.9 amd64 cells of a
    /// fleet sweep, where the same report's `cet-marked` read `partial` with `x86_ibt=true`.
    #[test]
    fn a_one_edge_marking_is_not_reported_as_no_marking() {
        let cfi = cfi_for_arch(
            &[obs("cet-marked", Verdict::Partial, Some("branch"))],
            "x86_64",
        );
        assert_eq!(cfi.verdict, Verdict::Off);
        assert!(
            !cfi.reason.contains("no control-flow markings"),
            "{}",
            cfi.reason
        );
        assert!(
            cfi.reason.contains("cet-marked measured partial"),
            "{}",
            cfi.reason
        );
        assert!(cfi.reason.contains("branch alone"), "{}", cfi.reason);

        let none = cfi_for_arch(&[obs("cet-marked", Verdict::Off, None)], "x86_64");
        assert!(
            none.reason.contains("no control-flow markings"),
            "{}",
            none.reason
        );
    }

    #[test]
    fn branch_protection_changes_the_aarch64_control_flow_verdict() {
        let on = cfi_for_arch(
            &[obs("branch-protection-marked", Verdict::On, Some("full"))],
            "aarch64",
        );
        let off = cfi_for_arch(
            &[obs("branch-protection-marked", Verdict::Off, None)],
            "aarch64",
        );
        assert_eq!(on.verdict, Verdict::On);
        assert_eq!(off.verdict, Verdict::Off);
        assert_ne!(
            on.verdict, off.verdict,
            "a build with branch protection must not score as one without it"
        );

        // And `fhardened-effective` is deliberately *not* what changed: its control-flow
        // slot stays inapplicable on aarch64, because the umbrella does not enable
        // branch protection and reporting a shortfall against it would be a new wrong
        // answer rather than a repaired one.
        let k = cet_for(
            &[obs("branch-protection-marked", Verdict::On, Some("full"))],
            "aarch64",
        );
        assert!(
            !k.applicable,
            "the umbrella's slot stays inapplicable on aarch64"
        );
    }

    /// GCS is reported, not required.
    ///
    /// It has no x86 counterpart under `-fcf-protection`, so requiring it would make the
    /// verdict depend on the compiler's vintage — Ubuntu's gcc 13.4 returns
    /// `probe-invalid` for it because that `standard` predates GCS — rather than on the
    /// build. A reader still needs to see that the artifact carries more than the verdict
    /// counts.
    #[test]
    fn gcs_is_named_in_the_note_without_gating_the_verdict() {
        let evidence = [
            obs("branch-protection-marked", Verdict::On, Some("full")),
            obs("gcs-marked", Verdict::On, None),
        ];
        let with_gcs = cfi_for_arch(&evidence, "aarch64");
        let without = cfi_for_arch(
            &[obs("branch-protection-marked", Verdict::On, Some("full"))],
            "aarch64",
        );
        assert_eq!(
            with_gcs.verdict, without.verdict,
            "GCS does not move the verdict"
        );
        assert!(
            with_gcs.constituents[0]
                .note
                .as_deref()
                .is_some_and(|n| n.contains("GCS")),
            "GCS in the artifact must be visible: {:?}",
            with_gcs.constituents[0].note
        );
        // The marked note stands either way; GCS is named only where it is carried.
        assert!(
            without.constituents[0].note.as_deref().is_some_and(|n| n
                .starts_with("marked, not shown in force: ")
                && !n.contains("GCS")),
            "and not named when there is nothing extra to say: {:?}",
            without.constituents[0].note
        );

        // A build whose GCS could not be measured still reads `on` for branch protection.
        let unmeasured = cfi_for_arch(
            &[
                obs("branch-protection-marked", Verdict::On, Some("full")),
                obs("gcs-marked", Verdict::ProbeInvalid, None),
            ],
            "aarch64",
        );
        assert_eq!(unmeasured.verdict, Verdict::On);
    }

    /// An architecture chard has no control-flow check for is unmeasured, not unprotected.
    ///
    /// `reduce` decides this: with nothing applicable, `missing.len() == applicable.len()`
    /// is vacuously true at zero, so the `off` arm would have claimed "no constituent is
    /// in force" about a protection nobody looked for. riscv64 has Zicfilp/Zicfiss and
    /// chard measures neither.
    #[test]
    fn an_architecture_without_a_control_flow_check_is_not_reported_unprotected() {
        for arch in ["riscv64", "s390x", "ppc64le"] {
            let c = cfi_for_arch(&[], arch);
            assert_eq!(
                c.verdict,
                Verdict::NotApplicable,
                "{arch} must not read `off`: {}",
                c.reason
            );
            assert!(!c.constituents[0].applicable, "{arch}");
            assert!(
                c.reason.contains("unmeasured"),
                "{arch}: the reason must say why, got {:?}",
                c.reason
            );
        }
    }

    /// A missing check is unmeasured, not absent.
    #[test]
    fn a_control_flow_check_absent_from_the_report_does_not_read_as_off() {
        let c = cfi_for_arch(&[], "aarch64");
        assert_eq!(
            c.verdict,
            Verdict::Indeterminate,
            "the architecture has a check and the report does not carry it, which is \
             missing evidence rather than measured absence: {}",
            c.reason
        );
    }

    /// An unmeasurable fill *mode* must not grant the `=zero` requirement.
    ///
    /// `is_pattern` collapses `probe-invalid` to `false`, and `false` is the value that
    /// grants satisfaction, so `active: on` with `pattern: probe-invalid` would mark the
    /// constituent satisfied while the mode is genuinely unknown. The hole is reachable
    /// wherever `auto-var-init-active` itself discriminates, clang included.
    #[test]
    fn unmeasurable_fill_mode_does_not_satisfy_the_zero_requirement() {
        let c = auto_var_init_constituent_for_test(Verdict::On, Verdict::ProbeInvalid);
        assert!(
            !c.satisfied,
            "the fill mode was never established, so =zero cannot be claimed"
        );
        assert_eq!(
            c.verdict,
            Some(Verdict::Indeterminate),
            "an unmeasurable mode must propagate as unmeasured, not as a shortfall"
        );

        // Both measured and zero-filling: satisfied.
        let c = auto_var_init_constituent_for_test(Verdict::On, Verdict::Off);
        assert!(c.satisfied);

        // Measured as pattern: a real shortfall against this umbrella, not unknown.
        let c = auto_var_init_constituent_for_test(Verdict::On, Verdict::On);
        assert!(!c.satisfied);
        assert_eq!(c.verdict, Some(Verdict::On));
    }

    /// Shim so the assertions above read against the same shape as the real code.
    struct ZeroInit {
        satisfied: bool,
        verdict: Option<Verdict>,
    }

    fn auto_var_init_constituent_for_test(active: Verdict, pattern: Verdict) -> ZeroInit {
        let (satisfied, verdict) = zero_init_decision(Some(active), Some(pattern));
        ZeroInit { satisfied, verdict }
    }

    #[test]
    fn a_glibc_version_is_established_by_its_major_and_minor() {
        let libc = |name: &str, v: Option<&str>| crate::env::Libc {
            impl_name: name.to_owned(),
            version: v.map(ToOwned::to_owned),
            detection: "test".to_owned(),
        };
        assert_eq!(
            established_glibc(&libc("glibc", Some("2.35"))),
            Some((2, 35))
        );
        assert_eq!(
            established_glibc(&libc("glibc", Some("2.43"))),
            Some((2, 43))
        );
        assert_eq!(established_glibc(&libc("glibc", Some("3.0"))), Some((3, 0)));
        // A packaging suffix still reads.
        assert_eq!(
            established_glibc(&libc("glibc", Some("2.39-r2"))),
            Some((2, 39))
        );
        // A bare major, an unparseable minor and no version establish nothing: none is 2.0.
        assert_eq!(established_glibc(&libc("glibc", Some("2"))), None);
        assert_eq!(established_glibc(&libc("glibc", Some("2.x"))), None);
        assert_eq!(established_glibc(&libc("glibc", Some("x.35"))), None);
        assert_eq!(established_glibc(&libc("glibc", None)), None);
        // musl's version is not a small glibc version, it is a different scale, and comparing it
        // against a glibc threshold is what published "needs level >= 2 on glibc 1.2.6" about eight
        // musl reports. A non-glibc libc places no glibc version, whatever its numbers say
        // (`fortify_bar` reads musl by name).
        assert_eq!(established_glibc(&libc("musl", Some("9.9"))), None);
        assert_eq!(established_glibc(&libc("unknown", None)), None);
    }

    #[test]
    fn fortify_level_meets_the_bar() {
        assert!(fortify_meets(Some("3"), 3));
        assert!(fortify_meets(Some("3"), 2));
        assert!(!fortify_meets(Some("2"), 3));
        assert!(!fortify_meets(Some("0"), 2));
        // A level we cannot parse must not be credited.
        assert!(!fortify_meets(None, 2));
        assert!(!fortify_meets(Some("unknown"), 2));
    }

    /// The constituents that could not be measured are listed apart from a marking measured
    /// `on` whose header's effect is unestablished, by verdict as well as by header, and a
    /// list with no member is not said.
    #[test]
    fn an_unconfirmed_list_names_each_kind_and_no_empty_one() {
        let constituent = |check: &'static str, verdict: Verdict| Constituent {
            flag: "-fcf-protection=full",
            check,
            applicable: true,
            verdict: Some(verdict),
            level: None,
            state: ConstituentState::NotEstablished,
            note: None,
            opt_out: Some(OptOut {
                header: PT_OPENBSD_NOBTCFI,
                facts: "a".repeat(64),
            }),
            implementation: None,
            bar: None,
        };
        let opted = constituent("cet-marked", Verdict::On);
        let withheld = constituent("cet-marked-object", Verdict::Indeterminate);
        assert_eq!(
            unconfirmed(&[&opted]),
            "1 was measured but its effect is not established (cet-marked)"
        );
        assert_eq!(
            unconfirmed(&[&withheld]),
            "1 could not be measured (cet-marked-object)"
        );
    }
}
