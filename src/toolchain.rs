// SPDX-License-Identifier: BSD-3-Clause

//! Identifying the toolchain under test.
//!
//! The point of this module is provenance for a `bare`-profile measurement. When
//! `cc probe.c` with no flags produces a PIE with a stack canary, the *reason*
//! is in `gcc -v`'s configure line (`--enable-default-pie`,
//! `--enable-default-ssp`) or, for clang, in a distro configuration file under
//! `/etc/clang/`. Recording those alongside the verdicts is what lets a reader
//! distinguish "this distro patched its compiler" from "chard passed a flag".
//!
//! Clang configuration files deserve the explicit call-out they get here: they
//! are a real mechanism by which a distro changes defaults for every invocation,
//! and they are invisible in `--version` output.
//!
//! The toolchain is published in two steps, and the type records which step a value
//! has reached. [`detect`] returns a [`Detected`]: everything the driver says about
//! itself, and nothing that depends on the environment. The join key `toolchain.id` is
//! `kind-version-libc-distro`, and its second half comes from [`crate::env::detect`],
//! which needs the with-headers macro dump this module produces before it can name the
//! libc. So the key cannot be spelled here, and a `Detected` cannot be published: only
//! [`Detected::qualified`] makes a [`Toolchain`], the struct a report carries, from the
//! two tags [`crate::env::Libc::tag`] and [`crate::env::Distro::tag`] spell. The tags
//! arrive as strings, which keeps this module independent of the environment module in
//! the way [`crate::env`]'s own header asks for.
//!
//! The linker has two witnesses. [`detect_linker`] asks the driver which program it
//! would run and takes that program's `--version` banner as the identity, which is a
//! claim about a file on the harness `PATH`. [`artifact_agreement`] then reads the
//! `.comment` section of every linked artifact the run built, where lld and mold write a
//! line of their own and GNU ld and gold write none, and publishes whether the artifacts
//! corroborate the banner, contradict it, or cannot speak to it. The two are published
//! side by side: `kind` stays the banner's word and `artifact.agreement` says what the
//! artifacts made of it. Why a disagreement is a finding about the environment carried as
//! a diagnostic, and where the two witnesses sit beside `-frecord-*`, is in
//! `DESIGN.md` under "The binary testifies about itself".

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::compile;
use crate::digest;
use crate::error::UserError;
use crate::link_inputs;
use crate::probe::Lang;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Gcc,
    Clang,
    Other,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Clang => "clang",
            Self::Other => "other",
        }
    }
}

/// Who turned the linker's name into the path the report publishes.
///
/// Separate from the claim itself, so a reader can weigh it. A driver that prints an
/// absolute path has looked the program up in its own search directories; a bare name
/// means that search failed and the link will fall through to `PATH`, which is what
/// gcc's collect2 and clang's linker lookup both do and what chard then does in their
/// place. A path the profile named needs no lookup at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathSource {
    /// The driver printed it: the program its `-###` link line runs, or its answer to
    /// `-print-prog-name`.
    Driver,
    /// The driver printed a bare name and chard searched `PATH` for it.
    PathSearch,
    /// The profile named the file, through `--ld-path=` or `-fuse-ld=/path`.
    Profile,
}

impl PathSource {
    /// Every value, for the schema test that pins the published vocabulary to this one.
    pub const ALL: &[Self] = &[Self::Driver, Self::PathSearch, Self::Profile];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Driver => "driver",
            Self::PathSearch => "path-search",
            Self::Profile => "profile",
        }
    }
}

/// What the linked artifacts say about the banner-derived `kind`.
///
/// Five values because five different things can be true, and a consumer that gates on
/// the identity needs them apart. `NoSignature` and `NoLinkedArtifact` are both an absence
/// of a linker line, and they differ in whether anything was counted: collapsing the
/// second into the first would publish a Mach-O host or a build that failed everywhere as
/// a corroboration of GNU ld. `ArtifactOnly` keeps a banner chard could not read apart
/// from a banner the artifacts contradict. Why the second of those carries an error
/// diagnostic and the first a warning is in `DESIGN.md` under "The binary testifies
/// about itself".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Agreement {
    /// Every linked artifact carries one linker line, and it names the banner's kind and,
    /// where the banner quotes one, its version.
    Agrees,
    /// The artifacts and the banner name different linkers or versions, two artifacts
    /// name different linkers, or the banner names lld or mold and no artifact carries
    /// the line those two always write.
    Disagrees,
    /// Every linked artifact carries one linker line and no `--version` banner chard read
    /// names a linker it recognises: the program printed nothing, printed a banner outside
    /// the grammar, or failed `--version`, or no linker path was read. The artifact is the
    /// only witness, and the report carries its
    /// line as `signature` beside a `kind` of `unknown`.
    ArtifactOnly,
    /// No artifact carries a linker line and the banner names a linker that writes none.
    /// GNU ld and gold leave nothing of their own in `.comment`, so a `bfd` or `gold`
    /// banner is only ever uncontradicted by this mechanism.
    NoSignature,
    /// Nothing was counted: no linked ELF artifact was read in this run (a host whose
    /// compiler emits Mach-O, a selection of probes that build nothing, or a run whose
    /// every link failed), or every artifact read was left uncounted and is named in the
    /// evidence under its reason. `artifacts_read` is 0 either way, and the evidence
    /// opens with which of the two it was.
    NoLinkedArtifact,
}

impl Agreement {
    /// Every value, for the schema test that pins the published vocabulary to this one.
    pub const ALL: &[Self] = &[
        Self::Agrees,
        Self::Disagrees,
        Self::ArtifactOnly,
        Self::NoSignature,
        Self::NoLinkedArtifact,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agrees => "agrees",
            Self::Disagrees => "disagrees",
            Self::ArtifactOnly => "artifact-only",
            Self::NoSignature => "no-signature",
            Self::NoLinkedArtifact => "no-linked-artifact",
        }
    }
}

/// The artifacts' verdict on the banner, with the evidence it rests on.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactAgreement {
    pub agreement: Agreement,
    /// The `.comment` line that named a linker, when one did: `Linker: LLD 22.1.8`,
    /// `mold 2.40.4 (compatible with GNU ld)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Distinct linked artifacts whose `.comment` was read to its end: the denominator.
    /// Relocatables, artifacts whose `.comment` could not be read and artifacts linked
    /// without the profile's link line are named in `evidence` and not counted, and so
    /// are the probes that handed over no artifact at all.
    pub artifacts_read: usize,
    /// Which artifacts, what their `.comment` carried, and why the verdict follows.
    pub evidence: String,
}

/// One artifact's testimony, as [`artifact_agreement`] reads it.
#[derive(Debug, Clone)]
pub struct ArtifactComment {
    /// `<probe>-<variant> sha256:<16 hex>`: the probe and variant that built it, and a
    /// prefix of the digest `build.artifact_sha256` publishes in full.
    pub label: String,
    /// `ElfFacts::comment`, the section's lines in file order.
    pub lines: Vec<String>,
    /// Why `.comment` could not be read, from `ElfFacts::comment_truncation`. Such an
    /// artifact is named and not counted: an unread section is no reading.
    pub unread: Option<String>,
    /// A relocatable, which no linker produced: named and not counted. `lld -r` writes no
    /// linker line, and a compiler-only `.comment` counted here would read as a
    /// disagreement against the run's own `.o` probes.
    pub relocatable: bool,
    /// Read from the profile-free clean build while the profile's link line selected a
    /// linker program (`Witnesses::selection` holds a `-fuse-ld=` or `--ld-path=`, which
    /// [`linker_program_flags`] reads; the `-B` and `--prefix` prefixes reach the clean
    /// build with the runtime selection, so they alone leave the clean
    /// link the measured build's): the check measures the toolchain
    /// default (`Check::measures_toolchain_default`), so the artifact was linked under the
    /// driver's default link line and the linker the profile selected had no part in it.
    /// Named and not counted, since the banner is the profile's linker: counted, a
    /// `bfd`-linked default artifact under `-fuse-ld=lld` read as the run's own artifacts
    /// disagreeing. Under a profile whose flags select no linker the clean build and the
    /// measured build go through the same link line, so the artifact is a witness like
    /// any other and this stays false.
    pub profile_free: bool,
}

/// What one linker is held to: the artifacts read for it, and the probes that handed
/// over none.
///
/// The second list is the enumerating loop's own account of itself. `artifacts_read`
/// counts what was fed; without the probes that fed nothing beside it, a run whose every
/// link but one failed reads like a run of one probe.
#[derive(Debug, Clone, Default)]
pub struct Witnesses {
    pub artifacts: Vec<ArtifactComment>,
    /// Probes none of whose observations carried ELF facts with a digest, in id order:
    /// a probe that did not build, one gated off this toolchain, or one built where the
    /// compiler emits something other than ELF.
    pub without_facts: Vec<String>,
    /// The linker selection this side's link line consulted, `Linker::profile_flags` as
    /// published: what a `profile_free` artifact was linked without, quoted in the
    /// evidence beside it. Empty when the profile selected nothing.
    pub selection: Vec<String>,
}

/// The linker the profile links with, and how that was established.
///
/// `path` is absolute wherever it could be resolved, since a bare `ld` is a name a reader
/// cannot follow; `path_source` says who resolved it and `detection` says how in prose.
/// `profile_flags` lists the flags consulted, so a `-fuse-ld=` the profile carries is
/// visible beside the linker it selected rather than only in `profile.cflags`.
#[derive(Debug, Clone, Serialize)]
pub struct Linker {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Present exactly when `path` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_source: Option<PathSource>,
    /// The profile flags that took part: `-B` and `--prefix` prefixes, `-fuse-ld=` and
    /// `--ld-path=`, as written. Empty when the profile selected nothing and the driver's default
    /// linker is the one reported.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub profile_flags: Vec<String>,
    pub detection: String,
    /// What the linked artifacts said about `kind`. `None` until the sweep has run;
    /// every published report carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactAgreement>,
    /// The linker the C++ probes were linked with, present only when the profile's
    /// cxxflags select a different one from the C link. The C++ link goes through the C++
    /// driver's own `-B` and `-print-prog-name` search, so it is queried there. Never
    /// carries a `cxx` of its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cxx: Option<Box<Linker>>,
}

/// What the driver says about itself, before the environment is known.
///
/// Every published field of [`Toolchain`] except the join key. The key needs the libc
/// and distribution tags, which [`crate::env::detect`] establishes from this struct's
/// own `macros_with_headers`, so a value of this type is complete for measurement and
/// incomplete for publication: [`crate::measure::Driver`] borrows one, and `Report`
/// carries a [`Toolchain`], which only [`Detected::qualified`] constructs. No runtime
/// check stands behind that; the type is the mechanism. The unit test that a `Detected`
/// serializes without an `id` is what would make a leak visible, as a report missing a
/// field the schema requires.
#[derive(Debug, Clone, Serialize)]
pub struct Detected {
    pub kind: Kind,
    pub version: String,
    /// The first line of the driver's `--version`. Absent where [`answered`] refused the job,
    /// with a [`QueryFailure`] on [`VERSION_RAW_FIELD`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_triple: Option<String>,
    pub driver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cxx_driver: Option<String>,
    /// `gcc -v`'s "Configured with:" line; the provenance of every `bare`
    /// default this toolchain has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configure_args: Option<String>,
    /// The configuration files the driver announced loading in `-v`: clang's
    /// `Configuration file:` and gcc's `Reading specs from`. A distro-defaults
    /// mechanism that `--version` does not reveal, and the one `resolve_profile`
    /// attributes a `bare` column to when the list is non-empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub config_files: Vec<String>,
    /// Not serialized here: the driver queries whose output [`answered`] refused, each a
    /// warning in the report's diagnostics. Empty where every query exited 0 with its
    /// output whole.
    #[serde(skip)]
    pub query_failures: Vec<QueryFailure>,
    pub linker: Linker,
    /// The architecture the arch-gated checks gated on, and what the run's artifacts made
    /// of it. `None` until the sweep has run; every published report carries it. See
    /// [`target_agreement`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetArch>,
    /// Fingerprint over the with-headers dump: two toolchains with equal hashes
    /// have identical macro-channel defaults, which makes cross-distro
    /// comparison a hash check before it is a table diff.
    pub predefined_macros_sha256: String,
    /// Full dump, included only under `--emit-macros`; reports stay compact by
    /// default while remaining self-contained when asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predefined_macros: Option<BTreeMap<String, String>>,
    /// The dump of the libc-identification headers exited non-zero, whether or not macros
    /// came out, in [`compile::BuildRecord::failure`]'s words. Absent on a clean dump, which
    /// is every supported configuration.
    ///
    /// This existed and was invisible. chard only spoke up when the dump was *empty*, and
    /// on Darwin it was not: `<features.h>` is glibc's, the include was a fatal error, and
    /// clang printed all 3047 macros regardless. So every macro-channel verdict on that
    /// platform rested on the driver continuing past an error it called fatal, and no
    /// report said so; a stderr note would not have, either, since a report outlives the
    /// terminal that produced it. The include is guarded now; this field is what would
    /// notice the next instance rather than the same one. Where it is present the libc's
    /// detection names it ([`Self::headers_dump`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub libc_headers_error: Option<String>,
    /// The intrinsic dump under `-fhardened -O2`, the reading `fhardened-effective`'s fortify
    /// bar is taken from where the driver offers the option ([`FhardenedFortify`]). Taken on
    /// every run, whatever the profile, since the umbrella's question is the option's own
    /// request and not the profile's.
    pub fhardened_fortify: FhardenedFortify,

    /// Not serialized: the with-headers dump the fingerprint above hashes and `env::detect`
    /// identifies the libc from, through [`Self::headers_dump`]. The intrinsic dump `detect`
    /// also takes serves `kind`, `version` and `arch_macros` and is not kept whole: every
    /// macro-channel arm
    /// dumps again, with headers, per variant (`measure::Driver::gather`).
    #[serde(skip)]
    pub macros_with_headers: BTreeMap<String, String>,
    /// Not serialized here: the names from [`ARCH_MACROS`] the intrinsic dump defined, in
    /// list order. [`target_agreement`] holds the gate's architecture to them after the
    /// sweep, and `toolchain.target.macros.defined` publishes them.
    #[serde(skip)]
    pub arch_macros: Vec<String>,
    /// Not serialized here: the width and byte order the intrinsic dump's
    /// `__SIZEOF_POINTER__` and `__BYTE_ORDER__` name ([`Abi::from_dump`]), published as
    /// `toolchain.target.macros.abi` and held to the artifacts by [`TargetArch::abi`].
    #[serde(skip)]
    pub arch_abi: Option<Abi>,
    /// Not serialized here: the intrinsic dump under the profile's C flags, taken by
    /// [`Detected::dump_with`] once the profile is known and `None` until then or where
    /// those flags are empty. `toolchain.target.profile_macros` publishes it.
    #[serde(skip)]
    pub profile_macros: Option<ProfileDump>,
    /// Not serialized here: the intrinsic dump through the C++ driver under the flags a C++
    /// probe's measured variant is built with, taken by [`Detected::dump_with`] only where
    /// those flags differ from the C ones and a C++ driver exists.
    /// `toolchain.target.profile_macros_cxx` publishes it.
    #[serde(skip)]
    pub profile_macros_cxx: Option<ProfileDump>,
    #[serde(skip)]
    pub driver_path: PathBuf,
    #[serde(skip)]
    pub cxx_driver_path: Option<PathBuf>,
}

/// The join key: `kind-version-libc-distro`, as in `gcc-16.1.1-glibc2.43-fedora44`.
///
/// One spelling, called by [`Detected::qualified`] alone. Three mechanisms hold a
/// published id to it: `Toolchain.id` is private and [`Detected::qualified`] is its only
/// constructor; `report::run_id_agrees` contradicts a hand-edited id, because the id is an
/// input to `run.id`; and the integration test
/// `the_published_toolchain_id_is_the_qualified_join_key` in `tests/schema_conformance.rs`
/// spells the expected key independently from the report's own `environment.libc` and
/// `environment.distro`. `Kind::as_str` rather than a `Display` impl, because the gates and
/// the unknown-flag rule read the same names and the three must agree.
#[must_use]
pub fn join_key(kind: Kind, version: &str, libc_tag: &str, distro_tag: &str) -> String {
    format!("{}-{version}-{libc_tag}-{distro_tag}", kind.as_str())
}

/// The toolchain as a report publishes it: a [`Detected`] under its join key.
///
/// `id` is the third element of the column tuple reports are joined on. The libc is in
/// it because `musl-gcc` and `gcc` on one Fedora host produce identical ids without it,
/// and a cross-report join would merge two toolchains that disagree about six checks. The
/// field is private and [`Detected::qualified`] is the one constructor, so an id and the
/// fields it is composed from arrive together. A placeholder id overwritten after the
/// environment is read would let a caller that skipped that step publish a plausible key
/// that joins every distribution with every other. `detected` is
/// flattened, so the JSON is the one flat object the schema describes.
#[derive(Debug, Clone, Serialize)]
pub struct Toolchain {
    id: String,
    #[serde(flatten)]
    pub detected: Detected,
}

impl Toolchain {
    /// The join key, `kind-version-libc-distro`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The join key and the detected half, from a destructure with no `..`.
    ///
    /// `report::inputs_of` classifies every published field as an input to
    /// `run.inputs_sha256` or as excluded, and `id` is private to this module, so the
    /// destructure that covers `Toolchain` lives here: a field added to `Toolchain` fails to
    /// compile until it is added to this pattern, and the caller then has to classify it.
    #[must_use]
    pub fn parts(&self) -> (&str, &Detected) {
        let Self { id, detected } = self;
        (id, detected)
    }
}

impl Detected {
    /// The published toolchain, keyed for the join.
    ///
    /// `libc_tag` and `distro_tag` are spelled by [`crate::env::Libc::tag`] and
    /// [`crate::env::Distro::tag`]. The composition is [`join_key`]. This is the only
    /// constructor of [`Toolchain`], whose `id` is private; the mechanisms that hold a
    /// published id to its halves are listed at [`join_key`].
    #[must_use]
    pub fn qualified(self, libc_tag: &str, distro_tag: &str) -> Toolchain {
        Toolchain {
            id: join_key(self.kind, &self.version, libc_tag, distro_tag),
            detected: self,
        }
    }

    /// The architecture this toolchain compiles *for*, normalized to the vocabulary
    /// `std::env::consts::ARCH` and every `Gate.arch` entry already use (`"x86_64"`,
    /// `"x86"`, `"aarch64"`), `None` when `-dumpmachine` gave no triple chard read (it
    /// printed none, or [`answered`] refused the job).
    ///
    /// Exists because arch-gated checks (CET, GCS, branch-protection) were gating on
    /// `env.kernel.arch`, which is the architecture *chard's own binary* was compiled
    /// for, not the one this toolchain targets. Invisible for a native build, where the
    /// two coincide; under `--cc aarch64-linux-gnu-gcc` on an x86_64 host it reported
    /// GCS/branch-protection `Unsupported` for a toolchain that measures them fine, and
    /// let CET run to completion against a target that cannot define it; a false `off`
    /// from the gate itself, the "clean-looking zero" this project's whole design exists
    /// to refuse, just produced upstream of any detector.
    ///
    /// The driver's own default target, asked with no flags. Where the profile's flags select
    /// another, the gate reads that one instead; [`gate_target`] decides which.
    pub fn target_arch(&self) -> Option<String> {
        arch_of_triple(self.target_triple.as_deref()?)
    }

    /// Detect the linker again under the profile's flags, when they select one.
    ///
    /// [`detect`] runs before the profile is resolved, because the profile needs the
    /// target architecture the toolchain reports, so the linker it records is the driver's
    /// default. A profile can name another through `-fuse-ld=`, `--ld-path=` or a `-B`
    /// prefix, and the report must name the linker the artifacts were linked with:
    /// `toolchain.linker` is provenance beside every link-channel verdict, and
    /// [`artifact_agreement`] holds it to those artifacts. Flags that select nothing leave
    /// the default detection in place, since the query would be the same one; the guard
    /// and the detection read the flags through the same parser, so they cannot disagree
    /// about what selects.
    ///
    /// Two lists, because two links happen. `c_link` is what every C probe is linked with
    /// and `cxx_link` what the C++ probes are, the same two lists `measure::variant_flags`
    /// hands the builds, so the parse mirrors the build, and no merged order that no link
    /// uses is invented. A selection present only in cxxflags reaches one real link and
    /// is published as `linker.cxx`; folding it into the C list would attribute every C
    /// artifact to a linker only the C++ link used. When the two selections agree,
    /// `linker.cxx` is absent and the one linker stands for both. Without a C++ driver no
    /// C++ link runs (`Driver::driver_for` withholds the C++ probe under `no-driver`), so the
    /// selection is recorded in `detection` and `linker.cxx` stays absent: a linker
    /// published for zero links would be an identity for a link that did not happen.
    /// `workdir` is the measurement's, for the driver's words the detection quotes
    /// ([`read_link_line`]).
    pub fn link_with(&mut self, c_link: &[String], cxx_link: &[String], workdir: &Path) {
        let c = link_selection(c_link);
        let cxx = link_selection(cxx_link);
        if !c.consulted.is_empty() {
            self.linker = detect_linker(&self.driver_path, c_link, workdir);
        }
        if cxx.selects_as(&c) {
            self.linker.cxx = None;
            return;
        }
        let Some(driver) = self.cxx_driver_path.as_deref() else {
            use std::fmt::Write as _;
            self.linker.cxx = None;
            crate::error::best_effort(write!(
                self.linker.detection,
                "; the profile's C++ link selects {} but no C++ driver sits beside the C \
                 one, so no C++ link ran and no C++ linker is published",
                cxx.consulted.join(" ")
            ));
            return;
        };
        let mut through = detect_linker(driver, cxx_link, workdir);
        through.cxx = None;
        self.linker.cxx = Some(Box::new(through));
    }

    /// The with-headers dump with its failure, [`Self::libc_headers_error`], for a reader
    /// that identifies something from it: `env::detect`, for the C library.
    ///
    /// What a dump that failed printed is a prefix of unknown length. A libc identified from
    /// it as from a clean one would have a detection silent on the failure the field beside
    /// it names. The two travel together so the reader cannot take the map
    /// without the failure (`env::libc_of` says what it then reads).
    #[must_use]
    pub fn headers_dump(&self) -> crate::env::HeadersDump<'_> {
        crate::env::HeadersDump {
            macros: &self.macros_with_headers,
            failure: self.libc_headers_error.as_deref(),
        }
    }

    /// Take the intrinsic macro dump again under `c_flags`, the flags a C probe's measured
    /// variant is built with, and through the C++ driver under `cxx_flags`, the flags a C++
    /// probe's is, for [`ProfileMacroWitness`].
    ///
    /// A second step for [`Detected::link_with`]'s reason: the profile needs the target
    /// architecture this struct reports. Empty C flags take nothing, since the dump would be
    /// the flagless one `detect` took. The C++ dump is taken only where `cxx_flags` differ
    /// from `c_flags`, as `linker.cxx` is published only where the C++ link's selection
    /// differs: where the two are equal, the C dump already witnesses the target every C++
    /// probe was built for. `measure::variant_flags` makes both lists, and they differ only
    /// where `cxxflags` is non-empty and not the C flags, so a differing C++ list is never
    /// empty. Both dumps witness the profile's flags whatever the probe selection, as
    /// `linker.cxx` witnesses the profile's C++ link selection whatever it is: the dump is
    /// taken before the sweep and speaks of the flags the report names, so a selection with
    /// no C++ probe still publishes the C++ dump, and a `disagrees` there names flags that
    /// select another target and withholds no verdict. Without a C++ driver there is no
    /// driver to dump through, and no C++ probe builds (`Driver::driver_for` withholds it
    /// under `no-driver`), so no C++ dump is taken.
    ///
    /// # Errors
    ///
    /// Errors when a dump's source cannot be written to `work` or a driver cannot be
    /// spawned. A dump the driver refuses is recorded, not an error.
    pub fn dump_with(
        &mut self,
        c_flags: &[String],
        cxx_flags: &[String],
        work: &Path,
    ) -> Result<()> {
        self.profile_macros = if c_flags.is_empty() {
            None
        } else {
            Some(
                profile_dump(
                    &self.driver_path,
                    Lang::C,
                    c_flags,
                    work,
                    "intrinsic-profile",
                )
                .context("dumping compiler-intrinsic macros under the profile's C flags")?,
            )
        };
        self.profile_macros_cxx = match self.cxx_driver_path.as_deref() {
            Some(driver) if cxx_flags != c_flags => Some(
                profile_dump(driver, Lang::Cxx, cxx_flags, work, "intrinsic-profile-cxx")
                    .context("dumping compiler-intrinsic macros under the profile's C++ flags")?,
            ),
            _ => None,
        };
        Ok(())
    }
}

/// The intrinsic macro dump through `driver`, a driver of `lang`, under `flags`, as a
/// [`ProfileDump`].
fn profile_dump(
    driver: &Path,
    lang: Lang,
    flags: &[String],
    work: &Path,
    tag: &str,
) -> Result<ProfileDump> {
    let (macros, record) = compile::macro_dump(driver, lang, flags, false, work, tag)?;
    Ok(ProfileDump {
        flags: flags.to_vec(),
        exit_status: record.exit_status,
        stdout_unterminated: record.stdout_unterminated,
        macros_defined: macros.len(),
        defined: arch_macros(&macros),
        abi: Abi::from_dump(&macros),
    })
}

/// The flags [`FhardenedFortify`]'s dump is taken under, before `-dM -E`. `-O2` because gcc
/// defines `_FORTIFY_SOURCE` under `-fhardened` only where it optimizes, and warns that it
/// did not otherwise.
pub const FHARDENED_DUMP_FLAGS: [&str; 2] = ["-fhardened", "-O2"];

/// The flags of [`FhardenedFortify`]'s control dump: [`FHARDENED_DUMP_FLAGS`] without the
/// option, so a level the driver defines whatever is asked is not read as the option's.
pub const FHARDENED_BASELINE_FLAGS: [&str; 1] = ["-O2"];

/// The fortify level the driver's own `-fhardened` asks, read from its intrinsic dump under
/// [`FHARDENED_DUMP_FLAGS`] and held to a control dump under [`FHARDENED_BASELINE_FLAGS`].
///
/// gcc picks the level in `linux_fortify_source_default_level` from the glibc it was
/// configured against, which the headers on the include path need not be (a cross gcc
/// configured against an older glibc, a glibc upgraded in place under a gcc built earlier).
/// The dump is the driver answering the question itself, so `composite::fhardened_bar` reads
/// it before any library reading, and reads the library only where [`Self::refusal`] names a
/// reason the dump does not answer it.
///
/// The control is two-armed: the option's dump must define a `_FORTIFY_SOURCE` the control
/// does not define, or defines lower. A driver that defines a level whatever it is
/// asked (Alpine's gcc, Ubuntu's specs) leaves `-fhardened` nothing to show, and a wrapper
/// that drops the token, or a specs `-D` under `-w` that silences gcc's `-Whardened`, reads
/// the same through both dumps: neither sets the bar. The register entry
/// `fhardened-dump-names-its-own-level` names what the two arms still trust.
///
/// Measured 2026-10-21, `-fhardened -O2` against `-O2`: on Fedora 44 x86_64 gcc 16 defines
/// `_FORTIFY_SOURCE 3` against none, and clang 22.1.8 exits 1 with `clang: error: unknown
/// argument: '-fhardened'`; in the `gcc:14` and `gcc:16` images gcc 14.4.0 and 16.2.0 define 3
/// against none; in an Ubuntu 24.04 image gcc 13 exits 1 with `gcc: error: unrecognized
/// command-line option '-fhardened'`; in an Ubuntu 26.04 image gcc 15 defines 3 against 3 and
/// warns `cc1: warning: '_FORTIFY_SOURCE' is not enabled by '-fhardened' because it was
/// specified in '-D' or '-U' [-Whardened]` (its specs add the `-D`); in an Alpine 3.25 image
/// gcc 15.2.0 defines 2 against 2. gcc's `-Whardened` names `-fhardened` whenever the option
/// yields the level (`because optimizations are turned off`, `because it was specified in
/// '-D' or '-U'`). The dump takes no profile flag: a profile whose `-specs=`, `-mmusl` or
/// `--sysroot` changes the level `-fhardened` asks is outside this reading.
///
/// Read back from `toolchain.fhardened_fortify` as written by the consistency rule
/// `fhardened-fortify-slot-disagrees-with-inputs` on read, a member `measure`
/// omits reading as its default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FhardenedFortify {
    /// [`FHARDENED_DUMP_FLAGS`], published so the invocation can be repeated by hand.
    pub flags: Vec<String>,
    pub exit_status: i32,
    /// The dump's output was cut off partway through a line
    /// (`compile::BuildRecord::stdout_unterminated`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stdout_unterminated: bool,
    /// Every macro the dump defined, counted: zero is a dump that said nothing.
    pub macros_defined: usize,
    /// The first line of the dump's stderr naming `-fhardened` or `-Whardened`: the driver
    /// refusing the option, saying the target does not support it, or saying it yielded the
    /// fortify level to something else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    /// The value the dump defined `_FORTIFY_SOURCE` to, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fortify_source: Option<String>,
    /// The control dump under [`FHARDENED_BASELINE_FLAGS`]: how it ended, and the
    /// `_FORTIFY_SOURCE` it defined, verbatim.
    pub baseline: FortifyBaseline,
}

/// The control arm of [`FhardenedFortify`]: the same dump without `-fhardened`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FortifyBaseline {
    /// [`FHARDENED_BASELINE_FLAGS`].
    pub flags: Vec<String>,
    pub exit_status: i32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stdout_unterminated: bool,
    pub macros_defined: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fortify_source: Option<String>,
}

impl FhardenedFortify {
    /// Read from the option's dump and the control's, each with the record of its run.
    #[must_use]
    pub fn from_dumps(
        macros: &BTreeMap<String, String>,
        record: &compile::BuildRecord,
        baseline_macros: &BTreeMap<String, String>,
        baseline_record: &compile::BuildRecord,
    ) -> Self {
        Self {
            flags: FHARDENED_DUMP_FLAGS.map(str::to_owned).to_vec(),
            exit_status: record.exit_status,
            stdout_unterminated: record.stdout_unterminated,
            macros_defined: macros.len(),
            diagnostic: fhardened_diagnostic(&record.stderr),
            fortify_source: macros.get("_FORTIFY_SOURCE").cloned(),
            baseline: FortifyBaseline {
                flags: FHARDENED_BASELINE_FLAGS.map(str::to_owned).to_vec(),
                exit_status: baseline_record.exit_status,
                stdout_unterminated: baseline_record.stdout_unterminated,
                macros_defined: baseline_macros.len(),
                fortify_source: baseline_macros.get("_FORTIFY_SOURCE").cloned(),
            },
        }
    }

    /// A dump clang's answer shape: exit 1, refusing the token. For tests whose subject is
    /// not the driver's reading: under it the bar is the library's (`composite::fhardened_bar`).
    #[cfg(test)]
    #[must_use]
    pub fn refused() -> Self {
        Self {
            exit_status: 1,
            macros_defined: 0,
            diagnostic: Some("clang: error: unknown argument: '-fhardened'".to_owned()),
            fortify_source: None,
            ..Self::defining("3")
        }
    }

    /// A dump that took the token and defined `_FORTIFY_SOURCE` to `level`, beside a control
    /// that defined none.
    #[cfg(test)]
    #[must_use]
    pub fn defining(level: &str) -> Self {
        Self {
            flags: FHARDENED_DUMP_FLAGS.map(str::to_owned).to_vec(),
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 400,
            diagnostic: None,
            fortify_source: Some(level.to_owned()),
            baseline: FortifyBaseline {
                flags: FHARDENED_BASELINE_FLAGS.map(str::to_owned).to_vec(),
                exit_status: 0,
                stdout_unterminated: false,
                macros_defined: 399,
                fortify_source: None,
            },
        }
    }

    /// Why the dump does not answer what `-fhardened` asks, as a constituent's note names it;
    /// `None` where it does. The option's dump must exit 0, whole, defining a macro, with no
    /// stderr line naming the option; the control must exit 0, whole, defining a macro, and
    /// define no `_FORTIFY_SOURCE`, or one the option's is an integer above. A driver that refuses the token
    /// (clang, gcc before 14), a target gcc does not support it for, a driver that yields the
    /// level to its own `-D` and says so, and one that defines the level whatever is asked all
    /// fail it, and their dump sets no bar.
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        let dump = "the driver's -fhardened -O2 dump";
        let control = "the driver's -O2 dump, the control without -fhardened,";
        let base = &self.baseline;
        if let Some(line) = &self.diagnostic {
            Some(format!("{dump} said `{line}`"))
        } else if self.exit_status != 0 {
            Some(format!("{dump} {}", compile::ended(self.exit_status)))
        } else if self.stdout_unterminated {
            Some(format!("{dump} was cut off partway through a line"))
        } else if self.macros_defined == 0 {
            Some(format!("{dump} defined no macro"))
        } else if base.exit_status != 0 {
            Some(format!("{control} {}", compile::ended(base.exit_status)))
        } else if base.stdout_unterminated {
            Some(format!("{control} was cut off partway through a line"))
        } else if base.macros_defined == 0 {
            Some(format!("{control} defined no macro"))
        } else if let Some(without) = &base.fortify_source {
            // Only a level the option raised is its own: an equal one is a default the driver
            // defines whatever is asked, and a lower one is something besides the option.
            let raised = self
                .fortify_source
                .as_deref()
                .and_then(|with| {
                    Some((
                        with.trim().parse::<u32>().ok()?,
                        without.trim().parse::<u32>().ok()?,
                    ))
                })
                .is_some_and(|(with, without)| with > without);
            (!raised).then(|| {
                format!(
                    "{control} defines _FORTIFY_SOURCE {without} as well, so the level is not \
                     the option's own"
                )
            })
        } else {
            None
        }
    }
}

/// The first line of a dump's stderr naming `-fhardened` or `-Whardened`, trimmed.
///
/// Public so the `driver_text` fuzz target (`fuzz/fuzz_targets/driver_text.rs`) holds it
/// to its laws.
#[must_use]
pub fn fhardened_diagnostic(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .find(|line| line.contains("-fhardened") || line.contains("-Whardened"))
        .map(|line| line.trim().to_owned())
}

/// The one environment variable chard reads: an absent `PATH` is nothing to search.
fn search_path() -> std::ffi::OsString {
    std::env::var_os("PATH").unwrap_or_default()
}

/// The first `name` on a `PATH`-shaped `search_path` that could be run, which is the entry
/// `execvp` chooses: an entry with no execute bit, or one that is not a regular file, is
/// passed over for the next, as the caller's own shell passes over it. With `is_file()`
/// alone as the predicate, a mode-644 `cc` ahead of the real one on `PATH` was the
/// resolved driver while `command -v cc` in the same shell named the real one.
///
/// The one search both the driver and the linker go through, taking the path as an
/// argument so a test can hand it a directory of shims without touching the process
/// environment, which edition 2024 makes `unsafe` to set.
fn find_on_path(name: &str, search_path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(search_path)
        .map(|dir| dir.join(name))
        .find(|full| is_executable_file(full))
}

/// Resolve a compiler name to an absolute path, searching `PATH` when it is not
/// already one.
///
/// The two shapes of `name` are refused differently. A bare name is searched as `execvp`
/// searches it, so the driver the caller's shell would run is the one chard runs, and a
/// name found nowhere on `PATH` is refused. An explicit path names one file, and it is
/// refused from its metadata when that file is not an executable regular file, before any
/// spawn: two failures that share `EACCES` belong to different owners, since a file with
/// no execute bit is the caller's `--cc` to fix, and an executable the kernel still
/// refuses (a `noexec` mount, a MAC policy) is the filesystem's, which the spawn reports
/// and the envelope classes as `PERMISSION`. A `+x` file the kernel has no loader for is
/// refused at the spawn with `ENOEXEC`, which `error::classify` reads as the caller's.
/// # Errors
///
/// Errors with a [`UserError`] when `name` is a bare name found nowhere on `PATH`, or a
/// path to nothing or to something other than an executable regular file.
pub fn resolve_driver(name: &str) -> Result<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        // One stat, read three ways: a path to nothing is the caller's, a stat that
        // failed for any other reason (`EACCES` on a directory in it, `ELOOP`) keeps its
        // errno for `error::classify` to read as a caller path, and a file that exists
        // is judged from its metadata. `Path::exists()` folded every errno into the first
        // of these, with a hint to pass a path that exists.
        let meta = match std::fs::metadata(candidate) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(UserError::with_hint(
                    format!("no such compiler: {name}"),
                    "pass --cc with a path that exists",
                )
                .into());
            }
            Err(e) => return Err(e).with_context(|| format!("reading {name}")),
        };
        if !is_executable(&meta) {
            return Err(UserError::with_hint(
                format!("{name} is not an executable file"),
                "pass --cc naming an executable compiler; `<cc> --version` must run",
            )
            .into());
        }
        return Ok(candidate.to_path_buf());
    }
    find_on_path(name, &search_path()).ok_or_else(|| {
        UserError::with_hint(
            format!("`{name}` not found on PATH"),
            "install the toolchain or pass --cc /path/to/compiler",
        )
        .into()
    })
}

/// A regular file with an execute bit set for someone, read from metadata alone: the
/// approximation of `execvp`'s access check that needs no `access(2)` binding. A file
/// whose only execute bit belongs to another user passes here and fails at the spawn,
/// where `EACCES` on an executable mode is the filesystem's to answer for.
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.is_file() && meta.permissions().mode() & 0o111 != 0
}

/// [`is_executable`] for a `PATH` entry, where a stat that fails for any reason is an
/// entry passed over, as `execvp` passes it over.
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| is_executable(&meta))
}

/// The refusal for a driver whose intrinsic dump defined no macro, carrying what the driver
/// said.
///
/// The dump's record was discarded here, so the refusal guessed: "it may not be a working C
/// compiler", with nothing of the driver's own. On Ubuntu 14.04 x86_64 (2026-10-12)
/// gcc 4.8.4 under a wrapper adding `-fstack-protector-strong` and clang 3.4 given an arm64
/// Darwin target both worked and each rejected one thing, which its stderr named, and a
/// `CCACHE_PREFIX` naming a program that fails is ccache's own stderr. The stderr is the
/// answer in each case, so it is quoted whole up to [`NO_MACROS_STDERR_LIMIT`] characters,
/// with the exit status (or the signal), and the guess is kept only where the driver said
/// nothing. A quote cut at the limit ends in ` [...]`.
///
/// The text goes into the error envelope only, never into a report, so it is not passed
/// through `measure::publish_text` as a report's driver line is; the envelope already names
/// the driver by its path.
fn no_macros_message(driver: &Path, record: &compile::BuildRecord) -> String {
    // Spelled as every failed dump's reason is (`BuildRecord::ended`), the signal included.
    let ended = record.ended();
    let said = record.stderr.trim();
    if said.is_empty() {
        return format!(
            "{} produced no predefined macros and wrote nothing to stderr ({ended}); it may \
             not be a working C compiler",
            driver.display(),
        );
    }
    // Its lines joined with ` | ` before any other control character becomes `?`, so a
    // two-line rejection reads as two lines rather than as one with a `?` in it.
    // Built up to the limit and no further, so ten megabytes of a wrapper's noise are not
    // copied once more to be cut.
    let lines = said.lines().map(str::trim).filter(|l| !l.is_empty());
    let mut quoted = String::new();
    let mut kept = 0usize;
    let mut cut = false;
    'quote: for (i, line) in lines.enumerate() {
        for c in (if i == 0 { "" } else { " | " })
            .chars()
            .chain(line.chars())
        {
            if kept == NO_MACROS_STDERR_LIMIT {
                cut = true;
                break 'quote;
            }
            quoted.push(c);
            kept = kept.saturating_add(1);
        }
    }
    if cut {
        quoted.push_str(" [...]");
    }
    format!(
        "{} produced no predefined macros ({ended}); its stderr read: {}",
        driver.display(),
        crate::table::scrub(&quoted)
    )
}

/// How much of a refused macro dump's stderr [`no_macros_message`] quotes: enough for a
/// driver's rejection and the line after it, short of a page of a wrapper's noise.
const NO_MACROS_STDERR_LIMIT: usize = 600;

/// The context of the [`QueryFailure`] a refused `-dumpmachine` leaves.
pub const TRIPLE_FIELD: &str = "toolchain.target_triple";

/// The context of the [`QueryFailure`] a refused `--version` of the driver leaves.
pub const VERSION_RAW_FIELD: &str = "toolchain.version_raw";

/// The context of the [`QueryFailure`] a refused `-v` leaves; `main` also notes it on the
/// profile, beside `flags_source`.
pub const CONFIG_FILES_FIELD: &str = "toolchain.config_files";

/// The `-v` query as its failure and the profile's note name it: the arguments [`detect`]
/// passes, in order.
pub const VERBOSE_QUERY: &str = "-v -E -x c /dev/null";

/// A driver query whose output [`detect`] refused: the job did not exit 0, exited 0 with its
/// output cut off partway through a line, or did not answer at all. `measure` publishes each
/// as a warning diagnostic whose context is the field the query would have filled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryFailure {
    /// The published field the query fills: `toolchain.version_raw`,
    /// `toolchain.target_triple` or `toolchain.config_files`.
    pub context: &'static str,
    /// How the query ended, in [`compile::BuildRecord::ended`]'s words, and what is left
    /// unread.
    pub message: String,
}

/// `record` where the query `query` exited 0 with its output whole; otherwise `None`, with a
/// [`QueryFailure`] on `context` saying how it ended and, in `unread`, what that leaves
/// unread.
///
/// A job that failed may still have printed: a wrapper's plausible triple before it exits
/// non-zero, or `-v`'s whole report with a `Configuration file:` line before the
/// preprocess fails. Read as the driver's answer, the first published a triple no driver
/// gave and the second decided a bare column's `flags_source`, so neither is read. A job
/// that exited 0 with its last line cut ([`compile::BuildRecord::stdout_unterminated`]) is
/// refused as a dump is, since a triple cut short is not the driver's either. Where the
/// driver did not answer at all (it could not be spawned, or outlived `compile`'s
/// deadline) there was no answer to refuse, and the failure is recorded the same way. Only
/// how the job ended is quoted, not its stderr: `-v`'s first stderr line is the driver's
/// own banner, not the reason it failed.
fn answered(
    record: Result<compile::BuildRecord>,
    query: &str,
    context: &'static str,
    unread: &str,
    failures: &mut Vec<QueryFailure>,
) -> Option<compile::BuildRecord> {
    let ended = match record {
        Ok(r) => match refusal(&r) {
            None => return Some(r),
            Some(ended) => ended,
        },
        Err(e) => format!("did not answer ({e:#})"),
    };
    failures.push(QueryFailure {
        context,
        message: format!(
            "the driver's `{query}` {ended}, so chard read nothing from its output: {unread}"
        ),
    });
    None
}

/// How a job that answered ended, where its output is not the program's answer: it did not
/// exit 0, or exited 0 with its output cut off partway through a line. `None` where it exited
/// 0 with its output whole. [`answered`] and the linker queries ([`ask_for_program`],
/// [`detect_linker_on`]) refuse through this one reading.
fn refusal(record: &compile::BuildRecord) -> Option<String> {
    if !record.succeeded() {
        Some(record.ended())
    } else if record.stdout_unterminated {
        Some(format!("{} {}", record.ended(), compile::CUT_OFF))
    } else {
        None
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_owned()
}

fn macro_num(macros: &BTreeMap<String, String>, key: &str) -> Option<String> {
    macros.get(key).map(|v| v.trim().to_owned())
}

/// Compose a dotted version from the compiler's own version macros rather than
/// by scraping `--version` text, whose format is vendor- and distro-specific.
fn version_from_macros(kind: Kind, macros: &BTreeMap<String, String>) -> String {
    let parts = match kind {
        Kind::Clang => ["__clang_major__", "__clang_minor__", "__clang_patchlevel__"],
        _ => ["__GNUC__", "__GNUC_MINOR__", "__GNUC_PATCHLEVEL__"],
    };
    let collected: Vec<String> = parts.iter().filter_map(|k| macro_num(macros, k)).collect();
    if collected.is_empty() {
        return "unknown".to_owned();
    }
    collected.join(".")
}

/// The compiler's environment as an `env -i` prefix a shell can run, built from what
/// `compile::compiler_environment` applies: a passed variable chard has as the shell's own
/// value, one it lacks left out as the environment leaves it out, an `--env` pair and a pin
/// at chard's value, single-quoted where the value is not one plain word.
///
/// The no-macros hint carries it because a toolchain that works from the operator's shell
/// and not from chard may need a variable the clear keeps from it (reproduced 2026-10-11
/// with a stand-in `gcc` that fails without `LD_LIBRARY_PATH`), and the bare command would
/// work from that shell and point nowhere.
fn compiler_environment_spelled() -> String {
    compiler_environment_spelled_as(compile::compiler_environment())
}

/// [`compiler_environment_spelled`] of the environment `applied`, as
/// `compile::compiler_environment_from` builds it.
fn compiler_environment_spelled_as(
    applied: Vec<(std::ffi::OsString, std::ffi::OsString)>,
) -> String {
    let words = applied.into_iter().map(|(name, value)| {
        let name = name.to_string_lossy();
        if compile::COMPILER_ENV_PASSED.contains(&name.as_ref()) {
            format!("{name}=\"${name}\"")
        } else {
            format!("{name}={}", shell_word(&value.to_string_lossy()))
        }
    });
    std::iter::once("env -i".to_owned())
        .chain(words)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `value` as one shell word: as written where every character is one no shell treats
/// specially, single-quoted otherwise, with each `'` closed, escaped and reopened. Shared
/// with `measure`'s closing line, which suggests a command.
#[must_use]
pub fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:,+=@%".contains(c));
    if plain {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Extract the `Configured with:` line and the out-of-band configuration files the
/// driver announced, from `-v` output.
///
/// Both families announce such a file in `-v` and nowhere else. clang prints
/// `Configuration file: <path>` for each file it loaded (`/etc/clang/<triple>-clang.cfg`,
/// `--config`); newer versions may list several. No environment variable names a file
/// for clang 22.1.8 to load, and the one that suppresses the default file,
/// `CLANG_NO_DEFAULT_CONFIG`, is kept from the driver (`compile::compiler_environment`
/// clears everything but `PATH` and the pins), so what this reads is the installed
/// configuration. (2026-09-28: this comment named `CLANG_CONFIG_FILE`
/// as a third source; clang does not read it, measured on Fedora 44 with clang 22.1.8,
/// and the reasoning sits beside that list.) gcc prints
/// `Reading specs from <path>` when an installed specs file replaces its built-in
/// specs, and `Using built-in specs.` when none does. A specs file is how a
/// distribution patches the driver's defaults without rebuilding the compiler, so a
/// `bare` column measured through one is the compiled-in defaults plus whatever the
/// file supplies, which is the same claim clang's file makes; only the clang line was
/// read, and gcc's form of the mechanism published `flags_source: none`.
///
/// Public so the `driver_text` fuzz target (`fuzz/fuzz_targets/driver_text.rs`) holds it
/// to its laws.
#[must_use]
pub fn parse_verbose(text: &str) -> (Option<String>, Vec<String>) {
    let mut configure = None;
    let mut config_files = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Configured with:") {
            configure = Some(rest.trim().to_owned());
        }
        if let Some(rest) = trimmed
            .strip_prefix("Configuration file:")
            .or_else(|| trimmed.strip_prefix("Reading specs from "))
        {
            let path = rest.trim();
            if !path.is_empty() {
                config_files.push(path.to_owned());
            }
        }
    }
    (configure, config_files)
}

/// The program a link will run, as the profile's flags decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Program {
    /// No selection: the driver's `ld`.
    Default,
    /// `-fuse-ld=<flavor>`: the driver looks for `ld.<flavor>`, which is the name gcc's
    /// collect2 and clang's linker lookup both search for on Linux.
    Named(String),
    /// `--ld-path=<path>`, or clang's `-fuse-ld=<path>`: the file itself.
    File(PathBuf),
}

/// What a profile's flags say about which linker the driver will run.
///
/// Read by chard rather than handed to the driver, because `-print-prog-name=ld` ignores
/// `-fuse-ld=` and `--ld-path=` in both drivers (measured on clang 21: `-fuse-ld=lld
/// -print-prog-name=ld` prints the default `ld`, `-print-prog-name=ld.lld` prints lld's
/// path). `-B` is different: both drivers search a `-B` prefix for programs, so those are
/// passed through to the query as written. Later flags win, as they do on a driver
/// command line, with one exception: clang reads its last `--ld-path=` before any
/// `-fuse-ld=`, so an `--ld-path=` outranks a `-fuse-ld=` written after it. Measured
/// 2026-10-05 on Fedora 44 x86_64 with clang 22.1.8 and `-###`: `--ld-path=B -fuse-ld=A`
/// ran `B`, with `A` a file and with `A` the flavour `bfd`, and an empty last
/// `--ld-path=` was refused (`invalid linker name in argument '--ld-path='`) whatever
/// `-fuse-ld=` said. gcc 16.1.1 refuses `--ld-path=` outright, so the order matters to
/// clang alone.
#[derive(Debug, Default, PartialEq, Eq)]
struct LinkSelection {
    /// `-B<dir>` flags, joined into the one-token form, in order. `--prefix=<dir>` and the
    /// two-token `--prefix <dir>` are `-B` to both drivers and are joined into it too.
    prefixes: Vec<String>,
    program: Option<Program>,
    /// Every flag consulted, as written, for the report.
    consulted: Vec<String>,
    /// The flags of `consulted` that name the program, `-fuse-ld=` and `--ld-path=`, as
    /// written: what [`linker_program_flags`] hands an arm beside the runtime selection,
    /// which carries the prefixes.
    program_flags: Vec<String>,
}

impl LinkSelection {
    /// Would the driver run the same program under both selections?
    ///
    /// `-fuse-ld=ld` and no `-fuse-ld=` at all name the driver's default, so the two
    /// compare equal here even though only one consulted a flag.
    fn selects_as(&self, other: &Self) -> bool {
        self.prefixes == other.prefixes
            && self.program.clone().unwrap_or(Program::Default)
                == other.program.clone().unwrap_or(Program::Default)
    }
}

/// The flags of `link_line` that choose the linker: `-B` prefixes (and `--prefix`, which
/// both drivers read as `-B`), `-fuse-ld=` and `--ld-path=`, as written and in order. The
/// same list `Linker::profile_flags` publishes for the link line it was detected under.
///
/// A word handed to another tool is passed over with the word that hands it, and a one-word
/// selection after clang's `-Xarch_<arch>` is carried as the pair ([`Hand`] has the
/// measurements). A word another reader takes, as its option or as the value of its
/// two-token one, is passed over as well: the readers are projections of one walk
/// ([`selections`]), which gives each word one owner.
#[must_use]
pub fn linker_selecting_flags(link_line: &[String]) -> Vec<String> {
    link_selection(link_line).consulted
}

/// The flags of `link_line` that name the linker program, `-fuse-ld=` and `--ld-path=`, as
/// written and in order: [`linker_selecting_flags`] without its prefixes.
///
/// A control arm that links is handed these after the runtime selection
/// ([`runtime_selecting_flags`]), which carries the `-B` and `--prefix` prefixes to every
/// arm on every channel; together the two give the arm every flag the
/// report's linker was detected under, each once.
#[must_use]
pub fn linker_program_flags(link_line: &[String]) -> Vec<String> {
    link_selection(link_line).program_flags
}

/// What the driver does with the word after `word`: the hand of a [`Reading`], which every
/// walk over a flag list asks of [`read`] (the selection readers' one walk, [`selections`],
/// of which [`target_selection`], [`runtime_selecting_flags`], [`header_selecting_flags`]
/// and [`link_selection`] are projections; the removal reader [`runtime_removing_flags`];
/// the refusals; the listing, macro-operation and level readers; the output kinds'
/// partition; the readers of a build's own line and of the arms, [`read`]'s doc names
/// them). One classifier, so a spelling is added in one place and a `match` on it is
/// exhaustive in each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hand {
    /// Hands it to another tool, which reads it as its own option: the linker (`-Xlinker`,
    /// `--for-linker`, clang's `-Xoffload-linker`), the assembler (`-Xassembler`, gcc's
    /// `--for-assembler`), clang's `-cc1` and `-cc1as` (`-Xclang`, `-Xclangas`), LLVM's option
    /// parser (`-mllvm`), clang's analyzer and offload tools (`-Xanalyzer`, `-Xopenmp-target`
    /// and its joined `-Xopenmp-target=<triple>`, `-Xoffload-linker` and its joined
    /// `-Xoffload-linker<triple>`, `-Xcuda-ptxas`, `-Xcuda-fatbinary`), and gcc's unique-prefix
    /// abbreviations of its two `--for-` options (`--for-l`, `--for-a` and longer). A selection
    /// reader passes over the pair: `-Xlinker -L/x` is GNU ld's `-L`, which gcc 16.1.1 and
    /// clang 22.1.8 both put after their own library directories (measured 2026-10-08 on Fedora
    /// 44 x86_64 with `-###`), where the driver's `-L` goes ahead of them, and `-Xclang
    /// -resource-dir -Xclang /x` is `-cc1`'s option, whose value the driver never sees as a
    /// word. Measured the same day with `-###` and `-L` after each word: gcc accepts
    /// `-Xlinker`, `--for-linker`, `--for-assembler`, their abbreviations, `-Xassembler` and
    /// `-Xpreprocessor` and rejects the rest; clang accepts every word but `--for-assembler`
    /// and the abbreviations, reporting the `-X<tool>` ones unused for a C link. gcc reads the
    /// word after `-Xflang` as its own (the `-L` landed ahead of gcc's directories) and clang
    /// rejects `-Xflang`, so it is no hand-on. A selection reader that read the word after
    /// one of these as the driver's own would let `-Xlinker -L/x` reach every arm as a
    /// shadowing driver `-L/x`, and `-Xclang -resource-dir -Xclang /x` hand the arms
    /// `-resource-dir -Xclang`.
    Tool,
    /// Hands it to gcc's `cc1` as a preprocessor word (`-Xpreprocessor`), which reads two of
    /// the driver's own words there as the driver would: a header removal, which the removal
    /// reader finds ([`runtime_removing_flags`] has the measurement), and `-isysroot`, which
    /// the target reader carries ([`target_selection`]: measured 2026-10-08 with gcc 16.1.1,
    /// `-Xpreprocessor -isysroot -Xpreprocessor /x` and `-Wp,-isysroot,/x` each moved the `-v
    /// -E` search list to the root as the driver's `-isysroot` does, and clang's `-cc1` left it
    /// unchanged). The runtime, header and linker readers pass the pair over: no runtime
    /// or linker selection goes through `cc1`, and a header word handed there
    /// (`-Xpreprocessor -I`) is left to the listing comparison, which withholds on it
    /// ([`header_selecting_flags`] says why the arms do not carry it).
    Preprocessor,
    /// Applies it as a driver option when the target's architecture is the one named (clang's
    /// `-Xarch_<arch>`). A one-word selection after it is carried as the pair, whatever
    /// `<arch>` names, so the arms are handed what the measured build was; a two-word option
    /// clang refuses outright ("options requiring arguments are unsupported"), and some
    /// one-word ones it does not forward (`-m32`, `--target=`, `-resource-dir=`: "not all
    /// driver options can be forwarded"), so the measured build fails before any arm matters.
    /// Measured 2026-10-08 with clang 22.1.8 on Fedora 44 x86_64, `-###` against the same line
    /// without the pair: `--rtlib=`, `-stdlib=`, `-static-libgcc` and `-L` were applied
    /// (`--rtlib=compiler-rt` linked `clang_rt.crtbegin.o`, `-stdlib=libc++` gave clang++
    /// `-lc++`, `-static-libgcc` gave `-lgcc_eh`); `-B`, `--prefix=`, `--sysroot=` and
    /// `--gcc-install-dir=` were accepted without a word and not applied (the link ran the
    /// host's `ld` beside a `-B` directory holding one and `-print-prog-name=ld` named the
    /// host's, `-v -E` under `--sysroot=` kept the host's `/usr/include`, and a
    /// `--gcc-install-dir=` that is an error when given directly passed in silence);
    /// `-fuse-ld=` and `--ld-path=` were accepted and the link still ran the default linker;
    /// and gcc 16.1.1 rejects `-Xarch_` as an unknown option. The pair is carried either way:
    /// an inert pair hands the arms the inert word the measured build had, and nothing else.
    Arch,
    /// Takes it as this option's own value, where the option is no selection reader's spelling: `-u
    /// -B<dir>/` is the undefined symbol named `-B<dir>/` to both drivers and no search prefix,
    /// `-MF -L/x` a dependency file, `-o -I/x` an output, `-D -m32` a macro, `-z -fuse-ld=lld` a
    /// linker keyword. Every walk passes over the pair, as it passes over a hand-on's, so a
    /// selection spelled as such a value reaches no arm and no clean build as the selection. The
    /// spellings are [`VALUE_TWO_TOKEN`] and, on gcc, the abbreviations [`VALUE_ABBREVIATED`]
    /// bounds ([`takes_a_value`] has the measurement), and gcc's long spellings of them
    /// (`--force-link`, `--def`; [`LONG_ALIASES`]). What the pair itself chooses, the arms carry
    /// nothing of: a word no reader takes (`-u`, `-o`, `-z`), or a header or specs word the readers
    /// leave to the listing comparison or to the ledger (`-iprefix`, `-specs`, `--config`;
    /// [`header_selecting_flags`] and the `measure` module say which). A walk that read the value
    /// as a word of its own was measured on Fedora 44 x86_64, each cell against the same line
    /// without the pair: with clang 22.1.8 and an `ld` in `<dir>` linking every program with an
    /// executable stack, `--profile explicit --flags "-O2 -u -B<dir>/"` read
    /// `linker-default-noexecstack` `off` where `-O2` reads `on`, a wrong `off` from a clean build
    /// linked by a linker the measured line never chose, five more checks `indeterminate` and
    /// `Linker::profile_flags` listing the prefix, 6 of 72 differing; with gcc 16.1.1 and a `specs`
    /// file in `<dir>` switching the stack protector off, `-O2 -fstack-protector-strong -u
    /// -B<dir>/` read 13 of 72 as `probe-invalid` or `indeterminate`. With this class in the walk
    /// both cells read as the line without the pair, 0 of 72 differing.
    Value,
    /// Reads it itself.
    Driver,
}

/// Two-token driver options that select nothing, each taking the next word as its value:
/// the spellings gcc 16.1.1 and clang 22.1.8 accept so, or one accepts so while the other
/// refuses the option (a measured build carrying it fails under that driver before any arm
/// matters). The selection spellings and the hand-ons are not here: they are their own
/// classes ([`selection_word`], [`hand`]), and `tests::a_value_taking_option_is_no_selection_and_no_hand_on`
/// holds the three apart. The order is the measurement's: the spellings both drivers take,
/// then gcc's alone, then clang's alone; [`takes_a_value`] says how each was measured, and
/// why sixteen of the 135 it found are not here: gcc's long spellings of a short option
/// some reader names (`--define-macro` of `-D`, `--include` of `-include`, `--force-link`
/// of `-u`), which [`LONG_ALIASES`] reads as the short spelling, so each is of the short
/// spelling's class. The 119 here are the rest.
const VALUE_TWO_TOKEN: [&str; 119] = [
    // Both drivers. `--param` joins its value to itself (`--param=<value>`) on gcc, which
    // reports a value that names no parameter as that joined spelling.
    "-A",
    "-D",
    "-dumpdir",
    "-e",
    "-F",
    "-imultilib",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
    "-l",
    "-MF",
    "-MQ",
    "-MT",
    "-o",
    "--param",
    "--print-file-name",
    "--print-prog-name",
    "-specs",
    "-T",
    "-U",
    "-u",
    "-x",
    "-z",
    // gcc alone; clang refuses the option.
    "-aux-info",
    "-copyext",
    "--dump",
    "--dumpbase",
    "--dumpbase-ext",
    "--dumpdir",
    "--embed-directory",
    "-fcobol-exceptions",
    "-fdefaultbyte",
    "-findicator-column",
    "-fintrinsic-modules-path",
    "-fmodules-map",
    "-fmodules-map-file",
    "-gnatO",
    "-Hd",
    "-Hf",
    "-imultiarch",
    "-J",
    "-preprocess",
    "-truncate",
    "-wrapper",
    "-Xf",
    // clang alone; gcc refuses the option.
    "-alias_list",
    "-allowable_client",
    "--analyzer-output",
    "-arch_only",
    "--bootclasspath",
    "-bundle_loader",
    "-ccc-gcc-name",
    "--classpath",
    "--CLASSPATH",
    "-client_name",
    "-compatibility_version",
    "--config",
    "-current_version",
    "-cxx-isystem",
    "--dyld-prefix",
    "--encoding",
    "--extdirs",
    "-fdebug-compilation-dir",
    "-fexperimental-openacc-macro-override",
    "-filelist",
    "-fmodule-implementation-of",
    "-fmodules-user-build-path",
    "-fnew-alignment",
    "-force_load",
    "-framework",
    "-ftrapv-handler",
    "-gen-cdb-fragment-path",
    "-hlsl-entry",
    "-iapinotes-modules",
    "-iframework",
    "-iframeworkwithsysroot",
    "-image_base",
    "-init",
    "-install_name",
    "-ivfsoverlay",
    "-iwithsysroot",
    "-meabi",
    "--mhwdiv",
    "-MJ",
    "-mmlir",
    "-module-dependency-dir",
    "-mthread-model",
    "-multiply_defined",
    "-multiply_defined_unused",
    "--no-system-header-prefix",
    "--output-class-directory",
    "-pagezero_size",
    "-read_only_relocs",
    "-reexport_framework",
    "-reexport_library",
    "--resource",
    "-rpath",
    "-seg1addr",
    "-seg_addr_table",
    "-seg_addr_table_filename",
    "-segs_read_only_addr",
    "-segs_read_write_addr",
    "-serialize-diagnostics",
    "-sub_library",
    "-sub_umbrella",
    "--system-header-prefix",
    "-V",
    "-vfsoverlay",
    "--vfsoverlay",
    "-weak_framework",
    "-weak_library",
    "-weak_reference_mismatches",
    "-working-directory",
    "-Xmicrosoft-visualc-tools-root",
    "-Xmicrosoft-visualc-tools-version",
    "-Xmicrosoft-windows-sdk-root",
    "-Xmicrosoft-windows-sdk-version",
    "-Xmicrosoft-windows-sys-root",
    "-Zlinker-input",
];

/// gcc's long spellings whose proper prefixes gcc 16.1.1 takes a value for, each with the
/// shortest prefix it took, where the long spelling is a short option's no reader names:
/// every longer proper prefix took one too, and clang 22.1.8 refuses each of them. The
/// whole spelling is its own class: a value-taking option ([`VALUE_TWO_TOKEN`]), a pair the
/// drivers divide (`--entry`, [`DIVIDED_TWO_TOKEN`]), or refused by both (`--output-pch`,
/// which gcc takes a prefix of and refuses whole with a value). A range begins after a
/// shorter spelling that is an option of its own (`--dump` before `--dumpd`, `--output`
/// before `--output-`), which is that option. The abbreviations of gcc's long spellings of
/// a reader's own word (`--def` of `-D`, `--sys` of `--sysroot`, `--forc` of `-u`, measured
/// the same way) are read as that word and are [`LONG_ALIASES`]'s. gcc resolves a prefix
/// only where it names one option: `--include-d` names two (`--include-directory` and
/// `--include-directory-after`) and is refused, which is why `--include-directory` has no
/// range and the abbreviations of `--include-directory-after` begin after it (those four
/// families are [`DIVIDED_ABBREVIATED`], since clang reads them as another option).
/// `tests::every_abbreviation_bound_is_the_measured_one` holds each shortest prefix, and
/// the word one shorter, as literals.
const VALUE_ABBREVIATED: [(&str, &str); 7] = [
    ("--dumpbase-ext", "--dumpbase-"),
    ("--dumpdir", "--dumpd"),
    ("--embed-directory", "--embed-dire"),
    ("--entry", "--en"),
    ("--output-pch", "--output-"),
    ("--print-file-name", "--print-f"),
    ("--print-prog-name", "--print-p"),
];

/// Whether the driver takes the word after `word` as `word`'s own value, `word` being no
/// selection reader's spelling ([`Hand::Value`]): one of [`VALUE_TWO_TOKEN`], or a proper
/// prefix of a long spelling of [`VALUE_ABBREVIATED`] at least as long as the shortest gcc
/// took. The table holds what the sweep found on the drivers it measured, and no more: a
/// two-token option of another driver, or of a later version, that is in neither this
/// class nor a reader's is read as the driver's own, so its value reaches the arms as the
/// selection it spells, the reading this class closes for the measured drivers; the
/// ledger's control-arms entry carries that remainder with the sweep's tables.
///
/// Measured 2026-10-28 UTC on Fedora 44 x86_64 with gcc 16.1.1 and clang 22.1.8: every
/// option-shaped string in either driver's binary and manual page (9119 candidates, the
/// suffixes the linker's string merging hides among them), each under `-###` over a C input
/// with `-m32` as the word after it, and alone. An option takes the next word where the
/// driver, given it alone, reports a missing value (gcc's "missing argument to", "missing
/// filename after" and kin; clang's "argument to ... is missing") and, given `-m32` after it,
/// reports neither that nor the option unrecognised and reaches no i386 code generation,
/// which `-m32` read as the driver's own does (`elf_i386` on gcc's link line, an `i386`
/// triple on clang's `-cc1` line). Of the candidates, 53 take the next word on both drivers,
/// 23 on gcc alone with clang refusing the option, 93 on clang alone with gcc refusing it;
/// the selection spellings and hand-ons among them are their own classes, and the rest, 135,
/// are [`VALUE_TWO_TOKEN`], 38 of both drivers, 22 of gcc alone and 75 of clang alone (the
/// table's three groups). Seven take it on gcc and are read as a flag of their own by
/// clang, sixteen the reverse, of which two are the longer header options
/// [`HEADER_LONGER`] already held; the other 21 are [`DIVIDED_TWO_TOKEN`]. Every prefix of
/// every long spelling was measured the same way on both drivers; the project ledger
/// carries the tables.
#[must_use]
pub fn takes_a_value(word: &str) -> bool {
    value_taking(&spelled_alone(word))
}

/// [`takes_a_value`] of a short spelling: one of [`VALUE_TWO_TOKEN`], or a proper prefix of
/// a long spelling of [`VALUE_ABBREVIATED`] at least as long as the shortest gcc took.
fn value_taking(word: &str) -> bool {
    VALUE_TWO_TOKEN.contains(&word)
        || VALUE_ABBREVIATED
            .iter()
            .any(|(alias, shortest)| abbreviates_properly(word, alias, shortest))
}

/// How gcc reads one of its long spellings of a short option ([`LONG_ALIASES`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AliasForm {
    /// The short spelling takes its value as the next word or joined (`-D X`, `-DX`): the
    /// alias alone is that option, taking the next word as it does (`--def X` is `-D X`),
    /// and the whole spelling joined by `=` is the short spelling joined (`--define-macro=X`
    /// is `-DX`) where gcc takes that form.
    TwoToken {
        /// Whether gcc takes the whole spelling joined by `=` (`--define-macro=X`; not
        /// `--for-linker=`, which is a joined hand-on of its own, no alias).
        joins_by_eq: bool,
    },
    /// The short spelling carries its value joined only (`-m32`, `-std=c99`): the alias alone
    /// takes the next word and is read as the short spelling joined to it (`--machine 32` is
    /// `-m32`), and the whole spelling joined by `=` the same (`--machine=32`).
    JoinsNext,
    /// The alias alone is the short spelling (`--optimize` is `-O`), the next word the
    /// driver's own; the whole spelling joined by `=` is the short spelling joined
    /// (`--optimize=2` is `-O2`).
    Alone,
    /// The alias is the short spelling whole (`--no-standard-libraries` is `-nostdlib`),
    /// and gcc takes no `=` form of it (`--pie=` names no option).
    Whole,
}

impl AliasForm {
    /// Whether gcc takes the whole spelling joined by `=`: always for the alias of a short
    /// spelling that joins its value (`--machine=32`) or takes none (`--optimize=2`), where
    /// the row says so for a two-token one, and never for a whole spelling.
    const fn joins_by_eq(self) -> bool {
        match self {
            Self::TwoToken { joins_by_eq } => joins_by_eq,
            Self::JoinsNext | Self::Alone => true,
            Self::Whole => false,
        }
    }
}

/// One of gcc's long spellings of a short option: the long spelling, the short spelling gcc
/// reads it as (ending in the `=` a joined value follows where the short spelling joins by
/// one), the shortest proper prefix gcc takes for it (`None` where gcc takes none, or where
/// every proper prefix gcc takes is a divided pair, [`DIVIDED_ABBREVIATED`]: clang reads
/// `--include-directory-` as its own `--include-directory` joined to `-`, so the prefix is
/// no alias to both drivers), and its form, which says whether gcc also takes the whole
/// spelling joined by `=`.
struct LongAlias {
    long: &'static str,
    short: &'static str,
    shortest: Option<&'static str>,
    form: AliasForm,
}

const fn alias(
    long: &'static str,
    short: &'static str,
    shortest: Option<&'static str>,
    form: AliasForm,
) -> LongAlias {
    LongAlias {
        long,
        short,
        shortest,
        form,
    }
}

/// gcc's long spellings of the short options the readers of a flag list name, each read as
/// the short spelling by every reader ([`read`]): the target's `-m32` and `-m64`
/// (`--machine`), the macro reader's `-D` and `-U`, the header reader's `-include`,
/// `-imacros`, `-I` and `-idirafter`, the system root, library directory and search prefix
/// (`--sysroot`, `-L`, `-B`), the optimisation level (`-O`), the value-taking options `-u`,
/// `-x`, `-o`, `-A` and `-specs`, the hand-ons `-Xlinker` and `-Xassembler`, and the
/// removals `-nostdlib` and `-nostdinc` and the linkage forms the output kinds read. A long
/// spelling of a short option no reader names is not here: the value class keeps its own
/// ([`VALUE_ABBREVIATED`], whose short spellings take a value as the long ones do), and
/// `--entry`, which gcc reads as `-e` and clang as a flag of its own, is a divided pair
/// ([`DIVIDED_TWO_TOKEN`]). An exact reader of a long option is incomplete by construction:
/// gcc maps `--word` to `-fword` and `--no-word` to `-fno-word` wherever no entry of its own
/// matches, which [`generic_map`] models for every `--word` no table owns (`--use-ld=gold`
/// is the linker selection `-fuse-ld=gold`, `--no-pie` the position choice `-fno-pie`,
/// `--stack-protector-strong` the `-f` flag; clang 22.1.8 refuses each), maps `--warn-word`
/// to `-Wword`, `--debug` to `-g` and a few more to other prefixes, which no reader names,
/// and takes a unique proper prefix of any long spelling it maps by name; this table names
/// the spellings the readers' own words have with the bounds measured, and a long spelling
/// of another driver, or of a later gcc, is read as written or through the generic map.
///
/// Measured 2026-10-28 UTC on Fedora 44 x86_64 with gcc 16.1.1 and clang 22.1.8, each
/// spelling under `-###` over a C input, read from gcc's `COLLECT_GCC_OPTIONS` line (the
/// options as gcc read them) and clang's `-cc1` line, and for the macro and include
/// spellings from `-dM -E`: `--machine 32`, `--machine=32` and `--machine-32` are `-m32` to
/// gcc (`--machine 16` is `-m16`, `--machine=x32` is `-mx32`, `--machine no-sse` is
/// `-mno-sse`), `--mach` and `--machine` alone are refused, and clang refuses every form;
/// `--optimize` is `-O`, `--optimize=2` is `-O2` and `--op` the shortest prefix gcc takes,
/// `--op=2` and `--o` refused, `--optimize 2` leaving `2` an input file, and clang reads the
/// whole spelling the same; `--define-macro X`, `--define-macro=X` and `--def X` are `-D X`
/// (`--def=X` is gcc's Modula-2 `-fdef=X`, accepted with a warning and defining nothing,
/// `--de` refused), `--undefine-macro X` and `--un X` are `-U X` (`--un=X` refused),
/// `--imacros f`, `--imacros=f` and `--im f` are `-imacros f` (`--im=f` refused),
/// `--include f` and `--include=f` are `-include f` (`--inc`, `--incl` and `--includ` are
/// refused as naming two options), `--include-directory d` and `--include-directory=d` are
/// `-I d`, `--include-directory-after` is `-idirafter`, `--include-prefix` is `-iprefix`,
/// `--include-with-prefix` and `--include-with-prefix-after` are `-iwithprefix`,
/// `--include-with-prefix-before` is `-iwithprefixbefore`, `--include-barrier` is `-I-`,
/// and clang reads each whole spelling but the barrier the same, refusing every
/// abbreviation; `--sysroot r` and `--sys r` are `--sysroot=r`, `--library-directory x`,
/// `--library-directory=x` and `--li x` are `-L x`, `--prefix p`, `--prefix=p` and `--pref p`
/// are `-B p` (clang reads each whole spelling the same); `--force-link s`,
/// `--force-link=s` and `--forc s` are `-u s`, `--language c`, `--language=c` and `--la c`
/// `-x c`, `--output o` and `--output=o` `-o o`, `--assert X`, `--assert=X` and `--asser X`
/// `-A X`, `--specs f`, `--specs=f` and `--sp f` `-specs=f` (clang refuses `--specs f` and
/// reports the rest unused at `-c`); `--std c99` and `--std=c99` are `-std=c99` on both;
/// `--for-linker` and `--for-l` hand the next word to the linker as `-Xlinker` does, and
/// `--for-assembler` and `--for-a` to the assembler (clang refuses the assembler spelling
/// and the abbreviations); `--no-standard-libraries` and `--no-standard-l` are `-nostdlib`,
/// `--no-standard-includes` and `--no-standard-i` `-nostdinc` (clang reads the whole
/// spellings the same); `--pie`, `--shared`, `--static` and `--static-pie` are the linkage
/// forms (clang refuses `--pie` and `--static-pie`, reads `--static` and reports `--shared`
/// unused at `-c`). The abbreviation bounds are those `takes_a_value`'s sweep measured
/// (`tests::every_abbreviation_bound_is_the_measured_one` holds each as a literal), and
/// `tests::every_long_alias_is_read_as_its_short_spelling` holds each form. A spelling
/// clang refuses fails a measured build under clang before any arm matters, so the reading
/// is gcc's; none here is read by one driver as a flag of its own and by the other as the
/// option (that is the divided class).
const LONG_ALIASES: [LongAlias; 30] = [
    alias("--machine", "-m", None, AliasForm::JoinsNext),
    alias("--optimize", "-O", Some("--op"), AliasForm::Alone),
    alias("--std", "-std=", None, AliasForm::JoinsNext),
    alias(
        "--define-macro",
        "-D",
        Some("--def"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--undefine-macro",
        "-U",
        Some("--un"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include",
        "-include",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--imacros",
        "-imacros",
        Some("--im"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include-directory",
        "-I",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include-directory-after",
        "-idirafter",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include-prefix",
        "-iprefix",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include-with-prefix",
        "-iwithprefix",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include-with-prefix-before",
        "-iwithprefixbefore",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include-with-prefix-after",
        "-iwithprefix",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--include-barrier",
        "-I-",
        Some("--include-b"),
        AliasForm::Whole,
    ),
    alias(
        "--sysroot",
        "--sysroot=",
        Some("--sys"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--library-directory",
        "-L",
        Some("--li"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--prefix",
        "-B",
        Some("--pref"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--force-link",
        "-u",
        Some("--forc"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--language",
        "-x",
        Some("--la"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--output",
        "-o",
        None,
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--assert",
        "-A",
        Some("--asser"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--specs",
        "-specs=",
        Some("--sp"),
        AliasForm::TwoToken { joins_by_eq: true },
    ),
    alias(
        "--for-linker",
        "-Xlinker",
        Some("--for-l"),
        AliasForm::TwoToken { joins_by_eq: false },
    ),
    alias(
        "--for-assembler",
        "-Xassembler",
        Some("--for-a"),
        AliasForm::TwoToken { joins_by_eq: false },
    ),
    alias(
        "--no-standard-libraries",
        "-nostdlib",
        Some("--no-standard-l"),
        AliasForm::Whole,
    ),
    alias(
        "--no-standard-includes",
        "-nostdinc",
        Some("--no-standard-i"),
        AliasForm::Whole,
    ),
    alias("--pie", "-pie", None, AliasForm::Whole),
    alias("--shared", "-shared", Some("--sh"), AliasForm::Whole),
    alias("--static", "-static", None, AliasForm::Whole),
    alias(
        "--static-pie",
        "-static-pie",
        Some("--static-"),
        AliasForm::Whole,
    ),
];

/// The short spelling gcc reads a word of [`LONG_ALIASES`] as.
enum Spelling {
    /// One word: `-D` for `--def`, `-DX` for `--define-macro=X`, `-O` for `--op`, `-nostdlib`
    /// for `--no-standard-l`.
    Word(String),
    /// The short spelling joined to the next word: `-m` for `--machine`, `-std=` for `--std`.
    Joins(&'static str),
}

/// `word` as gcc reads it where it is one of [`LONG_ALIASES`] spelled alone (the whole
/// spelling, or a proper prefix from the measured shortest), joined by `=` to a value, or
/// `--machine-` joined, or a `--word` no spelling of any table owns, which gcc maps to
/// `-fword` ([`generic_map`]); `None` for any other word, which is read as written: an
/// abbreviation joined by `=` among them, which gcc refuses (`--un=X`, `--op=2`) or maps
/// generically (`--def=X` is its `-fdef=X`), and `--sysroot=`, `--prefix=` and
/// `--library-directory=` with nothing after the `=`, which name no directory and are the
/// readers' own joined spellings.
fn alias_of(word: &str) -> Option<Spelling> {
    explicit_alias_of(word).or_else(|| generic_map(word).map(Spelling::Word))
}

/// gcc's generic map of a long spelling: `--word` is `-fword` (`--no-word` is `-fno-word`)
/// wherever no spelling of its own matches, so `--use-ld=gold` is `-fuse-ld=gold`,
/// `--no-pie` is `-fno-pie`, `--plugin=p.so` is `-fplugin=p.so`, `--profile-use=rel` is
/// `-fprofile-use=rel` and `--stack-protector-strong` is `-fstack-protector-strong`,
/// words the readers own or refuse (measured 2026-10-28 UTC on Fedora 44 x86_64 with gcc
/// 16.1.1 under `-###`, from `COLLECT_GCC_OPTIONS`; clang 22.1.8 refuses each, so a
/// measured build under clang fails before any arm matters). `None` where the word is a
/// spelling some table owns as written (a selection, a value-taking or divided option, a
/// hand-on, clang's `--rtlib=`, `--target=` and kin, `--param=`, the joined hand-ons), or
/// is no `--word` at all. gcc's maps to other prefixes (`--debug` to `-g`, `--warn-format`
/// to `-Wformat`, `--profile` to `-p`, `--verbose` to `-v`, measured the same way) are
/// read as `-f` words no reader names, and a `--word` gcc refuses (`--sjlj-exceptions`)
/// fails the measured build, so neither reading reaches a verdict.
fn generic_map(word: &str) -> Option<String> {
    let rest = word.strip_prefix("--")?;
    if !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    // A reader that owns the word's stem in one form owns it in every form: clang's
    // `--config` takes the next word and `--config=f` joins it, one option of the
    // relative-path reader (clang 22.1.8 reads `--config=rel/c.cfg` and `--config rel/c.cfg`;
    // gcc 16.1.1 refuses both; measured 2026-10-28 UTC on Fedora 44 x86_64 under `-###`), so
    // the map stops at the stem, whichever reader's table names it.
    let stem = word.split_once('=').map_or(word, |(stem, _)| stem);
    let joined = format!("{stem}=");
    let owned = [word, stem, joined.as_str()].into_iter().any(|w| {
        selection_word_of(w).is_some()
            || hand_of(w) != Hand::Driver
            || divided_word(w)
            || crate::compile::names_a_path_option(w)
    }) || ["--param=", "--for-linker=", "--for-assembler="]
        .iter()
        .any(|p| word.starts_with(p));
    (!owned).then(|| format!("-f{rest}"))
}

/// [`alias_of`] over [`LONG_ALIASES`] alone.
fn explicit_alias_of(word: &str) -> Option<Spelling> {
    if let Some(rest) = word.strip_prefix("--machine-")
        && !rest.is_empty()
    {
        return Some(Spelling::Word(format!("-m{rest}")));
    }
    for alias in &LONG_ALIASES {
        if word == alias.long
            || alias
                .shortest
                .is_some_and(|shortest| abbreviates_properly(word, alias.long, shortest))
        {
            return Some(match alias.form {
                AliasForm::TwoToken { .. } => {
                    Spelling::Word(alias.short.trim_end_matches('=').to_owned())
                }
                AliasForm::Alone | AliasForm::Whole => Spelling::Word(alias.short.to_owned()),
                AliasForm::JoinsNext => Spelling::Joins(alias.short),
            });
        }
        // An empty value after the `=` is left to the readers' own joined spellings where
        // the short spelling takes a separate word (`--sysroot=`, `--prefix=` and
        // `--library-directory=` name no directory, and `-D` alone would take the next);
        // `--optimize=` is gcc's `-O`.
        if alias.form.joins_by_eq()
            && let Some(value) = word
                .strip_prefix(alias.long)
                .and_then(|rest| rest.strip_prefix('='))
            && (!value.is_empty() || !matches!(alias.form, AliasForm::TwoToken { .. }))
        {
            return Some(Spelling::Word(format!("{}{value}", alias.short)));
        }
    }
    None
}

/// `word` as gcc reads it on its own: the short spelling of an alias spelled alone or
/// joined ([`alias_of`]), or the word itself. An alias that joins the next word
/// (`--machine`) is itself here, since alone it names no option; [`read`] joins it.
pub(crate) fn spelled_alone(word: &str) -> std::borrow::Cow<'_, str> {
    match alias_of(word) {
        Some(Spelling::Word(short)) => std::borrow::Cow::Owned(short),
        Some(Spelling::Joins(_)) | None => std::borrow::Cow::Borrowed(word),
    }
}

/// The words of a flag list one [`Reading`] covers: the word alone, or the word and the
/// next, which the driver takes with it or joins to it. One state, so a reading that joins
/// the next word covers two by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Covers {
    /// The word alone: one the driver reads on its own, or one that would take the next
    /// word where none exists.
    Word,
    /// The word and the next, which the driver takes with it: a hand-on's handed word, a
    /// value-taking option's value, or a two-token selection's value.
    Pair,
    /// The word and the next, joined into one short spelling (`-m32` for `--machine 32`).
    Joined,
}

impl Covers {
    /// How many words of the list the reading covers, which every walk advances by.
    pub(crate) const fn span(self) -> usize {
        match self {
            Self::Word => 1,
            Self::Pair | Self::Joined => 2,
        }
    }
}

/// One word of a flag list as the driver reads it where it stands ([`read`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reading<'a> {
    /// The word as gcc reads it: the short spelling where the word is one of gcc's long
    /// aliases or an abbreviation of one ([`LONG_ALIASES`]), joined to the next word where
    /// the alias joins it (`-m32` for `--machine 32`), and the word itself otherwise.
    pub word: std::borrow::Cow<'a, str>,
    /// What the driver does with the word after this one, classified on `word`.
    pub hand: Hand,
    /// The words of the list this reading covers.
    pub covers: Covers,
}

impl Reading<'_> {
    /// How many words of the list this reading covers ([`Covers::span`]).
    pub(crate) const fn span(&self) -> usize {
        self.covers.span()
    }

    /// Whether `word` is the alias joined to the next word.
    pub(crate) fn joined(&self) -> bool {
        self.covers == Covers::Joined
    }

    /// How far a reader of the driver's own words advances past this reading: what it
    /// covers, except that the word clang applies for one architecture (`-Xarch_<arch>
    /// <word>`, [`Hand::Arch`]) is read next as the driver's own, since the driver applies
    /// it as one (clang 22.1.8 forwarded `-Xarch_x86_64 -Wl,-znotext` to its link, measured
    /// 2026-10-28 UTC on Fedora 44 x86_64 under `-###`). The selection walk carries the pair
    /// instead, under its own reader ([`Hand::Arch`]). `<arch>` is not read: a word clang
    /// leaves unused for another architecture (`-Xarch_i386 -fPIE` on x86_64, measured the
    /// same day) is read as applied all the same, as the selection walk carries it, so such
    /// a reading withholds, refuses or fails a build rather than reads a verdict.
    pub(crate) fn own_words_span(&self) -> usize {
        if self.hand == Hand::Arch {
            1
        } else {
            self.span()
        }
    }
}

/// What the driver does with `word` and the word after it, `next`: the one classifier
/// every reader of a flag list asks, so that a word read by one as its own is read by none
/// of the others as the driver's, whatever gcc's spelling of it. The selection walk
/// ([`selections`]), the refusals ([`driver_divided_pairs`], [`runtime_removing_flags`],
/// [`unsupported_target_flags`], `compile::relative_path_readings`), the listing readers
/// (`compile_inputs::macro_words`, `compile_inputs::optimization_words`), the macro
/// operation reader (`measure`'s `preprocessor_ops` and its unread-input guard) and the
/// output kinds' partition (`probe::LinkMode::partition_flags`) each advance by what it
/// covers ([`Covers`]) and classify its `word`. The hand-ons are [`Hand`]'s classes, the value-taking options
/// [`takes_a_value`]'s, the selections [`selection_word`]'s, and gcc's long aliases of each
/// [`LONG_ALIASES`]'s; what any of them leaves out is read as a word of the driver's own,
/// spanning itself. The readers of a build's own line and of the arms ask it too: the
/// silencing flag of a target's macros ([`silencing_flag`]), the control arms' macro set
/// (`measure::macro_names_in`), a shared-object build's position-independence choice
/// (`probe::LinkMode::states_a_pic_choice`) and a link line's text-relocation permission
/// (`decode::diag`), each stepping past clang's `-Xarch_<arch>` to the applied word
/// ([`Reading::own_words_span`]); the level reader of `no-strict-overflow`
/// (`decode::runtime`) reads that word in an arm of its own.
pub(crate) fn read<'a>(word: &'a str, next: Option<&str>) -> Reading<'a> {
    let (word, covers): (std::borrow::Cow<'a, str>, Covers) = match (alias_of(word), next) {
        (Some(Spelling::Word(short)), _) => (std::borrow::Cow::Owned(short), Covers::Word),
        (Some(Spelling::Joins(short)), Some(value)) => (
            std::borrow::Cow::Owned(format!("{short}{value}")),
            Covers::Joined,
        ),
        (Some(Spelling::Joins(_)) | None, _) => (std::borrow::Cow::Borrowed(word), Covers::Word),
    };
    let hand = hand_of(&word);
    let covers = if covers == Covers::Word && next.is_some() && takes_a_word_of(&word) {
        Covers::Pair
    } else {
        covers
    };
    Reading { word, hand, covers }
}

/// Whether the driver takes the word after `word` with it: a hand-on, a value-taking
/// option, a two-token selection, or an alias that joins the next word (`--machine`). The
/// class is [`read`]'s, asked with a stand-in next word, so it has one definition; it is
/// what [`driver_divided_pairs`] asks of a word that may end the list.
fn takes_a_word(word: &str) -> bool {
    read(word, Some("")).covers != Covers::Word
}

/// [`takes_a_word`] of a short spelling.
fn takes_a_word_of(word: &str) -> bool {
    hand_of(word) != Hand::Driver || matches!(selection_word_of(word), Some((_, Takes::Two)))
}

/// Two-token options one driver takes a value for and the other reads as a flag of its own,
/// so the walk cannot be right for both where the next word selects something, as with
/// clang's `-isystem-after` and `-include-pch` ([`HEADER_LONGER`]): gcc's `-Tbss`, `-Tdata`
/// and `-Ttext`, which clang reads as its `-T` joined to a script name, gcc's `-dumpbase`,
/// `-dumpbase-ext`, `-dialect` and `--entry`, which clang accepts as flags and reports
/// unused; and clang's `-dependency-file`, `-undefined`, `-umbrella` and the rest, which gcc
/// reads as its `-d` or `-u` joined to the rest and accepts. Each is [`Owner::Nobody`]'s,
/// passing over itself alone, and a pair of one before a word a reader takes is refused
/// before any build ([`driver_divided_pairs`]). Measured as [`takes_a_value`] says.
const DIVIDED_TWO_TOKEN: [&str; 21] = [
    // gcc takes the next word; clang reads it as its own.
    "-dialect",
    "-dumpbase",
    "-dumpbase-ext",
    "--entry",
    "-Tbss",
    "-Tdata",
    "-Ttext",
    // clang takes the next word; gcc reads it as its own.
    "-darwin-target-variant",
    "-darwin-target-variant-triple",
    "-dependency-dot",
    "-dependency-file",
    "-dsym-dir",
    "-dylib_file",
    "-dylinker_install_name",
    "-exported_symbols_list",
    "-lazy_framework",
    "-lazy_library",
    "-object-file-name",
    "-umbrella",
    "-undefined",
    "-unexported_symbols_list",
];

/// gcc's long spellings whose proper prefixes, from the shortest here, gcc 16.1.1 takes a
/// value for and clang 22.1.8 reads as its own `--include` or `--include-directory` joined to
/// the rest, with the next word its own: divided pairs ([`DIVIDED_TWO_TOKEN`]). The whole
/// spelling both drivers take is an alias ([`LONG_ALIASES`], whose row takes no abbreviation
/// of its own, since every proper prefix gcc takes is divided here; a test holds the two
/// tables to that), and the shorter prefixes gcc refuses as naming two options
/// ([`VALUE_ABBREVIATED`] says so).
const DIVIDED_ABBREVIATED: [(&str, &str); 4] = [
    ("--include-directory-after", "--include-directory-"),
    ("--include-prefix", "--include-p"),
    ("--include-with-prefix-after", "--include-with-prefix-a"),
    ("--include-with-prefix-before", "--include-with-prefix-b"),
];

/// Whether `word` is a pair the drivers divide ([`DIVIDED_TWO_TOKEN`], or a proper prefix
/// of [`DIVIDED_ABBREVIATED`] at least as long as its shortest).
fn divided_word(word: &str) -> bool {
    DIVIDED_TWO_TOKEN.contains(&word)
        || DIVIDED_ABBREVIATED
            .iter()
            .any(|(alias, shortest)| abbreviates_properly(word, alias, shortest))
}

/// Whether `word` is a proper prefix of `alias` at least as long as `shortest`
/// ([`abbreviates`] without the whole spelling, whose class is its own).
fn abbreviates_properly(word: &str, alias: &str, shortest: &str) -> bool {
    word != alias && abbreviates(word, alias, shortest)
}

/// The words of [`Hand::Tool`] spelled whole; the abbreviations and the joined
/// `-Xopenmp-target=` are matched in [`hand`].
const PASSED_THROUGH: [&str; 12] = [
    "-Xlinker",
    "--for-linker",
    "--for-assembler",
    "-Xassembler",
    "-Xclang",
    "-Xclangas",
    "-mllvm",
    "-Xoffload-linker",
    "-Xopenmp-target",
    "-Xcuda-ptxas",
    "-Xcuda-fatbinary",
    "-Xanalyzer",
];

/// What the driver does with the word after `word` ([`Hand`]), `word` read on its own as
/// gcc reads it ([`spelled_alone`]: `--for-l` is `-Xlinker`, `--def` is `-D`).
fn hand(word: &str) -> Hand {
    hand_of(&spelled_alone(word))
}

/// [`hand`] of a short spelling.
fn hand_of(word: &str) -> Hand {
    if word == "-Xpreprocessor" {
        Hand::Preprocessor
    } else if word.starts_with("-Xarch_") {
        Hand::Arch
    } else if PASSED_THROUGH.contains(&word)
        || word.starts_with("-Xopenmp-target=")
        || word.starts_with("-Xoffload-linker")
    {
        Hand::Tool
    } else if value_taking(word) {
        Hand::Value
    } else {
        Hand::Driver
    }
}

/// Who reads the word after `word`, as [`hand`] classifies it, with the tool named, for the
/// reader of the paths a flag list hands each tool (`compile::relative_path_readings`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handed<'a> {
    /// The driver, as its own word ([`Hand::Driver`]).
    Driver,
    /// The driver, as its own option for one architecture ([`Hand::Arch`]).
    Arch,
    /// The preprocessor, gcc's `cc1` or clang's `-cc1` (`-Xpreprocessor`, [`Hand::Preprocessor`]).
    Preprocessor,
    /// The assembler: `-Xassembler`, and `--for-assembler` and its abbreviations.
    Assembler,
    /// A linker, which reads its own options and not the driver's: `-Xlinker`, `--for-linker`
    /// and its abbreviations hand to the one named `linker`, and clang's `-Xoffload-linker`
    /// (joined to a triple or not) to the offload linker it names.
    Linker(&'a str),
    /// Another tool, named by the word that hands to it: every other [`Hand::Tool`] word.
    Tool(&'a str),
}

/// Who reads the word after `word` ([`Handed`]).
pub(crate) fn handed(word: &str) -> Handed<'_> {
    match hand(word) {
        // A value-taking option is the driver's own word, and its value the driver's too
        // (`compile::relative_path_readings` passes the pair over unread unless the option
        // names a path).
        Hand::Driver | Hand::Value => Handed::Driver,
        Hand::Arch => Handed::Arch,
        Hand::Preprocessor => Handed::Preprocessor,
        Hand::Tool => {
            let short = spelled_alone(word);
            if short == "-Xlinker" {
                Handed::Linker("linker")
            } else if word.starts_with("-Xoffload-linker") {
                Handed::Linker(word)
            } else if short == "-Xassembler" {
                Handed::Assembler
            } else {
                Handed::Tool(word)
            }
        }
    }
}

/// The reader whose words the control arms take a selection from: the one walk every
/// selection reader is a projection of ([`selections`]) gives each word of a flag list one
/// owner, so a word one reader takes as the value of a two-token option is read by no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// The target reader's ([`target_selecting_flags`]): `chooses` is whether the words
    /// choose the target (`true`) or a system root (`false`), which [`selects_target`] reads.
    Target { chooses: bool },
    /// The runtime reader's ([`runtime_selecting_flags`]).
    Runtime,
    /// The header reader's ([`header_selecting_flags`]).
    Header,
    /// The linker reader's program flags ([`linker_program_flags`]): `-fuse-ld=` and
    /// `--ld-path=`, which [`link_selection`] reads the program from.
    Linker,
    /// No reader's: clang's `-isystem-after` and `-include-pch` ([`HEADER_LONGER`]), spelled
    /// alone, which no arm carries ([`header_selecting_flags`] says why they are left out),
    /// and the other two-token options one driver takes a value for and the other reads as a
    /// flag of its own ([`DIVIDED_TWO_TOKEN`], [`DIVIDED_ABBREVIATED`]). Each passes over
    /// itself and no value. The two drivers read the word after it differently (one as the
    /// option's value, the other as a flag of its own), and the walk cannot be right for both
    /// where that word selects something: a pair whose second word a reader takes is refused
    /// before any build ([`driver_divided_pairs`], which has the measurement), and a pair
    /// whose second word selects nothing reads the same under either driver, since neither
    /// reading carries a word of it to the arms.
    Nobody,
}

/// The tokens a selection word takes: itself, or itself and the next word. A count that
/// cannot be zero, so the walk ([`selections`]) advances on every word it classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Takes {
    One,
    Two,
}

impl Takes {
    fn len(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

/// The longest selection any reader takes, in words: the target reader's system root through
/// the preprocessor, `-Xpreprocessor -isysroot -Xpreprocessor <dir>` (two hand-on pairs). The
/// `flag_words` fuzz target bounds its one-reader law by it.
pub const LONGEST_SELECTION: usize = 4;

/// One word of a selection: its owner and the tokens it takes; `None` for a word that
/// selects nothing. The word is read on its own as gcc reads it ([`spelled_alone`]: `--li`
/// is `-L`, `--machine=32` is `-m32`; an alias that joins the next word, `--machine` alone,
/// is no selection until [`read`] joins it), and each reader's own classifier is asked in
/// turn ([`target_word`], [`runtime_word`], [`header_word`], [`linker_word`]), the order
/// deciding nothing: `tests::no_spelling_is_two_readers` holds, over the lists the
/// classifiers read, that no spelling one of them names is, or begins, a spelling another
/// names, so at most one answers for any word. A pair the drivers divide ([`divided_word`])
/// is [`Owner::Nobody`]'s, asked last, and none of its spellings is a reader's
/// (`tests::a_value_taking_option_is_no_selection_and_no_hand_on`).
fn selection_word(flag: &str) -> Option<(Owner, Takes)> {
    selection_word_of(&spelled_alone(flag))
}

/// [`selection_word`] of a short spelling.
fn selection_word_of(flag: &str) -> Option<(Owner, Takes)> {
    if let Some((chooses, takes)) = target_word(flag) {
        return Some((Owner::Target { chooses }, takes));
    }
    if let Some(takes) = runtime_word(flag) {
        return Some((Owner::Runtime, takes));
    }
    if let Some(selection) = header_word(flag) {
        return Some(selection);
    }
    if linker_word(flag) {
        return Some((Owner::Linker, Takes::One));
    }
    divided_word(flag).then_some((Owner::Nobody, Takes::One))
}

/// The selections of `flags`, each with its owner and its words, as written and in order: the one
/// walk the four selection readers ([`target_selecting_flags`], [`runtime_selecting_flags`],
/// [`header_selecting_flags`], [`link_selection`]) are projections of. Each word is classified once
/// ([`selection_word`]) and given to one owner with the tokens it takes, so a word one reader takes
/// as the value of its two-token option (`-L -B<dir>`: the target reader's library directory named
/// `-B<dir>`) is the value and not another reader's option (no runtime prefix), and the arms carry
/// the words of the measured line each once. What a prefix read from such a value does, measured
/// with each reader walking the list on its own against this walk on Fedora 44 x86_64, under
/// `--profile explicit --flags "-O2 --library-directory -B<dir>/"` (the `-L` spelling is refused
/// before any arm as a relative path, `compile::relative_path_readings`; the long spelling is not):
/// with gcc 16.1.1 and a `specs` file in `<dir>` appending `-fno-stack-protector` to `cc1`'s
/// options, the arms and the clean build read specs the measured build did not, the linker was
/// detected under `-B<dir>/` and `Linker::profile_flags` listed it, and 13 of 72 checks read
/// `probe-invalid` or `indeterminate` (the four stack-protector readings among them, over a
/// forced-on arm the specs had switched off), with and without `-fstack-protector-strong` on the
/// line; with clang 22.1.8 and an `ld` in `<dir>` linking every program with an executable stack,
/// the clean build linked through it and `linker-default-noexecstack` read `off`, a wrong `off`,
/// beside five `indeterminate` readings. Under this walk every check in the three cells reads what
/// the line without the pair reads (0 of 72 differ from that control), and nothing is consulted for
/// the linker.
///
/// A word handed to another tool is passed over with the word that hands it, and so is the
/// value of an option that selects nothing (`-u -B<dir>/`, the symbol named `-B<dir>/` to
/// both drivers and no prefix: [`Hand::Value`] has that measurement); a one-word
/// selection after clang's `-Xarch_<arch>` is carried as the pair under its own reader; and
/// `-isysroot` handed to gcc's `cc1` through `-Xpreprocessor`, which reads it as the driver
/// would, is the target reader's system root as written ([`Hand`] has the measurements). A
/// two-token spelling at the end of the list, with no value to take, is no selection: the
/// driver takes the word chard appends after the flags as its value, and the build fails
/// (gcc 16.1.1 on Fedora 44 x86_64, 2026-10-28 UTC: `-u -o out s.c` named `out` an input
/// it could not find, and `-u -dM -E` exited 1 with no define).
fn selections(flags: &[String]) -> Vec<(Owner, &[String])> {
    let mut selected = Vec::new();
    let mut i = 0;
    while let Some(flag) = flags.get(i) {
        let one = i.saturating_add(1);
        let two = i.saturating_add(2);
        let reading = read(flag, flags.get(one).map(String::as_str));
        match reading.hand {
            Hand::Tool | Hand::Value => {
                i = two;
                continue;
            }
            Hand::Preprocessor => {
                // `cc1` reads `-isysroot` handed to it as the driver would (`Hand::Preprocessor`
                // has the measurement), so `-Xpreprocessor -isysroot -Xpreprocessor <dir>` and
                // `-Xpreprocessor -isysroot<dir>` are carried as written, a system root; any
                // other word after `-Xpreprocessor` is `cc1`'s.
                let end = match flags.get(one).map(String::as_str) {
                    Some("-isysroot") if flags.get(two).is_some_and(|w| w == "-Xpreprocessor") => {
                        i.saturating_add(LONGEST_SELECTION)
                    }
                    Some(w) if w.starts_with("-isysroot") && w != "-isysroot" => two,
                    _ => {
                        i = two;
                        continue;
                    }
                };
                if let Some(taken) = flags.get(i..end) {
                    selected.push((Owner::Target { chooses: false }, taken));
                }
                i = end;
                continue;
            }
            Hand::Arch => {
                if let Some(next) = flags.get(one)
                    && let Some((owner, Takes::One)) = selection_word(next)
                    && let Some(pair) = flags.get(i..two)
                {
                    selected.push((owner, pair));
                }
                i = two;
                continue;
            }
            Hand::Driver => {}
        }
        // A word that selects nothing is passed over with the word it joins (`--std c99`),
        // and a selection is carried as written with the words its reading spans
        // (`--machine 32`, which is `-m32` to the driver, as the pair).
        let Some((owner, takes)) = selection_word_of(&reading.word) else {
            i = i.saturating_add(reading.span());
            continue;
        };
        // A two-token spelling with no value after it is no selection: `get` is `None`.
        let end = i.saturating_add(takes.len().max(reading.span()));
        match flags.get(i..end) {
            Some(taken) => {
                selected.push((owner, taken));
                i = end;
            }
            None => i = one,
        }
    }
    selected
}

/// The words of `flags` that `owner` reads, as written and in order ([`selections`]).
fn owned_by(flags: &[String], owner: Owner) -> Vec<String> {
    selections(flags)
        .into_iter()
        .filter(|(o, _)| *o == owner)
        .flat_map(|(_, words)| words.iter().cloned())
        .collect()
}

/// Spellings that name the linker program, each carrying its value joined: the one token
/// each takes.
const LINKER_JOINED: [&str; 2] = ["-fuse-ld=", "--ld-path="];

/// Whether `flag` names the linker program ([`LINKER_JOINED`]).
fn linker_word(flag: &str) -> bool {
    LINKER_JOINED.iter().any(|p| flag.starts_with(p))
}

/// The `-B<dir>` a runtime selection's words spell, where they are a search prefix:
/// `-B<dir>`, `--prefix=<dir>`, `-B <dir>` or `--prefix <dir>` (gcc's abbreviations of it
/// included, [`prefix_word`]), joined into the one-token form; `None` for another runtime
/// word, and for `--prefix=` with no directory, which both drivers accept and which names
/// none.
fn prefix_directory(words: &[String]) -> Option<String> {
    match words {
        [one] => {
            let dir = one
                .strip_prefix("-B")
                .or_else(|| one.strip_prefix("--prefix="))?;
            (!dir.is_empty()).then(|| format!("-B{dir}"))
        }
        [option, dir] if prefix_word(option) => Some(format!("-B{dir}")),
        _ => None,
    }
}

/// Whether a runtime selection's words are a search prefix spelling, with or without a
/// directory ([`prefix_directory`]).
fn is_prefix_spelling(words: &[String]) -> bool {
    match words {
        [one] => one.starts_with("-B") || one.starts_with("--prefix="),
        [option, _] => prefix_word(option),
        _ => false,
    }
}

/// Whether `word` is the two-token search prefix option: `-B`, or gcc's `--prefix` and its
/// abbreviations (`--pref` and longer), which are `-B` to it ([`LONG_ALIASES`]).
fn prefix_word(word: &str) -> bool {
    spelled_alone(word) == "-B"
}

fn link_selection(flags: &[String]) -> LinkSelection {
    let mut selection = LinkSelection::default();
    // Set by an `--ld-path=`, after which a `-fuse-ld=` is consulted and decides nothing
    // about the program. clang still reads `-fuse-ld=lld` beside an `--ld-path=` to treat
    // the linker as lld (its `LinkerIsLLD`); this function chooses only the program, and it
    // keeps the flag in `consulted`, so a control arm handed that list carries it as well.
    let mut ld_path = false;
    for (owner, words) in selections(flags) {
        // A pair after clang's `-Xarch_<arch>` is consulted and, where it names a program,
        // carried, as the driver was handed it. It chooses no program for the detection to
        // look for and no search prefix: clang 22.1.8 ran the default linker under
        // `-Xarch_x86_64 -fuse-ld=lld` (`Hand::Arch` has the measurement), and a prefix
        // through it reaches the arms by the runtime selection.
        let (through_arch, own) = match words {
            [first, rest @ ..] if hand(first) == Hand::Arch => (true, rest),
            _ => (false, words),
        };
        match owner {
            Owner::Runtime => {
                if !is_prefix_spelling(own) {
                    continue;
                }
                selection.consulted.extend(words.iter().cloned());
                if !through_arch && let Some(prefix) = prefix_directory(own) {
                    selection.prefixes.push(prefix);
                }
            }
            Owner::Linker => {
                selection.consulted.extend(words.iter().cloned());
                selection.program_flags.extend(words.iter().cloned());
                let Some(flag) = own.first().filter(|_| !through_arch) else {
                    continue;
                };
                if let Some(value) = flag.strip_prefix("-fuse-ld=") {
                    if ld_path {
                        continue;
                    }
                    selection.program = Some(if value.is_empty() || value == "ld" {
                        Program::Default
                    } else if value.contains('/') {
                        Program::File(PathBuf::from(value))
                    } else {
                        Program::Named(format!("ld.{value}"))
                    });
                } else if let Some(value) = flag.strip_prefix("--ld-path=") {
                    ld_path = true;
                    selection.program = Some(if value.is_empty() {
                        Program::Default
                    } else {
                        Program::File(PathBuf::from(value))
                    });
                }
            }
            Owner::Target { .. } | Owner::Header | Owner::Nobody => {}
        }
    }
    selection
}

/// The flags of `flags` that choose the target the driver emits code for, and the system
/// root it builds that target against, as written and in order: `-m32`, `-m64`,
/// `--target=`, and the two-token `-target` and `-arch`; then `--sysroot=`, the two-token
/// `--sysroot`, `-isysroot` in its joined and two-token spellings, and the library search
/// directory `-L` in both of its, and in its long spelling `--library-directory`, joined by
/// `=` and as two tokens, both of which gcc 16.1.1 and clang 22.1.8 pass to the linker as
/// `-L` (checked with `-###` on Fedora 44 x86_64; gcc also takes `--li` and every longer
/// prefix as the whole, and `--sys` and longer as `--sysroot`, which [`target_word`] reads;
/// clang accepts no abbreviation).
///
/// A target brings its own C library and startup objects, which a control arm's link reads:
/// under `-m32` on an x86_64 driver the measured build is `EM_386`, linked against the i386
/// `crt1.o`, while an arm without the flag is `EM_X86_64`, linked against the x86_64 one. A
/// system root chooses the same things for a fixed target: the C library's headers, so its
/// version macros and its fortify wrappers, and its `crt1.o`, `libc.so` and symbol versions.
/// `--sysroot` moves both halves for clang, but only the headers for Fedora 44's gcc 16,
/// whose install-relative `../../../../lib64` precedes the root on its library search path, so
/// it links the host's `crt1.o` and `libc.so` (measured; the project ledger carries the run). A
/// gcc configured `--with-sysroot`, or a cross gcc, is measured through Debian 12's and
/// Ubuntu 24.04's `aarch64-linux-gnu-gcc` (built-in root `/`, explicit `--sysroot=/`
/// measured too) and Fedora 44's (built-in root `/usr/aarch64-linux-gnu/sys-root`, empty)
/// under `--sysroot`, on 2026-10-01 (the project ledger). `-isysroot` moves the
/// headers for gcc, and for clang only on Darwin, where it also chooses the SDK the link reads
/// (measured with Apple clang 21; the project ledger carries the run).
///
/// A library search directory chooses the same things a root does, one directory at a
/// time, and a cross gcc can need one to link at all. Fedora 44's `gcc-aarch64-linux-gnu`
/// 16.2.1 ships no target C library, and its specs link `-latomic_asneeded`, which an
/// aarch64 Fedora root holds only in its own `usr/lib/gcc/aarch64-redhat-linux/16`; with
/// `--sysroot=ROOT -LROOT/usr/lib/gcc/aarch64-redhat-linux/16` the measured build links,
/// and with `-L` left out of the arms every arm and the clean build fail with
/// `cannot find -latomic_asneeded`, and 36 of the 58 checks measured on 2026-10-01 read
/// `probe-invalid` (the project ledger, the 2026-10-01 cross gcc note). Where an arm and the
/// measured build link from different directories the triple validates the detector on
/// libraries the measured build did not read, which is the argument for carrying the root.
/// `-L` reaches the compile-only arms too, where Apple clang 21 notes it as unused ("argument
/// unused during compilation"); no detector reads that phrase, and `-L` under clang is
/// unmeasured.
///
/// The C library a GNU/Linux gcc targets is taken too: `-mglibc`,
/// `-muclibc`, `-mmusl` and `-mbionic`, which gcc 16.1.1 on Fedora 44 x86_64 answered under
/// `-###` with another dynamic linker each (and `-mmusl` with other `int_fast` types), and
/// `-mandroid` with `-tno-android-cc` and `-tno-android-ld`, under which it linked
/// `crtbegin_dynamic.o`; clang 22.1.8 accepts `-mglibc` and `-muclibc` and changes nothing.
/// gcc's `--no-sysroot-suffix` drops the multilib suffix from the system root, which
/// Fedora 44's gcc has none of (`*sysroot_suffix_spec` is empty), so its effect is
/// unmeasured here.
/// Measured on 2026-10-06 on that host, which has musl's loader installed, under
/// `--profile explicit -O2 -mmusl` with gcc 16.1.1: without the C library selection, the
/// measured probes run under `ld-musl-x86_64.so.1` and the arms under glibc's, so
/// `fortify-enforced-known`, both `fortify-level-ge-2` rungs and `shadow-stack-enforced`
/// read `off` over positive arms that abort or run under a shadow stack; with it they read
/// `probe-invalid`, the positive arm failing to relocate `__printf_chk` as the measured
/// build would. Under `-m16` and `-mandroid` (gcc and clang, and gcc) the arms fail to
/// link as the measured build does, with no 32-bit C library and no `crtbegin_dynamic.o` on
/// the host, and the readings that x86_64 arms give without the selection read
/// `probe-invalid`, `build-failed` or, with the arch gate reading `i386` under `-m16`,
/// `arch-gated`. `-m16` and `-mx32` are not taken: a profile carrying either is refused
/// before any arm ([`unsupported_target_flags`]), so the `-m16` run above is not one a
/// profile can make.
///
/// `-B` and `--prefix` are not taken here, though they can choose startup objects: they
/// choose the linker and the compiler proper too, and are the runtime's
/// ([`runtime_selecting_flags`], which carries them to every arm, not only the arms that
/// link). clang's `--gcc-toolchain=` and `--gcc-install-dir=`, which choose `crtbegin.o`
/// and libstdc++ but not the C library, are the runtime's too. A library directory handed
/// to the linker (`-Wl,-L`, `-Xlinker -L`, `--for-linker=-L`, `-Wl,--library-path=`) is not
/// taken: the driver puts it after its own directories, so it cannot shadow the C library
/// or `libgcc` (measured 2026-10-06 with both drivers, a `libc.so` script there naming an
/// object without the x86 feature note: every spelling linked the host's libc and kept the
/// note, where `-L` dropped it). A two-token spelling at the end of the list, with no value
/// to take, is left out, as the driver would refuse it.
///
/// A word handed to another tool is passed over with the word that hands it, and a one-word
/// selection after clang's `-Xarch_<arch>` is carried as the pair ([`Hand`] has the
/// measurements). A word another reader takes, as its option or as the value of its
/// two-token one, is passed over as well: the readers are projections of one walk
/// ([`selections`]), which gives each word one owner.
#[must_use]
pub fn target_selecting_flags(flags: &[String]) -> Vec<String> {
    target_selection(flags)
        .into_iter()
        .flat_map(|(_, tokens)| tokens.iter().cloned())
        .collect()
}

/// Whether `flags` choose the target the driver emits code for: `-m32`, `-m64`,
/// `--target=`, `-target` or `-arch`, parsed as [`target_selecting_flags`] parses them. A
/// system root alone chooses no target, since it is built against the one the driver
/// already has.
///
/// Where this holds, [`gate_target`] reads the arch gate's architecture from the dump under
/// the profile's flags rather than from the flagless `-dumpmachine`, which cannot see them.
#[must_use]
pub fn selects_target(flags: &[String]) -> bool {
    target_selection(flags)
        .iter()
        .any(|(chooses_target, _)| *chooses_target)
}

/// The parse behind [`target_selecting_flags`] and [`selects_target`]: each selection's
/// tokens, as written and in order, beside whether it chooses the target (`true`) or a
/// system root (`false`).
fn target_selection(flags: &[String]) -> Vec<(bool, &[String])> {
    selections(flags)
        .into_iter()
        .filter_map(|(owner, words)| match owner {
            Owner::Target { chooses } => Some((chooses, words)),
            Owner::Runtime | Owner::Header | Owner::Linker | Owner::Nobody => None,
        })
        .collect()
}

/// One word of a target selection: whether it chooses the target (`true`) or a system root
/// (`false`), and the tokens it takes, one or two; `None` for a word that selects nothing. The
/// exact two-token spellings are matched before the joined prefixes, so `-isysroot` alone takes
/// the next word and `-isysroot<dir>` takes none.
fn target_word(flag: &str) -> Option<(bool, Takes)> {
    if TARGET_WHOLE.contains(&flag) {
        Some((true, Takes::One))
    } else if TARGET_TWO_TOKEN.contains(&flag) {
        Some((true, Takes::Two))
    } else if ROOT_WHOLE.contains(&flag) {
        Some((false, Takes::One))
    } else if ROOT_TWO_TOKEN.contains(&flag) {
        // gcc's `--library-directory`, and its abbreviations of it and of `--sysroot`
        // (`--li`, `--sys` and longer), reach here as `-L` and `--sysroot`
        // ([`LONG_ALIASES`] has the measurement), so every reader of the list, the
        // relative-path refusal among them, reads them as the whole spellings.
        Some((false, Takes::Two))
    } else if TARGET_JOINED.iter().any(|p| flag.starts_with(p)) {
        Some((true, Takes::One))
    } else if ROOT_JOINED.iter().any(|p| flag.starts_with(p)) || root_through_preprocessor(flag) {
        Some((false, Takes::One))
    } else {
        None
    }
}

/// Spellings that choose the target and are the whole selection.
const TARGET_WHOLE: [&str; 2] = ["-m32", "-m64"];

/// Spellings that choose the target and take their value in the next token.
const TARGET_TWO_TOKEN: [&str; 2] = ["-target", "-arch"];

/// Spellings that choose the target and carry their value joined.
const TARGET_JOINED: [&str; 1] = ["--target="];

/// Spellings that choose the system root, or the C library within it, and are the whole
/// selection.
const ROOT_WHOLE: [&str; 8] = [
    "-mglibc",
    "-muclibc",
    "-mmusl",
    "-mbionic",
    "-mandroid",
    "-tno-android-cc",
    "-tno-android-ld",
    "--no-sysroot-suffix",
];

/// Spellings that choose the system root, or a library directory within it, and take their
/// value in the next token (`--library-directory`, which gcc reads as `-L`, reaches here so,
/// [`LONG_ALIASES`]).
const ROOT_TWO_TOKEN: [&str; 3] = ["--sysroot", "-isysroot", "-L"];

/// Spellings that choose the system root, or a library directory within it, and carry their
/// value joined.
const ROOT_JOINED: [&str; 4] = ["--sysroot=", "-isysroot", "-L", "--library-directory="];

/// Whether `flag` is a `-Wp,` list with an `-isysroot` item, which gcc's `cc1` reads as the
/// driver would (`Hand::Preprocessor`): a system root, carried whole.
fn root_through_preprocessor(flag: &str) -> bool {
    flag.strip_prefix("-Wp,")
        .is_some_and(|list| list.split(',').any(|item| item.starts_with("-isysroot")))
}

/// The flags of `flags` that choose the runtime a build compiles and links against within
/// its target, as written and in order: the C++ standard library (`-stdlib=`, `--stdlib=`,
/// the two-token `--stdlib`, and its header directory `-stdlib++-isystem`, joined and as
/// two tokens), the compiler runtime (`--rtlib=`, `-rtlib=`, the two-token `--rtlib`), the
/// unwinder (`--unwindlib=`, `-unwindlib=`), the GCC installation clang takes
/// `crtbegin.o`, `libgcc` and libstdc++ from (`--gcc-toolchain=`, `--gcc-install-dir=`, and
/// `--gcc-triple=`, which picks the triple's directory within the prefix), and the resource
/// directory clang takes its own runtime from (`-resource-dir=` and the two-token
/// `-resource-dir`: `clang_rt.crtbegin.o`, `libclang_rt.builtins.a`, the sanitizer runtimes
/// and the builtin headers).
///
/// Also: the driver's search prefix, `-B` joined and as two tokens and
/// `--prefix=` and `--prefix <dir>`, which gcc 16.1.1 and clang 22.1.8 both read as `-B`;
/// clang's installation directory, `-ccc-install-dir <dir>`, from which it finds the GCC
/// installation at `<dir>/../lib/gcc/<triple>/<version>`; the default configuration file
/// clang loads, chosen by `--config-system-dir=`, `--config-user-dir=` and dropped by
/// `--no-default-config` (Fedora 44's own file is `--gcc-triple=x86_64-redhat-linux`, a
/// runtime selection); and which form of a runtime library the link reads, `-static-libgcc`
/// and `-shared-libgcc` (`libgcc_eh.a` or `libgcc_s.so` for the unwinder),
/// `-static-libstdc++`, gcc's `-static-libasan`, `-static-libtsan`, `-static-liblsan`,
/// `-static-libubsan` and `-static-libhwasan`, and clang's `-static-libsan`, `-shared-libsan`
/// and `-static-openmp`.
///
/// Each spelling was accepted under `-###` on Fedora 44 x86_64 by clang 22.1.8, gcc 16.1.1,
/// or both, on 2026-10-05 or 2026-10-06. The spellings refused there are not taken, since a
/// measured build carrying one fails before it selects anything: `-stdlib <v>`,
/// `-rtlib <v>`, `--unwindlib <v>`, `--gcc-toolchain <dir>`, `--gcc-install-dir <dir>`,
/// `-gcc-toolchain` in either form, `--gcc-triple <v>`, `-gcc-triple=`, `--resource-dir` in
/// either form, `-resource-dir` joined without `=`, `-ccc-install-dir=`,
/// `--config-system-dir <dir>`, and the abbreviations `--pref=` and `-prefix=`. Fedora 44's
/// own clang configuration file passes `--gcc-triple=`, and one on the command line wins
/// over it. gcc 16.1.1 refuses every clang spelling but `-unwindlib=`, which it reads as
/// `-u nwindlib=...`, an undefined symbol for the link; the arm carries it as the measured
/// build did, so the two still link alike.
///
/// Like the target, the runtime hardens nothing, and an arm that leaves it out validates a
/// detector on other startup objects or another library than the measured build used.
/// Measured on 2026-10-05 on Fedora 44 x86_64 with clang 22.1.8 and a copy of the gcc 16.1.1
/// install directory whose `crtbegin*.o` had its `.note.gnu.property` removed with
/// `objcopy`: under `--gcc-install-dir=` that copy, or `--gcc-toolchain=` its prefix, a
/// program built with `-fcf-protection=full` carried no x86 feature note, and before the
/// arms carried the selection `cet-marked` read `off` over a positive control linked
/// against the host's marked `crtbeginS.o` (`measure::arm_flags` has the rest). On
/// 2026-10-06 the same held for a prefix holding a second triple's copy under
/// `--gcc-triple=` that triple, and for a resource directory whose `clang_rt.crtbegin.o`
/// had the note removed under `--rtlib=compiler-rt -resource-dir=` it: before the two were
/// taken here, `cet-marked` and `shadow-stack-enforced` read `off` over positive controls
/// linked against the host's marked objects. Later that day, with gcc 16.1.1 and clang
/// 22.1.8, the same two checks read `off` under `--prefix=` and `--prefix` naming a
/// directory of note-stripped `crtbegin*.o` (both drivers), under `-ccc-install-dir` naming
/// the `bin` beside such an installation, and under `--config-system-dir=` and
/// `--config-user-dir=` naming a directory whose `x86_64-redhat-linux-gnu-clang.cfg` held
/// `--gcc-install-dir=` it (clang). `-B` itself reached only the arms that link before that
/// day, so the linked checks were sound under it, but gcc adds `<prefix>/include` ahead of
/// the system headers: with a `features.h` there that set `__USE_FORTIFY_LEVEL` to 0,
/// `-O2 -D_FORTIFY_SOURCE=3 -B<prefix>/` read `fortify-effective` `off` over positive macro
/// arms that read the host's headers. `-static-libgcc` moved the C++ probe's unwinder from
/// `libgcc_s.so.1` into the executable, from a `libgcc_eh.a` the profile's `-L` could choose,
/// while its arms kept `libgcc_s.so.1`; no check reads that probe's marking, so no verdict
/// moved. `--no-default-config` and the sanitizer and `OpenMP` forms were inert on that host
/// (accepted, no verdict moved).
///
/// `-B` and `--prefix` also choose the assembler, the linker and the compiler proper, and gcc
/// reads a `specs` file found in the prefix as its own specs. Carried, the arms run the
/// programs and read the specs the measured build does; a specs file there that forces
/// hardening reaches the negative arm too, and the triple reads `probe-invalid`, which is
/// what it is. Left off, it read `off` as above. So the prefix is carried, and the linker
/// selection ([`linker_program_flags`]) adds only the program flags beside it.
///
/// Also: clang's exception model, `-fsjlj-exceptions`, `-fdwarf-exceptions`,
/// `-fseh-exceptions` and `-fwasm-exceptions`, of which the last written wins. The model
/// decides where the landing-pad table goes and whether one is written at all, which
/// `except-table-emitted` reads. On Raspbian 13 armv6 (clang 19.1.7) the `SjLj` and DWARF
/// models put it inside `.text`, where no section marks it, and the check read `off` over
/// arms built under the default model, which marks it with a `.rel.ARM.extab`; on Fedora 44
/// x86_64 (clang 22.1.8) those two emit `.gcc_except_table` and read `on`, and
/// `-fseh-exceptions` writes no table and read `off` the same way. Carried, both arms build
/// under the profile's model, and where it writes no mark the triple cannot tell the arms
/// apart and reads `probe-invalid`. The cost, measured on that x86_64 host: under clang's
/// `-O2 -fexceptions -fsjlj-exceptions`, `cxx-hardening-requested` and `cxx-stdlib-assertions`
/// moved from `off` to `probe-invalid`, since their arms, built with no `-O`, keep `SjLj` frames
/// whose runtime (`__gxx_personality_sj0`, `_Unwind_SjLj_Register`) the glibc toolchain does
/// not ship and fail to link, where the measured build linked only because `-O2` removed its
/// landing pads; under `SjLj` at `-O0` and under DWARF at either level nothing moved, and the
/// SEH cells moved `except-table-emitted` alone, at both levels. `-fwasm-exceptions` crashed clang 22.1.8 on x86_64, so
/// that build fails with or without it. gcc rejects all four. `-fignore-exceptions` is not a
/// model and is not taken: the build it describes keeps no landing pads, which
/// `except-table-emitted` reads as `off` against an arm without it, the reading
/// `exceptions-macro`'s notes describe. A model chosen any other way (a `--config=` or
/// `-specs=` file, or the frontend option handed through `-Xclang`, `-Wp,` or
/// `-Xpreprocessor`) does not reach the arms, and `except-table-emitted` is withheld where
/// the measured compile's `-###` line names another model than theirs
/// (`report::EXCEPTION_MODEL_READINGS`).
///
/// A removal (`-nostdinc++`, `-nostdlib++`, `-nostartfiles` and the rest) is not taken: a
/// profile carrying one is refused ([`runtime_removing_flags`] says why). clang's
/// configuration files named by `--config=` and gcc's `-specs=` are not taken either: what
/// they inject is as likely hardening as a runtime, and a later flag cannot switch it off,
/// which is the reason the arms are profile-free (`measure`'s module note). Where one also
/// chooses the startup objects, the checks those objects decide are withheld under
/// `link-inputs-unmatched-by-arms` ([`crate::link_inputs`] has the comparison); where one
/// chooses the headers or adds a macro operation, the checks those decide are withheld
/// under `compile-inputs-unmatched-by-arms` ([`crate::compile_inputs`] has that
/// comparison). A linkage form
/// (`-static`, `-static-pie`, `-pie`, `-no-pie`, `-shared`) is not taken: it is what the
/// `pie` checks and the output kinds read, not a choice of where the runtime is found. A
/// two-token spelling at the end of the list, with no value to take, is left out.
///
/// A word handed to another tool is passed over with the word that hands it, and a one-word
/// selection after clang's `-Xarch_<arch>` is carried as the pair ([`Hand`] has the
/// measurements). A word another reader takes, as its option or as the value of its
/// two-token one, is passed over as well: the readers are projections of one walk
/// ([`selections`]), which gives each word one owner.
#[must_use]
pub fn runtime_selecting_flags(flags: &[String]) -> Vec<String> {
    owned_by(flags, Owner::Runtime)
}

/// Spellings of the runtime selection that take their value in the next token.
const RUNTIME_TWO_TOKEN: [&str; 6] = [
    "--stdlib",
    "--rtlib",
    "-stdlib++-isystem",
    "-resource-dir",
    "-B",
    "-ccc-install-dir",
];

/// Spellings of the runtime selection that carry their value joined.
const RUNTIME_JOINED: [&str; 15] = [
    "-stdlib=",
    "--stdlib=",
    "-stdlib++-isystem",
    "--rtlib=",
    "-rtlib=",
    "--unwindlib=",
    "-unwindlib=",
    "--gcc-toolchain=",
    "--gcc-install-dir=",
    "--gcc-triple=",
    "-resource-dir=",
    "-B",
    "--prefix=",
    "--config-system-dir=",
    "--config-user-dir=",
];

/// Spellings of the runtime selection that are the whole selection.
const RUNTIME_WHOLE: [&str; 16] = [
    "--no-default-config",
    "-static-libgcc",
    "-shared-libgcc",
    "-static-libstdc++",
    "-static-libasan",
    "-static-libtsan",
    "-static-liblsan",
    "-static-libubsan",
    "-static-libhwasan",
    "-static-libsan",
    "-shared-libsan",
    "-static-openmp",
    "-fsjlj-exceptions",
    "-fdwarf-exceptions",
    "-fseh-exceptions",
    "-fwasm-exceptions",
];

/// The tokens a word of a runtime selection takes; `None` for a word that selects nothing.
fn runtime_word(flag: &str) -> Option<Takes> {
    // gcc's `--prefix` and its abbreviations (`--pref` and longer: `--pref <dir>/
    // -print-prog-name=ld` named the `ld` in `<dir>`, as `-B` does, measured 2026-10-28 UTC
    // on Fedora 44 x86_64 with gcc 16.1.1; `--pre` and the joined `--pref=<dir>` are refused
    // as naming no option, and clang 22.1.8 refuses the abbreviation) reach here as `-B`
    // ([`LONG_ALIASES`]), so every reader of the list reads them as the whole spelling.
    if RUNTIME_TWO_TOKEN.contains(&flag) {
        Some(Takes::Two)
    } else if RUNTIME_WHOLE.contains(&flag) || RUNTIME_JOINED.iter().any(|p| flag.starts_with(p)) {
        Some(Takes::One)
    } else {
        None
    }
}

/// The directory and include options of the header selection
/// ([`header_selecting_flags`]), each read joined or as two tokens.
pub(crate) const HEADER_VALUED: [&str; 6] = [
    "-I",
    "-isystem",
    "-idirafter",
    "-iquote",
    "-include",
    "-imacros",
];

/// The spellings of the header selection that are the whole selection.
pub(crate) const HEADER_WHOLE: [&str; 2] = ["-undef", "-pthread"];

/// The words of [`HEADER_VALUED`] that select a search directory rather than a file: under
/// one of these a header the probe includes can be shadowed, which is what
/// `measure::twinless_unread_input` holds the twinless macro checks to.
pub(crate) const HEADER_DIRECTORY: [&str; 4] = ["-I", "-isystem", "-idirafter", "-iquote"];

/// Whether `word`, a word [`header_selecting_flags`] selected, is a directory word of
/// [`HEADER_DIRECTORY`], joined (`-I/x`, `-isystem=dir`) or the option alone ahead of its
/// value (`-isystem`), read as gcc reads it (`--include-directory` and
/// `--include-directory=/x` are `-I`, `--include-directory-after` is `-idirafter`;
/// [`LONG_ALIASES`]), and not a longer option ([`HEADER_LONGER`]) or a hand-on word.
#[must_use]
pub(crate) fn selects_header_directory(word: &str) -> bool {
    let word = spelled_alone(word);
    !HEADER_LONGER.iter().any(|l| word.starts_with(l))
        && HEADER_DIRECTORY.iter().any(|d| word.starts_with(d))
}

/// Longer options that begin with one of [`HEADER_VALUED`] and are not it: clang's, which
/// take their value as the next token where they stand alone, and which gcc reads as the
/// shorter option joined to the rest. Spelled alone each is [`Owner::Nobody`]'s and passes
/// over itself, so the next word is read by its own reader, as gcc reads it (the variant has
/// the measurement and clang's side).
pub(crate) const HEADER_LONGER: [&str; 2] = ["-isystem-after", "-include-pch"];

/// The pairs of `flags` the two drivers read differently, each as its two words joined by
/// a space, as written and in order: one of [`HEADER_LONGER`] spelled alone, or a word of
/// [`DIVIDED_TWO_TOKEN`] or an abbreviation [`DIVIDED_ABBREVIATED`] bounds, followed by a
/// word a selection reader takes ([`selection_word`]). One driver reads the pair as the
/// option and its value; the other reads the first word as a flag of its own, or as a
/// shorter option joined to the rest, and the second as a flag of its own (measured
/// 2026-10-28 UTC on Fedora 44 x86_64: gcc 16.1.1's `-dM -E` dump under `-isystem-after
/// -m32` defines `__i386__`, and clang 22.1.8 warns the pair unused and keeps x86_64; under
/// `-Tbss -m32` gcc takes the address and keeps x86_64, and clang's `-cc1` line names an
/// i386 triple beside a script named `bss`; [`takes_a_value`] has the sweep). The control
/// arms can be built to match one reading and not the other, so `measure` refuses the pair
/// before any build. A spelling of [`HEADER_LONGER`] with the value joined
/// (`-isystem-after<dir>`) is one word to both drivers and selects nothing, and gcc reads it
/// as `-isystem` joined to a relative path, which `compile::relative_path_readings` refuses,
/// so the refusal asks for a directory named with `-idirafter`, which both drivers read, or
/// the option left out, and for the whole spelling where an abbreviation divides. A word
/// handed to another tool, or taken as the value of an option
/// that selects nothing, is passed over with the word that takes it, as the selection walk
/// passes it; a divided word before such a word is a divided pair too, since one driver
/// reads that word as the value and the other hands the word after it on or takes it (the
/// loop says what was measured); a pair whose second word selects nothing and takes nothing
/// is left to the walk, which reads the same selections under either driver's reading of it.
#[must_use]
pub fn driver_divided_pairs(flags: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(flag) = flags.get(i) {
        let one = i.saturating_add(1);
        let two = i.saturating_add(2);
        let reading = read(flag, flags.get(one).map(String::as_str));
        match reading.hand {
            Hand::Tool | Hand::Preprocessor | Hand::Arch | Hand::Value => {
                i = two;
                continue;
            }
            Hand::Driver => {}
        }
        // A selection's own words are passed over as the walk reads them, its value among
        // them: `-L -isystem-after -m32` is a library directory and then `-m32` to both
        // drivers, as `-u -Tbss -m32` is a symbol and then `-m32`.
        let Some((owner, takes)) = selection_word_of(&reading.word) else {
            i = i.saturating_add(reading.span());
            continue;
        };
        // Divided where the next word is a selection, or takes a word of its own (a hand-on,
        // a value-taking option, an alias that joins the next word): under one driver it is
        // the pair's value and the word after it the driver's own, under the other it takes
        // that word, and the two readings stay out of step until a word that takes none
        // (measured 2026-10-28 UTC on Fedora 44 x86_64: under `-Tbss -u -B<dir>/` gcc
        // 16.1.1's `-###` searches `<dir>` and clang 22.1.8's shows `-T bss` and `-u
        // -B<dir>/`). A selection word after the pair's words is then read by one driver and
        // not the other, so the pair is refused whatever follows, which costs an edit where
        // nothing selecting follows.
        if owner == Owner::Nobody
            && let Some(next) = flags.get(one)
            && (selection_word(next).is_some_and(|(of, _)| of != Owner::Nobody)
                || takes_a_word(next))
        {
            found.push(format!("{flag} {next}"));
            i = two;
            continue;
        }
        // The larger of what the selection takes and what the reading covers: they differ
        // only for a two-token spelling with no value after it, which selects nothing.
        i = i.saturating_add(takes.len().max(reading.span()));
    }
    found
}

/// The flags of `flags` that choose the headers and predefined macros a compile reads within
/// its target and runtime, as written and in order: the header search directories `-I`,
/// `-isystem`, `-idirafter` and `-iquote`, the forced includes `-include` and `-imacros`,
/// each joined and as two tokens, `-undef`, and `-pthread`.
///
/// gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64 (measured 2026-10-28 UTC with `-###`,
/// `-no-integrated-cpp -c` over an empty C input) hand each directory and include word to
/// the compile proper as written, a value beginning `=` (a directory under the system root,
/// `-I=dir`, `-isystem =dir`) kept as it was spelled, and `-undef` as itself; `-pthread` gcc
/// answers with `-D_REENTRANT` on both `cc1` commands and clang with `-pthread` on `-cc1`,
/// and the `-dM -E` dump of each defines `_REENTRANT` under it. Under `-undef` the dump of
/// each loses `__GNUC__`, `__OPTIMIZE__`, `__PIE__`, `__SSP_STRONG__` and the architecture
/// macros and keeps the profile's own `-D`.
///
/// Like the target and the runtime, a header the profile selects hardens nothing by itself,
/// and an arm that leaves it out validates a detector on a compile the measured build did not
/// make: the arms' listing ([`crate::compile_inputs`]) then differs from the measured one on
/// those words and `compile-inputs-unmatched-by-arms` withholds every check the compile's
/// inputs decide, which is what a profile's `-I` or `-pthread` does without this selection
/// (measured on that host, `--profile explicit --flags "-O2 -I/usr/include -pthread
/// -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE" --ldflags "-pie -pthread"`: 17 of
/// 72 checks withheld under gcc 16.1.1 and clang 22.1.8 alike without the selection, and
/// published with it). Carried, the three builds read the same headers and the
/// comparison matches on them. What a carried header
/// does, it does to every arm alike: a `features.h` under the profile's `-isystem` that
/// declines fortification silences the positive fortify arms as it silences the measured
/// build, and a `-include` that undefines `_FORTIFY_SOURCE` likewise, so the triple reads
/// `probe-invalid` and never `off`; `tests/fake_driver.rs` holds both shapes.
///
/// gcc's long spellings of these words, and the abbreviations gcc takes for them, are read
/// as the short word by every reader ([`LONG_ALIASES`], measured the same way on both
/// drivers): `--include f`, `--include=f`, `--imacros f`, `--im f`, `--include-directory d`
/// and `--include-directory-after d` are carried as `-include`, `-imacros`, `-I` and
/// `-idirafter` are, as the pair where the value is the next word.
///
/// Spellings outside this list are not taken, and a profile carrying one still withholds
/// by the listing comparison: the other directory words (`-iprefix`, `-iwithprefix`,
/// `-iwithprefixbefore`, `-iwithsysroot`, `-imultilib`, `-iframework`, `-F`, and gcc's long
/// spellings of them, `--include-prefix`, `--include-with-prefix`, which are read as those
/// words), clang's
/// `-isystem-after` and `-include-pch` (which gcc reads as `-isystem` and `-include` joined
/// to a value beginning `-`, and the next word as its own, which is how the walk reads the
/// line: [`Owner::Nobody`] has the measurement and clang's side), a word handed to the
/// preprocessor (`-Wp,-I/x`,
/// `-Xpreprocessor -I`, which `cc1` and `-cc1` read as the driver would, measured the same
/// way, and which the reader passes over as the runtime reader does), and `-fopenmp`, whose
/// `-D_REENTRANT` gcc adds beside a library and a code-generation change. A two-token
/// spelling at the end of the list, with no value to take, is left out, as the driver
/// refuses it.
///
/// A header whose effect turns on a macro only the profile defines (`-DNDEBUG -include h`, where
/// `h` undefines `_FORTIFY_SOURCE` under `NDEBUG`) acts on the measured build and not on the arms,
/// which carry the header and not the profile's macro words, as a system header keyed on a profile
/// macro has always acted; the triple discriminates and the reading is of the build the profile
/// makes (`fortify-requested`, `fortify-printf-flag` and `fortify-enforced-known` `off` under that
/// profile on gcc 16.1.1, over arms that discriminate, where a walk without this selection
/// withholds them, and `fortify-effective`, which has no twin, withheld by the spoof clause's
/// unread-input case below; `tests/fake_driver.rs` holds the shape); a macro a flag the arms do not
/// carry implies keys a header the same way (`-O2 -fPIE -D_FORTIFY_SOURCE=3 -include h`, `h`
/// undefining `_FORTIFY_SOURCE` under `__PIE__`, with `-pie`: the same readings, gcc 16.1.1). Where
/// such a header defines or undefines a macro the compiler reserves for its own account of its code
/// generation, the reading is forged, and this reader does not hold it: the verdict layer does, for
/// a check with an artifact twin (`macro-contradicted-by-artifact`,
/// [`crate::report::MACRO_TWINS`]), where a check reading the same protection from the artifact
/// reads the opposite presence (`-O2 -fcf-protection=none -DGATE -include h`, `h` defining `__CET__
/// 3` under `GATE`, on gcc 16.1.1: `cet-macro` `indeterminate` under the rule beside `cet-marked`,
/// `cet-marked-object` and `cet-endbr-emitted` `off`; `tests/fake_driver.rs` holds the shape
/// through the profile's own list), and the spoof clause does for the two checks with none
/// (`optimization-enabled`, `fortify-effective`): a forced include or macro file in the list is an
/// input `macro-supplied-by-profile` cannot read by name, and a search directory one under which a
/// header the probe includes can be shadowed, so those two are withheld under it wherever the list
/// carries either (`measure::twinless_unread_input` has the measurement of the same header keyed on
/// `__OPTIMIZE__`, forced in and as a shadow).
///
/// A word handed to another tool is passed over with the word that hands it, and a one-word
/// selection after clang's `-Xarch_<arch>` is carried as the pair ([`Hand`] has the
/// measurements; clang 22.1.8 applied `-Xarch_x86_64 -I/x` as the driver's `-I`). A word
/// another reader takes, as its option or as the value of its two-token one, is passed over
/// as well: the readers are projections of one walk ([`selections`]), which gives each word
/// one owner.
#[must_use]
pub fn header_selecting_flags(flags: &[String]) -> Vec<String> {
    owned_by(flags, Owner::Header)
}

/// One word of a header selection: its owner and the tokens it takes, two for a directory
/// or include option alone and one for it joined or for `-undef` and `-pthread`; a longer
/// option that begins with one of them ([`HEADER_LONGER`]), spelled alone, is
/// [`Owner::Nobody`]'s and takes no value (gcc's reading; the variant says why), joined it
/// selects nothing, and `None` for a word that selects nothing.
fn header_word(flag: &str) -> Option<(Owner, Takes)> {
    if HEADER_LONGER.contains(&flag) {
        Some((Owner::Nobody, Takes::One))
    } else if HEADER_LONGER.iter().any(|l| flag.starts_with(l)) {
        None
    } else if HEADER_VALUED.contains(&flag) {
        Some((Owner::Header, Takes::Two))
    } else if HEADER_WHOLE.contains(&flag) || HEADER_VALUED.iter().any(|p| flag.starts_with(p)) {
        Some((Owner::Header, Takes::One))
    } else {
        None
    }
}

/// The flags of `flags` that remove part of the runtime rather than choose it, as written
/// and in order: the startup objects (`-nostartfiles`), the default libraries (`-nostdlib`
/// and gcc's alias `--no-standard-libraries`, `-nodefaultlibs`, `-nolibc`, clang's
/// `-nostdlib++`), and the default header directories (`-nostdinc` and gcc's alias
/// `--no-standard-includes`, `-nostdinc++`, clang's `-nostdlibinc` and `-nobuiltininc`).
/// Each is accepted by gcc 16.1.1 or clang 22.1.8 on Fedora 44 x86_64, or both (clang
/// takes gcc's two aliases as well); `measure` refuses a profile carrying one, as
/// `CONFIGURATION`.
///
/// A removal is half of a choice whose other half the profile names elsewhere: an object
/// or a script handed to the link, `-isystem`, `-I`, `-l`. Carried to the arms alone, it
/// builds them against no startup object, library or header at all; left off, the arms
/// validate a detector on objects the measured build does not contain. Measured on
/// 2026-10-06 on Fedora 44 x86_64 with gcc 16.1.1 under `--profile explicit` with
/// `-O2 -nostartfiles -fcf-protection=full`: every measured link warned that it could not
/// find `_start`, 15 of 72 checks moved against the same profile without the removal
/// (the runtime checks to `indeterminate` and `probe-invalid`), and `cet-marked` read
/// `on` from artifacts holding no startup object, a reading the host's startup objects
/// had no part in. The replacement the operator's build supplies is not in the profile,
/// so neither carrying nor leaving out is sound, and the profile is refused instead.
/// Where the replacement is an installation, the selections
/// [`runtime_selecting_flags`] and [`target_selecting_flags`] carry name it whole.
///
/// A removal reaches the build by more spellings than its own, each found here as written
/// (measured on 2026-10-06 on Fedora 44 x86_64, gcc 16.1.1, clang 22.1.8, with `-v -E` for
/// the header search list and `-Wl,-t` for the link's inputs):
///
/// - gcc takes a unique prefix of a long option, so `--no-standard-i` and every longer
///   prefix of `--no-standard-includes` emptied the `<...>` search list as the whole alias
///   does, and `--no-standard-l` and longer left `crt1.o` and `libc.so` out of the link.
///   clang rejects the abbreviations.
/// - A word handed to the preprocessor, `-Wp,<list>` (comma separated, any position) or
///   `-Xpreprocessor <word>`, is read by gcc's `cc1` with the driver's own meaning:
///   `-nostdinc` and `--no-standard-includes` (and its prefixes) emptied the search list,
///   and `-nostdinc++` emptied the C++ part of it under `g++`. Those three are found. The
///   other two header removals are not: gcc's `cc1` rejects `-nostdlibinc` and
///   `-nobuiltininc` (the build fails), and clang's `cc1`, which receives the word through
///   either spelling, accepts `-nobuiltininc` and `-nostdinc++` and leaves the list the
///   driver built unchanged, and rejects the rest. `-Xclang <word>` is the same `cc1`
///   reading with the same results, and is not found either.
/// - clang's `-Xarch_<arch> <word>` applies `<word>` as a driver option when the target's
///   architecture is `<arch>`: `-Xarch_x86_64 -nostdinc` emptied the search list,
///   `-Xarch_x86_64 -nostartfiles` (and `-Xarch_host`) left the startup objects out, and
///   `-Xarch_i386 -nostartfiles`, unused at x86_64, left them out under
///   `--target=i386-redhat-linux`. Every removal after any `-Xarch_` is found, since the
///   architecture it applies to depends on a target the profile can change. gcc rejects
///   `-Xarch_`.
///
/// GNU ld's own `-nostdlib`, after `-Wl,`, `-Xlinker` or `--for-linker`, is not a removal:
/// it drops only ld's built-in search directories, and the drivers name every directory
/// they link from with `-L`, so the linked executable was byte-identical to the one without
/// it under both drivers with ld.bfd (the only linker installed there; lld, gold and mold
/// were not measured). Nor is a word after any other hand-on ([`Hand::Tool`]), nor the
/// value of an option that takes the next word and selects nothing (the symbol `-nostdlib`
/// after `-u`, [`Hand::Value`]), nor the value of a selection's own two-token spelling (the
/// directory named `-nostdinc` after `-L`, [`selection_word`] with [`Takes::Two`]): both
/// drivers read each as the value (measured 2026-10-28 UTC on Fedora 44 x86_64 under `-###`:
/// `-L -nostdinc` reaches the link line as `-L-nostdinc` and `cc1` sees no `-nostdinc`, and
/// `-L -u -nostdlib` is a directory, then the removal, whose link line has no `crt1.o`). So
/// this reader passes over a value as the selection walk does, and a removal after the
/// value is found as the driver's own.
#[must_use]
pub fn runtime_removing_flags(flags: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(word) = flags.get(i) {
        let next = flags.get(i.saturating_add(1));
        let reading = read(word, next.map(String::as_str));
        match reading.hand {
            // The next word is another tool's option (GNU ld's `-nostdlib` after `-Xlinker`),
            // or the value of an option that selects nothing (the symbol `-nostdlib` after
            // `-u`), not the driver's: the reading spans both.
            Hand::Tool | Hand::Value => {}
            Hand::Preprocessor | Hand::Arch => {
                let removes: fn(&str) -> bool = if reading.hand == Hand::Preprocessor {
                    preprocessor_removes_headers
                } else {
                    driver_removes
                };
                if let Some(next) = next
                    && removes(next)
                {
                    found.push(word.clone());
                    found.push(next.clone());
                }
            }
            // A selection's value (the directory `-nostdinc` after `-L`) is within the
            // reading's span, and a removal spelled long (`--no-standard-l`) is read as the
            // short word.
            Hand::Driver => {
                if driver_removes(&reading.word)
                    || word
                        .strip_prefix("-Wp,")
                        .is_some_and(|list| list.split(',').any(preprocessor_removes_headers))
                {
                    found.push(word.clone());
                }
            }
        }
        i = i.saturating_add(reading.span());
    }
    found
}

/// Whether the driver reads `word` as a removal: one of the eleven spellings
/// [`runtime_removing_flags`] names, or a prefix of one of gcc's two long aliases that gcc
/// takes for the whole (`--no-standard-i`, `--no-standard-l` and longer).
fn driver_removes(word: &str) -> bool {
    const REMOVALS: [&str; 9] = [
        "-nostartfiles",
        "-nostdlib",
        "-nodefaultlibs",
        "-nolibc",
        "-nostdlib++",
        "-nostdinc",
        "-nostdinc++",
        "-nostdlibinc",
        "-nobuiltininc",
    ];
    // gcc's `--no-standard-libraries` and `--no-standard-includes`, and their abbreviations
    // from `--no-standard-l` and `--no-standard-i`, reach here as `-nostdlib` and `-nostdinc`
    // ([`LONG_ALIASES`]).
    REMOVALS.contains(&&*spelled_alone(word))
}

/// Whether gcc's `cc1` reads `word`, handed to it by `-Wp,` or `-Xpreprocessor`, as a
/// removal of default header directories ([`runtime_removing_flags`] has the measurement).
fn preprocessor_removes_headers(word: &str) -> bool {
    let word = spelled_alone(word);
    word == "-nostdinc" || word == "-nostdinc++"
}

/// Whether `word` is `alias` or a prefix of it at least as long as `shortest`, the shortest
/// prefix gcc 16.1.1 accepted for it.
fn abbreviates(word: &str, alias: &str, shortest: &str) -> bool {
    word.len() >= shortest.len() && alias.starts_with(word)
}

/// The driver's words that select x32 or 16-bit code, which gcc's `cc1` reads the same way
/// when they are relayed to it (`-mabi=ilp32` is not one: `cc1` generates no code from it
/// there).
const CC1_WORDS: [&str; 2] = ["-mx32", "-m16"];

/// Mark in `taken` the words of `flags` that select x32 or 16-bit code as gcc's `cc1` reads
/// them. gcc hands `cc1` every `-Xpreprocessor` value and every `-Wp,` item in order
/// (measured with another relayed word between them), and `cc1` reads gcc's long spellings across
/// that stream as the driver reads them: `-Xpreprocessor --machine -Xpreprocessor x32`,
/// `-Wp,--machine -Wp,x32` and `-Wp,--machine -Xpreprocessor x32` each define `__ILP32__`
/// as `-Wp,--machine,x32` and `-Wp,-mx32` do (measured 2026-10-28 UTC on Fedora 44 x86_64
/// with gcc 16.1.1 by `-dM -E`). So the stream is read with [`read`], an item with the next
/// item, and a selection found there is refused with the words that carried it: the handed
/// word alone after `-Xpreprocessor`, as the lone `-Xpreprocessor -mx32` is found, and the
/// whole `-Wp,` word. Item by item, not by the span: a selection standing as another
/// relayed word's value (`-Wp,-MF,-mx32`) is found as well, the cost
/// [`unsupported_target_flags`]'s doc names.
fn mark_cc1_relayed_selections(flags: &[String], taken: &mut [bool]) {
    let mut stream: Vec<(&str, std::ops::Range<usize>)> = Vec::new();
    for (k, word) in flags.iter().enumerate() {
        if word == "-Xpreprocessor" {
            if let Some(handed) = flags.get(k.saturating_add(1)) {
                stream.push((handed, k.saturating_add(1)..k.saturating_add(2)));
            }
        } else if let Some(list) = word.strip_prefix("-Wp,") {
            stream.extend(list.split(',').map(|item| (item, k..k.saturating_add(1))));
        }
    }
    let mut mark = |range: &std::ops::Range<usize>| {
        for k in range.clone() {
            if let Some(word) = taken.get_mut(k) {
                *word = true;
            }
        }
    };
    let mut k = 0;
    while let Some((item, range)) = stream.get(k) {
        let next = stream.get(k.saturating_add(1));
        let reading = read(item, next.map(|(handed, _)| *handed));
        if CC1_WORDS.contains(&&*reading.word) {
            mark(range);
            if reading.span() == 2
                && let Some((_, next_range)) = next
            {
                mark(next_range);
            }
        }
        k = k.saturating_add(1);
    }
}

/// The flags of `flags` that select x32, 16-bit or aarch64 ILP32 code, as written and in
/// order; `measure` refuses a profile carrying one, as `CONFIGURATION`, because chard does
/// not measure those targets (decided 2026-10-07). x32 and 16-bit were measured on
/// 2026-10-07 and 2026-10-08 on Fedora 44 x86_64 with gcc 16.1.1, clang 22.1.8 and GNU as
/// 2.46.1, by the class and machine of the object `-c` wrote:
///
/// - `-mx32` (`ELFCLASS32` `EM_X86_64`) and `-m16` (`ELFCLASS32` `EM_386`, 16-bit code)
///   under both drivers. Handed to gcc's `cc1` by `-Wp,<list>` or `-Xpreprocessor`, either
///   reaches code generation (the dump under `-Wp,-mx32` defined `__ILP32__` and the
///   assembly differed from the plain build's) while the driver still assembles for x86_64,
///   so the object is an `ELFCLASS64` `EM_X86_64` one holding x32 code, which no class
///   check would withhold; clang rejects both words there.
/// - clang's target triple with an x32 or 16-bit environment, `gnux32`, `muslx32` or
///   `code16`, after `--target=` or the two-token `-target` (`x86_64-linux-gnux32`,
///   `x86_64-pc-linux-gnux32`, `x86_64-gnux32`, `i386-pc-linux-code16`), and the same
///   triple handed to clang's `cc1` as its `-triple <triple>` or `-triple=<triple>` through
///   `-Xclang` or its joined `-Xclang=`, which won over a later `-m64`. clang hands `cc1`
///   every `-Xclang` value in order as one list, whatever other options stand between them,
///   and an option that takes an `-Xclang` as its own value (`-Xlinker -Xclang`, `-MT
///   -Xclang`) shifts which words pair without changing the order: `-Xclang -triple -O2
///   -Xclang <triple>`, `-Xclang=-triple -Xclang <triple>` and `-Xlinker -Xclang -Xclang
///   -triple -Xclang <triple>` built x32, where `-Xclang -aux-triple -Xclang <triple>` built
///   x86_64. So a `-triple` word (bare or joined to `-Xclang=`) anywhere before a word
///   naming such a triple (bare or joined) is found with it, whatever each is paired with,
///   and the `-Xclang` before either is named as its carrier; the cost is the refusal of a
///   profile where a bare `-triple` word stands before any later word with an x32 or
///   `code16` component, whatever option took either. clang normalises a triple before
///   reading it, so the environment selects from
///   any component (`gnux32-x86_64` and `x86_64-gnux32-linux` built x32), and a version
///   after it selects too (`gnux321`, `code161`). gcc rejects all of them, and clang
///   rejects the two-token `--target`.
/// - GNU as's `--x32`, handed to it by gcc's `-Wa,<list>`, `-Xassembler`, the two-token
///   `--for-assembler` in any abbreviation gcc takes (`--for-a` and longer) or the joined
///   `--for-assembler=` (whose abbreviations, `--for-a=` and the rest, gcc rejects), under
///   which as wrote an `ELFCLASS32` `EM_X86_64` object from 64-bit code, a later `-m64`
///   included. as takes a long option with one dash or two and by any unambiguous prefix,
///   and `-x`, `--x`, `-x3`, `--x3`, `-x32` and `--x32` each selected x32; `---x32`,
///   `--X32`, `--x32x` and `--x32=1` were rejected. clang's integrated assembler rejected
///   every one of them, and clang under `-fno-integrated-as` handed them to as, which
///   built x32.
///
/// aarch64 ILP32 was measured on 2026-10-13 on Fedora 44 x86_64 with the cross
/// `aarch64-linux-gnu-gcc` 16.1.1, clang 22.1.8 and the cross GNU as 2.46, the same way
/// (an ILP32 object is `ELFCLASS32` `EM_AARCH64`, or a Mach-O `64_32` one):
///
/// - gcc's `-mabi=ilp32`, which gcc 16 calls deprecated and still honours, and only that
///   spelling: `-mabi=ilp`, `-mabi=ILP32`, `-mabi ilp32`, `--mabi=ilp32`, `-mab=ilp32` and
///   `-milp32` were rejected. Handed to `cc1` by `-Wp,` or `-Xpreprocessor` it does not reach
///   code generation (the assembly was byte for byte the plain build's, and `__ILP32__`
///   undefined), so a `-Wp,` list is not read for it, unlike `-mx32`'s; the word after
///   `-Xpreprocessor` is still found, as every driver word is wherever it stands, which
///   refuses that inert profile too, and so is the word after `-Xlinker` or `-Xclang`
///   (both built LP64). clang rejected it ("unknown target ABI"), as it did `-Xclang
///   -target-abi -Xclang ilp32`.
/// - The same word handed to GNU as by `-Wa,<list>`, `-Xassembler`, the two-token
///   `--for-assembler` in any abbreviation gcc takes, or the joined `--for-assembler=`
///   (and by clang under `-fno-integrated-as`): as wrote an `ELFCLASS32` object, a later
///   `-mabi=lp64` to the driver included. as took no other spelling (`--mabi=ilp32`,
///   `-mabi=ilp`, `-mab=ilp32`, `-mabi=ILP32`, `-mabi,ilp32` were rejected).
/// - clang's triple with a `gnu_ilp32` environment in any component, matched by prefix and
///   case as the x32 environments are (`aarch64-linux-gnu_ilp32`, `gnu_ilp32-aarch64`,
///   `aarch64_be-linux-gnu_ilp32`, and `gnu_ilp321` as a version; `gnuilp32` and
///   `GNU_ILP32` were rejected and are not refused, and `gnu_ilp32x`, which clang also
///   rejected, is refused by the prefix), and a triple whose architecture is `arm64_32` or
///   `aarch64_32` in any component, matched whole as clang matches an architecture
///   (`arm64_32-apple-watchos` and `watchos-arm64_32` built Mach-O `64_32`; `arm64_32x` and
///   the Linux spellings of it were rejected). Each reaches the same carriers as an x32
///   triple: `--target=`, `-target`, and `cc1`'s `-triple` through `-Xclang`.
/// - Darwin's two-token `-arch arm64_32` (and `-arch aarch64_32`, which clang rejected),
///   which built `64_32` for an Apple target and was rejected for any other.
///
/// Those refused though inert or rejected (`-Xpreprocessor`, `-Xlinker` and `-Xclang`
/// `-mabi=ilp32`, `-mabi=ilp32` before `-mabi=lp64`, `gnu_ilp32x`, `-arch aarch64_32`) are a
/// cost taken, not a gap: each ends in `CONFIGURATION` before any build, never in a verdict.
///
/// Each is found wherever it stands, which refuses some profiles that build neither
/// target: a later `-m64` or `-m32` won over `-mx32`, `-m16` and an x32 `--target=`, and
/// `-Xarch_x86_64 -mx32`, `-Xarch_x86_64 -m16`, `i386-linux-gnux32` (i386) and
/// `x86_64-linux-code16` (x86_64) built the other target, and a word another option or tool
/// takes as its argument is found as well (`-Wa,-I,--x32`, where as reads `--x32` as `-I`'s
/// directory, and `-Xlinker -m16` built x86_64). A refusal costs the operator an edit, where
/// a missed selection measures a target chard does not read. A triple's environment is
/// matched by prefix and case, as clang matched it (`gnux32abc` and `GNUX32` were refused
/// by clang as versions). An x32 or 16-bit target a toolchain selects by default, or by a
/// `--config=` or `-specs=` file, is not a profile flag and is not found here; a run over
/// the `ELFCLASS32` `EM_X86_64` artifact it builds is withheld by
/// `measure::settle_emulation`, which holds an artifact's class to the kernel's width, and
/// by the target witness (`TargetArch::abi`), which holds every artifact of the read family
/// and every agreeing dump to the width the architecture's rows stand for. A spec file
/// handing `cc1` `-mx32` builds an `ELFCLASS64` artifact holding x32 code, which no class
/// check withholds, and its dump names `__SIZEOF_POINTER__` 4, which the abi witness
/// withholds on wherever the spec reaches the dump (measured 2026-10-14 with gcc 16.1.1: a
/// `*cc1: + -mx32` spec dumps 4 and writes an ELF64 object); a spec that reaches `cc1` and
/// not the dump would still pass, which the ledger's control-arms entry carries with the
/// rest of `-specs=` and `--config=`.
/// An aarch64 ILP32 target a toolchain selects by default, or by a config or spec file, is
/// not found here either: a run over the `ELFCLASS32` `EM_AARCH64` artifact it builds is
/// withheld the same way, and the abi witness withholds every arch-gated check over it.
/// Only the artifact witnesses that target: clang's ILP32 dump names `__SIZEOF_POINTER__`
/// 8, so a run that builds no ELF artifact reads `agrees`, an open case the ledger carries.
#[must_use]
pub fn unsupported_target_flags(flags: &[String]) -> Vec<String> {
    /// Whether `triple` names an x32, 16-bit or ILP32 environment, or an ILP32
    /// architecture, in any component.
    fn unsupported(triple: &str) -> bool {
        triple.split('-').any(|component| {
            ["gnux32", "muslx32", "code16", "gnu_ilp32"]
                .iter()
                .any(|env| component.starts_with(env))
                || ILP32_ARCHES.contains(&component)
        })
    }
    /// The architecture names that select aarch64 ILP32, matched whole.
    const ILP32_ARCHES: [&str; 2] = ["arm64_32", "aarch64_32"];
    /// The one spelling gcc and GNU as take for aarch64 ILP32.
    const ILP32_ABI: &str = "-mabi=ilp32";
    /// Whether `argument`, a word gcc hands GNU as, selects a target chard does not
    /// measure: as's `--x32` in a spelling as took, or its `-mabi=ilp32`.
    fn assembler_selects(argument: &str) -> bool {
        x32_assembler(argument) || argument == ILP32_ABI
    }
    /// Whether `argument`, a word gcc hands GNU as, is as's `--x32` in a spelling as took:
    /// one dash or two, then a nonempty prefix of `x32`.
    fn x32_assembler(argument: &str) -> bool {
        argument
            .strip_prefix("--")
            .or_else(|| argument.strip_prefix('-'))
            .is_some_and(|name| !name.is_empty() && "x32".starts_with(name))
    }
    /// Whether `word` hands the next word to the assembler: `-Xassembler`, or gcc's
    /// two-token `--for-assembler` in any abbreviation gcc takes (`--for-a` and longer).
    fn hands_to_assembler(word: &str) -> bool {
        word == "-Xassembler" || abbreviates(word, "--for-assembler", "--for-a")
    }
    /// Whether `word` is clang's `cc1` option `-triple` as a profile word: bare (the value
    /// of an `-Xclang`, or of whatever else took it) or joined to `-Xclang=`.
    fn triple_option(word: &str) -> bool {
        word == "-triple" || word == "-Xclang=-triple"
    }
    /// Whether `word` names an x32, 16-bit or ILP32 triple as a profile word: bare or joined to
    /// `-Xclang=`.
    fn names_unsupported(word: &str) -> bool {
        unsupported(word.strip_prefix("-Xclang=").unwrap_or(word))
    }
    /// Mark `range` as found, so the words come out as written and in order whichever arm
    /// found them, each once.
    fn mark(taken: &mut [bool], range: std::ops::Range<usize>) {
        for k in range {
            if let Some(word) = taken.get_mut(k) {
                *word = true;
            }
        }
    }
    let mut taken = vec![false; flags.len()];
    let mut i = 0;
    while let Some(word) = flags.get(i) {
        let next = flags.get(i.saturating_add(1));
        // gcc's `--machine 16`, `--machine=x32` and `--machine-16` are `-m16` and `-mx32` to
        // it ([`LONG_ALIASES`]): the reading is the short word, spanning the pair.
        let reading = read(word, next.map(String::as_str));
        let w = &*reading.word;
        let take = if CC1_WORDS.contains(&w)
            || w == ILP32_ABI
            || w.strip_prefix("--target=").is_some_and(unsupported)
            || w.strip_prefix("-Wa,")
                .is_some_and(|list| list.split(',').any(assembler_selects))
            || w.strip_prefix("--for-assembler=")
                .is_some_and(assembler_selects)
            || w.strip_prefix("-Xclang=")
                .unwrap_or(w)
                .strip_prefix("-triple=")
                .is_some_and(unsupported)
        {
            reading.span()
        } else if (w == "-target" && next.is_some_and(|t| unsupported(t)))
            || (hands_to_assembler(w) && next.is_some_and(|a| assembler_selects(a)))
            || (w == "-arch" && next.is_some_and(|a| ILP32_ARCHES.contains(&a.as_str())))
            || (w == "-Xclang"
                && next
                    .and_then(|n| n.strip_prefix("-triple="))
                    .is_some_and(unsupported))
        {
            2
        } else {
            0
        };
        if take > 0 {
            mark(&mut taken, i..i.saturating_add(take));
            i = i.saturating_add(take);
        } else {
            i = i.saturating_add(1);
        }
    }
    mark_cc1_relayed_selections(flags, &mut taken);
    // clang's `cc1` option `-triple` with its value: clang hands `cc1` every `-Xclang` and
    // `-Xclang=` value in order, whatever other options stand between them, and an option
    // that takes an `-Xclang` as its own value shifts which words pair without changing the
    // order. So every `-triple` word before the last word naming such a triple, and every
    // naming word after the first `-triple` word, is found, with the `-Xclang` before each.
    if let Some(first) = flags.iter().position(|w| triple_option(w))
        && let Some(last) = flags
            .iter()
            .rposition(|w| names_unsupported(w))
            .filter(|&q| q > first)
    {
        for (k, word) in flags.iter().enumerate() {
            if (k < last && triple_option(word)) || (k > first && names_unsupported(word)) {
                mark(&mut taken, k..k.saturating_add(1));
                if let Some(carrier) = k.checked_sub(1)
                    && flags.get(carrier).is_some_and(|c| c == "-Xclang")
                {
                    mark(&mut taken, carrier..k);
                }
            }
        }
    }
    flags
        .iter()
        .zip(taken)
        .filter(|(_, found)| *found)
        .map(|(word, _)| word.clone())
        .collect()
}

/// The linker family a `--version` banner names, `unknown` for one chard does not recognise.
///
/// mold's banner reads `mold 2.4.0 (compatible with GNU ld)` and lld's `LLD 18.1.3
/// (compatible with GNU linkers)`, so the two are tested before bfd's `GNU ld`, whose
/// wording both quote.
///
/// Public so the `driver_text` fuzz target (`fuzz/fuzz_targets/driver_text.rs`) holds it
/// to its laws.
#[must_use]
pub fn linker_kind(banner: &str) -> &'static str {
    let lower = banner.to_lowercase();
    if lower.contains("gnu gold") {
        "gold"
    } else if lower.contains("lld") {
        "lld"
    } else if lower.contains("mold") {
        "mold"
    } else if lower.contains("gnu ld") {
        "bfd"
    } else {
        UNKNOWN_KIND
    }
}

/// The linker a `.comment` line names, with the version it quotes; `None` for every
/// other producer's line (`GCC:`, `clang version`, `rustc`, `Android`).
///
/// The grammar, and the claim that lld and mold always write it, were measured on
/// 2026-09-28 in the `docker.io/library/ubuntu:22.04` and `ubuntu:24.04` images and on
/// Fedora 44 aarch64: lld 14.0.0, 15.0.7, 18.1.3 and 22.1.8 write `Linker: <vendor> LLD
/// <version>` (the vendor word is `Ubuntu` there and absent on Fedora); mold 1.0.3, 2.30.0
/// and 2.40.4 write `mold <version> (compatible with GNU ld)` as the first line. Both
/// lines survive `-Wl,--strip-all` and `-s` and appear in shared objects. A relocatable
/// produced by `lld -r` carries no linker line, which is why relocatables are not counted.
/// GNU ld 2.42 and 2.46.1 and gold 1.16 write nothing of their own; gold adds a
/// `.note.gnu.gold` section, a possible future signal that is not read here.
///
/// lld's version is the token after `LLD`, which is the line's last token in every
/// measured form; mold's is the token after `mold`.
///
/// Public so the `driver_text` fuzz target (`fuzz/fuzz_targets/driver_text.rs`) holds it
/// to its laws.
#[must_use]
pub fn linker_line(line: &str) -> Option<(&'static str, &str)> {
    if let Some(rest) = line.strip_prefix("Linker: ")
        && let Some((_, after)) = rest.split_once("LLD ")
    {
        return after.split_whitespace().next().map(|v| ("lld", v));
    }
    line.strip_prefix("mold ")
        .and_then(|rest| rest.split_whitespace().next())
        .map(|v| ("mold", v))
}

/// Linkers that write a line of their own into every output, so their absence from a
/// linked artifact under a banner naming one is a disagreement. `report::ASSUMPTIONS`
/// carries this as `lld-and-mold-sign-every-output`.
const SELF_SIGNING: &[&str] = &["lld", "mold"];

/// Hold the banner-derived `kind` to the `.comment` of every linked artifact the run built.
///
/// `banner` is the first line of `--version`, compared by whitespace token against the
/// version the artifact's line quotes, because a shim that answers with the right kind and
/// the wrong version is exactly the substitution the check exists for. The rules, in order:
/// nothing counted is [`Agreement::NoLinkedArtifact`]; two counted artifacts whose linker
/// lines differ, or one signed beside one unsigned, disagree with each other and the banner
/// is beside the point; one line everywhere is [`Agreement::ArtifactOnly`] when no banner
/// chard read names a linker it recognises, agrees when it names the banner's kind and version
/// and disagrees otherwise; no line anywhere disagrees when the banner names a
/// self-signing linker and is [`Agreement::NoSignature`] when it names one that writes
/// nothing or none chard recognises. `evidence` names the artifacts each rule turned on,
/// the ones not counted and the probes that handed over none.
pub fn artifact_agreement(
    kind: &str,
    banner: Option<&str>,
    witnesses: &Witnesses,
) -> ArtifactAgreement {
    let artifacts = witnesses.artifacts.as_slice();
    let counted: Vec<&ArtifactComment> = artifacts
        .iter()
        .filter(|a| !a.relocatable && a.unread.is_none() && !a.profile_free)
        .collect();
    let artifacts_read = counted.len();
    let aside = not_counted(witnesses);
    let verdict =
        |agreement: Agreement, signature: Option<&str>, evidence: String| ArtifactAgreement {
            agreement,
            signature: signature.map(ToOwned::to_owned),
            artifacts_read,
            evidence: format!("{evidence}{aside}"),
        };

    let Some(first) = counted.first() else {
        let nothing = if artifacts.is_empty() {
            "no linked ELF artifact was read in this run".to_owned()
        } else {
            format!(
                "none of the {} artifact(s) read could be counted",
                artifacts.len()
            )
        };
        return verdict(Agreement::NoLinkedArtifact, None, nothing);
    };
    let first_line = signature_of(first);
    if let Some(other) = counted.iter().find(|a| signature_of(a) != first_line) {
        return verdict(
            Agreement::Disagrees,
            None,
            artifacts_disagree(first, other, artifacts_read.saturating_sub(2)),
        );
    }

    match first_line.and_then(|l| linker_line(l).map(|(k, v)| (l.as_str(), k, v))) {
        Some((line, _, _)) if kind == UNKNOWN_KIND => verdict(
            Agreement::ArtifactOnly,
            Some(line),
            format!(
                "no --version banner chard read names a linker it recognises, and all \
                 {artifacts_read} linked artifact(s) carry `{line}`; the artifact is the \
                 only witness, and its line stands as signature beside a kind of {kind}"
            ),
        ),
        Some((line, signed_kind, _)) if signed_kind != kind => verdict(
            Agreement::Disagrees,
            Some(line),
            format!(
                "all {artifacts_read} linked artifact(s) carry `{line}`, which names \
                 {signed_kind}, while the --version banner of the program chard resolved \
                 names {kind}; first {}",
                first.label
            ),
        ),
        Some((line, _, version)) => match banner {
            Some(b) if !b.split_whitespace().any(|t| t == version) => verdict(
                Agreement::Disagrees,
                Some(line),
                format!(
                    "all {artifacts_read} linked artifact(s) carry `{line}`, while the \
                     program chard resolved answers --version as `{b}`, another version \
                     of {kind}; first {}",
                    first.label
                ),
            ),
            _ => verdict(
                Agreement::Agrees,
                Some(line),
                format!(
                    "all {artifacts_read} linked artifact(s) carry `{line}`, which names \
                     the banner's kind and version; first {}",
                    first.label
                ),
            ),
        },
        None if SELF_SIGNING.contains(&kind) => verdict(
            Agreement::Disagrees,
            None,
            format!(
                "none of the {artifacts_read} linked artifact(s) carries a `Linker: LLD` \
                 or `mold` line while the banner names {kind}; lld and mold write one into \
                 every output they link (assumption lld-and-mold-sign-every-output), so \
                 the program that answered --version is not the one that linked {}",
                first.label
            ),
        ),
        None => verdict(
            Agreement::NoSignature,
            None,
            unsigned_evidence(kind, first, artifacts_read),
        ),
    }
}

/// Evidence for [`Agreement::NoSignature`]: what the banner's kind leaves unestablished,
/// and what the artifacts carried instead of a linker line.
fn unsigned_evidence(kind: &str, first: &ArtifactComment, artifacts_read: usize) -> String {
    let banner = if kind == UNKNOWN_KIND {
        "no --version banner chard read names a linker it recognises, so the lines have \
         nothing to be held to"
            .to_owned()
    } else {
        format!(
            "GNU ld and gold write no line of their own into .comment, so a {kind} banner \
             is uncontradicted here and cannot be corroborated"
        )
    };
    let carried = first.lines.first().map_or_else(
        || "no .comment line at all".to_owned(),
        |l| format!("compiler lines only (`{l}` in {})", first.label),
    );
    format!("{banner}; the {artifacts_read} linked artifact(s) carry {carried}")
}

/// The `kind` `detect_linker_on` publishes when no banner it read established one: the
/// program printed no banner, one outside the grammar, or failed `--version`, or no linker
/// path was read.
const UNKNOWN_KIND: &str = "unknown";

/// The line that names a linker, when the artifact carries one.
fn signature_of(artifact: &ArtifactComment) -> Option<&String> {
    artifact.lines.iter().find(|l| linker_line(l).is_some())
}

/// Evidence for two of the run's own artifacts naming different linkers, or one naming
/// one and the other none; `rest` is how many more were read.
///
/// The reason the verdict turned on is the one stated: two signed artifacts were linked
/// by two linkers, and a signed one beside an unsigned one rests on the assumption that
/// lld and mold sign every output.
fn artifacts_disagree(first: &ArtifactComment, other: &ArtifactComment, rest: usize) -> String {
    let quote = |a: &ArtifactComment| {
        signature_of(a).map_or_else(|| "no linker line".to_owned(), |l| format!("`{l}`"))
    };
    let why = if signature_of(first).is_none() || signature_of(other).is_none() {
        "lld and mold write a line into every output they link"
    } else {
        "two linkers linked this run's artifacts"
    };
    format!(
        "the run's own artifacts disagree: {} carries {} and {} carries {}; {why}, and \
         {rest} more linked artifact(s) were read",
        first.label,
        quote(first),
        other.label,
        quote(other)
    )
}

/// The artifacts `artifact_agreement` named and left out of the count, and the probes
/// that handed over none, as a clause for its evidence; empty when every artifact
/// counted and every probe contributed one.
///
/// Each artifact is named under one reason, the first that applies in the order the
/// count excludes them: relocatable, then unread, then linked without the selection the
/// profile's link line made, which is quoted from `Witnesses::selection`.
fn not_counted(witnesses: &Witnesses) -> String {
    use std::fmt::Write as _;
    let artifacts = witnesses.artifacts.as_slice();
    let mut aside = String::new();
    let relocatable: Vec<&str> = artifacts
        .iter()
        .filter(|a| a.relocatable)
        .map(|a| a.label.as_str())
        .collect();
    if !relocatable.is_empty() {
        crate::error::best_effort(write!(
            aside,
            "; {} relocatable artifact(s) left uncounted, since no linker produced them: {}",
            relocatable.len(),
            relocatable.join(", ")
        ));
    }
    let unread: Vec<String> = artifacts
        .iter()
        .filter(|a| !a.relocatable)
        .filter_map(|a| a.unread.as_ref().map(|why| format!("{} ({why})", a.label)))
        .collect();
    if !unread.is_empty() {
        crate::error::best_effort(write!(
            aside,
            "; {} artifact(s) left uncounted because .comment could not be read: {}",
            unread.len(),
            unread.join(", ")
        ));
    }
    let profile_free: Vec<&str> = artifacts
        .iter()
        .filter(|a| !a.relocatable && a.unread.is_none() && a.profile_free)
        .map(|a| a.label.as_str())
        .collect();
    if !profile_free.is_empty() {
        let selected = if witnesses.selection.is_empty() {
            "a linker".to_owned()
        } else {
            format!("`{}`", witnesses.selection.join(" "))
        };
        crate::error::best_effort(write!(
            aside,
            "; {} artifact(s) linked under the driver default while the profile selected \
             {selected}, left uncounted since the check reads the clean build: {}",
            profile_free.len(),
            profile_free.join(", ")
        ));
    }
    if !witnesses.without_facts.is_empty() {
        crate::error::best_effort(write!(
            aside,
            "; {} probe(s) contributed no readable artifact: {}",
            witnesses.without_facts.len(),
            witnesses.without_facts.join(", ")
        ));
    }
    aside
}

/// Where the architecture the arch gate read came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchSource {
    /// The first component of the driver's `-dumpmachine` answer, as
    /// [`Detected::target_arch`] normalizes it.
    Dumpmachine,
    /// `environment.kernel.arch`, because `-dumpmachine` gave no triple chard read.
    Kernel,
    /// The one architecture macro the intrinsic dump under the profile's C flags defined,
    /// because those flags select a target ([`selects_target`]), which the flagless
    /// `-dumpmachine` cannot see. [`gate_target`] says when.
    ProfileMacros,
}

impl ArchSource {
    /// Every value, for the schema test that pins the published vocabulary to this one.
    pub const ALL: &[Self] = &[Self::Dumpmachine, Self::Kernel, Self::ProfileMacros];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dumpmachine => "dumpmachine",
            Self::Kernel => "kernel",
            Self::ProfileMacros => "profile-macros",
        }
    }
}

/// The architecture the arch gate reads, and where it was read from.
///
/// Where the profile's C flags select a target ([`selects_target`]) and the intrinsic dump
/// taken under them ([`Detected::profile_macros`]) completed, its output whole, and defined
/// exactly one of [`ARCH_MACROS`], the gate reads that macro's architecture, as
/// [`ArchSource::ProfileMacros`]. Everywhere else it reads the flagless `-dumpmachine`
/// ([`arch_of_triple`]), or `kernel_arch` where that gave no triple chard read.
///
/// `-dumpmachine` is asked with no profile flags, so under `--target=aarch64-linux-gnu` on an
/// x86_64 driver it names x86_64 while every probe is built for aarch64; gcc 16.1.1 prints its
/// own triple under every target flag, and clang 22.1.8 names the selected one only when asked
/// under it (the project ledger, the 2026-10-01 target-flags note). The dump under the profile's
/// flags is the witness both drivers answer, and it is taken under the same list a C probe's
/// measured variant is built with, so it names the target those builds were posed under. The
/// premise is then held to the artifacts by [`target_agreement`], as the `-dumpmachine` one is:
/// an artifact of another family withholds every gate it decides otherwise. A selection the
/// dump does not resolve (it failed, defined none of the three, or more than one) leaves the
/// flagless reading in place, which that dump and the artifacts then contradict, so every gate
/// they decide otherwise is withheld rather than re-gated. A target only the C++ flags select
/// does not move the gate: the C probes, and the clean builds, were not built for it, and
/// [`TargetArch::with_cxx_dump`] withholds the C++ probes' gates it decides otherwise.
///
/// The one reading, for the gate (`main`), the profile resolution that picks flags by
/// architecture, the composites, and the consistency rule that re-derives it from a
/// published report. The premise rests on `profile-dump-names-the-selected-target` in
/// `report::ASSUMPTIONS`.
#[must_use]
pub fn gate_target(
    target_triple: Option<&str>,
    profile: Option<&ProfileDump>,
    kernel_arch: &str,
) -> (String, ArchSource) {
    if let Some(arch) = profile.and_then(selected_arch) {
        return (arch.to_owned(), ArchSource::ProfileMacros);
    }
    target_triple.and_then(arch_of_triple).map_or_else(
        || (kernel_arch.to_owned(), ArchSource::Kernel),
        |arch| (arch, ArchSource::Dumpmachine),
    )
}

/// The gate vocabulary's architecture `dump` names, where its flags select a target and it
/// completed with exactly one of [`ARCH_MACROS`] defined.
fn selected_arch(dump: &ProfileDump) -> Option<&'static str> {
    if !selects_target(&dump.flags) || !dump.completed() {
        return None;
    }
    let mut named = ARCH_MACROS
        .iter()
        .filter(|(name, _)| dump.defined.iter().any(|d| d == name));
    match (named.next(), named.next()) {
        (Some((_, machine)), None) => Some(gate_arch_of_machine(machine)),
        _ => None,
    }
}

/// The first components of a `-dumpmachine` triple [`arch_of_triple`] normalizes, each with
/// the gate-vocabulary architecture it names; the identity rows are here so the table lists
/// every named value. Every value that function returns is a second element here or a first
/// component no row names, returned as written (`arch_of_triple_reads_the_table` holds it), so
/// a test that iterates these values and one passthrough has iterated every case it decides
/// (the `openssf-tldr` profile's, in `guide`, `report` and `main`). The fixture miner's own
/// mapping (`fixture::arch_of_triple`) is a different vocabulary, the ELF reader's machine
/// names, and is kept apart on purpose.
pub const TRIPLE_ARCHS: &[(&str, &str)] = &[
    ("x86_64", "x86_64"),
    ("amd64", "x86_64"),
    ("aarch64", "aarch64"),
    ("arm64", "aarch64"),
    ("i386", "x86"),
    ("i486", "x86"),
    ("i586", "x86"),
    ("i686", "x86"),
];

/// The first component of a `-dumpmachine` triple, normalized to the vocabulary
/// `std::env::consts::ARCH` and every `Gate.arch` entry use (`"x86_64"`, `"x86"`,
/// `"aarch64"`) by [`TRIPLE_ARCHS`]; any other first component is returned as written.
#[must_use]
pub fn arch_of_triple(triple: &str) -> Option<String> {
    let first = triple.split('-').next()?;
    let normalized = TRIPLE_ARCHS
        .iter()
        .find(|(component, _)| *component == first)
        .map_or(first, |(_, arch)| arch);
    Some(normalized.to_owned())
}

/// What the run's ELF artifacts made of the architecture the arch gate read.
///
/// Four values because four things can be true. `Unmapped` keeps an architecture chard
/// names no `e_machine` family for apart from one the artifacts contradict, and
/// `NoElfArtifact` keeps a run with nothing to read (a Mach-O host, a selection that
/// builds nothing) apart from a corroboration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchAgreement {
    /// Every ELF artifact read carries the `e_machine` family of the gate's architecture.
    Agrees,
    /// An artifact carries another family, or the run's own artifacts carry more than
    /// one.
    Disagrees,
    /// The gate's architecture names no family [`machine_family`] maps, and the artifacts
    /// carry one machine: nothing to hold the two to each other.
    Unmapped,
    /// No ELF artifact was read in this run.
    NoElfArtifact,
}

impl ArchAgreement {
    /// Every value, for the schema test that pins the published vocabulary to this one.
    pub const ALL: &[Self] = &[
        Self::Agrees,
        Self::Disagrees,
        Self::Unmapped,
        Self::NoElfArtifact,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agrees => "agrees",
            Self::Disagrees => "disagrees",
            Self::Unmapped => "unmapped",
            Self::NoElfArtifact => "no-elf-artifact",
        }
    }
}

/// The architecture arch-gated checks gated on, held to the artifacts the run built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetArch {
    /// The value `report::applicability` compared every `Gate.arch` against.
    pub arch: String,
    pub source: ArchSource,
    pub agreement: ArchAgreement,
    /// The stored `elf.machine` to the number of distinct artifacts, by digest, carrying it.
    pub machines: BTreeMap<String, usize>,
    /// Distinct ELF artifacts read: the denominator of `machines`.
    pub artifacts_read: usize,
    /// Which artifacts, what they carried, and why the agreement follows.
    pub evidence: String,
    /// The second witness: the architecture macros the driver's intrinsic macro dump
    /// defined, and what they made of `arch`.
    pub macros: MacroWitness,
    /// The same witness under the flags a C probe's measured variant is built with, where
    /// the profile gives any: the target those flags select. Absent where they are empty,
    /// since the dump would then be `macros`'s own invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_macros: Option<ProfileMacroWitness>,
    /// The same witness through the C++ driver under the flags a C++ probe's measured
    /// variant is built with, where those differ from the C ones: the target a C++ probe
    /// was built for. Absent where they are equal, since `profile_macros` then witnesses
    /// both, and where no C++ driver exists, since no C++ probe then builds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_macros_cxx: Option<ProfileMacroWitness>,
    /// The width and byte order of the artifacts and dumps that agree about the family,
    /// held to the ones `arch`'s rows stand for ([`AbiWitness`]). Settled last, over the
    /// witnesses above, by [`TargetArch::with_intrinsic_abi`] and
    /// [`TargetArch::with_cxx_dump`] as each adds what it reads.
    pub abi: AbiWitness,
    /// Not published: the artifacts of the read family by width and order, with the first
    /// label of each, from which `abi` is settled whenever a witness is added.
    #[serde(skip)]
    family_artifacts: BTreeMap<String, (usize, String)>,
    /// Not published: the artifacts of the read family whose record carries no `elf_data`
    /// (a record without the field), which the witness cannot hold and the evidence
    /// names rather than counting as "no artifact read".
    #[serde(skip)]
    family_unrecorded: usize,
}

impl TargetArch {
    /// Carry the flagless dump's width and order ([`Detected::arch_abi`]) into
    /// `macros.abi`, and settle [`TargetArch::abi`] over it. [`target_agreement`] cannot
    /// read it from `arch_macros`, which carries the family macros alone, so the caller
    /// adds it; a report re-derives it from the published `toolchain.target.macros.abi`.
    #[must_use]
    pub fn with_intrinsic_abi(mut self, abi: Option<Abi>) -> Self {
        self.macros.abi = abi;
        self.settle_abi();
        self
    }

    /// [`TargetArch::abi`] over the witnesses as they stand: the artifacts of the read
    /// family, and each dump whose agreement about the family is `Agrees` and that named a
    /// width and order.
    fn settle_abi(&mut self) {
        let expected = Abi::of_arch(&self.arch);
        let from = arch_read_from(self.source);
        let mut dumps: BTreeMap<String, Abi> = BTreeMap::new();
        let witnesses = [
            (INTRINSIC_DUMP, Some(&self.macros)),
            (
                PROFILE_DUMP,
                self.profile_macros.as_ref().map(|p| &p.witness),
            ),
            (
                PROFILE_CXX_DUMP,
                self.profile_macros_cxx.as_ref().map(|p| &p.witness),
            ),
        ];
        for (name, witness) in witnesses {
            if let Some(w) = witness
                && w.agreement == MacroAgreement::Agrees
                && let Some(abi) = w.abi
            {
                dumps.insert(name.to_owned(), abi);
            }
        }
        let artifacts: BTreeMap<String, usize> = self
            .family_artifacts
            .iter()
            .map(|(abi, (n, _))| (abi.clone(), *n))
            .collect();
        let (agreement, evidence) = abi_agreement(
            &self.arch,
            from,
            expected,
            &self.family_artifacts,
            self.family_unrecorded,
            &dumps,
        );
        self.abi = AbiWitness {
            expected,
            artifacts,
            dumps,
            agreement,
            evidence,
        };
    }

    /// Hold `arch` to `dump`, the intrinsic dump through the C++ driver under the C++ flags
    /// ([`Detected::profile_macros_cxx`]), as [`target_agreement`] holds it to the C one.
    /// `artifacts` are the ones [`target_agreement`] was given: the C++ dump is overruled
    /// only by the ones C++ probes built ([`corroboration`]).
    #[must_use]
    pub fn with_cxx_dump(
        mut self,
        dump: Option<&ProfileDump>,
        artifacts: &[ArtifactMachine],
    ) -> Self {
        let from = arch_read_from(self.source);
        let corroborated = corroboration(self.agreement, &self.machines, artifacts, Lang::Cxx);
        self.profile_macros_cxx = dump
            .map(|d| profile_macro_witness(&self.arch, from, PROFILE_CXX_DUMP, d, corroborated));
        self.settle_abi();
        self
    }

    /// The dump under profile flags that witnesses a probe of `lang`: the C++ one for a C++
    /// probe where it was taken, the C one otherwise. A C probe was built under the C
    /// flags whatever the C++ ones select, and where no C++ dump was taken the C++ flags
    /// are the C ones.
    fn profile_witness_for(&self, lang: Lang) -> Option<(&ProfileMacroWitness, &'static str)> {
        match (lang, &self.profile_macros_cxx) {
            (Lang::Cxx, Some(cxx)) => Some((cxx, PROFILE_CXX_DUMP)),
            _ => self.profile_macros.as_ref().map(|p| (p, PROFILE_DUMP)),
        }
    }

    /// Every machine a witness to a probe of `lang` named: the artifacts' `e_machine`
    /// values, then the machine of each architecture macro the flagless dump defined, then
    /// those of the dump under the flags that probe was built with: `profile_macros_cxx`
    /// for a C++ probe where it was taken, `profile_macros` otherwise. The set
    /// `report::withhold_on_contradicted_target` holds the probe's arch gates to.
    pub fn witnessed_machines(&self, lang: Lang) -> impl Iterator<Item = &str> {
        self.machines
            .keys()
            .map(String::as_str)
            .chain(self.macros.machines())
            .chain(
                self.profile_witness_for(lang)
                    .into_iter()
                    .flat_map(|(p, _)| p.witness.machines()),
            )
    }

    /// Which witness to a probe of `lang` named `machine`, as a clause a gating reason
    /// quotes. An artifact is named first, since it is what the compiler emitted.
    #[must_use]
    pub fn witness_of(&self, machine: &str, lang: Lang) -> String {
        if self.machines.contains_key(machine) {
            return format!("an artifact this run built carries e_machine {machine}");
        }
        let profile = self
            .profile_witness_for(lang)
            .map(|(p, dump)| (&p.witness, dump));
        let (witness, dump) = std::iter::once((&self.macros, INTRINSIC_DUMP))
            .chain(profile)
            .find(|(w, _)| w.machines().any(|m| m == machine))
            .unwrap_or((&self.macros, INTRINSIC_DUMP));
        if machine == OUTSIDE_ARCH_MACROS {
            return format!(
                "the driver's {dump} defines none of {}, the macros every target of those \
                 families defines",
                arch_macro_names()
            );
        }
        let named = ARCH_MACROS
            .iter()
            .filter(|(_, m)| *m == machine)
            .map(|(name, _)| *name)
            .find(|name| witness.defined.iter().any(|d| d == name))
            .unwrap_or("an architecture macro");
        format!("the driver's {dump} defines {named}, the macro of e_machine {machine}")
    }
}

/// A target's width and byte order: `EI_CLASS` and `EI_DATA` in an artifact, and what a
/// macro dump's `__SIZEOF_POINTER__` and `__BYTE_ORDER__` name. Published as one word,
/// `ELF64 little-endian`, the spelling `readelf -h` gives the two fields.
///
/// A family's `e_machine` covers more than one of these: `EM_X86_64` is LP64 and x32,
/// `EM_AARCH64` is LP64, ILP32 and `aarch64_be`, `EM_PPC64` both orders. The mechanism
/// table's rows (`mechanism::ARCHS`) were measured on one of each ([`Abi::of_arch`]), so an
/// artifact of the read family at another width or order is a target the table has no row
/// for, as a foreign `e_machine` is, and [`TargetArch::abi`] withholds every gated check
/// under it. Comparing the machine alone would let an x32 or ILP32 object pass the 64-bit
/// gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Abi {
    pub class: u8,
    pub order: crate::elf::ByteOrder,
}

impl Abi {
    /// The width and order the mechanism table's rows for `arch` stand for: the hosts
    /// they were measured on. `None` for an architecture outside the table, of which
    /// nothing is expected.
    #[must_use]
    pub fn of_arch(arch: &str) -> Option<Self> {
        use crate::elf::ByteOrder::LittleEndian;
        match arch {
            "x86_64" | "aarch64" => Some(Self {
                class: 64,
                order: LittleEndian,
            }),
            "x86" => Some(Self {
                class: 32,
                order: LittleEndian,
            }),
            _ => None,
        }
    }

    /// What a macro dump names: `__SIZEOF_POINTER__` 4 or 8 is the width (x32 and aarch64
    /// ILP32 define 4 with their 64-bit family macro, as their `ELFCLASS32` objects carry),
    /// and `__BYTE_ORDER__` `__ORDER_LITTLE_ENDIAN__` or `__ORDER_BIG_ENDIAN__` the order;
    /// gcc and clang define both for every target (measured 2026-10-14 for gcc 16.1.1 under
    /// `-m64`, `-m32`, `-mx32`, and the aarch64 cross gcc flagless, `-mbig-endian` and
    /// `-mabi=ilp32`, and for clang 22.1.8 under `--target=` x86_64, i386, `aarch64_be`,
    /// x86_64-linux-gnux32, powerpc64 and powerpc64le). One measured target the dump
    /// misnames: under clang's `aarch64-linux-gnu_ilp32` triple the dump names 8 and no
    /// `__ILP32__` while `clang -c` writes `ELFCLASS32` objects, so only an artifact
    /// witnesses that target, and a run that reads none publishes its gated verdicts as
    /// aarch64's (the ledger names it, 2026-10-14). `None` where either macro is absent or
    /// spelled otherwise (a PDP order, a dump `-undef` silenced): nothing to hold.
    #[must_use]
    pub fn from_dump(macros: &BTreeMap<String, String>) -> Option<Self> {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        let class = match macros.get("__SIZEOF_POINTER__").map(String::as_str) {
            Some("8") => 64,
            Some("4") => 32,
            _ => return None,
        };
        let order = match macros.get("__BYTE_ORDER__").map(String::as_str) {
            Some("__ORDER_LITTLE_ENDIAN__") => LittleEndian,
            Some("__ORDER_BIG_ENDIAN__") => BigEndian,
            _ => return None,
        };
        Some(Self { class, order })
    }
}

impl std::fmt::Display for Abi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ELF{} {}", self.class, self.order)
    }
}

impl Serialize for Abi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// What the artifacts and dumps of the read family made of its width and byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbiAgreement {
    /// Every artifact of the read family, and every dump that agreed about the family,
    /// carries the width and order its rows stand for.
    Agrees,
    /// One of them carries another width or order.
    Disagrees,
    /// `arch` has no row in the mechanism table, so nothing is expected of them.
    Unmapped,
    /// No artifact of the read family was read and no dump that agreed about the family
    /// named a width and order: nothing to hold.
    NoWitness,
}

impl AbiAgreement {
    /// Every value, for the schema test that pins the published vocabulary to this one.
    pub const ALL: &[Self] = &[
        Self::Agrees,
        Self::Disagrees,
        Self::Unmapped,
        Self::NoWitness,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agrees => "agrees",
            Self::Disagrees => "disagrees",
            Self::Unmapped => "unmapped",
            Self::NoWitness => "no-witness",
        }
    }
}

/// The width and byte order of the read family's artifacts and dumps, held to the ones
/// the mechanism table's rows for the read architecture stand for: `toolchain.target.abi`.
///
/// Read only from what agrees about the family: an artifact of another `e_machine`, or a
/// dump defining another family's macro or none, already withholds under the machine
/// comparison, and its width says nothing about the read family's rows; an overruled,
/// superseded or failed dump witnesses no target. A disagreement withholds every gated
/// check under `target-abi-contradicted` (`report::withhold_on_contradicted_target`): the
/// rows were measured at one width and order, and a target at another is one the table has
/// no row for, whichever way each gate went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbiWitness {
    /// The width and order the rows for `arch` stand for; absent where `arch` has no row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<Abi>,
    /// Each width and order among the artifacts of the read family, to the number of
    /// distinct artifacts, by digest, carrying it. A record with no `elf_data` is left out.
    pub artifacts: BTreeMap<String, usize>,
    /// Each dump that agreed about the family, to the width and order it named.
    pub dumps: BTreeMap<String, Abi>,
    pub agreement: AbiAgreement,
    pub evidence: String,
}

impl AbiWitness {
    /// The block before [`TargetArch::settle_abi`] fills it, which the constructor does
    /// before returning.
    fn unsettled() -> Self {
        Self {
            expected: None,
            artifacts: BTreeMap::new(),
            dumps: BTreeMap::new(),
            agreement: AbiAgreement::NoWitness,
            evidence: String::new(),
        }
    }

    /// The artifacts of `family` among `artifacts`, by width and order, with the first
    /// label carrying each; the part [`target_agreement`] computes once from the artifacts.
    fn artifacts_of(
        family: Option<&str>,
        artifacts: &[ArtifactMachine],
    ) -> (BTreeMap<String, (usize, String)>, usize) {
        let mut out: BTreeMap<String, (usize, String)> = BTreeMap::new();
        let mut unrecorded: usize = 0;
        for a in artifacts {
            if Some(a.machine.as_str()) != family {
                continue;
            }
            let Some(order) = a.order else {
                unrecorded = unrecorded.saturating_add(1);
                continue;
            };
            let abi = Abi {
                class: a.class,
                order,
            };
            let entry = out
                .entry(abi.to_string())
                .or_insert_with(|| (0, a.label.clone()));
            entry.0 = entry.0.saturating_add(1);
        }
        (out, unrecorded)
    }
}

/// The agreement and evidence of [`AbiWitness`] over what the witnesses carried: `expected`
/// is what `arch`'s rows stand for, `family_artifacts` the read family's artifacts by width
/// and order with the first label of each, `family_unrecorded` those whose record carries no
/// order, and `dumps` each agreeing dump's width and order.
fn abi_agreement(
    arch: &str,
    from: &str,
    expected: Option<Abi>,
    family_artifacts: &BTreeMap<String, (usize, String)>,
    family_unrecorded: usize,
    dumps: &BTreeMap<String, Abi>,
) -> (AbiAgreement, String) {
    let artifacts_total: usize = family_artifacts.values().map(|(n, _)| *n).sum();
    match expected {
        None => (
            AbiAgreement::Unmapped,
            format!(
                "{arch}, read from {from}, has no row in the mechanism table, so no width \
                 or byte order is expected of its artifacts or dumps"
            ),
        ),
        Some(expected) if family_artifacts.is_empty() && dumps.is_empty() => (
            AbiAgreement::NoWitness,
            format!(
                "the rows for {arch}, read from {from}, stand for {expected}; {} and no \
                 dump that agreed about the family named a width and byte order, so \
                 nothing holds it",
                if family_unrecorded == 0 {
                    "no ELF artifact of its family was read".to_owned()
                } else {
                    format!(
                        "the {family_unrecorded} ELF artifact(s) of its family read carry no \
                         recorded byte order (a record without the `elf_data` field)"
                    )
                }
            ),
        ),
        Some(expected) => {
            let against: Vec<String> = family_artifacts
                .iter()
                .filter(|(abi, _)| **abi != expected.to_string())
                .map(|(abi, (n, first))| {
                    format!("{n} ELF artifact(s) this run built carry {abi} (first {first})")
                })
                .chain(
                    dumps
                        .iter()
                        .filter(|(_, abi)| **abi != expected)
                        .map(|(name, abi)| {
                            format!(
                                "the driver's {name} defines __SIZEOF_POINTER__ {} and \
                             __BYTE_ORDER__ {}, naming {abi}",
                                abi.class / 8,
                                abi.order
                            )
                        }),
                )
                .collect();
            if against.is_empty() {
                let with = artifacts_total;
                (
                    AbiAgreement::Agrees,
                    format!(
                        "the rows for {arch}, read from {from}, stand for {expected}; all \
                         {with} ELF artifact(s) of its family carry it, and so does every \
                         dump that agreed about the family ({})",
                        if dumps.is_empty() {
                            "none named a width and order".to_owned()
                        } else {
                            dumps.keys().cloned().collect::<Vec<_>>().join(", ")
                        }
                    ),
                )
            } else {
                (
                    AbiAgreement::Disagrees,
                    format!(
                        "the rows for {arch}, read from {from}, stand for {expected}, and a \
                         target of its family at another width or byte order is one the \
                         table has no row for: {}",
                        against.join("; ")
                    ),
                )
            }
        }
    }
}

/// The flagless dump, as evidence and gating reasons name it.
const INTRINSIC_DUMP: &str = "intrinsic macro dump";
/// The dump under the profile's flags, as evidence and gating reasons name it.
const PROFILE_DUMP: &str = "intrinsic macro dump under the profile's C flags";
/// The C++ driver's dump under the profile's C++ flags, as evidence and gating reasons
/// name it. Only the C++ driver is asked under those flags, so "the driver's" before it
/// names that one.
const PROFILE_CXX_DUMP: &str = "intrinsic macro dump under the profile's C++ flags";

/// An intrinsic macro dump taken under the flags a probe's measured variant is built with
/// ([`Detected::dump_with`]): through the C driver under the C flags for
/// `toolchain.target.profile_macros`, and through the C++ driver under the C++ flags for
/// `toolchain.target.profile_macros_cxx`. It is what [`profile_macro_witness`] reads, and
/// what a report re-derives either published [`ProfileMacroWitness`] from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDump {
    pub flags: Vec<String>,
    pub exit_status: i32,
    /// The dump's output was cut off partway through a line
    /// (`compile::BuildRecord::stdout_unterminated`), which a dump that exited 0 can be: it
    /// witnesses no target, as one that exited non-zero does.
    pub stdout_unterminated: bool,
    /// Every macro the dump defined, counted.
    pub macros_defined: usize,
    /// The names from [`ARCH_MACROS`] it defined, in list order.
    pub defined: Vec<String>,
    /// The width and byte order its `__SIZEOF_POINTER__` and `__BYTE_ORDER__` name
    /// ([`Abi::from_dump`]), where it defined both.
    pub abi: Option<Abi>,
}

impl ProfileDump {
    /// Whether the dump can witness a target: it exited 0, its output was not cut off
    /// partway through a line, and it defined a macro. The one reading `selected_arch`,
    /// `profile_macro_witness` and the binary's pre-build arch refusal all ask, so none of
    /// them reads a machine from a dump another calls failed.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.exit_status == 0 && !self.stdout_unterminated && self.macros_defined > 0
    }
}

/// The macro witness under the profile's flags, with the invocation it read.
///
/// `-dumpmachine` and the flagless dump are asked with no profile flags, so they agree
/// with each other by construction about a target the profile's flags choose (`-m32`,
/// `--target=`, `-arch x86_64`). The artifacts witness such a target where the run reads
/// ELF artifacts; this dump witnesses it on every run whose profile gives flags, including
/// one that reads none. A dump that exited non-zero or defined no macro at all
/// (a flag the driver refused), or exited 0 with its output cut off partway through a line,
/// is [`MacroAgreement::DumpFailed`]: silence, never a target outside the three families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileMacroWitness {
    /// The flags the dump ran under, before `-dM -E`.
    pub flags: Vec<String>,
    pub exit_status: i32,
    /// [`ProfileDump::stdout_unterminated`], published only where it is true.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stdout_unterminated: bool,
    /// Every macro the dump defined, counted: zero is a dump that said nothing.
    pub macros_defined: usize,
    #[serde(flatten)]
    pub witness: MacroWitness,
}

impl ProfileMacroWitness {
    /// The dump this witness was read from, for re-derivation.
    #[must_use]
    pub fn dump(&self) -> ProfileDump {
        ProfileDump {
            flags: self.flags.clone(),
            exit_status: self.exit_status,
            stdout_unterminated: self.stdout_unterminated,
            macros_defined: self.macros_defined,
            defined: self.witness.defined.clone(),
            abi: self.witness.abi,
        }
    }
}

/// [`ProfileMacroWitness`] for `dump`, which evidence calls `name`, against `arch`, read from
/// `from`, with the artifacts' corroboration of `arch` where they give it
/// ([`corroboration`]).
fn profile_macro_witness(
    arch: &str,
    from: &str,
    name: &str,
    dump: &ProfileDump,
    corroborated: Option<Corroboration<'_>>,
) -> ProfileMacroWitness {
    let flags = dump.flags.join(" ");
    let witness = if dump.completed() {
        let mut w = overruled(
            macro_witness(arch, from, name, &dump.defined, dump.abi),
            name,
            arch,
            from,
            corroborated,
            DumpTaken::UnderProfileFlags(&dump.flags),
        );
        w.evidence = format!("{}; the flags were `{flags}`", w.evidence);
        w
    } else {
        let cut = if dump.stdout_unterminated {
            format!(" {},", compile::CUT_OFF)
        } else {
            String::new()
        };
        MacroWitness {
            abi: None,
            defined: Vec::new(),
            agreement: MacroAgreement::DumpFailed,
            evidence: format!(
                "the {name} (`{flags}`) {}{cut} with {} macro(s), so it witnesses \
                 no target, and {arch}, read from {from}, stands uncorroborated by it",
                compile::ended(dump.exit_status),
                dump.macros_defined
            ),
        }
    };
    ProfileMacroWitness {
        flags: dump.flags.clone(),
        exit_status: dump.exit_status,
        stdout_unterminated: dump.stdout_unterminated,
        macros_defined: dump.macros_defined,
        witness,
    }
}

/// The architecture macros the macro witness reads, each beside the `elf.machine` name of
/// the family it is defined for.
///
/// The families are the ones a `Gate.arch` names (`x86_64`, `x86`, `aarch64`), in
/// `elf::machine_name`'s spelling so a macro and an artifact name one machine alike. gcc
/// and clang define exactly one of the three for a target of those families and none for
/// any other target; every architecture outside them decides every gate the same way, so
/// a macro for one would witness nothing a gate reads. That premise withholds verdicts
/// when it reads a contradiction, so `report::ASSUMPTIONS` carries it as
/// `arch-macros-name-the-target`, with the measurement behind it.
/// `report::tests::every_gate_architecture_has_an_arch_macro` holds the list to the gates.
pub const ARCH_MACROS: &[(&str, &str)] = &[
    ("__x86_64__", "x86_64"),
    ("__i386__", "i386"),
    ("__aarch64__", "aarch64"),
];

/// The machine [`MacroWitness::machines`] names for a dump that defines none of
/// [`ARCH_MACROS`] where the gate's architecture is of one of their families: a target
/// outside the three, which is what such a dump witnesses. The mechanism table has no row
/// for it, so every gate decides it outside the table, which is another outcome than any
/// the gate took under the architecture it read, and
/// `report::withhold_on_contradicted_target` withholds every gated check under it.
/// `elf::machine_name` never returns it. Where the run's artifacts all carry the read
/// family, the dump is [`MacroAgreement::Overruled`] and names no machine.
pub const OUTSIDE_ARCH_MACROS: &str = "outside-arch-macros";

/// The names in [`ARCH_MACROS`], comma-separated, for evidence strings.
fn arch_macro_names() -> String {
    ARCH_MACROS
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The names from [`ARCH_MACROS`] `macros` defines, in list order.
#[must_use]
pub fn arch_macros(macros: &BTreeMap<String, String>) -> Vec<String> {
    ARCH_MACROS
        .iter()
        .filter(|(name, _)| macros.contains_key(*name))
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

/// What the intrinsic macro dump made of the architecture the arch gate read.
///
/// The first three values mean what [`ArchAgreement`]'s do, with the architecture macros
/// in the place of the artifacts. A dump defining none of [`ARCH_MACROS`] is what a
/// target outside those three families produces: `Disagrees` where `arch` is of one of
/// them, since the dump then witnesses a target the gate did not read, and `NoArchMacro`
/// otherwise, which leaves `arch` uncorroborated by this witness rather than
/// contradicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MacroAgreement {
    /// The dump defines the macro of `arch`'s family and no other.
    Agrees,
    /// The dump defines the macro of another family, the macros of more than one, or none
    /// where `arch` is of one of their families.
    Disagrees,
    /// `arch` names no family [`machine_family`] maps, and the dump defines one macro.
    Unmapped,
    /// The dump defines none of [`ARCH_MACROS`], and `arch` is of none of their families.
    NoArchMacro,
    /// The dump exited non-zero, defined no macro at all, or exited 0 with its output cut off
    /// partway through a line ([`ProfileDump::stdout_unterminated`]), so it witnesses nothing. Only
    /// [`ProfileMacroWitness`] reads it: `detect` refuses a driver whose flagless dump is
    /// empty.
    DumpFailed,
    /// The gate read its architecture from the dump under the profile's C flags
    /// ([`ArchSource::ProfileMacros`]), because those flags select a target. This dump was
    /// asked with no flags, so it names the driver's default target, which no probe was
    /// built for, and it witnesses nothing about the gate. Only the flagless
    /// `toolchain.target.macros` reads it.
    Superseded,
    /// The dump defines none of [`ARCH_MACROS`] under an `arch` of one of their families,
    /// which alone would witness a target outside the three, while every ELF artifact the
    /// run built carries the family of `arch` ([`ArchAgreement::Agrees`]). The artifacts
    /// are the compiler's output and the one witness the profile's flags cannot silence,
    /// so they overrule the dump: it witnesses no target and withholds nothing. A profile
    /// flag that suppresses the predefined macros (`-undef`) produces this on a native run.
    Overruled,
}

impl MacroAgreement {
    /// Every value, for the schema test that pins the published vocabulary to this one.
    pub const ALL: &[Self] = &[
        Self::Agrees,
        Self::Disagrees,
        Self::Unmapped,
        Self::NoArchMacro,
        Self::DumpFailed,
        Self::Superseded,
        Self::Overruled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agrees => "agrees",
            Self::Disagrees => "disagrees",
            Self::Unmapped => "unmapped",
            Self::NoArchMacro => "no-arch-macro",
            Self::DumpFailed => "dump-failed",
            Self::Superseded => "superseded",
            Self::Overruled => "overruled",
        }
    }
}

/// The driver's intrinsic macro dump as a witness to the gate's architecture.
///
/// `-dumpmachine` and the macro dump are both the driver's word about itself, from two
/// places in it: the driver prints the triple, and the compiler proper defines the macros
/// for the target it emits code for. A wrapper or a multilib driver that prints a fixed
/// triple leaves the macros telling the truth, and unlike `e_machine` the dump exists on a
/// run that reads no ELF artifact (a Mach-O host, a selection of macro-channel probes).
/// This dump is taken with no profile flags, as `-dumpmachine` is, so it witnesses the
/// driver's own target; a target the profile's flags select (`-m32`, `--target=`,
/// `-arch x86_64`) is [`ProfileMacroWitness`]'s to report, and the artifacts'.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MacroWitness {
    /// The names from [`ARCH_MACROS`] the intrinsic dump defined, in list order.
    pub defined: Vec<String>,
    pub agreement: MacroAgreement,
    /// The macros, the machine each names, and why the agreement follows.
    pub evidence: String,
    /// The width and byte order the dump's `__SIZEOF_POINTER__` and `__BYTE_ORDER__` name,
    /// where it defined both ([`Abi::from_dump`]), published whatever the agreement, since
    /// it is a fact of the dump: a superseded or overruled dump names its target's width
    /// too. [`TargetArch::abi`] reads it only where the agreement is `Agrees`. Absent where
    /// the dump failed, or defined one of the two macros or neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<Abi>,
}

impl MacroWitness {
    /// The `elf.machine` name of each macro in `defined`, in [`ARCH_MACROS`] order, or
    /// [`OUTSIDE_ARCH_MACROS`] alone where `defined` is empty and the agreement is
    /// `Disagrees`; nothing where the agreement is `DumpFailed`, `Superseded` or
    /// `Overruled`, since such a dump witnesses no target a probe was built for.
    pub fn machines(&self) -> impl Iterator<Item = &str> {
        let outside = (self.defined.is_empty() && self.agreement == MacroAgreement::Disagrees)
            .then_some(OUTSIDE_ARCH_MACROS);
        let read = match self.agreement {
            MacroAgreement::Agrees
            | MacroAgreement::Disagrees
            | MacroAgreement::Unmapped
            | MacroAgreement::NoArchMacro => true,
            MacroAgreement::DumpFailed | MacroAgreement::Superseded | MacroAgreement::Overruled => {
                false
            }
        };
        ARCH_MACROS
            .iter()
            .filter(move |(name, _)| read && self.defined.iter().any(|d| d == name))
            .map(|(_, machine)| *machine)
            .chain(outside)
    }
}

/// How one witnessed machine stands to the gate's architecture: the rule
/// [`target_agreement`] applies to the artifacts' one machine and to the macros' one.
enum Stands {
    Agrees,
    /// Another family than `arch`'s, which it carries.
    Disagrees(&'static str),
    Unmapped,
}

fn stands(arch: &str, machine: &str) -> Stands {
    match machine_family(arch) {
        Some(f) if f == machine => Stands::Agrees,
        Some(f) => Stands::Disagrees(f),
        None => Stands::Unmapped,
    }
}

/// [`MacroWitness`] for `defined`, the architecture macros `dump` defined, against `arch`,
/// read from `from`.
fn macro_witness(
    arch: &str,
    from: &str,
    dump: &str,
    defined: &[String],
    abi: Option<Abi>,
) -> MacroWitness {
    let mut witness = MacroWitness {
        abi,
        defined: ARCH_MACROS
            .iter()
            .filter(|(name, _)| defined.iter().any(|d| d == name))
            .map(|(name, _)| (*name).to_owned())
            .collect(),
        agreement: MacroAgreement::NoArchMacro,
        evidence: String::new(),
    };
    let machines: Vec<&str> = witness.machines().collect();
    let named = witness
        .defined
        .iter()
        .zip(&machines)
        .map(|(name, m)| format!("{name} (e_machine {m})"))
        .collect::<Vec<_>>()
        .join(", ");
    let family_has_macro = |f: &str| ARCH_MACROS.iter().any(|(_, machine)| *machine == f);
    let (agreement, evidence) = match machines.as_slice() {
        [] => match machine_family(arch) {
            Some(f) if family_has_macro(f) => (
                MacroAgreement::Disagrees,
                format!(
                    "the {dump} defines none of {}; a target outside those families \
                     defines none, and so does a target of one of them under a flag that \
                     suppresses the predefined macros (`-undef`), which no ELF artifact in \
                     this run tells apart (assumption arch-macros-name-the-target), so it \
                     is read as a target outside the three, while the arch gate read {arch} \
                     from {from}, whose family is {f}",
                    arch_macro_names()
                ),
            ),
            _ => (
                MacroAgreement::NoArchMacro,
                format!(
                    "the {dump} defines none of {}, so {arch}, read from \
                     {from}, stands uncorroborated by it",
                    arch_macro_names()
                ),
            ),
        },
        [machine] => match stands(arch, machine) {
            Stands::Agrees => (
                MacroAgreement::Agrees,
                format!(
                    "the {dump} defines {named}, the family of {arch}, read \
                     from {from}"
                ),
            ),
            Stands::Disagrees(f) => (
                MacroAgreement::Disagrees,
                format!(
                    "the {dump} defines {named}, while the arch gate read \
                     {arch} from {from}, whose family is {f}"
                ),
            ),
            Stands::Unmapped => (
                MacroAgreement::Unmapped,
                format!(
                    "{arch}, read from {from}, names no e_machine family chard maps, and \
                     the {dump} defines {named}"
                ),
            ),
        },
        _ => (
            MacroAgreement::Disagrees,
            format!(
                "the {dump} defines {named}, the macros of {} machines, \
                 where a target defines one (assumption arch-macros-name-the-target); the \
                 arch gate read {arch} from {from}",
                machines.len()
            ),
        ),
    };
    witness.agreement = agreement;
    witness.evidence = evidence;
    witness
}

/// `witness` with the artifacts' word over it: where it defines none of [`ARCH_MACROS`]
/// under an architecture of their families (`Disagrees` with nothing defined, which alone
/// names [`OUTSIDE_ARCH_MACROS`]) and `corroborated` says every ELF artifact the run built
/// carries that architecture's family, the dump reads [`MacroAgreement::Overruled`] and
/// names no machine.
///
/// The dump is the driver's word, and a profile flag can silence it: `-undef` suppresses
/// the predefined macros, so under it a native x86_64 run's dump defines none of the three
/// while every artifact is x86_64 (measured 2026-10-11, gcc 16.1.1 on Fedora 44
/// x86_64), and without this rule `textrel-absent` and `linker-default-noexecstack` would be
/// withheld under a cause the artifacts refuted. The artifacts are the compiler's output,
/// which no flag of the profile can silence, and they answer the one question the dump's
/// silence leaves open, whether the target is of the read family or outside the three.
/// Only that silence is overruled: a dump defining another family's macro beside agreeing
/// artifacts still disagrees and withholds, the conservative direction. With no artifact
/// (`NoElfArtifact`), or artifacts of another family, nothing overrules the dump; nor does
/// an artifact a probe of another language built ([`corroboration`]). The evidence blames
/// the silence on a flag only where one chard knows to suppress the predefined macros is
/// among the flags the dump was taken under ([`DumpTaken`], [`silencing_flag`]); otherwise,
/// and for the flagless dump, the cause is not established, and the evidence says so. A
/// driver that adds `-undef` itself, under `bare-optimized`, therefore does not have its
/// dump's silence blamed on `-O2`.
fn overruled(
    mut witness: MacroWitness,
    dump: &str,
    arch: &str,
    from: &str,
    corroborated: Option<Corroboration<'_>>,
    taken: DumpTaken<'_>,
) -> MacroWitness {
    let Some(Corroboration {
        family,
        artifacts,
        lang,
    }) = corroborated
    else {
        return witness;
    };
    if witness.agreement != MacroAgreement::Disagrees || !witness.defined.is_empty() {
        return witness;
    }
    witness.agreement = MacroAgreement::Overruled;
    let cause = match taken {
        DumpTaken::UnderProfileFlags(flags) => match silencing_flag(flags, family) {
            Some(flag) => format!(
                "the artifacts are the compiler's output, which the flags this dump was \
                 taken under cannot silence as they can the dump (`{flag}` among them \
                 suppresses the predefined macros, the known cause)"
            ),
            None => "no flag this dump was taken under is one chard knows to suppress the \
                     predefined macros (`-undef`, `-U` of the family's macro), so what \
                     silenced it, the driver's own configuration or a wrapper, chard does not \
                     establish; the artifacts are the compiler's output"
                .to_owned(),
        },
        DumpTaken::WithNoFlags => "this dump was taken with no profile flag, so what silenced \
                                   it, the driver's own configuration or a wrapper, chard does \
                                   not establish; the artifacts are the compiler's output"
            .to_owned(),
    };
    witness.evidence = format!(
        "the {dump} defines none of {}, which alone would witness a target outside those \
         families, while all {artifacts} ELF artifact(s) this run built from {} probes carry \
         e_machine {family}, the family of {arch}, read from {from}; {cause}, so they \
         overrule it: this dump witnesses no target and withholds nothing",
        arch_macro_names(),
        lang_name(lang),
    );
    witness
}

/// The flag among `flags` that suppresses the predefined macros of a target of `family`, as
/// the evidence names it: `-undef`, or `-U` of the macro [`ARCH_MACROS`] gives `family` (as
/// one word or two). `-U` of another family's macro silences nothing on this target, so it
/// is not named. `None` where no such flag is, in which case the dump's silence has no cause
/// chard can name.
fn silencing_flag(flags: &[String], family: &str) -> Option<String> {
    let name = ARCH_MACROS
        .iter()
        .find(|(_, machine)| *machine == family)
        .map(|(name, _)| *name);
    let mut i = 0;
    while let Some(flag) = flags.get(i) {
        let next = flags.get(i.saturating_add(1)).map(String::as_str);
        // The word as gcc reads it (`--undefine-macro` and `--un` are `-U`, `LONG_ALIASES`),
        // walked by the classifier, so the value of an option that takes the next word
        // (`-o -undef`, an output file) is no flag.
        let reading = read(flag, next);
        let word = &*reading.word;
        if word == "-undef" {
            return Some(flag.clone());
        }
        if let Some(name) = name
            && word.strip_prefix("-U") == Some(name)
        {
            return Some(flag.clone());
        }
        if let Some(name) = name
            && word == "-U"
            && reading.span() == 2
            && next == Some(name)
        {
            return Some(format!("{flag} {name}"));
        }
        i = i.saturating_add(reading.own_words_span());
    }
    None
}

/// The language's name in published text.
fn lang_name(lang: Lang) -> &'static str {
    match lang {
        Lang::C => "C",
        Lang::Cxx => "C++",
    }
}

/// The artifacts' corroboration of the architecture the gate read, for a macro dump taken
/// through the driver of `lang`: the one `e_machine` every artifact carries, which is the
/// family of the read architecture ([`ArchAgreement::Agrees`]), and how many of them probes
/// of `lang` built. What a dump defining none of [`ARCH_MACROS`] is overruled by
/// ([`overruled`]).
#[derive(Debug, Clone, Copy)]
struct Corroboration<'a> {
    /// The `e_machine` every artifact carries.
    family: &'a str,
    /// How many distinct artifacts probes of `lang` built.
    artifacts: usize,
    lang: Lang,
}

/// The one derivation of [`Corroboration`], for the flagless and C dumps in
/// [`target_agreement`] and the C++ one in [`TargetArch::with_cxx_dump`].
///
/// A dump is overruled only by artifacts of its own language. The C++ dump witnesses a target only
/// the C++ flags select, and a C artifact, built under the C flags, says nothing about that target:
/// on a run whose C++ flags select a target outside the three and whose C++ builds all failed, the
/// C artifacts are the host's and the C++ dump is silent, and the dump is the one witness to the
/// C++ probes' target. Pooled artifacts would read that dump `overruled` on the strength of the C
/// artifacts alone. `None` where the artifacts disagree, are of no mapped family, are absent, or
/// none of them is a probe of `lang`'s.
fn corroboration<'a>(
    agreement: ArchAgreement,
    machines: &'a BTreeMap<String, usize>,
    artifacts: &[ArtifactMachine],
    lang: Lang,
) -> Option<Corroboration<'a>> {
    if agreement != ArchAgreement::Agrees {
        return None;
    }
    let family = machines.keys().next()?.as_str();
    let of_lang = artifacts.iter().filter(|a| a.lang == Some(lang)).count();
    (of_lang > 0).then_some(Corroboration {
        family,
        artifacts: of_lang,
        lang,
    })
}

/// How a macro dump was taken, which is what its silence can be blamed on: a dump under
/// the profile's flags names the flag among them that suppresses the predefined macros as
/// the known cause, where there is one ([`silencing_flag`]); the flagless dump, taken with
/// no flag, and a dump under flags that name none, name no cause, since what silenced it
/// (the driver's own configuration, a wrapper) chard does not establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DumpTaken<'a> {
    WithNoFlags,
    UnderProfileFlags(&'a [String]),
}

/// One artifact's `e_machine`, `EI_CLASS` and `EI_DATA`, as [`target_agreement`] reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMachine {
    /// `<probe> sha256:<16 hex>`: the probe that built it and a prefix of the digest
    /// `build.artifact_sha256` publishes in full.
    pub label: String,
    /// `ElfFacts::machine`.
    pub machine: String,
    /// `ElfFacts::elf_class`.
    pub class: u8,
    /// `ElfFacts::elf_data`; `None` for a record written before the field, which the abi
    /// witness leaves out as carrying no order to hold.
    pub order: Option<crate::elf::ByteOrder>,
    /// The language of the probe that built it, which decides the dump it can corroborate
    /// ([`corroboration`]); `None` for a probe the corpus does not name, which corroborates
    /// no dump and still counts among the machines.
    pub lang: Option<Lang>,
}

/// The stored `elf.machine` name of the family an architecture compiles for, or `None`
/// for an architecture chard maps to none.
///
/// The argument is in [`Detected::target_arch`]'s vocabulary, or `std::env::consts::ARCH`'s
/// where the gate fell back to the kernel. The names on the right are
/// `elf::machine_name`'s, which name families rather than widths: `ppc64` covers
/// `powerpc64le`, `s390` covers `s390x`, `riscv` both widths. Prefix matches, because a
/// triple's first component carries sub-architecture and byte order (`armv7hl`,
/// `aarch64_be`, `mips64el`) that `e_machine` does not.
#[must_use]
pub fn machine_family(arch: &str) -> Option<&'static str> {
    let family = match arch {
        "x86_64" => "x86_64",
        "x86" => "i386",
        a if a.starts_with("aarch64") => "aarch64",
        a if a.starts_with("arm") || a.starts_with("thumb") => "arm",
        a if a.starts_with("riscv") => "riscv",
        a if a.starts_with("powerpc64") || a.starts_with("ppc64") => "ppc64",
        a if a.starts_with("powerpc") || a.starts_with("ppc") => "ppc",
        a if a.starts_with("s390") => "s390",
        a if a.starts_with("mips") => "mips",
        a if a.starts_with("loongarch") => "loongarch",
        _ => return None,
    };
    Some(family)
}

/// The gate vocabulary's name for the architecture an artifact's `e_machine` names.
///
/// `Gate.arch` names `x86_64`, `x86` and `aarch64`; `elf::machine_name` names the second
/// `i386`. Every other machine is returned as it is, which no gate names, so a gate
/// decides on it as on any architecture it does not list.
#[must_use]
pub fn gate_arch_of_machine(machine: &str) -> &str {
    if machine == "i386" { "x86" } else { machine }
}

/// Hold the architecture the arch gate read to the `e_machine` of every ELF artifact
/// the run built, and to the architecture macros of the driver's intrinsic macro dump.
///
/// `-dumpmachine` decides `arch-gated` before any build, so it is a premise every
/// arch-gated verdict rests on, and the artifacts are the one witness to it the driver
/// does not author about itself: `e_machine` is what the compiler emitted. The linker's
/// banner is held to `.comment` by [`artifact_agreement`] for the same reason.
/// `artifacts` is one entry per distinct artifact. The rules, in order: nothing read is
/// [`ArchAgreement::NoElfArtifact`]; more than one machine among the artifacts disagrees
/// whatever the gate read; one machine agrees when it is the family of `arch`, disagrees
/// when `arch` has a family and it is another, and is [`ArchAgreement::Unmapped`] when
/// `arch` has none. `arch_macros` is [`Detected::arch_macros`], held to `arch` by the same
/// rules in [`MacroWitness`], and `profile` is [`Detected::profile_macros`], held to it by
/// [`ProfileMacroWitness`]'s; the agreements are published side by side, each answering
/// for its own witness, except that a dump defining none of the macros beside artifacts
/// that all carry `arch`'s family is overruled by them ([`overruled`]). What the verdicts
/// do about either is `report::withhold_on_contradicted_target`'s, and why is in
/// `DESIGN.md` under "The binary testifies about itself".
#[must_use]
pub fn target_agreement(
    arch: &str,
    source: ArchSource,
    artifacts: &[ArtifactMachine],
    arch_macros: &[String],
    profile: Option<&ProfileDump>,
) -> TargetArch {
    let mut machines: BTreeMap<String, usize> = BTreeMap::new();
    let mut first: BTreeMap<&str, &str> = BTreeMap::new();
    for a in artifacts {
        let n = machines.entry(a.machine.clone()).or_default();
        *n = n.saturating_add(1);
        first.entry(a.machine.as_str()).or_insert(a.label.as_str());
    }
    let artifacts_read = artifacts.len();
    let from = arch_read_from(source);
    let carried = machines
        .iter()
        .map(|(m, n)| {
            format!(
                "{m} on {n} (first {})",
                first.get(m.as_str()).copied().unwrap_or("?")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let (agreement, evidence) = if artifacts.is_empty() {
        (
            ArchAgreement::NoElfArtifact,
            format!(
                "no ELF artifact was read in this run, so {arch}, read from {from}, stands \
                 uncorroborated"
            ),
        )
    } else if machines.len() > 1 {
        (
            ArchAgreement::Disagrees,
            format!(
                "the run's own {artifacts_read} ELF artifact(s) carry {} machines, \
                 {carried}; the arch gate read {arch} from {from}",
                machines.len()
            ),
        )
    } else {
        let machine = machines.keys().next().map_or("", String::as_str);
        match stands(arch, machine) {
            Stands::Agrees => (
                ArchAgreement::Agrees,
                format!(
                    "all {artifacts_read} ELF artifact(s) carry e_machine {carried}, the \
                     family of {arch}, read from {from}"
                ),
            ),
            Stands::Disagrees(f) => (
                ArchAgreement::Disagrees,
                format!(
                    "all {artifacts_read} ELF artifact(s) carry e_machine {carried}, while \
                     the arch gate read {arch} from {from}, whose family is {f}"
                ),
            ),
            Stands::Unmapped => (
                ArchAgreement::Unmapped,
                format!(
                    "{arch}, read from {from}, names no e_machine family chard maps, and \
                     all {artifacts_read} ELF artifact(s) carry {carried}"
                ),
            ),
        }
    };
    let corroborated = corroboration(agreement, &machines, artifacts, Lang::C);
    let macros = if source == ArchSource::ProfileMacros {
        superseded_witness(arch_macros, profile)
    } else {
        overruled(
            macro_witness(arch, from, INTRINSIC_DUMP, arch_macros, None),
            INTRINSIC_DUMP,
            arch,
            from,
            corroborated,
            DumpTaken::WithNoFlags,
        )
    };
    let profile_macros =
        profile.map(|dump| profile_macro_witness(arch, from, PROFILE_DUMP, dump, corroborated));
    let (family_artifacts, family_unrecorded) =
        AbiWitness::artifacts_of(machine_family(arch), artifacts);
    let mut target = TargetArch {
        arch: arch.to_owned(),
        source,
        agreement,
        machines,
        artifacts_read,
        evidence,
        macros,
        profile_macros,
        profile_macros_cxx: None,
        abi: AbiWitness::unsettled(),
        family_artifacts,
        family_unrecorded,
    };
    target.settle_abi();
    target
}

/// The flagless dump's [`MacroWitness`] where the gate read the dump under the profile's
/// flags: [`MacroAgreement::Superseded`], with the macros it defined kept.
fn superseded_witness(arch_macros: &[String], profile: Option<&ProfileDump>) -> MacroWitness {
    let defined: Vec<String> = ARCH_MACROS
        .iter()
        .filter(|(name, _)| arch_macros.iter().any(|d| d == name))
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let flags = profile.map_or_else(
        || "none were dumped".to_owned(),
        |p| format!("`{}`", p.flags.join(" ")),
    );
    let named = if defined.is_empty() {
        format!("none of {}", arch_macro_names())
    } else {
        defined.join(", ")
    };
    MacroWitness {
        abi: None,
        evidence: format!(
            "the {INTRINSIC_DUMP}, asked with no flags, defines {named}, naming the driver's \
             default target; the profile's C flags ({flags}) select a target, every C probe \
             was built under them, and the arch gate read the {PROFILE_DUMP}, so this dump \
             witnesses no target a probe was built for"
        ),
        defined,
        agreement: MacroAgreement::Superseded,
    }
}

/// Where `arch` came from, as evidence names it.
fn arch_read_from(source: ArchSource) -> &'static str {
    match source {
        ArchSource::Dumpmachine => "the driver's -dumpmachine",
        ArchSource::Kernel => "the kernel, since -dumpmachine gave no triple chard read",
        ArchSource::ProfileMacros => {
            "the intrinsic macro dump under the profile's C flags, which select a target"
        }
    }
}

/// Identify the linker `driver` will run under `profile_flags`.
///
/// Public so the caller can re-run it once the profile is known; see
/// [`Detected::link_with`] for why that is a second step.
pub fn detect_linker(driver: &Path, profile_flags: &[String], workdir: &Path) -> Linker {
    detect_linker_on(driver, profile_flags, &search_path(), workdir)
}

/// What the driver's own `-###` link line says about the linker it runs.
///
/// Public, with [`link_line`], for the `driver_text` fuzz target.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkLine {
    /// The line runs this file directly, as clang's does.
    Runs(PathBuf),
    /// The line runs gcc's `collect2`, which picks the linker from the `-fuse-ld=` and
    /// `--ld-path=` flags it is handed; these are they, as written.
    Collect2(Vec<String>),
}

/// The last command of a `-###` listing: the link, since both drivers print the steps in
/// the order they would run them. The words are read by [`link_inputs::words`], the
/// tokeniser the input comparisons use, so a quoted path holding a space is one word here
/// as there; on the lines gcc and clang print, where no word read here holds a space or an
/// escape, it reads what a split on whitespace with the quotes trimmed read before it.
///
/// Public so the `driver_text` fuzz target (`fuzz/fuzz_targets/driver_text.rs`) holds it
/// to its laws.
#[must_use]
pub fn link_line(listing: &str) -> Option<LinkLine> {
    let line = listing
        .lines()
        .rfind(|l| l.starts_with(" \"") || l.starts_with(" /"))?;
    let words = link_inputs::words(line);
    let program = words.first()?;
    if Path::new(program).file_name()? == "collect2" {
        let chosen = words
            .iter()
            .skip(1)
            .filter(|w| w.starts_with("-fuse-ld=") || w.starts_with("--ld-path="))
            .cloned()
            .collect();
        Some(LinkLine::Collect2(chosen))
    } else if Path::new(program).components().count() > 1 {
        Some(LinkLine::Runs(PathBuf::from(program)))
    } else {
        None
    }
}

/// What [`link_line`] made of the driver's `-###` listing under the profile's selection.
struct LinkLineReading {
    /// Selection flags the line adds to the profile's: an `--ld-path=` for the file a
    /// clang line runs, or the flags a gcc line hands `collect2`.
    adds: Vec<String>,
    /// The sentence the detection opens with when the line chose the program.
    runs: Option<String>,
    /// Why no line was read, when the driver could not be asked or exited other than 0 on
    /// the query; the detection opens with it, so the fallback route is published with its
    /// cause.
    unread: Option<String>,
}

/// Ask the driver for its `-###` listing under `consulted` and read the link line.
///
/// The listing is read under [`link_inputs::listing`]'s rule, the one the two input
/// comparisons follow: a driver that exits other than 0 has rejected the command it was
/// asked to list, so whatever it printed describes a link that would not run and is not
/// read. A driver that cannot be asked, or that exited so, is said so in the sentence
/// rather than read as a line that selected nothing: the detection that follows then names
/// the route it fell back to and why. With the status unread, a wrapper that printed a
/// listing running `/usr/bin/ld.lld` on `-###` and exited 1 would have that path published
/// as the linker while every link went through GNU ld (Fedora 44 x86_64, clang 22.1.8,
/// 2026-10-07).
///
/// `consulted` is the profile's link-selection words alone, not its flags, and the
/// sentence names that scope ([`link_inputs::under_named`]: `with no link-selection flag`,
/// `under the link-selection flag -fuse-ld=lld`), since `under no flags` here read as a
/// claim about the profile and was false of every profile without a selection.
///
/// The sentence quotes the driver's own stderr and lands in `toolchain.linker.detection`,
/// which no later pass rewrites, so the quote is published as it is made
/// ([`link_inputs::listing`] against `workdir`): a work directory the driver named (a
/// response file it could not read, a wrapper's own path) is made relative, as a gating's
/// reason is by `measure::publish`. The rest of the detection is chard's own words over
/// the profile's flags and paths chard resolved, and stays spelled as `profile_flags` and
/// `path` are.
fn read_link_line(driver: &Path, consulted: &[String], workdir: &Path) -> LinkLineReading {
    let mut args = consulted.to_vec();
    args.extend(
        ["-###", "-x", "c", "/dev/null", "-o", "/dev/null"]
            .iter()
            .map(|s| (*s).to_owned()),
    );
    let under = link_inputs::under_named(consulted, "link-selection flag");
    let listing = match link_inputs::listing(driver, &args, &under, workdir) {
        Ok(listing) => listing,
        Err(why) => {
            return LinkLineReading {
                adds: Vec::new(),
                runs: None,
                unread: Some(format!("{why}, so its link line was not read")),
            };
        }
    };
    match link_line(&listing) {
        Some(LinkLine::Runs(file)) => LinkLineReading {
            adds: vec![format!("--ld-path={}", file.display())],
            runs: Some(format!(
                "the driver's -### link line runs {}",
                file.display()
            )),
            unread: None,
        },
        Some(LinkLine::Collect2(chosen)) if !chosen.is_empty() => LinkLineReading {
            runs: Some(format!(
                "the driver's -### link line hands collect2 {}",
                chosen.join(" ")
            )),
            adds: chosen,
            unread: None,
        },
        Some(LinkLine::Collect2(_)) | None => LinkLineReading {
            adds: Vec::new(),
            runs: None,
            unread: None,
        },
    }
}

/// Ask the driver which program `selection` names, through any `-B` prefix it adds, and
/// resolve a bare answer on `search_path` the way the drivers' own lookups fall through.
/// `lead` opens every sentence it returns, so the link-line reading that preceded the
/// question stays in the published detection. `Err` carries the sentence for an
/// `unknown` linker.
fn ask_for_program(
    driver: &Path,
    selection: &LinkSelection,
    lead: &str,
    search_path: &OsStr,
) -> Result<(PathBuf, PathSource, String), String> {
    let name = match &selection.program {
        Some(Program::Named(name)) => name.as_str(),
        _ => "ld",
    };
    // Ask the driver which program it would run, through any `-B` prefix the
    // profile adds to its search.
    let mut args = selection.prefixes.clone();
    args.push(format!("-print-prog-name={name}"));
    let query = format!(
        "{lead}{} {}",
        driver.file_name().map_or_else(
            || driver.display().to_string(),
            |n| n.to_string_lossy().into_owned()
        ),
        args.join(" ")
    );
    // The error is named, not discarded. `driver did not answer` alone says a
    // spawn failed and leaves the reader to guess at which of its causes: a
    // driver that is not there, one that is not executable, or an `ETXTBSY` from
    // a concurrent write to the program being executed. A flaky failure of this
    // branch was diagnosed twice from the absence of a path alone, which is what
    // the errno was there to say. Formatted `{:#}` rather than `{}`: anyhow's
    // plain form prints the outermost context only, which named the program and
    // dropped the `os error` under it.
    let probe = match compile::capture(driver, &args) {
        Ok(probe) => probe,
        Err(why) => return Err(format!("driver did not answer {query}: {why:#}")),
    };
    // A query that failed is not the driver's answer, whatever it printed: a wrapper's
    // plausible path before it exits non-zero would be published as the linker's, and
    // nothing downstream holds a path to anything. No `PATH` search stands in for it.
    if let Some(ended) = refusal(&probe) {
        return Err(format!(
            "{query} {ended}, so chard read no linker path from its output"
        ));
    }
    let printed = probe.stdout.trim().to_owned();
    if printed.is_empty() {
        return Err(format!("{query} printed nothing"));
    }
    if Path::new(&printed).components().count() > 1 {
        Ok((
            PathBuf::from(&printed),
            PathSource::Driver,
            format!("{query} printed {printed}"),
        ))
    } else {
        // A bare name is the driver saying its own search directories do not
        // hold the program. gcc's collect2 and clang's linker lookup then fall
        // through to PATH, so chard searches the same PATH and says that it did.
        match find_on_path(&printed, search_path) {
            Some(found) => {
                let how = format!(
                    "{query} printed the bare name `{printed}`, which chard resolved on \
                             PATH to {}",
                    found.display()
                );
                Ok((found, PathSource::PathSearch, how))
            }
            None => Err(format!(
                "{query} printed the bare name `{printed}`, and it is on neither \
                         the driver's search path nor PATH"
            )),
        }
    }
}

/// The body, with the search path as a parameter so a test can supply a directory of shims.
///
/// The link line is read first, because it is what the driver runs. `-print-prog-name=ld`
/// ignores `-fuse-ld=` in both drivers, and a driver that is a wrapper adding one itself
/// (`exec clang -fuse-ld=lld "$@"`) answered it with the default `ld`: measured on
/// 2026-09-28 on Fedora 44 aarch64, clang 22.1.8, where the report published GNU ld while
/// every link went through ld.lld. The wrapper's flag is on the link line, in the program
/// clang runs and on the argv gcc hands `collect2` (gcc 16.2.1 on the same host, the same
/// day). The profile's own selection reaches the line too, so the line agrees with it
/// whenever no wrapper or configuration file added one. A driver whose `-###` names no
/// link, or that exited other than 0 on it ([`read_link_line`]), keeps the earlier route,
/// and the detection says which happened before it names that route: the fallback
/// question where the profile names no file, and the profile's own naming where it does.
/// Without the cause in the detection, a profile's `--ld-path=` under a driver that
/// rejected `-###` would read as if the line had agreed.
/// `workdir` is [`read_link_line`]'s, for the driver's words the detection quotes.
fn detect_linker_on(
    driver: &Path,
    profile_flags: &[String],
    search_path: &OsStr,
    workdir: &Path,
) -> Linker {
    let profile_selection = link_selection(profile_flags);
    let read = read_link_line(driver, &profile_selection.consulted, workdir);
    let mut effective = profile_flags.to_vec();
    effective.extend(read.adds);
    let line_says = read.runs;
    let unread = read.unread;
    let mut selection = link_selection(&effective);
    // What the report calls the profile's flags stays the profile's.
    selection.consulted.clone_from(&profile_selection.consulted);
    let unknown = |why: String| Linker {
        kind: UNKNOWN_KIND.to_owned(),
        version: None,
        path: None,
        path_source: None,
        profile_flags: selection.consulted.clone(),
        detection: why,
        artifact: None,
        cxx: None,
    };

    // Where the linker is, who says so, and the prose that records it.
    let (path, source, how) = match &selection.program {
        Some(Program::File(file)) => match &line_says {
            // The profile named this file and the line runs it: the profile said so first.
            Some(said)
                if profile_selection.program.as_ref() != Some(&Program::File(file.clone())) =>
            {
                (file.clone(), PathSource::Driver, said.clone())
            }
            _ => (
                file.clone(),
                PathSource::Profile,
                format!(
                    "{}the profile names {} outright",
                    unread
                        .as_ref()
                        .map_or_else(String::new, |said| format!("{said}, and ")),
                    file.display()
                ),
            ),
        },
        Some(Program::Default | Program::Named(_)) | None => {
            let lead = line_says
                .as_ref()
                .or(unread.as_ref())
                .map_or_else(String::new, |said| format!("{said}, and "));
            match ask_for_program(driver, &selection, &lead, search_path) {
                Ok(found) => found,
                Err(why) => return unknown(why),
            }
        }
    };

    // A linker that could not be run, and one whose `--version` ran and failed, keep the
    // path the route above found and give no kind or version: a failed job's banner is
    // not the linker's, and the `.comment` witness holds only lld and mold to theirs.
    let refused = match compile::capture(&path, &["--version".to_owned()]) {
        Ok(version) => match refusal(&version) {
            None => Ok(version),
            Some(ended) => Err(format!(
                "{how}; its --version {ended}, so chard read no kind or version from it"
            )),
        },
        Err(why) => Err(format!("{how}; it did not answer --version: {why:#}")),
    };
    let version = match refused {
        Ok(version) => version,
        Err(detection) => {
            return Linker {
                kind: UNKNOWN_KIND.to_owned(),
                version: None,
                path: Some(path.display().to_string()),
                path_source: Some(source),
                profile_flags: selection.consulted,
                detection,
                artifact: None,
                cxx: None,
            };
        }
    };
    let banner = first_line(&version.stdout);
    let kind = linker_kind(&banner);
    // What the banner established, said as such: a linker that prints nothing is
    // `unknown` for want of evidence, and the detection says which of the three
    // outcomes the banner produced.
    let tail = if banner.is_empty() {
        "it printed no --version banner, so the kind is unknown"
    } else if kind == UNKNOWN_KIND {
        "its --version banner is not one chard recognises"
    } else {
        "its --version banner names the kind"
    };
    Linker {
        kind: kind.to_owned(),
        version: (!banner.is_empty()).then_some(banner),
        path: Some(path.display().to_string()),
        path_source: Some(source),
        profile_flags: selection.consulted,
        detection: format!("{how}; {tail}"),
        artifact: None,
        cxx: None,
    }
}

/// Refuse the driver's intrinsic `-dM -E` dump where it cannot be read: where it defined no
/// macro ([`no_macros_message`]), or exited non-zero, whatever it printed first, or exited 0
/// with its output cut off partway through a line. `kind`,
/// `version`, the arch gate's macro witness and the width and byte order it publishes are
/// all read from this dump in [`detect`].
fn intrinsic_dump_read(
    driver: &Path,
    macros: &BTreeMap<String, String>,
    record: &compile::BuildRecord,
    work: &Path,
) -> Result<()> {
    let hint = || {
        format!(
            "check that the compiler runs in the environment chard gives it, which holds \
             nothing else: `{} <cc> -dM -E -x c /dev/null`",
            compiler_environment_spelled()
        )
    };
    if macros.is_empty() {
        return Err(UserError::with_hint(no_macros_message(driver, record), hint()).into());
    }
    // A listing that ran on past an error is a prefix of unknown length. Only emptiness was
    // tested here, while every variant's dump was refused on its status, so a driver that
    // printed its defines and then failed was measured. Refused through the reading
    // `Variant::macro_dump_failure` uses, which reads a listing cut off under a driver that
    // exited 0 as failed too: a cut `#define __clang_major__ 2` from `22` was clang 2.
    if let Some(ended) = record.dump_failure(Some(work)) {
        return Err(UserError::with_hint(
            format!(
                "{}: its intrinsic `-dM -E` macro dump printed {} macro definitions and \
                 {ended}; a dump that failed is not read, since what it printed before the \
                 failure is a prefix of unknown length",
                driver.display(),
                macros.len()
            ),
            hint(),
        )
        .into());
    }
    Ok(())
}

/// The driver's `-fhardened -O2` dump and its control under `-O2` ([`FhardenedFortify`]).
///
/// Never a query failure: a driver that refuses `-fhardened` is the ordinary case (clang),
/// and the reading records how each dump ended. A dump that cannot be run at all ends the
/// detection, as the intrinsic one does, since the driver it runs is that one.
fn fhardened_fortify(driver_path: &Path, work: &Path) -> Result<FhardenedFortify> {
    let flags = FHARDENED_DUMP_FLAGS.map(str::to_owned);
    let (macros, record) =
        compile::macro_dump(driver_path, Lang::C, &flags, false, work, "fhardened")
            .context("dumping macros under -fhardened -O2")?;
    let flags = FHARDENED_BASELINE_FLAGS.map(str::to_owned);
    let (baseline, baseline_record) = compile::macro_dump(
        driver_path,
        Lang::C,
        &flags,
        false,
        work,
        "fhardened-baseline",
    )
    .context("dumping macros under -O2, the control of the -fhardened dump")?;
    Ok(FhardenedFortify::from_dumps(
        &macros,
        &record,
        &baseline,
        &baseline_record,
    ))
}

/// Interrogate a compiler. `work` receives the throwaway sources used for the
/// macro dumps; they are retained as evidence.
/// # Errors
///
/// Errors when the driver cannot be resolved, cannot be run, or defines no
/// predefined macros at all, the last of which means it is not a working C
/// compiler and no channel could be measured with it. Errors too when its intrinsic
/// dump exits non-zero, whatever it printed first.
pub fn detect(driver_name: &str, work: &Path, emit_macros: bool) -> Result<Detected> {
    let driver_path = resolve_driver(driver_name)?;

    // The spawn's own io error stays the root, so `error::classify` reads its errno
    // (`ENOEXEC` the caller's, `EACCES` on an executable mode the filesystem's, `ETXTBSY`
    // a retry) with the driver named once, by `compile::capture`'s context.
    // A `--version` that ran and failed is not the driver's banner, whatever it printed:
    // refused as the queries below are, so `toolchain.version_raw` is absent and `run.id`
    // is taken without it.
    let mut query_failures = Vec::new();
    let version_raw = answered(
        Ok(compile::capture(&driver_path, &["--version".to_owned()])
            .context("asking the driver for its version")?),
        "--version",
        VERSION_RAW_FIELD,
        "toolchain.version_raw is absent; kind and version are read from the macro dump",
        &mut query_failures,
    )
    .map(|r| first_line(&r.stdout));

    let (macros_intrinsic, intrinsic_record) =
        compile::macro_dump(&driver_path, Lang::C, &[], false, work, "intrinsic")
            .context("dumping compiler-intrinsic macros")?;
    let (macros_with_headers, headers_record) =
        compile::macro_dump(&driver_path, Lang::C, &[], true, work, "with-headers")
            .context("dumping macros with libc headers")?;

    intrinsic_dump_read(&driver_path, &macros_intrinsic, &intrinsic_record, work)?;

    let fhardened_fortify = fhardened_fortify(&driver_path, work)?;
    if macros_with_headers.is_empty() {
        // Not fatal on its own: `kind` and `version` below come from the intrinsic dump,
        // and every macro-channel arm takes its own with-headers dump per variant, which
        // is where a failure would reach a verdict as `indeterminate`. What is lost here
        // is libc identification and `__USE_FORTIFY_LEVEL`, so it must be visible rather
        // than silently degrade the report.
        crate::error::note(&format!(
            "libc headers could not be preprocessed ({}); libc detection and \
             __USE_FORTIFY_LEVEL will be unavailable",
            headers_record
                .dump_failure(Some(work))
                .unwrap_or_else(|| { "exited 0 and defined no macros".to_owned() })
        ));
    }
    // A dump that errored and produced macros anyway is a case seen on Darwin. A reader
    // that looked only at whether the map was empty could not tell "the compiler objected
    // but kept going" from a clean run, nor a listing cut off under a driver that exited 0.
    // Recorded in the
    // report rather than noted on stderr, because the report is what gets read later, and
    // read through the status reading every other dump is, so [`Detected::headers_dump`]
    // hands the libc identification the failure on exactly the runs the field is on.
    let libc_headers_error = headers_record.dump_failure(Some(work));

    let kind = if macros_intrinsic.contains_key("__clang__") {
        Kind::Clang
    } else if macros_intrinsic.contains_key("__GNUC__") {
        Kind::Gcc
    } else {
        Kind::Other
    };
    let version = version_from_macros(kind, &macros_intrinsic);
    let arch_macros = arch_macros(&macros_intrinsic);
    let arch_abi = Abi::from_dump(&macros_intrinsic);

    // A query that did not exit 0 is not the driver's answer, whatever it printed first:
    // [`answered`] refuses its output and keeps how it ended, so a failed `-dumpmachine`
    // publishes no `toolchain.target_triple` (every reader of the triple, the arch gate and
    // the fortify bar among them, then reads it as unread) and a failed `-v` no configure
    // line and no configuration file, with a diagnostic for each.
    let target_triple = answered(
        compile::capture(&driver_path, &["-dumpmachine".to_owned()]),
        "-dumpmachine",
        TRIPLE_FIELD,
        "toolchain.target_triple is absent, as it is for a driver that names no triple, and \
         the architecture the checks gate on is read where toolchain.target.source names",
        &mut query_failures,
    )
    .map(|r| first_line(&r.stdout))
    .filter(|s| !s.is_empty());

    // -v writes its report to stderr and needs an input to get past the driver;
    // an empty preprocess is the cheapest one.
    let verbose = answered(
        compile::capture(
            &driver_path,
            &[
                "-v".to_owned(),
                "-E".to_owned(),
                "-x".to_owned(),
                "c".to_owned(),
                "/dev/null".to_owned(),
            ],
        ),
        VERBOSE_QUERY,
        CONFIG_FILES_FIELD,
        "toolchain.configure_args and toolchain.config_files are absent, which does not say \
         the driver loads no configuration file, so a bare column's profile.flags_source \
         `none` does not rule one out, as profile.toolchain_note says",
        &mut query_failures,
    );
    let (configure_args, config_files) = verbose
        .as_ref()
        .map_or((None, Vec::new()), |r| parse_verbose(&r.stderr));

    let cxx_driver_path = compile::cxx_driver_for(&driver_path);

    // Hash the with-headers dump, which subsumes the intrinsic one and includes
    // libc's conclusions.
    let mut canonical = String::new();
    for (name, value) in &macros_with_headers {
        use std::fmt::Write as _;
        crate::error::best_effort(writeln!(canonical, "{name}={value}"));
    }

    Ok(Detected {
        kind,
        version,
        version_raw,
        target_triple,
        driver: driver_path.display().to_string(),
        cxx_driver: cxx_driver_path.as_ref().map(|p| p.display().to_string()),
        configure_args,
        config_files,
        query_failures,
        // The driver's default; `Detected::link_with` replaces it once the profile is
        // known, when the profile selects another.
        linker: detect_linker(&driver_path, &[], work),
        // Held to the artifacts after the sweep, by `target_agreement`.
        target: None,
        predefined_macros_sha256: digest::sha256_hex(canonical.as_bytes()),
        predefined_macros: emit_macros.then(|| macros_with_headers.clone()),
        libc_headers_error,
        fhardened_fortify,
        macros_with_headers,
        arch_macros,
        arch_abi,
        // Taken by `Detected::dump_with` once the profile is known.
        profile_macros: None,
        profile_macros_cxx: None,
        driver_path,
        cxx_driver_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `-fhardened` reading over the answers measured on 2026-10-21 (gcc 16 on Fedora 44,
    /// clang 22.1.8, gcc 13 and 15 in Ubuntu 24.04 and 26.04 images, gcc 15.2.0 on Alpine
    /// 3.25), and the flags each dump is taken under, held: without `-O2` gcc defines no level
    /// under `-fhardened` and warns, so every gcc would fall back to the library.
    #[test]
    fn the_fhardened_reading_takes_only_a_level_the_option_itself_set() {
        assert_eq!(FHARDENED_DUMP_FLAGS, ["-fhardened", "-O2"]);
        assert_eq!(FHARDENED_BASELINE_FLAGS, ["-O2"]);
        let macros = |fortify: Option<&str>| {
            let mut m = BTreeMap::from([("__GNUC__".to_owned(), "16".to_owned())]);
            if let Some(level) = fortify {
                m.insert("_FORTIFY_SOURCE".to_owned(), level.to_owned());
            }
            m
        };
        let record = |exit_status: i32, stderr: &str| compile::BuildRecord {
            argv: Vec::new(),
            dropped_flags: Vec::new(),
            exit_status,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };
        let read = |with: Option<&str>, exit: i32, stderr: &str, without: Option<&str>| {
            FhardenedFortify::from_dumps(
                &macros(with),
                &record(exit, stderr),
                &macros(without),
                &record(0, ""),
            )
        };
        // gcc 16, Fedora 44: 3 against none.
        let fedora = read(Some("3"), 0, "", None);
        assert_eq!(fedora.refusal(), None);
        assert_eq!(fedora.fortify_source.as_deref(), Some("3"));
        // clang 22.1.8 and gcc 13: the token refused.
        for line in [
            "clang: error: unknown argument: '-fhardened'",
            "gcc: error: unrecognized command-line option '-fhardened'",
        ] {
            let refused = FhardenedFortify::from_dumps(
                &BTreeMap::new(),
                &record(1, &format!("{line}\n")),
                &macros(None),
                &record(0, ""),
            );
            assert_eq!(refused.diagnostic.as_deref(), Some(line));
            assert!(refused.refusal().is_some_and(|r| r.contains(line)));
        }
        // gcc 15, Ubuntu 26.04: its specs' -D, said by -Whardened, 3 against 3.
        let warned = "cc1: warning: '_FORTIFY_SOURCE' is not enabled by '-fhardened' because it \
                      was specified in '-D' or '-U' [-Whardened]";
        let ubuntu = read(Some("3"), 0, &format!("{warned}\n"), Some("3"));
        assert_eq!(ubuntu.diagnostic.as_deref(), Some(warned));
        assert!(ubuntu.refusal().is_some());
        // gcc 15.2.0, Alpine 3.25: 2 against 2, no warning.
        let alpine = read(Some("2"), 0, "", Some("2"));
        assert!(alpine.refusal().is_some_and(|r| r.contains("as well")));
        // A `-Whardened` line that does not spell the option is a diagnostic of it too.
        let w_only = "cc1: warning: '_FORTIFY_SOURCE' is not enabled because optimizations are \
                      turned off [-Whardened]";
        let warned = read(Some("3"), 0, &format!("{w_only}\n"), None);
        assert_eq!(warned.diagnostic.as_deref(), Some(w_only));
        // The control read from its own record: failed, cut or empty, it attributes nothing,
        // and one defining a level above the option's is not the option raising it.
        let control = |exit: i32, cut: bool, defined: usize, level: Option<&str>| {
            let mut base_macros = BTreeMap::new();
            for i in 0..defined {
                base_macros.insert(format!("M{i}"), String::new());
            }
            if let Some(level) = level {
                base_macros.insert("_FORTIFY_SOURCE".to_owned(), level.to_owned());
            }
            FhardenedFortify::from_dumps(
                &macros(Some("3")),
                &record(0, ""),
                &base_macros,
                &compile::BuildRecord {
                    stdout_unterminated: cut,
                    ..record(exit, "")
                },
            )
        };
        assert_eq!(control(0, false, 5, None).refusal(), None);
        assert_eq!(
            control(0, false, 5, Some("2")).refusal(),
            None,
            "raised from 2 to 3"
        );
        for (shape, read) in [
            ("failed", control(1, false, 5, None)),
            ("cut", control(0, true, 5, None)),
            ("empty", control(0, false, 0, None)),
            ("equal", control(0, false, 5, Some("3"))),
            ("higher", control(0, false, 5, Some("4"))),
            ("unreadable", control(0, false, 5, Some("x"))),
        ] {
            assert!(read.refusal().is_some(), "{shape}: {read:?}");
        }
        // A stderr line about something else is no diagnostic of the option.
        let other = read(Some("3"), 0, "cc1: warning: some other thing\n", None);
        assert_eq!(other.diagnostic, None);
        assert_eq!(other.refusal(), None);
    }

    /// The no-macros hint spells the environment the compiler is given, so the command it
    /// suggests fails the way chard's invocation did, with `PATH` where chard has one and
    /// without it where chard has none.
    #[test]
    fn the_no_macros_hint_spells_the_compiler_environment() {
        let spelled = |lookup: fn(&str) -> Option<std::ffi::OsString>,
                       added: &compile::EnvPairs| {
            compiler_environment_spelled_as(compile::compiler_environment_from(lookup, added))
        };
        let none = compile::EnvPairs::default();
        assert_eq!(
            spelled(|_| Some("/bin".into()), &none),
            "env -i PATH=\"$PATH\" LC_ALL=C TERM=dumb"
        );
        assert_eq!(spelled(|_| None, &none), "env -i LC_ALL=C TERM=dumb");
        let added = compile::compiler_environment_additions(
            &[
                "NIX_HARDENING_ENABLE=fortify pic",
                "QUOTE=it's $HOME",
                "EMPTY=",
                "PLAIN=a=b,c",
            ]
            .map(str::to_owned),
        )
        .expect("plain pairs");
        assert_eq!(
            spelled(|_| None, &added),
            "env -i EMPTY='' NIX_HARDENING_ENABLE='fortify pic' PLAIN=a=b,c \
             QUOTE='it'\\''s $HOME' LC_ALL=C TERM=dumb"
        );
    }

    /// [`arch_of_triple`] reads [`TRIPLE_ARCHS`], every row of it, and passes any other first
    /// component through as written.
    #[test]
    fn arch_of_triple_reads_the_table() {
        for (component, arch) in TRIPLE_ARCHS {
            assert_eq!(
                arch_of_triple(&format!("{component}-unknown-linux-gnu")).as_deref(),
                Some(*arch),
                "{component}"
            );
        }
        for passthrough in ["riscv64", "x86", "powerpc64le", "arm64e"] {
            assert_eq!(
                arch_of_triple(&format!("{passthrough}-unknown-linux-gnu")).as_deref(),
                Some(passthrough),
                "{passthrough}"
            );
        }
        assert_eq!(
            arch_of_triple("i686").as_deref(),
            Some("x86"),
            "a bare component"
        );
    }

    /// The compiler family's name is the one the gates and the report agree on.
    ///
    /// `Kind::as_str` reaches three places that must all say the same word: the published
    /// `toolchain.kind`, the `compiler_unsupported` gate lists in the probe corpus, and
    /// the rule that turns a driver's "I do not know that flag" into `unsupported`. A
    /// mutant returning the empty string or a constant leaves every one of them agreeing
    /// with itself and with nothing else; the gates stop matching, so a declared
    /// compiler limitation silently stops applying.
    #[test]
    fn the_compiler_family_names_are_the_ones_the_gates_use() {
        assert_eq!(Kind::Gcc.as_str(), "gcc");
        assert_eq!(Kind::Clang.as_str(), "clang");
        assert_eq!(Kind::Other.as_str(), "other");

        // The names are not free-standing: the corpus declares limitations against them,
        // so a rename here silently disarms those gates rather than failing to compile.
        let declared: std::collections::BTreeSet<&str> = crate::probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .flat_map(|c| c.gate.compiler_unsupported.iter().copied())
            .collect();
        assert!(
            !declared.is_empty(),
            "the corpus declares at least one compiler limitation, or this test proves nothing"
        );
        let known: std::collections::BTreeSet<&str> = [Kind::Gcc, Kind::Clang, Kind::Other]
            .iter()
            .map(|k| k.as_str())
            .collect();
        assert!(
            declared.is_subset(&known),
            "the corpus names compiler families this type cannot produce: {:?}",
            declared.difference(&known).collect::<Vec<_>>()
        );
    }

    #[test]
    fn target_selecting_flags_take_both_spellings_in_order() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            target_selecting_flags(&line("-O2 -m32 -fcf-protection=full -Wl,-z,now")),
            vec!["-m32"]
        );
        assert_eq!(
            target_selecting_flags(&line(
                "-target i686-linux-gnu -O2 --target=x86_64-linux-gnu -arch x86_64 -m64"
            )),
            vec![
                "-target",
                "i686-linux-gnu",
                "--target=x86_64-linux-gnu",
                "-arch",
                "x86_64",
                "-m64"
            ]
        );
        assert!(
            target_selecting_flags(&line("-O2 -march=i686 -mfpmath=sse -m32bit -target"))
                .is_empty(),
            "an ISA or tuning flag selects no target, and a dangling -target takes no value"
        );
    }

    /// A word the driver hands to another tool is that tool's option, so none of the three
    /// selection readers takes it or the word that hands it: `-Xlinker -L/x` is GNU ld's `-L`,
    /// which both drivers put after their own directories, `-Xclang -resource-dir -Xclang /x`
    /// is `-cc1`'s option, and so on for every word of `Hand::Tool`, gcc's `--for-`
    /// abbreviations and clang's offload and analyzer words among them. A two-word selection
    /// after clang's `-Xarch_<arch>`, which clang refuses, a dangling `-Xarch_`, and an
    /// `-Xarch_` pair whose word is a hardening flag select nothing either (a hardening flag
    /// must not ride into an arm on a pair), and the words around a hand-on are still read.
    /// gcc's `cc1` reads `-isysroot` handed through `-Xpreprocessor` or a `-Wp,` list as the
    /// driver would, so those are carried as a system root, and nothing else goes through the
    /// preprocessor. Measured on 2026-10-08 with clang 22.1.8 and gcc 16.1.1 on Fedora 44
    /// x86_64; until that day all three readers read the word after a hand-on as the driver's
    /// own.
    #[test]
    fn a_word_handed_to_another_tool_selects_nothing() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let hands_on = [
            "--for-assembler -m32",
            "--for-a -L/srv/x",
            "--for-as -m32",
            "--for-assemble -m32",
            "--for-l -L/srv/x",
            "--for-li -L/srv/x",
            "-Xoffload-linker -L/srv/x",
            "-Xopenmp-target -L/srv/x",
            "-Xopenmp-target=x86_64-unknown-linux-gnu -L/srv/x",
            "-Xcuda-ptxas -L/srv/x",
            "-Xcuda-fatbinary -L/srv/x",
            "-Xanalyzer -m32",
            "-Xclangas -m32",
            "-Xlinker -L/srv/x",
            "--for-linker -L/srv/x",
            "-Xclang -L/srv/x",
            "-Xlinker -m32",
            "-Xlinker --sysroot=/srv/x",
            "-Xassembler -m32",
            "-mllvm -m32",
            "-Xpreprocessor -D_X",
            "-Xpreprocessor -isysroot /srv/x",
            "-Xoffload-linkerx86_64-unknown-linux-gnu -fuse-ld=bfd",
            "-Xclang -resource-dir -Xclang /srv/x",
            "-Xlinker -stdlib=libc++",
            "-Xlinker --gcc-install-dir=/srv/g",
            "-Xclang -static-libgcc",
            "-Xlinker -fuse-ld=lld",
            "-Xlinker -B/srv/b",
            "--for-linker --ld-path=/srv/ld",
            "-Xarch_x86_64 -fcf-protection=full",
            "-Xarch_x86_64 -O2",
            "-Xarch_x86_64 -Wl,-z,now",
            "-Xarch_x86_64 -target i686-linux-gnu",
            "-Xarch_x86_64 -B /srv/b",
            "-Xarch_x86_64 --stdlib libc++",
            "-Xarch_x86_64 -I /srv/i",
            "-Xarch_x86_64 -include /srv/f.h",
            "-Xlinker -I/srv/i",
            "--for-linker -include/srv/f.h",
            "-Xclang -isystem/srv/s",
            "-Xclang -undef",
            "-Xpreprocessor -I",
            "-Xpreprocessor -pthread",
            "-Xarch_x86_64",
        ];
        let mut fed = 0_usize;
        for spelling in hands_on {
            let flags = line(&format!("-O2 {spelling} -fcf-protection=full"));
            assert!(
                target_selecting_flags(&flags).is_empty(),
                "`{spelling}` selects no target"
            );
            assert!(
                runtime_selecting_flags(&flags).is_empty(),
                "`{spelling}` selects no runtime"
            );
            assert!(
                header_selecting_flags(&flags).is_empty(),
                "`{spelling}` selects no header"
            );
            assert_eq!(
                link_selection(&flags),
                LinkSelection::default(),
                "`{spelling}` selects no linker"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed, 45,
            "every hand-on spelling was put through the four readers"
        );
        assert_eq!(
            target_selecting_flags(&line("-O2 -Xflang -L/srv/x")),
            line("-L/srv/x"),
            "gcc 16.1.1 reads the word after -Xflang as its own, and clang rejects -Xflang"
        );
        assert!(
            runtime_removing_flags(&line(
                "-O2 --for-assembler -nostdlib -Xoffload-linker -nostartfiles -Xclangas -nostdinc \
                 --for-a -nolibc"
            ))
            .is_empty(),
            "a removal handed to another tool is that tool's word, not the driver's"
        );
        let after = line(
            "-O2 -Xlinker -L/srv/x -m32 -Xclang -z -stdlib=libc++ -Xpreprocessor -I -pthread \
             -fuse-ld=lld",
        );
        assert_eq!(target_selecting_flags(&after), line("-m32"));
        assert_eq!(runtime_selecting_flags(&after), line("-stdlib=libc++"));
        assert_eq!(header_selecting_flags(&after), line("-pthread"));
        assert_eq!(linker_program_flags(&after), line("-fuse-ld=lld"));
    }

    /// A selection spelled as the value of a two-token option that selects nothing is that
    /// option's value and no reader's: `-u -B/x` is the symbol named `-B/x` and no prefix,
    /// `-MF -L/x` a dependency file and no library directory, `-o -I/x` an output and no
    /// header directory, `-D -m32` a macro and no target, `-z -fuse-ld=lld` a linker keyword
    /// and no program; the linker reader consults nothing from such a value either. Then
    /// every spelling of `VALUE_TWO_TOKEN`, and of each abbreviation range of
    /// `VALUE_ABBREVIATED` from its shortest to one short of the whole, before `-B/x` and
    /// before `-m32`: no reader takes the value, the words around the pair are still read,
    /// and the option dangling at the end of the list takes nothing; the removal reader
    /// passes over the value too (`runtime_removing_flags` says why). The bounds of the
    /// ranges are held as literals by `every_abbreviation_bound_is_the_measured_one`, and
    /// the table's members by `the_value_taking_table_holds_the_measured_spellings`.
    #[test]
    fn a_value_taking_option_takes_the_word_after_it() {
        one_reader("-O2 -u -B/x", "", "", "", "", "");
        one_reader("-O2 -MF -L/x", "", "", "", "", "");
        one_reader("-O2 -o -I/x", "", "", "", "", "");
        one_reader("-O2 -D -m32", "", "", "", "", "");
        one_reader("-O2 -z -fuse-ld=lld", "", "", "", "", "");
        one_reader("-O2 -m32 -u -B/x -I/i", "-m32", "", "-I/i", "", "");
        one_reader(
            "-O2 -MF -L/x -L/y -o -I/x -pthread",
            "-L/y",
            "",
            "-pthread",
            "",
            "",
        );
        one_reader(
            "-O2 -z -fuse-ld=lld --ld-path=/l",
            "",
            "",
            "",
            "--ld-path=/l",
            "--ld-path=/l",
        );
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let mut spellings: Vec<String> = VALUE_TWO_TOKEN.iter().map(|s| (*s).to_owned()).collect();
        let mut bounds = 0_usize;
        for (alias, shortest) in VALUE_ABBREVIATED {
            assert!(
                alias.starts_with(shortest) && shortest.len() < alias.len(),
                "{shortest} is a proper prefix of {alias}"
            );
            for end in shortest.len()..alias.len() {
                spellings.push(alias[..end].to_owned());
            }
            bounds = bounds.saturating_add(1);
        }
        assert_eq!(bounds, VALUE_ABBREVIATED.len(), "every range was fed");
        let mut fed = 0_usize;
        for spelling in &spellings {
            assert!(takes_a_value(spelling), "{spelling} takes a value");
            for value in ["-B/x", "-m32", "-I/i", "-fuse-ld=lld", "-nostdlib"] {
                let flags = line(&format!("-O2 {spelling} {value} -fcf-protection=full"));
                assert!(
                    target_selecting_flags(&flags).is_empty()
                        && runtime_selecting_flags(&flags).is_empty()
                        && header_selecting_flags(&flags).is_empty()
                        && link_selection(&flags) == LinkSelection::default()
                        && runtime_removing_flags(&flags).is_empty(),
                    "`{spelling} {value}` is the option's value and no reader's word"
                );
            }
            let around = line(&format!("-m32 {spelling} -B/x -I/i -fuse-ld=lld"));
            assert_eq!(target_selecting_flags(&around), line("-m32"), "{spelling}");
            assert_eq!(header_selecting_flags(&around), line("-I/i"), "{spelling}");
            assert_eq!(
                linker_program_flags(&around),
                line("-fuse-ld=lld"),
                "{spelling}"
            );
            let dangling = line(&format!("-O2 -m32 {spelling}"));
            assert_eq!(
                target_selecting_flags(&dangling),
                line("-m32"),
                "{spelling} dangling takes nothing and selects nothing"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, spellings.len(), "every spelling was fed");
        assert!(
            fed > VALUE_TWO_TOKEN.len() + VALUE_ABBREVIATED.len(),
            "the abbreviation ranges were walked: {fed} spellings"
        );
    }

    /// The bounds `every_abbreviation_bound_is_the_measured_one` holds: (shortest taken, one
    /// shorter, whole spelling), then the class of each: value, divided, target, runtime, or none.
    const ABBREVIATION_BOUNDS: [(&str, &str, &str, &str, &str, &str); 29] = [
        ("--asser", "--asse", "--assert", "value", "none", "value"),
        ("--def", "--de", "--define-macro", "value", "none", "value"),
        (
            "--dumpbase-",
            "--dumpbase",
            "--dumpbase-ext",
            "value",
            "value",
            "value",
        ),
        ("--dumpd", "--dump", "--dumpdir", "value", "value", "value"),
        (
            "--embed-dire",
            "--embed-dir",
            "--embed-directory",
            "value",
            "none",
            "value",
        ),
        ("--en", "--e", "--entry", "value", "none", "divided"),
        ("--forc", "--for", "--force-link", "value", "none", "value"),
        ("--im", "--i", "--imacros", "header", "none", "header"),
        ("--la", "--l", "--language", "value", "none", "value"),
        (
            "--output-",
            "--output",
            "--output-pch",
            "value",
            "value",
            "none",
        ),
        (
            "--print-f",
            "--print-",
            "--print-file-name",
            "value",
            "none",
            "value",
        ),
        (
            "--print-p",
            "--print-",
            "--print-prog-name",
            "value",
            "none",
            "value",
        ),
        ("--sp", "--s", "--specs", "value", "none", "value"),
        ("--un", "--u", "--undefine-macro", "value", "none", "value"),
        ("--sys", "--sy", "--sysroot", "target", "none", "target"),
        (
            "--li",
            "--l",
            "--library-directory",
            "target",
            "none",
            "target",
        ),
        ("--pref", "--pre", "--prefix", "runtime", "none", "runtime"),
        (
            "--include-directory-",
            "--include-directory",
            "--include-directory-after",
            "divided",
            "header",
            "header",
        ),
        (
            "--include-p",
            "--include-",
            "--include-prefix",
            "divided",
            "none",
            "value",
        ),
        (
            "--include-with-prefix-a",
            "--include-with-prefix-",
            "--include-with-prefix-after",
            "divided",
            "none",
            "value",
        ),
        (
            "--include-with-prefix-b",
            "--include-with-prefix-",
            "--include-with-prefix-before",
            "divided",
            "none",
            "value",
        ),
        (
            "--for-l",
            "--for-",
            "--for-linker",
            "hand-on",
            "none",
            "hand-on",
        ),
        (
            "--for-a",
            "--for-",
            "--for-assembler",
            "hand-on",
            "none",
            "hand-on",
        ),
        ("--op", "--o", "--optimize", "driver", "none", "driver"),
        (
            "--no-standard-l",
            "--no-standard-",
            "--no-standard-libraries",
            "driver",
            "none",
            "driver",
        ),
        (
            "--no-standard-i",
            "--no-standard-",
            "--no-standard-includes",
            "driver",
            "none",
            "driver",
        ),
        (
            "--include-b",
            "--include-",
            "--include-barrier",
            "header-joined",
            "none",
            "header-joined",
        ),
        ("--sh", "--s", "--shared", "driver", "none", "driver"),
        (
            "--static-",
            "--static",
            "--static-pie",
            "driver",
            "driver",
            "driver",
        ),
    ];

    /// Members of the value-taking table, by name (`the_value_taking_table_holds_the_measured_spellings`).
    const VALUE_SPELLINGS_TAKEN: [&str; 56] = [
        "-u",
        "-z",
        "-MF",
        "-MT",
        "-MQ",
        "-o",
        "-D",
        "-U",
        "-A",
        "-x",
        "-e",
        "-l",
        "-T",
        "--force-link",
        "--output",
        "--language",
        "--param",
        "-specs",
        "--specs",
        "-F",
        "-iprefix",
        "-iwithprefix",
        "-iwithprefixbefore",
        "-imultilib",
        "-dumpdir",
        "--include-prefix",
        "--include-with-prefix",
        "--include-with-prefix-after",
        "--include-with-prefix-before",
        "--assert",
        "--define-macro",
        "--undefine-macro",
        "--print-file-name",
        "--print-prog-name",
        "-aux-info",
        "-wrapper",
        "--dump",
        "--dumpbase",
        "--dumpbase-ext",
        "--dumpdir",
        "-imultiarch",
        "-J",
        "--embed-directory",
        "-Xf",
        "-serialize-diagnostics",
        "-MJ",
        "-rpath",
        "-framework",
        "--config",
        "-cxx-isystem",
        "-iframework",
        "-iwithsysroot",
        "-working-directory",
        "-mmlir",
        "-V",
        "-Zlinker-input",
    ];

    /// Words of no value-taking class, by name: a driver's own flag, a selection, a hand-on, a
    /// joined form, a mode flag, a divided word, an abbreviation one short of its bound, and
    /// gcc's long spellings of a selection (`--include` is `-include`, the header's) or of a
    /// word that joins the next (`--std` is `-std=`).
    const VALUE_SPELLINGS_NOT_TAKEN: [&str; 60] = [
        "-c",
        "-S",
        "-E",
        "-fsyntax-only",
        "-O2",
        "-fPIE",
        "-pthread",
        "-m32",
        "-m64",
        "-B/x",
        "-L/x",
        "-I/x",
        "-Wl,-z,now",
        "-u-x",
        "-o/x",
        "--output=x",
        "-specs=/s",
        "-l/x",
        "-DX",
        "-Tbss",
        "-dumpbase",
        "--entry",
        "-dependency-file",
        "-undefined",
        "-L",
        "-B",
        "-I",
        "-include",
        "-isystem",
        "-target",
        "-arch",
        "--sysroot",
        "--prefix",
        "--library-directory",
        "--stdlib",
        "--rtlib",
        "-resource-dir",
        "-Xlinker",
        "-Xclang",
        "-mllvm",
        "--for-linker",
        "-Xarch_x86_64",
        "-Xpreprocessor",
        "-print-prog-name=ld",
        "--version",
        "-d",
        "-h",
        "-R",
        "--sys",
        "--li",
        "--pref",
        "-Wp,-nostdinc",
        "--include",
        "--include-directory",
        "--include-directory-after",
        "--imacros",
        "--std",
        "",
        "-",
        "--",
    ];

    /// Every row of `LONG_ALIASES` is read as its short spelling in each form gcc takes,
    /// written as literals so a swapped or dropped row fails here: the long spelling alone,
    /// its shortest abbreviation (where gcc takes one) and the word one shorter (no alias),
    /// its `=` form where gcc joins one, and the words it joins; the generic map on the words
    /// the readers own and on none a table holds; `spelled_alone` is idempotent; no alias is
    /// also a value-taking or divided spelling as written (a row may be a selection's own
    /// spelling, as `--sysroot` is); each shortest prefix is a proper prefix of its long
    /// spelling, and none where the divided table has the row; and the rows name the
    /// thirty, each once. Counted against the rows and the extra cases.
    /// The rows `every_long_alias_is_read_as_its_short_spelling` holds: (the long spelling,
    /// what it reads as alone, its shortest abbreviation or "", the `=v` form's reading or
    /// "" where gcc refuses it).
    const LONG_ALIAS_ROWS: [(&str, &str, &str, &str); 30] = [
        ("--machine", "--machine", "", "-mv"),
        ("--optimize", "-O", "--op", "-Ov"),
        ("--std", "--std", "", "-std=v"),
        ("--define-macro", "-D", "--def", "-Dv"),
        ("--undefine-macro", "-U", "--un", "-Uv"),
        ("--include", "-include", "", "-includev"),
        ("--imacros", "-imacros", "--im", "-imacrosv"),
        ("--include-directory", "-I", "", "-Iv"),
        ("--include-directory-after", "-idirafter", "", "-idirafterv"),
        ("--include-prefix", "-iprefix", "", "-iprefixv"),
        ("--include-with-prefix", "-iwithprefix", "", "-iwithprefixv"),
        (
            "--include-with-prefix-before",
            "-iwithprefixbefore",
            "",
            "-iwithprefixbeforev",
        ),
        (
            "--include-with-prefix-after",
            "-iwithprefix",
            "",
            "-iwithprefixv",
        ),
        ("--include-barrier", "-I-", "--include-b", ""),
        ("--sysroot", "--sysroot", "--sys", "--sysroot=v"),
        ("--library-directory", "-L", "--li", "-Lv"),
        ("--prefix", "-B", "--pref", "-Bv"),
        ("--force-link", "-u", "--forc", "-uv"),
        ("--language", "-x", "--la", "-xv"),
        ("--output", "-o", "", "-ov"),
        ("--assert", "-A", "--asser", "-Av"),
        ("--specs", "-specs", "--sp", "-specs=v"),
        ("--for-linker", "-Xlinker", "--for-l", ""),
        ("--for-assembler", "-Xassembler", "--for-a", ""),
        (
            "--no-standard-libraries",
            "-nostdlib",
            "--no-standard-l",
            "",
        ),
        ("--no-standard-includes", "-nostdinc", "--no-standard-i", ""),
        ("--pie", "-pie", "", ""),
        ("--shared", "-shared", "--sh", ""),
        ("--static", "-static", "", ""),
        ("--static-pie", "-static-pie", "--static-", ""),
    ];

    #[test]
    fn every_long_alias_is_read_as_its_short_spelling() {
        let mut fed = 0_usize;
        for (long, alone, shortest, joined) in LONG_ALIAS_ROWS {
            let row = LONG_ALIASES
                .iter()
                .find(|a| a.long == long)
                .unwrap_or_else(|| panic!("{long} is a row of the table"));
            assert_eq!(
                row.shortest.is_some(),
                !shortest.is_empty(),
                "{long}: the table takes an abbreviation where this row names one"
            );
            assert_eq!(spelled_alone(long), alone, "{long} alone");
            assert_eq!(spelled_alone(alone), alone, "{alone} is read as itself");
            if !shortest.is_empty() {
                assert_eq!(spelled_alone(shortest), alone, "{shortest} is {long}");
                let shorter = shortest
                    .get(..shortest.len().saturating_sub(1))
                    .unwrap_or("");
                // One short of the bound names no alias, unless it is another row's whole
                // spelling (`--static` under `--static-`, `--include-directory` under
                // `--include-directory-`), which gcc reads as that row.
                let another_row = LONG_ALIASES.iter().any(|a| a.long == shorter);
                assert!(
                    explicit_alias_of(shorter).is_none() || another_row,
                    "{shorter} is one short of the bound and names no alias"
                );
                let whole_but_one = long.get(..long.len().saturating_sub(1)).unwrap_or("");
                assert_eq!(
                    spelled_alone(whole_but_one),
                    alone,
                    "{whole_but_one} is {long}"
                );
            }
            let eq_form = format!("{long}=v");
            if joined.is_empty() {
                assert!(
                    explicit_alias_of(&eq_form).is_none(),
                    "{eq_form} is no joined form of the table"
                );
            } else {
                assert_eq!(spelled_alone(&eq_form), joined, "{eq_form}");
                assert_eq!(spelled_alone(joined), joined, "{joined} is read as itself");
            }
            // The row's long spelling is no other table's as written.
            assert!(
                !VALUE_TWO_TOKEN.contains(&long) && !divided_word(long),
                "{long} is an alias and no value-taking or divided spelling"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, LONG_ALIASES.len(), "every row was fed");
        for alias in &LONG_ALIASES {
            if let Some(shortest) = alias.shortest {
                assert!(
                    alias.long.starts_with(shortest) && shortest.len() < alias.long.len(),
                    "{}'s shortest {shortest} is a proper prefix of it",
                    alias.long
                );
            }
            assert!(
                LONG_ALIAS_ROWS.iter().any(|row| row.0 == alias.long),
                "{} has a row",
                alias.long
            );
        }
        let mut longs: Vec<&str> = LONG_ALIAS_ROWS.iter().map(|row| row.0).collect();
        longs.sort_unstable();
        longs.dedup();
        assert_eq!(
            longs.len(),
            LONG_ALIASES.len(),
            "the rows name each alias once"
        );
        for (long, shortest) in DIVIDED_ABBREVIATED {
            let row = LONG_ALIASES.iter().find(|a| a.long == long);
            assert!(
                row.is_some_and(|a| a.shortest.is_none()),
                "{long}: the whole spelling is an alias and its prefixes from {shortest} are \
                 divided, so the alias row takes no abbreviation of its own"
            );
        }
    }

    /// The words an alias joins (`--machine 32` is `-m32` as the pair, `--std c99` is
    /// `-std=c99`, `--machine-32` is `-m32` alone, and `--machine` alone joins nothing),
    /// gcc's generic map on the words the readers own and on none a table holds, and the
    /// spellings some table owns as written, which stay as written; each a literal, counted.
    #[test]
    fn the_joined_words_the_generic_map_and_the_owned_spellings_read_as_measured() {
        let mut fed = 0_usize;
        let joins: [(&str, Option<&str>, &str, usize); 6] = [
            ("--machine", Some("32"), "-m32", 2),
            ("--std", Some("c99"), "-std=c99", 2),
            ("--machine-32", None, "-m32", 1),
            ("--machine", None, "--machine", 1),
            ("--def", Some("X"), "-D", 2),
            ("--li", Some("/x"), "-L", 2),
        ];
        for (word, next, spelled, span) in joins {
            let reading = read(word, next);
            assert_eq!(
                (&*reading.word, reading.span()),
                (spelled, span),
                "{word} {next:?}"
            );
            fed = fed.saturating_add(1);
        }
        // gcc's generic map, on words the readers own and on none a table holds.
        let generic: [(&str, &str); 10] = [
            ("--use-ld=gold", "-fuse-ld=gold"),
            ("--no-pie", "-fno-pie"),
            ("--PIC", "-fPIC"),
            ("--no-pic", "-fno-pic"),
            ("--plugin=/srv/p.so", "-fplugin=/srv/p.so"),
            ("--profile-use=rel", "-fprofile-use=rel"),
            ("--stack-protector-strong", "-fstack-protector-strong"),
            ("--hardened", "-fhardened"),
            ("--def=X", "-fdef=X"),
            ("--no-stack-clash-protection", "-fno-stack-clash-protection"),
        ];
        for (word, mapped) in generic {
            assert_eq!(
                spelled_alone(word),
                mapped,
                "{word} through the generic map"
            );
            fed = fed.saturating_add(1);
        }
        // Words some table owns as written stay as written: clang's own long spellings, the
        // value-taking and divided ones, the joined hand-ons, `--param=`, and no `--word`.
        let owned: [&str; 14] = [
            "--sysroot=/r",
            "--target=x86_64-linux-gnu",
            "--rtlib=compiler-rt",
            "--stdlib",
            "--gcc-toolchain=/g",
            "--ld-path=/ld",
            "--no-default-config",
            "--param=x=1",
            "--param",
            "--entry",
            "--include-p",
            "--for-linker=-z",
            "--",
            "---x",
        ];
        for word in owned {
            assert_eq!(spelled_alone(word), word, "{word} is read as written");
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed,
            joins.len() + generic.len() + owned.len(),
            "every case was fed"
        );
    }

    /// Each abbreviation range's bound, as measured (gcc 16.1.1 under `-###`, the ledger's
    /// sweep): the shortest prefix gcc took, as a literal, is of its class, and the word one
    /// shorter is of none, or is the whole spelling of another option (`--dump` before
    /// `--dumpd`, `--output` before `--output-`, `--include` before `--include-p`); the whole
    /// spelling is of its own class. Written as literals so that a moved bound in the
    /// tables fails here, which a bound read back from the tables cannot.
    #[test]
    fn every_abbreviation_bound_is_the_measured_one() {
        // (shortest taken, one shorter, whole spelling), the class of each: value, divided,
        // target, runtime, header (two-token or joined, as `-I-` is), linker, none, or
        // another value-taking whole spelling.
        let classes = ABBREVIATION_BOUNDS;
        let class = |word: &str| -> &'static str {
            match (takes_a_value(word), selection_word(word), hand(word)) {
                (true, None, Hand::Value) => "value",
                (false, Some((Owner::Nobody, _)), _) => "divided",
                (false, Some((Owner::Target { .. }, Takes::Two)), _) => "target",
                (false, Some((Owner::Runtime, Takes::Two)), _) => "runtime",
                (false, Some((Owner::Header, Takes::Two)), _) => "header",
                (false, Some((Owner::Header, Takes::One)), _) => "header-joined",
                (false, Some((Owner::Runtime, Takes::One)), _) => "runtime-joined",
                (false, Some((Owner::Target { .. }, Takes::One)), _) => "target-joined",
                (false, Some((Owner::Linker, _)), _) => "linker",
                (false, None, Hand::Tool) => "hand-on",
                // A word of the driver's own: an alias read as one (`--op` as `-O`,
                // `--no-standard-l` as `-nostdlib`), or a word that names no option.
                (false, None, Hand::Driver) => {
                    if explicit_alias_of(word).is_some() {
                        "driver"
                    } else {
                        "none"
                    }
                }
                other => panic!("{word} is of no class this test names: {other:?}"),
            }
        };
        let mut fed = 0_usize;
        for (shortest, shorter, whole, of_shortest, of_shorter, of_whole) in classes {
            assert!(whole.starts_with(shortest) && shortest.starts_with(shorter));
            assert_eq!(class(shortest), of_shortest, "{shortest}");
            assert_eq!(class(shorter), of_shorter, "{shorter}");
            assert_eq!(class(whole), of_whole, "{whole}");
            fed = fed.saturating_add(1);
        }
        let aliases_abbreviated = LONG_ALIASES
            .iter()
            .filter(|alias| alias.shortest.is_some())
            .count();
        assert_eq!(
            fed,
            VALUE_ABBREVIATED.len() + DIVIDED_ABBREVIATED.len() + aliases_abbreviated,
            "every range of the three tables was fed"
        );
    }

    /// The value-taking table holds the spellings the sweep measured, by name: a sample of
    /// each group as literals (both drivers, gcc alone, clang alone), and words no table
    /// holds, so a swapped or dropped entry fails here where the table's length cannot see
    /// it: a flag of the driver's own, a selection, a hand-on, a joined form, a mode flag.
    #[test]
    fn the_value_taking_table_holds_the_measured_spellings() {
        let taken = VALUE_SPELLINGS_TAKEN;
        let not_taken = VALUE_SPELLINGS_NOT_TAKEN;
        let mut fed = 0_usize;
        for word in taken {
            assert!(
                takes_a_value(word),
                "{word} takes the next word, as measured"
            );
            fed = fed.saturating_add(1);
        }
        for word in not_taken {
            assert!(!takes_a_value(word), "{word} takes no value as this class");
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, taken.len() + not_taken.len(), "every word was fed");
    }

    /// gcc's abbreviations of the three two-token selection spellings are the selections:
    /// `--sys /r` is the system root `--sysroot /r`, `--li /x` the library directory `-L /x`
    /// and `--pref /p/` the search prefix `--prefix /p/`, each read by its whole spelling's
    /// reader, carried as written, and the prefix consulted by the linker reader as `-B/p/`;
    /// the words one short of each bound are no reader's (`target_word` and `runtime_word`
    /// have the measurement).
    #[test]
    fn gccs_abbreviations_of_the_selection_spellings_are_the_selections() {
        one_reader("-O2 --sys /r -m32", "--sys /r -m32", "", "", "", "");
        one_reader("-O2 --sysr /r", "--sysr /r", "", "", "", "");
        one_reader("-O2 --li /x -I/i", "--li /x", "", "-I/i", "", "");
        one_reader(
            "-O2 --library-directo /x",
            "--library-directo /x",
            "",
            "",
            "",
            "",
        );
        one_reader("-O2 --pref /p/", "", "--pref /p/", "", "", "--pref /p/");
        one_reader(
            "-O2 --prefi /p/ -fuse-ld=lld",
            "",
            "--prefi /p/",
            "",
            "-fuse-ld=lld",
            "--prefi /p/ -fuse-ld=lld",
        );
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            link_selection(&line("-O2 --pref /p/")).prefixes,
            vec!["-B/p/".to_owned()],
            "the abbreviated prefix is a prefix the detection looks under"
        );
        assert!(
            !selects_target(&line("-O2 --sys /r --li /x")),
            "a root and a directory choose no target"
        );
        // A selection spelled as such an abbreviation's value is the value: `--li -B/x` is a
        // directory named `-B/x`.
        one_reader("-O2 --li -B/x", "--li -B/x", "", "", "", "");
        one_reader("-O2 --pref -I/i", "", "--pref -I/i", "", "", "--pref -I/i");
        for short in ["--sy", "--l", "--pre"] {
            let flags = line(&format!("-O2 {short} -B/x"));
            assert_eq!(
                runtime_selecting_flags(&flags),
                line("-B/x"),
                "{short} names no option, so the word after it is read on its own"
            );
        }
    }

    /// The three classes of a word that takes the next one are disjoint: no value-taking
    /// spelling (`VALUE_TWO_TOKEN`, the abbreviation ranges) or divided one
    /// (`DIVIDED_TWO_TOKEN`, its ranges) is a selection reader's spelling or a hand-on, no
    /// word is both value-taking and divided, and each divided range's whole spelling is a
    /// value-taking word of both drivers while its abbreviations are not. So `hand` and
    /// `selection_word` answer for any word from at most one class whichever is asked first.
    #[test]
    fn a_value_taking_option_is_no_selection_and_no_hand_on() {
        let mut values: Vec<String> = VALUE_TWO_TOKEN.iter().map(|s| (*s).to_owned()).collect();
        for (alias, shortest) in VALUE_ABBREVIATED {
            values.extend((shortest.len()..alias.len()).map(|end| alias[..end].to_owned()));
        }
        let mut divided: Vec<String> = DIVIDED_TWO_TOKEN.iter().map(|s| (*s).to_owned()).collect();
        for (alias, shortest) in DIVIDED_ABBREVIATED {
            assert!(
                alias.starts_with(shortest) && shortest.len() < alias.len(),
                "{shortest} is a proper prefix of {alias}"
            );
            assert!(
                takes_a_word(alias),
                "{alias} whole takes the next word on both drivers (as a value, or as the \
                 header selection `--include-directory-after` is read as)"
            );
            divided.extend((shortest.len()..alias.len()).map(|end| alias[..end].to_owned()));
        }
        let mut fed = 0_usize;
        for word in &values {
            let selected = target_word(word).is_some()
                || runtime_word(word).is_some()
                || header_word(word).is_some()
                || linker_word(word);
            assert!(
                !selected,
                "{word} takes a value and is no reader's spelling"
            );
            assert_eq!(
                hand(word),
                Hand::Value,
                "{word} is the driver's own value-taking option"
            );
            assert!(!divided_word(word), "{word} is not divided");
            fed = fed.saturating_add(1);
        }
        for word in &divided {
            let selected = target_word(word).is_some()
                || runtime_word(word).is_some()
                || header_word(word).is_some()
                || linker_word(word);
            assert!(!selected, "{word} is divided and no reader's spelling");
            assert_eq!(
                hand(word),
                Hand::Driver,
                "{word} is read by the driver whose flag it is"
            );
            assert!(divided_word(word), "{word} is divided");
            assert_eq!(
                selection_word(word),
                Some((Owner::Nobody, Takes::One)),
                "{word} is nobody's and passes over itself"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, values.len() + divided.len(), "every word was fed");
        let mut sorted = values.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            values.len(),
            "no value-taking spelling is listed twice"
        );
    }

    /// gcc's `cc1` reads `-isysroot` handed through `-Xpreprocessor` or a `-Wp,` list as the
    /// driver would (measured 2026-10-08 with gcc 16.1.1 on Fedora 44 x86_64: the `-v -E`
    /// search list moved to the root as under the driver's own `-isysroot`; clang's `-cc1` left
    /// it unchanged), so the target reader carries each spelling as written, as a system root
    /// and not a target, and the runtime and linker readers take nothing from it.
    #[test]
    fn a_system_root_handed_to_the_preprocessor_is_carried_as_written() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        for root in [
            "-Xpreprocessor -isysroot -Xpreprocessor /srv/x",
            "-Xpreprocessor -isysroot/srv/x",
            "-Wp,-isysroot,/srv/x",
            "-Wp,-O2,-isysroot/srv/x",
        ] {
            let flags = line(&format!("-O2 {root} -m32"));
            assert_eq!(
                target_selecting_flags(&flags),
                line(&format!("{root} -m32")),
                "`{root}` is a system root cc1 reads as the driver would, carried as written"
            );
            assert!(
                runtime_selecting_flags(&flags).is_empty()
                    && link_selection(&flags) == LinkSelection::default(),
                "`{root}` selects no runtime and no linker"
            );
        }
        assert!(
            !selects_target(&line("-Wp,-isysroot,/srv/x")),
            "a system root through the preprocessor chooses no target"
        );
    }

    /// A one-word selection after clang's `-Xarch_<arch>` is carried as the pair, whatever the
    /// architecture named (each reader is fed an `-Xarch_aarch64` pair on an x86_64 line), so
    /// the arms get what the measured build got, applied or inert ([`Hand::Arch`] has which):
    /// the target, runtime and header readers each take their own pairs and not another's, a root
    /// pair chooses no target and a `-m32` pair does, and the linker reader consults both pairs
    /// and carries the program pair, chooses no program (clang 22.1.8 ran the default linker
    /// under `-Xarch_x86_64 -fuse-ld=lld`, measured 2026-10-08) and takes no search prefix from
    /// a pair.
    #[test]
    fn a_one_word_selection_after_xarch_is_carried_as_the_pair() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let pairs = [
            ("-Xarch_x86_64 -mmusl", "target"),
            ("-Xarch_x86_64 -m32", "target"),
            ("-Xarch_x86_64 --sysroot=/srv/r", "target"),
            ("-Xarch_aarch64 --sysroot=/srv/r", "target"),
            ("-Xarch_x86_64 -L/srv/l", "target"),
            ("-Xarch_x86_64 --rtlib=compiler-rt", "runtime"),
            ("-Xarch_aarch64 --rtlib=compiler-rt", "runtime"),
            ("-Xarch_x86_64 -static-libgcc", "runtime"),
            ("-Xarch_x86_64 --gcc-install-dir=/srv/g", "runtime"),
            ("-Xarch_x86_64 -B/srv/b", "runtime"),
            ("-Xarch_x86_64 -I/srv/i", "header"),
            ("-Xarch_aarch64 -isystem/srv/s", "header"),
            ("-Xarch_x86_64 -include/srv/f.h", "header"),
            ("-Xarch_x86_64 -undef", "header"),
            ("-Xarch_x86_64 -pthread", "header"),
        ];
        let mut fed = 0_usize;
        for (spelling, reader) in pairs {
            let flags = line(&format!("-O2 {spelling} -Wl,-z,now"));
            let (target, runtime, header) = (
                target_selecting_flags(&flags),
                runtime_selecting_flags(&flags),
                header_selecting_flags(&flags),
            );
            let (own, others) = match reader {
                "target" => (target, [runtime, header]),
                "runtime" => (runtime, [target, header]),
                "header" => (header, [target, runtime]),
                other => panic!("no reader is called {other}"),
            };
            assert_eq!(own, line(spelling), "`{spelling}` is carried as the pair");
            assert!(
                others.iter().all(Vec::is_empty),
                "`{spelling}` is the {reader} reader's alone: {others:?}"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 15, "every pair was put through the three readers");
        assert!(
            !selects_target(&line("-O2 -Xarch_aarch64 --sysroot=/srv/r")),
            "a root through -Xarch_ chooses no target"
        );
        assert!(
            selects_target(&line("-O2 -Xarch_x86_64 -m32")),
            "a target through -Xarch_ chooses one, as the driver is handed it"
        );
        let linker = link_selection(&line(
            "-O2 -Xarch_aarch64 -fuse-ld=lld -Xarch_x86_64 -B/srv/b",
        ));
        assert_eq!(
            linker.consulted,
            line("-Xarch_aarch64 -fuse-ld=lld -Xarch_x86_64 -B/srv/b"),
            "both pairs are consulted, as the driver was handed them"
        );
        assert_eq!(
            linker.program_flags,
            line("-Xarch_aarch64 -fuse-ld=lld"),
            "an arm that links carries the program pair"
        );
        assert_eq!(
            linker.program, None,
            "clang reads -fuse-ld= through -Xarch_ as nothing, so the detection looks for no program"
        );
        assert!(
            linker.prefixes.is_empty(),
            "a prefix through -Xarch_ is the runtime selection's to carry, not a search prefix"
        );
    }

    /// One shape of `a_value_one_reader_takes_is_no_other_readers_option`: the list, then
    /// what each reader returns for it, the target's, the runtime's, the header's, the
    /// linker's program flags and what the linker reader consulted.
    fn one_reader(
        list: &str,
        target: &str,
        runtime: &str,
        header: &str,
        program: &str,
        read: &str,
    ) {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let flags = line(list);
        assert_eq!(
            target_selecting_flags(&flags),
            line(target),
            "{list}: the target's"
        );
        assert_eq!(
            runtime_selecting_flags(&flags),
            line(runtime),
            "{list}: the runtime's"
        );
        assert_eq!(
            header_selecting_flags(&flags),
            line(header),
            "{list}: the header's"
        );
        assert_eq!(
            linker_program_flags(&flags),
            line(program),
            "{list}: the linker's program flags"
        );
        assert_eq!(
            linker_selecting_flags(&flags),
            line(read),
            "{list}: what the linker consulted"
        );
        let every = [target, runtime, header, program]
            .iter()
            .flat_map(|s| line(s))
            .count();
        assert!(
            every < flags.len(),
            "{list}: the readers together return at most the words after -O2, each once"
        );
    }

    /// A word one reader takes as the value of its two-token option is no other reader's
    /// option: `-L -B/x` is the target reader's library directory named `-B/x` and no runtime
    /// prefix, `-L -I/x` its directory and no header word, `-B -pthread` the runtime's prefix
    /// named `-pthread` and no header word, and so on through every pair of readers, the
    /// linker's program flags and the longer options nobody carries among them; the linker
    /// reader consults no prefix from such a value either. Each shape is fed to all four
    /// readers and to `link_selection` ([`one_reader`]), and the arms carry the words once
    /// (`measure::tests::the_arms_carry_a_two_token_value_once` holds that end).
    #[test]
    fn a_value_one_reader_takes_is_no_other_readers_option() {
        one_reader("-O2 -L -B/x", "-L -B/x", "", "", "", "");
        one_reader("-O2 -L -I/x", "-L -I/x", "", "", "", "");
        one_reader("-O2 -B -pthread", "", "-B -pthread", "", "", "-B -pthread");
        one_reader("-O2 -L -fuse-ld=lld", "-L -fuse-ld=lld", "", "", "", "");
        one_reader(
            "-O2 --library-directory -B/x",
            "--library-directory -B/x",
            "",
            "",
            "",
            "",
        );
        one_reader("-O2 -arch -B/x", "-arch -B/x", "", "", "", "");
        one_reader(
            "-O2 -target -include/x",
            "-target -include/x",
            "",
            "",
            "",
            "",
        );
        one_reader("-O2 --sysroot -m32", "--sysroot -m32", "", "", "", "");
        one_reader(
            "-O2 -isysroot -pthread",
            "-isysroot -pthread",
            "",
            "",
            "",
            "",
        );
        one_reader("-O2 --stdlib -pthread", "", "--stdlib -pthread", "", "", "");
        one_reader("-O2 --rtlib -I/x", "", "--rtlib -I/x", "", "", "");
        one_reader(
            "-O2 --prefix -I/x",
            "",
            "--prefix -I/x",
            "",
            "",
            "--prefix -I/x",
        );
        one_reader(
            "-O2 -resource-dir -L/x",
            "",
            "-resource-dir -L/x",
            "",
            "",
            "",
        );
        one_reader(
            "-O2 -ccc-install-dir --ld-path=/x",
            "",
            "-ccc-install-dir --ld-path=/x",
            "",
            "",
            "",
        );
    }

    /// The second half of `a_value_one_reader_takes_is_no_other_readers_option`: the header
    /// reader's values, the longer options nobody carries (alone they pass over themselves,
    /// and as another reader's value they are that value), the root through the
    /// preprocessor, a pair after `-Xarch_`, and a line every reader takes from, each
    /// word once; the search prefix is never a value the target took.
    #[test]
    fn a_header_value_a_longer_option_and_a_mixed_line_are_read_once() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        one_reader("-O2 -I -m32", "", "", "-I -m32", "", "");
        one_reader("-O2 -isystem -B/x", "", "", "-isystem -B/x", "", "");
        one_reader(
            "-O2 -include --sysroot=/r",
            "",
            "",
            "-include --sysroot=/r",
            "",
            "",
        );
        one_reader(
            "-O2 -imacros -fuse-ld=lld",
            "",
            "",
            "-imacros -fuse-ld=lld",
            "",
            "",
        );
        one_reader("-O2 -isystem-after -L", "", "", "", "", "");
        one_reader("-O2 -include-pch -B/x", "", "-B/x", "", "", "-B/x");
        one_reader("-O2 -isystem-after -m32 -L/y", "-m32 -L/y", "", "", "", "");
        one_reader("-O2 -isystem-after -I/x", "", "", "-I/x", "", "");
        one_reader(
            "-O2 -L -isystem-after -m32",
            "-L -isystem-after -m32",
            "",
            "",
            "",
            "",
        );
        one_reader(
            "-O2 -B -include-pch -I/x",
            "",
            "-B -include-pch",
            "-I/x",
            "",
            "-B -include-pch",
        );
        let root = "-Xpreprocessor -isysroot -Xpreprocessor -B/x";
        one_reader(&format!("-O2 {root}"), root, "", "", "", "");
        one_reader("-O2 -Xarch_x86_64 -L -B/x", "", "-B/x", "", "", "-B/x");
        one_reader(
            "-O2 -L -B/x -B/y -I/z",
            "-L -B/x",
            "-B/y",
            "-I/z",
            "",
            "-B/y",
        );
        let prefix = link_selection(&line("-O2 -L -B/x -B/y"));
        assert_eq!(
            prefix.prefixes,
            line("-B/y"),
            "the search prefix is the runtime's word, never a value the target took"
        );
    }

    /// Every divided spelling, by name, as the sweep measured it: the table's own length
    /// cannot see a swapped entry.
    const DIVIDED_BY_NAME: [&str; 21] = [
        "-dialect",
        "-dumpbase",
        "-dumpbase-ext",
        "--entry",
        "-Tbss",
        "-Tdata",
        "-Ttext",
        "-darwin-target-variant",
        "-darwin-target-variant-triple",
        "-dependency-dot",
        "-dependency-file",
        "-dsym-dir",
        "-dylib_file",
        "-dylinker_install_name",
        "-exported_symbols_list",
        "-lazy_framework",
        "-lazy_library",
        "-object-file-name",
        "-umbrella",
        "-undefined",
        "-unexported_symbols_list",
    ];

    /// Each divided spelling held by name is of the class and in the table (`DIVIDED_BY_NAME`),
    /// and the table holds nothing else.
    #[test]
    fn every_divided_spelling_is_held_by_name() {
        for word in DIVIDED_BY_NAME {
            assert!(
                divided_word(word),
                "{word} is a divided spelling, as measured"
            );
            assert!(
                DIVIDED_TWO_TOKEN.contains(&word),
                "{word} is in the table by name"
            );
        }
        assert_eq!(DIVIDED_BY_NAME.len(), DIVIDED_TWO_TOKEN.len());
    }

    /// The lists with a divided pair and the pair found in each
    /// (`the_pairs_the_drivers_read_differently_are_found_and_nothing_else_is`).
    const DIVIDED_PAIRS_FOUND: [(&str, &str); 20] = [
        ("-O2 -isystem-after -m32", "-isystem-after -m32"),
        ("-include-pch -B/x -O2", "-include-pch -B/x"),
        ("-O2 -isystem-after -I/x -fPIE", "-isystem-after -I/x"),
        ("-O2 -include-pch -fuse-ld=lld", "-include-pch -fuse-ld=lld"),
        (
            "-O2 -isystem-after --sysroot -m32",
            "-isystem-after --sysroot",
        ),
        (
            "-O2 -isystem-after -isystem-after -m32",
            "-isystem-after -m32",
        ),
        ("-L -isystem-after -include-pch -m32", "-include-pch -m32"),
        ("-O2 -Tbss -B/x", "-Tbss -B/x"),
        ("-O2 -dependency-file -L/x", "-dependency-file -L/x"),
        ("-O2 --entry -m32", "--entry -m32"),
        ("-O2 --include-p -I/x", "--include-p -I/x"),
        (
            "-O2 --include-directory-afte -B/x",
            "--include-directory-afte -B/x",
        ),
        ("-O2 -undefined -fuse-ld=lld", "-undefined -fuse-ld=lld"),
        // A divided word before a word that takes one: gcc reads `-u` as `-Tbss`'s
        // value and `-B/x` as a prefix, clang `-T bss` and `-u -B/x`.
        ("-O2 -Tbss -u -B/x", "-Tbss -u"),
        ("-O2 -dependency-file -o -B/x", "-dependency-file -o"),
        ("-O2 -Tbss -Xlinker -L/x", "-Tbss -Xlinker"),
        (
            "-O2 --entry -Xpreprocessor -isysroot /r",
            "--entry -Xpreprocessor",
        ),
        ("-O2 -Tbss -u", "-Tbss -u"),
        // A chain in mixed directions: gcc takes `-undefined` as `-Tbss`'s address and
        // reads `-B/x` as a prefix, clang reads `-T bss` and `-undefined -B/x`; the
        // second word is the pair found.
        ("-O2 -Tbss -undefined -B/x", "-undefined -B/x"),
        ("-O2 -Tbss -undefined -u -B/x", "-undefined -u"),
    ];

    /// A longer header option alone, or a word one driver takes a value for and the other
    /// reads as its own (`-Tbss`, `-dependency-file`, gcc's abbreviation `--include-p`),
    /// before a word a reader takes is the pair the drivers read differently, found as
    /// written from any position and from either list order, and nothing else is: the joined
    /// spelling, a value no reader takes, a dangling option, the pair handed to another tool
    /// or after `-Xarch_`, and the pair taken as the value of an option that selects nothing
    /// (`driver_divided_pairs` says why; clang refuses a two-word option after `-Xarch_`
    /// outright). Every divided spelling is fed before `-m32`.
    #[test]
    fn the_pairs_the_drivers_read_differently_are_found_and_nothing_else_is() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let found = DIVIDED_PAIRS_FOUND;
        let mut divided = 0_usize;
        let mut every: Vec<String> = DIVIDED_TWO_TOKEN.iter().map(|s| (*s).to_owned()).collect();
        for (alias, shortest) in DIVIDED_ABBREVIATED {
            every.extend((shortest.len()..alias.len()).map(|end| alias[..end].to_owned()));
        }
        for word in &every {
            assert_eq!(
                driver_divided_pairs(&line(&format!("-O2 {word} -m32 -fPIE"))),
                vec![format!("{word} -m32")],
                "{word} before a target word is divided"
            );
            assert!(
                driver_divided_pairs(&line(&format!("-O2 {word} -O3 -m32"))).is_empty(),
                "{word} before a word no reader takes is not"
            );
            divided = divided.saturating_add(1);
        }
        assert_eq!(divided, every.len(), "every divided spelling was fed");
        let mut fed = 0_usize;
        for (list, pair) in found {
            assert_eq!(driver_divided_pairs(&line(list)), vec![pair], "{list}");
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, found.len(), "every pair was fed");
        assert_eq!(
            driver_divided_pairs(&line("-isystem-after -m32 -O2 -include-pch -B/x")),
            vec![
                "-isystem-after -m32".to_owned(),
                "-include-pch -B/x".to_owned()
            ],
            "both pairs, in order"
        );
        for passes in [
            "-O2 -L -isystem-after -m32",
            "-O2 -isystem-after/srv/i -m32",
            "-O2 -isystem-after=/srv/i -m32",
            "-O2 -isystem-after /srv/i -m32",
            "-O2 -include-pch /srv/p.pch -B/x",
            "-O2 -isystem-after -O3",
            "-O2 -isystem-after",
            "-O2 -Xlinker -isystem-after -m32",
            "-O2 -Xpreprocessor -include-pch -B/x",
            "-O2 -Xarch_x86_64 -isystem-after -m32",
            "-O2 -I -isystem-after -m32",
            "-O2 -u -Tbss -m32",
            "-O2 -T -dependency-file -B/x",
            "-O2 -Tbss 0x1000 -B/x",
            "-O2 --include-directory-after -B/x",
            "-O2 --include-prefix -I/x",
            "-O2 -Tbss",
            // Two divided words of one driver's in a row flip the readings twice, back into
            // step (gcc takes `-Tdata` as `-Tbss`'s address; clang reads two scripts); a
            // chain in mixed directions is caught at its second word (below).
            "-O2 -Tbss -Tdata 0x1 -B/x",
            "-O2 -Tbss -Tbss -O3",
        ] {
            assert!(
                driver_divided_pairs(&line(passes)).is_empty(),
                "{passes} reads the same under either driver, or the measured build fails first"
            );
        }
    }

    /// No selection the walk returns is longer than `LONGEST_SELECTION`, and the root
    /// through the preprocessor is exactly that long, so the bound the fuzz target's
    /// one-reader law searches to is the walk's own.
    #[test]
    fn no_selection_is_longer_than_the_bound() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let root = line("-O2 -Xpreprocessor -isysroot -Xpreprocessor /x -m32");
        let longest = selections(&root)
            .iter()
            .map(|(_, words)| words.len())
            .max()
            .expect("the root is a selection");
        assert_eq!(
            longest, LONGEST_SELECTION,
            "the root through the preprocessor"
        );
        let every = line(
            "-O2 -L -B/x -L -I/x -B -pthread -L -fuse-ld=lld --library-directory -B/px/ -arch \
             -B/x --stdlib -pthread --prefix -I/x -resource-dir -L/x -I -m32 -include \
             --sysroot=/r -Xarch_x86_64 -L/y -Xarch_x86_64 -B/x -Xpreprocessor -isysroot/x \
             -Xpreprocessor -isysroot -Xpreprocessor /x -target t -isysroot /r -include-pch \
             /p -isystem-after /a -m32 -m64 --target=t -mmusl --no-sysroot-suffix",
        );
        let mut fed = 0_usize;
        for (_, words) in selections(&every) {
            assert!(
                words.len() <= LONGEST_SELECTION,
                "{words:?} is longer than the bound"
            );
            fed = fed.saturating_add(1);
        }
        assert!(fed >= 20, "the line holds every shape: {fed} selections");
    }

    /// No spelling one reader names is, or begins, a spelling another names, so
    /// `selection_word` answers for any word from at most one reader whichever is asked
    /// first: every pair across the lists the classifiers read (`TARGET_WHOLE`,
    /// `TARGET_TWO_TOKEN`, `TARGET_JOINED`, `ROOT_WHOLE`, `ROOT_TWO_TOKEN`, `ROOT_JOINED` and
    /// the `-Wp,` clause for the target; `RUNTIME_TWO_TOKEN`, `RUNTIME_JOINED`,
    /// `RUNTIME_WHOLE`; `HEADER_VALUED`, `HEADER_WHOLE`, `HEADER_LONGER`; `LINKER_JOINED`)
    /// is prefix-free, and each spelling, bare and joined to a value, is its own reader's
    /// and no other's.
    #[test]
    fn no_spelling_is_two_readers() {
        let lists: [(&[&str], &str); 13] = [
            (&TARGET_WHOLE, "target"),
            (&TARGET_TWO_TOKEN, "target"),
            (&TARGET_JOINED, "target"),
            (&ROOT_WHOLE, "target"),
            (&ROOT_TWO_TOKEN, "target"),
            (&ROOT_JOINED, "target"),
            (&["-Wp,-isysroot"], "target"),
            (&RUNTIME_TWO_TOKEN, "runtime"),
            (&RUNTIME_JOINED, "runtime"),
            (&RUNTIME_WHOLE, "runtime"),
            (&HEADER_VALUED, "header"),
            (&HEADER_WHOLE, "header"),
            (&HEADER_LONGER, "header"),
        ];
        let mut spellings: Vec<(&str, &str)> = Vec::new();
        let mut counted = 0_usize;
        for (list, reader) in lists {
            spellings.extend(list.iter().map(|s| (*s, reader)));
            counted = counted.saturating_add(list.len());
        }
        spellings.extend(LINKER_JOINED.iter().map(|s| (*s, "linker")));
        counted = counted.saturating_add(LINKER_JOINED.len());
        assert_eq!(spellings.len(), counted, "every list was fed");
        assert!(
            spellings.len() == 70,
            "the lists hold the 70 spellings the readers take (a list grew or shrank): {}",
            spellings.len()
        );
        // The spellings read joined to a value: their joined forms are their reader's alone.
        let joined: Vec<(&str, &str)> = [
            (&TARGET_JOINED[..], "target"),
            (&ROOT_JOINED[..], "target"),
            (&RUNTIME_JOINED[..], "runtime"),
            (&HEADER_VALUED[..], "header"),
            (&LINKER_JOINED[..], "linker"),
        ]
        .iter()
        .flat_map(|(list, reader)| list.iter().map(move |s| (*s, *reader)))
        .collect();
        assert_eq!(
            joined.len(),
            TARGET_JOINED.len()
                + ROOT_JOINED.len()
                + RUNTIME_JOINED.len()
                + HEADER_VALUED.len()
                + LINKER_JOINED.len(),
            "every joined list was fed"
        );
        let readers = |word: &str| -> Vec<&'static str> {
            let mut answered = Vec::new();
            if target_word(word).is_some() {
                answered.push("target");
            }
            if runtime_word(word).is_some() {
                answered.push("runtime");
            }
            if header_word(word).is_some() {
                answered.push("header");
            }
            if linker_word(word) {
                answered.push("linker");
            }
            answered
        };
        let mut pairs = 0_usize;
        for (a, reader_a) in &spellings {
            for (b, reader_b) in &spellings {
                if reader_a == reader_b {
                    continue;
                }
                assert!(
                    !a.starts_with(b),
                    "{reader_a}'s `{a}` begins with {reader_b}'s `{b}`: a word can be both"
                );
                pairs = pairs.saturating_add(1);
            }
            for word in [(*a).to_owned(), format!("{a}/x"), format!("{a}=/x")] {
                let answered = readers(&word);
                assert!(
                    answered.len() <= 1 && answered.iter().all(|r| r == reader_a),
                    "`{word}` is read by {answered:?}, and is {reader_a}'s spelling `{a}`"
                );
            }
            assert_eq!(readers(a), [*reader_a], "`{a}` is {reader_a}'s");
        }
        assert!(pairs > 0, "the pairs across readers were compared");
        for (a, reader) in &joined {
            assert_eq!(
                readers(&format!("{a}x")),
                [*reader],
                "`{a}x`, the joined form, is {reader}'s"
            );
        }
    }

    /// The exception flags that choose no model are not a runtime selection: the switch itself,
    /// `-fignore-exceptions` (not carried, as `runtime_selecting_flags` says), the C++,
    /// asynchronous and non-call forms, unwind tables, a misspelt selector, a negation clang
    /// rejects, and the frontend option handed through `-Xclang` or `-Wp,`, which the compile
    /// listing's comparison withholds on instead (`report::EXCEPTION_MODEL_READINGS`).
    #[test]
    fn exception_flags_that_choose_no_model_are_not_carried() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert!(
            runtime_selecting_flags(&line(
                "-fexceptions -fno-exceptions -fignore-exceptions -fcxx-exceptions \
                 -fasync-exceptions -fnon-call-exceptions -funwind-tables \
                 -fsjlj-exceptions-x -fno-sjlj-exceptions -Xclang -exception-model=sjlj \
                 -Wp,-exception-model=sjlj"
            ))
            .is_empty(),
            "none of them chooses a model the driver reads"
        );
    }

    /// Every spelling of a runtime selection clang 22.1.8 accepted under `-###` on
    /// 2026-10-05 is taken, as written and in order, and the spellings it refused, the
    /// removals, the configuration files and the hardening are not.
    #[test]
    fn runtime_selecting_flags_take_every_accepted_spelling_in_order() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let accepted = [
            "-stdlib=libc++",
            "--stdlib=libstdc++",
            "--stdlib libc++",
            "-stdlib++-isystem /srv/v1",
            "-stdlib++-isystem/srv/v2",
            "--rtlib=compiler-rt",
            "-rtlib=libgcc",
            "--rtlib compiler-rt",
            "--unwindlib=libunwind",
            "-unwindlib=libgcc",
            "--gcc-toolchain=/srv/g",
            "--gcc-install-dir=/srv/g/lib/gcc/t/16",
            "--gcc-triple=x86_64-other-linux-gnu",
            "-resource-dir=/srv/rd",
            "-resource-dir /srv/rd2",
            "-B/srv/b",
            "-B /srv/b2",
            "--prefix=/srv/p",
            "--prefix /srv/p2",
            "-ccc-install-dir /srv/i/bin",
            "--config-system-dir=/srv/cs",
            "--config-user-dir=/srv/cu",
            "--no-default-config",
            "-static-libgcc",
            "-shared-libgcc",
            "-static-libstdc++",
            "-static-libasan",
            "-static-libtsan",
            "-static-liblsan",
            "-static-libubsan",
            "-static-libhwasan",
            "-static-libsan",
            "-shared-libsan",
            "-static-openmp",
            "-fsjlj-exceptions",
            "-fdwarf-exceptions",
            "-fseh-exceptions",
            "-fwasm-exceptions",
        ];
        let mut fed = 0_usize;
        for spelling in accepted {
            let tokens = line(spelling);
            let mut profile = line("-O2 -m32 -fcf-protection=full");
            profile.extend(tokens.iter().cloned());
            profile.extend(line("-Wl,-z,now -fuse-ld=bfd"));
            assert_eq!(
                runtime_selecting_flags(&profile),
                tokens,
                "`{spelling}` is a runtime selection and nothing around it is"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed, 38,
            "every accepted spelling was put through the reader"
        );
        let all = accepted.join(" ");
        assert_eq!(
            runtime_selecting_flags(&line(&format!("-O2 {all} -D_FORTIFY_SOURCE=3"))),
            line(&all),
            "all of them at once, in the order written"
        );
        assert!(
            runtime_selecting_flags(&line(
                "-O2 -nostdinc++ -nostdlib++ -specs=/srv/s --config=/srv/c -isystem /srv/i \
                 -stdlib -rtlib -gcc-toolchain /srv/g -lc++ \
                 --gcc-triple x86_64-other-linux-gnu -gcc-triple=t --resource-dir=/srv/rd \
                 --resource-dir /srv/rd -resource-dir/srv/rd \
                 -ccc-install-dir=/srv/i --pref=/srv/p -prefix=/srv/p -static -static-pie \
                 -nostartfiles -nostdlib -static-libgcc-x -fuse-ld=lld \
                 -fstack-protector-strong --sysroot=/srv/r"
            ))
            .is_empty(),
            "a removal, a configuration file, an include directory, a library, a linkage \
             form, the linker and the spellings the drivers refuse select no runtime"
        );
        for dangling in [
            "--stdlib",
            "--rtlib",
            "-stdlib++-isystem",
            "-resource-dir",
            "-B",
            "--prefix",
            "-ccc-install-dir",
        ] {
            assert!(
                runtime_selecting_flags(&line(&format!("-O2 {dangling}"))).is_empty(),
                "a dangling {dangling} takes no value"
            );
        }
    }

    /// Every header selection spelling gcc 16.1.1 and clang 22.1.8 hand the compile proper
    /// as written (measured 2026-10-28 UTC on Fedora 44 x86_64 with `-###`) is taken, as written
    /// and in order, alone and all at once; a directory word outside the selection, a longer
    /// option beginning with a selected one, a word handed to the preprocessor or another
    /// tool, a removal, a macro, `-fopenmp` and a dangling two-token spelling are not.
    #[test]
    fn header_selecting_flags_take_every_accepted_spelling_in_order() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let accepted = [
            "-I/srv/i",
            "-I /srv/i2",
            "-I=inc",
            "-I =inc2",
            "-I-",
            "-isystem/srv/s",
            "-isystem /srv/s2",
            "-isystem=sys",
            "-isystem =sys2",
            "-idirafter/srv/a",
            "-idirafter /srv/a2",
            "-iquote/srv/q",
            "-iquote /srv/q2",
            "-include/srv/f.h",
            "-include /srv/f2.h",
            "-imacros/srv/m.h",
            "-imacros /srv/m2.h",
            "-undef",
            "-pthread",
        ];
        let mut fed = 0_usize;
        for spelling in accepted {
            let tokens = line(spelling);
            let mut profile = line("-O2 -m32 -fcf-protection=full -stdlib=libc++");
            profile.extend(tokens.iter().cloned());
            profile.extend(line("-D_FORTIFY_SOURCE=3 -Wl,-z,now -fuse-ld=bfd"));
            assert_eq!(
                header_selecting_flags(&profile),
                tokens,
                "`{spelling}` is a header selection and nothing around it is"
            );
            assert!(
                target_selecting_flags(&profile) == line("-m32")
                    && runtime_selecting_flags(&profile) == line("-stdlib=libc++")
                    && linker_program_flags(&profile) == line("-fuse-ld=bfd"),
                "`{spelling}` is no other reader's: {profile:?}"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed, 19,
            "every accepted spelling was put through the reader"
        );
        let all = accepted.join(" ");
        assert_eq!(
            header_selecting_flags(&line(&format!("-O2 {all} -fstack-protector-strong"))),
            line(&all),
            "all of them at once, in the order written"
        );
        assert!(
            header_selecting_flags(&line(
                "-O2 -iprefix /srv/p -iwithprefix inc -iwithprefixbefore inc -iwithsysroot /inc \
                 -imultilib m -iframework /srv/fw -F/srv/fw -isysroot /srv/r --sysroot=/srv/r \
                 -isystem-after /srv/after -isystem-after/srv/after2 -include-pch /srv/p.pch \
                 -include-pch/srv/p2.pch -nostdinc -nostdinc++ -D_REENTRANT -U_REENTRANT \
                 -Wp,-I/srv/w -Wp,-include,/srv/w.h -Xpreprocessor -I -Xpreprocessor /srv/x \
                 -Xpreprocessor -undef -Xclang -I/srv/c -Xlinker -I/srv/l -Xarch_x86_64 -I /srv/t \
                 -fopenmp -pthreads -lpthread -specs=/srv/s --config=/srv/c -undefx \
                 -std=gnu17 -fstack-protector-strong -D_FORTIFY_SOURCE=3"
            ))
            .is_empty(),
            "a directory word outside the selection, a longer option, a removal, a macro, a \
             word handed on, -fopenmp and a near spelling select no header"
        );
        assert_eq!(
            header_selecting_flags(&line("-O2 -Include -Isystem /srv/s")),
            line("-Include -Isystem"),
            "a word beginning -I is the driver's -I joined to the rest, whatever it spells"
        );
        assert_eq!(
            header_selecting_flags(&line(
                "-O2 -include-pch -I/srv/i -undef -isystem-after -imacros/srv/m.h -pthread"
            )),
            line("-I/srv/i -undef -imacros/srv/m.h -pthread"),
            "a longer option passes over itself alone, and the word after it is read as gcc \
             reads it; under clang, which takes that word as the value, the listing \
             comparison withholds on the difference"
        );
        for dangling in [
            "-I",
            "-isystem",
            "-idirafter",
            "-iquote",
            "-include",
            "-imacros",
        ] {
            assert!(
                header_selecting_flags(&line(&format!("-O2 {dangling}"))).is_empty(),
                "a dangling {dangling} takes no value"
            );
        }
    }

    /// Every directory word ([`HEADER_DIRECTORY`]) is one the reader takes
    /// ([`HEADER_VALUED`]) and reads as a directory in each of its four forms
    /// ([`selects_header_directory`]), the file and whole words and the longer options read
    /// as none, each list fed whole and counted, so the twinless clause's trigger cannot
    /// drift from the reader's own list.
    #[test]
    fn the_header_directory_words_are_valued_and_selected_in_every_form() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let mut fed = 0_usize;
        for word in HEADER_DIRECTORY {
            assert!(
                HEADER_VALUED.contains(&word),
                "{word} is a directory word the header reader does not take"
            );
            for spelling in [
                format!("{word}/srv/d"),
                format!("{word} /srv/d"),
                format!("{word}=inc"),
                format!("{word} =inc"),
            ] {
                let selected = header_selecting_flags(&line(&format!("-O2 {spelling}")));
                assert!(
                    selected.iter().any(|w| selects_header_directory(w)),
                    "`{spelling}` is read as a directory: {selected:?}"
                );
                fed += 1;
            }
        }
        for word in HEADER_VALUED
            .iter()
            .filter(|w| !HEADER_DIRECTORY.contains(w))
            .chain(HEADER_WHOLE.iter())
        {
            let selected = header_selecting_flags(&line(&format!("-O2 {word} /srv/f")));
            assert!(
                !selected.iter().any(|w| selects_header_directory(w)),
                "`{word}` selects no directory: {selected:?}"
            );
            fed += 1;
        }
        for longer in HEADER_LONGER {
            assert!(
                !selects_header_directory(longer),
                "{longer} is a longer option, not a directory word"
            );
            fed += 1;
        }
        // gcc's long spellings of the directory words are read as them, in each form the
        // walk carries, and its long spelling of a file word as that.
        for (spelling, directory) in [
            ("--include-directory /srv/d", true),
            ("--include-directory=/srv/d", true),
            ("--include-directory-after /srv/d", true),
            ("--include-directory-after=inc", true),
            ("--include /srv/f.h", false),
            ("--im /srv/m.h", false),
        ] {
            let selected = header_selecting_flags(&line(&format!("-O2 {spelling}")));
            assert!(
                !selected.is_empty(),
                "`{spelling}` is the header's: {selected:?}"
            );
            assert_eq!(
                selected.iter().any(|w| selects_header_directory(w)),
                directory,
                "`{spelling}` read as a directory: {selected:?}"
            );
            fed += 1;
        }
        // The other direction: the valued words that are not directories are exactly the
        // two forced-file words, so a directory word added to the reader's list alone is
        // caught here rather than read as a file.
        let files: Vec<&str> = HEADER_VALUED
            .iter()
            .copied()
            .filter(|w| !HEADER_DIRECTORY.contains(w))
            .collect();
        assert_eq!(
            files,
            ["-include", "-imacros"],
            "every other valued word names a file"
        );
        assert_eq!(
            fed,
            HEADER_DIRECTORY.len() * 4
                + (HEADER_VALUED.len() - HEADER_DIRECTORY.len())
                + HEADER_WHOLE.len()
                + HEADER_LONGER.len()
                + 6,
            "every word of every list was fed, and the six long spellings"
        );
    }

    /// Each entry of the reader's own lists is read in every form, each valued option joined
    /// and as two tokens and each whole word, counted against the lists' sizes; the test
    /// above holds the hand-written forms, this one holds the lists as they grow.
    #[test]
    fn the_header_readers_lists_are_each_fed_in_every_form() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let mut fed = 0_usize;
        for option in HEADER_VALUED {
            for spelling in [format!("{option}/srv/v"), format!("{option} /srv/v")] {
                assert_eq!(
                    header_selecting_flags(&line(&format!("-O2 {spelling} -m32"))),
                    line(&spelling),
                    "{option} is read in the form `{spelling}`"
                );
                fed = fed.saturating_add(1);
            }
        }
        for word in HEADER_WHOLE {
            assert_eq!(
                header_selecting_flags(&line(&format!("-O2 {word} -m32"))),
                vec![word],
                "{word} is read whole"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed,
            HEADER_VALUED.len() * 2 + HEADER_WHOLE.len(),
            "every list entry was fed in every form"
        );
    }

    /// Every removal gcc 16.1.1 or clang 22.1.8 accepted under `-###` on 2026-10-06 is
    /// found, as written and in order, and a selection, a near spelling and a linkage form
    /// are not.
    #[test]
    fn runtime_removing_flags_find_every_removal_in_order() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let removals = [
            "-nostartfiles",
            "-nostdlib",
            "--no-standard-libraries",
            "-nodefaultlibs",
            "-nolibc",
            "-nostdlib++",
            "-nostdinc",
            "--no-standard-includes",
            "-nostdinc++",
            "-nostdlibinc",
            "-nobuiltininc",
        ];
        let mut fed = 0_usize;
        for flag in removals {
            assert_eq!(
                runtime_removing_flags(&line(&format!("-O2 -m32 {flag} -Wl,-z,now"))),
                vec![flag],
                "`{flag}` is a removal and nothing around it is"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 11, "every removal was put through the reader");
        let all = removals.join(" ");
        assert_eq!(
            runtime_removing_flags(&line(&format!("-O2 {all}"))),
            line(&all),
            "all of them at once, in the order written"
        );
        assert!(
            runtime_removing_flags(&line(
                "-O2 -static -static-pie -static-libgcc -stdlib=libc++ -nostdlibfoo \
                 -Wl,-nostdlib -Xlinker -nostdlib -isystem /srv/i"
            ))
            .is_empty(),
            "a linkage form, a selection and a near spelling are not removals, nor is a word \
             the driver hands another tool"
        );
    }

    /// Every spelling that reached a removal past the driver's own on 2026-10-06 (a gcc
    /// abbreviation, a word handed to the preprocessor, clang's `-Xarch_`) is found as
    /// written, and every pass-through measured inert, rejected, or handed to a tool that
    /// reads the word as its own option is not.
    #[test]
    fn runtime_removing_flags_find_every_pass_through_spelling() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let removals = [
            "--no-standard-i",
            "--no-standard-inc",
            "--no-standard-include",
            "--no-standard-l",
            "--no-standard-lib",
            "--no-standard-librarie",
            "-Wp,-nostdinc",
            "-Wp,--no-standard-includes",
            "-Wp,--no-standard-i",
            "-Wp,-nostdinc++",
            "-Wp,-O2,-nostdinc",
            "-Wp,-I/srv/i,-nostdinc++,-DX",
            "-Xpreprocessor -nostdinc",
            "-Xpreprocessor --no-standard-includes",
            "-Xpreprocessor --no-standard-in",
            "-Xpreprocessor -nostdinc++",
            "-Xarch_x86_64 -nostdinc",
            "-Xarch_x86_64 -nostdlibinc",
            "-Xarch_x86_64 -nobuiltininc",
            "-Xarch_x86_64 -nostdinc++",
            "-Xarch_x86_64 -nostartfiles",
            "-Xarch_x86_64 -nostdlib",
            "-Xarch_x86_64 -nodefaultlibs",
            "-Xarch_x86_64 -nolibc",
            "-Xarch_x86_64 -nostdlib++",
            "-Xarch_host -nostartfiles",
            "-Xarch_i386 -nostartfiles",
            "-Xarch_aarch64 --no-standard-libraries",
        ];
        let mut fed = 0_usize;
        for spelling in removals {
            assert_eq!(
                runtime_removing_flags(&line(&format!("-O2 -m32 {spelling} -Wl,-z,now"))),
                line(spelling),
                "`{spelling}` is a removal and nothing around it is"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed, 28,
            "every pass-through removal was put through the reader"
        );
        let all = removals.join(" ");
        assert_eq!(
            runtime_removing_flags(&line(&format!("-O2 {all} -nostdinc"))),
            line(&format!("{all} -nostdinc")),
            "all of them at once, in the order written"
        );
        let inert = [
            "-Wl,-nostdlib",
            "-Wl,--nostdlib",
            "-Xlinker -nostdlib",
            "--for-linker -nostdlib",
            "--for-linker=-nostdlib",
            "-Xclang -nostdinc",
            "-Xclang -nobuiltininc",
            "-Xclang -nostdsysteminc",
            "-Wp,-nostdlibinc",
            "-Wp,-nobuiltininc",
            "-Wp,-nostdsysteminc",
            "-Wp,-nostdlib",
            "-Wp,-I/srv/i",
            "-Xpreprocessor -nobuiltininc",
            "-Xpreprocessor -nostartfiles",
            "-Wa,-nostdinc",
            "-Xassembler -nostdinc",
            "-mllvm -nostdinc",
            "--no-standard-",
            "--no-standard",
            "--no-standard-includesx",
            "--no-standard-x",
            "-Xarch_x86_64 -O2",
            "-Xarch_x86_64=-nostdinc",
            "-Xpreprocessor",
            "-Xarch_x86_64",
        ];
        let mut fed = 0_usize;
        for spelling in inert {
            assert!(
                runtime_removing_flags(&line(&format!("-O2 {spelling}"))).is_empty(),
                "`{spelling}` removes nothing the drivers were measured to remove"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 26, "every inert spelling was put through the reader");
    }

    /// A removal spelled as the value of a two-token option is the value and no removal:
    /// after a selection's own spelling (`-L -nostdinc`, `-B -nostartfiles`, `-I -nostdinc`,
    /// `-isystem -nostdinc++`) and after an option that selects nothing (`-u -nostdlib`, `-o
    /// -nostdinc`), as both drivers read it; a removal after the value is still found (`-L
    /// -u -nostdlib`, whose removal a reader that passed over `-u`'s value and not `-L`'s
    /// would lose to `-u`), and a removal spelled as the value of a word that
    /// passes over itself alone (`-isystem-after -nostdinc`) is found as gcc reads it.
    #[test]
    fn a_removal_spelled_as_a_two_token_value_is_the_value() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let mut fed = 0_usize;
        for value in [
            "-L -nostdinc",
            "-B -nostartfiles",
            "-I -nostdinc",
            "-isystem -nostdinc++",
            "--sysroot -nostdlib",
            "-target -nolibc",
            "--li -nostdinc",
            "-u -nostdlib",
            "-o -nostdinc",
            "-MF --no-standard-includes",
            "-x -nostdinc++",
            "-z -nostartfiles",
        ] {
            assert!(
                runtime_removing_flags(&line(&format!("-O2 {value} -m32"))).is_empty(),
                "`{value}` is a value, not a removal"
            );
            fed = fed.saturating_add(1);
        }
        for (list, found) in [
            ("-O2 -L -u -nostdlib", "-nostdlib"),
            ("-O2 -u -L -nostdlib", "-nostdlib"),
            ("-O2 -L -nostdinc -nostdinc", "-nostdinc"),
            ("-O2 -isystem-after -nostdinc", "-nostdinc"),
            ("-O2 -Tbss -nostdlib", "-nostdlib"),
            (
                "-O2 -u -nostdlib -nostartfiles -o -nolibc -nodefaultlibs",
                "-nostartfiles -nodefaultlibs",
            ),
        ] {
            assert_eq!(runtime_removing_flags(&line(list)), line(found), "{list}");
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 18, "every shape was fed");
    }

    #[test]
    fn target_selecting_flags_take_every_sysroot_spelling_in_order() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            target_selecting_flags(&line(
                "-O2 --sysroot=/srv/a -isysroot /srv/b -fstack-protector-strong \
                 --sysroot /srv/c -m32 -isysroot/srv/d -Wl,-z,now"
            )),
            vec![
                "--sysroot=/srv/a",
                "-isysroot",
                "/srv/b",
                "--sysroot",
                "/srv/c",
                "-m32",
                "-isysroot/srv/d"
            ]
        );
        assert!(
            target_selecting_flags(&line(
                "-O2 -B/srv/prefix -B /srv/p --gcc-toolchain=/srv/g -isystem /srv/i --sysroot"
            ))
            .is_empty(),
            "a prefix, a GCC installation and an include directory choose no system root, \
             and a dangling --sysroot takes no value"
        );
        assert!(
            target_selecting_flags(&line("-O2 -isystem /srv/i -isysroot")).is_empty(),
            "a dangling -isysroot takes no value and is not read as a joined -isysrootDIR"
        );
    }

    /// Every spelling that selected aarch64 ILP32 in the 2026-10-13 measurement (the cross
    /// gcc 16.1.1, clang 22.1.8, the cross GNU as 2.46; `unsupported_target_flags` lists
    /// them) is found, through every carrier an x32 triple has, and the near spellings the
    /// tools rejected, the inert `-Wp,` list and LP64 are not.
    #[test]
    fn unsupported_target_flags_find_every_aarch64_ilp32_spelling() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let selections = [
            "-mabi=ilp32",
            "-Wa,-mabi=ilp32",
            "-Wa,--noexecstack,-mabi=ilp32",
            "-Xassembler -mabi=ilp32",
            "--for-assembler -mabi=ilp32",
            "--for-a -mabi=ilp32",
            "--for-assembler=-mabi=ilp32",
            "--target=aarch64-linux-gnu_ilp32",
            "--target=aarch64-unknown-linux-gnu_ilp32",
            "--target=aarch64_be-linux-gnu_ilp32",
            "--target=aarch64-gnu_ilp32",
            "--target=gnu_ilp32-aarch64",
            "--target=aarch64-linux-gnu_ilp321",
            "--target=arm64_32-apple-watchos",
            "--target=aarch64_32-apple-watchos",
            "--target=watchos-arm64_32",
            "-target aarch64-linux-gnu_ilp32",
            "-target arm64_32-apple-watchos",
            "-Xclang -triple -Xclang aarch64-unknown-linux-gnu_ilp32",
            "-Xclang -triple -Xclang arm64_32-apple-watchos",
            "-Xclang -triple=aarch64-linux-gnu_ilp32",
            "-Xclang=-triple -Xclang=aarch64-linux-gnu_ilp32",
            "-Xclang -triple=arm64_32-apple-watchos",
            "-Xclang=-triple -Xclang=arm64_32-apple-watchos",
            "-arch arm64_32",
            "-arch aarch64_32",
        ];
        let mut fed = 0_usize;
        for spelling in selections {
            assert_eq!(
                unsupported_target_flags(&line(&format!(
                    "-O2 --target=aarch64-linux-gnu {spelling} -mabi=lp64 -Wl,-z,now"
                ))),
                line(spelling),
                "`{spelling}` selects aarch64 ILP32 and nothing around it does"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed,
            selections.len(),
            "every spelling was put through the reader"
        );
        let all = selections.join(" ");
        assert_eq!(
            unsupported_target_flags(&line(&format!("-O2 {all} -mabi=lp64"))),
            line(&all),
            "all of them at once, in the order written"
        );
        assert!(
            unsupported_target_flags(&line(
                "-O2 -mabi=lp64 -mabi=ilp -mabi=ILP32 -mabi=ilp32x -mab=ilp32 --mabi=ilp32 \
                 -milp32 -mabi ilp32 -Wp,-mabi=ilp32 -Wp,-O2,-mabi=ilp32 -Wa,-mabi=lp64 \
                 -Wa,--mabi=ilp32,-mabi=ilp,-mab=ilp32,-mabi=ILP32,-mabi -Xassembler -mabi \
                 -Xlinker -mabi --for-a=-mabi=ilp32 --target=aarch64-linux-gnu \
                 --target=aarch64-linux-gnuilp32 --target=aarch64-linux-GNU_ILP32 \
                 --target=aarch64-linux-ilp32 --target=arm64-apple-watchos \
                 --target=arm64_32x-apple-watchos -arch arm64 -arch=arm64_32 -arch ARM64_32 \
                 -march=armv8-a -Xclang -target-abi -Xclang lp64 -arch"
            ))
            .is_empty(),
            "LP64, the spellings the tools rejected, a -Wp, list cc1 does not generate code \
             from, a word for another tool and a dangling -arch select nothing"
        );
        assert_eq!(
            unsupported_target_flags(&line("-O2 -Xpreprocessor -mabi=ilp32")),
            line("-mabi=ilp32"),
            "the word after -Xpreprocessor is found as the word, inert there or not: the cost \
             the doc comment names"
        );
    }

    /// Every spelling that selected x32 or 16-bit code in the reader's measurement is found
    /// as written, with the triple or assembler word it carries, and `-m32`, an x86_64
    /// triple, a near spelling, a word for another tool, a joined abbreviation gcc rejects
    /// and a two-token spelling without its value are not. A word handed to `cc1` by
    /// `-Xpreprocessor` is found as the word, and `cc1`'s `-triple` with its value is found
    /// across clang's `-Xclang` list, adjacent or not and whatever other option took an
    /// `-Xclang` between them, by the words that carried them.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table of every measured spelling, read in one place"
    )]
    fn unsupported_target_flags_find_every_x32_and_sixteen_bit_spelling() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let selections = [
            "-mx32",
            "-m16",
            "--target=x86_64-linux-gnux32",
            "--target=x86_64-pc-linux-gnux32",
            "--target=x86_64-gnux32",
            "--target=x86_64-unknown-linux-muslx32",
            "--target=i386-pc-linux-code16",
            "-target x86_64-linux-gnux32",
            "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
            "-Xclang -triple=x86_64-pc-linux-gnux32",
            "-Wa,--x32",
            "-Wa,-O2,--x32",
            "-Xassembler --x32",
            "-Wa,-x32",
            "-Wa,--x3",
            "-Wa,-x3",
            "-Wa,--x",
            "-Wa,-O2,-x",
            "-Xassembler -x32",
            "-Xassembler --x3",
            "-Xassembler -x",
            "--for-assembler --x32",
            "--for-assembler -x",
            "--for-assembler=--x32",
            "--for-assembler=-x",
            "--for-a -x32",
            "--for-as --x3",
            "--for-assembl --x",
            "-Wp,-mx32",
            "-Wp,-m16",
            "-Wp,-O2,-mx32",
            "-Wp,--machine=x32",
            "-Wp,--machine,x32",
            "-Wp,--machine,16",
            "-Wp,--machine=16",
            "-Wp,--machine -Wp,x32",
            "--target=gnux32-x86_64",
            "--target=x86_64-gnux32-linux",
            "-Xclang -triple -Xclang gnux32-x86_64",
            "-Xclang=-triple=x86_64-pc-linux-gnux32",
            "-Xclang=-triple -Xclang=x86_64-pc-linux-gnux32",
            "-Xclang -triple -Xclang=x86_64-pc-linux-gnux32",
            "-Xclang=-triple -Xclang x86_64-pc-linux-gnux32",
            "-Xclang=-triple=i386-pc-linux-code16",
            "--target=x86_64-linux-gnux321",
            "--target=x86_64-linux-muslx3210",
            "--target=i386-linux-code161",
            "-Xclang -triple -Xclang x86_64-linux-gnux3210",
        ];
        let mut fed = 0_usize;
        for spelling in selections {
            assert_eq!(
                unsupported_target_flags(&line(&format!("-O2 -m32 {spelling} -Wl,-z,now"))),
                line(spelling),
                "`{spelling}` selects x32 or 16-bit code and nothing around it does"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 48, "every spelling was put through the reader");
        let all = selections.join(" ");
        assert_eq!(
            unsupported_target_flags(&line(&format!("-O2 {all} -m64"))),
            line(&all),
            "all of them at once, in the order written"
        );
        assert!(
            unsupported_target_flags(&line(
                "-O2 -m32 -m64 -m16bit -mx3 --target=x86_64-linux-gnu -target i686-linux-gnu \
                 -Xclang -triple -Xclang x86_64-pc-linux-gnu -Wa,--32 -Xlinker --x32 \
                 -Wa,---x32,--X32,--x32x,--x32=1,-x33,--,- -Xassembler -- \
                 --for-linker --x32 --for-l -x32 --for-a=-x32 --for-assemble=-x \
                 --for-assembler --64 -Xassembler --32 -Wp,-m32,-mx32x,-m64 \
                 -Xpreprocessor -m32 --target=x86_64-linux-gnu-x32 \
                 -Xclang=-triple=x86_64-linux-gnu -Xclang -triple -Xclang x86_64-linux-gnu -Xclang= \
                 -march=x86-64 -target -Xclang -triple"
            ))
            .is_empty(),
            "i386, x86_64, a near spelling, a word for another tool, a joined abbreviation gcc \
             rejects, cc1 words that are no x32 -triple pair and a dangling -target, -Xclang or \
             -triple select neither"
        );
        assert!(
            unsupported_target_flags(&line(
                "-O2 -Xclang x86_64-pc-linux-gnux32 -Xclang -triple -Xclang=-triple"
            ))
            .is_empty(),
            "an x32 triple before every -triple word is no pair: cc1 would read a dangling -triple"
        );
        assert!(
            unsupported_target_flags(&line(
                "-O2 -Xclang -aux-triple -Xclang x86_64-pc-linux-gnux32 --target x86_64-linux-gnux32"
            ))
            .is_empty(),
            "cc1's -aux-triple names no target, clang rejects the two-token --target, and no \
             -triple word stands before either value"
        );
        assert_eq!(
            unsupported_target_flags(&line(
                "-Xclang -triple -Xclang x86_64-linux-gnu -Xclang -aux-triple -Xclang \
                 x86_64-pc-linux-gnux32"
            )),
            line("-Xclang -triple -Xclang x86_64-pc-linux-gnux32"),
            "a bare x32 triple after a bare -triple is found whatever option took it: the cost \
             the doc comment names"
        );
        for (split, named) in [
            (
                "-O2 -Xclang -triple -O2 -Xclang x86_64-pc-linux-gnux32 -Wl,-z,now",
                "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
            ),
            (
                "-Xclang -triple -m64 -Xclang=i386-pc-linux-code16",
                "-Xclang -triple -Xclang=i386-pc-linux-code16",
            ),
            (
                "-Xclang=-triple -Wl,-z,now -Xclang x86_64-pc-linux-gnux32 -O2",
                "-Xclang=-triple -Xclang x86_64-pc-linux-gnux32",
            ),
            (
                "-Xlinker -Xclang -Xclang -triple -Xclang x86_64-pc-linux-gnux32",
                "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
            ),
            (
                "-MT -Xclang -Xclang -triple -Xclang x86_64-pc-linux-gnux32",
                "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
            ),
            (
                "-Xclang -triple -Xlinker -Xclang -Xclang x86_64-pc-linux-gnux32",
                "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
            ),
            (
                "-Xclang -triple=x86_64-linux-gnu -Xclang -triple -Xclang x86_64-pc-linux-gnux32",
                "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
            ),
        ] {
            assert_eq!(
                unsupported_target_flags(&line(split)),
                line(named),
                "clang hands cc1 every -Xclang value in order, so the pair need not be adjacent \
                 and an option taking an -Xclang as its value shifts nothing: {split}"
            );
        }
        assert_eq!(
            unsupported_target_flags(&line("-O2 -Xpreprocessor -mx32 -Xpreprocessor -m16")),
            line("-mx32 -m16"),
            "a word handed to cc1 by -Xpreprocessor is found as the word"
        );
        // gcc hands cc1 every -Xpreprocessor value and -Wp, item in order, and cc1 joins
        // `--machine` to the next relayed word, whichever carrier brought it (measured
        // 2026-10-28 UTC on Fedora 44 x86_64 with gcc 16.1.1 by `-dM -E`: each defines
        // `__ILP32__` or `__i386__`); a selection standing as another relayed word's value
        // is found too, as one standing as a driver word's value is.
        for (relayed, named) in [
            (
                "-O2 -Xpreprocessor --machine -Xpreprocessor x32",
                "--machine x32",
            ),
            (
                "-O2 -Xpreprocessor --machine -Xpreprocessor 16",
                "--machine 16",
            ),
            ("-O2 -Wp,--machine -Xpreprocessor x32", "-Wp,--machine x32"),
            ("-O2 -Xpreprocessor --machine -Wp,x32", "--machine -Wp,x32"),
            (
                "-O2 -Wp,-O2 -Wp,--machine -Wp,x32 -m64",
                "-Wp,--machine -Wp,x32",
            ),
            (
                "-O2 -Wp,-MF,-mx32 -Xpreprocessor -o -Xpreprocessor -m16",
                "-Wp,-MF,-mx32 -m16",
            ),
        ] {
            assert_eq!(
                unsupported_target_flags(&line(relayed)),
                line(named),
                "the words gcc relays to cc1 are one stream to it: {relayed}"
            );
        }
    }

    /// gcc 16.1.1's C library selections on a GNU/Linux target and gcc's
    /// `--no-sysroot-suffix` are taken as written and in order; each was accepted under
    /// `-###` on Fedora 44 x86_64 on 2026-10-06, where `-mmusl`, `-muclibc` and `-mbionic`
    /// each named another dynamic linker and `-mandroid` linked `crtbegin_dynamic.o`.
    #[test]
    fn target_selecting_flags_take_the_c_library_selections() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let taken = [
            "-mglibc",
            "-muclibc",
            "-mmusl",
            "-mbionic",
            "-mandroid",
            "-tno-android-cc",
            "-tno-android-ld",
            "--no-sysroot-suffix",
        ];
        let mut fed = 0_usize;
        for flag in taken {
            assert_eq!(
                target_selecting_flags(&line(&format!("-O2 {flag} -fcf-protection=full"))),
                vec![flag],
                "`{flag}` is a target selection and nothing around it is"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(
            fed,
            taken.len(),
            "every selection was put through the reader"
        );
        let all = taken.join(" ");
        assert_eq!(
            target_selecting_flags(&line(&format!("-O2 {all} -D_FORTIFY_SOURCE=3"))),
            line(&all),
            "all of them at once, in the order written"
        );
        assert!(
            target_selecting_flags(&line("-O2 -mmusl-x -mno-android -march=i686")).is_empty(),
            "a near spelling and an ISA flag select nothing"
        );
    }

    #[test]
    fn target_selecting_flags_take_library_directories_as_the_root_half() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            target_selecting_flags(&line(
                "--sysroot=/srv/r -O2 -L/srv/r/usr/lib/gcc/t/16 -lm -L /srv/l -Wl,-L/srv/w"
            )),
            vec![
                "--sysroot=/srv/r",
                "-L/srv/r/usr/lib/gcc/t/16",
                "-L",
                "/srv/l"
            ],
            "both spellings of -L, in order; a library named with -l and a directory \
             handed to the linker with -Wl, are neither"
        );
        assert!(
            !selects_target(&line("-L/srv/l -L /srv/m")),
            "a library directory selects no target, so the gate stays on -dumpmachine"
        );
        assert!(
            target_selecting_flags(&line("-O2 -L")).is_empty(),
            "a dangling -L takes no value"
        );
        assert_eq!(
            target_selecting_flags(&line(
                "--library-directory=/srv/a -O2 --library-directory /srv/b --library-directory"
            )),
            vec![
                "--library-directory=/srv/a",
                "--library-directory",
                "/srv/b"
            ],
            "the long spelling, joined and as two tokens; a dangling one takes no value"
        );
        assert!(
            !selects_target(&line(
                "--library-directory=/srv/a --library-directory /srv/b"
            )),
            "the long spelling selects no target either"
        );
    }

    #[test]
    fn version_comes_from_macros_not_banner_text() {
        let gcc = BTreeMap::from([
            ("__GNUC__".to_owned(), "16".to_owned()),
            ("__GNUC_MINOR__".to_owned(), "1".to_owned()),
            ("__GNUC_PATCHLEVEL__".to_owned(), "1".to_owned()),
        ]);
        assert_eq!(version_from_macros(Kind::Gcc, &gcc), "16.1.1");

        let clang = BTreeMap::from([
            ("__clang_major__".to_owned(), "22".to_owned()),
            ("__clang_minor__".to_owned(), "1".to_owned()),
            ("__clang_patchlevel__".to_owned(), "8".to_owned()),
        ]);
        assert_eq!(version_from_macros(Kind::Clang, &clang), "22.1.8");
    }

    #[test]
    fn unknown_version_is_named_not_empty() {
        assert_eq!(version_from_macros(Kind::Gcc, &BTreeMap::new()), "unknown");
    }

    #[test]
    fn parses_configure_line_and_clang_config_files() {
        let text = "Using built-in specs.\n\
                    COLLECT_GCC=/usr/bin/gcc\n\
                    Configured with: ../configure --enable-default-pie --enable-default-ssp\n\
                    Configuration file: /etc/clang/x86_64-redhat-linux-gnu.cfg\n\
                    Thread model: posix\n";
        let (configure, configs) = parse_verbose(text);
        assert_eq!(
            configure.as_deref(),
            Some("../configure --enable-default-pie --enable-default-ssp")
        );
        assert_eq!(
            configs,
            vec!["/etc/clang/x86_64-redhat-linux-gnu.cfg".to_owned()]
        );
    }

    /// A scratch directory of executable shell scripts standing in for a driver and the
    /// linkers it might name. Removed on drop.
    struct Shims {
        dir: PathBuf,
    }

    impl Shims {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("chard-linker-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("scratch directory");
            Self { dir }
        }

        /// A directory under the scratch root, for a `PATH` entry or a `-B` prefix.
        fn subdir(&self, name: &str) -> PathBuf {
            let dir = self.dir.join(name);
            std::fs::create_dir_all(&dir).expect("subdirectory");
            dir
        }

        /// Write `body` under a `#!/bin/sh` line at `path` and wait until the kernel will run
        /// it: [`compile::test_script`], which has the measurement that put the wait there.
        fn script(path: &Path, body: &str) -> PathBuf {
            compile::test_script(path, body)
        }

        /// A linker that answers `--version` with `banner` and nothing else.
        fn linker(dir: &Path, name: &str, banner: &str) -> PathBuf {
            Self::script(&dir.join(name), &format!("echo '{banner}'"))
        }

        /// A driver that answers `-print-prog-name=<name>` the way gcc on Fedora and clang
        /// both do: with `<prefix>/<name>` when a `-B` prefix holds the program, and with
        /// the bare name otherwise, since neither driver searches `PATH` for the answer.
        fn driver(&self) -> PathBuf {
            self.driver_named("cc")
        }

        /// [`Shims::driver`] under another file name, for a C++ driver beside the C one.
        fn driver_named(&self, name: &str) -> PathBuf {
            Self::script(
                &self.dir.join(name),
                "prog=; prefix=\n\
                 for a in \"$@\"; do\n\
                   case \"$a\" in\n\
                     -print-prog-name=*) prog=\"${a#-print-prog-name=}\" ;;\n\
                     -B*) prefix=\"${a#-B}\" ;;\n\
                   esac\n\
                 done\n\
                 if [ -n \"$prefix\" ] && [ -x \"$prefix/$prog\" ]; then\n\
                   echo \"$prefix/$prog\"\n\
                 else\n\
                   echo \"$prog\"\n\
                 fi",
            )
        }
    }

    impl Drop for Shims {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const GOLD: &str = "GNU gold (GNU Binutils 1.2.3) 1.16";
    const BFD: &str = "GNU ld (GNU Binutils) 2.46.1";
    const LLD: &str = "Ubuntu LLD 18.1.3 (compatible with GNU linkers)";
    const MOLD: &str = "mold 2.4.0 (compatible with GNU ld)";

    /// The reproduction. `gcc -print-prog-name=ld` on Fedora prints the bare
    /// name `ld`; the report then published `path: "ld"`, a name that resolves only through
    /// a search the reader would have to repeat, and the version of whatever `ld` sat first
    /// on the harness's PATH under a detection string silent about that search. The path is
    /// the resolved one, and the record says chard resolved it.
    #[test]
    fn a_bare_name_from_the_driver_is_resolved_on_path_and_says_so() {
        let shims = Shims::new("bare");
        let bin = shims.subdir("bin");
        let ld = Shims::linker(&bin, "ld", GOLD);
        let driver = shims.driver();

        let linker = detect_linker_on(&driver, &[], bin.as_os_str(), Path::new(""));
        assert_eq!(linker.kind, "gold", "detection: {}", linker.detection);
        assert_eq!(linker.version.as_deref(), Some(GOLD));
        assert_eq!(
            linker.path.as_deref(),
            Some(ld.display().to_string().as_str()),
            "detection: {}",
            linker.detection
        );
        assert_eq!(
            linker.path_source,
            Some(PathSource::PathSearch),
            "detection: {}",
            linker.detection
        );
        assert!(linker.profile_flags.is_empty());
        assert!(
            linker.detection.contains("bare name `ld`")
                && linker.detection.contains("resolved on PATH"),
            "the detection must say the driver printed a name and chard resolved it: {}",
            linker.detection
        );
    }

    /// The link line is the last command of a `-###` listing, in the two shapes the
    /// drivers print. The listings are trimmed from clang 22.1.8 and gcc 16.2.1 on Fedora
    /// 44 aarch64 (2026-09-29), through a wrapper adding `-fuse-ld=lld` and without one.
    #[test]
    fn the_link_line_names_the_program_a_driver_runs() {
        let clang = " \"/usr/bin/clang-22\" \"-cc1\" \"-triple\" \"aarch64\"\n \"/usr/bin/ld.lld\" \"-pie\" \"-o\" \"m\"\n";
        assert_eq!(
            link_line(clang),
            Some(LinkLine::Runs(PathBuf::from("/usr/bin/ld.lld")))
        );
        let gcc = " /usr/libexec/gcc/aarch64-redhat-linux/16/cc1 -quiet m.c\n /usr/libexec/gcc/aarch64-redhat-linux/16/collect2 -plugin /usr/libexec/gcc/x/liblto_plugin.so -fuse-ld=lld -o m\nCOMPILER_PATH=/usr/libexec/gcc/\n";
        assert_eq!(
            link_line(gcc),
            Some(LinkLine::Collect2(vec!["-fuse-ld=lld".to_owned()]))
        );
        let plain = " /usr/libexec/gcc/aarch64-redhat-linux/16/collect2 -plugin x.so -o m\n";
        assert_eq!(link_line(plain), Some(LinkLine::Collect2(Vec::new())));
        assert_eq!(link_line("gcc: error: no input files\n"), None);
        assert_eq!(
            link_line(" \"ld\" \"-o\" \"m\"\n"),
            None,
            "a bare name is not a path"
        );
        assert_eq!(
            link_line(" \"/opt/my tools/ld.lld\" \"-o\" \"m\"\n"),
            Some(LinkLine::Runs(PathBuf::from("/opt/my tools/ld.lld"))),
            "a quoted path holding a space is one word, as link_inputs::words reads it"
        );
    }

    /// One link line under exit 0 and under exit 1: read under the first, refused under the second
    /// with the status and the driver's error line in the sentence, so the detection that follows
    /// names the route it fell back to. The rule is `link_inputs::listing`'s, which the two input
    /// comparisons already follow: a driver that exits other than 0 rejected the command it was
    /// asked to list. With the status unread, a wrapper that printed a listing running
    /// `/usr/bin/ld.lld` and exited 1 would have that path published as the linker (Fedora 44
    /// x86_64, clang 22.1.8, 2026-10-07). Counted against the drivers handed in.
    #[test]
    fn a_link_line_from_a_query_the_driver_rejected_is_not_read() {
        let shims = Shims::new("status");
        let mut fed = 0;
        for status in [0, 1] {
            let driver = Shims::script(
                &shims.dir.join(format!("exits-{status}")),
                &format!(
                    "echo 'cc: error: unrecognized command-line option' >&2\n\
                     echo ' \"/opt/bin/ld.lld\" \"-o\" \"/dev/null\"' >&2\n\
                     exit {status}"
                ),
            );
            fed += 1;
            let read = read_link_line(&driver, &[], Path::new(""));
            if status == 0 {
                assert_eq!(read.adds, ["--ld-path=/opt/bin/ld.lld"]);
                assert_eq!(
                    read.runs.as_deref(),
                    Some("the driver's -### link line runs /opt/bin/ld.lld")
                );
                assert_eq!(read.unread, None);
            } else {
                assert!(
                    read.adds.is_empty(),
                    "exit 1 selects nothing: {:?}",
                    read.adds
                );
                assert_eq!(read.runs, None, "exit 1 names no program");
                let why = read.unread.expect("exit 1: the sentence says why");
                assert_eq!(
                    why,
                    "the driver exited 1 on its -### listing with no link-selection flag \
                     (cc: error: unrecognized command-line option), so its link line was \
                     not read"
                );
            }
        }
        assert_eq!(fed, 2, "a driver exiting 0 and one exiting 1");
    }

    /// The sentence a rejected query leaves names the scope the query ran under, the
    /// profile's link-selection words and not its flags, and quotes the driver's stderr
    /// as published: a path under the work directory made relative, as `measure::publish`
    /// makes a gating's reason. It does not say `under no flags` for a profile without a
    /// selection, `openssf-tldr` included, nor quote the line as written.
    /// Counted against the cases handed in.
    #[test]
    fn a_rejected_query_names_its_scope_and_publishes_the_drivers_words() {
        let shims = Shims::new("named");
        let work = shims.subdir("work");
        let driver = Shims::script(
            &shims.dir.join("rejects"),
            &format!(
                "echo 'cc: error: cannot read {}/late.rsp' >&2\nexit 1",
                work.display()
            ),
        );
        let cases: [(&[&str], &str); 3] = [
            (&[], "with no link-selection flag"),
            (
                &["-fuse-ld=lld"],
                "under the link-selection flag -fuse-ld=lld",
            ),
            (
                &["-B/opt/bin", "-fuse-ld=lld"],
                "under the link-selection flags -B/opt/bin -fuse-ld=lld",
            ),
        ];
        let mut fed = 0;
        for (consulted, named) in cases {
            fed += 1;
            let consulted: Vec<String> = consulted.iter().map(|s| (*s).to_owned()).collect();
            let read = read_link_line(&driver, &consulted, &work);
            let why = read.unread.expect("exit 1: the sentence says why");
            assert_eq!(
                why,
                format!(
                    "the driver exited 1 on its -### listing {named} (cc: error: cannot read \
                     late.rsp), so its link line was not read"
                )
            );
            assert!(
                !why.contains(&work.display().to_string()),
                "the work directory is not in the published sentence: {why}"
            );
        }
        assert_eq!(fed, cases.len(), "every scope was fed");
    }

    /// `-print-prog-name=ld` ignores `-fuse-ld=` in both drivers, so a profile linking with
    /// lld was reported as linking with whatever `ld` is. The flavour is turned into the
    /// program name the driver's link step searches for, `ld.lld`, and resolved the same way.
    #[test]
    fn a_profile_fuse_ld_selects_the_linker_the_link_will_run() {
        let shims = Shims::new("fuse");
        let bin = shims.subdir("bin");
        Shims::linker(&bin, "ld", GOLD);
        let lld = Shims::linker(&bin, "ld.lld", LLD);
        let driver = shims.driver();

        let flags = ["-O2".to_owned(), "-fuse-ld=lld".to_owned()];
        let linker = detect_linker_on(&driver, &flags, bin.as_os_str(), Path::new(""));
        assert_eq!(linker.kind, "lld", "detection: {}", linker.detection);
        assert_eq!(
            linker.path.as_deref(),
            Some(lld.display().to_string().as_str()),
            "detection: {}",
            linker.detection
        );
        assert_eq!(
            linker.path_source,
            Some(PathSource::PathSearch),
            "detection: {}",
            linker.detection
        );
        assert_eq!(linker.profile_flags, vec!["-fuse-ld=lld".to_owned()]);
        assert!(
            linker.detection.contains("ld.lld"),
            "the query names the program the flavour selects: {}",
            linker.detection
        );
    }

    /// A `-B` prefix reaches the driver's own search, so the linker it holds wins over the
    /// one on PATH, and the report attributes the path to the driver.
    #[test]
    fn a_b_prefix_reaches_the_drivers_own_search() {
        let shims = Shims::new("prefix");
        let bin = shims.subdir("bin");
        Shims::linker(&bin, "ld", GOLD);
        let prefix = shims.subdir("prefix");
        let bfd = Shims::linker(&prefix, "ld", BFD);
        let driver = shims.driver();

        let joined = [format!("-B{}", prefix.display())];
        let linker = detect_linker_on(&driver, &joined, bin.as_os_str(), Path::new(""));
        assert_eq!(linker.kind, "bfd", "detection: {}", linker.detection);
        assert_eq!(
            linker.path.as_deref(),
            Some(bfd.display().to_string().as_str()),
            "detection: {}",
            linker.detection
        );
        assert_eq!(
            linker.path_source,
            Some(PathSource::Driver),
            "detection: {}",
            linker.detection
        );
        assert_eq!(linker.profile_flags, joined.to_vec());

        // The two-token spelling selects the same linker and records both tokens.
        let split = ["-B".to_owned(), prefix.display().to_string()];
        let linker = detect_linker_on(&driver, &split, bin.as_os_str(), Path::new(""));
        assert_eq!(linker.kind, "bfd", "detection: {}", linker.detection);
        assert_eq!(linker.profile_flags, split.to_vec());
    }

    /// A gcc link line hands `collect2` the selection flags it adds, and one that hands it
    /// none adds nothing and names no program.
    #[test]
    fn a_collect2_line_adds_the_selection_it_hands_on_and_nothing_else() {
        let shims = Shims::new("collect2");
        let line = |name: &str, words: &str| {
            Shims::script(
                &shims.dir.join(name),
                &format!(
                    "echo ' /usr/libexec/gcc/x/16/collect2 -plugin x.so {words}-o /dev/null' >&2\n\
                     exit 0"
                ),
            )
        };
        let handed = read_link_line(&line("handed", "-fuse-ld=lld "), &[], Path::new(""));
        assert_eq!(handed.adds, ["-fuse-ld=lld"]);
        assert_eq!(
            handed.runs.as_deref(),
            Some("the driver's -### link line hands collect2 -fuse-ld=lld")
        );
        let plain = read_link_line(&line("plain", ""), &[], Path::new(""));
        assert!(
            plain.adds.is_empty() && plain.runs.is_none() && plain.unread.is_none(),
            "{:?} {:?}",
            plain.runs,
            plain.unread
        );
    }

    /// A profile naming the linker file the driver's link line also runs is the profile's
    /// naming: the path's source is the profile, which said so first.
    #[test]
    fn a_profile_named_linker_the_line_also_runs_is_the_profile_s() {
        let shims = Shims::new("ldpath-runs");
        let mold = Shims::linker(&shims.subdir("elsewhere"), "mold", MOLD);
        let driver = Shims::script(
            &shims.dir.join("cc"),
            &format!(
                "echo ' \"{}\" \"-o\" \"/dev/null\"' >&2\nexit 0",
                mold.display()
            ),
        );
        let flags = [format!("--ld-path={}", mold.display())];
        let linker = detect_linker_on(
            &driver,
            &flags,
            shims.subdir("empty").as_os_str(),
            Path::new(""),
        );
        assert_eq!(
            linker.path_source,
            Some(PathSource::Profile),
            "detection: {}",
            linker.detection
        );
        assert!(
            linker
                .detection
                .contains(&format!("the profile names {} outright", mold.display())),
            "{}",
            linker.detection
        );
    }

    /// The toolchain's own target architecture is read from the driver's triple, and a
    /// driver that named none has none.
    #[test]
    fn the_target_architecture_is_the_triple_s() {
        let mut detected = detected_fixture(PathBuf::from("cc"));
        assert_eq!(detected.target_arch(), None);
        detected.target_triple = Some("aarch64-linux-gnu".to_owned());
        assert_eq!(detected.target_arch().as_deref(), Some("aarch64"));
    }

    /// A `-Wp,` list selects a system root only where one of its items is `-isysroot`.
    #[test]
    fn a_preprocessor_list_selects_a_root_only_through_isysroot() {
        assert_eq!(target_word("-Wp,-isysroot,/sdk"), Some((false, Takes::One)));
        assert_eq!(target_word("-Wp,-DNDEBUG"), None);
    }

    /// Another linker's line at the banner's own version number disagrees on its kind.
    #[test]
    fn another_linker_at_the_banner_s_version_disagrees_on_its_kind() {
        let crossed = agreement(
            "mold",
            "mold 22.1.8 (compatible with GNU ld)",
            &[artifact("x sha256:aa", &[LLD_LINE])],
        );
        assert_eq!(
            crossed.agreement,
            Agreement::Disagrees,
            "{}",
            crossed.evidence
        );
        assert!(
            crossed.evidence.contains("while the --version banner"),
            "{}",
            crossed.evidence
        );
    }

    /// `--ld-path=` names the file outright, so no driver query is needed and the path is
    /// the profile's own.
    #[test]
    fn a_profile_can_name_the_linker_file_outright() {
        let shims = Shims::new("ldpath");
        let mold = Shims::linker(&shims.subdir("elsewhere"), "mold", MOLD);
        // A driver that cannot answer anything, to show it was not asked.
        let driver = Shims::script(&shims.dir.join("cc"), "exit 1");

        let flags = [format!("--ld-path={}", mold.display())];
        let linker = detect_linker_on(
            &driver,
            &flags,
            shims.subdir("empty").as_os_str(),
            Path::new(""),
        );
        assert_eq!(linker.kind, "mold", "detection: {}", linker.detection);
        assert_eq!(
            linker.path.as_deref(),
            Some(mold.display().to_string().as_str()),
            "detection: {}",
            linker.detection
        );
        assert_eq!(
            linker.path_source,
            Some(PathSource::Profile),
            "detection: {}",
            linker.detection
        );
        assert_eq!(linker.profile_flags, flags.to_vec());
        // The driver exited 1 on `-###`, and the detection says so before the profile's
        // naming, so the cause is not dropped.
        assert_eq!(
            linker.detection,
            format!(
                "the driver exited 1 on its -### listing under the link-selection flag \
                 --ld-path={mold} (no diagnostic on stderr), so its link line was not read, \
                 and the profile names {mold} outright; its --version banner names the kind",
                mold = mold.display()
            )
        );
    }

    /// A name the driver cannot find and PATH does not hold is `unknown` with no path,
    /// and the detection says where it looked. Guessing the default `ld` here would name
    /// a linker the build will not use, since the build fails instead.
    #[test]
    fn a_linker_found_nowhere_is_unknown_rather_than_guessed() {
        let shims = Shims::new("nowhere");
        let empty = shims.subdir("empty");
        let driver = shims.driver();

        let flags = ["-fuse-ld=mold".to_owned()];
        let linker = detect_linker_on(&driver, &flags, empty.as_os_str(), Path::new(""));
        assert_eq!(linker.kind, "unknown", "detection: {}", linker.detection);
        assert!(linker.path.is_none());
        assert!(linker.path_source.is_none());
        assert_eq!(linker.profile_flags, flags.to_vec());
        assert!(
            linker.detection.contains("ld.mold") && linker.detection.contains("PATH"),
            "{}",
            linker.detection
        );
    }

    /// A linker that answers `--version` with nothing keeps its path and loses its kind,
    /// and the detection says no banner arrived rather than claiming one named the kind.
    /// The shim exits 0. Apple's ld64, which does not know `--version`, prints nothing on
    /// stdout and exits 1 (macOS 27 arm64, ld-27037.1), so it reads as a failed `--version`
    /// ([`a_failed_linker_version_names_how_it_ended_and_reads_no_banner`]).
    #[test]
    fn a_silent_linker_keeps_its_path_and_says_no_banner_arrived() {
        let shims = Shims::new("silent");
        let bin = shims.subdir("bin");
        let ld = Shims::linker(&bin, "ld", "");
        let driver = shims.driver();

        let linker = detect_linker_on(&driver, &[], bin.as_os_str(), Path::new(""));
        assert_eq!(linker.kind, "unknown", "detection: {}", linker.detection);
        assert!(linker.version.is_none());
        assert_eq!(
            linker.path.as_deref(),
            Some(ld.display().to_string().as_str()),
            "detection: {}",
            linker.detection
        );
        assert_eq!(
            linker.path_source,
            Some(PathSource::PathSearch),
            "detection: {}",
            linker.detection
        );
        assert!(
            linker.detection.contains("no --version banner"),
            "{}",
            linker.detection
        );
    }

    /// A `-print-prog-name` that fails, or exits 0 with its answer cut off, is refused
    /// before its output is read, whatever it printed, and no `PATH` search stands in for
    /// it; the same answer whole at exit 0 is read.
    /// Both an absolute path and a bare name that `PATH` would resolve, so neither route
    /// past the query reads a failed job.
    #[test]
    fn a_failed_print_prog_name_publishes_no_linker_path() {
        let shims = Shims::new("prog-name-status");
        let bin = shims.subdir("bin");
        let ld = Shims::linker(&bin, "ld", "GNU ld (GNU Binutils) 2.46");
        for (printed, source) in [
            (ld.display().to_string(), PathSource::Driver),
            ("ld".to_owned(), PathSource::PathSearch),
        ] {
            for (case, (body, refused)) in [
                (format!("echo '{printed}'; exit 0"), None),
                (format!("echo '{printed}'; exit 1"), Some(compile::ended(1))),
                (
                    format!("printf '%s' '{printed}'; exit 0"),
                    Some(format!("{} {}", compile::ended(0), compile::CUT_OFF)),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let driver = Shims::script(
                    &shims.dir.join(format!("cc-{case}-{}", printed.len())),
                    &body,
                );
                let linker = detect_linker_on(&driver, &[], bin.as_os_str(), Path::new(""));
                if let Some(ended) = refused {
                    assert_eq!(linker.kind, "unknown", "detection: {}", linker.detection);
                    assert!(linker.version.is_none());
                    assert!(linker.path.is_none(), "detection: {}", linker.detection);
                    assert!(linker.path_source.is_none());
                    assert!(
                        linker.detection.ends_with(&format!(
                            "-print-prog-name=ld {ended}, so chard read no linker path from \
                             its output"
                        )),
                        "{}",
                        linker.detection
                    );
                } else {
                    assert_eq!(linker.kind, "bfd", "detection: {}", linker.detection);
                    assert_eq!(
                        linker.path.as_deref(),
                        Some(ld.display().to_string().as_str()),
                        "detection: {}",
                        linker.detection
                    );
                    assert_eq!(linker.path_source, Some(source));
                }
            }
        }
    }

    /// A linker whose `--version` fails, or exits 0 with its banner cut off, keeps its path
    /// and gives no kind or version, and the detection says how the job ended rather than
    /// that it did not answer; the same banner whole at exit 0 is read as `bfd`.
    #[test]
    fn a_failed_linker_version_names_how_it_ended_and_reads_no_banner() {
        let shims = Shims::new("linker-version-status");
        let banner = "GNU ld (GNU Binutils) 2.46";
        let driver = shims.driver();
        for (case, (body, refused)) in [
            (format!("echo '{banner}'; exit 0"), None),
            (format!("echo '{banner}'; exit 1"), Some(compile::ended(1))),
            (
                format!("printf '%s' '{banner}'; exit 0"),
                Some(format!("{} {}", compile::ended(0), compile::CUT_OFF)),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let bin = shims.subdir(&format!("bin-{case}"));
            let ld = Shims::script(&bin.join("ld"), &body);
            let linker = detect_linker_on(&driver, &[], bin.as_os_str(), Path::new(""));
            assert_eq!(
                linker.path.as_deref(),
                Some(ld.display().to_string().as_str()),
                "the path is the route's either way: {}",
                linker.detection
            );
            assert_eq!(linker.path_source, Some(PathSource::PathSearch));
            match refused {
                None => {
                    assert_eq!(linker.kind, "bfd", "detection: {}", linker.detection);
                    assert_eq!(linker.version.as_deref(), Some(banner));
                }
                Some(ended) => {
                    assert_eq!(linker.kind, "unknown", "detection: {}", linker.detection);
                    assert!(linker.version.is_none());
                    assert!(
                        linker.detection.ends_with(&format!(
                            "; its --version {ended}, so chard read no kind or version from it"
                        )) && !linker.detection.contains("did not answer"),
                        "{}",
                        linker.detection
                    );
                }
            }
        }
    }

    /// The banners the four linkers print, and the compatibility clause two of them add,
    /// which quotes bfd's wording and must not be read as bfd.
    #[test]
    fn a_banner_names_its_own_linker_and_not_the_one_it_is_compatible_with() {
        assert_eq!(linker_kind(BFD), "bfd");
        assert_eq!(linker_kind(GOLD), "gold");
        assert_eq!(linker_kind(LLD), "lld");
        assert_eq!(linker_kind(MOLD), "mold");
        assert_eq!(linker_kind("GNU ld (GNU Binutils for Ubuntu) 2.42"), "bfd");
        assert_eq!(linker_kind(""), "unknown");
        assert_eq!(linker_kind("@(#)PROGRAM:ld  PROJECT:ld-1167.5"), "unknown");
    }

    /// `--prefix=<dir>` and `--prefix <dir>` are `-B` to gcc 16.1.1 and clang 22.1.8
    /// (measured 2026-10-06 on Fedora 44 x86_64: each linked the `crtbegin.o` of a prefix
    /// directory whose copy lacked the x86 feature note), so the linker query asks through
    /// them as through `-B`, and an arm takes them from the runtime selection, not here.
    #[test]
    fn link_selection_reads_prefix_as_the_drivers_read_it() {
        let flags: Vec<String> = [
            "-O2",
            "--prefix=/opt/a/",
            "--prefix",
            "/opt/b/",
            "-fuse-ld=lld",
            "--ld-path=/opt/ld",
            "--prefix=",
            "--prefix",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let selection = link_selection(&flags);
        assert_eq!(
            selection.prefixes,
            vec!["-B/opt/a/".to_owned(), "-B/opt/b/".to_owned()],
            "both spellings are prefixes; an empty one and a dangling one name no directory"
        );
        assert_eq!(
            selection.consulted,
            vec![
                "--prefix=/opt/a/",
                "--prefix",
                "/opt/b/",
                "-fuse-ld=lld",
                "--ld-path=/opt/ld",
                "--prefix="
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
        );
        assert_eq!(
            linker_program_flags(&flags),
            vec!["-fuse-ld=lld".to_owned(), "--ld-path=/opt/ld".to_owned()]
        );
        assert!(
            linker_program_flags(&["-B/opt/c".to_owned(), "--prefix=/opt/d".to_owned()]).is_empty(),
            "prefixes alone name no program"
        );
    }

    /// The flags are read the way the driver reads them: the last selection wins, the
    /// default can be spelled, a flavour with a slash is a file, and the two-token `-B`
    /// is one prefix.
    #[test]
    fn link_selection_reads_the_flags_the_driver_would() {
        let flags: Vec<String> = [
            "-O2",
            "-fuse-ld=gold",
            "-Wl,-z,now",
            "-B",
            "/opt/tc/bin",
            "-B/opt/other/",
            "-fuse-ld=lld",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let selection = link_selection(&flags);
        assert_eq!(selection.program, Some(Program::Named("ld.lld".to_owned())));
        assert_eq!(
            selection.prefixes,
            vec!["-B/opt/tc/bin".to_owned(), "-B/opt/other/".to_owned()]
        );
        assert_eq!(
            selection.consulted,
            vec![
                "-fuse-ld=gold".to_owned(),
                "-B".to_owned(),
                "/opt/tc/bin".to_owned(),
                "-B/opt/other/".to_owned(),
                "-fuse-ld=lld".to_owned(),
            ]
        );

        assert_eq!(
            linker_program_flags(&flags),
            vec!["-fuse-ld=gold".to_owned(), "-fuse-ld=lld".to_owned()],
            "the program flags, without the prefixes the runtime selection carries"
        );

        let one = |flag: &str| link_selection(&[flag.to_owned()]).program;
        assert_eq!(one("-fuse-ld=ld"), Some(Program::Default));
        assert_eq!(one("-fuse-ld="), Some(Program::Default));
        assert_eq!(
            one("-fuse-ld=/opt/ld/bin/ld"),
            Some(Program::File(PathBuf::from("/opt/ld/bin/ld")))
        );
        assert_eq!(
            one("--ld-path=/opt/mold/bin/mold"),
            Some(Program::File(PathBuf::from("/opt/mold/bin/mold")))
        );
        assert_eq!(
            link_selection(&["-O2".to_owned()]),
            LinkSelection::default()
        );
    }

    /// clang's `--ld-path=` outranks a `-fuse-ld=` written after it, in each form the
    /// later flag takes, and that flag is still consulted. [`LinkSelection`] carries the
    /// measurement.
    #[test]
    fn an_ld_path_outranks_a_later_fuse_ld() {
        let read = |flags: &[&str]| {
            link_selection(&flags.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        };
        let mold = Some(Program::File(PathBuf::from("/opt/mold/bin/mold")));
        for later in ["-fuse-ld=bfd", "-fuse-ld=/opt/ld/bin/ld", "-fuse-ld=ld"] {
            let selection = read(&["--ld-path=/opt/mold/bin/mold", later]);
            assert_eq!(selection.program, mold, "{later} after --ld-path=");
            assert_eq!(
                selection.consulted,
                ["--ld-path=/opt/mold/bin/mold", later],
                "the overridden flag is still one the profile carried"
            );
            assert_eq!(
                read(&[later, "--ld-path=/opt/mold/bin/mold"]).program,
                mold,
                "{later} before --ld-path="
            );
        }
        assert_eq!(
            read(&["--ld-path=/opt/a/ld", "--ld-path=/opt/mold/bin/mold"]).program,
            mold,
            "the last --ld-path= is the one clang reads"
        );
    }

    /// A `Detected` with nothing measured behind it: the shim drivers given, a sentinel
    /// linker that any re-detection replaces, and every other field empty.
    fn undetected(driver: PathBuf, cxx_driver: Option<PathBuf>) -> Detected {
        Detected {
            kind: Kind::Other,
            version: "0".to_owned(),
            version_raw: None,
            target_triple: None,
            driver: driver.display().to_string(),
            cxx_driver: cxx_driver.as_ref().map(|p| p.display().to_string()),
            configure_args: None,
            config_files: Vec::new(),
            query_failures: Vec::new(),
            linker: Linker {
                kind: "sentinel".to_owned(),
                version: None,
                path: None,
                path_source: None,
                profile_flags: Vec::new(),
                detection: "the default detection".to_owned(),
                artifact: None,
                cxx: None,
            },
            target: None,
            predefined_macros_sha256: String::new(),
            predefined_macros: None,
            libc_headers_error: None,
            fhardened_fortify: FhardenedFortify::refused(),
            macros_with_headers: BTreeMap::new(),
            arch_macros: Vec::new(),
            arch_abi: None,
            profile_macros: None,
            profile_macros_cxx: None,
            driver_path: driver,
            cxx_driver_path: cxx_driver,
        }
    }

    /// A `Detected` for tests of the two-step publication: `undetected` with a gcc
    /// identity, so the composed key has halves to read.
    fn detected_fixture(driver: PathBuf) -> Detected {
        Detected {
            kind: Kind::Gcc,
            version: "16.1.1".to_owned(),
            ..undetected(driver, None)
        }
    }

    /// The join key is composed from the four halves and read back through `id()`, and
    /// the composition is the one function the consistency of the key rests on.
    #[test]
    fn qualified_composes_the_join_key_from_the_tags() {
        let toolchain = detected_fixture(PathBuf::from("cc")).qualified("glibc2.43", "fedora44");
        assert_eq!(toolchain.id(), "gcc-16.1.1-glibc2.43-fedora44");
        assert_eq!(
            toolchain.id(),
            join_key(Kind::Gcc, "16.1.1", "glibc2.43", "fedora44")
        );
        // The published object is flat, and the key is its first field: the report is
        // streamed in declaration order, and a `Toolchain` declares `id` before the
        // flattened half, which is the order every report before the split had.
        let streamed = serde_json::to_string(&toolchain).expect("serializes");
        assert!(
            streamed.starts_with(r#"{"id":"gcc-16.1.1-glibc2.43-fedora44","kind":"gcc","#),
            "the key leads and the detected half follows it flat: {streamed}"
        );
        let published = serde_json::to_value(&toolchain).expect("serializes");
        assert_eq!(published["kind"], "gcc");
        assert_eq!(published["version"], "16.1.1");
        assert!(
            published.get("detected").is_none(),
            "the detected half is flattened, so no nested object is published: {published}"
        );
    }

    /// A `Detected` carries no `id`, so one that reached a report would fail the schema
    /// on a required field rather than publish a plausible key. No runtime check stands
    /// behind `Report.toolchain` being a `Toolchain`; the type does, and this is what
    /// makes a leak visible.
    #[test]
    fn a_detected_toolchain_serializes_without_an_id() {
        let published =
            serde_json::to_value(detected_fixture(PathBuf::from("cc"))).expect("serializes");
        assert!(
            published.get("id").is_none(),
            "a Detected must not carry a join key: {published}"
        );
        assert_eq!(published["kind"], "gcc");
    }

    /// `link_with` re-detects only when the profile selects something, so a `bare` run
    /// keeps the default detection and an `explicit` run with `--ld-path=` replaces it.
    #[test]
    fn link_with_replaces_the_default_only_when_the_profile_selects() {
        let shims = Shims::new("linkwith");
        let mold = Shims::linker(&shims.subdir("elsewhere"), "mold", MOLD);
        let driver = Shims::script(&shims.dir.join("cc"), "exit 1");
        let mut toolchain = undetected(driver, None);

        let plain = ["-O2".to_owned(), "-fstack-protector-strong".to_owned()];
        toolchain.link_with(&plain, &plain, Path::new(""));
        assert_eq!(
            toolchain.linker.kind, "sentinel",
            "nothing selected, nothing replaced"
        );

        let selects = [format!("--ld-path={}", mold.display())];
        toolchain.link_with(&selects, &selects, Path::new(""));
        assert_eq!(
            toolchain.linker.kind, "mold",
            "detection: {}",
            toolchain.linker.detection
        );
        assert_eq!(
            toolchain.linker.path_source,
            Some(PathSource::Profile),
            "detection: {}",
            toolchain.linker.detection
        );
    }

    const GCC_LINE: &str = "GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)";
    const CLANG_LINE: &str = "clang version 22.1.8 (Fedora 22.1.8-4.fc44)";
    const LLD_LINE: &str = "Linker: LLD 22.1.8";
    const LLD_OLD_LINE: &str = "Linker: Ubuntu LLD 18.1.3";
    const MOLD_LINE: &str = "mold 2.40.4 (compatible with GNU ld)";
    const LLD_BANNER: &str = "LLD 22.1.8 (compatible with GNU linkers)";
    const MOLD_BANNER: &str = "mold 2.40.4 (compatible with GNU ld)";

    /// A counted artifact carrying `lines`.
    fn artifact(label: &str, lines: &[&str]) -> ArtifactComment {
        ArtifactComment {
            label: label.to_owned(),
            lines: lines.iter().map(|l| (*l).to_owned()).collect(),
            unread: None,
            relocatable: false,
            profile_free: false,
        }
    }

    /// The artifacts alone, every probe having contributed one and the profile having
    /// selected nothing.
    fn witnesses(artifacts: &[ArtifactComment]) -> Witnesses {
        Witnesses {
            artifacts: artifacts.to_vec(),
            without_facts: Vec::new(),
            selection: Vec::new(),
        }
    }

    /// [`artifact_agreement`] with an empty banner standing for none.
    fn agreement(kind: &str, banner: &str, artifacts: &[ArtifactComment]) -> ArtifactAgreement {
        artifact_agreement(
            kind,
            (!banner.is_empty()).then_some(banner),
            &witnesses(artifacts),
        )
    }

    /// The artifacts' verdict over lines that name a linker: agreement on kind and
    /// version, and the three ways signed artifacts can disagree.
    ///
    /// The version is compared because a shim that answers with the right kind and the
    /// wrong version is exactly the substitution the check exists for, and two artifacts
    /// of one run that name different linkers disagree with each other whatever the
    /// banner says.
    #[test]
    fn artifact_agreement_reads_the_lines_a_linker_writes() {
        let lld = agreement(
            "lld",
            LLD_BANNER,
            &[
                artifact("link-defaults-clean sha256:aa", &[LLD_LINE, GCC_LINE]),
                artifact(
                    "shared-object-defaults-clean sha256:bb",
                    &[GCC_LINE, LLD_LINE],
                ),
            ],
        );
        assert_eq!(lld.agreement, Agreement::Agrees, "{}", lld.evidence);
        assert_eq!(lld.signature.as_deref(), Some(LLD_LINE));
        assert_eq!(lld.artifacts_read, 2);

        let vendor = agreement("lld", LLD, &[artifact("x sha256:aa", &[LLD_OLD_LINE])]);
        assert_eq!(
            vendor.agreement,
            Agreement::Agrees,
            "a vendor word before LLD is part of the grammar: {}",
            vendor.evidence
        );

        let older = agreement(
            "lld",
            LLD_BANNER,
            &[artifact("x sha256:aa", &[LLD_OLD_LINE])],
        );
        assert_eq!(older.agreement, Agreement::Disagrees, "{}", older.evidence);
        assert!(
            older.evidence.contains("18.1.3") && older.evidence.contains("22.1.8"),
            "both versions are named: {}",
            older.evidence
        );

        let wrong_kind = agreement("bfd", BFD, &[artifact("x sha256:aa", &[LLD_LINE])]);
        assert_eq!(
            wrong_kind.agreement,
            Agreement::Disagrees,
            "{}",
            wrong_kind.evidence
        );
        assert_eq!(wrong_kind.signature.as_deref(), Some(LLD_LINE));

        let mold = agreement(
            "mold",
            MOLD_BANNER,
            &[artifact("x sha256:aa", &[GCC_LINE, MOLD_LINE])],
        );
        assert_eq!(mold.agreement, Agreement::Agrees, "{}", mold.evidence);
        assert_eq!(mold.signature.as_deref(), Some(MOLD_LINE));

        let mixed = agreement(
            "gold",
            GOLD,
            &[
                artifact("a-clean sha256:aa", &[GCC_LINE]),
                artifact("b-clean sha256:bb", &[LLD_LINE]),
            ],
        );
        assert_eq!(mixed.agreement, Agreement::Disagrees, "{}", mixed.evidence);
        assert!(
            mixed.evidence.contains("a-clean sha256:aa") && mixed.evidence.contains("b-clean"),
            "both artifacts are named: {}",
            mixed.evidence
        );
        assert_eq!(mixed.artifacts_read, 2);

        // A banner with no version quoted agrees on the kind alone.
        let no_banner = agreement("lld", "", &[artifact("x sha256:aa", &[LLD_LINE])]);
        assert_eq!(
            no_banner.agreement,
            Agreement::Agrees,
            "{}",
            no_banner.evidence
        );
    }

    /// A banner chard could not read leaves the artifact as the only witness, and that
    /// is its own value.
    ///
    /// `kind` is `unknown` when the program printed no banner, one outside the grammar,
    /// or failed `--version`, or no linker path was read; each is a gap in what chard read
    /// and none is a finding
    /// about the environment. Publishing `disagrees` there, with the error diagnostic
    /// that value carries, would accuse a `PATH` of lying when the report names nothing
    /// for the artifact to contradict. The line is carried as `signature`, and over
    /// unsigned artifacts the verdict stays `no-signature` with evidence that says what
    /// the unknown banner leaves unestablished.
    #[test]
    fn artifact_agreement_over_an_unread_banner_is_the_artifacts_word_alone() {
        for banner in ["", "@(#)PROGRAM:ld  PROJECT:ld-1167.5"] {
            let only = agreement(
                "unknown",
                banner,
                &[
                    artifact("link-defaults-measured sha256:aa", &[GCC_LINE, LLD_LINE]),
                    artifact("shared-object-defaults-measured sha256:bb", &[LLD_LINE]),
                ],
            );
            assert_eq!(
                only.agreement,
                Agreement::ArtifactOnly,
                "banner {banner:?}: {}",
                only.evidence
            );
            assert_eq!(only.signature.as_deref(), Some(LLD_LINE));
            assert_eq!(only.artifacts_read, 2);
            assert!(
                only.evidence.contains("only witness")
                    && only.evidence.contains("names a linker it recognises")
                    && only.evidence.contains(LLD_LINE),
                "{}",
                only.evidence
            );
        }

        let unsigned = agreement("unknown", "", &[artifact("x sha256:aa", &[GCC_LINE])]);
        assert_eq!(
            unsigned.agreement,
            Agreement::NoSignature,
            "{}",
            unsigned.evidence
        );
        assert!(
            unsigned.evidence.contains("names a linker it recognises")
                && !unsigned.evidence.contains("writes no line"),
            "an unrecognised banner says nothing about what its linker writes: {}",
            unsigned.evidence
        );

        // Two artifacts of one run naming different linkers disagree with each other
        // whatever the banner said, and an unread banner does not soften that.
        let mixed = agreement(
            "unknown",
            "",
            &[
                artifact("a-measured sha256:aa", &[MOLD_LINE]),
                artifact("b-measured sha256:bb", &[LLD_LINE]),
            ],
        );
        assert_eq!(mixed.agreement, Agreement::Disagrees, "{}", mixed.evidence);
    }

    /// The artifacts' verdict over lines no linker wrote, where the two absences stay
    /// apart and neither reads as agreement.
    ///
    /// A `bfd` or `gold` banner over compiler-only lines is `no-signature` and never
    /// `agrees`, because those two write nothing and an agreement over nothing would be a
    /// clean-looking corroboration; an `lld` banner over compiler-only lines is
    /// `disagrees`, on the assumption `lld-and-mold-sign-every-output`; and an empty
    /// artifact list is `no-linked-artifact` with a zero denominator, whatever the banner
    /// named.
    #[test]
    fn artifact_agreement_reads_only_what_a_linker_writes() {
        let bfd = agreement(
            "bfd",
            BFD,
            &[artifact("link-defaults-clean sha256:aa", &[GCC_LINE])],
        );
        assert_eq!(bfd.agreement, Agreement::NoSignature, "{}", bfd.evidence);
        assert_eq!(bfd.artifacts_read, 1);
        assert!(bfd.signature.is_none());
        assert!(
            bfd.evidence.contains("cannot be corroborated") && bfd.evidence.contains(GCC_LINE),
            "{}",
            bfd.evidence
        );
        let gold = agreement(
            "gold",
            GOLD,
            &[artifact("link-defaults-clean sha256:aa", &[CLANG_LINE])],
        );
        assert_eq!(gold.agreement, Agreement::NoSignature, "{}", gold.evidence);

        let unsigned = agreement("lld", LLD_BANNER, &[artifact("x sha256:aa", &[GCC_LINE])]);
        assert_eq!(
            unsigned.agreement,
            Agreement::Disagrees,
            "{}",
            unsigned.evidence
        );
        assert!(
            unsigned.evidence.contains("lld-and-mold-sign-every-output"),
            "the assumption is cited: {}",
            unsigned.evidence
        );

        let none = agreement("bfd", BFD, &[]);
        assert_eq!(none.agreement, Agreement::NoLinkedArtifact);
        assert_eq!(none.artifacts_read, 0);
        let none_lld = agreement("lld", LLD_BANNER, &[]);
        assert_eq!(
            none_lld.agreement,
            Agreement::NoLinkedArtifact,
            "nothing read is not a missing signature"
        );
    }

    /// Relocatables, unread `.comment` sections and artifacts linked before the profile's
    /// selection are named and left out of the count, the probes that handed over no
    /// artifact are named beside them, and a run whose every artifact is excluded is
    /// `no-linked-artifact` whose evidence says that artifacts were read and none counted,
    /// apart from the wording a run that read nothing gets.
    #[test]
    fn artifact_agreement_counts_only_what_it_read() {
        const GCC: &str = "GCC: (GNU) 16.2.1";
        let linked = ArtifactComment {
            label: "link-defaults-measured sha256:aa".to_owned(),
            lines: vec![GCC.to_owned()],
            unread: None,
            relocatable: false,
            profile_free: false,
        };
        let relocatable = ArtifactComment {
            label: "cet-marked-measured sha256:bb".to_owned(),
            lines: vec![GCC.to_owned()],
            unread: None,
            relocatable: true,
            profile_free: false,
        };
        let unread = ArtifactComment {
            label: "stack-canary-measured sha256:cc".to_owned(),
            lines: Vec::new(),
            unread: Some(".comment: 0x900+0x40 could not be read".to_owned()),
            relocatable: false,
            profile_free: false,
        };

        let some = artifact_agreement(
            "lld",
            Some("LLD 22.1.8"),
            &Witnesses {
                artifacts: vec![linked.clone(), relocatable.clone(), unread.clone()],
                without_facts: vec!["aarch64-gcs".to_owned(), "fortify-source".to_owned()],
                selection: Vec::new(),
            },
        );
        assert_eq!(some.artifacts_read, 1, "{}", some.evidence);
        assert_eq!(some.agreement, Agreement::Disagrees, "{}", some.evidence);
        assert!(
            some.evidence
                .contains("1 relocatable artifact(s) left uncounted")
                && some.evidence.contains("cet-marked-measured sha256:bb")
                && some
                    .evidence
                    .contains("left uncounted because .comment could not be read")
                && some.evidence.contains("stack-canary-measured sha256:cc")
                && some.evidence.contains(
                    "2 probe(s) contributed no readable artifact: aarch64-gcs, fortify-source"
                ),
            "{}",
            some.evidence
        );

        let nothing = artifact_agreement(
            "lld",
            Some("LLD 22.1.8"),
            &witnesses(&[relocatable, unread]),
        );
        assert_eq!(
            nothing.agreement,
            Agreement::NoLinkedArtifact,
            "{}",
            nothing.evidence
        );
        assert_eq!(nothing.artifacts_read, 0);
        assert!(
            nothing
                .evidence
                .starts_with("none of the 2 artifact(s) read could be counted")
                && !nothing.evidence.contains("no linked ELF artifact was read")
                && nothing.evidence.contains("left uncounted")
                && !nothing
                    .evidence
                    .contains("contributed no readable artifact"),
            "two artifacts were read and the evidence must say so: {}",
            nothing.evidence
        );

        let empty = artifact_agreement("lld", Some("LLD 22.1.8"), &Witnesses::default());
        assert_eq!(empty.agreement, Agreement::NoLinkedArtifact);
        assert_eq!(empty.artifacts_read, 0);
        assert!(
            empty
                .evidence
                .starts_with("no linked ELF artifact was read in this run")
                && !empty.evidence.contains("could be counted"),
            "nothing read is worded as nothing read: {}",
            empty.evidence
        );
    }

    /// A disagreement names the artifact it rests on, and its clause states the reason
    /// the verdict turned on.
    ///
    /// The error diagnostic quotes this evidence verbatim, so a `disagrees` that named no
    /// artifact would be the report's loudest finding pointing at nothing a reader can
    /// take to `build.artifact_sha256`. Two signed artifacts were linked by two linkers,
    /// and the assumption that lld and mold sign every output is cited only where an
    /// unsigned artifact is what the verdict turned on.
    #[test]
    fn a_disagreement_names_the_artifact_it_rests_on() {
        let wrong_kind = agreement("bfd", BFD, &[artifact("x-measured sha256:aa", &[LLD_LINE])]);
        assert_eq!(wrong_kind.agreement, Agreement::Disagrees);
        assert!(
            wrong_kind.evidence.ends_with("first x-measured sha256:aa"),
            "{}",
            wrong_kind.evidence
        );

        let older = agreement(
            "lld",
            LLD_BANNER,
            &[artifact("y-measured sha256:bb", &[LLD_OLD_LINE])],
        );
        assert_eq!(older.agreement, Agreement::Disagrees);
        assert!(
            older.evidence.ends_with("first y-measured sha256:bb"),
            "{}",
            older.evidence
        );

        let two_linkers = agreement(
            "lld",
            LLD_BANNER,
            &[
                artifact("a-measured sha256:aa", &[LLD_LINE]),
                artifact("b-measured sha256:bb", &[MOLD_LINE]),
            ],
        );
        assert_eq!(two_linkers.agreement, Agreement::Disagrees);
        assert!(
            two_linkers
                .evidence
                .contains("two linkers linked this run's artifacts")
                && !two_linkers.evidence.contains("every output they link"),
            "{}",
            two_linkers.evidence
        );

        let one_unsigned = agreement(
            "lld",
            LLD_BANNER,
            &[
                artifact("a-measured sha256:aa", &[LLD_LINE]),
                artifact("b-measured sha256:bb", &[GCC_LINE]),
            ],
        );
        assert_eq!(one_unsigned.agreement, Agreement::Disagrees);
        assert!(
            one_unsigned
                .evidence
                .contains("write a line into every output they link")
                && one_unsigned.evidence.contains("no linker line")
                && !one_unsigned.evidence.contains("two linkers linked"),
            "{}",
            one_unsigned.evidence
        );
    }

    /// An artifact read from the clean build under a profile that selected a linker is
    /// named beside the selection and left out of the count, so the profile's linker is
    /// held to the artifacts its link line produced and to nothing else.
    ///
    /// The shape that produced a false `disagrees`: `linker-default-noexecstack` reads
    /// the clean build (`Check::measures_toolchain_default`), so under
    /// `--flags -fuse-ld=lld` its artifact carries the compiler line only while every
    /// other artifact carries `Linker: LLD`. Counted, the pair read as the run's own
    /// artifacts disagreeing, with an error diagnostic on a run whose banner was exactly
    /// right.
    #[test]
    fn an_artifact_linked_before_the_selection_is_named_and_not_counted() {
        let selected = artifact("link-defaults-measured sha256:aa", &[GCC_LINE, LLD_LINE]);
        let default = ArtifactComment {
            label: "linker-default-execstack-clean sha256:bb".to_owned(),
            lines: vec![GCC_LINE.to_owned()],
            unread: None,
            relocatable: false,
            profile_free: true,
        };
        let held = artifact_agreement(
            "lld",
            Some(LLD_BANNER),
            &Witnesses {
                artifacts: vec![selected, default.clone()],
                without_facts: Vec::new(),
                selection: vec!["-fuse-ld=lld".to_owned()],
            },
        );
        assert_eq!(held.agreement, Agreement::Agrees, "{}", held.evidence);
        assert_eq!(held.artifacts_read, 1, "{}", held.evidence);
        assert_eq!(held.signature.as_deref(), Some(LLD_LINE));
        assert!(
            held.evidence.contains(
                "1 artifact(s) linked under the driver default while the profile selected \
                 `-fuse-ld=lld`, left uncounted"
            ) && held
                .evidence
                .contains("linker-default-execstack-clean sha256:bb"),
            "the selection the artifact was linked without is quoted: {}",
            held.evidence
        );

        // Alone, it is nothing read; counting it would corroborate a linker that had no
        // part in it.
        let alone = agreement("lld", LLD_BANNER, &[default]);
        assert_eq!(
            alone.agreement,
            Agreement::NoLinkedArtifact,
            "{}",
            alone.evidence
        );
        assert_eq!(alone.artifacts_read, 0);
    }

    /// A `.comment` line is a linker's only when it is lld's or mold's.
    #[test]
    fn linker_line_reads_the_two_grammars_and_nothing_else() {
        assert_eq!(linker_line("Linker: LLD 22.1.8"), Some(("lld", "22.1.8")));
        assert_eq!(
            linker_line("Linker: Ubuntu LLD 18.1.3"),
            Some(("lld", "18.1.3"))
        );
        assert_eq!(
            linker_line("mold 2.40.4 (compatible with GNU ld)"),
            Some(("mold", "2.40.4"))
        );
        assert_eq!(linker_line("mold 1.0.3"), Some(("mold", "1.0.3")));
        assert_eq!(
            linker_line("GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)"),
            None
        );
        assert_eq!(
            linker_line("clang version 22.1.8 (Fedora 22.1.8-4.fc44)"),
            None
        );
        assert_eq!(linker_line("rustc version 1.99.0"), None);
        assert_eq!(linker_line("Android (12345) clang version 17"), None);
        assert_eq!(
            linker_line("Linker: "),
            None,
            "a prefix with nothing after it"
        );
        assert_eq!(
            linker_line("mold"),
            None,
            "the word alone quotes no version"
        );
    }

    /// A selection present only in cxxflags is published as the C++ probes' linker,
    /// queried through the C++ driver, and the C linker stands unchanged.
    ///
    /// `-fuse-ld=` in cxxflags alone reaches one real link (the C++ probe, built with
    /// cxxflags when the profile has them), so it is published as `linker.cxx`, with the
    /// flag in its `profile_flags`, rather than left invisible by reading cflags and
    /// ldflags only; and when the two selections
    /// agree there is one linker and no `cxx`.
    #[test]
    fn a_cxxflags_only_selection_is_published_as_the_cxx_linker() {
        let shims = Shims::new("cxxonly");
        let bin = shims.subdir("bin");
        Shims::linker(&bin, "ld.lld", LLD);
        let mold = Shims::linker(&shims.subdir("elsewhere"), "mold", MOLD);
        let driver = shims.driver();
        // A C++ driver that answers every query with mold's path, so a linker found
        // through it can only have come through it.
        let cxx_driver = Shims::script(
            &shims.dir.join("c++"),
            &format!("echo '{}'", mold.display()),
        );
        let mut toolchain = undetected(driver, Some(cxx_driver));

        let c_link = ["-O2".to_owned()];
        let cxx_link = ["-fuse-ld=mold".to_owned()];
        toolchain.link_with(&c_link, &cxx_link, Path::new(""));
        assert_eq!(
            toolchain.linker.kind, "sentinel",
            "the C link selected nothing"
        );
        let cxx = toolchain
            .linker
            .cxx
            .as_deref()
            .expect("the C++ selection is published");
        assert_eq!(cxx.kind, "mold", "detection: {}", cxx.detection);
        assert_eq!(cxx.profile_flags, vec!["-fuse-ld=mold".to_owned()]);
        assert!(cxx.cxx.is_none(), "cxx never carries a cxx");
        assert!(
            cxx.detection.starts_with("c++ -print-prog-name="),
            "the C++ driver is the one queried: {}",
            cxx.detection
        );

        // The same selection on both sides is one linker.
        let both = [format!("-B{}", bin.display()), "-fuse-ld=lld".to_owned()];
        toolchain.link_with(&both, &both, Path::new(""));
        assert_eq!(
            toolchain.linker.kind, "lld",
            "detection: {}",
            toolchain.linker.detection
        );
        assert!(toolchain.linker.cxx.is_none(), "{:?}", toolchain.linker.cxx);

        // `-fuse-ld=ld` names the default the other side already has, so it is no
        // difference; and with no C++ driver no C++ link runs, so no C++ linker is
        // published and `detection` records the selection that reached no link.
        toolchain.cxx_driver_path = None;
        toolchain.link_with(&[], &["-fuse-ld=ld".to_owned()], Path::new(""));
        assert!(toolchain.linker.cxx.is_none());
        assert!(
            !toolchain.linker.detection.contains("no C++ link ran"),
            "a selection equal to the default is no selection: {}",
            toolchain.linker.detection
        );
        toolchain.link_with(&[], &both, Path::new(""));
        assert!(
            toolchain.linker.cxx.is_none(),
            "a linker for a link that did not happen: {:?}",
            toolchain.linker.cxx
        );
        assert!(
            toolchain.linker.detection.contains("no C++ link ran")
                && toolchain.linker.detection.contains("-fuse-ld=lld"),
            "{}",
            toolchain.linker.detection
        );
    }

    /// gcc's specs file is a configuration file by the same rule as clang's, and the
    /// line saying none is loaded adds nothing.
    ///
    /// `gcc -v` opens with `Reading specs from <path>` when an installed specs file
    /// replaces the built-in specs, and with `Using built-in specs.` otherwise. Only
    /// clang's line was parsed, so a gcc measured through a specs file published
    /// `flags_source: none`, the value reserved for compiled-in defaults.
    #[test]
    fn parses_gcc_specs_file_as_a_configuration_file() {
        let with_specs = "Reading specs from /usr/lib/gcc/x86_64-linux-gnu/14/specs\n\
                          COLLECT_GCC=gcc\n\
                          Configured with: ../configure --enable-default-pie\n\
                          Thread model: posix\n";
        let (configure, configs) = parse_verbose(with_specs);
        assert_eq!(
            configure.as_deref(),
            Some("../configure --enable-default-pie")
        );
        assert_eq!(
            configs,
            vec!["/usr/lib/gcc/x86_64-linux-gnu/14/specs".to_owned()]
        );

        let built_in = "Using built-in specs.\nCOLLECT_GCC=gcc\n";
        assert!(
            parse_verbose(built_in).1.is_empty(),
            "built-in specs are the compiled-in defaults, and name no file"
        );
    }

    /// `detect` on a driver this test wrote, waiting out `ETXTBSY` the way `Shims::script`
    /// does: a sibling test's fork can hold the write descriptor, and the envelope classes
    /// that as a retry rather than as the caller's. Returns the first error that is not
    /// one, or the last one at the deadline.
    fn detect_waiting_out_etxtbsy(driver: &Path, work: &Path) -> anyhow::Error {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let err = detect(&driver.display().to_string(), work, false)
                .expect_err("a driver that cannot run is an error");
            if !crate::error::is_transient(&err) || std::time::Instant::now() >= deadline {
                return err;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// The two ways a `--cc` that exists can fail to run, and the owner each is given.
    ///
    /// A file with no execute bit is refused by `resolve_driver` from its metadata, before
    /// any spawn: the class was `PERMISSION`, and `chmod` is the wrong action for a text
    /// file. A `+x` file with no shebang is refused by the kernel at `execve` with
    /// `ENOEXEC`, which no `ErrorKind` names and which read as `INTERNAL`; the spawn's io
    /// error stays the root and `error::classify` reads the errno as the caller's. An
    /// `EACCES` that survives an executable mode (a `noexec` mount) is left to the spawn
    /// and stays `PERMISSION`, which is why the mode is read from metadata rather than
    /// learnt from the spawn's errno. Darwin runs the shebang-less file through `sh`
    /// instead of refusing it, so that arm is asserted on Linux and announced elsewhere.
    #[test]
    fn a_driver_that_cannot_be_executed_is_the_callers_to_fix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("chard-noexec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let unrunnable = dir.join("mode-644");
        std::fs::write(&unrunnable, "hello\n").expect("write");
        std::fs::set_permissions(&unrunnable, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 644");
        let err = resolve_driver(&unrunnable.display().to_string())
            .expect_err("a mode-644 file cannot be a compiler");
        let user = err
            .downcast_ref::<UserError>()
            .unwrap_or_else(|| panic!("classified as the caller's: {err:#}"));
        assert!(
            user.message.contains("not an executable file") && user.message.contains("mode-644"),
            "the message names the path and the requirement: {}",
            user.message
        );
        assert!(
            user.hint.as_deref().is_some_and(|h| h.contains("--cc")),
            "the hint names the option to fix: {:?}",
            user.hint
        );

        // A directory exists and is nothing `execve` can load; refused by the same rule.
        let err = resolve_driver(&dir.display().to_string())
            .expect_err("a directory cannot be a compiler");
        assert!(
            err.downcast_ref::<UserError>()
                .is_some_and(|u| u.message.contains("not an executable file")),
            "{err:#}"
        );

        if cfg!(target_os = "linux") {
            let no_loader = dir.join("no-shebang");
            std::fs::write(&no_loader, "hello\n").expect("write");
            std::fs::set_permissions(&no_loader, std::fs::Permissions::from_mode(0o755))
                .expect("chmod 755");
            let err = detect_waiting_out_etxtbsy(&no_loader, &dir);
            let (class, hint) = crate::error::classify(&err);
            assert_eq!(
                class,
                crate::error::ErrorClass::UserInput,
                "ENOEXEC is the caller's: {err:#}"
            );
            let rendered = format!("{err:#}");
            assert!(
                rendered.contains("os error 8") && rendered.matches("no-shebang").count() == 1,
                "the errno reaches the message and the driver is named once: {rendered}"
            );
            assert!(
                hint.as_deref().is_some_and(|h| h.contains("executable")),
                "the hint names the requirement: {hint:?}"
            );
        } else {
            crate::error::capability_gap(
                "ENOEXEC through detect",
                "this host runs a shebang-less file through sh instead of refusing it",
            );
        }

        crate::error::best_effort(std::fs::remove_dir_all(&dir));
    }

    /// A `--cc` script whose shebang names an interpreter that does not exist passes the
    /// metadata check, since the script is an executable regular file, and fails at the
    /// spawn with `ENOENT`. The class is the caller's, and the hint names the interpreter
    /// beside the path, because the path exists and a hint to check it sent the caller to
    /// the wrong thing. Both kernels refuse this at `execve`, so the arm runs on every
    /// host.
    #[test]
    fn a_driver_whose_interpreter_is_missing_is_the_callers_to_fix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("chard-nointerp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let script = dir.join("no-interp");
        std::fs::write(
            &script,
            format!("#!{}\n", dir.join("absent-interpreter").display()),
        )
        .expect("write");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 755");

        let err = detect_waiting_out_etxtbsy(&script, &dir);
        let (class, hint) = crate::error::classify(&err);
        assert_eq!(
            class,
            crate::error::ErrorClass::UserInput,
            "a missing interpreter is the caller's: {err:#}"
        );
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("os error 2") && rendered.contains("no-interp"),
            "the errno reaches the message and the script is named: {rendered}"
        );
        assert!(
            hint.as_deref().is_some_and(|h| h.contains("interpreter")),
            "the hint names the interpreter as a thing to check: {hint:?}"
        );
        crate::error::best_effort(std::fs::remove_dir_all(&dir));
    }

    /// A `--cc` path whose stat fails for a reason other than absence keeps its errno, so
    /// the envelope classes it as it classes the same path handed to `chard elf`.
    ///
    /// `Path::exists()` folded every errno into "no such compiler", with a hint to pass a
    /// path that exists: for a directory in the path the caller cannot search, that sent
    /// them to check a path that exists, and for a symbolic-link loop it named the wrong
    /// repair. The loop is host-independent; the `EACCES` arm is announced where the
    /// process can stat through the mode anyway.
    #[test]
    fn a_driver_path_that_cannot_be_read_is_classified_by_its_errno() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("chard-ccstat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        std::os::unix::fs::symlink(dir.join("loop-b"), dir.join("loop-a")).expect("link a");
        std::os::unix::fs::symlink(dir.join("loop-a"), dir.join("loop-b")).expect("link b");
        let err = resolve_driver(&dir.join("loop-a").display().to_string())
            .expect_err("a symbolic-link loop cannot be a compiler");
        let (class, hint) = crate::error::classify(&err);
        assert_eq!(class, crate::error::ErrorClass::UserInput, "{err:#}");
        assert!(
            hint.as_deref()
                .is_some_and(|h| h.contains("symbolic links")),
            "the hint names the loop: {hint:?}"
        );
        assert!(format!("{err:#}").contains("loop-a"), "{err:#}");

        let locked = dir.join("locked");
        std::fs::create_dir(&locked).expect("create the locked directory");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 000");
        let inner = locked.join("inner");
        let stops = std::fs::metadata(&inner)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
        if stops {
            let err = resolve_driver(&inner.display().to_string())
                .expect_err("a path under a directory the caller cannot search");
            assert_eq!(
                crate::error::classify(&err).0,
                crate::error::ErrorClass::Permission,
                "{err:#}"
            );
            assert!(format!("{err:#}").contains("os error 13"), "{err:#}");
        } else {
            crate::error::capability_gap(
                "PERMISSION from a --cc under a mode-000 directory",
                "this process stats through the mode anyway, so it stops nothing here",
            );
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 700");
        crate::error::best_effort(std::fs::remove_dir_all(&dir));
    }

    /// The bare-name search chooses the entry `execvp` would, so a `cc` on `PATH` that the
    /// caller could not run is passed over for the one their shell runs.
    ///
    /// Measured before the predicate changed, through the built binary on Darwin aarch64
    /// (Apple clang 21.0.0, rustc 1.98.1, debug profile): a mode-644 `cc` first on `PATH`
    /// was the resolved driver, refused as the caller's input with a hint to make `cc
    /// --version` run, while `command -v cc` in the same shell named the real compiler
    /// behind it. A directory named `cc` is passed over by the same rule, and a search
    /// whose every entry is unrunnable finds nothing, as the shell finds nothing.
    #[test]
    fn the_path_search_passes_over_an_entry_the_caller_could_not_run() {
        use std::os::unix::fs::PermissionsExt as _;
        let shims = Shims::new("pathorder");
        let as_dir = shims.subdir("dir");
        std::fs::create_dir_all(as_dir.join("cc")).expect("a directory named cc");
        let unrunnable = shims.subdir("m644");
        std::fs::write(unrunnable.join("cc"), "hello\n").expect("write");
        std::fs::set_permissions(
            unrunnable.join("cc"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod 644");
        let runnable = shims.subdir("bin");
        std::fs::write(runnable.join("cc"), "#!/bin/sh\nexit 0\n").expect("write");
        std::fs::set_permissions(runnable.join("cc"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod 755");

        let search = std::env::join_paths([&as_dir, &unrunnable, &runnable]).expect("a PATH");
        let found = find_on_path("cc", &search).expect("the runnable cc is on the path");
        assert_eq!(found, runnable.join("cc"));

        let search = std::env::join_paths([&as_dir, &unrunnable]).expect("a PATH");
        assert_eq!(
            find_on_path("cc", &search),
            None,
            "an entry the caller could not run is never the resolved driver"
        );
    }

    #[test]
    fn missing_compiler_is_a_user_error_with_a_hint() {
        let err = resolve_driver("definitely-not-a-real-compiler-xyzzy").unwrap_err();
        let user = err
            .downcast_ref::<UserError>()
            .expect("classified as user error");
        assert!(user.hint.is_some());
    }

    /// The arch gate's premise, held to the artifacts: each of the four agreements from the
    /// shape that produces it, and the triple spellings a driver prints mapped to the
    /// machine its artifacts carry.
    #[test]
    fn target_agreement_holds_the_gate_architecture_to_e_machine() {
        let artifact = |label: &str, machine: &str| ArtifactMachine {
            class: 64,
            order: Some(crate::elf::ByteOrder::LittleEndian),
            label: label.to_owned(),
            machine: machine.to_owned(),
            lang: Some(Lang::C),
        };
        let held = |arch: &str, artifacts: &[ArtifactMachine]| {
            target_agreement(arch, ArchSource::Dumpmachine, artifacts, &[], None)
        };

        let none = held("x86_64", &[]);
        assert_eq!(none.agreement, ArchAgreement::NoElfArtifact);
        assert_eq!(none.artifacts_read, 0);

        let agrees = held("x86", &[artifact("a sha256:aa", "i386")]);
        assert_eq!(
            agrees.agreement,
            ArchAgreement::Agrees,
            "{}",
            agrees.evidence
        );

        let lie = held("aarch64", &[artifact("a sha256:aa", "x86_64")]);
        assert_eq!(lie.agreement, ArchAgreement::Disagrees);
        assert!(
            lie.evidence.contains("x86_64 on 1 (first a sha256:aa)")
                && lie.evidence.contains("-dumpmachine"),
            "the evidence names the machine, the artifact and the source: {}",
            lie.evidence
        );

        let mixed = held(
            "x86_64",
            &[
                artifact("a sha256:aa", "x86_64"),
                artifact("b sha256:bb", "i386"),
            ],
        );
        assert_eq!(mixed.agreement, ArchAgreement::Disagrees);
        assert_eq!(mixed.machines.len(), 2);
        // Two machines, the first by name the gate's own family: still a disagreement.
        let family_first = held(
            "riscv64",
            &[
                artifact("a sha256:aa", "riscv"),
                artifact("b sha256:bb", "x86_64"),
            ],
        );
        assert_eq!(
            family_first.agreement,
            ArchAgreement::Disagrees,
            "{}",
            family_first.evidence
        );

        let unmapped = held(
            "sparc64",
            &[artifact("a sha256:aa", "unrecognised (e_machine 0x2b)")],
        );
        assert_eq!(
            unmapped.agreement,
            ArchAgreement::Unmapped,
            "{}",
            unmapped.evidence
        );

        let kernel = target_agreement("aarch64", ArchSource::Kernel, &[], &[], None);
        assert!(kernel.evidence.contains("kernel"), "{}", kernel.evidence);

        for (first_component, machine) in [
            ("armv7hl", "arm"),
            ("aarch64_be", "aarch64"),
            ("powerpc64le", "ppc64"),
            ("ppc", "ppc"),
            ("s390x", "s390"),
            ("riscv64", "riscv"),
            ("mips64el", "mips"),
            ("loongarch64", "loongarch"),
        ] {
            assert_eq!(
                machine_family(first_component),
                Some(machine),
                "{first_component}"
            );
        }
        assert_eq!(ArchAgreement::ALL.len(), 4);
    }

    /// The macro witness: each of the four agreements from the shape that produces it,
    /// the machines it names to the withholding, and the dump read down to the three
    /// macros it knows.
    #[test]
    fn the_macro_witness_holds_the_gate_architecture_to_the_dump() {
        let held = |arch: &str, defined: &[&str]| {
            let defined: Vec<String> = defined.iter().map(|d| (*d).to_owned()).collect();
            target_agreement(arch, ArchSource::Dumpmachine, &[], &defined, None)
        };

        let agrees = held("x86", &["__i386__"]);
        assert_eq!(agrees.macros.agreement, MacroAgreement::Agrees);
        assert_eq!(
            agrees.agreement,
            ArchAgreement::NoElfArtifact,
            "the ELF witness is apart"
        );

        let lie = held("aarch64", &["__x86_64__"]);
        assert_eq!(lie.macros.agreement, MacroAgreement::Disagrees);
        assert!(
            lie.macros
                .evidence
                .contains("__x86_64__ (e_machine x86_64)")
                && lie.macros.evidence.contains("-dumpmachine"),
            "the evidence names the macro, its machine and the source: {}",
            lie.macros.evidence
        );
        assert_eq!(
            lie.witnessed_machines(Lang::C).collect::<Vec<_>>(),
            ["x86_64"]
        );
        assert!(
            lie.witness_of("x86_64", Lang::C)
                .contains("defines __x86_64__")
        );

        let two = held("x86_64", &["__x86_64__", "__aarch64__"]);
        assert_eq!(two.macros.agreement, MacroAgreement::Disagrees);

        let unmapped = held("sparc64", &["__x86_64__"]);
        assert_eq!(unmapped.macros.agreement, MacroAgreement::Unmapped);

        let silent = held("riscv64", &[]);
        assert_eq!(silent.macros.agreement, MacroAgreement::NoArchMacro);
        assert_eq!(silent.witnessed_machines(Lang::C).count(), 0);

        // A dump with no architecture macro under an architecture of the three families
        // witnesses a target outside them: every gate is decided as off its list.
        for arch in ["x86_64", "x86", "aarch64"] {
            let absent = held(arch, &[]);
            assert_eq!(absent.macros.agreement, MacroAgreement::Disagrees, "{arch}");
            assert_eq!(
                absent.witnessed_machines(Lang::C).collect::<Vec<_>>(),
                [OUTSIDE_ARCH_MACROS],
                "{arch}"
            );
            assert!(
                absent.macros.evidence.contains("defines none of")
                    && absent.macros.evidence.contains("-dumpmachine"),
                "{}",
                absent.macros.evidence
            );
            assert!(
                absent
                    .witness_of(OUTSIDE_ARCH_MACROS, Lang::C)
                    .contains("defines none of __x86_64__"),
                "the reason names the absence rather than a machine"
            );
            assert_eq!(
                gate_arch_of_machine(OUTSIDE_ARCH_MACROS),
                OUTSIDE_ARCH_MACROS
            );
        }

        let artifact_first = target_agreement(
            "aarch64",
            ArchSource::Dumpmachine,
            &[ArtifactMachine {
                class: 64,
                order: Some(crate::elf::ByteOrder::LittleEndian),
                label: "a sha256:aa".to_owned(),
                machine: "x86_64".to_owned(),
                lang: Some(Lang::C),
            }],
            &["__x86_64__".to_owned()],
            None,
        );
        assert!(
            artifact_first
                .witness_of("x86_64", Lang::C)
                .starts_with("an artifact this run built"),
            "an artifact is named before the dump"
        );

        let dump: BTreeMap<String, String> =
            [("__aarch64__", "1"), ("__ARM_ARCH", "8"), ("__LP64__", "1")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
        assert_eq!(arch_macros(&dump), ["__aarch64__"]);
        assert_eq!(MacroAgreement::ALL.len(), 7);
    }

    /// The witness under the profile's flags: a target those flags select contradicts the
    /// flagless reading, on a run with no ELF artifact, and a dump the driver refused
    /// witnesses nothing rather than a target outside the three families.
    #[test]
    fn the_profile_dump_witnesses_a_target_the_profile_flags_select() {
        let dump = |exit_status: i32, macros_defined: usize, defined: &[&str]| ProfileDump {
            abi: None,
            flags: vec!["-m32".to_owned()],
            exit_status,
            stdout_unterminated: false,
            macros_defined,
            defined: defined.iter().map(|d| (*d).to_owned()).collect(),
        };
        let held = |profile: &ProfileDump| {
            target_agreement(
                "x86_64",
                ArchSource::Dumpmachine,
                &[],
                &["__x86_64__".to_owned()],
                Some(profile),
            )
        };

        let m32 = held(&dump(0, 350, &["__i386__"]));
        assert_eq!(m32.macros.agreement, MacroAgreement::Agrees, "flagless");
        let profile = m32.profile_macros.as_ref().expect("taken");
        assert_eq!(profile.witness.agreement, MacroAgreement::Disagrees);
        assert!(
            profile
                .witness
                .evidence
                .contains("__i386__ (e_machine i386)")
                && profile.witness.evidence.contains("`-m32`"),
            "the evidence names the macro and the flags: {}",
            profile.witness.evidence
        );
        assert_eq!(
            m32.witnessed_machines(Lang::C).collect::<Vec<_>>(),
            ["x86_64", "i386"]
        );
        assert!(
            m32.witness_of("i386", Lang::C)
                .contains("under the profile's C flags defines __i386__"),
            "{}",
            m32.witness_of("i386", Lang::C)
        );
        assert!(
            m32.witness_of("x86_64", Lang::C)
                .contains("intrinsic macro dump defines"),
            "a machine both dumps name is the flagless dump's"
        );
        assert_eq!(profile.dump(), dump(0, 350, &["__i386__"]), "round-trips");

        let native = held(&dump(0, 350, &["__x86_64__"]));
        assert_eq!(
            native.profile_macros.expect("taken").witness.agreement,
            MacroAgreement::Agrees
        );

        for refused in [
            dump(1, 0, &[]),
            dump(1, 350, &["__aarch64__"]),
            dump(0, 0, &[]),
            ProfileDump {
                stdout_unterminated: true,
                ..dump(0, 350, &["__i386__"])
            },
        ] {
            assert!(!refused.completed(), "{refused:?}");
            assert!(
                ProfileDump {
                    exit_status: 0,
                    stdout_unterminated: false,
                    macros_defined: 350,
                    ..refused.clone()
                }
                .completed(),
                "only the failure makes {refused:?} incomplete"
            );
            let t = held(&refused);
            let w = &t.profile_macros.as_ref().expect("taken").witness;
            assert_eq!(w.agreement, MacroAgreement::DumpFailed, "{refused:?}");
            assert_eq!(
                w.evidence.contains(compile::CUT_OFF),
                refused.stdout_unterminated,
                "{}",
                w.evidence
            );
            let published = t.profile_macros.as_ref().expect("taken");
            assert_eq!(
                published.dump().stdout_unterminated,
                refused.stdout_unterminated,
                "the cut is published, so the rule re-deriving the witness sees it"
            );
            assert!(w.defined.is_empty(), "{refused:?}");
            assert_eq!(
                t.witnessed_machines(Lang::C).collect::<Vec<_>>(),
                ["x86_64"],
                "a failed dump names no machine, {OUTSIDE_ARCH_MACROS} included"
            );
        }

        assert!(
            target_agreement("x86_64", ArchSource::Dumpmachine, &[], &[], None)
                .profile_macros
                .is_none()
        );
    }

    /// A query is read only where it exited 0 with its output whole: a non-zero status, a
    /// signal, a cut last line and no answer at all each leave `None` and one failure that
    /// says which, and the first is the only arm that hands the record on.
    #[test]
    fn a_query_is_read_only_where_it_exited_0_with_its_output_whole() {
        let record = |exit_status: i32, stdout_unterminated: bool| compile::BuildRecord {
            argv: Vec::new(),
            dropped_flags: Vec::new(),
            exit_status,
            stdout: "x86_64-linux-mu".to_owned(),
            stderr: String::new(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated,
        };
        let mut failures = Vec::new();
        let read = answered(
            Ok(record(0, false)),
            "-q",
            TRIPLE_FIELD,
            "unread",
            &mut failures,
        );
        assert!(read.is_some() && failures.is_empty(), "{failures:?}");
        let refused = [
            (Ok(record(1, false)), "exited 1"),
            (Ok(record(-1, false)), "was killed by a signal"),
            (
                Ok(record(0, true)),
                "exited 0 with its output cut off partway through a line",
            ),
            (
                compile::capture(Path::new("/nonexistent/chard-driver"), &[]),
                "did not answer (",
            ),
        ];
        let fed = refused.len();
        for (record, ended) in refused {
            let mut failures = Vec::new();
            assert!(answered(record, "-q", TRIPLE_FIELD, "unread", &mut failures).is_none());
            let [failure] = failures.as_slice() else {
                panic!("one failure per refused query: {failures:?}");
            };
            assert_eq!(failure.context, TRIPLE_FIELD);
            assert!(
                failure
                    .message
                    .starts_with(&format!("the driver's `-q` {ended}"))
                    && failure
                        .message
                        .ends_with(", so chard read nothing from its output: unread"),
                "{}",
                failure.message
            );
        }
        assert_eq!(fed, 4, "a status, a signal, a cut and no answer");
    }

    /// A failed dump's witness says how the dump ended in `BuildRecord::ended`'s words: the
    /// `-1` sentinel names a signal, never "exited -1", and a real `exit(-1)`, which reads
    /// 255 on Unix, keeps its number.
    #[test]
    fn a_failed_dump_s_witness_says_how_the_dump_ended() {
        for (exit_status, ended) in [
            (-1, "was killed by a signal"),
            (255, "exited 255"),
            (1, "exited 1"),
        ] {
            let failed = ProfileDump {
                abi: None,
                flags: vec!["-m32".to_owned()],
                exit_status,
                stdout_unterminated: false,
                macros_defined: 0,
                defined: Vec::new(),
            };
            let t = target_agreement(
                "x86_64",
                ArchSource::Dumpmachine,
                &[],
                &["__x86_64__".to_owned()],
                Some(&failed),
            );
            let w = &t.profile_macros.as_ref().expect("taken").witness;
            assert_eq!(w.agreement, MacroAgreement::DumpFailed);
            assert!(
                w.evidence.starts_with(&format!(
                    "the intrinsic macro dump under the profile's C flags (`-m32`) {ended} \
                     with 0 macro(s), so it witnesses no target"
                )),
                "{}",
                w.evidence
            );
        }
    }

    /// A selection of the target, and only that, moves the gate off the flagless reading:
    /// `-m32`, `-m64`, `--target=`, `-target` and `-arch` select one, a system root
    /// alone does not, and a two-token spelling with no value is no selection.
    #[test]
    fn only_a_target_flag_selects_a_target() {
        let v = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        for selecting in [
            "-m32",
            "-O2 -m64",
            "--target=aarch64-linux-gnu --sysroot=/r -fuse-ld=lld",
            "-target aarch64-linux-gnu",
            "-arch x86_64",
            "--sysroot /r -m32",
        ] {
            assert!(selects_target(&v(selecting)), "{selecting}");
        }
        for not in [
            "",
            "-O2 -fstack-protector-strong",
            "--sysroot=/r",
            "--sysroot /r",
            "-isysroot /sdk",
            "-isysroot/sdk",
            "-target",
            "-arch",
            "-march=armv8.5-a",
            "-DCHARD_SELECTS_X86_64",
            "--sysroot -m32",
            "-mmusl",
            "-mandroid -tno-android-ld",
            "--sysroot=/r --no-sysroot-suffix",
        ] {
            assert!(!selects_target(&v(not)), "{not}");
        }
        assert_eq!(
            target_selecting_flags(&v("-O2 --sysroot /r -m32 -target")),
            v("--sysroot /r -m32"),
            "the tokens, as written and in order, and no dangling two-token spelling"
        );
    }

    /// The gate reads the dump under the profile's flags where those select a target and it
    /// names one architecture, and the flagless `-dumpmachine` (or the kernel) everywhere
    /// else.
    #[test]
    fn the_gate_reads_the_target_the_profile_selects() {
        let dump =
            |flags: &str, exit_status: i32, macros_defined: usize, defined: &[&str]| ProfileDump {
                abi: None,
                flags: flags.split_whitespace().map(str::to_owned).collect(),
                exit_status,
                stdout_unterminated: false,
                macros_defined,
                defined: defined.iter().map(|d| (*d).to_owned()).collect(),
            };
        let triple = Some("x86_64-redhat-linux");
        let gate = |d: Option<&ProfileDump>| gate_target(triple, d, "x86_64");
        let flagless = ("x86_64".to_owned(), ArchSource::Dumpmachine);

        assert_eq!(gate(None), flagless, "no profile flags");
        assert_eq!(
            gate(Some(&dump(
                "--target=aarch64-linux-gnu",
                0,
                400,
                &["__aarch64__"]
            ))),
            ("aarch64".to_owned(), ArchSource::ProfileMacros)
        );
        assert_eq!(
            gate(Some(&dump(
                "-target aarch64-linux-gnu",
                0,
                400,
                &["__aarch64__"]
            ))),
            ("aarch64".to_owned(), ArchSource::ProfileMacros)
        );
        assert_eq!(
            gate(Some(&dump("-m32", 0, 350, &["__i386__"]))),
            ("x86".to_owned(), ArchSource::ProfileMacros),
            "the gate's vocabulary, not e_machine's"
        );
        assert_eq!(
            gate(Some(&dump("-m64", 0, 350, &["__x86_64__"]))),
            ("x86_64".to_owned(), ArchSource::ProfileMacros),
            "a selection of the default target is still read from its dump"
        );
        for unresolved in [
            // Flags that select no target: the dump witnesses, it does not gate.
            dump("-O2", 0, 350, &["__aarch64__"]),
            dump("-DCHARD_SELECTS_X86_64", 0, 350, &["__x86_64__"]),
            dump("--sysroot=/r", 0, 350, &["__aarch64__"]),
            // A dump the driver refused, or one that said nothing.
            dump("--target=aarch64-linux-gnu", 1, 0, &[]),
            dump("--target=aarch64-linux-gnu", 1, 400, &["__aarch64__"]),
            dump("--target=aarch64-linux-gnu", 0, 0, &[]),
            // A dump that exited 0 with its output cut off partway through a line.
            ProfileDump {
                stdout_unterminated: true,
                ..dump("--target=aarch64-linux-gnu", 0, 400, &["__aarch64__"])
            },
            // A target outside the three families, or a dump naming two.
            dump("--target=riscv64-linux-gnu", 0, 300, &[]),
            dump("-m32", 0, 350, &["__x86_64__", "__i386__"]),
        ] {
            assert_eq!(gate(Some(&unresolved)), flagless, "{unresolved:?}");
        }
        assert_eq!(
            gate_target(None, None, "aarch64"),
            ("aarch64".to_owned(), ArchSource::Kernel)
        );
        assert_eq!(
            gate_target(None, Some(&dump("-m32", 0, 350, &["__i386__"])), "x86_64"),
            ("x86".to_owned(), ArchSource::ProfileMacros),
            "the selection is read whatever -dumpmachine gave"
        );
        assert_eq!(ArchSource::ALL.len(), 3);
    }

    /// Gated on the target the profile selects, the flagless dump is superseded and names no
    /// machine, the dump under the profile's flags agrees, and the artifacts are held to the
    /// selected target: of it they agree, of the driver's default they disagree and that
    /// machine withholds.
    #[test]
    fn a_selected_target_is_held_to_its_artifacts() {
        let cross = ProfileDump {
            abi: None,
            flags: vec![
                "--target=aarch64-linux-gnu".to_owned(),
                "-fuse-ld=lld".to_owned(),
            ],
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 400,
            defined: vec!["__aarch64__".to_owned()],
        };
        let (arch, source) = gate_target(Some("x86_64-redhat-linux"), Some(&cross), "x86_64");
        let artifact = |machine: &str| ArtifactMachine {
            class: 64,
            order: Some(crate::elf::ByteOrder::LittleEndian),
            label: "p sha256:0".to_owned(),
            machine: machine.to_owned(),
            lang: Some(Lang::C),
        };
        let flagless = ["__x86_64__".to_owned()];
        let t = target_agreement(
            &arch,
            source,
            &[artifact("aarch64")],
            &flagless,
            Some(&cross),
        );
        assert_eq!(t.arch, "aarch64");
        assert_eq!(t.source, ArchSource::ProfileMacros);
        assert_eq!(t.agreement, ArchAgreement::Agrees, "{}", t.evidence);
        assert_eq!(t.macros.agreement, MacroAgreement::Superseded);
        assert_eq!(
            t.macros.defined, flagless,
            "the flagless dump is still published"
        );
        assert!(
            t.macros
                .evidence
                .contains("--target=aarch64-linux-gnu -fuse-ld=lld"),
            "{}",
            t.macros.evidence
        );
        assert_eq!(
            t.profile_macros.as_ref().expect("taken").witness.agreement,
            MacroAgreement::Agrees
        );
        assert_eq!(
            t.witnessed_machines(Lang::C).collect::<Vec<_>>(),
            ["aarch64", "aarch64"],
            "the superseded dump names no machine"
        );
        assert!(
            t.evidence
                .contains("under the profile's C flags, which select a target"),
            "{}",
            t.evidence
        );

        let wrong = target_agreement(
            &arch,
            source,
            &[artifact("x86_64")],
            &flagless,
            Some(&cross),
        );
        assert_eq!(wrong.agreement, ArchAgreement::Disagrees);
        assert!(
            wrong.witnessed_machines(Lang::C).any(|m| m == "x86_64"),
            "an artifact of the default target still speaks against the selected one"
        );
    }

    /// A silent dump is overruled only by artifacts of probes of its own language.
    ///
    /// The C++ dump witnesses a target only the C++ flags select, which a C artifact says
    /// nothing about: beside C artifacts alone, all of the read family, a C++ dump
    /// defining none of the three still disagrees and withholds the C++ probes' gates;
    /// beside a C++ artifact of the family it is overruled. The C dump likewise is not
    /// overruled by a C++ artifact alone. Measured shape (measured 2026-10-14, clang
    /// 22.1.8 on Fedora 44 x86_64, `--cxxflags "--target=riscv64-linux-gnu -O2"` under C
    /// flags selecting nothing): every C++ build fails, the C artifacts are x86_64, and
    /// the C++ dump is the one witness to the C++ probes' target.
    #[test]
    fn a_silent_dump_is_overruled_only_by_artifacts_of_its_own_language() {
        let artifact = |label: &str, lang: Lang| ArtifactMachine {
            class: 64,
            order: Some(crate::elf::ByteOrder::LittleEndian),
            label: label.to_owned(),
            machine: "x86_64".to_owned(),
            lang: Some(lang),
        };
        let silent = ProfileDump {
            abi: None,
            flags: vec!["--target=riscv64-linux-gnu".to_owned(), "-O2".to_owned()],
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 200,
            defined: Vec::new(),
        };
        let c_only = [artifact("c sha256:aa", Lang::C)];
        let t = target_agreement(
            "x86_64",
            ArchSource::Dumpmachine,
            &c_only,
            &["__x86_64__".to_owned()],
            None,
        )
        .with_cxx_dump(Some(&silent), &c_only);
        assert_eq!(t.agreement, ArchAgreement::Agrees);
        let cxx = &t.profile_macros_cxx.as_ref().expect("taken").witness;
        assert_eq!(
            cxx.agreement,
            MacroAgreement::Disagrees,
            "a C artifact corroborates no C++ dump: {}",
            cxx.evidence
        );
        assert_eq!(
            t.witnessed_machines(Lang::Cxx).collect::<Vec<_>>(),
            ["x86_64", "x86_64", OUTSIDE_ARCH_MACROS],
            "the C++ probes' gates are held to the silent dump"
        );

        let both = [
            artifact("c sha256:aa", Lang::C),
            artifact("cxx sha256:bb", Lang::Cxx),
        ];
        let t = target_agreement(
            "x86_64",
            ArchSource::Dumpmachine,
            &both,
            &["__x86_64__".to_owned()],
            None,
        )
        .with_cxx_dump(Some(&silent), &both);
        let cxx = &t.profile_macros_cxx.as_ref().expect("taken").witness;
        assert_eq!(cxx.agreement, MacroAgreement::Overruled, "{}", cxx.evidence);
        assert!(
            cxx.evidence
                .contains("all 1 ELF artifact(s) this run built from C++ probes"),
            "the evidence counts the C++ artifacts alone: {}",
            cxx.evidence
        );
        assert_eq!(t.witnessed_machines(Lang::Cxx).count(), 2);

        // The C dumps, by the same rule, are not overruled by a C++ artifact alone.
        let cxx_only = [artifact("cxx sha256:bb", Lang::Cxx)];
        let t = target_agreement("x86_64", ArchSource::Kernel, &cxx_only, &[], Some(&silent));
        assert_eq!(t.agreement, ArchAgreement::Agrees);
        assert_eq!(
            t.macros.agreement,
            MacroAgreement::Disagrees,
            "{}",
            t.macros.evidence
        );
        assert_eq!(
            t.profile_macros.as_ref().map(|p| p.witness.agreement),
            Some(MacroAgreement::Disagrees)
        );
        // An artifact of a probe the corpus does not name corroborates nothing.
        let unknown = [ArtifactMachine {
            class: 64,
            order: Some(crate::elf::ByteOrder::LittleEndian),
            label: "? sha256:cc".to_owned(),
            machine: "x86_64".to_owned(),
            lang: None,
        }];
        let t = target_agreement("x86_64", ArchSource::Kernel, &unknown, &[], None);
        assert_eq!(t.agreement, ArchAgreement::Agrees);
        assert_eq!(t.macros.agreement, MacroAgreement::Disagrees);
    }

    /// The overruled evidence blames a flag only where the dump was taken under flags.
    ///
    /// The flagless dump is taken with no profile flag, so `-undef` cannot be what
    /// silenced it; its evidence names the artifacts and says the cause is not
    /// established, and the dump under the profile's flags names the flag.
    #[test]
    fn the_overruled_evidence_blames_a_flag_only_under_flags() {
        let artifacts = [ArtifactMachine {
            class: 64,
            order: Some(crate::elf::ByteOrder::LittleEndian),
            label: "p sha256:aa".to_owned(),
            machine: "x86_64".to_owned(),
            lang: Some(Lang::C),
        }];
        let silent = ProfileDump {
            abi: None,
            flags: vec!["-undef".to_owned()],
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 15,
            defined: Vec::new(),
        };
        let t = target_agreement("x86_64", ArchSource::Kernel, &artifacts, &[], Some(&silent));
        assert_eq!(t.macros.agreement, MacroAgreement::Overruled);
        assert!(
            !t.macros.evidence.contains("-undef")
                && !t.macros.evidence.contains("profile's flags")
                && t.macros.evidence.contains("taken with no profile flag")
                && t.macros.evidence.contains("does not establish")
                && t.macros.evidence.contains("from C probes"),
            "{}",
            t.macros.evidence
        );
        let under = &t.profile_macros.as_ref().expect("taken").witness;
        assert_eq!(under.agreement, MacroAgreement::Overruled);
        assert!(
            under.evidence.contains("`-undef`")
                && under
                    .evidence
                    .contains("the flags this dump was taken under")
                && !under.evidence.contains("does not establish"),
            "{}",
            under.evidence
        );

        // Under flags that name no such flag (a driver adding `-undef` itself, under
        // `bare-optimized`), the dump is overruled all the same and the evidence names no
        // cause; `-U` of the read family's macro, as one word or two, is named like `-undef`,
        // and `-U` of another family's macro, which silences nothing on this target, is not
        // (an x86_64 read under `-U__i386__ -U__x86_64__` names the second).
        let under = |flags: &[&str]| {
            let dump = ProfileDump {
                abi: None,
                flags: flags.iter().map(|f| (*f).to_owned()).collect(),
                exit_status: 0,
                stdout_unterminated: false,
                macros_defined: 15,
                defined: Vec::new(),
            };
            let t = target_agreement("x86_64", ArchSource::Kernel, &artifacts, &[], Some(&dump));
            let w = t.profile_macros.expect("taken").witness;
            assert_eq!(w.agreement, MacroAgreement::Overruled, "{flags:?}");
            w.evidence
        };
        let o2 = under(&["-O2"]);
        assert!(
            o2.contains("no flag this dump was taken under is one chard knows")
                && o2.contains("does not establish")
                && !o2.contains("among them suppresses"),
            "{o2}"
        );
        assert!(under(&["-U__x86_64__", "-O2"]).contains("`-U__x86_64__` among them suppresses"));
        assert!(under(&["-O2", "-U", "__x86_64__"]).contains("`-U __x86_64__` among them"));
        let other = under(&["-O2", "-U", "__i386__"]);
        assert!(
            other.contains("does not establish") && !other.contains("among them"),
            "{other}"
        );
        let other = under(&["-U__aarch64__", "-O2"]);
        assert!(
            other.contains("does not establish") && !other.contains("among them"),
            "{other}"
        );
        assert!(
            under(&["-U__i386__", "-U__x86_64__", "-O2"])
                .contains("`-U__x86_64__` among them suppresses")
        );
        assert!(
            under(&["-UFOO", "-U"]).contains("does not establish"),
            "a -U of a macro outside the table, or a trailing -U, names nothing"
        );
        let flags = |f: &[&str]| f.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        assert_eq!(silencing_flag(&[], "x86_64"), None);
        assert_eq!(silencing_flag(&flags(&["-U__i386__"]), "x86_64"), None);
        assert_eq!(
            silencing_flag(&flags(&["-U__i386__"]), "i386").as_deref(),
            Some("-U__i386__")
        );
        assert_eq!(
            silencing_flag(&flags(&["-U", "__aarch64__"]), "aarch64").as_deref(),
            Some("-U __aarch64__")
        );
        assert_eq!(
            silencing_flag(&flags(&["-undef"]), "riscv").as_deref(),
            Some("-undef"),
            "a family with no macro in the table still has -undef named"
        );
    }

    /// The silencing flag is read in gcc's long spellings, walked by the classifier: a
    /// value that only looks like the flag (an output file named `-undef`) is passed over,
    /// and the flag after it is found.
    #[test]
    fn the_silencing_flag_is_read_in_gccs_spellings_and_not_in_a_value() {
        let flags = |f: &[&str]| f.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        // gcc's long spellings, and a value that only looks like a flag.
        assert_eq!(
            silencing_flag(&flags(&["--un", "__aarch64__"]), "aarch64").as_deref(),
            Some("--un __aarch64__")
        );
        assert_eq!(
            silencing_flag(&flags(&["--undefine-macro=__i386__"]), "i386").as_deref(),
            Some("--undefine-macro=__i386__")
        );
        assert_eq!(silencing_flag(&flags(&["-o", "-undef"]), "x86_64"), None);
        assert_eq!(
            silencing_flag(&flags(&["-o", "-U__aarch64__", "-undef"]), "aarch64").as_deref(),
            Some("-undef"),
            "the output file named like a flag is passed over, and the flag after it found"
        );
        assert_eq!(
            silencing_flag(&flags(&["-Xarch_x86_64", "-undef"]), "x86_64").as_deref(),
            Some("-undef"),
            "the word clang applies for one architecture is the driver's own"
        );
    }

    /// Under another read family, the cause named is that family's macro, not the host's:
    /// the family `overruled` is given is the one the artifacts corroborate.
    #[test]
    fn the_cause_named_is_the_read_familys_macro() {
        let aarch64 = [ArtifactMachine {
            class: 64,
            order: Some(crate::elf::ByteOrder::LittleEndian),
            label: "p sha256:aa".to_owned(),
            machine: "aarch64".to_owned(),
            lang: Some(Lang::C),
        }];
        let under_aarch64 = |flags: &[&str]| {
            let dump = ProfileDump {
                abi: None,
                flags: flags.iter().map(|f| (*f).to_owned()).collect(),
                exit_status: 0,
                stdout_unterminated: false,
                macros_defined: 15,
                defined: Vec::new(),
            };
            let t = target_agreement("aarch64", ArchSource::Kernel, &aarch64, &[], Some(&dump));
            let w = t.profile_macros.expect("taken").witness;
            assert_eq!(w.agreement, MacroAgreement::Overruled, "{flags:?}");
            w.evidence
        };
        assert!(
            under_aarch64(&["-O2", "-U__aarch64__"])
                .contains("`-U__aarch64__` among them suppresses")
        );
        let other = under_aarch64(&["-U__x86_64__", "-O2"]);
        assert!(
            other.contains("does not establish") && !other.contains("among them"),
            "{other}"
        );
    }

    /// The width and order each row stands for, and what a dump names.
    #[test]
    fn an_abi_is_read_from_the_rows_and_from_a_dump() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        for arch in crate::mechanism::ARCHS {
            let abi = Abi::of_arch(arch).unwrap_or_else(|| panic!("{arch} has rows"));
            assert_eq!(abi.order, LittleEndian, "{arch}");
            assert_eq!(abi.class, if *arch == "x86" { 32 } else { 64 }, "{arch}");
        }
        for outside in ["riscv64", "armv7", "ppc64le", OUTSIDE_ARCH_MACROS, ""] {
            assert_eq!(Abi::of_arch(outside), None, "{outside}");
        }
        let dump = |pointer: Option<&str>, order: Option<&str>| {
            let mut m = BTreeMap::new();
            if let Some(p) = pointer {
                m.insert("__SIZEOF_POINTER__".to_owned(), p.to_owned());
            }
            if let Some(o) = order {
                m.insert("__BYTE_ORDER__".to_owned(), o.to_owned());
            }
            Abi::from_dump(&m)
        };
        let le = Some("__ORDER_LITTLE_ENDIAN__");
        let be = Some("__ORDER_BIG_ENDIAN__");
        assert_eq!(
            dump(Some("8"), le),
            Some(Abi {
                class: 64,
                order: LittleEndian
            })
        );
        assert_eq!(
            dump(Some("4"), le),
            Some(Abi {
                class: 32,
                order: LittleEndian
            })
        );
        assert_eq!(
            dump(Some("8"), be),
            Some(Abi {
                class: 64,
                order: BigEndian
            })
        );
        assert_eq!(dump(None, le), None, "no width");
        assert_eq!(dump(Some("8"), None), None, "no order");
        assert_eq!(dump(Some("2"), le), None, "a width no ELF class carries");
        assert_eq!(dump(Some("8"), Some("__ORDER_PDP_ENDIAN__")), None);
        assert_eq!(
            Abi {
                class: 32,
                order: BigEndian
            }
            .to_string(),
            "ELF32 big-endian"
        );
        assert_eq!(
            serde_json::to_value(Abi {
                class: 64,
                order: LittleEndian
            })
            .expect("serializes"),
            serde_json::json!("ELF64 little-endian")
        );
    }

    /// The abi witness over artifacts: the read family's artifacts at the rows' width and
    /// order agree; one at the other width (x32 under x86_64, ILP32 under aarch64) or the
    /// other order (`aarch64_be` under aarch64) disagrees and is named; an artifact of another
    /// family is not read here, since the machine comparison holds it; a record with no
    /// order is left out; an architecture outside the table expects nothing.
    #[test]
    fn the_abi_witness_holds_the_read_familys_artifacts_to_the_rows() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        let artifact =
            |machine: &str, class: u8, order: Option<crate::elf::ByteOrder>| ArtifactMachine {
                label: format!("p sha256:{machine}{class}"),
                machine: machine.to_owned(),
                class,
                order,
                lang: Some(Lang::C),
            };
        let read = |arch: &str, artifacts: &[ArtifactMachine]| {
            target_agreement(arch, ArchSource::Dumpmachine, artifacts, &[], None).abi
        };

        let agreeing = read("x86_64", &[artifact("x86_64", 64, Some(LittleEndian))]);
        assert_eq!(agreeing.agreement, AbiAgreement::Agrees, "{agreeing:?}");
        assert_eq!(
            agreeing.expected.map(|a| a.to_string()).as_deref(),
            Some("ELF64 little-endian")
        );
        assert_eq!(agreeing.artifacts.get("ELF64 little-endian"), Some(&1));
        assert!(
            agreeing.evidence.contains("stand for ELF64 little-endian"),
            "{}",
            agreeing.evidence
        );

        let x32 = read("x86_64", &[artifact("x86_64", 32, Some(LittleEndian))]);
        assert_eq!(x32.agreement, AbiAgreement::Disagrees, "{x32:?}");
        assert!(
            x32.evidence.contains("1 ELF artifact(s) this run built carry ELF32 little-endian (first p sha256:x86_6432)")
                && x32.evidence.contains("table has no row for"),
            "{}",
            x32.evidence
        );

        let ilp32 = read("aarch64", &[artifact("aarch64", 32, Some(LittleEndian))]);
        assert_eq!(ilp32.agreement, AbiAgreement::Disagrees, "{ilp32:?}");
        let be = read("aarch64", &[artifact("aarch64", 64, Some(BigEndian))]);
        assert_eq!(be.agreement, AbiAgreement::Disagrees, "{be:?}");
        assert!(be.evidence.contains("ELF64 big-endian"), "{}", be.evidence);

        // Two artifacts, one at each width: the one at the other width is named alone.
        let mixed = read(
            "x86_64",
            &[
                artifact("x86_64", 64, Some(LittleEndian)),
                artifact("x86_64", 32, Some(LittleEndian)),
            ],
        );
        assert_eq!(mixed.agreement, AbiAgreement::Disagrees);
        assert_eq!(mixed.artifacts.len(), 2);

        // i386 under an x86 read is the rows' width; a foreign family is not read here.
        let i386 = read("x86", &[artifact("i386", 32, Some(LittleEndian))]);
        assert_eq!(i386.agreement, AbiAgreement::Agrees, "{i386:?}");
        let foreign = read("x86_64", &[artifact("riscv", 64, Some(LittleEndian))]);
        assert_eq!(foreign.agreement, AbiAgreement::NoWitness, "{foreign:?}");
        assert!(foreign.artifacts.is_empty());

        // A record from before the field carries no order and is left out of the counts,
        // and the no-witness evidence counts it so the leaving-out is not silent.
        let unrecorded = read("x86_64", &[artifact("x86_64", 32, None)]);
        assert_eq!(
            unrecorded.agreement,
            AbiAgreement::NoWitness,
            "{unrecorded:?}"
        );
        assert!(unrecorded.artifacts.is_empty());
        assert!(
            unrecorded
                .evidence
                .contains("the 1 ELF artifact(s) of its family read carry no recorded byte order"),
            "{}",
            unrecorded.evidence
        );
        let two = read(
            "x86_64",
            &[artifact("x86_64", 64, None), artifact("x86_64", 32, None)],
        );
        assert!(
            two.evidence.contains("the 2 ELF artifact(s)"),
            "{}",
            two.evidence
        );

        // Outside the table nothing is expected, whatever the artifacts carry.
        let outside = read("riscv64", &[artifact("riscv", 32, Some(BigEndian))]);
        assert_eq!(outside.agreement, AbiAgreement::Unmapped, "{outside:?}");
        assert_eq!(outside.expected, None);
        assert!(outside.evidence.contains("no row in the mechanism table"));
    }

    /// The abi witness over dumps: the flagless dump's width and order are read through
    /// `with_intrinsic_abi`, the profile dump's and the C++ dump's through their own
    /// `ProfileDump`, each only where the dump agreed about the family; a dump of another
    /// order under a read that agrees about the family disagrees and is named; a failed,
    /// superseded, overruled or disagreeing dump is not read.
    #[test]
    fn the_abi_witness_reads_each_dump_that_agreed_about_the_family() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        let abi = |class: u8, order| Abi { class, order };
        let dump = |flags: &[&str], defined: &[&str], abi: Option<Abi>| ProfileDump {
            flags: flags.iter().map(|f| (*f).to_owned()).collect(),
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 300,
            defined: defined.iter().map(|d| (*d).to_owned()).collect(),
            abi,
        };
        let aarch64 = ["__aarch64__".to_owned()];

        // No artifact, both dumps agreeing about the family at the rows' width and order.
        let t = target_agreement(
            "aarch64",
            ArchSource::Dumpmachine,
            &[],
            &aarch64,
            Some(&dump(
                &["-O2"],
                &["__aarch64__"],
                Some(abi(64, LittleEndian)),
            )),
        )
        .with_intrinsic_abi(Some(abi(64, LittleEndian)));
        assert_eq!(t.abi.agreement, AbiAgreement::Agrees, "{:?}", t.abi);
        assert_eq!(t.abi.dumps.len(), 2, "{:?}", t.abi.dumps);
        assert_eq!(t.macros.abi, Some(abi(64, LittleEndian)));
        assert_eq!(
            t.profile_macros.as_ref().and_then(|p| p.witness.abi),
            Some(abi(64, LittleEndian))
        );

        // The profile's flags select big-endian (`-mbig-endian` on an aarch64 driver): the
        // dump under them names the other order, and that alone disagrees.
        let t = target_agreement(
            "aarch64",
            ArchSource::Dumpmachine,
            &[],
            &aarch64,
            Some(&dump(
                &["-mbig-endian"],
                &["__aarch64__"],
                Some(abi(64, BigEndian)),
            )),
        )
        .with_intrinsic_abi(Some(abi(64, LittleEndian)));
        assert_eq!(t.abi.agreement, AbiAgreement::Disagrees, "{:?}", t.abi);
        assert!(
            t.abi.evidence.contains(
                "the driver's intrinsic macro dump under the profile's C flags defines \
                 __SIZEOF_POINTER__ 8 and __BYTE_ORDER__ big-endian, naming ELF64 big-endian"
            ),
            "{}",
            t.abi.evidence
        );
        // And `-mabi=ilp32`: the other width.
        let t = target_agreement(
            "aarch64",
            ArchSource::Dumpmachine,
            &[],
            &aarch64,
            Some(&dump(
                &["-mabi=ilp32"],
                &["__aarch64__"],
                Some(abi(32, LittleEndian)),
            )),
        )
        .with_intrinsic_abi(Some(abi(64, LittleEndian)));
        assert_eq!(t.abi.agreement, AbiAgreement::Disagrees, "{:?}", t.abi);
        assert!(
            t.abi.evidence.contains("naming ELF32 little-endian"),
            "{}",
            t.abi.evidence
        );

        // The C++ dump is read the same way, through `with_cxx_dump`.
        let t = target_agreement("aarch64", ArchSource::Dumpmachine, &[], &aarch64, None)
            .with_intrinsic_abi(Some(abi(64, LittleEndian)))
            .with_cxx_dump(
                Some(&dump(
                    &["-mbig-endian"],
                    &["__aarch64__"],
                    Some(abi(64, BigEndian)),
                )),
                &[],
            );
        assert_eq!(t.abi.agreement, AbiAgreement::Disagrees, "{:?}", t.abi);
        assert!(
            t.abi.dumps.contains_key(PROFILE_CXX_DUMP),
            "{:?}",
            t.abi.dumps
        );
    }

    /// A dump that disagrees about the family, a failed one, and a flagless one the
    /// profile's superseded name nothing to the abi witness: the first is the machine
    /// comparison's, the others witness no target.
    #[test]
    fn the_abi_witness_leaves_a_disagreeing_failed_or_superseded_dump_unread() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        let abi = |class: u8, order| Abi { class, order };
        let dump = |flags: &[&str], defined: &[&str], abi: Option<Abi>| ProfileDump {
            flags: flags.iter().map(|f| (*f).to_owned()).collect(),
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 300,
            defined: defined.iter().map(|d| (*d).to_owned()).collect(),
            abi,
        };
        let aarch64 = ["__aarch64__".to_owned()];
        // `--target=powerpc64-linux-gnu` names big-endian and none of the three.
        let t = target_agreement(
            "x86_64",
            ArchSource::Dumpmachine,
            &[],
            &["__x86_64__".to_owned()],
            Some(&dump(
                &["--target=powerpc64-linux-gnu"],
                &[],
                Some(abi(64, BigEndian)),
            )),
        )
        .with_intrinsic_abi(Some(abi(64, LittleEndian)));
        assert_eq!(
            t.profile_macros.as_ref().map(|p| p.witness.agreement),
            Some(MacroAgreement::Disagrees)
        );
        assert_eq!(t.abi.agreement, AbiAgreement::Agrees, "{:?}", t.abi);
        assert_eq!(
            t.abi.dumps.len(),
            1,
            "the flagless dump alone: {:?}",
            t.abi.dumps
        );

        // A failed dump, and a flagless dump the profile's superseded, name nothing here.
        let mut failed = dump(&["-mbig-endian"], &[], Some(abi(64, BigEndian)));
        failed.exit_status = 1;
        let t = target_agreement(
            "aarch64",
            ArchSource::Dumpmachine,
            &[],
            &aarch64,
            Some(&failed),
        )
        .with_intrinsic_abi(Some(abi(64, LittleEndian)));
        assert_eq!(t.abi.agreement, AbiAgreement::Agrees, "{:?}", t.abi);
        let t = target_agreement(
            "x86",
            ArchSource::ProfileMacros,
            &[],
            &["__x86_64__".to_owned()],
            Some(&dump(&["-m32"], &["__i386__"], Some(abi(32, LittleEndian)))),
        )
        .with_intrinsic_abi(Some(abi(64, LittleEndian)));
        assert_eq!(t.macros.agreement, MacroAgreement::Superseded);
        assert_eq!(t.abi.agreement, AbiAgreement::Agrees, "{:?}", t.abi);
        assert_eq!(t.abi.dumps.len(), 1, "{:?}", t.abi.dumps);
        assert_eq!(
            t.abi.expected.map(|a| a.to_string()).as_deref(),
            Some("ELF32 little-endian")
        );
    }

    /// The C++ driver's dump under the C++ flags witnesses the C++ probes' target alone:
    /// `-m32` in cxxflags beside C flags that select nothing contradicts the gate for a
    /// C++ probe and leaves a C probe held to the C dump.
    #[test]
    fn the_cxx_dump_witnesses_the_cxx_probes_alone() {
        let dump = |flags: &str, defined: &[&str]| ProfileDump {
            abi: None,
            flags: vec![flags.to_owned()],
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 350,
            defined: defined.iter().map(|d| (*d).to_owned()).collect(),
        };
        let c = dump("-O2", &["__x86_64__"]);
        let cxx = dump("-m32", &["__i386__"]);
        let t = target_agreement(
            "x86_64",
            ArchSource::Dumpmachine,
            &[],
            &["__x86_64__".to_owned()],
            Some(&c),
        )
        .with_cxx_dump(Some(&cxx), &[]);
        let witness = &t.profile_macros_cxx.as_ref().expect("taken").witness;
        assert_eq!(witness.agreement, MacroAgreement::Disagrees);
        assert!(
            witness.evidence.contains("under the profile's C++ flags")
                && witness.evidence.contains("`-m32`"),
            "{}",
            witness.evidence
        );
        assert_eq!(
            t.witnessed_machines(Lang::C).collect::<Vec<_>>(),
            ["x86_64", "x86_64"],
            "a C probe is held to the C dump"
        );
        assert_eq!(
            t.witnessed_machines(Lang::Cxx).collect::<Vec<_>>(),
            ["x86_64", "i386"],
            "a C++ probe is held to the C++ dump in place of the C one"
        );
        assert!(
            t.witness_of("i386", Lang::Cxx)
                .contains("under the profile's C++ flags defines __i386__"),
            "{}",
            t.witness_of("i386", Lang::Cxx)
        );
        assert_eq!(
            t.profile_macros_cxx.as_ref().map(ProfileMacroWitness::dump),
            Some(cxx),
            "round-trips"
        );

        // With no C++ dump, the C++ flags are the C ones, and the C dump witnesses both.
        let one = target_agreement(
            "x86_64",
            ArchSource::Dumpmachine,
            &[],
            &["__x86_64__".to_owned()],
            Some(&dump("-m32", &["__i386__"])),
        )
        .with_cxx_dump(None, &[]);
        assert!(one.profile_macros_cxx.is_none());
        for lang in [Lang::C, Lang::Cxx] {
            assert_eq!(
                one.witnessed_machines(lang).collect::<Vec<_>>(),
                ["x86_64", "i386"],
                "{lang:?}"
            );
        }
    }
}
