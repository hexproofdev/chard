// SPDX-License-Identifier: BSD-3-Clause

//! The measurement loop: build a probe, validate the detector, decide a verdict.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};

use crate::compile;
use crate::elf;
use crate::env::Environment;
use crate::error::UserError;
use crate::listings::{self, ProbeListings};
use crate::probe::{self, Channel, Check, Detection, Evidence, Lang, Probe};
use crate::report::{
    self, Applicability, Diagnostic, EvidenceOut, Observation, Profile, Severity, Variant, Verdict,
};
use crate::run as runner;
use crate::toolchain::{self, Detected};

/// What a probe's measurement produced: its observations, and anything about the run
/// that is not attributable to a single check.
#[derive(Debug)]
pub struct ProbeOutcome {
    pub observations: Vec<Observation>,
    /// The driver's answers the probe's listing rules read ([`listings::Listings`]), where
    /// the probe owed one ([`listings::Owed`]): the record a replay re-derives the rules from.
    pub listings: Option<listings::Listings>,
    /// The artifacts and dumps the observations and their arms reference, for the
    /// report's `facts`. See [`report::FactStore`].
    pub facts: report::FactStore,
    pub diagnostics: Vec<Diagnostic>,
}

/// A probe's share of the report's [`report::FactStore`] while it is measured, and every
/// entry the store refused.
#[derive(Debug, Default)]
pub struct Facts {
    pub store: report::FactStore,
    pub refused: Vec<Box<report::Conflict>>,
}

impl Facts {
    /// Record an entry [`artifact_fact`] or [`dump_fact`] made, keeping a refusal.
    fn record(&mut self, entry: Option<(String, report::FactEntry)>) {
        if let Some((key, entry)) = entry
            && let Err(conflict) = self.store.insert(key, entry)
        {
            self.refused.push(conflict);
        }
    }
}

/// Everything a check needs to know that is not the probe or the evidence.
#[derive(Debug)]
pub struct Conditions<'a> {
    pub env: &'a Environment,
    pub profile: &'a Profile,
    pub toolchain_kind: toolchain::Kind,
    /// The architecture the toolchain compiles for under this profile
    /// (`toolchain::gate_target`), which arch-gated checks (CET, GCS, branch-protection)
    /// gate on. Not `env.kernel.arch` read directly: that is the architecture chard's own
    /// binary was compiled for, the wrong question under cross-compilation.
    pub target_arch: &'a str,
    /// With no profile flags the measured build *is* the clean build, so it is not
    /// compiled twice, and the regime-matched negative arm would duplicate the
    /// profile-free one.
    pub profile_is_clean: bool,
}

impl Conditions<'_> {
    /// Whether the profile adds anything to a bare build.
    pub fn profile_is_clean(profile: &Profile) -> bool {
        profile.cflags.is_empty() && profile.cxxflags.is_empty() && profile.ldflags.is_empty()
    }
}

/// Flags for the measured variant: the profile, plus anything appended after it
/// so that it wins.
pub fn variant_flags(profile: &Profile, lang: Lang, extra: &[&str]) -> Vec<String> {
    let mut flags = profile_flags_for((&profile.cflags, &profile.cxxflags, &profile.ldflags), lang);
    flags.extend(extra.iter().map(|s| (*s).to_owned()));
    flags
}

/// The profile's flags a `lang` build carries, from its three lists (`cflags`, `cxxflags`,
/// `ldflags`): [`variant_flags`] with nothing after them, and what `chard detect` reads a
/// published profile through.
#[must_use]
pub fn profile_flags_for(
    (cflags, cxxflags, ldflags): (&[String], &[String], &[String]),
    lang: Lang,
) -> Vec<String> {
    let base = match lang {
        Lang::Cxx if !cxxflags.is_empty() => cxxflags,
        _ => cflags,
    };
    let mut flags = base.to_vec();
    flags.extend(ldflags.iter().cloned());
    flags
}

/// The flags `check`'s regime arm is built with in a `lang` probe under a profile of these
/// three lists (`cflags`, `cxxflags`, `ldflags`): the profile's flags for that language
/// ([`profile_flags_for`]) followed by the arm the check declares ([`Check::regime_arm`]).
/// `None` where the check declares no arm.
#[must_use]
pub fn regime_arm_flags(
    lists: (&[String], &[String], &[String]),
    lang: Lang,
    check: &Check,
) -> Option<Vec<String>> {
    let declared = check.regime_arm()?;
    let mut flags = profile_flags_for(lists, lang);
    flags.extend(declared.iter().map(|s| (*s).to_owned()));
    Some(flags)
}

/// Flags for a control arm: the control's own flags and nothing else.
pub fn control_flags(extra: &[&str]) -> Vec<String> {
    extra.iter().map(|s| (*s).to_owned()).collect()
}

/// Flags for one control arm of `check`: the control's own, and, when the check reads a
/// link or what it produced, the linker selection the profile's link line makes.
pub fn arm_flags(check: &Check, profile: &Profile, lang: Lang, extra: &[&str]) -> Vec<String> {
    let line = variant_flags(profile, lang, &[]);
    let mut flags = toolchain::target_selecting_flags(&line);
    flags.extend(toolchain::runtime_selecting_flags(&line));
    if !check.measures_toolchain_default {
        flags.extend(toolchain::header_selecting_flags(&line));
    }
    if check.channel() != Channel::Macro {
        flags.extend(toolchain::linker_program_flags(&line));
    }
    flags.extend(control_flags(extra));
    flags
}

/// Flags for the clean build: the target and system root the profile selects, with the
/// library search directories (`-L`) beside it ([`crate::toolchain::target_selecting_flags`]),
/// then the runtime it selects ([`crate::toolchain::runtime_selecting_flags`]), and nothing
/// else.
pub fn clean_flags(profile: &Profile, lang: Lang) -> Vec<String> {
    let line = variant_flags(profile, lang, &[]);
    let mut flags = toolchain::target_selecting_flags(&line);
    flags.extend(toolchain::runtime_selecting_flags(&line));
    flags
}

/// Whether the file at `path` opens with the LLVM bitcode magic
/// ([`compile::BITCODE_MAGIC`]). A file that cannot be opened, or is shorter, is not.
fn is_bitcode(path: &Path) -> bool {
    use std::io::Read as _;
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok_and(|()| magic == compile::BITCODE_MAGIC)
}

/// Why a probe's own libraries stop its build before the probe's link.
enum AuxStop {
    /// A library failed to build: the record the probe publishes as its own build.
    Failed(compile::BuildRecord),
    /// A library was built and is not this run's.
    Unwitnessed(compile::WitnessAbsence),
}

/// Builds and runs probe variants with one toolchain, in one work directory.
#[derive(Debug)]
pub struct Driver<'a> {
    /// The detected half of the toolchain, which is all measurement reads. The join key
    /// lives on the published `toolchain::Toolchain`, so the loop cannot depend on it.
    pub toolchain: &'a Detected,
    pub workdir: &'a Path,
    pub timeout: Duration,
    /// The flag for the structured-diagnostics side build, when
    /// `--structured-diagnostics` is on and this toolchain has a structured form. `None`
    /// builds nothing extra. See [`crate::structured`].
    pub structured: Option<&'static str>,
    /// The run's witness: every build is handed it, and every artifact the ELF reader reads
    /// is held to it before anything else is read from it or it is run
    /// ([`compile::RunWitness`]). `None` on a macOS run alone, whose Mach-O artifacts the ELF
    /// reader does not read: each is read and run with no witness asked of it.
    pub witness: Option<&'a compile::RunWitness>,
}

impl Driver<'_> {
    /// The compiler driver for a probe's language.
    ///
    /// # Errors
    ///
    /// Errors when the probe needs a C++ driver and none was found.
    pub fn driver_for(&self, lang: Lang) -> Result<&Path> {
        match lang {
            Lang::C => Ok(self.toolchain.driver_path.as_path()),
            Lang::Cxx => self.toolchain.cxx_driver_path.as_deref().ok_or_else(|| {
                UserError::with_hint(
                    "this probe needs a C++ driver and none was found next to the C driver",
                    "install the matching g++/clang++ package",
                )
                .into()
            }),
        }
    }

    /// Build a probe's `aux_libs` in order, returning the first that failed to build or is
    /// not this run's ([`AuxStop`]), if any.
    fn build_aux_libs(
        &self,
        probe: &Probe,
        driver: &Path,
        arm: &[String],
    ) -> Result<Option<AuxStop>> {
        for aux in probe.aux_libs {
            let source = self.workdir.join(aux.source_name);
            std::fs::write(&source, aux.source)
                .with_context(|| crate::error::HarnessPath(source.clone()))
                .context("writing the auxiliary library source")?;
            let artifact = self.workdir.join(format!("lib{}.so", aux.stem));
            let flags = aux_lib_flags(arm, aux.stem, self.workdir);
            let record = compile::build(
                driver,
                &flags,
                &source,
                &artifact,
                aux.link_libs,
                self.witness,
            )?;
            if aux_build_failed(&record) {
                return Ok(Some(AuxStop::Failed(record)));
            }
            if let Some(absence) = self.aux_lib_absence(&artifact, aux.stem) {
                return Ok(Some(AuxStop::Unwitnessed(absence)));
            }
        }
        Ok(None)
    }

    /// Why a library of the probe's own chain, just built at `artifact`, is not this run's,
    /// or `None` where the run's witness confirms it or the run has none.
    fn aux_lib_absence(&self, artifact: &Path, stem: &str) -> Option<compile::WitnessAbsence> {
        let witness = self.witness?;
        let absence = match elf::facts_for(artifact) {
            Ok(facts) => witness.confirm(&facts).err()?,
            Err(e) => compile::WitnessAbsence::Unread(report::ArtifactRefusal::of(&e).why),
        };
        Some(compile::WitnessAbsence::Library {
            name: format!("lib{stem}.so"),
            absence: Box::new(absence),
        })
    }

    /// Build the probe's own dependency chain, and say whether the variant stops there: a
    /// library that failed to build is the variant's build record, and one that is not
    /// this run's leaves the variant unwitnessed, with nothing linked against it.
    fn aux_libs_stop(
        &self,
        probe: &Probe,
        driver: &Path,
        arm: &[String],
        variant: &mut Variant,
    ) -> Result<bool> {
        match self.build_aux_libs(probe, driver, arm)? {
            Some(AuxStop::Failed(failed)) => variant.build = Some(failed),
            Some(AuxStop::Unwitnessed(absence)) => variant.unwitnessed = Some(absence),
            None => return Ok(false),
        }
        Ok(true)
    }

    /// The same build again with the compiler's SARIF on stderr, decoded, for a probe with
    /// a check the structured decoder reads; `None` when the gate is off or the probe has
    /// no such check.
    fn structured_capture(
        &self,
        probe: &Probe,
        driver: &Path,
        flags: &[String],
        source: &Path,
        inputs: &[&str],
        qualified: &str,
    ) -> Option<crate::structured::Capture> {
        let flag = self.structured?;
        if !probe
            .checks
            .iter()
            .any(|c| c.channel() == Channel::CompilerDiag && probe::diag_needles(c.id).is_some())
        {
            return None;
        }
        let mut side = flags.to_vec();
        side.push(flag.to_owned());
        let out = self.workdir.join(format!("{qualified}-sarif.out"));
        let record = compile::build_with_inputs(
            driver,
            &side,
            source,
            inputs,
            &out,
            probe.link_libs,
            self.witness,
        );
        Some(crate::structured::Capture::of(
            flag,
            record.as_ref().map_err(|e| format!("{e:#}")),
        ))
    }

    /// Why a relocatable object a build of the run compiled is not read as the report's
    /// compiler's, or `None` where its `.comment` names that compiler, shows none, or the
    /// artifact is linked.
    fn compiled_elsewhere(&self, facts: &elf::ElfFacts) -> Option<compile::WitnessAbsence> {
        if facts.elf_type != RELOCATABLE {
            return None;
        }
        match toolchain::object_compiler(
            &facts.comment,
            facts.comment_truncation(),
            self.toolchain.kind,
            &self.toolchain.version,
        ) {
            toolchain::ObjectCompiler::Other(lines) => {
                Some(compile::WitnessAbsence::OtherCompiler {
                    lines,
                    named: format!(
                        "{} {}",
                        self.toolchain.kind.as_str(),
                        self.toolchain.version
                    ),
                    witnessed: self.witness.is_some(),
                })
            }
            toolchain::ObjectCompiler::Agrees | toolchain::ObjectCompiler::NotShown(_) => None,
        }
    }

    /// Read `artifact` into `variant`: its facts where the reader read it and the run's
    /// witness confirms it, and otherwise why not.
    fn read_artifact(&self, artifact: &Path, variant: &mut Variant) {
        match elf::facts_for(artifact) {
            Ok(facts) => match self
                .witness
                .map_or(Ok(()), |witness| witness.confirm(&facts))
                .and_then(|()| self.compiled_elsewhere(&facts).map_or(Ok(()), Err))
            {
                Ok(()) => variant.elf = Some(facts),
                Err(absence) => {
                    variant.elf_error = Some(report::ArtifactRefusal::unwitnessed(&absence));
                    variant.unwitnessed = Some(absence);
                }
            },
            Err(e) => {
                let refusal = report::ArtifactRefusal::of(&e);
                if self.witness.is_some() {
                    variant.unwitnessed = Some(if is_bitcode(artifact) {
                        compile::WitnessAbsence::Bitcode
                    } else {
                        compile::WitnessAbsence::Unread(refusal.why.clone())
                    });
                }
                variant.elf_error = Some(refusal);
            }
        }
    }

    /// Build (and if needed run) one variant, collecting whatever evidence the
    /// probe's channels require.
    ///
    /// # Errors
    ///
    /// Errors when the compiler cannot be invoked or the work directory is unusable.
    pub fn gather(&self, probe: &Probe, flags_in: &[String], tag: &str) -> Result<Variant> {
        self.gather_with(probe, flags_in, &[], tag)
    }

    /// The macro dump of `probe`'s own translation unit, where it has a macro-channel check,
    /// with its record; an empty map and no record otherwise.
    fn probe_macro_dump(
        &self,
        probe: &Probe,
        driver: &Path,
        kept: &[String],
        qualified: &str,
    ) -> Result<(BTreeMap<String, String>, Option<compile::BuildRecord>)> {
        if !probe.checks.iter().any(|c| c.channel() == Channel::Macro) {
            return Ok((BTreeMap::new(), None));
        }
        let words = dump_words(probe.link_mode, kept, self.witness.is_some());
        let (macros, record) = compile::macro_dump(
            driver,
            probe.lang,
            &words,
            compile::DumpUnit::Source(probe.source),
            self.workdir,
            qualified,
        )?;
        Ok((macros, Some(record)))
    }

    /// [`Driver::gather`] with `inputs` linked after the probe's source: a positive arm's own
    /// inputs ([`probe::PositiveInput`]), written into the work directory before the build and
    /// named on its command line, so the arm's `argv` carries them. Every other variant is
    /// gathered with none.
    ///
    /// # Errors
    ///
    /// As [`Driver::gather`], and when an input cannot be written.
    pub fn gather_with(
        &self,
        probe: &Probe,
        flags_in: &[String],
        inputs: &[&probe::PositiveInput],
        tag: &str,
    ) -> Result<Variant> {
        let driver = self.driver_for(probe.lang)?;

        // `tag` names the variant only ("clean", "measured", "<check>-pos"); the
        // probe id is prefixed here so retained evidence filenames read as
        // `link-defaults-clean` rather than repeating the probe twice.
        let qualified = format!("{}-{tag}", probe.id);
        // Drop flags that cannot coexist with this output kind (`LinkMode::partition_flags`);
        // the build below and the dump both start from what survives.
        let (kept, dropped) = probe.link_mode.partition_flags(flags_in);

        let (macros_preprocessor, macro_dump) =
            self.probe_macro_dump(probe, driver, &kept, &qualified)?;

        let mut variant = Variant {
            macros: macros_preprocessor.clone(),
            macros_preprocessor,
            macro_source: "preprocessor",
            macro_dump,
            elf: None,
            build: None,
            run: None,
            run_error: None,
            elf_error: None,
            unwitnessed: None,
            artifact: None,
            structured: None,
            workdir: Some(self.workdir.to_path_buf()),
        };
        if !probe.needs_build() {
            return Ok(variant);
        }

        // The probe's own dependency chain, before its link.
        if self.aux_libs_stop(probe, driver, flags_in, &mut variant)? {
            return Ok(variant);
        }

        let source = self.workdir.join(probe.source_name);
        let suffix = match probe.link_mode {
            probe::LinkMode::Executable => String::new(),
            probe::LinkMode::SharedObject | probe::LinkMode::SharedObjectAsCompiled => {
                ".so".to_owned()
            }
            probe::LinkMode::Object => ".o".to_owned(),
        };
        let artifact = self.workdir.join(format!("{qualified}{suffix}"));
        // Append the flags that produce this output kind, so a profile written for
        // executables does not fail to link a library probe.
        let mut flags = kept;
        let produced = probe.link_mode.extra_flags(&flags);
        flags.extend(produced.iter().map(|s| (*s).to_owned()));
        // Where the chain was built, and where the linker must look to *follow* it.
        flags.extend(chain_search_flags(probe, self.workdir));
        for input in inputs {
            let path = self.workdir.join(input.source_name);
            std::fs::write(&path, input.source)
                .with_context(|| crate::error::HarnessPath(path.clone()))
                .context("writing a control arm's own input")?;
        }
        let input_names: Vec<&str> = inputs.iter().map(|input| input.source_name).collect();
        let mut build = compile::build_with_inputs(
            driver,
            &flags,
            &source,
            &input_names,
            &artifact,
            probe.link_libs,
            self.witness,
        )?;
        variant.structured =
            self.structured_capture(probe, driver, &flags, &source, &input_names, &qualified);
        // What the filter removed, carried into the record.
        build.dropped_flags = dropped;
        let build = build;
        // Exited 0 and wrote nothing (`compile::build` clears the path first): the ELF read
        // and the run are skipped.
        let produced_artifact = build.artifact_sha256.is_some();
        if build.succeeded() && produced_artifact {
            variant.artifact = Some(artifact.clone());
            // An unreadable artifact from a build that succeeded is missing evidence, so
            // the check reports build-failed rather than a verdict.
            self.read_artifact(&artifact, &mut variant);
            // Prefer what the compiler believed over a separate preprocessor job: `-dM -E`
            // is driven by *cpp_options and code generation by *cc1_options, so a spec file
            // patching one makes them disagree, and the artifact is the side that matters.
            if let Some(facts) = variant.elf.as_ref()
                && let Ok(from_artifact) = report::self_report_entries(facts)
            {
                variant.macros = from_artifact;
                variant.macro_source = "compiled-artifact";
            }
            // Run only what the witness confirmed: running an unwitnessed artifact would
            // read a program this run cannot show it built.
            if probe.needs_run() && variant.unwitnessed.is_none() {
                match runner::execute(&artifact, self.workdir, self.timeout, probe.run_environment)
                {
                    Ok(record) => variant.run = Some(record),
                    // Recorded, not propagated: see `Variant::run_error`.
                    Err(err) => variant.run_error = Some(format!("{err:#}")),
                }
            }
        }
        variant.build = Some(build);
        Ok(variant)
    }
}

/// `ElfFacts::elf_type` for a relocatable object, the spelling the ELF reader gives
/// `e_type` 1: an object a build compiled and did not link, which is what
/// `Driver::compiled_elsewhere` holds to the report's compiler. `src/main.rs` reads the
/// same spelling for the run's warnings, through this constant.
pub const RELOCATABLE: &str = "ET_REL";

/// The self-report's entries that are chard's own summaries rather than macros.
const SELF_REPORT_SUMMARIES: &[&str] = &["_FORTIFY_IMPL", "_CXX_STDLIB"];

/// A dump's value for a macro, followed through the dump's own definitions.
fn expanded_in_dump<'a>(dump: &'a BTreeMap<String, String>, value: &'a str) -> &'a str {
    let mut current = value;
    for _ in 0..dump.len() {
        match dump.get(current) {
            Some(next) if next != current => current = next,
            _ => break,
        }
    }
    current
}

/// Where the compiled artifact's macros and the preprocessor dump disagree, one entry per
/// macro, `name: codegen=<value> cpp=<value>`, or none where there is no second view to
/// disagree with.
fn compare_macro_views(bare: &Variant) -> Vec<String> {
    let mut disagreements = Vec::new();
    if bare.macro_source != "compiled-artifact"
        || bare.macro_dump.is_none()
        || bare.macro_dump_failure().is_some()
    {
        return disagreements;
    }
    let Some(listing) = bare
        .elf
        .as_ref()
        .and_then(|elf| probe::self_report_listing(&elf.self_report))
    else {
        return disagreements;
    };
    let cpp = &bare.macros_preprocessor;
    for (name, value) in &listing {
        if SELF_REPORT_SUMMARIES.contains(&name.as_str()) {
            continue;
        }
        let dumped = cpp.get(name).map(|v| expanded_in_dump(cpp, v));
        match (value.as_deref(), dumped) {
            (Some(codegen), Some(other)) if codegen == other => {}
            (None, None) => {}
            (codegen, other) => disagreements.push(format!(
                "{name}: codegen={} cpp={}",
                codegen.unwrap_or("<undefined>"),
                other.unwrap_or("<undefined>")
            )),
        }
    }
    disagreements
}

/// Macros the *compiler* defines to describe its own code generation.
const COMPILER_DEFINED_MACROS: &[&str] = &[
    "__SSP__",
    "__SSP_STRONG__",
    "__SSP_ALL__",
    "__SSP_EXPLICIT__",
    "__USE_FORTIFY_LEVEL",
    // Listed for the same reason as glibc's spelling above, since `fortify-effective` turns
    // on it: a macro a verdict turns on has to be one the flag list cannot forge.
    "_USE_FORTIFY_LEVEL",
    // FreeBSD's settled level, which `fortify-effective`'s FreeBSD clauses read,
    // and the platform macro those clauses require beside it: a flag list defining either
    // is answering the question.
    "__SSP_FORTIFY_LEVEL",
    "__FreeBSD__",
    "__ARM_FEATURE_BTI_DEFAULT",
    "__ARM_FEATURE_PAC_DEFAULT",
    "__ARM_FEATURE_GCS_DEFAULT",
    "__PIE__",
    "__PIC__",
    "__CET__",
    "__OPTIMIZE__",
    // `exceptions-macro` turns on this one.
    "__EXCEPTIONS",
];

/// The macro that names the compiler family, which a probe's source branches on to choose
/// a construct or to print `frontend=` for its decoder. Not in [`COMPILER_DEFINED_MACROS`],
/// since no macro check reads it; watched here because a flag list defining or undefining
/// it steers a probe that branches on it ([`PROBE_MACRO_BRANCHES`]).
#[cfg(test)]
const COMPILER_IDENTITY_MACROS: &[&str] = &["__clang__"];

/// The probes whose own source branches on a macro the compiler defines to describe its
/// code generation or itself, each with the macros it branches on: the names of
/// [`COMPILER_DEFINED_MACROS`] and [`COMPILER_IDENTITY_MACROS`] its `#if`, `#ifdef`,
/// `#ifndef` and `#elif` lines test.
const PROBE_MACRO_BRANCHES: &[(&str, &[&str])] = &[
    ("cxx-stdlib-assertions", &["__OPTIMIZE__"]),
    ("pic-object", &["__clang__"]),
    ("shadow-stack", &["__CET__"]),
    ("strict-flex-arrays", &["__OPTIMIZE__"]),
    (
        "strict-flex-arrays-enforced",
        &["__FreeBSD__", "__OPTIMIZE__", "__clang__"],
    ),
    ("trapv", &["__clang__"]),
    ("ub-null-check", &["__OPTIMIZE__"]),
    ("ub-signed-overflow", &["__OPTIMIZE__", "__clang__"]),
    ("ub-strict-aliasing", &["__OPTIMIZE__", "__clang__"]),
    ("ubsan-trap", &["__clang__"]),
    ("zero-call-used-regs", &["__CET__"]),
];

/// Whether the source of the probe `id` branches on a macro ([`PROBE_MACRO_BRANCHES`]), so
/// [`settle_probe_branches`] withholds its readings off the macro channel where the compile
/// comparison found a difference: what a replay holds such a reading to.
#[must_use]
pub(crate) fn branches_on_macros(id: &str) -> bool {
    PROBE_MACRO_BRANCHES.iter().any(|(probe, _)| *probe == id)
}

/// Which of `names` this flag list defines or undefines itself, in the spellings
/// [`preprocessor_ops`] reads.
fn spoofed_among<'a>(flags: &[String], names: &[&'a str]) -> Vec<&'a str> {
    let mut found: Vec<&'a str> = Vec::new();
    for op in preprocessor_ops(flags) {
        if let Some(m) = names.iter().find(|m| **m == op.name)
            && !found.contains(m)
        {
            found.push(m);
        }
    }
    found
}

/// `macro-supplied-by-profile` over what [`settle`] left, for a check off the macro channel
/// of a probe in [`PROBE_MACRO_BRANCHES`] whose measured flag list defines or undefines a
/// macro the probe's source branches on, or carries an input that can: the program chard
/// built and ran took the branch the list chose, so the reading measures the list. A check
/// already withheld keeps its reason, as the spoof clause inside `settle` leaves a declared
/// rule standing.
fn settle_probe_branches(
    settled: Settled,
    probe: &Probe,
    check: &Check,
    profile_flags: &[String],
    unmatched_compile: Option<&str>,
) -> Settled {
    if check.channel() == Channel::Macro || !settled.verdict.is_measurement() {
        return settled;
    }
    let Some((_, branches)) = PROBE_MACRO_BRANCHES.iter().find(|(id, _)| *id == probe.id) else {
        return settled;
    };
    let names: Vec<String> = branches.iter().map(|m| format!("`{m}`")).collect();
    let spoofed = spoofed_among(profile_flags, branches);
    let reason = if !spoofed.is_empty() {
        let spoofed: Vec<String> = spoofed.iter().map(|m| format!("`{m}`")).collect();
        format!(
            "the flag list defines or undefines {} itself, and the source of the probe `{}` branches on it",
            spoofed.join(", "),
            probe.id
        )
    } else if unread_preprocessor_input(profile_flags) {
        format!(
            "the flag list carries a preprocessor input this rule does not read by name, and the source of the probe `{}` branches on {}",
            probe.id,
            names.join(", ")
        )
    } else if let Some(unmatched) = unmatched_compile {
        // The driver's `-###` listing for the measured compile names what a specs or
        // configuration file, or a header selection, added: a macro operation or a header
        // among them can define what the probe branches on, and the list never named it.
        format!(
            "the driver's listing for the measured compile differs from the arms' ({unmatched}), and the source of the probe `{}` branches on {}",
            probe.id,
            names.join(", ")
        )
    } else if report::COMPILE_INPUT_READINGS.contains(&check.id)
        && toolchain::header_selecting_flags(profile_flags)
            .iter()
            .any(|w| toolchain::selects_header_directory(w))
    {
        // Under a header search directory a header the probe includes can be shadowed, keyed
        // on a macro only the measured build defines, and the arms, carrying the directory
        // and never the macro words, read the shadow as inert.
        format!(
            "the flag list selects a header search directory (`-I`, `-isystem`, `-idirafter` or `-iquote`) that can shadow a header the probe `{}` includes, and its source branches on {}",
            probe.id,
            names.join(", ")
        )
    } else {
        return settled;
    };
    Settled {
        verdict: report::gating_rule::MACRO_SPOOFED.verdict(),
        gating: Some(report::Gating {
            rule: report::gating_rule::MACRO_SPOOFED,
            arch: None,
            libc: None,
            needs_vm: check.gate.needs_vm,
            reason,
        }),
        level: None,
    }
}

/// Which compiler-defined macros this flag list defines or undefines itself, in the
/// spellings [`preprocessor_ops`] reads; Fedora ships
/// `-Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3`, so the passthrough forms are not
/// hypothetical.
fn spoofed_macros(flags: &[String]) -> Vec<&'static str> {
    spoofed_among(flags, COMPILER_DEFINED_MACROS)
}

/// The spoof clause's reason for a macro-channel check with no artifact or runtime twin
/// ([`report::MACRO_WITHOUT_TWIN`]) whose measured flag list selects a header search
/// directory ([`crate::toolchain::HEADER_VALUED`]'s directory words, in the spellings
/// [`crate::toolchain::header_selecting_flags`] reads) or carries a preprocessor input
/// [`preprocessor_ops`] does not read by name ([`unread_preprocessor_input`]), or `None`
/// where the check has a twin or the list carries neither.
fn twinless_unread_input(
    check: &Check,
    observed: &str,
    profile_flags: &[String],
) -> Option<String> {
    if !report::MACRO_WITHOUT_TWIN
        .iter()
        .any(|(id, _)| *id == check.id)
    {
        return None;
    }
    unread_input_reason(
        observed,
        profile_flags,
        &format!(
            "no check reading the artifact or a run of it holds `{}`",
            check.id
        ),
    )
}

/// The reason [`twinless_unread_input`] and [`withhold_where_no_twin_measured`] publish for
/// a macro reading under `profile_flags`, quoting the compiler-defined macros `observed`
/// names, with `unheld` saying why nothing built holds the reading; `None` where the list
/// selects no header search directory and carries no input [`preprocessor_ops`] does not
/// read by name.
fn unread_input_reason(observed: &str, profile_flags: &[String], unheld: &str) -> Option<String> {
    let carrier = UnreadInput::of(profile_flags)?.clause();
    let names: Vec<String> = COMPILER_DEFINED_MACROS
        .iter()
        .filter(|m| observed.contains(*m))
        .map(|m| format!("`{m}`"))
        .collect();
    let reads = if names.is_empty() {
        "the macro it reads".to_owned()
    } else {
        names.join(", ")
    };
    Some(format!(
        "the flag list {carrier} can define or undefine {reads} as a `-D` in the list would, and {unheld}"
    ))
}

/// What in a flag list [`unread_input_reason`] reads as able to set a macro the spoof clause
/// cannot see: a header search directory, under which a header the probe includes can be
/// shadowed, a preprocessor input the clause does not read by name, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnreadInput {
    Directory,
    Input,
    Both,
}

impl UnreadInput {
    /// The list's, or `None` where it selects no header search directory and carries no
    /// input [`preprocessor_ops`] does not read by name.
    fn of(profile_flags: &[String]) -> Option<Self> {
        let directory = toolchain::header_selecting_flags(profile_flags)
            .iter()
            .any(|w| toolchain::selects_header_directory(w));
        match (directory, unread_preprocessor_input(profile_flags)) {
            (true, true) => Some(Self::Both),
            (true, false) => Some(Self::Directory),
            (false, true) => Some(Self::Input),
            (false, false) => None,
        }
    }

    /// The clause of the gating reason, ending in the subject of "can define or undefine".
    fn clause(self) -> &'static str {
        match self {
            Self::Both => {
                "selects a header search directory and carries a preprocessor input this rule \
                 does not read by name; either"
            }
            Self::Directory => {
                "selects a header search directory, under which a header the probe includes can \
                 be shadowed, and such a header"
            }
            Self::Input => {
                "carries a preprocessor input this rule does not read by name, and such an input"
            }
        }
    }

    /// The same in a few words, for a diagnostic beside the reason, ending in the subject of
    /// "can set".
    fn short(self) -> &'static str {
        match self {
            Self::Both => {
                "selects a header search directory and carries an input the spoof clause does \
                 not read by name, either of which"
            }
            Self::Directory => "selects a header search directory, under which a shadowing header",
            Self::Input => "carries an input the spoof clause does not read by name, which",
        }
    }
}

/// What the twin `twin` of a reading [`withhold_where_no_twin_measured`] holds is, in this run,
/// in place of a measurement: absent from `observations`, with the probe that carries it, or
/// its verdict and the rule that withheld it. The probe is returned too where the twin is
/// absent, so the diagnostic can name the probe to select.
fn twin_state(twin: &str, observations: &[Observation]) -> (String, Option<&'static str>) {
    match observations.iter().find(|t| t.check == twin) {
        None => {
            let probe = probe::CORPUS
                .iter()
                .find(|p| p.checks.iter().any(|c| c.id == twin))
                .map(|p| p.id);
            let state = match probe {
                Some(p) => {
                    format!("`{twin}` is not in this run, its probe `{p}` not selected")
                }
                None => format!("`{twin}` is not in this run"),
            };
            (state, probe)
        }
        Some(t) => {
            let state = match &t.gating {
                Some(g) => format!(
                    "`{twin}` reads `{}` under `{}`",
                    t.verdict.as_str(),
                    g.rule.id
                ),
                None => format!("`{twin}` reads `{}`", t.verdict.as_str()),
            };
            (state, None)
        }
    }
}

/// The macro checks with a twin in [`report::MACRO_TWINS`] that the input clause holds
/// where no twin of theirs is a measurement in the run: without it, a run that leaves
/// `optimization-object` out, or whose twin is not a measurement, would publish a forged
/// `__OPTIMIZE__` that a forced include or a shadow header carried. The clause reads the
/// profile's own words, so a check here is one of [`report::COMPILE_INPUT_READINGS`], whose
/// arms carry the same words; the other twinned checks are left to their twins, and are
/// unheld where a twin is absent.
pub(crate) const HELD_BY_INPUT_WITHOUT_TWIN: &[&str] = &["optimization-enabled"];

/// Withhold under `macro-supplied-by-profile` each measurement of a check in
/// `HELD_BY_INPUT_WITHOUT_TWIN` where no twin of it is a measurement in `observations`
/// ([`report::measured_twins`]) and its probe's measured flag list selects a header search
/// directory or carries an input the spoof clause does not read by name. Run after
/// [`report::withhold_contradicted_macros`], so a reading a twin contradicted keeps that
/// rule's reason; a reading already withheld is not a measurement and is left alone.
#[must_use]
pub fn withhold_where_no_twin_measured(
    observations: &mut [Observation],
    profile: &Profile,
) -> Vec<Diagnostic> {
    let unheld: Vec<(usize, String, String)> = observations
        .iter()
        .enumerate()
        .filter(|(_, o)| {
            HELD_BY_INPUT_WITHOUT_TWIN.contains(&o.check.as_str())
                && o.verdict.is_measurement()
                && report::measured_twins(o, observations).is_empty()
        })
        .filter_map(|(i, o)| {
            let lang = match probe::CORPUS.iter().find(|p| p.id == o.probe) {
                Some(p) => p.lang,
                None => Lang::C,
            };
            let flags = variant_flags(profile, lang, &[]);
            let input = UnreadInput::of(&flags)?;
            let states: Vec<(String, Option<&'static str>)> = report::MACRO_TWINS
                .iter()
                .filter(|t| t.macro_check == o.check)
                .flat_map(|t| {
                    t.witnesses
                        .iter()
                        .map(|w| twin_state(w.check, observations))
                })
                .collect();
            let said: Vec<&str> = states.iter().map(|(s, _)| s.as_str()).collect();
            let said = said.join("; ");
            // The check's observable names the macro it reads; the self-report holds every
            // macro the probe reports, and an `off` reading's lacks the one it reads.
            let reason = unread_input_reason(
                &o.observable,
                &flags,
                &format!(
                    "no twin of it, which would read the artifact, is a measurement in this \
                     run ({said})"
                ),
            )?;
            let select: Vec<String> = states
                .iter()
                .filter_map(|(_, p)| p.map(|p| format!("`--probe {p}`")))
                .collect();
            let hint = if select.is_empty() {
                String::new()
            } else {
                format!(
                    "; a run that adds {} lets the twin hold the reading where its object is one the twin reads",
                    select.join(" and ")
                )
            };
            let message = format!(
                "`{}` read `{}` on the macro channel, and no twin of it is a measurement in \
                 this run ({said}) while the flag list {} can set the macro it reads, \
                 so it is withheld as indeterminate under macro-supplied-by-profile{hint}",
                o.check,
                o.verdict.as_str(),
                input.short(),
            );
            Some((i, reason, message))
        })
        .collect();
    let mut withheld = Vec::new();
    for (i, reason, message) in unheld {
        let Some(o) = observations.get_mut(i) else {
            continue;
        };
        o.verdict = report::gating_rule::MACRO_SPOOFED.verdict();
        o.level = None;
        o.gating = Some(report::Gating {
            rule: report::gating_rule::MACRO_SPOOFED,
            arch: None,
            libc: None,
            needs_vm: false,
            reason,
        });
        withheld.push(Diagnostic {
            severity: Severity::Warning,
            context: Some(o.check.clone()),
            message,
            rejection: None,
        });
    }
    withheld
}

/// One `-D` or `-U` a flag list hands the preprocessor.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PreprocessorOp {
    /// `-D` rather than `-U`.
    define: bool,
    name: String,
    /// Passed through the driver to the preprocessor (`-Wp,` or `-Xpreprocessor`), which
    /// applies it after every plain `-D` and `-U`.
    passthrough: bool,
}

/// Every `-D` and `-U` in `flags`, in order: the joined `-DNAME=v` and `-UNAME`, the split
/// `-D NAME`, the `-Wp,` comma form and `-Xpreprocessor` argument that pass them through
/// the driver, and gcc's long spellings of each (`--define-macro NAME`,
/// `--define-macro=NAME=v`, `--def NAME`, `--undefine-macro`, `--un`), read as the short
/// word (`toolchain::read`). [`spoofed_macros`] and [`profile_defines`] read flag lists
/// through this one reader, so the two cannot disagree about which spellings a list uses.
fn preprocessor_ops(flags: &[String]) -> Vec<PreprocessorOp> {
    let mut ops = Vec::new();
    let mut after_xpreprocessor = false;
    // A bare `-D` or `-U` waiting for the name the next piece carries, with whether that
    // bare word was itself passed through.
    let mut split: Option<(bool, bool)> = None;
    let mut i = 0;
    while let Some(flag) = flags.get(i) {
        let reading = toolchain::read(flag, flags.get(i.saturating_add(1)).map(String::as_str));
        i = i.saturating_add(1);
        let passthrough = after_xpreprocessor || flag.starts_with("-Wp,");
        after_xpreprocessor = flag == "-Xpreprocessor";
        // A relay word between a bare `-D` and its name (`-Xpreprocessor -D -Xpreprocessor
        // NAME`, `-Xclang -D -Xclang NAME`) is not the name: the driver hands the next word
        // on to the preprocessor, which reads it as the name.
        if split.is_some() && (flag == "-Xpreprocessor" || flag == "-Xclang") {
            continue;
        }
        // The value of an option that is no `-D` or `-U`, or of a selection, is no
        // operation: the reading spans it, and it is passed over.
        if split.is_none()
            && reading.span() == 2
            && matches!(
                reading.hand,
                toolchain::Hand::Value | toolchain::Hand::Driver
            )
            && !matches!(&*reading.word, "-D" | "-U")
        {
            i = i.saturating_add(1);
            continue;
        }
        let word: &str = &reading.word;
        // `-Wp,-D -Wp,NAME` hands the name through a second `-Wp,`: its `-Wp` piece is the
        // relay, not the name.
        let pieces = word
            .split(',')
            .skip(usize::from(split.is_some() && word.starts_with("-Wp,")));
        for piece in pieces {
            // gcc's `cc1` reads the long spellings as the driver does (`-Wp,--def,X` and
            // `-Xpreprocessor --define-macro=X` define `X`; measured 2026-10-28 on Fedora 44
            // x86_64 with gcc 16.1.1 by `-dM -E`; clang's `-cc1` refuses them), so each piece
            // is read as gcc reads it.
            let spelled = toolchain::spelled_alone(piece.trim());
            let piece: &str = &spelled;
            let (define, passthrough, rest) = if let Some((define, passed)) = split.take() {
                (define, passed, piece)
            } else {
                match (piece.strip_prefix("-D"), piece.strip_prefix("-U")) {
                    (Some(rest), _) => (true, passthrough, rest),
                    (None, Some(rest)) => (false, passthrough, rest),
                    (None, None) => continue,
                }
            };
            if rest.is_empty() {
                split = Some((define, passthrough));
                continue;
            }
            // The name is the leading identifier, after any space the word carries
            // (`-D __CET__` as one word, `-D'__OPTIMIZE__ =1'`, both of which gcc 16.1.1
            // honours), ending as `report::flag_keys` ends it.
            let rest = rest.trim_start();
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let name = rest.get(..end).unwrap_or(rest).to_owned();
            ops.push(PreprocessorOp {
                define,
                name,
                passthrough,
            });
        }
    }
    ops
}

/// Whether `flags` leave `name` defined, by the order gcc and clang apply them in: the
/// passthrough forms after the plain ones, and within each group the last word wins.
fn profile_defines(flags: &[String], name: &str) -> bool {
    let (mut plain, mut passed) = (None, None);
    for op in preprocessor_ops(flags)
        .into_iter()
        .filter(|op| op.name == name)
    {
        if op.passthrough {
            passed = Some(op.define);
        } else {
            plain = Some(op.define);
        }
    }
    passed.or(plain) == Some(true)
}

/// Whether `flags` hand the preprocessor an input [`preprocessor_ops`] does not read: a
/// forced `-include` or `-imacros` (joined, split, in gcc's long and abbreviated spellings
/// `--include=`, `--imacros`, `--im`, which `toolchain::read` reads as the short word, and
/// clang's `-include-pch`), an `@file` response file, or a `-D` or `-U` passed to clang's
/// frontend through `-Xclang`, whose place among the driver's own words
/// [`preprocessor_ops`] does not model.
fn unread_preprocessor_input(flags: &[String]) -> bool {
    let mut after_xclang = false;
    let mut i = 0;
    while let Some(flag) = flags.get(i) {
        let one = i.saturating_add(1);
        let reading = toolchain::read(flag, flags.get(one).map(String::as_str));
        let joined = flag.strip_prefix("-Xclang=");
        let frontend = after_xclang || joined.is_some();
        after_xclang = flag == "-Xclang";
        let word: &str = &reading.word;
        // Each piece as gcc's `cc1` reads it: the long spellings handed through `-Wp,` or
        // `-Xpreprocessor` act as the driver's (`-Wp,--include=f` and `-Wp,--im,f` force the
        // file in).
        let pieces: Vec<std::borrow::Cow<'_, str>> = match (joined, flag.strip_prefix("-Wp,")) {
            (Some(value), _) => vec![toolchain::spelled_alone(value.trim())],
            (None, Some(rest)) => rest
                .split(',')
                .map(|piece| toolchain::spelled_alone(piece.trim()))
                .collect(),
            (None, None) => vec![std::borrow::Cow::Borrowed(word.trim())],
        };
        let unread = pieces.iter().any(|piece| {
            piece.starts_with("-include")
                || piece.starts_with("-imacros")
                || ["--include", "--imacros"].iter().any(|long| {
                    piece
                        .strip_prefix(long)
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('='))
                })
                || piece.starts_with('@')
                || (frontend && (piece.starts_with("-D") || piece.starts_with("-U")))
        });
        if unread {
            return true;
        }
        let takes_its_value = reading.span() == 2
            && matches!(
                reading.hand,
                toolchain::Hand::Value | toolchain::Hand::Driver
            );
        if takes_its_value {
            if flags.get(one).is_some_and(|value| value.starts_with('@')) {
                return true;
            }
            after_xclang = false;
            i = i.saturating_add(2);
        } else {
            i = one;
        }
    }
    false
}

/// The checks whose observations carry `evidence.cxx_assertions_source`: the three that
/// read libstdc++'s assertions, as a macro, an abort and a symbol.
pub const CXX_ASSERTIONS_ATTRIBUTED: [&str; 3] = [
    "cxx-hardening-requested",
    "cxx-stdlib-assertions",
    "cxx-assertions-symbol",
];

/// Every value [`cxx_assertions_source`] returns, in the order it tests for them; the
/// schema's enum for `evidence.cxx_assertions_source` is pinned to this list.
pub const CXX_ASSERTIONS_SOURCES: [&str; 3] =
    ["profile", "library-unoptimized-default", "unattributed"];

/// The label chard derives for the source of libstdc++'s assertions in the measured build,
/// where they are there.
pub fn cxx_assertions_source(
    check: &str,
    macros: &BTreeMap<String, String>,
    profile_flags: &[String],
) -> Option<&'static str> {
    if !CXX_ASSERTIONS_ATTRIBUTED.contains(&check)
        || probe::cxx_stdlib(macros) != Some("libstdc++")
        || !macros.contains_key("_GLIBCXX_ASSERTIONS")
    {
        return None;
    }
    let [profile, library, unattributed] = CXX_ASSERTIONS_SOURCES;
    if ["_GLIBCXX_ASSERTIONS", "_GLIBCXX_DEBUG"]
        .iter()
        .any(|name| profile_defines(profile_flags, name))
    {
        Some(profile)
    } else if !macros.contains_key("__OPTIMIZE__")
        && !profile_defines(profile_flags, "_GLIBCXX_NO_ASSERTIONS")
        && !unread_preprocessor_input(profile_flags)
    {
        Some(library)
    } else {
        Some(unattributed)
    }
}

pub fn evidence_for(variant: &Variant) -> Evidence<'_> {
    Evidence {
        macros: &variant.macros,
        elf: variant.elf.as_ref(),
        build: variant.build.as_ref(),
        run: variant.run.as_ref(),
        workdir: variant.workdir.as_deref(),
    }
}

/// The macro names `evidence.macros` is trimmed to.
pub const MACRO_EVIDENCE_KEEP: &[&str] = &[
    "__SSP__",
    "__SSP_STRONG__",
    "__SSP_ALL__",
    "__SSP_EXPLICIT__",
    "_FORTIFY_SOURCE",
    "__USE_FORTIFY_LEVEL",
    "_USE_FORTIFY_LEVEL",
    // FreeBSD's settled level, from `<ssp/ssp.h>`.
    "__SSP_FORTIFY_LEVEL",
    // Which implementation is providing the wrappers, and fortify-headers' own include
    // guard, which it defines only inside its `_FORTIFY_SOURCE > 0 && __OPTIMIZE__`
    // gate; the self-report and a preprocessor dump both carry the guard.
    "_FORTIFY_IMPL",
    "_FORTIFY_HEADERS_H",
    "__PIC__",
    "__PIE__",
    "__CET__",
    "__OPTIMIZE__",
    "__NO_INLINE__",
    "__OPTIMIZE_SIZE__",
    "__ARM_FEATURE_BTI_DEFAULT",
    "__ARM_FEATURE_PAC_DEFAULT",
    "__ARM_FEATURE_GCS_DEFAULT",
    "__GLIBC__",
    "__GLIBC_MINOR__",
    // The platform macro that names FreeBSD's libc, read by `fortify-effective`'s FreeBSD
    // clauses beside `__SSP_FORTIFY_LEVEL`.
    "__FreeBSD__",
    "_GLIBCXX_ASSERTIONS",
    "_LIBCPP_HARDENING_MODE",
    // The names `_LIBCPP_HARDENING_MODE` forwards to.
    "_LIBCPP_HARDENING_MODE_NONE",
    "_LIBCPP_HARDENING_MODE_FAST",
    "_LIBCPP_HARDENING_MODE_EXTENSIVE",
    "_LIBCPP_HARDENING_MODE_DEBUG",
    "_LIBCPP_HARDENING_MODE_DEFAULT",
    // Which standard library answered.
    "_CXX_STDLIB",
    "_LIBCPP_VERSION",
    "__GLIBCXX__",
    "__SANITIZE_ADDRESS__",
    "__SANITIZE_UNDEFINED__",
    "__STDC_VERSION__",
    "__EXCEPTIONS",
    "__FAST_MATH__",
    "_FILE_OFFSET_BITS",
    "__GNUC__",
    "__clang_major__",
];

/// Trim a macro dump to the hardening-relevant entries. The full dump is
/// thousands of lines; embedding all of it per observation would bury the
/// evidence it is meant to expose (`--emit-macros` keeps the complete one once,
/// at toolchain level). [`MACRO_EVIDENCE_KEEP`] is the list, and the report says so.
pub fn relevant_macros(macros: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    MACRO_EVIDENCE_KEEP
        .iter()
        .filter_map(|name| macros.get_key_value(*name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

pub fn blank_observation(probe: &Probe, check: &Check, verdict: Verdict) -> Observation {
    Observation {
        probe: probe.id.to_owned(),
        check: check.id.to_owned(),
        flag: check.flag.to_owned(),
        channel: check.channel(),
        polarity: check.polarity,
        verdict,
        level: None,
        recommended_level: check.recommended_level().map(ToOwned::to_owned),
        confidence: format!("{:?}", check.confidence).to_lowercase(),
        observable: check.observable.to_owned(),
        boundary: probe::boundary_for(check.flag),
        defects: check.defects.iter().map(|d| (*d).to_owned()).collect(),
        observes: check.observes,
        references: check.references.to_vec(),
        evidence: EvidenceOut::default(),
        build: None,
        run: None,
        controls: None,
        gating: None,
        build_rejection: None,
        structured_diagnostics: None,
        notes: check.notes.to_owned(),
    }
}

/// Measure one probe: gather its evidence once, then decide each of its checks.
pub fn run_probe(driver: &Driver<'_>, probe: &Probe, ctx: &Conditions<'_>) -> ProbeOutcome {
    let mut outcome = measure_probe(driver, probe, ctx);
    for observation in &mut outcome.observations {
        publish(observation, driver.workdir);
    }
    for diagnostic in &mut outcome.diagnostics {
        diagnostic.message = publish_text(&diagnostic.message, driver.workdir);
    }
    outcome
}

/// What a report carries of a captured string: the work directory made relative, and
/// the compiler's temporary file names replaced.
pub(crate) fn publish_text(text: &str, workdir: &Path) -> String {
    scrub_compiler_temp_names(&compile::relativize(text, workdir))
}

/// Rewrite an observation's published copies for the report.
fn publish(observation: &mut Observation, workdir: &Path) {
    let build = |record: &compile::BuildRecord| {
        let mut relative = record.relative_to(workdir);
        relative.stdout = scrub_compiler_temp_names(&relative.stdout);
        relative.stderr = scrub_compiler_temp_names(&relative.stderr);
        relative
    };
    let run = |record: &runner::RunRecord| {
        let mut published = record.clone();
        published.argv = record
            .argv
            .iter()
            .map(|arg| compile::relativize(arg, workdir))
            .collect();
        published.stdout = publish_text(&record.stdout, workdir);
        published.stderr = publish_text(&record.stderr, workdir);
        published
    };
    let text = |value: &mut Option<String>| {
        if let Some(inner) = value.as_ref() {
            *value = Some(publish_text(inner, workdir));
        }
    };

    observation.build = observation.build.as_ref().map(build);
    observation.run = observation.run.as_ref().map(run);
    observation.evidence.macro_dump = observation.evidence.macro_dump.as_ref().map(build);
    text(&mut observation.evidence.observed);
    text(&mut observation.build_rejection);
    if let Some(gating) = observation.gating.as_mut() {
        gating.reason = publish_text(&gating.reason, workdir);
    }
    if let Some(controls) = observation.controls.as_mut() {
        let arms = [
            Some(&mut controls.positive),
            Some(&mut controls.negative),
            controls.regime_negative.as_mut(),
        ];
        for arm in arms.into_iter().flatten() {
            text(&mut arm.detail);
            arm.build = arm.build.as_ref().map(build);
            arm.run = arm.run.as_ref().map(run);
            arm.macro_dump = arm.macro_dump.as_ref().map(build);
        }
    }
}

/// Where the compilers this project meets put their temporary objects.
const TEMP_ROOTS: [&str; 3] = ["/tmp/", "/var/tmp/", "/var/folders/"];

/// The suffixes the two drivers give a temporary file. `.ii` before `.i`, because a
/// name is matched by the first suffix that fits.
const TEMP_SUFFIXES: [&str; 8] = [".ii", ".i", ".o", ".s", ".ld", ".le", ".res", ".args"];

/// The characters that end a path inside a diagnostic, beside whitespace.
const PATH_END: [char; 6] = [':', '\'', '"', ')', ',', ';'];

/// Does `c` end a path inside a diagnostic? [`PATH_END`] says which.
fn ends_path(c: char) -> bool {
    PATH_END.contains(&c) || c.is_whitespace()
}

/// Is `path` a temporary file one of the compilers named?
fn is_compiler_temp_name(path: &str) -> bool {
    let unprefixed = path.strip_prefix("/private").unwrap_or(path);
    if !TEMP_ROOTS.iter().any(|root| unprefixed.starts_with(root)) {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some(stem) = TEMP_SUFFIXES.iter().find_map(|s| name.strip_suffix(s)) else {
        return false;
    };
    let random = |s: &str| s.len() == 6 && s.chars().all(|c| c.is_ascii_alphanumeric());
    stem.strip_prefix("cc").is_some_and(random)
        || stem
            .rsplit_once('-')
            .is_some_and(|(source, tail)| !source.is_empty() && random(tail))
}

/// `text` with every compiler temporary name replaced by `<compiler-temp>`.
#[must_use]
pub fn scrub_compiler_temp_names(text: &str) -> String {
    const PRIVATE: &str = "/private";
    let mut out = String::with_capacity(text.len());
    for (i, token) in text.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let mut rest = token;
        while let Some((start, root)) = TEMP_ROOTS
            .iter()
            .filter_map(|root| rest.find(root).map(|at| (at, *root)))
            .min()
        {
            let before = rest.get(..start).unwrap_or("");
            let path_start = if before.ends_with(PRIVATE) {
                start.saturating_sub(PRIVATE.len())
            } else {
                start
            };
            let after_root = start.saturating_add(root.len());
            let end = rest
                .get(after_root..)
                .and_then(|tail| tail.find(ends_path))
                .map_or(rest.len(), |at| after_root.saturating_add(at));
            let path = rest.get(path_start..end).unwrap_or("");
            out.push_str(rest.get(..path_start).unwrap_or(""));
            if is_compiler_temp_name(path) {
                out.push_str("<compiler-temp>");
            } else {
                out.push_str(path);
            }
            rest = rest.get(end..).unwrap_or("");
        }
        out.push_str(rest);
    }
    out
}

/// The body of [`run_probe`], before its observations are prepared for publication.
fn measure_probe(driver: &Driver<'_>, probe: &Probe, ctx: &Conditions<'_>) -> ProbeOutcome {
    let mut observations: Vec<Observation> = Vec::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    // A probe whose language has no driver chard could find yields `indeterminate` for
    // its checks under `no-driver`, and never aborts the run ([`run_probe`] says why).
    let program = match driver.driver_for(probe.lang) {
        Ok(program) => program,
        Err(err) => return no_driver(probe, &err),
    };

    // Two distinct builds, answering two distinct questions (the module note says why):
    // `clean`, the reference the controls validate the detector against, and `measured`,
    // which carries the profile and is the thing being reported on.
    let clean = match driver.gather(probe, &clean_flags(ctx.profile, probe.lang), "clean") {
        Ok(variant) => variant,
        Err(err) => return unmeasured(probe, "clean", &err),
    };
    let measured = if ctx.profile_is_clean {
        None
    } else {
        match driver.gather(
            probe,
            &variant_flags(ctx.profile, probe.lang, &[]),
            "measured",
        ) {
            Ok(variant) => Some(variant),
            Err(err) => return unmeasured(probe, "measured", &err),
        }
    };
    let bare = measured.as_ref().unwrap_or(&clean);

    diagnostics.extend(evidence_faults(probe, &clean, bare));

    // Asked once per probe, after both builds exist: the arms' selection is the same for
    // every check of the probe that reads a link, or the compile's headers and macros.
    let (record, findings) = ask_listings(program, probe, ctx);
    // The compile's answer is per check: a difference the driver makes with the
    // optimisation level withholds the checks whose arms are at another level.
    let measured_flags = variant_flags(ctx.profile, probe.lang, &[]);

    let mut facts = Facts::default();
    for check in probe.checks {
        match run_check(
            driver,
            probe,
            check,
            (&clean, bare),
            ctx,
            findings.for_check(
                check,
                &listings::arm_optimization_classes(check, &measured_flags, ctx.profile_is_clean),
            ),
            &mut facts,
        ) {
            Ok(observation) => observations.push(observation),
            // A control arm that cannot be *attempted* is a failure to validate the
            // detector, not a reading of the toolchain.
            Err(err) => {
                let (observation, diagnostic) = unvalidated(probe, check, &err);
                observations.push(observation);
                diagnostics.push(diagnostic);
            }
        }
    }
    diagnostics.extend(facts.refused.iter().map(|conflict| Diagnostic {
        severity: Severity::Error,
        message: conflict.sentence(),
        context: Some(probe.id.to_owned()),
        rejection: None,
    }));
    let owed = listings::Owed::of(probe, ctx.profile_is_clean);
    ProbeOutcome {
        observations,
        listings: owed.any().then_some(record),
        facts: facts.store,
        diagnostics,
    }
}

/// The artifacts a probe's faults are read from, each under the label that says which
/// build it is.
fn fault_roles<'a>(clean: &'a Variant, bare: &'a Variant) -> Vec<(&'a Variant, &'static str)> {
    if std::ptr::eq(clean, bare) {
        vec![(clean, "clean")]
    } else {
        vec![(clean, "clean"), (bare, "measured")]
    }
}

/// A table the reader could not finish, on an artifact it otherwise read, as one error
/// diagnostic per cut table per artifact, and a view it dropped as one warning per entry.
fn unread_table_faults(probe: &Probe, roles: &[(&Variant, &str)]) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for (variant, tag) in roles {
        let Some(facts) = variant.elf.as_ref() else {
            continue;
        };
        let mut named: BTreeSet<elf::ElfTable> = BTreeSet::new();
        for cut in &facts.truncations {
            let (severity, message) = match cut.kind {
                elf::TruncationKind::Unread => {
                    if !named.insert(cut.table) {
                        continue;
                    }
                    (
                        Severity::Error,
                        format!(
                            "the {tag} artifact's {} table could not be read to its end, so \
                             every elf-static check reading it withholds: {}",
                            cut.table.as_str(),
                            cut.detail
                        ),
                    )
                }
                elf::TruncationKind::Ignored => (
                    Severity::Warning,
                    format!(
                        "the {tag} artifact's {} table declared something the reader did not \
                         follow, and the loader's or the ABI's reading was measured: {}",
                        cut.table.as_str(),
                        cut.detail
                    ),
                ),
            };
            out.push(Diagnostic {
                severity,
                message,
                context: Some(probe.id.to_owned()),
                rejection: None,
            });
        }
    }
    out
}

/// Faults in the measurement itself, read off the evidence once it is gathered.
fn evidence_faults(probe: &Probe, clean: &Variant, bare: &Variant) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let roles = fault_roles(clean, bare);

    // Exited 0 and wrote nothing.
    for (variant, tag) in &roles {
        if variant
            .build
            .as_ref()
            .is_some_and(|b| b.succeeded() && b.artifact_sha256.is_none())
        {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: format!("the {tag} build exited 0 and produced no artifact"),
                context: Some(probe.id.to_owned()),
                rejection: None,
            });
        }
    }

    for (variant, tag) in &roles {
        if let Some(absence) = variant.unwitnessed.as_ref() {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: format!(
                    "the {tag} artifact {absence}{}, so chard cannot show {}: nothing was \
                     read from it, it was not run, and no check reads it (a check that reads \
                     this build is withheld under {}, and one that takes it as a control arm \
                     reads probe-invalid){}",
                    absence.cause(),
                    absence.unshown(),
                    absence.rule().id,
                    if absence.rule() == report::gating_rule::ARTIFACT_OTHER_COMPILER {
                        ". The run's linked artifacts are not held to a compiler line"
                    } else {
                        ""
                    }
                ),
                context: Some(probe.id.to_owned()),
                rejection: None,
            });
        } else if let Some(reason) = variant.elf_error.as_ref() {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: format!(
                    "the {tag} artifact linked but its ELF facts could not be read, so \
                     every elf-static check over it withholds; over the measured build, so \
                     do its macro checks, under artifact-lacks-self-report, unless it is a \
                     Mach-O object on a macOS run: {reason}"
                ),
                context: Some(probe.id.to_owned()),
                rejection: None,
            });
        }
    }

    diagnostics.extend(unread_table_faults(probe, &roles));

    // A macro dump that failed, or defined nothing: the checks over it withhold through
    // `Variant::sufficient_for`, and this is where the reason reaches the report.
    for (variant, tag) in &roles {
        if variant.macro_dump.is_none() || variant.build.as_ref().is_some_and(|b| !b.succeeded()) {
            continue;
        }
        if let Some(reason) = variant.macro_dump_failure() {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: format!(
                    "the {tag} variant's macro channel could not be read, so every \
                     macro-channel check over it withholds: {reason}"
                ),
                context: Some(probe.id.to_owned()),
                rejection: None,
            });
        }
    }

    // The self-report is provenance rather than a check: if the section is missing, say
    // so as a diagnostic instead of inventing an observation, and say which way it is
    // missing.
    if let Some(facts) = bare.elf.as_ref()
        && probe.embeds_self_report()
        && let Err(absence) = report::self_report_entries(facts)
    {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "probe embeds a {} section but the measured artifact {absence}",
                elf::SELF_REPORT_SECTION
            ),
            context: Some(probe.id.to_owned()),
            rejection: None,
        });
    }

    diagnostics.extend(macro_view_diagnostics(probe, bare));

    diagnostics
}

/// The diagnostic of the two macro views compared ([`compare_macro_views`]), where they
/// disagree.
fn macro_view_diagnostics(probe: &Probe, bare: &Variant) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    // The two macro views should agree, where there are two (a dump is taken only for a
    // probe with a macro-channel check).
    let mut disagreements = compare_macro_views(bare);
    if !disagreements.is_empty() {
        disagreements.sort();
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "the compiler and the preprocessor disagree about {} macro(s): {}",
                disagreements.len(),
                disagreements.join(", ")
            ),
            context: Some(probe.id.to_owned()),
            rejection: None,
        });
    }
    diagnostics
}

/// Every check of a probe whose language has no driver chard could find.
fn no_driver(probe: &Probe, err: &anyhow::Error) -> ProbeOutcome {
    let reason = format!("{err}");
    let observations = probe
        .checks
        .iter()
        .map(|check| {
            let mut observation =
                blank_observation(probe, check, report::gating_rule::NO_DRIVER.verdict());
            observation.gating = Some(report::Gating {
                rule: report::gating_rule::NO_DRIVER,
                arch: None,
                libc: None,
                needs_vm: false,
                reason: format!(
                    "{} was not built: {reason}. The other probes are unaffected",
                    probe.id
                ),
            });
            observation
        })
        .collect();
    ProbeOutcome {
        observations,
        listings: None,
        facts: report::FactStore::default(),
        diagnostics: vec![Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "probe {} skipped: no driver for {:?} was found. Its {} check(s) are \
                 withheld as indeterminate rather than missing",
                probe.id,
                probe.lang,
                probe.checks.len()
            ),
            context: None,
            rejection: None,
        }],
    }
}

/// One check whose control arm could not be built at all, carrying why.
fn unvalidated(probe: &Probe, check: &Check, err: &anyhow::Error) -> (Observation, Diagnostic) {
    let reason = format!("{err:#}");
    let mut observation =
        blank_observation(probe, check, report::gating_rule::UNMEASURED.verdict());
    observation.gating = Some(report::Gating {
        rule: report::gating_rule::UNMEASURED,
        arch: None,
        libc: None,
        needs_vm: false,
        reason: format!(
            "a control arm for {} could not be built at all ({reason})",
            check.id
        ),
    });
    let diagnostic = Diagnostic {
        severity: Severity::Error,
        message: format!(
            "check {} not measured: a control arm could not be built: {reason}",
            check.id
        ),
        context: Some(probe.id.to_owned()),
        rejection: None,
    };
    (observation, diagnostic)
}

/// Every check of a probe whose evidence could not be collected at all, carrying why.
fn unmeasured(probe: &Probe, stage: &str, err: &anyhow::Error) -> ProbeOutcome {
    let reason = format!("{err:#}");
    let observations = probe
        .checks
        .iter()
        .map(|check| {
            let mut observation =
                blank_observation(probe, check, report::gating_rule::UNMEASURED.verdict());
            observation.gating = Some(report::Gating {
                rule: report::gating_rule::UNMEASURED,
                arch: None,
                libc: None,
                needs_vm: false,
                reason: format!(
                    "probe {} was not measured: its {stage} build could not be attempted at all ({reason})",
                    probe.id
                ),
            });
            observation
        })
        .collect();
    ProbeOutcome {
        observations,
        listings: None,
        facts: report::FactStore::default(),
        diagnostics: vec![Diagnostic {
            severity: Severity::Error,
            message: format!(
                "probe {} not measured: the {stage} build could not be attempted: {reason}. Its {} check(s) are indeterminate rather than missing",
                probe.id,
                probe.checks.len()
            ),
            context: Some(probe.id.to_owned()),
            rejection: None,
        }],
    }
}

/// Decide one check: validate the detector with a forced-on and a forced-off build,
/// then read the measured build through it.
///
/// # Errors
///
/// Errors when a control arm cannot be built at all.
#[expect(
    clippy::too_many_lines,
    reason = "the control triple reads as one sequence."
)]
pub fn run_check(
    driver: &Driver<'_>,
    probe: &Probe,
    check: &Check,
    (clean, bare): (&Variant, &Variant),
    ctx: &Conditions<'_>,
    listings: ProbeListings<'_>,
    facts: &mut Facts,
) -> Result<Observation> {
    let unmatched_compile = listings.compile;
    let mut observation = blank_observation(probe, check, Verdict::Indeterminate);

    match report::applicability(check, ctx.env, ctx.target_arch) {
        // Each publishes the verdict its rule's premise reserves.
        Applicability::Unsupported(gating)
        | Applicability::Untrustworthy(gating)
        | Applicability::Unread(gating) => {
            observation.verdict = gating.rule.verdict();
            observation.gating = Some(gating);
            return Ok(observation);
        }
        Applicability::Applicable => {}
    }

    let bare = subject_variant(check, clean, bare);

    // The build this check reads left an artifact that is set aside: not this run's
    // (`artifact-lacks-run-witness`), or this run's and compiled by another compiler than the
    // report names (`artifact-compiled-by-another-compiler`).
    if let Some(absence) = bare.unwitnessed.as_ref() {
        let gating = report::witness_gating(check, absence);
        observation.verdict = gating.rule.verdict();
        observation.evidence.observed = Some(format!("the artifact {absence}"));
        observation.gating = Some(gating);
        attach_macro_provenance(&mut observation, check, bare);
        facts.record(artifact_fact(bare, driver.workdir));
        if check.channel() == Channel::Macro {
            facts.record(dump_fact(bare));
        }
        observation.build.clone_from(&bare.build);
        return Ok(observation);
    }

    // The measured build alone is held to the profile (`Variant::sufficient_for_measured`).
    if let Err(withheld) = bare.sufficient_for_measured(check.channel(), ctx.profile) {
        observation.verdict = withheld.verdict;
        // The reason, in the field a reader checks a verdict against.
        observation.evidence.observed = match check.channel() {
            Channel::Macro => macro_reason(bare),
            Channel::ElfStatic => bare
                .elf_error
                .as_ref()
                .map(|r| r.why.clone())
                .or_else(|| bare.run_error.clone()),
            Channel::CompilerDiag => withheld.refusal.as_ref().map(|refusal| {
                refused_build_reason(
                    bare.build.as_ref(),
                    &publish_text(&refusal.line, driver.workdir),
                )
            }),
            Channel::Runtime => bare.run_error.clone(),
        };
        attach_macro_provenance(&mut observation, check, bare);
        // Entered only on a path that returns the observation, so no entry is left behind
        // by a check that errors out before it publishes one.
        facts.record(artifact_fact(bare, driver.workdir));
        if check.channel() == Channel::Macro {
            facts.record(dump_fact(bare));
        }
        observation.build_rejection = withheld.refusal.map(|refusal| refusal.sentence);
        observation.build.clone_from(&bare.build);
        observation.run.clone_from(&bare.run);
        return Ok(observation);
    }

    // Every detection below passes through `reading`, which is the one place a cut table
    // reaches the triple: an arm read from a half-read table is indeterminate before
    // `decide` sees it, and the measured reading is what `artifact_gating` withholds.
    let probe::Decoding {
        detection: bare_detection,
        proof: bare_proof,
    } = reading(check, bare);
    let bare_decoded = decoded(check, bare, bare_proof.as_ref());

    // Controls are built on the clean variant's footing, never on the profile, so that
    // they validate the detector rather than the profile: each arm carries the profile's
    // target, runtime and header selection, and off the macro channel its linker selection,
    // and nothing else of it (`arm_flags`).
    let positive_control = check.positive_for(ctx.target_arch);
    let positive_flags = arm_flags(check, ctx.profile, probe.lang, positive_control);
    let positive_flags_for_object = positive_flags.clone();
    let negative_flags = arm_flags(check, ctx.profile, probe.lang, check.negative);
    // The positive arm alone links the check's own inputs, where it has any
    // (`probe::PositiveInput`): no other build is handed them.
    let positive = driver.gather_with(
        probe,
        &positive_flags,
        &check.positive_inputs(),
        &format!("{}-pos", check.id),
    )?;
    let positive_reading = positive
        .sufficient_for(check.channel())
        .ok()
        .map(|()| reading(check, &positive));

    // A check with no negative control uses the clean build as its negative sample: for a
    // flag that is off by default, an unflagged build is exactly what "absent" looks like.
    let negative_variant = if negative_flags.is_empty() {
        None
    } else {
        Some(driver.gather(probe, &negative_flags, &format!("{}-neg", check.id))?)
    };
    let negative_arm = negative_variant.as_ref().unwrap_or(clean);
    let negative_reading = negative_arm
        .sufficient_for(check.channel())
        .ok()
        .map(|()| reading(check, negative_arm));

    // Regime-matched negative arm, for runtime detectors only.
    let regime_flags = check
        .owes_regime_control(ctx.profile_is_clean)
        .then(|| {
            regime_arm_flags(
                (
                    &ctx.profile.cflags,
                    &ctx.profile.cxxflags,
                    &ctx.profile.ldflags,
                ),
                probe.lang,
                check,
            )
        })
        .flatten();
    let regime = match regime_flags.as_ref() {
        Some(flags) => Some(driver.gather(probe, flags, &format!("{}-regime-neg", check.id))?),
        None => None,
    };
    // Two levels of `Option`, because the two absences are different facts: the outer is
    // whether a regime arm was owed at all, the inner whether the owed arm could be read.
    let regime_negative_reading: Option<Option<probe::Decoding>> = regime.as_ref().map(|regime| {
        regime
            .sufficient_for(check.channel())
            .is_ok()
            .then(|| reading(check, regime))
    });

    // Where the plain pair withholds on an arm that did not behave as its flag forces, the
    // driver is asked for that arm's own compile command, once, and what it shows of the
    // arm's flags, or why it could not be read, goes to `decide` beside the arm
    // (`crate::overridden`).
    let (positive_overridden, negative_overridden) = {
        let outcome = |r: &Option<probe::Decoding>| r.as_ref().map(|r| r.detection.outcome);
        let program = driver.driver_for(probe.lang)?;
        let asked = |control: &[&str], flags: &[String]| {
            let language = match probe.lang {
                Lang::C => "c",
                Lang::Cxx => "c++",
            };
            crate::overridden::query(program, flags, control, language)
        };
        match report::owed_listing(outcome(&positive_reading), outcome(&negative_reading)) {
            Some(report::Arm::Positive) => (asked(positive_control, &positive_flags), None),
            Some(report::Arm::Negative) if negative_variant.is_some() => {
                (None, asked(check.negative, &negative_flags))
            }
            _ => (None, None),
        }
    };
    // Each arm reaches `decide` with the flags that built it, the same lists the three
    // `gather` calls above were given, so the published `Controls` is complete on
    // construction and cannot claim fewer flags than built an arm.
    let (verdict, mut controls) = report::decide(
        &bare_detection,
        report::ArmInput {
            detection: positive_reading.as_ref().map(|r| &r.detection),
            flags: positive_flags,
            overridden: positive_overridden,
        },
        report::ArmInput {
            detection: negative_reading.as_ref().map(|r| &r.detection),
            flags: negative_flags,
            overridden: negative_overridden,
        },
        regime_negative_reading
            .as_ref()
            .zip(regime_flags)
            .map(|(r, flags)| report::ArmInput {
                detection: r.as_ref().map(|r| &r.detection),
                flags,
                overridden: None,
            }),
        check.levels.grade(),
    );
    // Every arm publishes what it compiled and what happened when it ran, whether the
    // triple agreed or not, so a reader can re-run an arm and check the outcome it is
    // being asked to take on trust.
    controls.positive.build.clone_from(&positive.build);
    controls.positive.run.clone_from(&positive.run);
    controls.negative.build.clone_from(&negative_arm.build);
    controls.negative.run.clone_from(&negative_arm.run);
    if let Some(arm) = controls.regime_negative.as_mut()
        && let Some(regime) = regime.as_ref()
    {
        arm.build.clone_from(&regime.build);
        arm.run.clone_from(&regime.run);
    }
    // Each arm's reading as a value, on every arm the decoder read, whether the triple
    // agreed or not: the outcome `decide` was handed, with the clause and facts it came
    // from, so `decoded-reading-disagrees-with-facts` can replay it.
    controls.positive.decoded = positive_reading
        .as_ref()
        .and_then(|r| decoded(check, &positive, r.proof.as_ref()));
    controls.negative.decoded = negative_reading
        .as_ref()
        .and_then(|r| decoded(check, negative_arm, r.proof.as_ref()));
    if let Some(arm) = controls.regime_negative.as_mut()
        && let Some(regime) = regime.as_ref()
    {
        arm.decoded = regime_negative_reading
            .as_ref()
            .and_then(Option::as_ref)
            .and_then(|r| decoded(check, regime, r.proof.as_ref()));
    }
    // An arm that could not be evaluated says why in `detail`, which `decide`, handed no
    // detection for it, leaves empty: on the macro channel the cause can be the arm's own
    // dump, which nothing else in the report records.
    if controls.positive.detail.is_none() {
        controls.positive.detail = unevaluable_reason(&positive, check.channel());
    }
    if controls.negative.detail.is_none() {
        controls.negative.detail =
            unevaluable_reason(negative_variant.as_ref().unwrap_or(clean), check.channel());
    }
    if let Some(arm) = controls.regime_negative.as_mut()
        && let Some(regime) = regime.as_ref()
        && arm.detail.is_none()
    {
        arm.detail = unevaluable_reason(regime, check.channel());
    }
    // Where each macro arm read its macros from, and the dump that read them, on every
    // arm and whether the triple agreed or not: the macros themselves are in the store.
    if check.channel() == Channel::Macro {
        let arms = [
            Some((&mut controls.positive, &positive)),
            Some((&mut controls.negative, negative_arm)),
            controls.regime_negative.as_mut().zip(regime.as_ref()),
        ];
        for (arm, variant) in arms.into_iter().flatten() {
            arm.macro_source = Some(variant.macro_source.to_owned());
            arm.macro_dump = variant.macro_dump.as_ref().map(published_dump_record);
        }
    }

    // Each build the declared family reads is read here, once, into the field of its own
    // arm; `declared_gating` sees nothing else of the triple.
    let positive_object = if report::LINK_ANDED_MARKINGS.contains(&check.id)
        && controls.positive.outcome == Some(probe::Outcome::Absent)
    {
        let object_probe = Probe {
            link_mode: probe::LinkMode::Object,
            ..*probe
        };
        Some(driver.gather(
            &object_probe,
            &positive_flags_for_object,
            &format!("{}-pos-object", check.id),
        )?)
    } else {
        None
    };
    let readings = DeclaredReadings::read(
        check,
        &controls,
        (&positive, positive_control),
        positive_object.as_ref(),
        negative_variant.as_ref(),
        clean,
        bare,
        ctx.env.kernel.native_machine(),
    );
    let declared = |verdict: Verdict| {
        declared_gating(
            verdict,
            probe,
            check,
            ctx.env.libc.impl_name.as_str(),
            ctx.toolchain_kind.as_str(),
            &readings,
        )
    };
    // `bare` is the build the check's own observable was read from, so the artifact rule
    // inside `settle` asks its precondition of the same object the detector examined.
    let profile_flags = variant_flags(ctx.profile, probe.lang, &[]);
    let settled = settle(
        verdict,
        check,
        &bare_detection,
        declared,
        MeasuredArtifact::of(probe, bare, bare_proof.as_ref()),
        bare.run.as_ref(),
        &profile_flags,
    );
    // The spoof rule's other half, by probe: a runtime or artifact reading of a probe whose
    // own source branches on a macro the measured list defines is a reading of the list.
    let settled = settle_probe_branches(
        settled,
        probe,
        check,
        &profile_flags,
        unmatched_compile.filter(|_| !check.measures_toolchain_default),
    );
    // The self-report gate's other half: an artifact the reader refused, or a build that
    // wrote none, which `settle` could not see.
    let settled = settle_self_report_unread(settled, check, bare, ctx.env.distro.is_macos());
    let settled = settle_emulation(
        settled,
        verdict,
        check,
        bare.elf.as_ref(),
        bare.elf_error.as_ref().map(|r| r.why.as_str()),
        bare.run.as_ref(),
        ctx.env.kernel.native_machine(),
        ctx.env.distro.is_macos(),
    );
    // The listing rules, over whatever the stages before them published (`listings::chain`,
    // which `chard detect` replays over the published listings).
    let settled = settle_listings(settled, check, &listings);
    // An `on` that stood under LTO because the listing resolved the compile to PIC without
    // PIE is quoted beside the detector's own account: the listing is its evidence.
    let lto_pic = report::lto_pic_evidence(check, settled.verdict, listings.lto);
    observation.verdict = settled.verdict;
    observation.gating = settled.gating;
    observation.level = settled.level;
    observation.controls = Some(controls);
    observation.evidence = EvidenceOut {
        macros: (check.channel() == Channel::Macro).then(|| relevant_macros(&bare.macros)),
        macros_filter: None,
        macro_source: None,
        macro_dump: None,
        observed: Some(match &lto_pic {
            Some(basis) => format!("{}; {}", bare_detection.observed, basis.sentence()),
            None => bare_detection.observed.clone(),
        }),
        lto_pic,
        decoded: bare_decoded,
        cxx_assertions_source: None,
    };
    attach_macro_provenance(&mut observation, check, bare);
    // From the map the report publishes for the measured build, the one
    // `cxx-assertions-derived-from-inputs` re-derives it from: the inline map on the
    // macro channel, the artifact's `.chard.report` in `facts` elsewhere.
    let published_macros = if check.channel() == Channel::Macro {
        observation.evidence.macros.clone()
    } else {
        bare.elf
            .as_ref()
            .filter(|_| {
                bare.build
                    .as_ref()
                    .is_some_and(|b| b.artifact_sha256.is_some())
            })
            // Over an artifact with no account there is nothing to attribute from.
            .and_then(|elf| probe::self_report_account(&elf.self_report))
    };
    observation.evidence.cxx_assertions_source = published_macros
        .and_then(|macros| {
            cxx_assertions_source(
                check.id,
                &macros,
                &variant_flags(ctx.profile, Lang::Cxx, &[]),
            )
        })
        .map(ToOwned::to_owned);
    // The store's entries for this observation, entered last so an arm that errored out
    // above leaves none behind.
    let evaluated = [Some(&positive), Some(negative_arm), regime.as_ref()];
    facts.record(artifact_fact(bare, driver.workdir));
    if report::stores_arm_artifacts(check) {
        for arm in evaluated.into_iter().flatten() {
            facts.record(artifact_fact(arm, driver.workdir));
        }
    }
    if check.channel() == Channel::Macro {
        for variant in std::iter::once(bare).chain(evaluated.into_iter().flatten()) {
            facts.record(dump_fact(variant));
        }
    }
    // The dump an `elf-static` predicate read its macros from, where a published reading
    // names one: the reference is the reading's `decoded.macros`, so an arm the decoder
    // never read stores none.
    if check.channel() == Channel::ElfStatic
        && let Some(controls) = observation.controls.as_ref()
    {
        let read = [
            (bare, observation.evidence.decoded.as_ref()),
            (&positive, controls.positive.decoded.as_ref()),
            (negative_arm, controls.negative.decoded.as_ref()),
        ];
        let regime_read = regime.as_ref().zip(
            controls
                .regime_negative
                .as_ref()
                .and_then(|a| a.decoded.as_ref()),
        );
        for (variant, reading) in read
            .into_iter()
            .chain(regime_read.map(|(v, d)| (v, Some(d))))
        {
            if reading.is_some_and(|d| d.macros.is_some()) {
                facts.record(dump_fact(variant));
            }
        }
    }
    let [measured, positive_arm, negative_arm] = crate::structured::ARMS;
    observation.structured_diagnostics = structured_comparison(
        check,
        [
            (measured, bare),
            (positive_arm, &positive),
            (negative_arm, negative_variant.as_ref().unwrap_or(clean)),
        ],
    );
    observation.build.clone_from(&bare.build);
    observation.run.clone_from(&bare.run);
    Ok(observation)
}

/// Both decoders over each arm of a check the structured decoder reads.
fn structured_comparison(
    check: &Check,
    arms: [(&'static str, &Variant); crate::structured::ARMS.len()],
) -> Option<crate::structured::Comparison> {
    let needles = probe::diag_needles(check.id)?;
    let mut format = None;
    let mut compared = BTreeMap::new();
    let mut missing = Vec::new();
    let expected = arms.len();
    for (arm, variant) in arms {
        let (Some(build), Some(capture)) = (variant.build.as_ref(), variant.structured.as_ref())
        else {
            missing.push(arm);
            continue;
        };
        format = Some(capture.flag);
        let prose = probe::diag_severity_of(build, needles).map(crate::decode::diag::Seen::word);
        compared.insert(arm, crate::structured::compare(prose, capture, needles));
    }
    Some(crate::structured::Comparison {
        format: format?,
        arms_expected: expected,
        arms: compared,
        arms_missing: missing,
    })
}

/// What a check publishes once `decide` has spoken: the verdict, the reason it carries, and
/// the level that survives.
struct Settled {
    verdict: Verdict,
    gating: Option<report::Gating>,
    level: Option<String>,
}

/// The measured build's artifact as [`settle`]'s artifact gates read it: the facts the
/// reader took from it, and the output kind the probe asked the driver for, which
/// `report::link_mode_limitation` holds the facts' classification to.
mod measured_artifact {
    use std::collections::BTreeSet;

    use super::{Probe, Variant, elf, probe};
    use crate::predicate::{ElfField, Evaluation, ReadKey};

    #[derive(Debug, Clone, Copy)]
    pub(super) struct MeasuredArtifact<'a> {
        link_mode: probe::LinkMode,
        elf: Option<&'a elf::ElfFacts>,
        proof: Option<&'a Evaluation>,
    }

    impl<'a> MeasuredArtifact<'a> {
        /// The artifact `variant` read, as a build of `probe`: its facts beside the output
        /// kind the probe's own link mode asked for, and the proof of the reading taken over
        /// it (`None` for a code decoder), whose reads say which facts the reading rested on.
        pub(super) fn of(
            probe: &Probe,
            variant: &'a Variant,
            proof: Option<&'a Evaluation>,
        ) -> Self {
            Self {
                link_mode: probe.link_mode,
                elf: variant.elf.as_ref(),
                proof,
            }
        }

        pub(super) fn link_mode(self) -> probe::LinkMode {
            self.link_mode
        }

        pub(super) fn elf(self) -> Option<&'a elf::ElfFacts> {
            self.elf
        }

        /// The ELF fields the reading read, in the order the field type sorts them.
        pub(super) fn read_fields(self) -> BTreeSet<ElfField> {
            elf_fields_read(self.proof)
        }
    }

    /// The ELF fields `proof` read; empty for a reading with no proof.
    pub(super) fn elf_fields_read(proof: Option<&Evaluation>) -> BTreeSet<ElfField> {
        let Some(proof) = proof else {
            return BTreeSet::new();
        };
        proof
            .reads
            .iter()
            .filter_map(|r| match r.key {
                ReadKey::Elf(field) => Some(field),
                ReadKey::Macro(_)
                | ReadKey::Symbol(_)
                | ReadKey::SymbolNames
                | ReadKey::Truncations => None,
            })
            .collect()
    }
}
use measured_artifact::MeasuredArtifact;

/// The rules that run after `decide`, in the one order they run in.
fn settle(
    verdict: Verdict,
    check: &Check,
    reading: &Detection,
    declared: impl FnOnce(Verdict) -> Option<report::Gating>,
    artifact: MeasuredArtifact<'_>,
    run: Option<&runner::RunRecord>,
    profile_flags: &[String],
) -> Settled {
    let (link_mode, elf) = (artifact.link_mode(), artifact.elf());
    let mut verdict = verdict;
    let mut gating = report::level_gating(verdict, check, reading)
        .or_else(|| report::detector_gating(verdict, reading));

    // A declared rule's verdict is left alone by the artifact gates, whatever class its
    // premise is: an `indeterminate` or `not-applicable` from (2) rests on the arms, and the
    // artifact gates would otherwise overwrite it with a reason about the measured build.
    let declared = if verdict == Verdict::ProbeInvalid {
        declared(verdict)
    } else {
        None
    };
    if let Some(declared) = declared {
        verdict = declared.rule.verdict();
        gating = Some(declared);
    } else {
        // Both the run and the artifact gates are handed the verdict `decide` reached,
        // and the artifact gate, consulted second, overwrites where both apply: a runtime
        // check can read a table too (`fortify-enforced-known` does).
        let decided = verdict;
        if let Some(limit) = report::deadline_limitation(decided, check, run)
            .or_else(|| report::stream_limitation(decided, check, run))
        {
            verdict = limit.rule.verdict();
            gating = Some(limit);
        }
        if let Some((gated, limit)) = artifact_gating(
            decided,
            check,
            link_mode,
            reading.outcome,
            elf,
            &artifact.read_fields(),
        ) {
            verdict = gated;
            gating = Some(limit);
        }
    }

    if check.channel() == Channel::Macro {
        let spoofed: Vec<&str> = spoofed_macros(profile_flags)
            .into_iter()
            .filter(|m| reading.observed.contains(m))
            .collect();
        if !spoofed.is_empty() {
            verdict = report::gating_rule::MACRO_SPOOFED.verdict();
            gating = Some(report::Gating {
                rule: report::gating_rule::MACRO_SPOOFED,
                arch: None,
                libc: None,
                needs_vm: false,
                reason: format!(
                    "the flag list defines or undefines {} itself",
                    spoofed.join(", ")
                ),
            });
        } else if verdict.is_measurement()
            && let Some(reason) = twinless_unread_input(check, &reading.observed, profile_flags)
        {
            verdict = report::gating_rule::MACRO_SPOOFED.verdict();
            gating = Some(report::Gating {
                rule: report::gating_rule::MACRO_SPOOFED,
                arch: None,
                libc: None,
                needs_vm: false,
                reason,
            });
        }
    }

    Settled {
        verdict,
        gating,
        level: published_level(verdict, reading.level.as_deref()),
    }
}

/// `artifact-lacks-self-report` over what [`settle`] left, for a macro-channel check whose
/// measured build wrote an artifact chard's ELF reader refused (`elf_error`, except a Mach-O
/// object on macOS, over which the dump is read by design) or exited 0 and wrote none: the
/// reading is the `-dM -E` dump's alone, and [`report::self_report_limitation`] inside
/// `settle` could not see it, since the artifact gates read `bare.elf` and here there is none.
/// The selection is [`report::artifact_account_missing`], the one the consistency rule reads.
/// Speaks where nothing did or only the level or detector rule did, as [`settle_emulation`]
/// does, so a declared rule's `unsupported`, the triple's `probe-invalid` and the later spoof
/// rule stand.
fn settle_self_report_unread(
    settled: Settled,
    check: &Check,
    bare: &Variant,
    macos: bool,
) -> Settled {
    let open = settled
        .gating
        .as_ref()
        .is_none_or(|g| g.rule.stage.is_reading_rule());
    if check.channel() != Channel::Macro
        || !open
        || bare.elf.is_some()
        || matches!(
            settled.verdict,
            Verdict::ProbeInvalid | Verdict::Unsupported
        )
    {
        return settled;
    }
    let Some(absence) =
        report::artifact_account_missing(None, bare.elf_error.as_ref(), bare.build.as_ref(), macos)
    else {
        return settled;
    };
    let limit = report::self_report_gating(check, &absence);
    Settled {
        verdict: limit.rule.verdict(),
        level: published_level(limit.rule.verdict(), None),
        gating: Some(limit),
    }
}

/// `run-under-emulation` over what [`settle`] left: the last rule of [`Stage::Run`], kept
/// out of `settle` only for its argument count.
#[expect(
    clippy::too_many_arguments,
    reason = "the rule reads the settled reading, the decided verdict, the check, the artifact's record or its refusal, the run, the kernel and the platform"
)]
fn settle_emulation(
    settled: Settled,
    decided: Verdict,
    check: &Check,
    elf: Option<&elf::ElfFacts>,
    unread: Option<&str>,
    run: Option<&runner::RunRecord>,
    kernel: crate::env::NativeMachine<'_>,
    macos: bool,
) -> Settled {
    let open = settled
        .gating
        .as_ref()
        .is_none_or(|g| g.rule.stage.is_reading_rule());
    let translation = run
        .filter(|_| macos)
        .map(|r| crate::decode::runtime::translation(&r.stdout));
    let limit = run.and_then(|_| {
        report::emulation_limitation(decided, check, elf, unread, kernel, translation.as_ref())
    });
    match limit {
        Some(limit) if open => Settled {
            verdict: limit.rule.verdict(),
            level: published_level(limit.rule.verdict(), None),
            gating: Some(limit),
        },
        _ => settled,
    }
}

/// The listing rules over what the earlier stages settled ([`listings::chain`]): where one
/// fires, its gating and the verdict its premise publishes, and otherwise `settled` as it was.
fn settle_listings(settled: Settled, check: &Check, listings: &ProbeListings<'_>) -> Settled {
    match listings::chain(check, settled.verdict, listings) {
        Some(limit) => Settled {
            verdict: limit.rule.verdict(),
            level: published_level(limit.rule.verdict(), None),
            gating: Some(limit),
        },
        None => settled,
    }
}

/// The driver's answers the listing rules read for one probe ([`listings::Owed`]), asked
/// once after both builds exist through `program`, the probe's driver, with what their
/// comparisons read of the filesystem ([`crate::link_inputs::Host`]); and the findings every
/// check of the probe reads, derived from that record by [`listings::findings`], the function
/// a replay runs over the published one.
fn ask_listings(
    program: &Path,
    probe: &Probe,
    ctx: &Conditions<'_>,
) -> (listings::Listings, listings::Findings) {
    let owed = listings::Owed::of(probe, ctx.profile_is_clean);
    let language = match probe.lang {
        Lang::C => "c",
        Lang::Cxx => "c++",
    };
    let host = crate::link_inputs::Host::default();
    let mut record = listings::Listings::default();
    if owed.link
        && let Some(check) = listings::link_reading_check(probe)
    {
        record.link = Some(ask_link(program, probe, ctx, check));
    }
    if owed.clean_link
        && let Some(check) = probe
            .checks
            .iter()
            .find(|c| report::reads_the_clean_link(c))
    {
        record.clean_link = Some(ask_clean_link(program, probe, ctx, check));
    }
    if owed.compile {
        record.compile = Some(ask_compile(program, probe, ctx, language, &host));
    }
    if owed.measured_compile {
        record.measured_compile = Some(ask_measured_compile(program, probe, ctx, language));
    }
    let findings = match listings::findings(&record, &host) {
        Ok(findings) => findings,
        Err(listings::Malformed(why)) => withheld_by(
            &record,
            &format!(
                "chard's own record of the driver's answers is not one its comparisons read \
             ({why})"
            ),
        ),
    };
    record.paths = host.answers();
    (record, findings)
}

/// Findings that withhold every rule `record` holds a comparison for, by `why`: what a record
/// [`listings::findings`] refuses stands for, since no comparison was shown.
fn withheld_by(record: &listings::Listings, why: &str) -> listings::Findings {
    let said = |held: bool| held.then(|| why.to_owned());
    listings::Findings {
        link: said(record.link.is_some()),
        clean_link: said(record.clean_link.is_some()),
        compile: listings::CompileFindings {
            whole: said(record.compile.is_some()),
            by_class: Vec::new(),
            exception_model: said(record.compile.is_some()),
        },
        sanitizers: record
            .measured_compile
            .as_ref()
            .map(|_| Err(why.to_owned())),
        lto: record
            .measured_compile
            .as_ref()
            .map(|_| Err(why.to_owned())),
    }
}

/// The two `-###` link lines `link-inputs-unmatched-by-arms` compares, of `check`'s arms:
/// whether the measured build's link and the arms' combine other startup objects is
/// [`listings::findings`]' answer over them.
fn ask_link(
    program: &Path,
    probe: &Probe,
    ctx: &Conditions<'_>,
    check: &Check,
) -> listings::LinkAsked {
    let measured_flags = linked_flags(probe, &variant_flags(ctx.profile, probe.lang, &[]));
    let measured = crate::link_inputs::query(program, &measured_flags);
    // The arms' question carries the measured line's form, so it is asked only where the
    // measured listing was read; the error is kept in the record either way.
    let arms = match &measured {
        Err(_) => None,
        Ok(inputs) => {
            let flags = arms_link_query(
                linked_flags(probe, &arm_flags(check, ctx.profile, probe.lang, &[])),
                inputs.form,
            );
            Some(listings::Asked {
                answer: crate::link_inputs::query(program, &flags).into(),
                flags,
            })
        }
    };
    listings::LinkAsked {
        measured: listings::Asked {
            flags: measured_flags,
            answer: measured.into(),
        },
        arms,
    }
}

/// The four driver answers `clean-link-unmatched-by-measured` compares, of `check`'s arms,
/// each asked only where the one before it was read: whether the clean build a default-asking
/// check reads would link otherwise than the measured build is [`listings::findings`]'
/// answer over them.
fn ask_clean_link(
    program: &Path,
    probe: &Probe,
    ctx: &Conditions<'_>,
    check: &Check,
) -> listings::CleanLinkAsked {
    let measured_flags = linked_flags(probe, &variant_flags(ctx.profile, probe.lang, &[]));
    let footing_flags = linked_flags(probe, &arm_flags(check, ctx.profile, probe.lang, &[]));
    let clean_build_flags = linked_flags(probe, &clean_flags(ctx.profile, probe.lang));
    let measured = listings::Asked {
        answer: crate::link_inputs::query(program, &measured_flags).into(),
        flags: measured_flags.clone(),
    };
    let mut asked = listings::CleanLinkAsked {
        measured,
        footing: None,
        measured_dirs: None,
        clean_dirs: None,
    };
    let read = |answer: &listings::Answer<_>| matches!(answer, listings::Answer::Answer(_));
    if !read(&asked.measured.answer) {
        return asked;
    }
    let footing = listings::Asked {
        answer: crate::link_inputs::query(program, &footing_flags).into(),
        flags: footing_flags,
    };
    let go_on = read(&footing.answer);
    asked.footing = Some(footing);
    if !go_on {
        return asked;
    }
    let measured_dirs = listings::Asked {
        answer: crate::link_inputs::query_search_dirs(program, &measured_flags).into(),
        flags: measured_flags,
    };
    let go_on = matches!(measured_dirs.answer, listings::Answer::Answer(_));
    asked.measured_dirs = Some(measured_dirs);
    if !go_on {
        return asked;
    }
    asked.clean_dirs = Some(listings::Asked {
        answer: crate::link_inputs::query_search_dirs(program, &clean_build_flags).into(),
        flags: clean_build_flags,
    });
    asked
}

/// The compile listings `compile-inputs-unmatched-by-arms` compares: whether the measured
/// build's compile and the arms' read other headers or predefined macros is
/// [`listings::findings`]' answer over them ([`listings::CompileFindings`]), a sentence
/// naming the difference for the whole probe, one per class of arm optimisation words, or
/// neither where the driver names the same inputs. `host` answers the comparison that decides
/// whether the classes are asked, as it answers [`listings::findings`]' own.
fn ask_compile(
    program: &Path,
    probe: &Probe,
    ctx: &Conditions<'_>,
    language: &str,
    host: &crate::link_inputs::Host,
) -> listings::CompileAsked {
    let measured_flags = variant_flags(ctx.profile, probe.lang, &[]);
    let measured = crate::compile_inputs::query(program, &measured_flags, language);
    let mut asked = listings::CompileAsked {
        measured: listings::Asked {
            flags: measured_flags.clone(),
            answer: measured.clone().into(),
        },
        stand_in: None,
        classes: Vec::new(),
    };
    let Ok(measured) = measured else {
        return asked;
    };
    let selection = stand_in_selection(ctx.profile, probe.lang, &measured_flags);
    let macro_words = crate::compile_inputs::macro_words(&measured_flags);
    let flags_at = |words: &[String]| -> Vec<String> {
        selection
            .iter()
            .chain(words.iter())
            .chain(macro_words.iter())
            .cloned()
            .collect()
    };
    let stand_in_flags = flags_at(&crate::compile_inputs::optimization_words(&measured_flags));
    let stand_in = crate::compile_inputs::query(program, &stand_in_flags, language);
    asked.stand_in = Some(listings::Asked {
        flags: stand_in_flags,
        answer: stand_in.clone().into(),
    });
    let Ok(stand_in) = stand_in else {
        return asked;
    };
    if crate::compile_inputs::difference(&measured, &stand_in, host).is_some() {
        return asked;
    }
    for words in listings::owed_classes(probe, &measured_flags, ctx.profile_is_clean) {
        let flags = flags_at(&words);
        asked.classes.push(listings::ClassAsked {
            listing: listings::Asked {
                answer: crate::compile_inputs::query(program, &flags, language).into(),
                flags,
            },
            words,
        });
    }
    asked
}

/// The measured compile's listing, under [`variant_flags`] as the measured build is, for its
/// sanitizer words ([`crate::compile_inputs::CompileInputs::sanitizers`]) where a probe holds
/// a check in [`report::SANITIZER_GROUP_CHECKS`] or
/// [`report::SIGNED_OVERFLOW_SANITIZER_CHECKS`], and its link-time-optimization words
/// ([`crate::compile_inputs::CompileInputs::lto`]) where it holds one in
/// [`report::LTO_CODEGEN_CHECKS`]. A listing that could not be read each rule
/// ([`report::lto_codegen_limitation`] among them) publishes as unknown.
fn ask_measured_compile(
    program: &Path,
    probe: &Probe,
    ctx: &Conditions<'_>,
    language: &str,
) -> listings::Asked<crate::compile_inputs::CompileInputs> {
    let flags = variant_flags(ctx.profile, probe.lang, &[]);
    listings::Asked {
        answer: crate::compile_inputs::query(program, &flags, language).into(),
        flags,
    }
}

/// `flags` through the probe's output kind, as its build takes them
/// ([`probe::LinkMode::partition_flags`] and `extra_flags`): what a listing of that build
/// is asked under.
fn linked_flags(probe: &Probe, flags: &[String]) -> Vec<String> {
    let (mut kept, _) = probe.link_mode.partition_flags(flags);
    let produced = probe.link_mode.extra_flags(&kept);
    kept.extend(produced.iter().map(|s| (*s).to_owned()));
    kept
}

/// The flags the arms' link listing is taken under: the arms' selection through the probe's
/// output kind, then the measured link's own linkage form, so the form is normalised and not
/// compared ([`crate::link_inputs`] says why). Held by its unit test, which fails without the
/// form.
fn arms_link_query(
    mut selection: Vec<String>,
    measured: crate::link_inputs::LinkageForm,
) -> Vec<String> {
    selection.push(measured.driver_flag().to_owned());
    selection
}

/// The macros `words`, a listing's macro words as written, name, into `names`: each word as
/// gcc reads it (`--def X` is `-D X`, `--define-macro=X` is `-DX`), walked by the one
/// classifier (`toolchain::read`), so a two-token operation is joined to its name and a value
/// another word takes is no operation; the pieces of a `-Wp,` word are read the same way.
fn macro_names_in(words: &[String], names: &mut BTreeSet<String>) {
    let mut i = 0;
    while let Some(word) = words.get(i) {
        let next = words.get(i.saturating_add(1)).map(String::as_str);
        let reading = toolchain::read(word, next);
        let spelled = &*reading.word;
        let joined;
        let word: &str = if crate::compile_inputs::is_macro_option(spelled) {
            match next.filter(|_| reading.span() == 2) {
                Some(name) => {
                    joined = format!("{spelled}{name}");
                    joined.as_str()
                }
                None => break,
            }
        } else {
            spelled
        };
        if let Some(list) = word.strip_prefix("-Wp,") {
            let mut pieces = list.split(',').map(toolchain::spelled_alone);
            while let Some(piece) = pieces.next() {
                let operation = if crate::compile_inputs::is_macro_option(&piece) {
                    pieces.next().map(|name| format!("{piece}{name}"))
                } else {
                    Some(piece.into_owned())
                };
                if let Some(name) = operation
                    .as_deref()
                    .and_then(crate::compile_inputs::macro_name)
                {
                    names.insert(name.to_owned());
                }
            }
        } else if let Some(name) = crate::compile_inputs::macro_name(word) {
            names.insert(name.to_owned());
        }
        i = i.saturating_add(reading.own_words_span());
    }
}

/// Every macro a control arm of the corpus sets or unsets by name, from the arms' own
/// `-D`, `-U` and `-Wp,` words: the requests chard measures on purpose (`_FORTIFY_SOURCE`,
/// `_GLIBCXX_ASSERTIONS`, `_GLIBCXX_NO_ASSERTIONS`, `_LIBCPP_HARDENING_MODE`). The register
/// entry `optimization-level-defaults-decide-only-their-own-checks` rests on this set, and its
/// test holds the entry's text to it.
pub(crate) fn macros_the_controls_set() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for probe in probe::CORPUS {
        for check in probe.checks {
            let regime: &[&str] = match check.regime_arm() {
                Some(arm) => arm,
                None => &[],
            };
            let arms = [check.positive, check.negative, regime];
            for arm in arms {
                macro_names_in(
                    &crate::compile_inputs::macro_words(&control_flags(arm)),
                    &mut names,
                );
            }
        }
    }
    names
}

/// The selection the arms' stand-in listing is taken under ([`ask_compile`]), ahead of the
/// profile's optimisation and macro words: what a macro arm of a check that reads the measured
/// build carries before its own flags ([`arm_flags`]), held by
/// `tests::the_stand_in_selection_is_what_the_arms_carry`. Never used for a default-asking
/// check, whose arms carry less.
fn stand_in_selection(profile: &Profile, lang: Lang, measured: &[String]) -> Vec<String> {
    let mut selection = clean_flags(profile, lang);
    selection.extend(toolchain::header_selecting_flags(measured));
    selection
}

/// Put the macro channel's provenance beside a macro-channel observation's evidence, for
/// every verdict including a withheld one: the dump's record makes the cell re-derivable by
/// hand, and the source says whether `macros` is the artifact's testimony or the
/// preprocessor's. Other channels never consulted the dump and get nothing.
fn attach_macro_provenance(observation: &mut Observation, check: &Check, variant: &Variant) {
    if check.channel() != Channel::Macro {
        return;
    }
    observation.evidence.macro_source = Some(variant.macro_source.to_owned());
    observation.evidence.macro_dump = variant.macro_dump.as_ref().map(published_dump_record);
    // The digest of the list `macros` was trimmed to, beside the trimmed map, so a
    // reader who finds a macro missing knows to look for the list before concluding
    // the compiler never defined it.
    if observation.evidence.macros.is_some() {
        observation.evidence.macros_filter = Some(report::evidence_filters().macros.sha256);
    }
}

/// The `-dM -E` record as the report carries it: the job, with its defines replaced by
/// a count of them.
fn published_dump_record(record: &compile::BuildRecord) -> compile::BuildRecord {
    let defines = define_lines(&record.stdout);
    let mut published = record.clone();
    published.stdout_sha256 = Some(dump_key(record));
    published.stdout = format!("<{defines} #define line(s) omitted; --emit-macros keeps them>");
    published
}

/// How many `#define` lines a dump printed.
fn define_lines(stdout: &str) -> usize {
    stdout
        .lines()
        .filter(|line| line.starts_with("#define "))
        .count()
}

/// The store entry for the artifact `variant`'s build wrote, keyed by its digest: the
/// reader's facts, or the reason it refused the artifact. `None` when the build wrote
/// nothing.
fn artifact_fact(variant: &Variant, workdir: &Path) -> Option<(String, report::FactEntry)> {
    let key = variant.build.as_ref()?.artifact_sha256.clone()?;
    let entry = match (variant.elf.as_ref(), variant.elf_error.as_ref()) {
        (Some(elf), _) => report::FactEntry::Elf {
            elf: Box::new(elf.clone()),
        },
        (None, Some(error)) => {
            let unnamed = match variant.artifact.as_deref() {
                Some(path) => error.why.replace(&path.display().to_string(), "<artifact>"),
                None => error.why.clone(),
            };
            report::FactEntry::Unreadable {
                error: publish_text(&unnamed, workdir),
                mach_o: error.mach_o,
            }
        }
        (None, None) => return None,
    };
    Some((key, entry))
}

/// The store entry for the dump `variant` read its macros from, keyed by the digest of
/// the dump's sorted lines ([`dump_key`]), or `None` where the macros came from the artifact's own
/// `.chard.report` (whose entry is the artifact's) or no dump was taken.
fn dump_fact(variant: &Variant) -> Option<(String, report::FactEntry)> {
    if variant.macro_source != "preprocessor" {
        return None;
    }
    let dump = variant.macro_dump.as_ref()?;
    Some((
        dump_key(dump),
        report::FactEntry::MacroDump {
            defines: define_lines(&dump.stdout),
            macros_filter: report::evidence_filters().macros.sha256,
            macros: relevant_macros(&variant.macros_preprocessor),
        },
    ))
}

/// Why a variant cannot answer the macro channel, or `None` when it can: the failed build's
/// exit status and the compiler's first line or, where the build ran, the dump's own failure,
/// in the order `Variant::sufficient_for` decides the verdict. The dump preprocesses the
/// build's own unit, so a unit the compiler cannot read fails both, and the build is the
/// subject. The one reading of the order for a control arm's `detail`
/// ([`unevaluable_reason`]) and the measured observation's `observed`.
fn macro_reason(variant: &Variant) -> Option<String> {
    build_failure_reason(variant).or_else(|| variant.macro_dump_failure())
}

fn build_failure_reason(variant: &Variant) -> Option<String> {
    variant
        .build
        .as_ref()
        .and_then(|b| b.failure(variant.workdir.as_deref()))
        .map(|ended| format!("the build {ended}"))
}

/// Why `variant` cannot answer `channel`, as one line, or `None` when it can: the `detail` a
/// control arm publishes when it could not be evaluated. A verdict alone (`build-failed`)
/// names the class and nothing a reader could act on; the exit status and the compiler's
/// first line make an unevaluable arm reproducible.
fn unevaluable_reason(variant: &Variant, channel: Channel) -> Option<String> {
    let withheld = variant.sufficient_for(channel).err()?;
    // Before the channels' own records: an unwitnessed arm is withheld on every channel,
    // and none of those records says why.
    if let Some(absence) = variant.unwitnessed.as_ref() {
        return Some(format!(
            "the arm's artifact {absence}, so chard cannot show {} and nothing was read \
             from it",
            absence.unshown()
        ));
    }
    let build_failure = || build_failure_reason(variant);
    let reason = match channel {
        // The build before the dump ([`macro_reason`]).
        Channel::Macro => macro_reason(variant),
        Channel::Runtime => variant.run_error.clone().or_else(build_failure),
        Channel::ElfStatic => variant
            .elf_error
            .as_ref()
            .map(|r| r.why.clone())
            .or_else(build_failure),
        Channel::CompilerDiag => build_failure(),
    };
    Some(reason.unwrap_or_else(|| {
        format!(
            "the arm could not be evaluated ({}) and left no record of why",
            withheld.as_str()
        )
    }))
}

/// The gating a known libc or compiler limitation may substitute for a `probe-invalid`.
fn known_limitation(
    verdict: Verdict,
    check: &Check,
    libc: &str,
    compiler: &str,
    positive: Option<probe::Outcome>,
) -> Option<report::Gating> {
    if verdict != Verdict::ProbeInvalid {
        return None;
    }
    report::libc_limitation(check, libc, positive)
        .or_else(|| report::compiler_limitation(check, compiler, positive))
}

/// What the declared family reads of the builds, one field per
/// [`report::gating_rule::Arm`], each filled from that build alone.
#[derive(Debug, Default)]
struct DeclaredReadings<'a> {
    positive: PositiveReading<'a>,
    negative: NegativeReading,
    /// The C++ standard library the profile-free build's macros name.
    clean: Option<&'a str>,
    /// The C++ standard library the measured build's macros name.
    measured: Option<&'a str>,
}

/// The positive control, as the declared family reads it.
#[derive(Debug, Default)]
struct PositiveReading<'a> {
    /// What the detector read of the arm, the one field `known_limitation` consults.
    outcome: Option<probe::Outcome>,
    /// The line of the arm's stderr saying the tool does not know, or declines, a flag of
    /// `Check::positive`.
    rejection: Option<String>,
    /// The line saying the linker took a `-z` keyword of `Check::positive` and ignored it.
    ignored_keyword: Option<String>,
    /// The line saying the tool does not know a flag of [`SCAFFOLDING_FLAGS`].
    scaffolding_rejection: Option<String>,
    /// The arm's predefined macros, empty when there is no arm to read them from.
    macros: Option<&'a BTreeMap<String, String>>,
    /// The arm compiled and not linked, as the check's own decoder read it, for a
    /// link-ANDed marking whose linked arm read `absent` (`report::LINK_ANDED_MARKINGS`).
    object: Option<report::ObjectMarking>,
    /// The arm's own run's stdout, where it ran: the probe's instrument lines, which
    /// `report::subobject_bound_lost_in_wrapper` and `report::machine_lacks_shadow_stack`
    /// read.
    stdout: Option<&'a str>,
    /// Whether the kernel executed the arm's artifact itself (`env::runs_natively`); `None`
    /// where no artifact was read, the kernel's family or byte order is unknown, or the
    /// artifact's record carries no byte order. Under qemu-user the emulator, not the
    /// machine, answers the probe's questions.
    native: Option<bool>,
    /// The arm's own run, where it ran, whose death `report::machine_lacks_pac` reads beside
    /// its stdout.
    run: Option<&'a crate::run::RunRecord>,
}

/// The negative control, as the declared family reads it: the line of its own build's
/// stderr saying the tool does not know a flag of `Check::negative`, and, from its run, what
/// the detector read, the C library's loader refusing to start it, and whether the kernel ran
/// it itself. Nothing when the clean build stood in, which was built with no control flag to
/// reject.
#[derive(Debug, Default)]
struct NegativeReading {
    rejection: Option<String>,
    /// What the detector read of the arm, which `report::loader_refuses_execstack` consults.
    outcome: Option<probe::Outcome>,
    /// The loader's refusal line of the arm's run, where it exited 127 saying so
    /// (`decode::runtime::loader_refusal`).
    refusal: Option<String>,
    /// As [`PositiveReading::native`], for this arm's artifact.
    native: Option<bool>,
}

impl<'a> DeclaredReadings<'a> {
    /// Each arm's field from that arm's build, as `run_check` built them. `positive` is
    /// the arm's build beside the control list it was built with (`Check::positive_for`
    /// the target), which is where a rejection in that arm is looked for.
    #[expect(clippy::too_many_arguments, reason = "the check and its controls")]
    fn read(
        check: &Check,
        controls: &report::Controls,
        (positive, positive_control): (&'a Variant, &[&str]),
        positive_object: Option<&Variant>,
        negative: Option<&Variant>,
        clean: &'a Variant,
        measured: &'a Variant,
        kernel: crate::env::NativeMachine<'_>,
    ) -> Self {
        // An arm whose artifact is set aside says nothing for the toolchain.
        if positive.unwitnessed.is_some() {
            return Self {
                positive: PositiveReading {
                    outcome: controls.positive.outcome,
                    ..PositiveReading::default()
                },
                negative: Self::negative_of(check, controls, negative, kernel),
                clean: probe::cxx_stdlib(evidence_for(clean).macros),
                measured: probe::cxx_stdlib(evidence_for(measured).macros),
            };
        }
        let positive_object = positive_object.filter(|object| object.unwitnessed.is_none());
        let positive_build = positive.build.as_ref();
        Self {
            positive: PositiveReading {
                outcome: controls.positive.outcome,
                rejection: positive_build.and_then(|b| control_flag_rejection(b, positive_control)),
                ignored_keyword: positive_build
                    .and_then(|b| z_keyword_rejection(b, positive_control)),
                scaffolding_rejection: positive_build
                    .and_then(|b| control_flag_rejection(b, SCAFFOLDING_FLAGS)),
                macros: Some(&positive.macros),
                object: positive_object.map(|object| {
                    let detection = reading(check, object).detection;
                    report::ObjectMarking {
                        outcome: detection.outcome,
                        observed: detection.observed,
                        sha256: object
                            .build
                            .as_ref()
                            .and_then(|b| b.artifact_sha256.clone()),
                    }
                }),
                stdout: positive.run.as_ref().map(|r| r.stdout.as_str()),
                run: positive.run.as_ref(),
                native: positive.elf.as_ref().and_then(|e| {
                    crate::env::runs_natively(kernel, &e.machine, e.elf_class, e.elf_data)
                }),
            },
            negative: Self::negative_of(check, controls, negative, kernel),
            clean: probe::cxx_stdlib(evidence_for(clean).macros),
            measured: probe::cxx_stdlib(evidence_for(measured).macros),
        }
    }

    /// The negative arm's reading, from its own build where it had one. An arm whose
    /// artifact is set aside hands over its outcome alone, for the reason
    /// [`Self::read`] gives for the positive arm.
    fn negative_of(
        check: &Check,
        controls: &report::Controls,
        negative: Option<&Variant>,
        kernel: crate::env::NativeMachine<'_>,
    ) -> NegativeReading {
        let read = negative.filter(|v| v.unwitnessed.is_none());
        NegativeReading {
            rejection: read
                .and_then(|v| v.build.as_ref())
                .and_then(|b| control_flag_rejection(b, check.negative)),
            outcome: negative.and(controls.negative.outcome),
            refusal: read
                .and_then(|v| v.run.as_ref())
                .and_then(crate::decode::runtime::loader_refusal)
                .map(str::to_owned),
            native: read.and_then(|v| v.elf.as_ref()).and_then(|e| {
                crate::env::runs_natively(kernel, &e.machine, e.elf_class, e.elf_data)
            }),
        }
    }
}

/// The declared family, in the order it is consulted; the first that fires is the
/// reason.
fn declared_gating(
    verdict: Verdict,
    probe: &Probe,
    check: &Check,
    libc: &str,
    compiler: &str,
    readings: &DeclaredReadings<'_>,
) -> Option<report::Gating> {
    let positive = &readings.positive;
    let no_macros = BTreeMap::new();
    known_limitation(verdict, check, libc, compiler, positive.outcome)
        // FreeBSD's gating names its cause beside the generic sentence, from the arm's own
        // self-report.
        .and_then(|gating| report::freebsd_gating(gating, check, positive.macros))
        .or_else(|| {
            unknown_flag_limitation(verdict, check, compiler, positive.rejection.as_deref())
        })
        .or_else(|| {
            unhardened_state_limitation(verdict, check, readings.negative.rejection.as_deref())
        })
        .or_else(|| linker_keyword_limitation(verdict, check, positive.ignored_keyword.as_deref()))
        .or_else(|| stdlib_limitation(verdict, check, readings.clean, readings.measured))
        .or_else(|| fortify_level_declined(verdict, check, positive.macros.unwrap_or(&no_macros)))
        .or_else(|| {
            scaffolding_limitation(
                verdict,
                probe,
                check,
                positive.scaffolding_rejection.as_deref(),
            )
        })
        .or_else(|| {
            (verdict == Verdict::ProbeInvalid)
                .then(|| {
                    report::link_drop_limitation(check, positive.outcome, positive.object.as_ref())
                })
                .flatten()
        })
        .or_else(|| {
            (verdict == Verdict::ProbeInvalid)
                .then(|| {
                    report::subobject_bound_lost_in_wrapper(
                        check,
                        positive.outcome,
                        positive.macros.unwrap_or(&no_macros),
                        positive.stdout,
                    )
                })
                .flatten()
        })
        .or_else(|| {
            (verdict == Verdict::ProbeInvalid)
                .then(|| {
                    report::machine_lacks_shadow_stack(
                        check,
                        positive.outcome,
                        positive.stdout,
                        positive.native,
                    )
                })
                .flatten()
        })
        .or_else(|| {
            (verdict == Verdict::ProbeInvalid)
                .then(|| {
                    let (outcome, stdout, native) =
                        (positive.outcome, positive.stdout, positive.native);
                    report::machine_lacks_bti(check, outcome, stdout, native)
                        .or_else(|| report::machine_lacks_pac(check, outcome, positive.run, native))
                })
                .flatten()
        })
        .or_else(|| {
            (verdict == Verdict::ProbeInvalid)
                .then(|| {
                    report::opt_in_not_honoured(
                        check,
                        positive.outcome,
                        positive.stdout,
                        positive.native,
                        libc,
                    )
                })
                .flatten()
        })
        .or_else(|| {
            let negative = &readings.negative;
            (verdict == Verdict::ProbeInvalid)
                .then(|| {
                    report::loader_refuses_execstack(
                        check,
                        negative.outcome,
                        negative.refusal.as_deref(),
                        negative.native,
                    )
                })
                .flatten()
        })
}

/// Which build a check's own observable is read from.
fn subject_variant<'a>(check: &Check, clean: &'a Variant, measured: &'a Variant) -> &'a Variant {
    if check.measures_toolchain_default {
        clean
    } else {
        measured
    }
}

/// The reading a variant gives `check`: its decoder's, through [`Check::decode`], with the
/// cut gate a code decoder needs applied after it.
fn reading(check: &Check, variant: &Variant) -> probe::Decoding {
    let decoding = check.decode(&evidence_for(variant));
    if check.predicate().is_some() {
        return decoding;
    }
    probe::Decoding {
        detection: withhold_unreadable(check, variant, decoding.detection),
        proof: decoding.proof,
    }
}

/// The reading `proof` as the report publishes it, over the store keys of `variant`'s
/// facts: `None` for a code decoder, or where the variant names no key the reading's
/// sources are stored under, which `decoded-reading-disagrees-with-facts` then names.
fn decoded(
    check: &Check,
    variant: &Variant,
    proof: Option<&crate::predicate::Evaluation>,
) -> Option<report::Decoded> {
    let predicate = check.predicate()?;
    let proof = proof?;
    let artifact = || variant.build.as_ref()?.artifact_sha256.clone();
    let (facts, macros) = match check.channel() {
        Channel::Macro => (macro_key(variant)?, None),
        Channel::ElfStatic => (
            artifact()?,
            crate::predicate::needs_macros(predicate)
                .then(|| macro_key(variant))
                .flatten(),
        ),
        Channel::Runtime | Channel::CompilerDiag => return None,
    };
    Some(report::Decoded {
        facts,
        macros,
        clause: proof.clause.clone(),
        outcome: proof.outcome,
        level: proof.level.clone(),
    })
}

/// The store key of the macro map `variant` was read with: its artifact's digest where
/// the map is the artifact's `.chard.report`, the digest of its dump's sorted lines where
/// the map is the dump's ([`dump_fact`]).
fn macro_key(variant: &Variant) -> Option<String> {
    if variant.macro_source == "compiled-artifact" {
        return variant.build.as_ref()?.artifact_sha256.clone();
    }
    let dump = variant.macro_dump.as_ref()?;
    Some(dump_key(dump))
}

/// The key a dump record is published and stored under: [`compile::dump_digest`] over its
/// output, chosen here once for the three places that need it (the published record, the
/// store entry and a reading's macro key).
fn dump_key(record: &compile::BuildRecord) -> String {
    compile::dump_digest(&record.stdout)
}

/// A code decoder's detection, or the indeterminate one that replaces it where the
/// variant's artifact was cut on a table the check reads, or where a runtime check's run
/// output was cut, unreadable or ended by chard's deadline, for the reason
/// [`runner::RunRecord::stream_cut`] gives.
fn withhold_unreadable(check: &Check, variant: &Variant, detection: Detection) -> Detection {
    match report::truncated_reading(check, variant.elf.as_ref())
        .or_else(|| report::cut_stream_reading(check, variant.run.as_ref()))
    {
        None => detection,
        // The detector's rule does not survive the cut: the reading is now the cut's, and
        // the run gate names its own rule over it.
        Some(why) => Detection {
            outcome: probe::Outcome::Indeterminate,
            level: None,
            observed: format!("{why}; the detector read: {}", detection.observed),
            rule: None,
        },
    }
}

/// The five gates on the artifact the detector read, in the order that keeps them apart:
/// truncation, slim LTO, self-report (over an artifact the reader parsed;
/// `settle_self_report_unread` takes one it did not), link mode (an executable link whose
/// artifact classifies as a shared object, read against `link_mode` and `read`, the
/// fields this reading rested on), and the precondition.
fn artifact_gating(
    verdict: Verdict,
    check: &Check,
    link_mode: probe::LinkMode,
    reading: probe::Outcome,
    elf: Option<&elf::ElfFacts>,
    read: &BTreeSet<crate::predicate::ElfField>,
) -> Option<(Verdict, report::Gating)> {
    if verdict == Verdict::Unsupported {
        return None;
    }
    if let Some(gating) = report::truncation_limitation(check, elf) {
        return (verdict != Verdict::ProbeInvalid).then_some((gating.rule.verdict(), gating));
    }
    // A precondition read over a slim LTO object, which has no generated code, would rule
    // on facts the final link has not produced yet.
    if let Some(gating) = report::lto_ir_limitation(check, elf) {
        return (verdict != Verdict::ProbeInvalid).then_some((gating.rule.verdict(), gating));
    }
    // A macro-channel reading over an artifact that carries no readable `.chard.report`
    // is the dump's.
    if let Some(gating) = report::self_report_limitation(check, elf) {
        return (verdict != Verdict::ProbeInvalid).then_some((gating.rule.verdict(), gating));
    }
    // Whatever the reading: the `relative-relocs` and `nodlopen` rows read the same
    // classification.
    if let Some(gating) = report::link_mode_limitation(check, link_mode, elf, read) {
        return (verdict != Verdict::ProbeInvalid).then_some((gating.rule.verdict(), gating));
    }
    report::artifact_limitation(verdict, check, reading, elf)
        .map(|gating| (gating.rule.verdict(), gating))
}

/// The linker selection each side's link line consulted, as `Toolchain::link_with`
/// published it: `c` is `toolchain.linker.profile_flags`, and `cxx` is
/// `toolchain.linker.cxx.profile_flags` when the C++ probes are held to a linker of their
/// own, `None` when they are held to the one linker beside every other probe.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkSelections<'a> {
    pub c: &'a [String],
    pub cxx: Option<&'a [String]>,
}

/// The artifacts the observations carry facts for, as the witnesses
/// `toolchain::artifact_agreement` holds the linker to: the C++ probes' apart when
/// `selections.cxx` is present, every other probe's first.
pub fn artifact_comments(
    observations: &[Observation],
    facts: &report::FactStore,
    profile_is_clean: bool,
    selections: LinkSelections<'_>,
) -> (toolchain::Witnesses, toolchain::Witnesses) {
    let split_cxx = selections.cxx.is_some();
    let mut c = toolchain::Witnesses {
        selection: selections.c.to_vec(),
        ..toolchain::Witnesses::default()
    };
    let mut cxx = toolchain::Witnesses {
        selection: selections.cxx.into_iter().flatten().cloned().collect(),
        ..toolchain::Witnesses::default()
    };
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut with_facts: BTreeSet<&str> = BTreeSet::new();
    let cxx_probe = |id: &str| split_cxx && probe::find(id).is_some_and(|p| p.lang == Lang::Cxx);
    for o in observations {
        let (Some(elf), Some(sha)) = (
            facts.measured_elf_of(o),
            o.build.as_ref().and_then(|b| b.artifact_sha256.as_deref()),
        ) else {
            continue;
        };
        with_facts.insert(o.probe.as_str());
        if !seen.insert(sha) {
            continue;
        }
        let probe = probe::find(&o.probe);
        let check = probe.and_then(|p| p.checks.iter().find(|c| c.id == o.check));
        let reads_clean = check.is_some_and(|c| c.measures_toolchain_default);
        let variant = if profile_is_clean || reads_clean {
            "clean"
        } else {
            "measured"
        };
        let short: String = sha.chars().take(16).collect();
        let side = if cxx_probe(&o.probe) {
            &mut cxx
        } else {
            &mut c
        };
        // The clean build carries the `-B` and `--prefix` prefixes with the runtime
        // selection, so only a program flag it lacks makes its link the default's.
        let selects = !toolchain::linker_program_flags(&side.selection).is_empty();
        side.artifacts.push(toolchain::ArtifactComment {
            label: format!("{}-{variant} sha256:{short}", o.probe),
            lines: elf.comment.clone(),
            unread: elf.comment_truncation().map(ToOwned::to_owned),
            relocatable: elf.pie.is_none()
                || probe.is_some_and(|p| p.link_mode == probe::LinkMode::Object),
            profile_free: reads_clean && selects,
        });
    }
    let mut named: BTreeSet<&str> = BTreeSet::new();
    for o in observations {
        if with_facts.contains(o.probe.as_str()) || !named.insert(o.probe.as_str()) {
            continue;
        }
        let side = if cxx_probe(&o.probe) {
            &mut cxx
        } else {
            &mut c
        };
        side.without_facts.push(o.probe.clone());
    }
    c.without_facts.sort();
    cxx.without_facts.sort();
    (c, cxx)
}

/// The gating a toolchain with no way to turn the mechanism *off* earns: the verdict is
/// withheld as `indeterminate`, because the triple had no absent arm.
fn unhardened_state_limitation(
    verdict: Verdict,
    check: &Check,
    rejection: Option<&str>,
) -> Option<report::Gating> {
    if verdict != Verdict::ProbeInvalid {
        return None;
    }
    let rejection = rejection.filter(|line| !rejection_is_a_refusal(line))?;
    Some(report::Gating {
        rule: report::gating_rule::NO_UNHARDENED_STATE,
        arch: None,
        libc: None,
        needs_vm: check.gate.needs_vm,
        reason: format!(
            "{} was measured against a negative control this toolchain rejected as an \
             option it does not know, so the unhardened state could not be built and the \
             verdict is withheld. The tool said: {rejection}",
            check.flag
        ),
    })
}

/// The gating a linker earns by accepting a keyword it does not implement.
fn linker_keyword_limitation(
    verdict: Verdict,
    check: &Check,
    rejection: Option<&str>,
) -> Option<report::Gating> {
    if verdict != Verdict::ProbeInvalid {
        return None;
    }
    let rejection = rejection?;
    Some(report::Gating {
        rule: report::gating_rule::LINKER_KEYWORD_IGNORED,
        arch: None,
        libc: None,
        needs_vm: check.gate.needs_vm,
        reason: format!(
            "{} was forced on and the linker took the keyword, said it was ignoring it, and \
             linked anyway, so the linker lacks the mechanism. The linker said: {rejection}",
            check.flag
        ),
    })
}

/// The gating the C library earns by settling a fortify request below what was asked.
fn fortify_level_declined(
    verdict: Verdict,
    check: &Check,
    macros: &BTreeMap<String, String>,
) -> Option<report::Gating> {
    if verdict != Verdict::ProbeInvalid {
        return None;
    }
    // The level this check's own control asked for, from the control itself.
    let requested: u32 = check
        .positive
        .iter()
        .find_map(|f| f.strip_prefix("-D_FORTIFY_SOURCE="))
        .and_then(|n| n.parse().ok())?;
    let arrived: u32 = macros.get("_FORTIFY_SOURCE")?.parse().ok()?;
    let settled: u32 = macros.get("__USE_FORTIFY_LEVEL")?.parse().ok()?;
    if arrived != requested || settled >= requested || macros.get("__OPTIMIZE__")? != "1" {
        return None;
    }
    Some(report::Gating {
        rule: report::gating_rule::FORTIFY_LEVEL_DECLINED,
        arch: None,
        libc: None,
        needs_vm: check.gate.needs_vm,
        reason: format!(
            "{} was forced on and arrived: the positive control's own artifact reports `_FORTIFY_SOURCE={arrived}`, and the C library settled it at `__USE_FORTIFY_LEVEL={settled}`, below the level this check asserts.",
            check.flag
        ),
    })
}

/// The gating a C++ standard library earns by keeping its assertions somewhere else: the
/// check is `not-applicable`, since its observable belongs to the other implementation.
fn stdlib_limitation(
    verdict: Verdict,
    check: &Check,
    clean: Option<&str>,
    measured: Option<&str>,
) -> Option<report::Gating> {
    if verdict != Verdict::ProbeInvalid {
        return None;
    }
    let stdlib = clean?;
    if measured != Some(stdlib) || !check.gate.cxx_stdlib_unsupported.contains(&stdlib) {
        return None;
    }
    Some(report::Gating {
        rule: report::gating_rule::STDLIB_LACKS_OBSERVABLE,
        arch: None,
        libc: None,
        needs_vm: check.gate.needs_vm,
        reason: format!(
            "{} is read through an observable {stdlib} does not have, and {stdlib} is the standard library of the measured build and the controls alike.",
            check.flag
        ),
    })
}

/// The gating a probe's own scaffolding may earn when the platform cannot build it: the
/// verdict is withheld as `indeterminate`, since the question was never posed.
fn scaffolding_limitation(
    verdict: Verdict,
    probe: &Probe,
    check: &Check,
    rejection: Option<&str>,
) -> Option<report::Gating> {
    if verdict != Verdict::ProbeInvalid || probe.aux_libs.is_empty() {
        return None;
    }
    let rejection = rejection.filter(|line| !rejection_is_a_refusal(line))?;
    Some(report::Gating {
        rule: report::gating_rule::SCAFFOLDING,
        arch: None,
        libc: None,
        needs_vm: check.gate.needs_vm,
        reason: format!(
            "{} is measured through a chain of shared libraries, and this toolchain rejected \
             the flags that build the chain, so the verdict is withheld. The linker said: \
             {rejection}",
            check.flag
        ),
    })
}

/// The gating a compiler's own "I do not know that flag" may substitute for a `probe-invalid`.
fn unknown_flag_limitation(
    verdict: Verdict,
    check: &Check,
    compiler: &str,
    rejection: Option<&str>,
) -> Option<report::Gating> {
    if verdict != Verdict::ProbeInvalid {
        return None;
    }
    let rejection = rejection?;
    if rejection_is_a_refusal(rejection) {
        return Some(report::Gating {
            rule: report::gating_rule::FLAG_REFUSED,
            arch: None,
            libc: None,
            needs_vm: check.gate.needs_vm,
            reason: format!(
                "{} was forced on and {compiler} refused to enable it, so the triple could \
                 not discriminate. The flag sits behind an opt-in the guide does not ask \
                 for. The driver said: {rejection}",
                check.flag
            ),
        });
    }
    Some(report::Gating {
        rule: report::gating_rule::FLAG_UNKNOWN,
        arch: None,
        libc: None,
        needs_vm: check.gate.needs_vm,
        reason: format!(
            "{} was forced on and {compiler} does not know it, so the triple could not \
             discriminate. This is a limit of the compiler, not of the probe. The driver \
             said: {rejection}",
            check.flag
        ),
    })
}

/// The words a probe's macro dump runs under: the words of the build's compile, in the
/// build's order.
fn dump_words(link_mode: probe::LinkMode, kept: &[String], witnessed: bool) -> Vec<String> {
    let (mut words, _) = probe::LinkMode::Object.partition_flags(kept);
    words.extend(
        link_mode
            .compile_flags(kept)
            .iter()
            .map(|s| (*s).to_owned()),
    );
    if witnessed {
        words.extend(compile::RunWitness::compile_words());
    }
    words
}

/// Where the linker must look to *follow* a probe's own dependency chain.
fn chain_search_flags(probe: &Probe, workdir: &Path) -> Vec<String> {
    if probe.aux_libs.is_empty() {
        return Vec::new();
    }
    vec![
        format!("-L{}", workdir.display()),
        format!("-Wl,-rpath-link,{}", workdir.display()),
    ]
}

/// The flags a link in a probe's own dependency chain is built with: the arm's target
/// selection, runtime selection, header selection and linker selection, then the fixed
/// scaffolding.
fn aux_lib_flags(arm: &[String], stem: &str, workdir: &Path) -> Vec<String> {
    let mut flags = toolchain::target_selecting_flags(arm);
    flags.extend(toolchain::runtime_selecting_flags(arm));
    flags.extend(toolchain::header_selecting_flags(arm));
    flags.extend(toolchain::linker_program_flags(arm));
    flags.extend([
        "-shared".to_owned(),
        "-fPIC".to_owned(),
        format!("-Wl,-soname,lib{stem}.so"),
        format!("-L{}", workdir.display()),
        format!("-Wl,-rpath-link,{}", workdir.display()),
    ]);
    flags
}

/// Did a link in the probe's own dependency chain fail to produce something usable?
fn aux_build_failed(record: &compile::BuildRecord) -> bool {
    !record.succeeded() || record.artifact_sha256.is_none()
}

/// The flags `build_aux_libs` supplies itself, which `scaffolding-unbuildable` recognises
/// the linker refusing.
pub const SCAFFOLDING_FLAGS: &[&str] = &["-soname", "-rpath-link", "-shared", "-fPIC"];

/// The `-z` keywords a flag list supplies to the linker.
fn z_keywords<'a>(flags: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    for flag in flags {
        let mut pieces = flag.split(',');
        while let Some(piece) = pieces.next() {
            if piece == "-z" {
                out.extend(pieces.next());
            }
        }
    }
    out
}

/// The linker's own sentence saying it took a `-z` keyword and ignored it, on a line that
/// names a keyword *this check's own control supplied*.
pub fn z_keyword_rejection(build: &compile::BuildRecord, flags: &[&str]) -> Option<String> {
    let supplied = z_keywords(flags);
    build.stderr.lines().find_map(|line| {
        let lower = line.to_lowercase();
        let ignored = lower.contains("ignored") || lower.contains("unknown -z value");
        (ignored && supplied.iter().any(|k| line.contains(k))).then(|| line.trim().to_owned())
    })
}

/// Every spelling a tool may name `flag` by: as written, and, where the driver hands it
/// on, the pieces the linker sees (lld names `-Wl,--copy-dt-needed-entries` as
/// `--copy-dt-needed-entries`). Shared by [`profile_flag_rejection`] and
/// [`control_flag_rejection`], so neither compares the driver's spelling against the
/// linker's.
fn spellings(flag: &str) -> impl Iterator<Item = &str> {
    std::iter::once(flag).chain(
        flag.strip_prefix("-Wl,")
            .into_iter()
            .flat_map(|rest| rest.split(',')),
    )
}

/// Did the toolchain reject a flag the *profile* supplied, rather than one this check owns?
pub fn profile_flag_rejection(build: &compile::BuildRecord, profile: &Profile) -> Option<String> {
    profile_flag_refusal(build, profile).map(|refusal| refusal.sentence)
}

/// A profile flag the toolchain refused, as [`profile_flag_rejection`] reads it, with the
/// line it was refused on, the tool and the flags kept apart from the sentence that names
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRefusal {
    /// The published `build_rejection`: the tool, the flags, and the line.
    pub sentence: String,
    /// The line alone, for a reason that quotes it without the attribution.
    pub line: String,
    /// The tool the line names (`cc1`, `/usr/bin/ld`, `clang`), or `the toolchain` where
    /// the line opens with no tool.
    pub tool: String,
    /// The profile flags the line names, as the tool spelled them, sorted and distinct:
    /// `--no-such-option` for a profile's `-Wl,--no-such-option`, which the linker names
    /// without the driver's prefix.
    pub flags: Vec<String>,
}

/// Every spelling of every flag the profile supplies that a tool could name.
fn profile_spellings(profile: &Profile) -> BTreeSet<&str> {
    profile
        .cflags
        .iter()
        .chain(profile.cxxflags.iter())
        .chain(profile.ldflags.iter())
        .flat_map(|flag| spellings(flag.as_str()))
        .filter(|token| token.starts_with('-'))
        .collect()
}

/// One profile flag a tool refused in a build, on the first line that refused it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlagRefusal {
    /// As [`ProfileRefusal::tool`].
    pub tool: String,
    /// One flag, as the tool spelled it.
    pub flag: String,
    /// The line, trimmed.
    pub line: String,
}

/// Every profile flag a build's tools refused, each tool and flag once, on the first line
/// that refused it, in the order of the build's stderr.
#[must_use]
pub fn profile_flag_refusals(build: &compile::BuildRecord, profile: &Profile) -> Vec<FlagRefusal> {
    let supplied = profile_spellings(profile);
    let mut out: Vec<FlagRefusal> = Vec::new();
    for (rejected, tool, line) in flag_rejections(build, &supplied, Lines::Refusals) {
        for flag in rejected {
            if !out.iter().any(|r| r.tool == tool && r.flag == flag) {
                out.push(FlagRefusal {
                    tool: tool.to_owned(),
                    flag: flag.to_owned(),
                    line: line.to_owned(),
                });
            }
        }
    }
    out
}

/// [`profile_flag_rejection`], with the refused line kept apart.
pub fn profile_flag_refusal(
    build: &compile::BuildRecord,
    profile: &Profile,
) -> Option<ProfileRefusal> {
    let supplied = profile_spellings(profile);
    flag_rejection(build, &supplied, Lines::Refusals).map(|(rejected, tool, line)| ProfileRefusal {
        sentence: format!(
            "{tool} rejected {}, supplied by the profile not by this check: {line}",
            rejected.join(" ")
        ),
        line: line.to_owned(),
        tool: tool.to_owned(),
        flags: rejected.iter().map(|flag| (*flag).to_owned()).collect(),
    })
}

/// Did the toolchain reject a flag *this check's own control* supplied?
pub fn control_flag_rejection(build: &compile::BuildRecord, flags: &[&str]) -> Option<String> {
    let supplied: BTreeSet<&str> = flags
        .iter()
        .copied()
        .flat_map(spellings)
        .filter(|token| token.starts_with('-'))
        .collect();
    flag_rejection(build, &supplied, Lines::Any).map(|(rejected, tool, line)| {
        format!("{tool} does not know {}: {line}", rejected.join(" "))
    })
}

/// Which rejection lines a reader counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lines {
    /// Every line that names a flag with a rejection phrase, a warning or a note among them.
    Any,
    /// Only a line the tool stopped on: not a `warning:` or `note:` line.
    Refusals,
}

/// Whether `line` carries a `warning` or `note` severity in its leading `tool: severity:`
/// prefixes, as a driver, a front end (`cc1:`) or a linker prints them.
fn line_is_a_warning_or_note(line: &str) -> bool {
    line.splitn(4, ':')
        .take(3)
        .map(str::trim)
        .any(|head| head.eq_ignore_ascii_case("warning") || head.eq_ignore_ascii_case("note"))
}

/// The phrases that mean a driver knows the flag and declines to enable it, as opposed to
/// never having heard of it.
const REFUSED_PHRASES: [&str; 1] = ["hasn't been enabled"];

/// Whether a rejection line is a refusal to enable rather than an unknown flag.
pub fn rejection_is_a_refusal(line: &str) -> bool {
    let lowered = line.to_lowercase();
    REFUSED_PHRASES.iter().any(|p| lowered.contains(p))
}

/// The shared half of both rejection rules: the first line that says "I do not know this"
/// *and* names one of `supplied`, as the rejected flags (sorted and distinct), the tool
/// that said so, and the line. One copy, so the phrase list has one chance to miss a
/// spelling, not two.
fn flag_rejection<'a>(
    build: &'a compile::BuildRecord,
    supplied: &BTreeSet<&str>,
    lines: Lines,
) -> Option<(Vec<&'a str>, &'a str, &'a str)> {
    flag_rejections(build, supplied, lines).into_iter().next()
}

/// Every line [`flag_rejection`] would accept, in stderr order: the rejected flags, the
/// tool and the line of each.
fn flag_rejections<'a>(
    build: &'a compile::BuildRecord,
    supplied: &BTreeSet<&str>,
    lines: Lines,
) -> Vec<(Vec<&'a str>, &'a str, &'a str)> {
    // Every spelling a driver or linker uses to say it does not know a flag.
    const PHRASES: [&str; 8] = [
        "unknown option",
        "unknown warning option",
        "unrecognized option",
        "unrecognized command line option",
        "unrecognized command-line option",
        "unknown argument",
        "unsupported option",
        "hasn't been enabled",
    ];

    let mut out = Vec::new();
    for line in build.stderr.lines() {
        let lowered = line.to_lowercase();
        if !PHRASES.iter().any(|p| lowered.contains(p)) {
            continue;
        }
        if lines == Lines::Refusals && line_is_a_warning_or_note(line) {
            continue;
        }
        // The flag a tool rejects comes before its suggestion, and the suggestion is a flag
        // the tool *does* know (clang's `did you mean '-Wbar'?`), so only the text before it
        // names a rejected flag.
        let named = line.split("did you mean").next().unwrap_or(line);
        let mut rejected: Vec<&str> = named
            .split_whitespace()
            // Typographic quotes as well as ASCII: gcc quotes the offending flag with
            // U+2018/U+2019 when the locale allows, so a token trimmed of `'` alone stays
            // `\u{2018}-fstrict-flex-arrays=3\u{2019}` and matches nothing the profile supplied.
            .map(|t| {
                t.trim_matches(|c: char| {
                    matches!(
                        c,
                        '\'' | '"'
                            | ','
                            | '`'
                            | '\u{2018}'
                            | '\u{2019}'
                            | '\u{201c}'
                            | '\u{201d}'
                            // Sentence punctuation, because a driver may keep talking after
                            // naming the flag (clang's `'-Wtrampolines'; did you mean`).
                            | ';'
                            | '?'
                            | '.'
                            | '!'
                    )
                })
            })
            .filter(|t| supplied.contains(t))
            .collect();
        rejected.sort_unstable();
        rejected.dedup();
        if rejected.is_empty() {
            continue;
        }
        // The tool's own name, when the line opens with one, so the reader knows whether to
        // look at the compiler driver or the linker.
        let tool = line
            .split_once(':')
            .map(|(head, _)| head.trim())
            .filter(|head| {
                !head.is_empty()
                    && !head.contains(char::is_whitespace)
                    && !matches!(*head, "warning" | "error" | "note")
            })
            .unwrap_or("the toolchain");
        out.push((rejected, tool, line.trim()));
    }
    out
}

/// The prefix of the file a `measure` run keeps in its work directory while it uses it.
pub const WORKDIR_CLAIM_PREFIX: &str = ".chard-measure.";

/// A work directory this process holds. Dropping it removes the claim file.
#[derive(Debug)]
pub struct WorkdirClaim {
    path: std::path::PathBuf,
}

impl WorkdirClaim {
    /// The claim file,
    /// `<workdir>/.chard-measure.<boot>.<pid namespace>.<time namespace>.<pid>.<start>`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Confirm this run still holds its work directory, before anything is published.
    ///
    /// # Errors
    ///
    /// [`crate::error::TransientError`] where the claim is gone, and the io error where it
    /// cannot be looked at.
    pub fn confirm(&self) -> Result<()> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => Ok(()),
            Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => {
                Err(crate::error::TransientError(format!(
                    "this run's claim on its work directory, {}, was removed while it measured",
                    self.path.display()
                ))
                .into())
            }
            Err(unread) => Err(anyhow::Error::new(unread)
                .context(crate::error::HarnessPath(self.path.clone()))
                .context("confirming the claim on the work directory")),
        }
    }
}

impl Drop for WorkdirClaim {
    fn drop(&mut self) {
        // A claim that cannot be removed is judged by the next run, through its process.
        if let Err(stuck) = std::fs::remove_file(&self.path)
            && stuck.kind() != std::io::ErrorKind::NotFound
        {
            crate::error::note(&format!(
                "the work directory claim {} could not be removed ({stuck})",
                self.path.display()
            ));
        }
    }
}

/// Who made a claim: the boot it was made under, the pid and time namespaces, the process
/// id and the process's start time in clock ticks after boot. A part this system's `/proc`
/// does not give is `-`, and a claim with one is never judged gone.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimHolder {
    boot: String,
    namespace: String,
    clock: String,
    pid: u32,
    started: String,
}

/// The inode in a `/proc/self/ns/<kind>` link, `<kind>:[<inode>]`.
fn namespace_inode(kind: &str) -> std::io::Result<Option<String>> {
    let link = std::fs::read_link(format!("/proc/self/ns/{kind}"))?;
    Ok(link.to_str().and_then(|l| {
        l.strip_prefix(kind)?
            .strip_prefix(":[")?
            .strip_suffix(']')
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .map(ToOwned::to_owned)
    }))
}

impl ClaimHolder {
    fn this_process() -> Self {
        let pid = std::process::id();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
            .unwrap_or_else(|| "-".to_owned());
        let namespace = namespace_inode("pid")
            .ok()
            .flatten()
            .unwrap_or_else(|| "-".to_owned());
        // A kernel without time namespaces has no link, and every process reads one clock.
        let clock = match namespace_inode("time") {
            Ok(Some(inode)) => inode,
            Err(absent) if absent.kind() == std::io::ErrorKind::NotFound => "none".to_owned(),
            _ => "-".to_owned(),
        };
        // A pid namespace mounted over its parent's `/proc` (`unshare -p -f` with no
        // `--mount-proc`) names other processes under this process's id; `/proc/self` then
        // names a pid that is not this one, and nothing read through `/proc` is this
        // process's.
        let own_proc = proc_self_is(&std::fs::read_link("/proc/self"), pid);
        let started = own_proc
            .then(|| std::fs::read_to_string(format!("/proc/{pid}/stat")).ok())
            .flatten()
            .and_then(|stat| stat_start_time(&stat))
            .unwrap_or_else(|| "-".to_owned());
        Self {
            boot,
            namespace,
            clock,
            pid,
            started,
        }
    }

    fn known(&self) -> bool {
        [&self.boot, &self.namespace, &self.clock, &self.started]
            .iter()
            .all(|part| *part != "-")
    }

    fn file_name(&self) -> String {
        format!(
            "{WORKDIR_CLAIM_PREFIX}{}.{}.{}.{}.{}",
            self.boot, self.namespace, self.clock, self.pid, self.started
        )
    }

    /// The holder a claim file's name records, from the part after the prefix.
    fn parse(rest: &str) -> Option<Self> {
        let parts: Vec<&str> = rest.split('.').collect();
        let [boot, namespace, clock, pid, started] = parts[..] else {
            return None;
        };
        if [boot, namespace, clock, started]
            .iter()
            .any(|p| p.is_empty())
        {
            return None;
        }
        Some(Self {
            boot: boot.to_owned(),
            namespace: namespace.to_owned(),
            clock: clock.to_owned(),
            pid: pid.parse().ok()?,
            started: started.to_owned(),
        })
    }
}

/// Whether `/proc/self` (`link`, as read) names this process's own pid.
fn proc_self_is(link: &std::io::Result<std::path::PathBuf>, pid: u32) -> bool {
    link.as_ref()
        .is_ok_and(|link| link.as_os_str() == pid.to_string().as_str())
}

/// Field 3 of a `/proc/<pid>/stat` line, the process's state, read after the last `)`.
fn stat_state(stat: &str) -> Option<char> {
    let (_, after_name) = stat.rsplit_once(')')?;
    let state = after_name.split_whitespace().next()?;
    let mut chars = state.chars();
    let first = chars.next()?;
    chars.next().is_none().then_some(first)
}

/// Field 22 of a `/proc/<pid>/stat` line, the process's start time. Read after the last
/// `)`, since the command name in field 2 may hold spaces and parentheses.
fn stat_start_time(stat: &str) -> Option<String> {
    let (_, after_name) = stat.rsplit_once(')')?;
    // Fields 3 onwards follow the name, so field 22 is the twentieth of them.
    after_name
        .split_whitespace()
        .nth(19)
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
        .map(ToOwned::to_owned)
}

/// What another run's claim says about the work directory.
#[derive(Debug, PartialEq, Eq)]
enum ClaimStanding {
    /// Its process is gone, or its pid now names a process started at another time.
    Gone,
    /// Its process is alive.
    Live(u32),
    /// This system cannot tell, for the reason given.
    Unjudged(&'static str),
}

/// The standing of another run's claim, from its owner (`None` where it could not be
/// read), the holder its name records (`None` where it records none) and this process.
fn judge_claim(
    owner: Option<u32>,
    own_uid: u32,
    other: Option<&ClaimHolder>,
    own: &ClaimHolder,
) -> ClaimStanding {
    match owner {
        Some(uid) if uid == own_uid => {}
        Some(_) => {
            return ClaimStanding::Unjudged(
                "another user made it, and this /proc may hide that user's processes",
            );
        }
        None => return ClaimStanding::Unjudged("its owner could not be read"),
    }
    let Some(other) = other else {
        return ClaimStanding::Unjudged("its name is not one chard writes");
    };
    if !own.known() {
        return ClaimStanding::Unjudged(
            "this system's /proc does not say which processes are alive",
        );
    }
    if other.boot != own.boot {
        return ClaimStanding::Unjudged("it was made under another boot");
    }
    if other.namespace != own.namespace {
        return ClaimStanding::Unjudged(
            "it was made in another pid namespace, such as a container sharing the directory",
        );
    }
    if other.clock != own.clock {
        return ClaimStanding::Unjudged("it was made in another time namespace");
    }
    standing_from_stat(
        &std::fs::read_to_string(format!("/proc/{}/stat", other.pid)),
        other,
    )
}

/// The standing `/proc/<pid>/stat` (`stat`, as read) gives a claim this system can judge.
fn standing_from_stat(stat: &std::io::Result<String>, other: &ClaimHolder) -> ClaimStanding {
    let stat = match stat {
        Ok(stat) => stat,
        Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => return ClaimStanding::Gone,
        Err(_) => return ClaimStanding::Unjudged("its process's /proc entry could not be read"),
    };
    match (stat_state(stat), stat_start_time(stat)) {
        (Some('Z' | 'X'), Some(_)) => ClaimStanding::Gone,
        (Some(_), Some(started)) if started == other.started => ClaimStanding::Live(other.pid),
        (Some(_), Some(_)) => ClaimStanding::Gone,
        _ => ClaimStanding::Unjudged("its process's /proc entry could not be parsed"),
    }
}

/// Claim `workdir` for this run, or refuse it because another run holds it.
///
/// # Errors
///
/// [`crate::error::TransientError`] for a live holder, [`UserError`] for a claim this
/// system cannot judge, and the io error where the claim cannot be made or the directory
/// cannot be listed.
pub fn claim_workdir(workdir: &Path) -> Result<WorkdirClaim> {
    use std::os::unix::fs::MetadataExt as _;

    let own = ClaimHolder::this_process();
    let name = own.file_name();
    let path = workdir.join(&name);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(_) => {}
        // A claim under this process's own name: with a known identity only this process
        // made it, so it is live; without one, a gone process with this pid may have.
        Err(taken) if taken.kind() == std::io::ErrorKind::AlreadyExists => {
            let holder = if own.known() {
                Ok(own.pid)
            } else {
                Err("this system's /proc does not say which processes are alive")
            };
            return Err(claim_refusal(workdir, &path, holder));
        }
        // The claim is chard's own file, so it is tagged as one: `error::classify` reads the
        // tag before the io kind.
        Err(refused) => {
            return Err(anyhow::Error::new(refused)
                .context(crate::error::HarnessPath(path))
                .context(format!("claiming the work directory {}", workdir.display())));
        }
    }
    let claim = WorkdirClaim { path };
    let own_uid = std::fs::symlink_metadata(&claim.path)
        .with_context(|| format!("reading the claim {}", claim.path.display()))?
        .uid();
    let mut live = None;
    let mut unjudged = None;
    let entries = std::fs::read_dir(workdir)
        .with_context(|| format!("listing the work directory {}", workdir.display()))?;
    for entry in entries {
        let entry =
            entry.with_context(|| format!("listing the work directory {}", workdir.display()))?;
        let other = entry.file_name();
        if other.as_encoded_bytes() == name.as_bytes() {
            continue;
        }
        let Some(rest) = other
            .as_encoded_bytes()
            .strip_prefix(WORKDIR_CLAIM_PREFIX.as_bytes())
        else {
            continue;
        };
        let holder = std::str::from_utf8(rest).ok().and_then(ClaimHolder::parse);
        let owner = entry.metadata().ok().map(|m| m.uid());
        match judge_claim(owner, own_uid, holder.as_ref(), &own) {
            ClaimStanding::Gone => match std::fs::remove_file(entry.path()) {
                Ok(()) => crate::error::note(&format!(
                    "removed {}, a claim left by a run whose process is gone",
                    entry.path().display()
                )),
                Err(stuck) if stuck.kind() != std::io::ErrorKind::NotFound => {
                    crate::error::note(&format!(
                        "a claim left by a run that is gone, {}, could not be removed \
                         ({stuck})",
                        entry.path().display()
                    ));
                }
                Err(_) => {}
            },
            ClaimStanding::Live(pid) => {
                live.get_or_insert((entry.path(), Ok(pid)));
            }
            ClaimStanding::Unjudged(reason) => {
                unjudged.get_or_insert((entry.path(), Err(reason)));
            }
        }
    }
    if let Some((held, holder)) = live.or(unjudged) {
        drop(claim);
        return Err(claim_refusal(workdir, &held, holder));
    }
    Ok(claim)
}

/// The refusal for a claim held by a live process (`Ok`, its pid) or one this system
/// cannot judge (`Err`, the reason).
fn claim_refusal(
    workdir: &Path,
    held: &Path,
    holder: std::result::Result<u32, &'static str>,
) -> anyhow::Error {
    let file = held.file_name().map_or_else(
        || held.display().to_string(),
        |f| f.to_string_lossy().into_owned(),
    );
    match holder {
        Ok(pid) => crate::error::TransientError(format!(
            "the work directory {} is in use by another chard measure, process {pid} (its claim is {file}); pass a different --workdir",
            workdir.display()
        ))
        .into(),
        Err(reason) => UserError::with_hint(
            format!(
                "the work directory {} may be in use by another chard measure: it holds {file}, \
                 which this run cannot judge: {reason}",
                workdir.display()
            ),
            format!(
                "if no chard measure is using {}, remove {}; otherwise pass a different --workdir",
                workdir.display(),
                held.display()
            ),
        )
        .into(),
    }
}

/// The level an observation may publish, given its verdict: none unless the verdict is a
/// measurement, so a withheld verdict never carries a confident level.
pub fn published_level(verdict: Verdict, measured: Option<&str>) -> Option<String> {
    verdict
        .is_measurement()
        .then(|| measured.map(ToOwned::to_owned))
        .flatten()
}

/// The compiler-diagnostic channel's reason for a build the driver refused: how the build
/// ended, in [`compile::BuildRecord::ended`]'s words, and the refused line. Without a
/// record, the sentence says the build was refused rather than inventing a status.
fn refused_build_reason(build: Option<&compile::BuildRecord>, line: &str) -> String {
    let ended = build.map_or_else(|| "was refused".to_owned(), compile::BuildRecord::ended);
    format!("the build {ended}: {line}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_control_arms_macro_set_reads_every_spelling_of_a_macro_word() {
        let words = |w: &[&str]| w.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        let mut names = BTreeSet::new();
        macro_names_in(
            &words(&[
                "--def",
                "A=1",
                "--define-macro=B",
                "-UC",
                "--un",
                "D",
                "-Wp,--def,E,-UF,-D,G",
                "-Xarch_x86_64",
                "-DH",
                "-u",
                "-DI",
                "-D",
            ]),
            &mut names,
        );
        let got: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(got, ["A", "B", "C", "D", "E", "F", "G", "H"]);
    }

    #[test]
    fn no_control_arm_spells_a_macro_word_apart_from_its_name() {
        let mut fed = 0;
        for probe in probe::CORPUS {
            for check in probe.checks {
                let regime: &[&str] = check.regime_arm().unwrap_or(&[]);
                for arm in [check.positive, check.negative, regime] {
                    let words = crate::compile_inputs::macro_words(&control_flags(arm));
                    assert!(
                        !words
                            .iter()
                            .any(|w| crate::compile_inputs::is_macro_option(w)),
                        "{}: {words:?}",
                        check.id
                    );
                    fed += 1;
                }
            }
        }
        assert!(fed > 0, "no control arm was read");
    }

    #[test]
    fn a_refused_build_s_reason_says_how_the_build_ended() {
        let record = |exit_status: i32| compile::BuildRecord {
            argv: Vec::new(),
            dropped_flags: Vec::new(),
            exit_status,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };
        for (exit_status, ended) in [
            (-1, "was killed by a signal"),
            (255, "exited 255"),
            (1, "exited 1"),
        ] {
            assert_eq!(
                refused_build_reason(Some(&record(exit_status)), "cc: error: no"),
                format!("the build {ended}: cc: error: no")
            );
        }
        assert_eq!(
            refused_build_reason(None, "cc: error: no"),
            "the build was refused: cc: error: no"
        );
    }

    use super::*;

    /// A work directory for one claim test, emptied first.
    fn claim_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("chard-claim-{tag}-{}", std::process::id()));
        if let Err(e) = std::fs::remove_dir_all(&dir) {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::NotFound,
                "emptying the claim test directory {}: {e}",
                dir.display()
            );
        }
        std::fs::create_dir_all(&dir).expect("creating the claim test directory");
        dir
    }

    fn claims_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("listing the claim test directory")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|n| n.starts_with(WORKDIR_CLAIM_PREFIX))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_stat_line_gives_its_start_time_past_a_command_name_with_parentheses() {
        let middle: Vec<String> = (4..=21).map(|field| field.to_string()).collect();
        let line = format!("42 (a) (b c) S {} 777 0 0\n", middle.join(" "));
        assert_eq!(stat_start_time(&line).as_deref(), Some("777"));
        assert_eq!(stat_start_time("42 (a) S 1 2 3"), None);
        assert_eq!(stat_start_time(&line.replace("777", "7x7")), None);
        assert_eq!(stat_start_time(&line.replace(')', " ")), None);
        if let Ok(own) = std::fs::read_to_string("/proc/self/stat") {
            assert!(stat_start_time(&own).is_some(), "{own}");
        }
    }

    #[test]
    fn a_claim_name_round_trips_and_a_malformed_one_is_unjudged() {
        let own = ClaimHolder::this_process();
        let name = own.file_name();
        let rest = name.strip_prefix(WORKDIR_CLAIM_PREFIX).expect("the prefix");
        assert_eq!(ClaimHolder::parse(rest), Some(own.clone()));
        for malformed in [
            "a.b.c.1",
            "a.b.c.1.2.3",
            "a..c.1.2",
            "a.b.c.x.2",
            "a.b.c.-1.2",
            "",
        ] {
            assert_eq!(ClaimHolder::parse(malformed), None, "{malformed}");
        }
        assert_eq!(
            judge_claim(Some(7), 7, None, &own),
            ClaimStanding::Unjudged("its name is not one chard writes")
        );
    }

    #[test]
    fn a_claim_another_user_owns_is_never_judged_gone() {
        let own = ClaimHolder::this_process();
        let gone = ClaimHolder {
            pid: 4_194_305,
            ..own.clone()
        };
        if own.known() {
            assert_eq!(
                judge_claim(Some(7), 7, Some(&gone), &own),
                ClaimStanding::Gone
            );
        }
        for owner in [Some(0), None] {
            assert!(
                matches!(
                    judge_claim(owner, 7, Some(&gone), &own),
                    ClaimStanding::Unjudged(_)
                ),
                "{owner:?}"
            );
        }
    }

    #[test]
    fn an_unknown_identity_judges_no_claim_gone() {
        let own = ClaimHolder::this_process();
        let unknown = ClaimHolder {
            started: "-".to_owned(),
            ..own.clone()
        };
        let gone = ClaimHolder {
            pid: 4_194_305,
            ..own.clone()
        };
        assert_eq!(
            judge_claim(Some(7), 7, Some(&gone), &unknown),
            ClaimStanding::Unjudged("this system's /proc does not say which processes are alive")
        );
    }

    #[test]
    fn proc_self_is_this_process_only_where_it_names_its_pid() {
        assert!(proc_self_is(&Ok("42".into()), 42));
        assert!(!proc_self_is(&Ok("5".into()), 42));
        assert!(!proc_self_is(&Err(std::io::ErrorKind::NotFound.into()), 42));
    }

    #[test]
    fn a_claims_process_is_judged_from_its_stat_line() {
        let holder = ClaimHolder {
            boot: "b".to_owned(),
            namespace: "1".to_owned(),
            clock: "none".to_owned(),
            pid: 42,
            started: "777".to_owned(),
        };
        let middle: Vec<String> = (4..=21).map(|field| field.to_string()).collect();
        let line = |state: &str, started: &str| {
            Ok(format!(
                "42 (chard) {state} {} {started} 0 0\n",
                middle.join(" ")
            ))
        };
        assert_eq!(
            standing_from_stat(&Err(std::io::ErrorKind::NotFound.into()), &holder),
            ClaimStanding::Gone
        );
        assert!(matches!(
            standing_from_stat(&Err(std::io::ErrorKind::PermissionDenied.into()), &holder),
            ClaimStanding::Unjudged(_)
        ));
        assert_eq!(
            standing_from_stat(&line("S", "777"), &holder),
            ClaimStanding::Live(42)
        );
        assert_eq!(
            standing_from_stat(&line("R", "778"), &holder),
            ClaimStanding::Gone
        );
        assert_eq!(
            standing_from_stat(&line("Z", "777"), &holder),
            ClaimStanding::Gone
        );
        assert_eq!(
            standing_from_stat(&line("X", "777"), &holder),
            ClaimStanding::Gone
        );
        assert!(matches!(
            standing_from_stat(&Ok("42 (chard".to_owned()), &holder),
            ClaimStanding::Unjudged(_)
        ));
        assert!(matches!(
            standing_from_stat(&line("SS", "777"), &holder),
            ClaimStanding::Unjudged(_)
        ));
    }

    #[test]
    fn a_claim_removed_under_its_run_is_not_confirmed() {
        let dir = claim_dir("confirm");
        let claim = claim_workdir(&dir).expect("the claim");
        claim.confirm().expect("a claim in place is confirmed");
        std::fs::remove_file(claim.path()).expect("removing the claim by hand");
        let refused = claim.confirm().expect_err("a removed claim");
        assert!(
            refused
                .downcast_ref::<crate::error::TransientError>()
                .is_some(),
            "{refused:#}"
        );
        drop(claim);
        std::fs::remove_dir_all(&dir).expect("removing the claim test directory");
    }

    #[test]
    fn a_held_work_directory_refuses_a_second_claim_until_it_is_released() {
        let dir = claim_dir("held");
        let own = ClaimHolder::this_process();
        let first = claim_workdir(&dir).expect("the first claim");
        assert_eq!(claims_in(&dir), [own.file_name()]);
        let refused = claim_workdir(&dir).expect_err("a second claim on a held directory");
        if own.known() {
            let transient = refused
                .downcast_ref::<crate::error::TransientError>()
                .unwrap_or_else(|| panic!("a live holder is TRANSIENT: {refused:#}"));
            assert!(
                transient.0.contains(&own.pid.to_string()),
                "{}",
                transient.0
            );
        } else {
            assert!(refused.downcast_ref::<UserError>().is_some(), "{refused:#}");
        }
        assert_eq!(
            claims_in(&dir),
            [own.file_name()],
            "the refusal left the claim"
        );
        drop(first);
        assert!(claims_in(&dir).is_empty(), "a dropped claim is removed");
        drop(claim_workdir(&dir).expect("a released directory is claimed again"));
        std::fs::remove_dir_all(&dir).expect("removing the claim test directory");
    }

    #[test]
    fn another_runs_claim_is_judged_by_its_process() {
        let own = ClaimHolder::this_process();
        if !own.known() {
            eprintln!("chard: no /proc here, so another run's claim is never judged gone");
            return;
        }
        let plant = |dir: &Path, holder: &ClaimHolder| {
            let path = dir.join(holder.file_name());
            std::fs::write(&path, "").expect("planting a claim");
            path
        };

        // Above any `pid_max` Linux allows, so its process is never alive.
        let dir = claim_dir("gone");
        let gone = plant(
            &dir,
            &ClaimHolder {
                pid: 4_194_305,
                ..own.clone()
            },
        );
        let reused = plant(
            &dir,
            &ClaimHolder {
                started: "0".to_owned(),
                ..own.clone()
            },
        );
        let claim = claim_workdir(&dir).expect("gone claims refuse nothing");
        assert!(!gone.exists() && !reused.exists(), "{:?}", claims_in(&dir));
        drop(claim);

        for (tag, planted) in [
            (
                "boot",
                ClaimHolder {
                    boot: "other".to_owned(),
                    ..own.clone()
                }
                .file_name(),
            ),
            (
                "namespace",
                ClaimHolder {
                    namespace: "1".to_owned(),
                    ..own.clone()
                }
                .file_name(),
            ),
            (
                "clock",
                ClaimHolder {
                    clock: "1".to_owned(),
                    ..own.clone()
                }
                .file_name(),
            ),
            ("malformed", format!("{WORKDIR_CLAIM_PREFIX}junk")),
        ] {
            let dir = claim_dir(tag);
            let planted = dir.join(planted);
            std::fs::write(&planted, "").expect("planting a claim");
            let refused = claim_workdir(&dir).expect_err("an unjudged claim refuses");
            let user = refused
                .downcast_ref::<UserError>()
                .unwrap_or_else(|| panic!("{tag}: an unjudged claim is USER_INPUT: {refused:#}"));
            assert!(
                user.hint
                    .as_deref()
                    .is_some_and(|h| h.contains(&planted.display().to_string())),
                "{tag}: {:?}",
                user.hint
            );
            assert_eq!(
                claims_in(&dir),
                [planted.file_name().unwrap().to_string_lossy().into_owned()],
                "{tag}: the planted claim stays and this run's own is removed"
            );
            std::fs::remove_dir_all(&dir).expect("removing the claim test directory");
        }

        std::fs::remove_dir_all(&dir).expect("removing the claim test directory");
    }

    #[test]
    fn a_live_holders_claim_refuses_as_transient() {
        let own = ClaimHolder::this_process();
        if !own.known() {
            eprintln!("chard: no /proc here, so another run's claim is never judged live");
            return;
        }
        let dir = claim_dir("live");
        // The test's parent outlives the test, and spawning a child here would be a site
        // `compile::tests` holds to the two that bound one.
        let parent = std::os::unix::process::parent_id();
        let started = std::fs::read_to_string(format!("/proc/{parent}/stat"))
            .ok()
            .and_then(|stat| stat_start_time(&stat))
            .expect("the parent's start time");
        let live = dir.join(
            ClaimHolder {
                pid: parent,
                started,
                ..own.clone()
            }
            .file_name(),
        );
        std::fs::write(&live, "").expect("planting a claim");
        let refused = claim_workdir(&dir).expect_err("a live claim refuses");
        let transient = refused
            .downcast_ref::<crate::error::TransientError>()
            .unwrap_or_else(|| panic!("a live holder is TRANSIENT: {refused:#}"));
        assert!(
            transient.0.contains(&format!("process {parent}")),
            "{}",
            transient.0
        );
        assert_eq!(
            claims_in(&dir),
            [live.file_name().unwrap().to_string_lossy().into_owned()],
            "the live claim stays and this run's own is removed"
        );
        std::fs::remove_dir_all(&dir).expect("removing the claim test directory");
    }

    #[test]
    fn a_compiler_temp_name_is_scrubbed_from_a_published_line_and_only_that() {
        for (line, want) in [
            (
                "/usr/bin/ld: /tmp/ccAbC123.o: warning: relocation in read-only section",
                "/usr/bin/ld: <compiler-temp>: warning: relocation in read-only section",
            ),
            (
                "ld: warning: object file (/tmp/probe-9f2a1c.o) was built for newer",
                "ld: warning: object file (<compiler-temp>) was built for newer",
            ),
            (
                "ld: in '/var/folders/xy/zz/T/probe-1a2b3c.o', section __TEXT",
                "ld: in '<compiler-temp>', section __TEXT",
            ),
            (
                "ld: in '/private/var/folders/xy/zz/T/probe-1a2b3c.o', section __TEXT",
                "ld: in '<compiler-temp>', section __TEXT",
            ),
            ("/tmp/ccAbC123.o", "<compiler-temp>"),
            (
                ">>> defined in /tmp/macro_report-93b266.o\n>>> referenced by macro_report.c",
                ">>> defined in <compiler-temp>\n>>> referenced by macro_report.c",
            ),
            (
                "/var/tmp/ccAbCdEf.ld and /tmp/ccQwErTy.s and /tmp/ccQwErTy.ii",
                "<compiler-temp> and <compiler-temp> and <compiler-temp>",
            ),
            // Under a temporary root and named by nobody's driver.
            ("-I/tmp/hdrs", "-I/tmp/hdrs"),
            (
                "In file included from /tmp/hdrs/x.h:1:",
                "In file included from /tmp/hdrs/x.h:1:",
            ),
            (
                "two /tmp/a.o and /tmp/b.o here",
                "two /tmp/a.o and /tmp/b.o here",
            ),
            ("/tmp/ccabc.o", "/tmp/ccabc.o"),
            ("/tmp/probe-abcdef.txt", "/tmp/probe-abcdef.txt"),
            ("/tmp/-abcdef.o", "/tmp/-abcdef.o"),
            // A compiler's shape outside a temporary root is a file the operator named.
            ("/srv/build/probe-abc123.o", "/srv/build/probe-abc123.o"),
            (
                "probe.c:3:5: warning: something in /usr/include/stdio.h",
                "probe.c:3:5: warning: something in /usr/include/stdio.h",
            ),
            ("", ""),
        ] {
            assert_eq!(scrub_compiler_temp_names(line), want, "{line}");
        }
    }

    #[test]
    fn publication_rewrites_every_copy_an_observation_carries() {
        let workdir = Path::new("/scratch/wd");
        let probe = some_probe();
        let check = &probe.checks[0];
        let record = || {
            let mut b = variant_build(1, false);
            b.argv = vec!["cc".to_owned(), "/scratch/wd/x.c".to_owned()];
            b.stderr = "/scratch/wd/x.c:1:1: error: /tmp/ccQwErTy.o".to_owned();
            b
        };
        let mut observation = blank_observation(probe, check, Verdict::BuildFailed);
        observation.build = Some(record());
        observation.evidence.macro_dump = Some(record());
        observation.evidence.observed = Some("saw /scratch/wd/x.c and /tmp/ccQwErTy.o".to_owned());
        observation.build_rejection = Some("ld rejected -z: /scratch/wd/x".to_owned());
        observation.gating = Some(report::Gating {
            rule: report::gating_rule::UNMEASURED,
            arch: None,
            libc: None,
            needs_vm: false,
            reason: "writing /scratch/wd/x.c failed".to_owned(),
        });
        let mut controls = controls_with_positive(probe::Outcome::Absent);
        controls.positive.detail = Some("/usr/bin/ld: /tmp/ccQwErTy.o: ignored".to_owned());
        controls.positive.build = Some(record());
        controls.positive.macro_dump = Some(record());
        observation.controls = Some(controls);

        publish(&mut observation, workdir);

        let build = observation.build.as_ref().expect("kept");
        assert_eq!(build.argv, ["cc", "x.c"]);
        // Publication rewrites paths and touches nothing else: the arm's flags survive.
        let arm = &observation.controls.as_ref().expect("kept").positive;
        assert_eq!(arm.flags, ["-sentinel-positive"]);
        assert_eq!(build.stderr, "x.c:1:1: error: <compiler-temp>");
        assert_eq!(
            observation
                .evidence
                .macro_dump
                .as_ref()
                .map(|b| b.stderr.as_str()),
            Some("x.c:1:1: error: <compiler-temp>")
        );
        assert_eq!(
            observation.evidence.observed.as_deref(),
            Some("saw x.c and <compiler-temp>")
        );
        assert_eq!(
            observation.build_rejection.as_deref(),
            Some("ld rejected -z: x")
        );
        assert_eq!(
            observation.gating.as_ref().map(|g| g.reason.as_str()),
            Some("writing x.c failed")
        );
        let controls = observation.controls.as_ref().expect("kept");
        assert_eq!(
            controls.positive.detail.as_deref(),
            Some("/usr/bin/ld: <compiler-temp>: ignored")
        );
        assert_eq!(
            controls.positive.build.as_ref().map(|b| b.argv.clone()),
            Some(vec!["cc".to_owned(), "x.c".to_owned()])
        );
        assert_eq!(
            controls
                .positive
                .macro_dump
                .as_ref()
                .map(|b| b.stderr.as_str()),
            Some("x.c:1:1: error: <compiler-temp>"),
            "the arm's dump record is rewritten like every other record"
        );
    }

    #[test]
    fn an_unevaluable_arm_names_the_job_that_failed_it() {
        let dump = |status: i32, stderr: &str| {
            let mut d = variant_build(status, false);
            d.stderr = stderr.to_owned();
            d
        };
        let base = || Variant {
            macros: BTreeMap::from([("__SSP_STRONG__".to_owned(), "3".to_owned())]),
            macros_preprocessor: BTreeMap::from([("__SSP_STRONG__".to_owned(), "3".to_owned())]),
            macro_source: "preprocessor",
            macro_dump: Some(dump(0, "")),
            elf: None,
            build: Some(variant_build(0, true)),
            run: None,
            run_error: None,
            elf_error: None,
            unwitnessed: None,
            artifact: None,
            structured: None,
            workdir: None,
        };

        // Readable on the macro channel: no reason.
        assert_eq!(unevaluable_reason(&base(), Channel::Macro), None);

        let mut failed = base();
        failed.macro_dump = Some(dump(1, "\nfatal error: late.h: No such file\n"));
        let reason = unevaluable_reason(&failed, Channel::Macro).expect("a reason");
        assert!(
            reason.contains("exited 1") && reason.contains("late.h"),
            "{reason}"
        );

        // The runtime channel: the run that could not be spawned wins over the build.
        let mut unspawnable = base();
        unspawnable.run_error = Some("exec format error".to_owned());
        assert_eq!(
            unevaluable_reason(&unspawnable, Channel::Runtime).as_deref(),
            Some("exec format error")
        );

        let mut unbuilt = base();
        unbuilt.build = Some(dump(2, "ld: cannot find -lfoo"));
        let reason = unevaluable_reason(&unbuilt, Channel::ElfStatic).expect("a reason");
        assert!(
            reason.contains("exited 2") && reason.contains("-lfoo"),
            "{reason}"
        );

        // The published dump record keeps everything but the defines, and counts them.
        let mut dumped = dump(1, "err");
        dumped.stdout = "#define A 1\n#define B 2\nnot a define\n".to_owned();
        let published = published_dump_record(&dumped);
        assert_eq!(published.exit_status, 1);
        assert_eq!(published.stderr, "err");
        assert!(
            published.stdout.starts_with("<2 #define line(s) omitted"),
            "{}",
            published.stdout
        );
        assert!(
            dumped.stdout.starts_with("#define A"),
            "the record the detectors read is untouched"
        );
    }

    #[test]
    fn a_linker_rejecting_the_profiles_flags_is_not_the_checks_fault() {
        let profile = Profile {
            id: "openssf-tldr".to_owned(),
            flags_source: "builtin".to_owned(),
            cflags: vec!["-O2".to_owned(), "-fstack-protector-strong".to_owned()],
            cxxflags: Vec::new(),
            ldflags: vec![
                "-Wl,-z,relro".to_owned(),
                "-Wl,-z,now".to_owned(),
                "-Wl,--as-needed".to_owned(),
                "-Wl,--no-copy-dt-needed-entries".to_owned(),
            ],
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        let build = |stderr: &str| compile::BuildRecord {
            argv: vec!["/usr/bin/cc".to_owned()],
            dropped_flags: Vec::new(),
            exit_status: 1,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            duration_ms: 1,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };

        let darwin = build(
            "clang: warning: argument unused during compilation: '-pie'\n\
             ld: unknown options: -z -z -z -z --as-needed --no-copy-dt-needed-entries \n\
             clang: error: linker command failed with exit code 1\n",
        );
        let named = profile_flag_rejection(&darwin, &profile).expect("classified");
        assert!(named.starts_with("ld rejected"), "{named}");
        for flag in ["-z", "--as-needed", "--no-copy-dt-needed-entries"] {
            assert!(named.contains(flag), "{flag} missing from: {named}");
        }

        // GNU ld's wording, and lld's, on the same rule.
        assert!(
            profile_flag_rejection(&build("ld: unrecognized option '--as-needed'"), &profile)
                .is_some()
        );
        assert!(
            profile_flag_rejection(&build("ld.lld: error: unknown argument: -z"), &profile)
                .is_some()
        );

        // Both signals are required: a phrase with no profile flag is about something else...
        assert!(
            profile_flag_rejection(&build("cc: error: unknown option: -fnonsense"), &profile)
                .is_none(),
            "a flag this profile never supplied is the check's own problem"
        );
        // ...and a profile flag with no rejection phrase is just a flag on the command line.
        assert!(
            profile_flag_rejection(
                &build("probe.c:3:5: error: use of undeclared identifier; -Wl,--as-needed"),
                &profile
            )
            .is_none(),
            "naming a profile flag is not the same as refusing it"
        );
        assert!(profile_flag_rejection(&build(""), &profile).is_none());
    }

    #[test]
    fn a_warning_or_note_naming_a_profile_flag_is_not_a_refusal() {
        let mut profile = Profile {
            id: "explicit".to_owned(),
            flags_source: "user".to_owned(),
            cflags: vec!["-O2".to_owned(), "-Wchard-no-such".to_owned()],
            cxxflags: Vec::new(),
            ldflags: vec!["-Wl,--as-needed".to_owned()],
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        let build = |stderr: &str| compile::BuildRecord {
            argv: vec!["/usr/bin/cc".to_owned()],
            dropped_flags: Vec::new(),
            exit_status: 1,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            duration_ms: 1,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };
        for line in [
            "clang: warning: unknown warning option '-Wchard-no-such' [-Wunknown-warning-option]",
            "warning: unknown warning option '-Wchard-no-such'; did you mean '-Wx'?",
            "cc1: note: unrecognized command-line option '-Wchard-no-such' may have been \
             intended to silence earlier diagnostics",
            "ld: warning: unrecognized option '--as-needed' ignored",
        ] {
            assert!(line_is_a_warning_or_note(line), "{line}");
            assert!(
                profile_flag_rejection(&build(line), &profile).is_none(),
                "went on without it: {line}"
            );
            assert!(
                control_flag_rejection(&build(line), &["-Wchard-no-such", "--as-needed"]).is_some(),
                "a control the driver warns about is still unknown to it: {line}"
            );
        }
        for line in [
            "gcc: error: unrecognized command-line option '-Wchard-no-such'",
            "clang: error: unknown argument: '-Wchard-no-such'",
            "error: unknown warning option '-Wchard-no-such' [-Werror,-Wunknown-warning-option]",
            "ld: unrecognized option '--as-needed'",
            "/usr/bin/ld.bfd: unrecognized option '--as-needed'",
            "ld: unknown options: --as-needed",
        ] {
            assert!(!line_is_a_warning_or_note(line), "{line}");
            assert!(
                profile_flag_rejection(&build(line), &profile).is_some(),
                "the tool stopped: {line}"
            );
        }
        // The refusal is read past the warning before it.
        let both = build(
            "clang: warning: unknown warning option '-Wchard-no-such'\n\
             ld: unrecognized option '--as-needed'",
        );
        let refusal = profile_flag_refusal(&both, &profile).expect("the linker's line");
        assert_eq!(refusal.line, "ld: unrecognized option '--as-needed'");
        assert_eq!(refusal.tool, "ld");
        assert_eq!(refusal.flags, ["--as-needed"]);
        assert!(
            refusal.sentence.ends_with(&refusal.line),
            "{}",
            refusal.sentence
        );
        profile.ldflags.clear();
        assert!(profile_flag_refusal(&both, &profile).is_none());
    }

    #[test]
    fn a_compiler_rejecting_the_profiles_flags_is_not_the_checks_fault() {
        let profile = Profile {
            id: "openssf-tldr".to_owned(),
            flags_source: "builtin".to_owned(),
            cflags: vec![
                "-O2".to_owned(),
                "-fstrict-flex-arrays=3".to_owned(),
                "-fstack-clash-protection".to_owned(),
            ],
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        let build = |stderr: &str| compile::BuildRecord {
            argv: vec!["/usr/bin/gcc".to_owned()],
            dropped_flags: Vec::new(),
            exit_status: 1,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            duration_ms: 1,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        };

        // gcc 9.4, verbatim from the sweep.
        let old_gcc = profile_flag_rejection(
            &build("gcc: error: unrecognized command line option '-fstrict-flex-arrays=3'"),
            &profile,
        )
        .expect("gcc 9.4's wording must classify");
        assert!(old_gcc.starts_with("gcc rejected"), "{old_gcc}");
        assert!(old_gcc.contains("-fstrict-flex-arrays=3"), "{old_gcc}");

        // gcc 16: hyphenated, and the flag in typographic quotes.
        let new_gcc = profile_flag_rejection(
            &build("gcc: error: unrecognized command-line option \u{2018}-fstrict-flex-arrays=3\u{2019}"),
            &profile,
        )
        .expect("gcc 16's wording, with curly quotes, must classify");
        assert!(
            new_gcc.contains("-fstrict-flex-arrays=3"),
            "the flag must survive typographic quote trimming: {new_gcc}"
        );

        // clang's spelling of the same refusal.
        assert!(
            profile_flag_rejection(
                &build("clang: error: unknown argument: '-fstrict-flex-arrays=3'"),
                &profile
            )
            .is_some()
        );

        // A flag this profile never supplied is the check's own problem.
        assert!(
            profile_flag_rejection(
                &build("gcc: error: unrecognized command line option '-fwho-knows'"),
                &profile
            )
            .is_none()
        );

        // A wrapper puts a space before the first colon (`ccache gcc: error: ...`), and
        // the invocation is not the tool that refused; the line is quoted whole either way.
        let wrapped = profile_flag_rejection(
            &build("ccache gcc: error: unrecognized command line option '-fstrict-flex-arrays=3'"),
            &profile,
        )
        .expect("the rejection is still classified");
        assert!(
            wrapped.starts_with("the toolchain rejected"),
            "a prefix that is not a single token must not be named as the tool: {wrapped}"
        );
        assert!(
            wrapped.contains("-fstrict-flex-arrays=3"),
            "and the flag is still named: {wrapped}"
        );
    }

    #[test]
    fn a_withheld_verdict_publishes_no_level() {
        let measured = [Verdict::On, Verdict::Off, Verdict::Partial];
        let withheld = [
            Verdict::Unsupported,
            Verdict::NotApplicable,
            Verdict::Indeterminate,
            Verdict::ProbeInvalid,
            Verdict::BuildFailed,
            Verdict::RunFailed,
        ];
        for v in measured {
            assert_eq!(
                published_level(v, Some("strong")),
                Some("strong".to_owned()),
                "{} is a measurement and must keep its level",
                v.as_str()
            );
            assert_eq!(published_level(v, None), None);
        }
        for v in withheld {
            assert_eq!(
                published_level(v, Some("strong")),
                None,
                "{} was withheld and must publish no level",
                v.as_str()
            );
        }
        // Every verdict is in one list or the other.
        assert_eq!(measured.len() + withheld.len(), Verdict::ALL.len());
    }

    #[test]
    fn a_flag_lists_net_definition_follows_the_compilers_order() {
        let defines = |flags: &[&str]| {
            profile_defines(
                &flags.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                "_X",
            )
        };
        for (flags, expected) in [
            (&["-Wp,-D_X", "-U_X"][..], true),
            (&["-U_X", "-Wp,-D_X"], true),
            (&["-D_X", "-Wp,-U_X"], false),
            (&["-Wp,-U_X", "-D_X"], false),
            (&["-D_X", "-U_X"], false),
            (&["-U_X", "-D_X"], true),
            (&["-Xpreprocessor", "-D_X", "-U_X"], true),
            (&["-D_X", "-Xpreprocessor", "-U_X"], false),
            (&["-Wp,-D_X", "-Wp,-U_X"], false),
            (&["-Wp,-U_X", "-Wp,-D_X"], true),
            (&["-Wp,-U_X,-D_X"], true),
            (&["-Wp,-D_X,-U_X"], false),
            (&["-D", "_X"], true),
            (&["-U_X", "-D", "_X", "-U", "_X"], false),
            (&["-D_X=1"], true),
            (&["-D_XY", "-D_", "-O2"], false),
            (&[], false),
        ] {
            assert_eq!(defines(flags), expected, "{flags:?}");
        }
    }

    #[test]
    fn the_long_spellings_of_a_define_attribute_the_assertions_as_the_short_ones() {
        let map = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        let flags = |f: &[&str]| f.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let o0 = map(&[("_CXX_STDLIB", "libstdc++"), ("_GLIBCXX_ASSERTIONS", "1")]);
        let o2 = map(&[
            ("_CXX_STDLIB", "libstdc++"),
            ("_GLIBCXX_ASSERTIONS", "1"),
            ("__OPTIMIZE__", "1"),
        ]);
        let mut fed = 0_usize;
        for id in CXX_ASSERTIONS_ATTRIBUTED {
            let source =
                |m: &BTreeMap<String, String>, f: &[&str]| cxx_assertions_source(id, m, &flags(f));
            for (long, short) in [
                (
                    &["--define-macro=_GLIBCXX_ASSERTIONS"][..],
                    &["-D_GLIBCXX_ASSERTIONS"][..],
                ),
                (
                    &["--define-macro", "_GLIBCXX_ASSERTIONS"],
                    &["-D", "_GLIBCXX_ASSERTIONS"],
                ),
                (
                    &["--def", "_GLIBCXX_ASSERTIONS"],
                    &["-D", "_GLIBCXX_ASSERTIONS"],
                ),
                (
                    &["--undefine-macro=_GLIBCXX_NO_ASSERTIONS"],
                    &["-U_GLIBCXX_NO_ASSERTIONS"],
                ),
                (
                    &["--un", "_GLIBCXX_NO_ASSERTIONS"],
                    &["-U", "_GLIBCXX_NO_ASSERTIONS"],
                ),
                (&["-u", "-D_GLIBCXX_ASSERTIONS"], &[]),
                (&["-L", "-D_GLIBCXX_ASSERTIONS"], &[]),
            ] {
                assert_eq!(source(&o0, long), source(&o0, short), "{id}: {long:?}");
                assert_eq!(source(&o2, long), source(&o2, short), "{id}: {long:?}");
            }
            assert_eq!(
                source(&o0, &["--def", "_GLIBCXX_ASSERTIONS"]),
                Some("profile"),
                "{id}: the abbreviated define names the profile"
            );
            assert_eq!(
                source(&o0, &["-u", "-D_GLIBCXX_ASSERTIONS"]),
                Some("library-unoptimized-default"),
                "{id}: a define taken as a symbol is no define, so the library's default stands"
            );
            assert_eq!(
                source(&o2, &["--define-macro=_GLIBCXX_ASSERTIONS"]),
                Some("profile"),
                "{id}: the long define names the profile in an optimized build"
            );
            assert_eq!(
                source(&o2, &["--undefine-macro", "_GLIBCXX_ASSERTIONS"]),
                Some("unattributed"),
                "{id}: the long undefine does not account for the assertions the build has"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, CXX_ASSERTIONS_ATTRIBUTED.len(), "every check was fed");
    }

    #[test]
    fn the_assertions_are_attributed_to_the_profile_the_library_or_neither() {
        let map = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        let flags = |f: &[&str]| f.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let o0 = map(&[("_CXX_STDLIB", "libstdc++"), ("_GLIBCXX_ASSERTIONS", "1")]);
        let o2 = map(&[
            ("_CXX_STDLIB", "libstdc++"),
            ("_GLIBCXX_ASSERTIONS", "1"),
            ("__OPTIMIZE__", "1"),
        ]);
        for id in CXX_ASSERTIONS_ATTRIBUTED {
            assert!(
                probe::CORPUS
                    .iter()
                    .any(|p| p.checks.iter().any(|c| c.id == id)),
                "{id} is attributed and is not a corpus check"
            );
            let source =
                |m: &BTreeMap<String, String>, f: &[&str]| cxx_assertions_source(id, m, &flags(f));
            assert_eq!(
                source(&o0, &["-U_GLIBCXX_ASSERTIONS"]),
                Some("library-unoptimized-default")
            );
            assert_eq!(source(&o0, &["-D_GLIBCXX_ASSERTIONS"]), Some("profile"));
            assert_eq!(
                source(&o0, &["-D_GLIBCXX_NO_ASSERTIONS"]),
                Some("unattributed"),
                "the library's default does not fire under _GLIBCXX_NO_ASSERTIONS"
            );
            assert_eq!(
                source(
                    &o0,
                    &["-D_GLIBCXX_NO_ASSERTIONS", "-U_GLIBCXX_NO_ASSERTIONS"]
                ),
                Some("library-unoptimized-default")
            );
            assert_eq!(source(&o0, &["-D_GLIBCXX_DEBUG"]), Some("profile"));
            assert_eq!(
                source(&o2, &["-O2", "-Wp,-D_GLIBCXX_ASSERTIONS"]),
                Some("profile")
            );
            assert_eq!(source(&o2, &["-O2"]), Some("unattributed"));
            // An input the reader does not resolve may have defined the assertions at -O0,
            // so the library's default is not named over it; a -D the reader does see
            // still names the profile.
            for unread in [
                &["-include", "x.h"][..],
                &["-includex.h"],
                &["--include=x.h"],
                &["-imacros", "x.h"],
                &["-include-pch", "x.pch"],
                &["@args"],
                &["-Wp,@args"],
                &["-Wp,-include,x.h"],
                &["-Xpreprocessor", "-imacros", "-Xpreprocessor", "x.h"],
                &["--im", "x.h"],
                &["--include", "x.h"],
                &["--imacros=x.h"],
                &["-Xclang", "-U_GLIBCXX_NO_ASSERTIONS"],
                &["-Xclang=-D_GLIBCXX_ASSERTIONS"],
                &["-Xclang=-include", "-Xclang=x.h"],
                &["-Xclang=@args"],
            ] {
                assert_eq!(source(&o0, unread), Some("unattributed"), "{unread:?}");
            }
            assert_eq!(
                source(&o0, &["-D_GLIBCXX_ASSERTIONS", "-include", "x.h"]),
                Some("profile")
            );
            assert_eq!(
                source(&o0, &["-Xclang", "-D_GLIBCXX_ASSERTIONS"]),
                Some("profile"),
                "the frontend's -D is read where it names the assertions"
            );
            assert_eq!(
                source(&o0, &["--include-directory=inc", "-Xclang", "-fno-pch"]),
                Some("library-unoptimized-default"),
                "a directory and a frontend flag are not preprocessor inputs"
            );
            assert_eq!(
                source(&map(&[("_CXX_STDLIB", "libstdc++")]), &[]),
                None,
                "no assertions, nothing to attribute"
            );
            assert_eq!(
                source(
                    &map(&[("_CXX_STDLIB", "libc++"), ("_GLIBCXX_ASSERTIONS", "1")]),
                    &[]
                ),
                None,
                "libc++ ignores the macro"
            );
        }
        assert_eq!(cxx_assertions_source("pie-macro", &o0, &[]), None);
    }

    #[test]
    fn only_compiler_generated_macros_count_as_spoofed() {
        let spoof = |flags: &[&str]| {
            spoofed_macros(&flags.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        };

        assert_eq!(spoof(&["-D__SSP_STRONG__=3"]), vec!["__SSP_STRONG__"]);
        assert_eq!(spoof(&["-U__PIE__"]), vec!["__PIE__"]);
        assert_eq!(spoof(&["-D__CET__"]), vec!["__CET__"]);
        assert_eq!(spoof(&["-D__EXCEPTIONS=1"]), vec!["__EXCEPTIONS"]);
        assert_eq!(
            spoof(&["-U__EXCEPTIONS", "-fexceptions"]),
            vec!["__EXCEPTIONS"]
        );

        // The real Fedora flag list, verbatim from `rpm --eval %{build_cflags}`.
        assert!(
            spoof(&[
                "-O2",
                "-Wall",
                "-Werror=format-security",
                "-Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3",
                "-Wp,-D_GLIBCXX_ASSERTIONS",
                "-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1",
                "-fstack-protector-strong",
                "-fcf-protection",
            ])
            .is_empty(),
            "a legitimate distribution flag list must not read as spoofed"
        );

        // The split spelling is the same definition.
        assert_eq!(spoof(&["-D", "__PIE__=2"]), vec!["__PIE__"]);

        assert_eq!(
            spoof(&["-Wp,-D__SSP_ALL__=1,-D_FORTIFY_SOURCE=2"]),
            vec!["__SSP_ALL__"]
        );
        // A function-like define names the macro the probes' `#ifdef` sees (measured with
        // gcc 16.1.1: `-D'__OPTIMIZE__(x)=1'` makes `#ifdef __OPTIMIZE__` true), and a
        // relay word between a bare `-D` and its name is not the name.
        assert_eq!(spoof(&["-D__CET__(x)=1"]), vec!["__CET__"]);
        assert_eq!(
            spoof(&["-Xpreprocessor", "-D", "-Xpreprocessor", "__CET__"]),
            vec!["__CET__"]
        );
        assert_eq!(
            spoof(&["-Xclang", "-U", "-Xclang", "__PIE__"]),
            vec!["__PIE__"]
        );
        assert_eq!(spoof(&["-Wp,-D", "-Wp,__CET__"]), vec!["__CET__"]);
        assert_eq!(spoof(&["-D __CET__"]), vec!["__CET__"]);
        assert_eq!(spoof(&["-D__OPTIMIZE__ =1"]), vec!["__OPTIMIZE__"]);

        // Every name is reserved for any use (C17 7.1.3), so a build system defining one is
        // not configuring a compiler; `_x` is reserved only at file scope, not in the macro
        // name space, and must never be added here.
        for m in COMPILER_DEFINED_MACROS {
            let reserved = m.starts_with("__")
                || m.strip_prefix('_')
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()));
            assert!(
                reserved,
                "{m} is not a reserved compiler-generated name, so a build system may \
                 legitimately define it and this rule would withhold a real measurement"
            );
        }
    }

    /// Every macro name a macro-channel predicate reads, beside its check. The walk restates
    /// `predicate::terms` because every line of `src/predicate/` outside its test module is
    /// the decoder's fingerprint.
    fn macro_names_the_predicates_read() -> Vec<(&'static str, String)> {
        macro_names_read_by(crate::predicate::macro_channel::table())
    }

    /// [`macro_names_the_predicates_read`] over the predicates of `table`.
    fn macro_names_read_by(table: &[crate::predicate::Entry]) -> Vec<(&'static str, String)> {
        use crate::predicate::{Conclusion, Cond, LevelOf, Term};
        fn walk<'p>(cond: &'p Cond, out: &mut Vec<&'p Term>) {
            match cond {
                Cond::All(members) | Cond::Any(members) | Cond::NoneOf(members) => {
                    for c in members {
                        walk(c, out);
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
        let mut out = Vec::new();
        for (check, predicate) in table {
            let p = predicate();
            let mut terms = Vec::new();
            for clause in &p.clauses {
                walk(&clause.when, &mut terms);
                if let Conclusion::Present(LevelOf::Value(t)) = &clause.then {
                    terms.push(t);
                }
            }
            if let Conclusion::Present(LevelOf::Value(t)) = &p.otherwise {
                terms.push(t);
            }
            for t in terms {
                // The `cxx-stdlib` ladder names libraries, not a verdict's macro.
                if let Term::Macro(name) | Term::CInt(name) = t {
                    out.push((*check, name.clone()));
                }
            }
        }
        out
    }

    #[test]
    fn every_macro_a_predicate_reads_is_a_field_the_header_writes() {
        let header = include_str!("../probes/chard_selfreport.h");
        let (read, derived) = self_report_entries(header).expect("the header reads");
        let written: BTreeSet<&str> = read
            .iter()
            .chain(derived.iter())
            .map(String::as_str)
            .collect();
        let names = macro_names_the_predicates_read();
        assert!(!names.is_empty(), "no predicate reads a macro");
        for (check, name) in &names {
            assert!(
                written.contains(name.as_str()),
                "{check} reads {name}, which chard_selfreport.h never writes: over an \
                 all-undefined report it would read as undefined, an `off` the artifact never \
                 gave"
            );
        }
        eprintln!(
            "{} macro names read by the predicates against {} the header writes",
            names.len(),
            written.len()
        );
    }

    #[test]
    fn every_macro_a_predicate_reads_is_guarded_against_forgery_or_says_why_not() {
        const MAY_BE_SUPPLIED: &[(&str, &str)] = &[
            (
                "_FORTIFY_SOURCE",
                "defining it is the mechanism; the check reads the request",
            ),
            ("_GLIBCXX_ASSERTIONS", "defining it is the mechanism"),
            ("_LIBCPP_HARDENING_MODE", "defining it is the mechanism"),
            // Not compiler-defined: fortify-headers defines its include guard, and
            // chard_selfreport.h condenses it into `_FORTIFY_IMPL`.
            (
                "_FORTIFY_HEADERS_H",
                "a C library header's guard, not a compiler macro",
            ),
            (
                "_FORTIFY_IMPL",
                "chard_selfreport.h's summary of the guard above",
            ),
        ];
        for (check, name) in macro_names_the_predicates_read() {
            let name = name.as_str();
            assert!(
                COMPILER_DEFINED_MACROS.contains(&name)
                    || MAY_BE_SUPPLIED.iter().any(|(m, _)| *m == name),
                "{check} reads {name}, which a flag list can forge with -D or -U and \
                 which is neither in COMPILER_DEFINED_MACROS nor named with a reason"
            );
        }
    }

    /// The reserved macros a probe's own source branches on: every name of
    /// [`COMPILER_DEFINED_MACROS`] and [`COMPILER_IDENTITY_MACROS`] that a `#if`, `#ifdef`,
    /// `#ifndef` or `#elif` line of `source` tests, as a whole identifier.
    fn branches_in(source: &str) -> Vec<&'static str> {
        let watched = COMPILER_DEFINED_MACROS
            .iter()
            .chain(COMPILER_IDENTITY_MACROS)
            .copied();
        let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let tests_name = |line: &str, name: &str| {
            line.match_indices(name).any(|(at, _)| {
                let before = line[..at].chars().next_back().is_none_or(|c| !is_ident(c));
                let after = line[at + name.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !is_ident(c));
                before && after
            })
        };
        let directives: Vec<&str> = source
            .lines()
            .map(str::trim_start)
            .filter_map(|l| l.strip_prefix('#'))
            .map(str::trim_start)
            .filter(|l| l.starts_with("if") || l.starts_with("elif"))
            .collect();
        watched
            .filter(|name| directives.iter().any(|d| tests_name(d, name)))
            .collect()
    }

    #[test]
    fn every_probe_declares_the_reserved_macros_its_source_branches_on() {
        let mut derived: Vec<(&str, Vec<&str>)> = probe::CORPUS
            .iter()
            .map(|p| (p.id, branches_in(p.source)))
            .filter(|(_, b)| !b.is_empty())
            .collect();
        derived.sort();
        let mut declared: Vec<(&str, Vec<&str>)> = PROBE_MACRO_BRANCHES
            .iter()
            .map(|(id, macros)| (*id, macros.to_vec()))
            .collect();
        declared.sort();
        for (_, macros) in &mut derived {
            macros.sort_unstable();
        }
        for (_, macros) in &mut declared {
            macros.sort_unstable();
        }
        assert_eq!(
            declared, derived,
            "PROBE_MACRO_BRANCHES (left) is not what the probe sources branch on (right)"
        );
        assert_eq!(
            derived.len(),
            11,
            "the ten C probes a grep for the three names finds, and the C++ one"
        );
        for (id, _) in &declared {
            assert!(
                probe::CORPUS.iter().any(|p| p.id == *id),
                "{id} is not a probe in the corpus"
            );
        }
    }

    #[test]
    fn the_branch_derivation_reads_directives_and_whole_identifiers() {
        assert_eq!(
            branches_in("#if defined(__CET__) && (__CET__ & 1)\n"),
            vec!["__CET__"]
        );
        assert_eq!(branches_in("  #ifdef __OPTIMIZE__\n"), vec!["__OPTIMIZE__"]);
        assert_eq!(
            branches_in("#if defined(__GNUC__) && !defined(__clang__)\n#elif __PIE__\n"),
            vec!["__PIE__", "__clang__"]
        );
        assert!(
            branches_in("/* __OPTIMIZE__ as the compiler set it */\n").is_empty(),
            "a macro named in a comment is not a branch"
        );
        assert!(
            branches_in("printf(\"%d\", __OPTIMIZE__);\n").is_empty(),
            "a macro used outside a directive is not a branch"
        );
        assert!(
            branches_in("#define CHARD_X __CET__\n").is_empty(),
            "a macro in a #define's body is not a branch"
        );
        assert!(
            branches_in("#ifdef __CET__X\n#if __PIE__2\n").is_empty(),
            "an identifier that only begins with a macro's name is not that macro"
        );
    }

    /// A verdict as [`settle`] leaves it, for the probe-branch tests.
    fn settled_as(verdict: Verdict) -> Settled {
        Settled {
            verdict,
            gating: None,
            level: Some("x".to_owned()),
        }
    }

    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn a_twinless_macro_check_is_withheld_under_an_unread_preprocessor_input() {
        let check_named = |id: &str| -> &'static Check {
            probe::CORPUS
                .iter()
                .flat_map(|p| p.checks.iter())
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("the corpus carries {id}"))
        };
        let unread = [
            "-include /srv/h",
            "-include/srv/h",
            "-imacros /srv/m",
            "--include=/srv/h",
            "--imacros /srv/m",
            "--im /srv/m",
            "-Wp,--include=/srv/h",
            "-Wp,--im,/srv/m",
            "-Xpreprocessor --imacros=/srv/m",
            "@/srv/args",
            "-Xclang -DGATE",
            "-Xclang=-UGATE",
            "-Wp,-include,/srv/h",
            "-include-pch /srv/p",
            "-I/srv/i",
            "-I /srv/i",
            "-I=inc",
            "-isystem /srv/s",
            "-isystem=inc",
            "-idirafter/srv/a",
            "-iquote /srv/q",
            "-Xarch_x86_64 -I/srv/x",
            "-I/srv/i -include /srv/h",
        ];
        let read = [
            "-DGATE",
            "-UGATE",
            "-pthread",
            "-undef",
            "-Xlinker -I/srv/i",
            "-Wp,-I/srv/i",
            "-isystem-after /srv/after",
            "-I",
        ];
        let mut fed = 0_usize;
        for (id, _) in report::MACRO_WITHOUT_TWIN {
            let check = check_named(id);
            assert_eq!(check.channel(), Channel::Macro, "{id}");
            let observed = match *id {
                "fortify-effective" => "__USE_FORTIFY_LEVEL=3",
                other => panic!("no observed line for {other}; add one"),
            };
            for spelling in unread {
                let mut flags = words(&["-O2"]);
                flags.extend(words(&spelling.split(' ').collect::<Vec<_>>()));
                let reason = twinless_unread_input(check, observed, &flags)
                    .unwrap_or_else(|| panic!("{id}: `{spelling}` withheld nothing"));
                let name = observed.split('=').next().expect("a name before the value");
                assert!(
                    reason.contains(&format!("`{name}`")) && reason.contains(&format!("`{id}`")),
                    "{id}: `{spelling}`: {reason}"
                );
                fed += 1;
            }
            for spelling in read {
                let mut flags = words(&["-O2"]);
                flags.extend(words(&spelling.split(' ').collect::<Vec<_>>()));
                assert_eq!(
                    twinless_unread_input(check, observed, &flags),
                    None,
                    "{id}: `{spelling}` is read by name or carries no macro"
                );
                fed += 1;
            }
            assert_eq!(
                twinless_unread_input(check, observed, &[]),
                None,
                "{id}: no list"
            );
        }
        assert_eq!(
            fed,
            report::MACRO_WITHOUT_TWIN.len() * (unread.len() + read.len()),
            "every twinless check was fed each spelling"
        );
    }

    #[test]
    fn every_carried_header_spelling_trips_the_twinless_clause_and_no_twinned_check_is_held() {
        let check_named = |id: &str| -> &'static Check {
            probe::CORPUS
                .iter()
                .flat_map(|p| p.checks.iter())
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("the corpus carries {id}"))
        };
        let spellings = header_spellings();
        let mut fed = 0_usize;
        for (id, _) in report::MACRO_WITHOUT_TWIN {
            let check = check_named(id);
            for spelling in &spellings {
                let mut flags = words(&["-O2"]);
                flags.extend(words(&spelling.split(' ').collect::<Vec<_>>()));
                let carried = !toolchain::header_selecting_flags(&flags).is_empty();
                let whole = toolchain::HEADER_WHOLE.iter().any(|w| w == spelling);
                let held = twinless_unread_input(check, "__USE_FORTIFY_LEVEL=3", &flags).is_some();
                assert_eq!(
                    held,
                    carried && !whole,
                    "{id}: `{spelling}` is carried to the arms ({carried}), a whole word \
                     ({whole}), and held by the clause ({held})"
                );
                fed += 1;
            }
        }
        for twin in report::MACRO_TWINS {
            let id = twin.macro_check;
            let check = check_named(id);
            for spelling in &spellings {
                let mut flags = words(&["-O2"]);
                flags.extend(words(&spelling.split(' ').collect::<Vec<_>>()));
                assert_eq!(
                    twinless_unread_input(check, "__CET__=3", &flags),
                    None,
                    "{id} has a twin, which holds it"
                );
                fed += 1;
            }
        }
        assert_eq!(
            fed,
            (report::MACRO_WITHOUT_TWIN.len() + report::MACRO_TWINS.len()) * spellings.len(),
            "every check of both lists was fed every spelling"
        );
    }

    #[test]
    fn the_input_clause_holds_a_twinned_reading_only_where_no_twin_measured() {
        for id in HELD_BY_INPUT_WITHOUT_TWIN {
            assert!(
                report::MACRO_TWINS.iter().any(|t| t.macro_check == *id),
                "{id} has a twin"
            );
            assert!(
                report::COMPILE_INPUT_READINGS.contains(id),
                "{id} is a compile-input reading"
            );
        }
        let macros = probe_named("toolchain-macros");
        let object = probe_named("optimization-object");
        let profile = |flags: &str| Profile {
            id: "explicit".to_owned(),
            flags_source: report::flags_source::NONE.to_owned(),
            cflags: words(&flags.split(' ').collect::<Vec<_>>()),
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        // (flags, the reading, the twin's verdict or none in the run, withheld)
        let cases = [
            ("-O0 -include h", Verdict::On, None, true),
            ("-O2 -include h", Verdict::Off, None, true),
            ("-O0 -Idir", Verdict::On, Some(Verdict::Indeterminate), true),
            (
                "-O2 -Idir",
                Verdict::Off,
                Some(Verdict::Indeterminate),
                true,
            ),
            ("-O0 -Idir", Verdict::On, Some(Verdict::ProbeInvalid), true),
            (
                "-O0 -Idir -include h",
                Verdict::On,
                Some(Verdict::Indeterminate),
                true,
            ),
            ("-O2 -Idir", Verdict::On, Some(Verdict::On), false),
            ("-O0 -Idir", Verdict::On, Some(Verdict::Off), false),
            ("-O2 -Idir", Verdict::Off, Some(Verdict::On), false),
            ("-O0 -Idir", Verdict::Off, Some(Verdict::Off), false),
            ("-O0", Verdict::On, None, false),
            ("-O0 -include h", Verdict::Indeterminate, None, false),
        ];
        for (flags, reading, twin, withheld) in cases {
            let mut observations = vec![blank_observation(
                macros,
                check_named("optimization-enabled"),
                reading,
            )];
            observations[0].level = Some("unread".to_owned());
            if let Some(verdict) = twin {
                let mut t = blank_observation(object, check_named("optimization-applied"), verdict);
                // A twin withheld is withheld under a rule, which the state names.
                if verdict == Verdict::Indeterminate {
                    t.gating = Some(report::Gating {
                        rule: report::gating_rule::ARTIFACT_LTO_IR,
                        arch: None,
                        libc: None,
                        needs_vm: false,
                        reason: String::new(),
                    });
                }
                observations.push(t);
            }
            let warnings = withhold_where_no_twin_measured(&mut observations, &profile(flags));
            let o = &observations[0];
            let case = format!("`{flags}` {reading:?} beside {twin:?}");
            if withheld {
                held_by_the_input_clause(&case, flags, reading, twin, &warnings, o);
            } else {
                assert!(warnings.is_empty(), "{case}");
                assert_eq!(o.verdict, reading, "{case}");
                assert!(o.gating.is_none(), "{case}");
            }
        }
        // A probe outside the corpus is read against the C list, not skipped.
        let mut observations = vec![blank_observation(
            macros,
            check_named("optimization-enabled"),
            Verdict::On,
        )];
        "no-such-probe".clone_into(&mut observations[0].probe);
        let warnings =
            withhold_where_no_twin_measured(&mut observations, &profile("-O0 -include h"));
        assert_eq!(warnings.len(), 1, "a probe outside the corpus withholds");
        assert_eq!(observations[0].verdict, Verdict::Indeterminate);
    }

    /// What [`withhold_where_no_twin_measured`] must have done to the reading `o` of one
    /// withheld case: one warning, and the reading `indeterminate` under
    /// `macro-supplied-by-profile`.
    fn held_by_the_input_clause(
        case: &str,
        _flags: &str,
        _reading: Verdict,
        twin: Option<Verdict>,
        warnings: &[Diagnostic],
        o: &Observation,
    ) {
        assert_eq!(warnings.len(), 1, "{case}");
        let warning = &warnings[0];
        assert_eq!(warning.severity, Severity::Warning, "{case}");
        assert_eq!(
            warning.context.as_deref(),
            Some("optimization-enabled"),
            "{case}"
        );
        assert_eq!(
            warning
                .message
                .contains("adds `--probe optimization-object`"),
            twin.is_none(),
            "{case}: the hint names the probe where the twin was left out: {}",
            warning.message
        );
        assert_eq!(o.verdict, Verdict::Indeterminate, "{case}");
        assert_eq!(o.level, None, "{case}");
        let gating = o.gating.as_ref().expect("a gating");
        assert_eq!(gating.rule.id, "macro-supplied-by-profile", "{case}");
        assert!(
            gating.reason.contains("`__OPTIMIZE__`"),
            "{case}: {}",
            gating.reason
        );
    }

    #[test]
    fn settle_applies_the_twinless_clause_to_a_measurement_alone() {
        let check_named = |id: &str| -> &'static Check {
            probe::CORPUS
                .iter()
                .flat_map(|p| p.checks.iter())
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("the corpus carries {id}"))
        };
        let check = check_named("fortify-effective");
        let twinned = check_named("optimization-enabled");
        let reading = Detection {
            outcome: probe::Outcome::Present,
            level: Some("3".to_owned()),
            observed: "__USE_FORTIFY_LEVEL=3".to_owned(),
            rule: None,
        };
        let optimized = Detection {
            outcome: probe::Outcome::Present,
            level: None,
            observed: "__OPTIMIZE__=1".to_owned(),
            rule: None,
        };
        let mut fed = 0_usize;
        for (list, held) in [
            ("-O2 -I/srv/i", true),
            ("-O2 -include /srv/h", true),
            ("-O2", false),
            ("-O2 -pthread", false),
        ] {
            let flags = words(&list.split(' ').collect::<Vec<_>>());
            let twin = settle_for(
                Verdict::On,
                twinned,
                &optimized,
                |_| None,
                None,
                None,
                &flags,
            );
            assert_eq!(twin.verdict, Verdict::On, "optimization-enabled `{list}`");
            assert!(twin.gating.is_none(), "optimization-enabled `{list}`");
            let out = settle_for(Verdict::On, check, &reading, |_| None, None, None, &flags);
            if held {
                assert_eq!(
                    out.verdict,
                    Verdict::Indeterminate,
                    "`{list}`: {:?}",
                    out.gating
                );
                assert_eq!(
                    out.gating.as_ref().map(|g| g.rule.id),
                    Some("macro-supplied-by-profile"),
                    "`{list}`"
                );
            } else {
                assert_eq!(out.verdict, Verdict::On, "`{list}`");
                assert!(out.gating.is_none(), "`{list}`");
            }
            fed += 1;
        }
        let declared = settle_for(
            Verdict::ProbeInvalid,
            check,
            &reading,
            always_declared(),
            None,
            None,
            &words(&["-O2", "-I/srv/i"]),
        );
        assert_eq!(
            declared.gating.as_ref().map(|g| g.rule.id),
            Some(report::gating_rule::LIBC_DECLARED.id),
            "a declared rule's verdict stands"
        );
        assert_eq!(fed, 4, "every list was fed");
    }

    #[test]
    fn a_list_defining_a_macro_a_probe_branches_on_withholds_that_probes_checks() {
        let mut rows = 0;
        for (id, macros) in PROBE_MACRO_BRANCHES {
            let probe = probe_named(id);
            for check in probe.checks {
                if check.channel() == Channel::Macro {
                    let out = settle_probe_branches(
                        settled_as(Verdict::On),
                        probe,
                        check,
                        &words(&[&format!("-D{}", macros[0])]),
                        None,
                    );
                    assert_eq!(out.verdict, Verdict::On, "{}", check.id);
                    continue;
                }
                for m in *macros {
                    for spelling in [
                        format!("-D{m}"),
                        format!("-D{m}=1"),
                        format!("-U{m}"),
                        format!("-Wp,-D{m}=3"),
                        format!("-Xpreprocessor -U{m}"),
                        format!("-D {m}"),
                        format!("-D{m}(x)=1"),
                        format!("-Xpreprocessor -D -Xpreprocessor {m}"),
                        format!("-Xclang -U -Xclang {m}"),
                        format!("-Wp,-D -Wp,{m}"),
                        format!("-D {m}=1"),
                        // gcc's long and abbreviated spellings, read as the short word.
                        format!("--define-macro={m}"),
                        format!("--define-macro {m}=1"),
                        format!("--def {m}"),
                        format!("--undefine-macro {m}"),
                        format!("--un {m}"),
                        // Handed to gcc's `cc1`, which reads the long spellings too.
                        format!("-Wp,--define-macro={m}"),
                        format!("-Wp,--def,{m}"),
                        format!("-Xpreprocessor --undefine-macro={m}"),
                        format!("-Xpreprocessor --def -Xpreprocessor {m}"),
                    ] {
                        let list: Vec<&str> = spelling.split(' ').collect();
                        let mut flags = words(&["-O2"]);
                        flags.extend(words(&list));
                        let out = settle_probe_branches(
                            settled_as(Verdict::On),
                            probe,
                            check,
                            &flags,
                            None,
                        );
                        let gating = out.gating.unwrap_or_else(|| {
                            panic!("{}: `{spelling}` withheld nothing", check.id)
                        });
                        assert_eq!(gating.rule, report::gating_rule::MACRO_SPOOFED);
                        assert_eq!(out.verdict, Verdict::Indeterminate);
                        assert_eq!(out.level, None);
                        assert!(
                            gating.reason.contains(&format!("`{m}`"))
                                && gating.reason.contains(&format!("`{id}`"))
                                && gating.reason.contains("defines or undefines"),
                            "{}: {}",
                            check.id,
                            gating.reason
                        );
                    }
                }
                // A preprocessor input the reader does not read by name withholds too.
                for input in [
                    "-include /tmp/h.h",
                    "-imacros /tmp/h.h",
                    "--include=/tmp/h.h",
                    "--im /tmp/h.h",
                    "@/tmp/response",
                    "-Xclang -DX=1",
                ] {
                    let list: Vec<&str> = input.split(' ').collect();
                    let out = settle_probe_branches(
                        settled_as(Verdict::On),
                        probe,
                        check,
                        &words(&list),
                        None,
                    );
                    let gating = out
                        .gating
                        .unwrap_or_else(|| panic!("{}: `{input}` withheld nothing", check.id));
                    assert_eq!(gating.rule, report::gating_rule::MACRO_SPOOFED);
                    assert!(
                        gating.reason.contains("does not read by name")
                            && gating.reason.contains(&format!("`{id}`"))
                            && gating.reason.contains(&format!("`{}`", macros[0])),
                        "{}: {}",
                        check.id,
                        gating.reason
                    );
                }
            }
            rows += 1;
        }
        assert_eq!(rows, PROBE_MACRO_BRANCHES.len());
    }

    #[test]
    fn a_long_define_of_another_macro_withholds_nothing_of_a_branching_probe() {
        let mut rows = 0;
        for (id, macros) in PROBE_MACRO_BRANCHES {
            let probe = probe_named(id);
            for check in probe
                .checks
                .iter()
                .filter(|c| c.channel() != Channel::Macro)
            {
                // The last two name the branch macro itself, as a value.
                for input in [
                    "--define-macro=X".to_owned(),
                    "--def X".to_owned(),
                    "--undefine-macro X".to_owned(),
                    "-u -DX".to_owned(),
                    format!("-u -D{}", macros[0]),
                    format!("--forc -D{}=1", macros[0]),
                ] {
                    let list: Vec<&str> = input.split(' ').collect();
                    let out = settle_probe_branches(
                        settled_as(Verdict::On),
                        probe,
                        check,
                        &words(&list),
                        None,
                    );
                    assert_eq!(out.verdict, Verdict::On, "{}: `{input}`", check.id);
                    assert!(out.gating.is_none(), "{}: `{input}` withheld", check.id);
                }
            }
            rows += 1;
        }
        assert_eq!(rows, PROBE_MACRO_BRANCHES.len());
    }

    #[test]
    fn an_unmatched_compile_listing_withholds_a_branching_probes_checks() {
        for (id, _) in PROBE_MACRO_BRANCHES {
            let probe = probe_named(id);
            for check in probe
                .checks
                .iter()
                .filter(|c| c.channel() != Channel::Macro)
            {
                let unmatched = "the measured compile names -D__OPTIMIZE__=1 and the arms do not";
                let out = settle_probe_branches(
                    settled_as(Verdict::On),
                    probe,
                    check,
                    &words(&["-O2", "-specs=/tmp/specs"]),
                    Some(unmatched),
                );
                let gating = out.gating.unwrap_or_else(|| {
                    panic!("{}: an unmatched listing withheld nothing", check.id)
                });
                assert_eq!(gating.rule, report::gating_rule::MACRO_SPOOFED);
                assert!(
                    gating.reason.contains(unmatched) && gating.reason.contains(&format!("`{id}`")),
                    "{}: {}",
                    check.id,
                    gating.reason
                );
            }
        }
    }

    #[test]
    fn a_header_search_directory_withholds_a_branching_probes_compile_input_readings() {
        let directories = [
            "-I/srv/i",
            "-I /srv/i",
            "-isystem /srv/s",
            "-isystem=inc",
            "-idirafter/srv/a",
            "-iquote /srv/q",
        ];
        let left = ["-undef", "-pthread", "-Xlinker -I/srv/i", "-Wp,-I/srv/i"];
        let (mut held, mut kept) = (0_usize, 0_usize);
        for (id, macros) in PROBE_MACRO_BRANCHES {
            let probe = probe_named(id);
            for check in probe
                .checks
                .iter()
                .filter(|c| c.channel() != Channel::Macro)
            {
                let compile_input = report::COMPILE_INPUT_READINGS.contains(&check.id);
                for spelling in directories {
                    let mut flags = words(&["-O2"]);
                    flags.extend(words(&spelling.split(' ').collect::<Vec<_>>()));
                    let out =
                        settle_probe_branches(settled_as(Verdict::On), probe, check, &flags, None);
                    if compile_input {
                        let gating = out.gating.unwrap_or_else(|| {
                            panic!("{}: `{spelling}` withheld nothing", check.id)
                        });
                        assert_eq!(gating.rule, report::gating_rule::MACRO_SPOOFED);
                        assert!(
                            gating.reason.contains("header search directory")
                                && toolchain::HEADER_DIRECTORY
                                    .iter()
                                    .all(|w| gating.reason.contains(&format!("`{w}`")))
                                && gating.reason.contains(&format!("`{id}`"))
                                && gating.reason.contains(&format!("`{}`", macros[0])),
                            "{}: {}",
                            check.id,
                            gating.reason
                        );
                        held += 1;
                    } else {
                        assert_eq!(out.verdict, Verdict::On, "{}: `{spelling}`", check.id);
                        assert!(out.gating.is_none(), "{}: `{spelling}`", check.id);
                        kept += 1;
                    }
                }
                for spelling in left {
                    let mut flags = words(&["-O2"]);
                    flags.extend(words(&spelling.split(' ').collect::<Vec<_>>()));
                    let out =
                        settle_probe_branches(settled_as(Verdict::On), probe, check, &flags, None);
                    assert!(out.gating.is_none(), "{}: `{spelling}`", check.id);
                    kept += 1;
                }
            }
        }
        assert_eq!(
            held,
            3 * directories.len(),
            "three compile-input readings, each spelling"
        );
        // The other readings, counted from the table.
        let non_macro: usize = PROBE_MACRO_BRANCHES
            .iter()
            .map(|(id, _)| {
                probe_named(id)
                    .checks
                    .iter()
                    .filter(|c| c.channel() != Channel::Macro)
                    .count()
            })
            .sum();
        assert_eq!(
            kept,
            (non_macro - 3) * directories.len() + non_macro * left.len(),
            "the eight other readings under each directory spelling, and every reading \
             under each word left alone ({non_macro} non-macro readings)"
        );
    }

    #[test]
    fn a_list_defining_nothing_a_probe_branches_on_leaves_its_checks_as_they_were() {
        for (id, macros) in PROBE_MACRO_BRANCHES {
            let probe = probe_named(id);
            for check in probe
                .checks
                .iter()
                .filter(|c| c.channel() != Channel::Macro)
            {
                let other = COMPILER_DEFINED_MACROS
                    .iter()
                    .chain(COMPILER_IDENTITY_MACROS)
                    .find(|m| !macros.contains(m))
                    .expect("a watched macro outside the row");
                let out = settle_probe_branches(
                    settled_as(Verdict::On),
                    probe,
                    check,
                    &words(&[&format!("-D{other}=1")]),
                    None,
                );
                assert_eq!(out.verdict, Verdict::On, "{}: {other}", check.id);
                assert!(out.gating.is_none());
                let out = settle_probe_branches(
                    settled_as(Verdict::On),
                    probe,
                    check,
                    &words(&["-O2", "-DNDEBUG"]),
                    None,
                );
                assert_eq!(out.verdict, Verdict::On);
                let declared = Settled {
                    verdict: Verdict::Unsupported,
                    gating: Some(report::Gating {
                        rule: report::gating_rule::LIBC_DECLARED,
                        arch: None,
                        libc: None,
                        needs_vm: false,
                        reason: "declared".to_owned(),
                    }),
                    level: None,
                };
                let out = settle_probe_branches(
                    declared,
                    probe,
                    check,
                    &words(&[&format!("-D{}", macros[0])]),
                    Some("differs"),
                );
                assert_eq!(out.verdict, Verdict::Unsupported);
                assert_eq!(
                    out.gating.map(|g| g.rule),
                    Some(report::gating_rule::LIBC_DECLARED)
                );
            }
        }
        let outside = probe_named("stack-canary");
        let out = settle_probe_branches(
            settled_as(Verdict::On),
            outside,
            &outside.checks[0],
            &words(&[
                "-D__CET__=3",
                "-D__OPTIMIZE__",
                "-D__clang__",
                "-include /tmp/h.h",
            ]),
            Some("differs"),
        );
        assert_eq!(out.verdict, Verdict::On);
        assert!(out.gating.is_none());
    }

    #[test]
    fn a_cxx_probe_uses_cxxflags_only_where_the_distribution_keeps_them_apart() {
        let separate = Profile {
            id: "test".to_owned(),
            flags_source: "builtin".to_owned(),
            cflags: vec!["-DC_SIDE".to_owned()],
            cxxflags: vec!["-DCXX_SIDE".to_owned()],
            ldflags: vec!["-Wl,-z,now".to_owned()],
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };

        assert_eq!(
            variant_flags(&separate, Lang::Cxx, &[]),
            vec!["-DCXX_SIDE", "-Wl,-z,now"],
            "a C++ probe must be built with the C++ flag list where one exists"
        );
        assert_eq!(
            variant_flags(&separate, Lang::C, &[]),
            vec!["-DC_SIDE", "-Wl,-z,now"],
            "a C probe must not pick up CXXFLAGS"
        );

        // No separate set: the C++ probe falls back rather than being built flagless.
        let shared = Profile {
            cxxflags: Vec::new(),
            ..separate.clone()
        };
        assert_eq!(
            variant_flags(&shared, Lang::Cxx, &[]),
            vec!["-DC_SIDE", "-Wl,-z,now"],
            "an empty CXXFLAGS means the distribution keeps one list, not none"
        );

        // `extra` is appended last so a control flag wins over the profile.
        assert_eq!(
            variant_flags(&shared, Lang::C, &["-fno-stack-protector"]),
            vec!["-DC_SIDE", "-Wl,-z,now", "-fno-stack-protector"],
            "a control flag that did not come last would be overridden by the profile"
        );
    }

    #[test]
    fn a_control_arm_is_built_for_the_target_the_profile_selects() {
        let check = |probe: &str, id: &str| -> &'static Check {
            probe::find(probe)
                .expect("the probe is in the corpus")
                .checks
                .iter()
                .find(|c| c.id == id)
                .expect("the check is in the probe")
        };
        let profile = Profile {
            id: "explicit".to_owned(),
            flags_source: "cli".to_owned(),
            cflags: vec!["-O2".to_owned(), "-m32".to_owned()],
            cxxflags: Vec::new(),
            ldflags: vec!["-fuse-ld=bfd".to_owned()],
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        let marked = check("link-defaults", "cet-marked");
        assert_eq!(
            arm_flags(marked, &profile, Lang::C, marked.positive),
            vec!["-m32", "-fuse-ld=bfd", "-fcf-protection=full"],
            "an elf-static arm carries the target, then the linker, then its own flags"
        );
        let cet_macro = check("toolchain-macros", "cet-macro");
        assert_eq!(
            arm_flags(cet_macro, &profile, Lang::C, cet_macro.positive),
            vec!["-m32", "-fcf-protection=full"],
            "a macro arm carries the target and not the linker"
        );
        assert_eq!(
            arm_flags(marked, &profile, Lang::C, &[]),
            vec!["-m32", "-fuse-ld=bfd"],
            "a check with no negative of its own builds that arm for the target"
        );
        let untargeted = Profile {
            cflags: vec!["-O2".to_owned()],
            ldflags: Vec::new(),
            ..profile.clone()
        };
        assert_eq!(
            arm_flags(marked, &untargeted, Lang::C, marked.positive),
            vec!["-fcf-protection=full"],
            "a profile selecting nothing leaves the arm its own flags"
        );
        let rooted = Profile {
            cflags: vec![
                "-O2".to_owned(),
                "--sysroot".to_owned(),
                "/srv/root".to_owned(),
            ],
            ldflags: vec!["--sysroot=/srv/root".to_owned()],
            ..profile.clone()
        };
        assert_eq!(
            arm_flags(marked, &rooted, Lang::C, marked.positive),
            vec![
                "--sysroot",
                "/srv/root",
                "--sysroot=/srv/root",
                "-fcf-protection=full"
            ],
            "an elf-static arm carries the system root the profile builds against"
        );
        assert_eq!(
            arm_flags(cet_macro, &rooted, Lang::C, cet_macro.positive),
            vec![
                "--sysroot",
                "/srv/root",
                "--sysroot=/srv/root",
                "-fcf-protection=full"
            ],
            "a macro arm reads the system root's headers"
        );
    }

    /// Every runtime selection spelling `toolchain::runtime_selecting_flags` takes, one
    /// value each.
    const RUNTIME_SPELLINGS: [&str; 38] = [
        "-stdlib=libc++",
        "--stdlib=libc++",
        "--stdlib libc++",
        "-stdlib++-isystem /srv/v1",
        "-stdlib++-isystem/srv/v1",
        "--rtlib=compiler-rt",
        "-rtlib=compiler-rt",
        "--rtlib compiler-rt",
        "--unwindlib=libunwind",
        "-unwindlib=libunwind",
        "--gcc-toolchain=/srv/g",
        "--gcc-install-dir=/srv/g/lib/gcc/t/16",
        "--gcc-triple=x86_64-other-linux-gnu",
        "-resource-dir=/srv/rd",
        "-resource-dir /srv/rd",
        "-B/srv/b",
        "-B /srv/b",
        "--prefix=/srv/p",
        "--prefix /srv/p",
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

    /// Every header selection spelling `toolchain::header_selecting_flags` takes, from its
    /// own lists: each valued option joined, as two tokens, and joined to a `=dir` value,
    /// and each whole word; `-I-` beside them.
    fn header_spellings() -> Vec<String> {
        let mut spellings = Vec::new();
        for option in toolchain::HEADER_VALUED {
            spellings.push(format!("{option}/srv/v"));
            spellings.push(format!("{option} /srv/v"));
            spellings.push(format!("{option}=rel"));
        }
        spellings.push("-I-".to_owned());
        spellings.extend(toolchain::HEADER_WHOLE.iter().map(|w| (*w).to_owned()));
        spellings
    }

    #[test]
    fn a_control_arm_is_built_against_the_runtime_the_profile_selects() {
        arms_carry_every_spelling(&RUNTIME_SPELLINGS, true);
    }

    #[test]
    fn a_control_arm_is_built_against_the_headers_the_profile_selects() {
        let spellings = header_spellings();
        assert_eq!(spellings.len(), 21, "every list of the reader is fed");
        let spellings: Vec<&str> = spellings.iter().map(String::as_str).collect();
        arms_carry_every_spelling(&spellings, false);
    }

    #[test]
    fn the_stand_in_selection_is_what_the_arms_carry() {
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let profile = Profile {
            id: "explicit".to_owned(),
            flags_source: "cli".to_owned(),
            cflags: words(
                "-O2 -m32 --gcc-toolchain=/srv/g -I/srv/i -include /srv/f.h -undef \
                 -imacros /srv/m.h -D_FORTIFY_SOURCE=3 -fstack-protector-strong",
            ),
            cxxflags: Vec::new(),
            ldflags: words("-fuse-ld=bfd --rtlib=compiler-rt -pthread -Wl,-z,now"),
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        let mut fed = 0_usize;
        for probe in probe::CORPUS {
            let measured = variant_flags(&profile, probe.lang, &[]);
            let stand_in = stand_in_selection(&profile, probe.lang, &measured);
            assert_eq!(
                stand_in,
                words(
                    "-m32 --gcc-toolchain=/srv/g --rtlib=compiler-rt -I/srv/i -include /srv/f.h \
                     -undef -imacros /srv/m.h -pthread"
                ),
                "{}: the clean build's selection, then the header selection",
                probe.id
            );
            for check in probe
                .checks
                .iter()
                .filter(|c| !c.measures_toolchain_default)
            {
                let mut want = stand_in.clone();
                if check.channel() != Channel::Macro {
                    want.extend(words("-fuse-ld=bfd"));
                }
                assert_eq!(
                    arm_flags(check, &profile, probe.lang, &[]),
                    want,
                    "{}'s arm carries the stand-in's selection and nothing else of the profile",
                    check.id
                );
                fed = fed.saturating_add(1);
            }
        }
        let reading_the_measured_build = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .filter(|c| !c.measures_toolchain_default)
            .count();
        assert_eq!(
            fed, reading_the_measured_build,
            "every check that reads the measured build was fed"
        );
    }

    #[test]
    fn the_arms_carry_a_two_token_value_once() {
        // (the profile's cflags, what every arm carries, what the clean build carries)
        let shapes = [
            (
                "-O2 -fstack-protector-strong --library-directory -B/srv/px/",
                "--library-directory -B/srv/px/",
                "--library-directory -B/srv/px/",
            ),
            (
                "-O2 -L -I/srv/i -D_FORTIFY_SOURCE=3",
                "-L -I/srv/i",
                "-L -I/srv/i",
            ),
            ("-O2 -B -pthread", "-B -pthread", "-B -pthread"),
            (
                "-O2 --stdlib -pthread -fPIE",
                "--stdlib -pthread",
                "--stdlib -pthread",
            ),
            ("-O2 -I -m32", "-I -m32", ""),
            ("-O2 -L -fuse-ld=lld", "-L -fuse-ld=lld", "-L -fuse-ld=lld"),
            (
                "-O2 -include-pch /srv/p.pch -B/srv/px/",
                "-B/srv/px/",
                "-B/srv/px/",
            ),
            // The order the arms carry the projections: target, runtime, header, then
            // the linker's program flags on the arms that link.
            (
                "-O2 -I/srv/i -B/srv/px/ -m32",
                "-m32 -B/srv/px/ -I/srv/i",
                "-m32 -B/srv/px/",
            ),
            (
                "-O2 -Xarch_x86_64 -B/srv/px/",
                "-Xarch_x86_64 -B/srv/px/",
                "-Xarch_x86_64 -B/srv/px/",
            ),
            (
                "-O2 -Xpreprocessor -isysroot -Xpreprocessor -B/srv/px/",
                "-Xpreprocessor -isysroot -Xpreprocessor -B/srv/px/",
                "-Xpreprocessor -isysroot -Xpreprocessor -B/srv/px/",
            ),
            // The value of an option that selects nothing is the option's.
            ("-O2 -u -B/srv/px/", "", ""),
            ("-O2 -MF -L/srv/x -fPIE", "", ""),
            ("-O2 -o -I/srv/i", "", ""),
            ("-O2 -D -m32", "", ""),
            ("-O2 -z -fuse-ld=lld", "", ""),
            ("-O2 -m32 -u -B/srv/px/ -I/srv/i", "-m32 -I/srv/i", "-m32"),
        ];
        arms_and_clean_carry(&shapes);
    }

    /// Each shape's arms and clean build, for a macro check and a linking check: (the
    /// profile's cflags, what every arm carries, what the clean build carries), every shape
    /// fed to both checks and counted.
    fn arms_and_clean_carry(shapes: &[(&str, &str, &str)]) {
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let checks: Vec<&'static Check> = [
            ("link-defaults", "cet-marked"),
            ("toolchain-macros", "cet-macro"),
        ]
        .iter()
        .map(|(probe, id)| {
            probe::find(probe)
                .expect("the probe is in the corpus")
                .checks
                .iter()
                .find(|c| c.id == *id)
                .expect("the check is in the probe")
        })
        .collect();
        let mut fed = 0_usize;
        for (cflags, arm, clean) in shapes {
            let profile = Profile {
                id: "explicit".to_owned(),
                flags_source: "cli".to_owned(),
                cflags: words(cflags),
                cxxflags: Vec::new(),
                ldflags: Vec::new(),
                toolchain_note: None,
                compiler_environment: compile::CompilerEnvironment::of_this_run(),
            };
            for check in &checks {
                assert_eq!(
                    arm_flags(check, &profile, Lang::C, &[]),
                    words(arm),
                    "{cflags}: {}'s arm carries the measured line's words once",
                    check.id
                );
                fed = fed.saturating_add(1);
            }
            assert_eq!(
                clean_flags(&profile, Lang::C),
                words(clean),
                "{cflags}: the clean build carries the target and runtime words once"
            );
        }
        assert_eq!(
            fed,
            shapes.len() * checks.len(),
            "every shape reached both arms"
        );
    }

    #[test]
    fn the_arms_carry_gccs_long_spellings_as_the_selections_they_are() {
        let shapes = [
            (
                "-O2 --machine 32 -I/srv/i",
                "--machine 32 -I/srv/i",
                "--machine 32",
            ),
            (
                "-O2 --machine=32 --machine-64",
                "--machine=32 --machine-64",
                "--machine=32 --machine-64",
            ),
            (
                "-O2 --li /srv/x --pref /srv/px/ --im /srv/m.h",
                "--li /srv/x --pref /srv/px/ --im /srv/m.h",
                "--li /srv/x --pref /srv/px/",
            ),
            ("-O2 --def -m32 --forc -B/srv/px/", "", ""),
            ("-O2 --std -m32 --machine -I/srv/i", "", ""),
            (
                "-O2 --include-directory /srv/i --include=/srv/h.h -fPIE",
                "--include-directory /srv/i --include=/srv/h.h",
                "",
            ),
        ];
        arms_and_clean_carry(&shapes);
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert!(
            toolchain::selects_target(&words("-O2 --machine 32"))
                && toolchain::selects_target(&words("--machine=64"))
                && !toolchain::selects_target(&words("--machine")),
            "`--machine 32` chooses the target as `-m32` does; `--machine` alone chooses none"
        );
    }

    #[test]
    fn the_default_asking_checks_are_the_assembly_probes() {
        let mut fed = 0_usize;
        for probe in probe::CORPUS {
            let assembly = Path::new(probe.source_name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("s"));
            for check in probe.checks {
                assert_eq!(
                    check.measures_toolchain_default, assembly,
                    "{}: a default-asking check is an assembly probe's and the reverse",
                    check.id
                );
                fed = fed.saturating_add(1);
            }
        }
        let checks = probe::CORPUS.iter().map(|p| p.checks.len()).sum::<usize>();
        assert_eq!(fed, checks, "every check was fed");
    }

    /// Both arms of a macro check and of two linking checks carry each of `spellings`
    /// first, from either flag list, and then only the arm's own flags; the clean build
    /// carries it too where `clean_carries`, and nothing of it otherwise.
    fn arms_carry_every_spelling(spellings: &[&str], clean_carries: bool) {
        let checks: Vec<&'static Check> = [
            ("link-defaults", "cet-marked"),
            ("toolchain-macros", "cet-macro"),
            ("cxx-stdlib-assertions", "cxx-stdlib-assertions"),
        ]
        .iter()
        .map(|(probe, id)| {
            probe::find(probe)
                .expect("the probe is in the corpus")
                .checks
                .iter()
                .find(|c| c.id == *id)
                .expect("the check is in the probe")
        })
        .collect();
        let channels: BTreeSet<String> = checks
            .iter()
            .map(|c| format!("{:?}", c.channel()))
            .collect();
        assert!(
            channels.contains("Macro") && channels.len() >= 2,
            "the macro channel and at least one linking channel are fed: {channels:?}"
        );
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let mut fed = 0_usize;
        for spelling in spellings {
            let selection = words(spelling);
            for in_ldflags in [false, true] {
                let (cflags, ldflags) = if in_ldflags {
                    (words("-O2"), selection.clone())
                } else {
                    (
                        [words("-O2"), selection.clone()].concat(),
                        words("-Wl,-z,now"),
                    )
                };
                let profile = Profile {
                    id: "explicit".to_owned(),
                    flags_source: "cli".to_owned(),
                    cflags,
                    cxxflags: Vec::new(),
                    ldflags,
                    toolchain_note: None,
                    compiler_environment: compile::CompilerEnvironment::of_this_run(),
                };
                for check in &checks {
                    let lang = probe::CORPUS
                        .iter()
                        .find(|p| p.checks.iter().any(|c| c.id == check.id))
                        .expect("the check's probe")
                        .lang;
                    for arm in [check.positive, check.negative] {
                        let mut want = selection.clone();
                        want.extend(arm.iter().map(|s| (*s).to_owned()));
                        assert_eq!(
                            arm_flags(check, &profile, lang, arm),
                            want,
                            "{}'s arm carries `{spelling}` (in ldflags: {in_ldflags}), then \
                             its own flags",
                            check.id
                        );
                        fed = fed.saturating_add(1);
                    }
                    if clean_carries {
                        assert_eq!(
                            clean_flags(&profile, lang),
                            selection,
                            "the clean build carries `{spelling}` and nothing that hardens"
                        );
                    } else {
                        assert!(
                            clean_flags(&profile, lang).is_empty(),
                            "the clean build carries nothing of `{spelling}`"
                        );
                    }
                }
            }
        }
        assert_eq!(
            fed,
            spellings.len() * 2 * checks.len() * 2,
            "every spelling, from either list, reached both arms of every check"
        );
    }

    #[test]
    fn an_arm_reads_the_runtime_of_its_own_language_after_the_target() {
        let check = |probe: &str, id: &str| -> &'static Check {
            probe::find(probe)
                .expect("the probe is in the corpus")
                .checks
                .iter()
                .find(|c| c.id == id)
                .expect("the check is in the probe")
        };
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let marked = check("link-defaults", "cet-marked");
        let cxx = check("cxx-stdlib-assertions", "cxx-stdlib-assertions");
        let both = Profile {
            id: "explicit".to_owned(),
            flags_source: "cli".to_owned(),
            cflags: words("-O2 -m32 --gcc-toolchain=/srv/g -I/srv/i -fcf-protection=full"),
            cxxflags: words("-O2 -m32 -stdlib=libc++"),
            ldflags: words("-fuse-ld=bfd --rtlib=compiler-rt -pthread"),
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        assert_eq!(
            arm_flags(marked, &both, Lang::C, marked.positive),
            words(
                "-m32 --gcc-toolchain=/srv/g --rtlib=compiler-rt -I/srv/i -pthread -fuse-ld=bfd \
                 -fcf-protection=full"
            ),
            "the target, then the runtime, then the headers, then the linker, then the arm's own"
        );
        assert_eq!(
            arm_flags(cxx, &both, Lang::Cxx, cxx.positive)
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>(),
            words("-m32 -stdlib=libc++ --rtlib=compiler-rt"),
            "a C++ arm reads the C++ list's runtime, not the C list's"
        );
        // The header selection is the language's own list's too, whole arms compared.
        let split = Profile {
            cflags: words("-O2 -I/srv/c -include /srv/c.h"),
            cxxflags: words("-O2 -isystem /srv/cxx -pthread"),
            ldflags: words("-fuse-ld=bfd"),
            ..both
        };
        assert_eq!(
            arm_flags(cxx, &split, Lang::Cxx, cxx.positive),
            [
                words("-isystem /srv/cxx -pthread -fuse-ld=bfd"),
                words(&cxx.positive.join(" "))
            ]
            .concat(),
            "a C++ arm carries the C++ list's header words and none of the C list's"
        );
        assert_eq!(
            arm_flags(marked, &split, Lang::C, marked.positive),
            [
                words("-I/srv/c -include /srv/c.h -fuse-ld=bfd"),
                words(&marked.positive.join(" "))
            ]
            .concat(),
            "a C arm carries the C list's header words and none of the C++ list's"
        );
    }

    #[test]
    fn the_clean_build_is_built_for_the_target_the_arms_are() {
        let probe = probe::CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.measures_toolchain_default))
            .expect("the corpus carries a default-asking check");
        let check = probe
            .checks
            .iter()
            .find(|c| c.measures_toolchain_default)
            .expect("found above");
        let profile = Profile {
            id: "explicit".to_owned(),
            flags_source: "cli".to_owned(),
            cflags: vec!["-O2".to_owned(), "-m32".to_owned()],
            cxxflags: Vec::new(),
            ldflags: vec!["-fuse-ld=bfd".to_owned(), "-Wl,-z,noexecstack".to_owned()],
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        let clean = clean_flags(&profile, probe.lang);
        assert_eq!(
            clean,
            vec!["-m32"],
            "the target and nothing that hardens or links"
        );
        let target = |flags: &[String]| toolchain::target_selecting_flags(flags);
        for arm in [check.positive, check.negative] {
            assert_eq!(
                target(&arm_flags(check, &profile, probe.lang, arm)),
                target(&clean),
                "an arm and the clean build it vouches for select one target"
            );
        }
        let untargeted = Profile {
            cflags: vec!["-O2".to_owned()],
            ..profile.clone()
        };
        assert!(
            clean_flags(&untargeted, probe.lang).is_empty(),
            "a profile selecting no target leaves the clean build flagless"
        );
        let rooted = Profile {
            cflags: vec!["-O2".to_owned(), "--sysroot=/srv/root".to_owned()],
            ..profile.clone()
        };
        let clean = clean_flags(&rooted, probe.lang);
        assert_eq!(
            clean,
            vec!["--sysroot=/srv/root"],
            "the system root and nothing that hardens or links"
        );
        for arm in [check.positive, check.negative] {
            assert_eq!(
                target(&arm_flags(check, &rooted, probe.lang, arm)),
                target(&clean),
                "an arm and the clean build it vouches for read one system root"
            );
        }
        let searched = Profile {
            cflags: vec!["--sysroot=/srv/root".to_owned(), "-O2".to_owned()],
            ldflags: vec![
                "-L/srv/root/usr/lib/gcc/t/16".to_owned(),
                "-Wl,-z,now".to_owned(),
            ],
            ..profile.clone()
        };
        let clean = clean_flags(&searched, probe.lang);
        assert_eq!(
            clean,
            vec!["--sysroot=/srv/root", "-L/srv/root/usr/lib/gcc/t/16"],
            "the root and the library directory, from either flag list, and nothing that \
             hardens"
        );
        for arm in [check.positive, check.negative] {
            assert_eq!(
                target(&arm_flags(check, &searched, probe.lang, arm)),
                target(&clean),
                "an arm and the clean build it vouches for search one set of directories"
            );
        }
    }

    #[test]
    fn a_default_asking_checks_arms_carry_no_header_word() {
        let probe = probe::CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.measures_toolchain_default))
            .expect("the corpus carries a default-asking check");
        let check = probe
            .checks
            .iter()
            .find(|c| c.measures_toolchain_default)
            .expect("found above");
        let included = Profile {
            id: "explicit".to_owned(),
            flags_source: "cli".to_owned(),
            cflags: vec![
                "-O2".to_owned(),
                "-include".to_owned(),
                "/srv/forced.h".to_owned(),
                "-m32".to_owned(),
            ],
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        assert_eq!(
            clean_flags(&included, probe.lang),
            vec!["-m32"],
            "the clean build carries the target and nothing of the profile's headers"
        );
        for arm in [check.positive, check.negative] {
            let flags = arm_flags(check, &included, probe.lang, arm);
            assert!(
                !flags.iter().any(|f| f == "-include"),
                "a default-asking check's arm stands on the clean build's footing and carries \
                 no header word: {flags:?}"
            );
            assert_eq!(flags.first().map(String::as_str), Some("-m32"), "{flags:?}");
        }
        let mut cflags = vec!["-O2".to_owned(), "-m32".to_owned()];
        cflags.extend(
            header_spellings()
                .iter()
                .flat_map(|s| s.split_whitespace().map(str::to_owned)),
        );
        let every = Profile {
            cflags,
            ..included.clone()
        };
        let mut want: Vec<String> = vec!["-m32".to_owned()];
        want.extend(check.positive.iter().map(|s| (*s).to_owned()));
        assert_eq!(
            arm_flags(check, &every, probe.lang, check.positive),
            want,
            "under every spelling of the reader's lists the default-asking arm carries the \
             target and its own flags alone"
        );
        let other = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter().map(move |c| (p.lang, c)))
            .find(|(_, c)| !c.measures_toolchain_default && c.channel() == Channel::Macro)
            .expect("the corpus carries a macro check that reads the measured build");
        assert_eq!(
            arm_flags(other.1, &included, other.0, other.1.positive)
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>(),
            vec!["-m32", "-include", "/srv/forced.h"],
            "a check that reads the measured build carries the header word after the target"
        );
    }

    #[test]
    fn a_profile_carrying_either_flag_list_is_not_clean() {
        let empty = Profile {
            id: "bare".to_owned(),
            flags_source: "builtin".to_owned(),
            cflags: Vec::new(),
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        };
        assert!(Conditions::profile_is_clean(&empty));

        let with_cflags = Profile {
            cflags: vec!["-O2".to_owned()],
            ..empty.clone()
        };
        assert!(!Conditions::profile_is_clean(&with_cflags));

        let with_ldflags = Profile {
            ldflags: vec!["-Wl,-z,now".to_owned()],
            ..empty.clone()
        };
        assert!(
            !Conditions::profile_is_clean(&with_ldflags),
            "a linker-only profile still changes the artifact under measurement"
        );

        // A distribution that hardens only its C++ builds supplies CXXFLAGS alone, and a
        // profile read as clean compiles no measured build at all.
        let with_cxxflags = Profile {
            cxxflags: vec!["-D_GLIBCXX_ASSERTIONS".to_owned()],
            ..empty.clone()
        };
        assert!(
            !Conditions::profile_is_clean(&with_cxxflags),
            "a C++-only flag list is a profile, and the C++ probes are built with it"
        );

        let with_both = Profile {
            cflags: vec!["-O2".to_owned()],
            ldflags: vec!["-Wl,-z,now".to_owned()],
            ..empty.clone()
        };
        assert!(!Conditions::profile_is_clean(&with_both));
    }

    #[test]
    fn a_default_asking_check_reads_the_clean_build_and_only_that_check_does() {
        let declared: Vec<&str> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.measures_toolchain_default)
            .map(|c| c.id)
            .collect();
        assert_eq!(
            declared,
            ["linker-default-noexecstack"],
            "a check reading the clean build is a check whose question is about the \
             toolchain rather than about the profile; adding one is a claim worth reading"
        );

        let check = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == "linker-default-noexecstack")
            .expect("the corpus carries the check the rule was written for");
        assert!(
            report::openssf_tldr_cflags("x86_64")
                .iter()
                .any(|f| f == check.positive[0]),
            "the confound is that the profile supplies this check's own positive control; \
             if that stops being true the rule needs re-arguing rather than keeping"
        );

        let named = |name: &str| {
            let mut v = blank_variant();
            let mut build = variant_build(0, true);
            build.argv = vec![name.to_owned()];
            v.build = Some(build);
            v
        };
        let clean = named("clean");
        let measured = named("measured");
        let arg_of = |v: &Variant| v.build.as_ref().expect("built").argv[0].clone();

        assert_eq!(
            arg_of(subject_variant(check, &clean, &measured)),
            "clean",
            "a default-asking check must not read a build the profile touched"
        );

        let ordinary = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| !c.measures_toolchain_default)
            .expect("every other check measures the profile");
        assert_eq!(
            arg_of(subject_variant(ordinary, &clean, &measured)),
            "measured",
            "every other check is asking what the profile's flags did"
        );
    }

    /// Real stored ELF facts with only `self_report` varied, deserialized so a new
    /// `ElfFacts` field fails here instead of defaulting; `truncations` and `symbol_tables`
    /// default, to a whole artifact with no symbol table.
    fn elf_with_report(self_report: &str) -> elf::ElfFacts {
        serde_json::from_value(serde_json::json!({
            "aarch64_bti": false, "aarch64_pac": false, "bind_now": false,
            "df_1_noopen": false, "df_1_pie": false, "dt_debug": false,
            "dt_relr": false, "dt_soname": false,
            "dynamic_tags": [], "elf_class": 64, "elf_data": "little-endian", "elf_type": "ET_EXEC",
            "aarch64_gcs": false, "gnu_property_types": [], "gnu_relro": true,
            "gnu_stack_executable": false, "gnu_stack_present": true,
            "has_dynamic": true, "has_interp": true, "machine": "x86_64",
            "needed": [], "pie": false, "recorded_command_line": "",
            "relro": "partial", "rpath": [], "runpath": [], "sections": [],
            "self_report": self_report, "shared_object": false, "static_pie": false,
            "statically_linked": false, "symbol_count": 35, "textrel": false,
            "watched_symbols": {}, "x86_ibt": false, "x86_shstk": false,
        }))
        .expect("fixture matches ElfFacts")
    }

    /// A [`Variant`] with everything absent, for tests that vary one field.
    fn blank_variant() -> Variant {
        Variant {
            macros: BTreeMap::new(),
            macros_preprocessor: BTreeMap::new(),
            macro_source: "preprocessor",
            macro_dump: None,
            elf: None,
            build: None,
            run: None,
            run_error: None,
            elf_error: None,
            unwitnessed: None,
            artifact: None,
            structured: None,
            workdir: None,
        }
    }

    /// A build that exited with `status` and produced an artifact digest or not.
    fn variant_build(status: i32, artifact: bool) -> compile::BuildRecord {
        compile::BuildRecord {
            argv: vec!["/usr/bin/cc".to_owned()],
            dropped_flags: Vec::new(),
            exit_status: status,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 1,
            artifact_sha256: artifact.then(|| "0".repeat(64)),
            stdout_sha256: None,
            stdout_unterminated: false,
        }
    }

    /// A real probe, for the `context` field, so the id in the assertions is a real one.
    fn some_probe() -> &'static Probe {
        probe::find("link-defaults").expect("the probe is in the corpus")
    }

    #[test]
    fn a_build_that_exited_zero_and_wrote_nothing_is_reported_for_the_arm_that_did_it() {
        let probe = some_probe();
        for (tag, dirty_clean) in [("clean", true), ("measured", false)] {
            let mut clean = blank_variant();
            let mut bare = blank_variant();
            let target = if dirty_clean { &mut clean } else { &mut bare };
            target.build = Some(variant_build(0, false));

            let faults = evidence_faults(probe, &clean, &bare);
            assert_eq!(faults.len(), 1, "{tag}: {faults:?}");
            assert_eq!(faults[0].severity, Severity::Error);
            assert!(
                faults[0]
                    .message
                    .contains(&format!("the {tag} build exited 0")),
                "{tag}: {}",
                faults[0].message
            );
            assert_eq!(faults[0].context.as_deref(), Some(probe.id));
        }

        // A build that wrote its artifact is no fault, and a failed one is a verdict.
        let mut built = blank_variant();
        built.build = Some(variant_build(0, true));
        assert!(
            evidence_faults(probe, &built, &blank_variant()).is_empty(),
            "a build that exited 0 and wrote its artifact raises no fault"
        );

        let mut failed = blank_variant();
        failed.build = Some(variant_build(1, false));
        assert!(
            evidence_faults(probe, &failed, &blank_variant()).is_empty(),
            "a build that failed is not faulted for writing nothing"
        );
    }

    #[test]
    fn an_unreadable_artifact_names_the_arm_and_the_reason() {
        let probe = some_probe();
        for (tag, dirty_clean) in [("clean", true), ("measured", false)] {
            let mut clean = blank_variant();
            let mut bare = blank_variant();
            let target = if dirty_clean { &mut clean } else { &mut bare };
            target.elf_error = Some(report::ArtifactRefusal {
                why: "not an ELF file".to_owned(),
                mach_o: false,
            });

            let faults = evidence_faults(probe, &clean, &bare);
            assert_eq!(faults.len(), 1, "{tag}: {faults:?}");
            assert!(
                faults[0]
                    .message
                    .contains(&format!("the {tag} artifact linked")),
                "{tag}: {}",
                faults[0].message
            );
            assert!(
                faults[0].message.contains("not an ELF file"),
                "the reason has to reach the report or the contradiction is unresolvable"
            );
        }
    }

    /// `(name, value)` pairs as a macro map.
    fn macro_pairs(list: &[(&str, &str)]) -> BTreeMap<String, String> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// A `.chard.report` as `probes/chard_selfreport.h` writes one: each entry `name=value`
    /// where defined and `name undefined` where not, between the markers.
    fn written_report(listed: &[(&str, Option<&str>)]) -> String {
        use std::fmt::Write as _;
        let mut text = "CHARD-REPORT-V2\n".to_owned();
        for (name, value) in listed {
            match value {
                Some(value) => writeln!(text, "{name}={value}").expect("a String takes it"),
                None => writeln!(text, "{name} undefined").expect("a String takes it"),
            }
        }
        text.push_str("CHARD-REPORT-END\n");
        text
    }

    /// The faults of a bare variant whose macros came from `source`, beside a dump of
    /// `cpp` whose `-dM -E` job exited `dump`, or no dump where `dump` is `None`; under
    /// `compiled-artifact` the artifact's section lists `listed`.
    fn macro_view_faults(
        listed: &[(&str, Option<&str>)],
        cpp: &[(&str, &str)],
        source: &'static str,
        dump: Option<i32>,
    ) -> Vec<Diagnostic> {
        let mut bare = blank_variant();
        bare.macro_source = source;
        bare.macros_preprocessor = macro_pairs(cpp);
        bare.macro_dump = dump.map(|status| variant_build(status, false));
        if source == "compiled-artifact" {
            let facts = elf_with_report(&written_report(listed));
            bare.macros = report::self_report_entries(&facts).expect("the report reads");
            bare.elf = Some(facts);
        } else {
            bare.macros = bare.macros_preprocessor.clone();
        }
        evidence_faults(some_probe(), &blank_variant(), &bare)
    }

    /// [`macro_view_faults`] beside a dump that exited 0.
    fn macro_view_faults_dumped(
        listed: &[(&str, Option<&str>)],
        cpp: &[(&str, &str)],
        source: &'static str,
    ) -> Vec<Diagnostic> {
        macro_view_faults(listed, cpp, source, Some(0))
    }

    #[test]
    fn the_two_macro_views_are_compared_on_every_listed_entry_in_both_directions() {
        let faults_for = macro_view_faults_dumped;

        // Macros from the preprocessor are one view, not two.
        assert!(
            faults_for(&[], &[("__PIE__", "0")], "preprocessor").is_empty(),
            "with no artifact there is nothing to compare the preprocessor against"
        );

        assert!(
            faults_for(
                &[("__PIE__", Some("2")), ("__CET__", None)],
                &[("__PIE__", "2")],
                "compiled-artifact"
            )
            .is_empty(),
            "views that agree on a defined and an undefined entry raise no fault"
        );

        for (listed, cpp, expected) in [
            (
                &[("__PIE__", Some("2"))][..],
                &[("__PIE__", "0")][..],
                "__PIE__: codegen=2 cpp=0",
            ),
            (
                &[("__PIE__", Some("2"))][..],
                &[("__STDC_VERSION__", "201710L")][..],
                "__PIE__: codegen=2 cpp=<undefined>",
            ),
            (
                &[("__PIE__", None)][..],
                &[("__STDC_VERSION__", "201710L"), ("__PIE__", "2")][..],
                "__PIE__: codegen=<undefined> cpp=2",
            ),
        ] {
            let faults = faults_for(listed, cpp, "compiled-artifact");
            assert_eq!(faults.len(), 1, "{listed:?} vs {cpp:?}");
            assert_eq!(faults[0].severity, Severity::Warning);
            assert!(
                faults[0].message.contains(expected)
                    && faults[0].message.contains("disagree about 1 macro(s)"),
                "{listed:?} vs {cpp:?}: {}",
                faults[0].message
            );
        }

        assert!(
            faults_for(
                &[("__PIE__", Some("2"))],
                &[("__PIE__", "2"), ("__STDC_VERSION__", "201710L")],
                "compiled-artifact"
            )
            .is_empty(),
            "a macro the self-report does not list is not a divergence"
        );
    }

    #[test]
    fn a_probe_with_no_dump_read_publishes_no_disagreement() {
        let faults_with = macro_view_faults;
        // No dump ran: one view, whatever the self-report says.
        let self_report = [
            ("__GNUC__", Some("16")),
            ("__GLIBC__", Some("2")),
            ("__STDC_VERSION__", Some("202311L")),
            ("__USE_FORTIFY_LEVEL", Some("0")),
            ("__SSP__", None),
        ];
        assert!(
            faults_with(&self_report, &[], "compiled-artifact", None).is_empty(),
            "no preprocessor job ran, so nothing disagreed with the artifact"
        );
        // Beside a dump that ran, the same report disagrees about all five: the gate is
        // the dump, not the shape of the maps.
        let faults = faults_with(
            &self_report,
            &[("__SSP__", "1")],
            "compiled-artifact",
            Some(0),
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        for entry in [
            "about 5 macro(s)",
            "__GLIBC__: codegen=2 cpp=<undefined>",
            "__GNUC__: codegen=16 cpp=<undefined>",
            "__USE_FORTIFY_LEVEL: codegen=0 cpp=<undefined>",
            "__SSP__: codegen=<undefined> cpp=1",
        ] {
            assert!(faults[0].message.contains(entry), "{}", faults[0].message);
        }
        let faults = faults_with(
            &[("__PIE__", Some("2"))],
            &[("__PIE__", "0")],
            "compiled-artifact",
            Some(1),
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0]
                .message
                .contains("macro channel could not be read"),
            "{}",
            faults[0].message
        );
        // A dump that exited 0 and defined nothing is the same.
        let faults = faults_with(&[("__PIE__", Some("2"))], &[], "compiled-artifact", Some(0));
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0].message.contains("defined no macros"),
            "{}",
            faults[0].message
        );
    }

    #[test]
    fn the_self_reports_summaries_and_spellings_are_not_disagreements() {
        let faults_for = macro_view_faults_dumped;
        // A real divergence warns with the summaries left out: they are not macros.
        let faults = faults_for(
            &[
                ("__SSP_STRONG__", Some("3")),
                ("_FORTIFY_IMPL", Some("glibc")),
                ("_CXX_STDLIB", Some("libstdc++")),
            ],
            &[("__SSP_STRONG__", "2")],
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0]
                .message
                .contains("about 1 macro(s): __SSP_STRONG__: codegen=3 cpp=2"),
            "{}",
            faults[0].message
        );
        assert!(
            faults_for(
                &[
                    ("_FORTIFY_IMPL", Some("glibc")),
                    ("_CXX_STDLIB", None),
                    ("__STDC_VERSION__", Some("201710L"))
                ],
                &[("__STDC_VERSION__", "201710L"), ("_CXX_STDLIB", "x")],
                "compiled-artifact"
            )
            .is_empty(),
            "a summary is compared in neither direction"
        );

        // A mode the headers name is compared as the number it expands to.
        let libcxx = [
            ("_LIBCPP_HARDENING_MODE", "_LIBCPP_HARDENING_MODE_FAST"),
            ("_LIBCPP_HARDENING_MODE_FAST", "2"),
        ];
        assert!(
            faults_for(
                &[("_LIBCPP_HARDENING_MODE", Some("2"))],
                &libcxx,
                "compiled-artifact"
            )
            .is_empty(),
            "the same mode in its two spellings"
        );
        let faults = faults_for(
            &[("_LIBCPP_HARDENING_MODE", Some("8"))],
            &libcxx,
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0]
                .message
                .contains("_LIBCPP_HARDENING_MODE: codegen=8 cpp=2"),
            "{}",
            faults[0].message
        );
        // The other direction reads the expansion too.
        let faults = faults_for(
            &[("_LIBCPP_HARDENING_MODE", None)],
            &libcxx,
            "compiled-artifact",
        );
        assert!(
            faults.len() == 1
                && faults[0]
                    .message
                    .contains("_LIBCPP_HARDENING_MODE: codegen=<undefined> cpp=2"),
            "{faults:?}"
        );
        // A chain is followed to its end, however deep, and a value naming no definition
        // is already the expansion.
        assert_eq!(
            expanded_in_dump(&macro_pairs(&[("A", "B"), ("B", "C"), ("C", "2")]), "A"),
            "2",
            "three steps"
        );
        assert_eq!(expanded_in_dump(&macro_pairs(&[("A", "B")]), "Z"), "Z");
        // A chain that is not libc++'s is followed the same way.
        let faults = faults_for(
            &[("X", Some("1"))],
            &[("X", "Y"), ("Y", "2")],
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0].message.contains("X: codegen=1 cpp=2"),
            "{}",
            faults[0].message
        );
        // A cycle in the dump ends.
        assert_eq!(
            expanded_in_dump(&macro_pairs(&[("A", "B"), ("B", "A")]), "A"),
            "A",
            "two steps over a two-entry cycle"
        );
    }

    #[test]
    fn a_header_settled_macro_one_view_alone_carries_is_a_disagreement() {
        let faults_for = macro_view_faults_dumped;
        let freebsd = [
            ("__SSP_FORTIFY_LEVEL", Some("0")),
            ("__FreeBSD__", Some("15")),
        ];
        let faults = faults_for(&freebsd, &[("__FreeBSD__", "15")], "compiled-artifact");
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0].message.contains(
                "disagree about 1 macro(s): __SSP_FORTIFY_LEVEL: codegen=0 cpp=<undefined>"
            ),
            "{}",
            faults[0].message
        );
        // Agreement is silence: the dump of the same unit settles the same level.
        assert!(
            faults_for(
                &freebsd,
                &[("__FreeBSD__", "15"), ("__SSP_FORTIFY_LEVEL", "0")],
                "compiled-artifact"
            )
            .is_empty(),
            "a dump that settles the level the artifact settles raises no fault"
        );
    }

    #[test]
    fn every_macro_a_predicate_reads_is_compared_in_both_directions() {
        let header = include_str!("../probes/chard_selfreport.h");
        let (read, derived) = self_report_entries(header).expect("the header reads");
        let inputs = summary_inputs(header, &derived).expect("the ladders read");
        // Both channels' predicates: an elf-static check of a probe with a macro-channel
        // check reads the variant's macros too, beside the dump.
        let mut names: Vec<String> = macro_names_the_predicates_read()
            .into_iter()
            .chain(macro_names_read_by(crate::predicate::elf_static::table()))
            .map(|(_, name)| name)
            .collect();
        names.sort_unstable();
        names.dedup();
        // The frame: a pass means "checked N names", not "found nothing to check".
        eprintln!(
            "{} macro name(s) read by the corpus's predicates",
            names.len()
        );
        for anchor in [
            "__EXCEPTIONS",
            "_GLIBCXX_ASSERTIONS",
            "_LIBCPP_HARDENING_MODE",
            "_FORTIFY_HEADERS_H",
            "_FORTIFY_IMPL",
        ] {
            assert!(
                names.iter().any(|n| n == anchor),
                "{anchor} is not read: {names:?}"
            );
        }
        for name in &names {
            let summary = derived.contains(name);
            assert!(
                read.contains(name) || summary,
                "{name} is read by a predicate and is no entry of the self-report, so the \
                 two macro views are never held to each other on it"
            );
            if summary {
                for input in &inputs[name] {
                    assert!(
                        read.contains(input) || input == "__APPLE__",
                        "{name}'s input {input} is no entry"
                    );
                }
            }
        }
        // The dump also defines an unlisted name, so it never reads as defining nothing.
        let faults_for = macro_view_faults_dumped;
        let unlisted = ("CHARD_TEST_UNLISTED", "1");
        let mut fed = 0_usize;
        for name in &read {
            let name = name.as_str();
            for (listed, cpp, entry) in [
                (
                    vec![(name, Some("7"))],
                    vec![unlisted],
                    format!("{name}: codegen=7 cpp=<undefined>"),
                ),
                (
                    vec![(name, None)],
                    vec![unlisted, (name, "7")],
                    format!("{name}: codegen=<undefined> cpp=7"),
                ),
                (
                    vec![(name, Some("20"))],
                    vec![unlisted, (name, "2")],
                    format!("{name}: codegen=20 cpp=2"),
                ),
                (
                    vec![(name, Some("2"))],
                    vec![unlisted, (name, "20")],
                    format!("{name}: codegen=2 cpp=20"),
                ),
            ] {
                fed += 1;
                let faults = faults_for(&listed, &cpp, "compiled-artifact");
                assert!(
                    faults.len() == 1
                        && faults[0].message.contains("disagree about 1 macro(s)")
                        && faults[0].message.contains(&entry),
                    "{name}: {faults:?}"
                );
            }
        }
        assert_eq!(fed, read.len() * 4, "every entry, four shapes each");
    }

    #[test]
    fn every_input_of_a_summary_is_an_entry_of_its_own() {
        let header = include_str!("../probes/chard_selfreport.h");
        let (read, derived) = self_report_entries(header).expect("the header reads");
        let inputs = summary_inputs(header, &derived).expect("the ladders read");
        assert_eq!(inputs.len(), SELF_REPORT_SUMMARIES.len());
        for (summary, names) in &inputs {
            assert!(!names.is_empty(), "{summary} reads nothing");
            for name in names {
                assert!(
                    read.contains(name) || name == "__APPLE__",
                    "{summary} reads {name}, which is no entry"
                );
            }
        }
        assert!(inputs["_FORTIFY_IMPL"].contains(&"_FORTIFY_HEADERS_H".to_owned()));
        assert!(inputs["_CXX_STDLIB"].contains(&"__GLIBCXX__".to_owned()));
    }

    /// The identifiers each derived entry's ladder tests: every name in the `#if` and
    /// `#elif` lines of the conditional that defines its token, but `defined`.
    fn summary_inputs(
        header: &str,
        derived: &[String],
    ) -> Result<BTreeMap<String, Vec<String>>, String> {
        let lines: Vec<&str> = header.lines().collect();
        let mut out = BTreeMap::new();
        for summary in derived {
            let written = format!("\"{summary}=");
            let at = lines
                .iter()
                .position(|l| l.contains("define CHARD__R_") && l.contains(&written))
                .ok_or(format!("{summary} is never written"))?;
            let opens = |l: &&str| matches!(directive_word(l), Some("if" | "ifdef" | "ifndef"));
            let open = lines[..at]
                .iter()
                .rposition(&opens)
                .ok_or(format!("{summary} is outside a conditional"))?;
            let mut names = Vec::new();
            let mut depth = 0_usize;
            for line in &lines[open..] {
                let word = directive_word(line);
                if opens(line) {
                    depth = depth.saturating_add(1);
                } else if word == Some("endif") {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                let Some(word @ ("if" | "ifdef" | "ifndef" | "elif")) = word else {
                    continue;
                };
                let test = line.split_once(word).map_or("", |(_, test)| test);
                for word in test.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                    let identifier =
                        word.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
                    if identifier && word != "defined" && !names.iter().any(|n| n == word) {
                        names.push(word.to_owned());
                    }
                }
            }
            out.insert(summary.clone(), names);
        }
        Ok(out)
    }

    #[test]
    fn a_failed_build_is_the_macro_channels_reason_before_its_dump() {
        let dump = |status| compile::BuildRecord {
            stderr: "fatal error: vector: No such file or directory\n".to_owned(),
            ..variant_build(status, false)
        };
        let arm = |build: i32, dumped: i32| {
            let mut v = blank_variant();
            v.build = Some(variant_build(build, false));
            v.macro_dump = Some(dump(dumped));
            v.macros_preprocessor = macro_pairs(&[("__PIE__", "2")]);
            v
        };
        let both = unevaluable_reason(&arm(1, 1), Channel::Macro).expect("withheld");
        assert!(both.starts_with("the build "), "{both}");
        assert_eq!(macro_reason(&arm(1, 1)).as_deref(), Some(both.as_str()));
        assert!(macro_reason(&arm(0, 0)).is_none());
        let dump_alone = unevaluable_reason(&arm(0, 1), Channel::Macro).expect("withheld");
        assert!(!dump_alone.starts_with("the build "), "{dump_alone}");
        assert_eq!(
            arm(1, 1).sufficient_for(Channel::Macro),
            Err(Verdict::BuildFailed)
        );
        assert_eq!(
            arm(0, 1).sufficient_for(Channel::Macro),
            Err(Verdict::Indeterminate)
        );
        // No dump-failure error beside the failed build: its checks withhold for the build.
        let faults = evidence_faults(some_probe(), &blank_variant(), &arm(1, 1));
        assert!(
            !faults
                .iter()
                .any(|f| f.message.contains("macro channel could not be read")),
            "{faults:?}"
        );
        let faults = evidence_faults(some_probe(), &blank_variant(), &arm(0, 1));
        assert!(
            faults
                .iter()
                .any(|f| f.message.contains("macro channel could not be read")),
            "{faults:?}"
        );
    }

    #[test]
    fn the_listing_and_the_account_read_one_report() {
        let shapes = [
            "",
            "no report here",
            "CHARD-REPORT-V2\nA=1\nB undefined\nCHARD-REPORT-END\n",
            "CHARD-REPORT-V2\nB undefined\nCHARD-REPORT-END\n",
            "CHARD-REPORT-V2\nA=1\n",
            "CHARD-REPORT-V2\nCHARD-REPORT-END\n",
            "CHARD-REPORT-V2\nA=1\nA=2\nCHARD-REPORT-END\n",
            "CHARD-REPORT-V2\nA=1\n\nCHARD-REPORT-END\n",
            "CHARD-REPORT-V1\nA=?\nB=2\nCHARD-REPORT-END\n",
        ];
        let mut read = 0_usize;
        for text in shapes {
            let listing = probe::self_report_listing(text);
            let account = probe::self_report_account(text);
            assert_eq!(listing.is_some(), account.is_some(), "{text:?}");
            if let (Some(listing), Some(account)) = (listing, account) {
                read += 1;
                let defined: BTreeMap<String, String> = listing
                    .into_iter()
                    .filter_map(|(name, value)| Some((name, value?)))
                    .collect();
                assert_eq!(defined, account, "{text:?}");
            }
        }
        assert_eq!(read, 3, "the three readable shapes");
    }

    #[test]
    fn a_dump_runs_under_the_words_of_its_builds_compile() {
        use probe::LinkMode;
        let words = |mode: LinkMode, flags: &[&str], witnessed: bool| {
            let flags: Vec<String> = flags.iter().map(|f| (*f).to_owned()).collect();
            let (kept, _) = mode.partition_flags(&flags);
            dump_words(mode, &kept, witnessed)
        };
        let profile = [
            "-O2",
            "-fPIE",
            "-pie",
            "-Wl,-z,now",
            "-L/x",
            "-lm",
            "-D_FORTIFY_SOURCE=2",
            "-pthread",
            "-static",
            "-include",
            "h.h",
            "-I/inc",
        ];
        let compiled = [
            "-O2",
            "-fPIE",
            "-D_FORTIFY_SOURCE=2",
            "-pthread",
            "-static",
            "-include",
            "h.h",
            "-I/inc",
        ];
        for mode in [LinkMode::Executable, LinkMode::Object] {
            assert_eq!(words(mode, &profile, false), compiled, "{mode:?}");
            let mut witnessed = compiled.to_vec();
            witnessed.extend(["-include", "chard_run_witness.h"]);
            assert_eq!(words(mode, &profile, true), witnessed, "{mode:?}");
        }
        // A shared object: its own filter drops `-fPIE` and `-pie`, the build adds
        // `-fPIC`, and `-shared` stays the link's.
        assert_eq!(
            words(LinkMode::SharedObject, &["-O2", "-fPIE", "-pie"], false),
            ["-O2", "-fPIC"]
        );
        assert_eq!(
            words(LinkMode::SharedObject, &["-fno-pic"], false),
            ["-fno-pic"],
            "an explicit choice is the build's and the dump's alike"
        );
        assert_eq!(
            words(LinkMode::SharedObjectAsCompiled, &["-O2"], false),
            ["-O2"]
        );
        for mode in [
            LinkMode::Executable,
            LinkMode::Object,
            LinkMode::SharedObject,
            LinkMode::SharedObjectAsCompiled,
        ] {
            let dumped = words(mode, &profile, true);
            for word in mode.extra_flags(&[]) {
                if word != "-fPIC" {
                    assert!(!dumped.iter().any(|d| d == word), "{mode:?}: {word}");
                }
            }
        }
    }

    #[test]
    fn a_macro_probe_reads_its_macros_where_its_unit_ends() {
        let header = include_str!("../probes/chard_selfreport.h");
        assert_eq!(late_directives_of_the_header(header), Ok(Vec::new()));
        for written in [
            "#include <signal.h>",
            "#  include <signal.h>",
            "# include_next <signal.h>",
            "#undef __PIE__",
            "_Pragma(\"push_macro(\\\"X\\\")\")",
        ] {
            let late = format!("{header}\n{written}\n");
            assert_eq!(
                late_directives_of_the_header(&late),
                Ok(vec![written.to_owned()]),
                "{written}"
            );
        }
        assert!(late_directives_of_the_header("#define CHARD_SELFREPORT_H\n").is_err());

        let probes: Vec<&Probe> = probe::CORPUS
            .iter()
            .filter(|p| p.checks.iter().any(|c| c.channel() == Channel::Macro))
            .collect();
        eprintln!("{} macro-channel probe(s)", probes.len());
        assert!(probes.len() >= 3, "{}", probes.len());
        for probe in &probes {
            assert_eq!(
                directives_after_the_header(probe.source),
                Ok(Vec::new()),
                "{}",
                probe.id
            );
        }
        let source = probes[0].source;
        for written in [
            "#include <signal.h>",
            "#  include <signal.h>",
            "#define X 1",
            "#  undef X",
            "#pragma pop_macro(\"X\")",
            "_Pragma(\"pop_macro(\\\"X\\\")\")",
        ] {
            let edited = format!("{source}\n{written}\n");
            assert_eq!(
                directives_after_the_header(&edited),
                Ok(vec![written.to_owned()]),
                "{written}"
            );
        }
        assert!(directives_after_the_header("int main(void) { return 0; }").is_err());
    }

    /// A line's directive word (`include` of `#  include <x>`), or `None` for a line that
    /// is no directive.
    fn directive_word(line: &str) -> Option<&str> {
        line.trim_start()
            .strip_prefix('#')?
            .split(|c: char| c.is_whitespace() || c == '<' || c == '"' || c == '(')
            .find(|w| !w.is_empty())
    }

    /// The lines of `header` after its first `CHARD__R_` definition that include a header,
    /// undefine a macro or carry a `_Pragma` operator, comments removed; an error where the
    /// header defines no entry.
    fn late_directives_of_the_header(header: &str) -> Result<Vec<String>, String> {
        let code = probe::without_c_comments(header);
        let first = code
            .lines()
            .position(|l| {
                directive_word(l) == Some("define")
                    && l.split_whitespace().any(|w| w.starts_with("CHARD__R_"))
            })
            .ok_or("the header defines no entry")?;
        Ok(code
            .lines()
            .skip(first)
            .filter(|l| {
                matches!(
                    directive_word(l),
                    Some("include" | "include_next" | "import" | "undef")
                ) || l.contains("_Pragma")
            })
            .map(|l| l.trim().to_owned())
            .collect())
    }

    /// Every directive of `source` after its `#include "chard_selfreport.h"` that is not a
    /// conditional, and every line there carrying a `_Pragma` operator, comments removed; an
    /// error where the source does not include the header.
    fn directives_after_the_header(source: &str) -> Result<Vec<String>, String> {
        let code = probe::without_c_comments(source);
        let include = format!("#include \"{}\"", probe::SELFREPORT_HEADER_NAME);
        let at = code
            .find(&include)
            .ok_or("the source does not include the header")?;
        Ok(code[at.saturating_add(include.len())..]
            .lines()
            .map(str::trim)
            .filter(|l| {
                let conditional = matches!(
                    directive_word(l),
                    Some("if" | "ifdef" | "ifndef" | "elif" | "else" | "endif")
                );
                (directive_word(l).is_some() && !conditional) || l.contains("_Pragma")
            })
            .map(str::to_owned)
            .collect())
    }

    /// The self-report's entries, from the `CHARD__R_*` tokens `CHARD_REPORT_BODY` lists: the
    /// names read from the macro of the same name and the names derived from a ladder, or an
    /// error naming the first entry whose define this cannot read.
    fn self_report_entries(header: &str) -> Result<(Vec<String>, Vec<String>), String> {
        let body_start = header
            .find("#define CHARD_REPORT_BODY \\")
            .ok_or("no CHARD_REPORT_BODY")?;
        let mut tokens: Vec<&str> = Vec::new();
        for line in header[body_start..].lines().skip(1) {
            for word in line.split_whitespace().filter(|w| *w != "\\") {
                if !word.starts_with("CHARD__R_") {
                    return Err(format!(
                        "CHARD_REPORT_BODY lists {word}, which is not an entry"
                    ));
                }
                tokens.push(word);
            }
            if !line.trim_end().ends_with('\\') {
                break;
            }
        }
        let (mut read, mut derived) = (Vec::new(), Vec::new());
        for token in &tokens {
            let defines: Vec<&str> = header
                .lines()
                .filter_map(|l| {
                    l.trim_start_matches(['#', ' '])
                        .strip_prefix("define ")?
                        .strip_prefix(*token)?
                        .strip_prefix(' ')
                })
                .collect();
            if defines.is_empty() {
                return Err(format!("{token} is listed and never defined"));
            }
            let (mut name, mut is_read, mut is_derived) = (None, false, false);
            for rest in defines {
                let unreadable =
                    || format!("{token} is defined in a shape this cannot read: {rest}");
                let quoted = rest.trim().strip_prefix('"').ok_or_else(unreadable)?;
                // The undefined branch, `"NAME undefined\n"`: a name and no value.
                if let Some(entry) = quoted.strip_suffix(" undefined\\n\"") {
                    if entry.contains(['=', ' ', '"']) {
                        return Err(unreadable());
                    }
                    if *name.get_or_insert(entry) != entry {
                        return Err(format!("{token} writes two names"));
                    }
                    continue;
                }
                let (entry, after) = quoted.split_once('=').ok_or_else(unreadable)?;
                if after.starts_with("?\\n\"") {
                    return Err(format!(
                        "{token} writes {entry}=?, which a macro defined as `?` writes too"
                    ));
                }
                if *name.get_or_insert(entry) != entry {
                    return Err(format!("{token} writes two names"));
                }
                if let Some((_, arg)) = after.split_once("CHARD__XSTR(") {
                    if arg.split_once(')').map(|(a, _)| a) != Some(entry) {
                        return Err(format!("{token} prints another macro than {entry}"));
                    }
                    is_read = true;
                } else {
                    is_derived = true;
                }
            }
            let name = name.ok_or("unreachable")?.to_owned();
            match (is_read, is_derived) {
                (true, false) => read.push(name),
                (false, true) => derived.push(name),
                _ => return Err(format!("{token} is neither read nor derived, or both")),
            }
        }
        Ok((read, derived))
    }

    #[test]
    fn the_self_report_summaries_are_the_entries_the_header_derives() {
        let header = include_str!("../probes/chard_selfreport.h");
        let (read, mut derived) = self_report_entries(header).expect("the header reads");
        // Every entry `CHARD_REPORT_BODY` lists, counted: a new entry moves this.
        assert_eq!(
            read.len() + derived.len(),
            35,
            "read {read:?}, derived {derived:?}"
        );
        derived.sort_unstable();
        let mut summaries = SELF_REPORT_SUMMARIES.to_vec();
        summaries.sort_unstable();
        assert_eq!(derived, summaries);

        // A derived entry whose string is on a continuation line fails, and one on its own
        // line is a summary.
        let listed = header.replacen(
            "    CHARD__R_FOB\n",
            "    CHARD__R_FOB CHARD__R_NEWSUM\n",
            1,
        );
        assert_ne!(listed, header, "the body's last line has moved");
        let continued =
            format!("{listed}\n#define CHARD__R_NEWSUM \\\n    \"_NEWSUM=derived\\n\"\n");
        assert!(
            self_report_entries(&continued).is_err_and(|e| e.contains("CHARD__R_NEWSUM")),
            "a continuation-line entry is unreadable, not skipped"
        );
        let other_prefix = header.replacen(
            "    CHARD__R_FOB\n",
            "    CHARD__R_FOB CHARD__E_NEWSUM\n",
            1,
        );
        assert!(
            self_report_entries(&other_prefix).is_err_and(|e| e.contains("CHARD__E_NEWSUM")),
            "a body word that is not an entry token is refused, not skipped"
        );
        let one_line = format!("{listed}\n#  define CHARD__R_NEWSUM \"_NEWSUM=derived\\n\"\n");
        let (_, derived) = self_report_entries(&one_line).expect("one line reads");
        assert!(derived.iter().any(|n| n == "_NEWSUM"), "{derived:?}");
    }

    #[test]
    fn a_probe_embedding_a_self_report_section_warns_when_the_artifact_has_none() {
        let with_report = probe::find("toolchain-macros").expect("the probe is in the corpus");
        assert!(
            with_report.embeds_self_report(),
            "this test is about a probe that embeds the section; its source has changed"
        );

        let mut bare = blank_variant();
        bare.elf = Some(elf_with_report(""));
        let faults = evidence_faults(with_report, &blank_variant(), &bare);
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert_eq!(faults[0].severity, Severity::Warning);
        assert_eq!(
            faults[0].message,
            "probe embeds a .chard.report section but the measured artifact lists 0 sections \
             and no `.chard.report`"
        );

        // Listed and cut: the reader's entry is quoted.
        let mut unread = blank_variant();
        let mut facts = elf_with_report("");
        facts.sections = vec![".text".to_owned(), ".chard.report".to_owned()];
        facts.truncations = vec![cut(
            elf::ElfTable::SectionNames,
            elf::TruncationKind::Unread,
            ".chard.report: 0x2000+0x400 could not be read (past the end)",
        )];
        unread.elf = Some(facts);
        let faults = evidence_faults(with_report, &blank_variant(), &unread);
        let about_section: Vec<&Diagnostic> = faults
            .iter()
            .filter(|d| d.message.starts_with("probe embeds"))
            .collect();
        assert_eq!(about_section.len(), 1, "{faults:?}");
        assert!(
            about_section[0].message.ends_with(
                "the measured artifact lists `.chard.report` and the reader could not finish \
                 it (.chard.report: 0x2000+0x400 could not be read (past the end))"
            ),
            "{}",
            about_section[0].message
        );

        // Listed, read, and holding no report: absent, and the length is said.
        for text in [
            "CHARD-REPORT-V1\nCHARD-REPORT-END",
            "__PIE__=2\n",
            "CHARD-REPORT-V1\n__PIE__=2\n",
            "foo=bar",
        ] {
            let mut hollow = blank_variant();
            let mut facts = elf_with_report(text);
            facts.sections = vec![".chard.report".to_owned()];
            assert!(
                matches!(
                    report::self_report_entries(&facts),
                    Err(report::SelfReportAbsence::NoReport { bytes }) if bytes == text.len()
                ),
                "{text:?}: {:?}",
                report::self_report_entries(&facts)
            );
            hollow.elf = Some(facts);
            let faults = evidence_faults(with_report, &blank_variant(), &hollow);
            assert_eq!(faults.len(), 1, "{text:?}: {faults:?}");
        }

        // A section that is there is not a fault...
        let mut carried = blank_variant();
        carried.elf = Some(elf_with_report(
            "CHARD-REPORT-V1\n__PIE__=2\nCHARD-REPORT-END",
        ));
        assert!(
            evidence_faults(with_report, &blank_variant(), &carried).is_empty(),
            "an artifact carrying the self-report section its probe embeds raises no fault"
        );

        // ...and neither is a probe that never asked for one.
        let no_report = probe::find("stack-canary").expect("the probe is in the corpus");
        assert!(
            !no_report.embeds_self_report(),
            "this test needs a probe that embeds no section"
        );
        let mut plain = blank_variant();
        plain.elf = Some(elf_with_report(""));
        assert!(
            evidence_faults(no_report, &blank_variant(), &plain).is_empty(),
            "a probe that embeds no self-report section is not faulted for an artifact without one"
        );
    }

    #[test]
    fn a_macro_reading_over_an_artifact_without_its_self_report_is_withheld() {
        use probe::Outcome;
        use report::gating_rule as g;

        let ssp = check_named("ssp-level");
        assert_eq!(ssp.channel(), Channel::Macro);
        let gated = |facts: Option<&elf::ElfFacts>, verdict: Verdict| {
            gating_for(verdict, ssp, Outcome::Absent, facts)
        };

        // Unlisted: a linker collected it or a tool removed it after the link.
        let unlisted = elf_with_report("");
        for verdict in [
            Verdict::On,
            Verdict::Off,
            Verdict::Partial,
            Verdict::Indeterminate,
        ] {
            let (withheld, gating) = gated(Some(&unlisted), verdict).expect("gated");
            assert_eq!(withheld, Verdict::Indeterminate, "{verdict:?}");
            assert_eq!(gating.rule, g::ARTIFACT_LACKS_SELF_REPORT);
            assert!(
                gating
                    .reason
                    .contains("lists 0 sections and no `.chard.report`"),
                "{}",
                gating.reason
            );
        }
        // The count is the list's.
        let mut two = elf_with_report("");
        two.sections = vec![".text".to_owned(), ".data".to_owned()];
        let (_, gating) = gated(Some(&two), Verdict::Off).expect("gated");
        assert!(
            gating
                .reason
                .contains("lists 2 sections and no `.chard.report`"),
            "{}",
            gating.reason
        );
        // `probe-invalid` keeps its controls' cause.
        assert!(gated(Some(&unlisted), Verdict::ProbeInvalid).is_none());
        // `unsupported` rests on the toolchain's own statement and is left standing.
        assert!(gated(Some(&unlisted), Verdict::Unsupported).is_none());

        // Listed and unread, and listed with no field: each names its own way.
        let mut unread = elf_with_report("");
        unread.sections = vec![".chard.report".to_owned()];
        unread.truncations = vec![cut(
            elf::ElfTable::SectionNames,
            elf::TruncationKind::Unread,
            ".chard.report: 0x2000+0x400 could not be read (past the end)",
        )];
        let (_, gating) = gated(Some(&unread), Verdict::Off).expect("gated");
        assert!(
            gating
                .reason
                .contains("could not finish it (.chard.report: 0x2000+0x400"),
            "{}",
            gating.reason
        );
        // A refused name table has not shown the section absent: the refusal is quoted
        // instead of a section count.
        let mut unnamed = elf_with_report("");
        unnamed.truncations = vec![cut(
            elf::ElfTable::SectionNames,
            elf::TruncationKind::Unread,
            "e_shstrndx is SHN_UNDEF, so the file declares no section-name table and no \
             section can be found by name",
        )];
        let (_, gating) = gated(Some(&unnamed), Verdict::Off).expect("gated");
        assert!(
            gating.reason.contains(
                "has no section the reader could look up by name (e_shstrndx is SHN_UNDEF"
            ),
            "{}",
            gating.reason
        );
        let mut empty = elf_with_report("");
        empty.sections = vec![".chard.report".to_owned()];
        let (_, gating) = gated(Some(&empty), Verdict::Off).expect("gated");
        assert!(
            gating.reason.contains("and the section is empty"),
            "{}",
            gating.reason
        );

        // The artifact names macros: nothing to withhold, and `gather` takes them.
        let carried = elf_with_report("CHARD-REPORT-V1\n__SSP_STRONG__=1\nCHARD-REPORT-END");
        assert!(gated(Some(&carried), Verdict::On).is_none());
        assert!(report::self_report_entries(&carried).is_ok());
        assert!(report::self_report_entries(&unlisted).is_err());
        // An account that nothing is defined is an account: the `off` it earns stands.
        let undefined = elf_with_report(
            "CHARD-REPORT-V2\n__SSP__ undefined\n__SSP_STRONG__ undefined\nCHARD-REPORT-END",
        );
        assert!(gated(Some(&undefined), Verdict::Off).is_none());
        assert_eq!(report::self_report_entries(&undefined), Ok(BTreeMap::new()));

        // No artifact was read: the dump is the witness by design and is not gated here.
        assert!(gated(None, Verdict::On).is_none());

        // Another channel reads its own tables, not the section.
        let canary = check_named("canary-emitted");
        assert_eq!(canary.channel(), Channel::ElfStatic);
        assert!(
            gating_for(Verdict::Off, canary, Outcome::Absent, Some(&unlisted))
                .is_none_or(|(_, g)| g.rule != g::ARTIFACT_LACKS_SELF_REPORT)
        );
    }

    /// A build record that exited 0 and wrote `artifact`, or nothing.
    fn build_exiting_zero(artifact: Option<String>) -> compile::BuildRecord {
        compile::BuildRecord {
            argv: vec!["cc".to_owned()],
            dropped_flags: Vec::new(),
            exit_status: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 1,
            artifact_sha256: artifact,
            stdout_sha256: None,
            stdout_unterminated: false,
        }
    }

    #[test]
    fn a_macro_reading_over_an_artifact_the_reader_refused_is_withheld_off_macos() {
        use report::gating_rule as g;

        let ssp = check_named("ssp-level");
        let settled = |verdict: Verdict, gating: Option<g::Rule>| Settled {
            verdict,
            level: None,
            gating: gating.map(|rule| report::Gating {
                rule,
                arch: None,
                libc: None,
                needs_vm: false,
                reason: "earlier".to_owned(),
            }),
        };
        let mut refused = blank_variant();
        refused.build = Some(build_exiting_zero(Some("ab".repeat(32))));
        refused.elf_error = Some(report::ArtifactRefusal {
            why: "probe-measured: file too short to be ELF".to_owned(),
            mach_o: false,
        });

        let out = settle_self_report_unread(settled(Verdict::On, None), ssp, &refused, false);
        assert_eq!(out.verdict, Verdict::Indeterminate);
        let gating = out.gating.expect("gated");
        assert_eq!(gating.rule, g::ARTIFACT_LACKS_SELF_REPORT);
        assert!(
            gating.reason.contains(
                "could not be read by chard's ELF reader (probe-measured: file too short to be ELF)"
            ),
            "{}",
            gating.reason
        );
        // The level rule's reason is overwritten; a later stage's, the declared family's
        // and the triple's verdicts are not.
        let out = settle_self_report_unread(
            settled(Verdict::Indeterminate, Some(g::LEVEL_OFF_SCALE)),
            ssp,
            &refused,
            false,
        );
        assert_eq!(
            out.gating.map(|g| g.rule),
            Some(g::ARTIFACT_LACKS_SELF_REPORT)
        );
        for (verdict, rule) in [
            (Verdict::Indeterminate, Some(g::MACRO_SPOOFED)),
            (Verdict::Unsupported, Some(g::LIBC_DECLARED)),
            (Verdict::ProbeInvalid, None),
        ] {
            let out = settle_self_report_unread(settled(verdict, rule), ssp, &refused, false);
            assert_eq!(out.verdict, verdict, "{verdict:?}");
            assert_eq!(out.gating.map(|g| g.rule), rule, "{verdict:?}");
        }
        // A refused ELF artifact is an absence on macOS too; a Mach-O object is the dump
        // reading by design there, and an absence on every other host.
        assert_eq!(
            settle_self_report_unread(settled(Verdict::On, None), ssp, &refused, true)
                .gating
                .map(|g| g.rule),
            Some(g::ARTIFACT_LACKS_SELF_REPORT)
        );
        let mut mach_o = blank_variant();
        mach_o.build = Some(build_exiting_zero(Some("cd".repeat(32))));
        mach_o.elf_error = Some(report::ArtifactRefusal {
            why: format!("probe-measured: {}", elf::MACH_O_REFUSAL),
            mach_o: true,
        });
        assert!(
            settle_self_report_unread(settled(Verdict::On, None), ssp, &mach_o, true)
                .gating
                .is_none()
        );
        assert_eq!(
            settle_self_report_unread(settled(Verdict::On, None), ssp, &mach_o, false)
                .gating
                .map(|g| g.rule),
            Some(g::ARTIFACT_LACKS_SELF_REPORT)
        );
        // An `unsupported` with no gating is a declared verdict and stands.
        assert!(
            settle_self_report_unread(settled(Verdict::Unsupported, None), ssp, &refused, false)
                .gating
                .is_none()
        );
        // Another channel is not the gate's.
        let canary = check_named("canary-emitted");
        assert!(
            settle_self_report_unread(settled(Verdict::Off, None), canary, &refused, false)
                .gating
                .is_none()
        );
    }

    #[test]
    fn a_macro_reading_over_a_build_that_wrote_no_artifact_is_withheld_on_every_host() {
        use report::gating_rule as g;

        let ssp = check_named("ssp-level");
        let settled = |verdict: Verdict| Settled {
            verdict,
            level: None,
            gating: None,
        };
        let mut unwritten = blank_variant();
        unwritten.build = Some(build_exiting_zero(None));
        let out = settle_self_report_unread(settled(Verdict::Off), ssp, &unwritten, false);
        let gating = out.gating.expect("gated");
        assert_eq!(gating.rule, g::ARTIFACT_LACKS_SELF_REPORT);
        assert!(
            gating
                .reason
                .contains("was never written: the build exited 0"),
            "{}",
            gating.reason
        );
        assert!(
            settle_self_report_unread(settled(Verdict::Off), ssp, &unwritten, true)
                .gating
                .is_some()
        );
        let mut failed = blank_variant();
        failed.build = Some(compile::BuildRecord {
            exit_status: 1,
            ..build_exiting_zero(None)
        });
        assert!(
            settle_self_report_unread(settled(Verdict::Off), ssp, &failed, false)
                .gating
                .is_none()
        );
        assert!(
            settle_self_report_unread(settled(Verdict::Off), ssp, &blank_variant(), false)
                .gating
                .is_none()
        );
        let mut read = blank_variant();
        read.elf = Some(elf_with_report(""));
        assert!(
            settle_self_report_unread(settled(Verdict::Off), ssp, &read, false)
                .gating
                .is_none()
        );
    }

    /// A variant whose artifact read whole but for the truncations given, with a canary
    /// reference in its symbol table so the detector has something to read as present.
    fn canary_variant(truncations: Vec<elf::Truncation>) -> Variant {
        let mut facts = elf_with_report("");
        facts.symbol_tables = vec![".dynsym".to_owned()];
        facts.watched_symbols.insert(
            "__stack_chk_fail".to_owned(),
            elf::SymbolFact {
                defined: false,
                tables: vec![".dynsym".to_owned()],
                versioned: Vec::new(),
            },
        );
        facts.truncations = truncations;
        let mut variant = blank_variant();
        variant.elf = Some(facts);
        variant.build = Some(variant_build(0, true));
        variant
    }

    fn cut(table: elf::ElfTable, kind: elf::TruncationKind, detail: &str) -> elf::Truncation {
        elf::Truncation {
            table,
            kind,
            detail: detail.to_owned(),
        }
    }

    #[test]
    fn a_shared_link_read_over_a_cut_dynamic_table_is_withheld() {
        use probe::Outcome;

        let check = check_named("pic-shared-link");
        let mut facts = elf_with_report("");
        facts.shared_object = Some(true);
        let mut variant = blank_variant();
        variant.build = Some(variant_build(0, true));
        variant.elf = Some(facts.clone());
        assert_eq!(reading(check, &variant).detection.outcome, Outcome::Present);
        facts.truncations = vec![cut(
            elf::ElfTable::Dynamic,
            elf::TruncationKind::Unread,
            ".dynamic unreadable at entry 3 of 30",
        )];
        variant.elf = Some(facts);
        let withheld = reading(check, &variant).detection;
        assert_eq!(withheld.outcome, Outcome::Indeterminate);
        assert!(
            withheld.observed.contains("dynamic"),
            "{}",
            withheld.observed
        );

        let (verdict, gating) =
            gating_for(Verdict::On, check, Outcome::Present, variant.elf.as_ref())
                .expect("a cut .dynamic gates the measured build");
        assert_eq!(verdict, Verdict::Indeterminate);
        assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
    }

    #[test]
    fn a_control_arm_truncated_on_a_read_table_cannot_vouch() {
        use probe::Outcome;
        use report::WithheldBecause;

        let check = check_named("canary-emitted");
        let torn_symbols = cut(
            elf::ElfTable::Symbols,
            elf::TruncationKind::Unread,
            ".symtab unreadable at symbol 3 of 40",
        );

        let whole = canary_variant(Vec::new());
        let present = reading(check, &whole).detection;
        assert_eq!(
            present.outcome,
            Outcome::Present,
            "a whole table's reading is left alone"
        );

        let torn = canary_variant(vec![torn_symbols.clone()]);
        let torn_reading = reading(check, &torn);
        let replaced = torn_reading.detection;
        assert_eq!(replaced.outcome, Outcome::Indeterminate);
        assert!(replaced.level.is_none());
        assert_eq!(
            torn_reading.proof.map(|p| p.clause).as_deref(),
            Some(crate::predicate::TRUNCATED),
            "the predicate's truncation preamble decided, before any clause read a symbol"
        );
        assert!(
            replaced.observed.contains(r#"unread_tables=["symbols"]"#),
            "the replacement names the table: {}",
            replaced.observed
        );

        // An ignored view leaves the facts whole, and a cut touches no check that reads
        // another table.
        let dropped = canary_variant(vec![cut(
            elf::ElfTable::Dynamic,
            elf::TruncationKind::Ignored,
            "SHT_DYNAMIC section at 0x3f0+0x20 lies outside every PT_DYNAMIC segment",
        )]);
        assert_eq!(reading(check, &dropped).detection.outcome, Outcome::Present);
        let relro = check_named("relro");
        assert_eq!(
            reading(relro, &torn).detection.outcome,
            reading(relro, &whole).detection.outcome,
            "relro reads no symbol table"
        );

        let absent = Detection {
            outcome: Outcome::Absent,
            level: None,
            observed: "__stack_chk_fail=absent __stack_chk_fail_local=absent".to_owned(),
            rule: None,
        };
        let (verdict, controls) = report::decide(
            &present,
            arm(Some(&present)),
            arm(Some(&replaced)),
            None,
            None,
        );
        assert_eq!(verdict, Verdict::ProbeInvalid);
        assert_eq!(
            controls.withheld(),
            Some(WithheldBecause::NegativeIndeterminate)
        );
        assert!(
            controls
                .negative
                .detail
                .as_deref()
                .is_some_and(|d| d.contains(r#"unread_tables=["symbols"]"#)),
            "the arm's detail is where a reader learns which table was cut: {:?}",
            controls.negative.detail
        );
        let (verdict, controls) = report::decide(
            &present,
            arm(Some(&replaced)),
            arm(Some(&absent)),
            None,
            None,
        );
        assert_eq!(verdict, Verdict::ProbeInvalid);
        assert_eq!(
            controls.withheld(),
            Some(WithheldBecause::PositiveIndeterminate)
        );
        let (verdict, controls) = report::decide(
            &present,
            arm(Some(&present)),
            arm(Some(&absent)),
            regime_arm(Some(&replaced)),
            None,
        );
        assert_eq!(verdict, Verdict::ProbeInvalid);
        assert_eq!(
            controls.withheld(),
            Some(WithheldBecause::RegimeUnevaluable)
        );
    }

    /// An artifact whose symbol table was read whole and holds `handler`, if any, as an
    /// undefined reference.
    fn handler_variant(handler: Option<&str>) -> Variant {
        let mut facts = elf_with_report("");
        facts.symbol_tables = vec![".dynsym".to_owned(), ".symtab".to_owned()];
        if let Some(name) = handler {
            facts.watched_symbols.insert(
                name.to_owned(),
                elf::SymbolFact {
                    defined: false,
                    tables: vec![".dynsym".to_owned(), ".symtab".to_owned()],
                    versioned: Vec::new(),
                },
            );
        }
        let mut variant = blank_variant();
        variant.elf = Some(facts);
        variant.build = Some(variant_build(0, true));
        variant
    }

    #[test]
    fn openbsds_smash_handler_is_a_canary_and_retguard_alone_withholds() {
        use probe::Outcome;
        use report::WithheldBecause;

        for id in ["canary-emitted", "ssp-covers-small-arrays"] {
            let check = check_named(id);
            let emitted = reading(check, &handler_variant(Some("__stack_smash_handler")));
            assert_eq!(emitted.detection.outcome, Outcome::Present, "{id}");
            assert_eq!(
                emitted.proof.map(|p| p.clause).as_deref(),
                Some("stack-chk-fail"),
                "{id}: the handler clause decided"
            );

            let none = reading(check, &handler_variant(None)).detection;
            assert_eq!(none.outcome, Outcome::Absent, "{id}");
            assert!(
                none.observed.contains("__stack_smash_handler=absent"),
                "{id}: {}",
                none.observed
            );

            let present = emitted.detection;
            let (verdict, controls) =
                report::decide(&present, arm(Some(&present)), arm(Some(&none)), None, None);
            assert_eq!(verdict, Verdict::On, "{id}: RETGUARD off discriminates");
            assert_eq!(controls.withheld(), None, "{id}");

            let (verdict, controls) =
                report::decide(&none, arm(Some(&none)), arm(Some(&none)), None, None);
            assert_eq!(
                verdict,
                Verdict::ProbeInvalid,
                "{id}: RETGUARD alone is not off"
            );
            assert_eq!(
                controls.withheld(),
                Some(WithheldBecause::PositiveSilent),
                "{id}"
            );
        }

        // An unrelated watched symbol is not a canary.
        let check = check_named("canary-emitted");
        let fortify = reading(check, &handler_variant(Some("__memcpy_chk"))).detection;
        assert_eq!(fortify.outcome, Outcome::Absent);
    }

    #[test]
    fn a_cut_dynamic_table_withholds_under_artifact_unreadable_before_the_precondition() {
        let check = check_named("relative-relocs");
        let mut facts = elf_with_report("");
        assert!(
            report::artifact_limitation(Verdict::Off, check, probe::Outcome::Absent, Some(&facts))
                .is_some(),
            "the fixture is a fixed-address executable the precondition rejects"
        );
        facts.truncations = vec![cut(
            elf::ElfTable::Dynamic,
            elf::TruncationKind::Unread,
            ".dynamic unreadable at entry 3 of 9 (offset 0x3f8)",
        )];

        let (verdict, gating) =
            gating_for(Verdict::Off, check, probe::Outcome::Absent, Some(&facts))
                .expect("a cut .dynamic gates the check");
        assert_eq!(verdict, Verdict::Indeterminate);
        assert_eq!(gating.rule, report::gating_rule::ARTIFACT_UNREADABLE);
        assert!(
            gating.reason.contains("dynamic table") && gating.reason.contains("entry 3 of 9"),
            "{}",
            gating.reason
        );

        assert!(
            gating_for(
                Verdict::ProbeInvalid,
                check,
                probe::Outcome::Absent,
                Some(&facts)
            )
            .is_none(),
            "a failed triple's controls carry its cause"
        );

        assert!(
            gating_for(
                Verdict::Unsupported,
                check,
                probe::Outcome::Absent,
                Some(&facts)
            )
            .is_none(),
            "a declared limitation already carries its rule"
        );
        for measured in [Verdict::On, Verdict::Partial] {
            let (verdict, _) = gating_for(measured, check, probe::Outcome::Present, Some(&facts))
                .expect("a reading from a cut table is withheld whatever it read");
            assert_eq!(verdict, Verdict::Indeterminate, "{measured:?}");
        }

        facts.truncations.clear();
        let (verdict, gating) =
            gating_for(Verdict::Off, check, probe::Outcome::Absent, Some(&facts))
                .expect("with the table whole, the precondition is what speaks");
        assert_eq!(verdict, Verdict::NotApplicable);
        assert_eq!(gating.rule, report::gating_rule::ARTIFACT_CANNOT_CARRY);
        assert!(gating_for(Verdict::Off, check, probe::Outcome::Absent, None).is_none());
    }

    #[test]
    fn a_slim_lto_object_withholds_an_elf_static_reading() {
        use report::gating_rule as g;

        let table = check_named("except-table-emitted");
        let mut facts = elf_with_report("");
        facts.elf_type = "ET_REL".to_owned();
        facts.sections = vec![
            ".text".to_owned(),
            format!("{}opts", report::LTO_IR_SECTION_PREFIX),
        ];
        assert!(
            gating_for(Verdict::Off, table, probe::Outcome::Absent, Some(&facts)).is_none(),
            "a fat object's reading stands"
        );

        facts
            .watched_symbols
            .insert(report::LTO_SLIM_SYMBOL.to_owned(), slim_marker());
        for (measured, reading) in [
            (Verdict::Off, probe::Outcome::Absent),
            (Verdict::On, probe::Outcome::Present),
        ] {
            let (verdict, gating) = gating_for(measured, table, reading, Some(&facts))
                .expect("a slim object's reading is withheld whatever it read");
            assert_eq!(verdict, Verdict::Indeterminate, "{measured:?}");
            assert_eq!(gating.rule, g::ARTIFACT_LTO_IR);
            assert!(
                gating.reason.contains(report::LTO_SLIM_SYMBOL),
                "{}",
                gating.reason
            );
        }
        for kept in [Verdict::ProbeInvalid, Verdict::Unsupported] {
            assert!(
                gating_for(kept, table, probe::Outcome::Absent, Some(&facts)).is_none(),
                "{kept:?} carries its own cause"
            );
        }
        let macro_check = check_named("exceptions-macro");
        let gating = report::lto_ir_limitation(macro_check, Some(&facts))
            .expect("a macro check over a slim object without a readable self-report");
        assert_eq!(gating.rule, g::ARTIFACT_LTO_IR);
        assert!(
            gating.reason.contains(".chard.report") && gating.reason.contains("compiler IR"),
            "{}",
            gating.reason
        );
        let mut kept = facts.clone();
        kept.self_report = "CHARD-REPORT-V1\n__EXCEPTIONS=1\nCHARD-REPORT-END".to_owned();
        assert!(
            report::lto_ir_limitation(macro_check, Some(&kept)).is_none(),
            "a macro check over an object that kept its section reads the section"
        );
        // Through the measure path's gate: the LTO rule before the self-report gate.
        let through = |f: &elf::ElfFacts| {
            gating_for(Verdict::Off, macro_check, probe::Outcome::Absent, Some(f))
                .map(|(v, g)| (v, g.rule))
        };
        assert_eq!(
            through(&facts),
            Some((Verdict::Indeterminate, g::ARTIFACT_LTO_IR))
        );
        let mut fat = facts.clone();
        fat.watched_symbols.clear();
        let mut listed = facts.clone();
        listed.sections.push(elf::SELF_REPORT_SECTION.to_owned());
        for (what, f) in [("a fat object", &fat), ("a listed, empty section", &listed)] {
            assert_eq!(
                through(f),
                Some((Verdict::Indeterminate, g::ARTIFACT_LACKS_SELF_REPORT)),
                "{what} is the self-report gate's case"
            );
        }
        for (id, _) in report::LTO_IR_CARRIES {
            let exempt = check_named(id);
            assert_eq!(exempt.channel(), Channel::ElfStatic, "{id}");
            assert!(
                probe::CORPUS
                    .iter()
                    .any(|p| p.link_mode == probe::LinkMode::Object
                        && p.checks.iter().any(|c| c.id == *id)),
                "{id} is exempted from a gate only an object probe can meet"
            );
            assert!(
                report::lto_ir_limitation(exempt, Some(&facts)).is_none(),
                "{id} is read as it stands over a slim object"
            );
        }

        facts.watched_symbols.clear();
        facts.truncations = vec![cut(
            elf::ElfTable::Symbols,
            elf::TruncationKind::Unread,
            ".symtab unreadable at entry 2 of 4",
        )];
        let gating = report::lto_ir_limitation(table, Some(&facts))
            .expect("IR beside an unread symbol table cannot be told fat");
        assert!(gating.reason.contains("entry 2 of 4"), "{}", gating.reason);
    }

    #[test]
    fn an_artifact_with_no_symbol_table_cannot_carry_a_symbol_reference() {
        let mut facts = elf_with_report("");
        assert!(
            facts.symbol_tables.is_empty(),
            "the fixture carries no symbol table"
        );
        let mut examined = 0usize;
        for id in [
            "canary-emitted",
            "ssp-covers-small-arrays",
            "cxx-assertions-symbol",
        ] {
            let check = check_named(id);
            assert!(
                check.reads().contains(&elf::ElfTable::Symbols),
                "{id} reads the symbol tables"
            );
            let (verdict, gating) =
                gating_for(Verdict::Off, check, probe::Outcome::Absent, Some(&facts))
                    .unwrap_or_else(|| panic!("{id}: an object with no symbol table is gated"));
            assert_eq!(verdict, Verdict::NotApplicable, "{id}");
            assert_eq!(
                gating.rule,
                report::gating_rule::ARTIFACT_CANNOT_CARRY,
                "{id}"
            );
            assert!(
                gating.reason.contains("a symbol table"),
                "{id}: the reason names what the artifact lacks: {}",
                gating.reason
            );
            examined += 1;
        }
        assert_eq!(examined, 3, "every symbol-reading check was examined");

        let check = check_named("canary-emitted");
        facts.symbol_tables = vec![".dynsym".to_owned()];
        assert!(
            gating_for(Verdict::Off, check, probe::Outcome::Absent, Some(&facts)).is_none(),
            "a dynamic link stripped of .symtab still carries .dynsym, and off is a reading"
        );

        facts.symbol_tables.clear();
        facts.truncations = vec![cut(
            elf::ElfTable::Symbols,
            elf::TruncationKind::Unread,
            "no section-header table: the symbol tables are unreachable",
        )];
        let (verdict, gating) =
            gating_for(Verdict::Off, check, probe::Outcome::Absent, Some(&facts))
                .expect("a table the reader could not reach gates the check");
        assert_eq!(verdict, Verdict::Indeterminate);
        assert_eq!(
            gating.rule,
            report::gating_rule::ARTIFACT_UNREADABLE,
            "unreachable is decided before absent: {}",
            gating.reason
        );
    }

    #[test]
    fn an_et_rel_object_without_a_dynamic_section_carries_no_truncation() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/elf/elf64-le-x86_64-rel.elf");
        let facts = elf::facts_for(&path).expect("the relocatable fixture reads");
        assert_eq!(facts.elf_type, "ET_REL");
        assert!(!facts.has_dynamic);
        assert!(
            facts.truncations.is_empty(),
            "a missing table is not-applicable's business and records no truncation: {:?}",
            facts.truncations
        );
        let check = check_named("cet-marked-object");
        assert!(report::truncation_limitation(check, Some(&facts)).is_none());
        assert!(
            gating_for(Verdict::Off, check, probe::Outcome::Absent, Some(&facts)).is_none(),
            "no gate on the artifact fires for a check that carries no precondition"
        );
    }

    #[test]
    fn a_cut_table_is_one_error_diagnostic_and_a_dropped_view_is_a_warning() {
        let whole = canary_variant(Vec::new());
        let torn = canary_variant(vec![
            cut(
                elf::ElfTable::Notes,
                elf::TruncationKind::Unread,
                "note table at 0x600+0x34: a note header lies past the end of the file at 0x618",
            ),
            cut(
                elf::ElfTable::Notes,
                elf::TruncationKind::Unread,
                "note table at 0x700+0x34: a note header lies past the end of the file at 0x718",
            ),
        ]);
        let diagnostics = evidence_faults(some_probe(), &whole, &torn);
        let named: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|d| d.message.contains("notes table"))
            .collect();
        assert_eq!(
            named.len(),
            1,
            "two entries on one table are one condition: {diagnostics:?}"
        );
        assert!(matches!(named[0].severity, Severity::Error));
        assert!(
            named[0].message.contains("measured") && named[0].message.contains("0x618"),
            "the diagnostic names the variant and quotes the reader's first sentence: {}",
            named[0].message
        );

        let diagnostics = evidence_faults(some_probe(), &torn, &torn);
        let named: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|d| d.message.contains("notes table"))
            .collect();
        assert_eq!(
            named.len(),
            1,
            "one artifact in both roles is one condition: {diagnostics:?}"
        );
        assert!(
            named[0].message.contains("the clean artifact's"),
            "the one build is named under clean, as artifact_comments labels it: {}",
            named[0].message
        );

        let dropped = canary_variant(vec![cut(
            elf::ElfTable::Dynamic,
            elf::TruncationKind::Ignored,
            "SHT_DYNAMIC section at 0x3f0+0x20 lies outside every PT_DYNAMIC segment",
        )]);
        let diagnostics = evidence_faults(some_probe(), &whole, &dropped);
        let warned: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|d| d.message.contains("dynamic table declared"))
            .collect();
        assert_eq!(warned.len(), 1, "{diagnostics:?}");
        assert!(
            matches!(warned[0].severity, Severity::Warning),
            "a declaration not followed left the facts whole, and is a warning: {:?}",
            warned[0]
        );
        assert!(
            warned[0].message.contains("0x3f0"),
            "the warning quotes the reader: {}",
            warned[0].message
        );
    }

    /// A probe from the corpus, by its id.
    fn probe_named(id: &str) -> &'static Probe {
        probe::CORPUS
            .iter()
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("{id} is not a probe in the corpus"))
    }

    fn check_named(id: &str) -> &'static Check {
        probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("{id} is not a check in the corpus"))
    }

    /// Controls whose positive arm read `outcome`, the only field either limitation
    /// consults; the flags are sentinels, so a pass that rewrote them would show.
    fn controls_with_positive(outcome: probe::Outcome) -> report::Controls {
        report::Controls {
            positive: report::ControlArm {
                flags: vec!["-sentinel-positive".to_owned()],
                outcome: Some(outcome),
                detail: None,
                build: None,
                run: None,
                macro_source: None,
                macro_dump: None,
                decoded: None,
                overridden: None,
            },
            negative: report::ControlArm {
                flags: vec!["-sentinel-negative".to_owned()],
                outcome: Some(probe::Outcome::Absent),
                detail: None,
                build: None,
                run: None,
                macro_source: None,
                macro_dump: None,
                decoded: None,
                overridden: None,
            },
            regime_negative: None,
            discrimination: report::Discrimination::Withheld(
                report::WithheldBecause::PositiveSilent,
            ),
        }
    }

    /// A build that emitted `stderr` and succeeded: clang reports an unknown `-W` option as
    /// a warning, so the rejection is found in a passing build.
    fn build_with_stderr(stderr: &str) -> compile::BuildRecord {
        compile::BuildRecord {
            argv: vec!["/usr/bin/clang".to_owned()],
            dropped_flags: Vec::new(),
            exit_status: 0,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            duration_ms: 1,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        }
    }

    #[test]
    fn a_probe_whose_scaffolding_cannot_be_built_is_gated_not_blamed() {
        let probe = probe_named("copy-dt-needed");
        let check = &probe.checks[0];
        let said = "ld: unknown options: -soname -rpath-link";

        let gated = scaffolding_limitation(Verdict::ProbeInvalid, probe, check, Some(said))
            .expect("a linker that rejects the scaffolding flags gates the check");
        assert!(
            gated.reason.contains(said),
            "the gating must quote the linker, got: {}",
            gated.reason
        );

        assert!(
            scaffolding_limitation(Verdict::ProbeInvalid, probe, check, None).is_none(),
            "probe-invalid without a rejection is the broken probe this verdict reports"
        );
        for verdict in [Verdict::On, Verdict::Off, Verdict::Unsupported] {
            assert!(
                scaffolding_limitation(verdict, probe, check, Some(said)).is_none(),
                "{verdict:?} was relabelled as a scaffolding limitation"
            );
        }

        // Never for a probe with no scaffolding, whose chain was never built.
        let plain = probe_named("link-unused-library");
        assert!(
            plain.aux_libs.is_empty(),
            "this assertion needs a probe with no aux libraries"
        );
        assert!(
            scaffolding_limitation(Verdict::ProbeInvalid, plain, &plain.checks[0], Some(said))
                .is_none(),
            "a probe with no scaffolding cannot have a scaffolding limitation"
        );
    }

    #[test]
    fn a_driver_that_refuses_to_enable_a_flag_is_not_a_driver_that_does_not_know_it() {
        let check = check_named("auto-var-init-active");
        // clang 15.0.7's wording, verbatim; clang 13 drops the quotes and ends the first
        // clause with a period, which is why the phrase matched is the part they share.
        let refused = "clang: error: '-ftrivial-auto-var-init=zero' hasn't been enabled; \
                       enable it at your own peril for benchmarking purpose only with \
                       '-enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang'";
        let gated = unknown_flag_limitation(Verdict::ProbeInvalid, check, "clang", Some(refused))
            .expect("a driver that refuses the control flag gates the check");
        assert_eq!(gated.rule, report::gating_rule::FLAG_REFUSED);
        assert!(
            gated.reason.contains("refused to enable it") && gated.reason.contains(refused),
            "the gating quotes what the driver said and names the refusal: {}",
            gated.reason
        );
        // Not "does not know", which the refusal reason uses to say what it is not.
        assert!(
            !gated
                .reason
                .contains("reported it as an option it does not know"),
            "a flag the driver knows must not be reported as one it does not: {}",
            gated.reason
        );

        let unknown = "clang: error: unknown argument: '-fhardened'";
        assert_eq!(
            unknown_flag_limitation(Verdict::ProbeInvalid, check, "clang", Some(unknown))
                .expect("an unknown flag still gates")
                .rule,
            report::gating_rule::FLAG_UNKNOWN,
        );
        assert!(rejection_is_a_refusal(refused));
        assert!(!rejection_is_a_refusal(unknown));
    }

    #[test]
    fn a_flag_the_compiler_does_not_know_gates_only_a_withheld_verdict() {
        let check = check_named("trampolines-warned");
        let said = "clang: warning: unknown warning option '-Wtrampolines'";

        let gated = unknown_flag_limitation(Verdict::ProbeInvalid, check, "clang", Some(said))
            .expect("a compiler that says it does not know the control flag gates the check");
        assert!(
            gated.reason.contains("does not know") && gated.reason.contains(said),
            "the gating must quote what the driver actually said, got: {}",
            gated.reason
        );
        assert_eq!(
            gated.libc, None,
            "this is a statement about the compiler, not the C library"
        );

        // No rejection, no claim: a probe-invalid under an accepted flag is a broken detector.
        assert!(
            unknown_flag_limitation(Verdict::ProbeInvalid, check, "clang", None).is_none(),
            "probe-invalid without a rejection was relabelled as a compiler limitation"
        );

        // Never over a reached verdict: it would overwrite a reading with a gating reason.
        for verdict in [Verdict::On, Verdict::Off, Verdict::Unsupported] {
            assert!(
                unknown_flag_limitation(verdict, check, "clang", Some(said)).is_none(),
                "{verdict:?} was relabelled as a compiler limitation"
            );
        }
    }

    #[test]
    fn a_linker_control_is_recognised_by_the_name_the_linker_uses() {
        let build = build_with_stderr("ld: error: unknown argument '--copy-dt-needed-entries'");
        let said = control_flag_rejection(&build, &["-Wl,--copy-dt-needed-entries"])
            .expect("the linker named the flag chard passed, in the linker's own spelling");
        assert!(
            said.contains("--copy-dt-needed-entries"),
            "the rejection must name the flag, got: {said}"
        );

        assert!(
            control_flag_rejection(&build, &["-Wl,--as-needed"]).is_none(),
            "a rejection of one flag was credited to another"
        );
    }

    #[test]
    fn a_control_the_toolchain_refuses_gates_only_a_withheld_verdict() {
        let check = check_named("no-copy-dt-needed");
        let said = "ld: error: unknown argument '--copy-dt-needed-entries'";

        let gated = unhardened_state_limitation(Verdict::ProbeInvalid, check, Some(said))
            .expect("a toolchain that refuses the negative control gates the check");
        assert!(
            gated
                .reason
                .contains("the unhardened state could not be built")
                && gated.reason.contains(said),
            "the gating must quote what the tool actually said, got: {}",
            gated.reason
        );

        assert!(
            unhardened_state_limitation(Verdict::ProbeInvalid, check, None).is_none(),
            "probe-invalid without a rejection was relabelled as an instrument limitation"
        );

        for verdict in [Verdict::On, Verdict::Off, Verdict::Unsupported] {
            assert!(
                unhardened_state_limitation(verdict, check, Some(said)).is_none(),
                "{verdict:?} was relabelled as a toolchain limitation"
            );
        }
    }

    #[test]
    fn an_entry_per_digest_however_many_checks_read_it() {
        let workdir = Path::new("/scratch/wd");
        let unreadable = |name: &str| {
            let mut v = blank_variant();
            v.build = Some(variant_build(0, true));
            let path = workdir.join(name);
            v.elf_error = Some(report::ArtifactRefusal {
                why: format!("{}: not an ELF file (bad magic)", path.display()),
                mach_o: false,
            });
            v.artifact = Some(path);
            v
        };
        let mut facts = Facts::default();
        for name in ["pie-clean", "pie-pie-pos", "pie-pie-neg"] {
            facts.record(artifact_fact(&unreadable(name), workdir));
        }
        assert_eq!(facts.store.len(), 1, "{:?}", facts.store);
        assert!(facts.refused.is_empty(), "{:?}", facts.refused);
        let entry = facts.store.get(&"0".repeat(64)).expect("one entry");
        assert_eq!(
            entry,
            &report::FactEntry::Unreadable {
                error: "<artifact>: not an ELF file (bad magic)".to_owned(),
                mach_o: false,
            },
            "the reason names no path, and so nothing of the work directory"
        );

        // A second, different entry for the digest: refused, the first kept.
        let mut read = blank_variant();
        read.build = Some(variant_build(0, true));
        read.elf = Some(elf_with_report(""));
        facts.record(artifact_fact(&read, workdir));
        assert_eq!(facts.store.len(), 1);
        assert_eq!(facts.refused.len(), 1);
        let sentence = facts.refused[0].sentence();
        assert!(
            sentence.contains("kept unreadable") && sentence.contains("refused elf (x86_64"),
            "{sentence}"
        );

        // A build that wrote nothing has nothing to key an entry by.
        let mut nothing = blank_variant();
        nothing.build = Some(variant_build(0, false));
        nothing.elf_error = Some(report::ArtifactRefusal {
            why: "never read".to_owned(),
            mach_o: false,
        });
        assert_eq!(artifact_fact(&nothing, workdir), None);
    }

    #[test]
    fn a_dump_is_stored_under_the_digest_its_record_publishes() {
        let stdout = "#define __SSP_STRONG__ 3\n#define __unrelated__ 1\n#define __PIE__ 2";
        let mut dump = variant_build(0, false);
        dump.stdout = stdout.to_owned();
        let mut variant = blank_variant();
        variant.macro_dump = Some(dump.clone());
        variant.macros_preprocessor = compile::parse_macros(stdout);
        variant.macros = variant.macros_preprocessor.clone();

        let published = published_dump_record(&dump);
        let (key, entry) = dump_fact(&variant).expect("a preprocessor reading is stored");
        assert_eq!(published.stdout_sha256.as_deref(), Some(key.as_str()));
        assert_eq!(key, compile::dump_digest(stdout));
        // The key is over the sorted lines.
        assert_eq!(macro_key(&variant), Some(key.clone()));
        let reordered = "#define __unrelated__ 1\n#define __PIE__ 2\n#define __SSP_STRONG__ 3";
        assert_eq!(compile::dump_digest(reordered), key);
        assert_ne!(key, crate::digest::sha256_hex(stdout.as_bytes()));
        assert_ne!(key, crate::digest::sha256_hex(reordered.as_bytes()));
        let set_dump = |variant: &mut Variant, text: &str| {
            variant.macro_dump.as_mut().expect("the dump").stdout = text.to_owned();
        };
        set_dump(&mut variant, reordered);
        assert_eq!(
            dump_fact(&variant).map(|(k, _)| k),
            Some(key.clone()),
            "a reordered dump is stored under the same key"
        );
        assert_eq!(macro_key(&variant), Some(key.clone()));
        set_dump(
            &mut variant,
            "#define __SSP_STRONG__ 2\n#define __unrelated__ 1\n#define __PIE__ 2",
        );
        assert_ne!(
            dump_fact(&variant).map(|(k, _)| k),
            Some(key.clone()),
            "a changed line moves the key"
        );
        set_dump(&mut variant, stdout);
        assert!(published.stdout.starts_with("<3 #define line(s) omitted"));
        assert_eq!(
            entry,
            report::FactEntry::MacroDump {
                defines: 3,
                macros_filter: report::evidence_filters().macros.sha256,
                macros: BTreeMap::from([
                    ("__PIE__".to_owned(), "2".to_owned()),
                    ("__SSP_STRONG__".to_owned(), "3".to_owned()),
                ]),
            },
            "the store keeps the defines the published filter keeps"
        );
        // The record a detector reads is untouched.
        assert_eq!(dump.stdout_sha256, None);

        // Read from the artifact instead: the artifact's entry is the store's account.
        variant.macro_source = "compiled-artifact";
        assert_eq!(dump_fact(&variant), None);
    }

    #[test]
    fn only_a_probe_with_a_chain_is_told_where_to_follow_it() {
        let workdir = Path::new("/tmp/chard-test");
        let chained = probe::CORPUS
            .iter()
            .find(|p| !p.aux_libs.is_empty())
            .expect("the corpus has a probe that builds its own chain");
        let plain = probe::CORPUS
            .iter()
            .find(|p| p.aux_libs.is_empty())
            .expect("and many that do not");

        let flags = chain_search_flags(chained, workdir);
        assert_eq!(flags.len(), 2, "a search path and a link-time search path");
        assert!(flags.iter().any(|f| f == "-L/tmp/chard-test"));
        assert!(flags.iter().any(|f| f == "-Wl,-rpath-link,/tmp/chard-test"));

        assert!(
            chain_search_flags(plain, workdir).is_empty(),
            "a probe with no chain is given nothing to follow: {}",
            plain.id
        );
    }

    #[test]
    fn a_chain_link_takes_the_arms_selections_and_linker_and_nothing_else() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let workdir = Path::new("/tmp/chard-test");
        let arm = line(
            "--target=aarch64-linux-gnu --sysroot=/srv/root -static-libgcc -B /opt/bin \
             -I /srv/i -fuse-ld=lld -Wl,--no-copy-dt-needed-entries -O2 -pthread \
             -fstack-protector-strong",
        );
        assert_eq!(
            aux_lib_flags(&arm, "chard_dt_b", workdir),
            line(
                "--target=aarch64-linux-gnu --sysroot=/srv/root -static-libgcc -B /opt/bin \
                 -I /srv/i -pthread -fuse-ld=lld -shared -fPIC -Wl,-soname,libchard_dt_b.so \
                 -L/tmp/chard-test -Wl,-rpath-link,/tmp/chard-test"
            ),
        );
        assert_eq!(
            aux_lib_flags(&line("-O2 -Wl,-z,now"), "chard_dt_a", workdir),
            line(
                "-shared -fPIC -Wl,-soname,libchard_dt_a.so -L/tmp/chard-test \
                 -Wl,-rpath-link,/tmp/chard-test"
            ),
            "an arm selecting nothing leaves the chain the scaffolding alone"
        );
    }

    #[test]
    fn the_arms_link_listing_is_taken_under_the_measured_links_form() {
        use crate::link_inputs::LinkageForm;
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let selection = line("--target=x86_64-linux-gnu --gcc-install-dir=/srv/g -fuse-ld=lld");
        let mut fed = 0_usize;
        for (form, flag) in [
            (LinkageForm::Pie, "-pie"),
            (LinkageForm::NoPie, "-no-pie"),
            (LinkageForm::Shared, "-shared"),
            (LinkageForm::Static, "-static"),
            (LinkageForm::StaticPie, "-static-pie"),
        ] {
            let query = arms_link_query(selection.clone(), form);
            assert_eq!(
                query[..selection.len()],
                selection[..],
                "the selection comes first, unchanged"
            );
            assert_eq!(
                query[selection.len()..],
                [flag.to_owned()],
                "{form:?} appends its flag and nothing else"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 5, "every form was fed");
        assert_eq!(
            arms_link_query(Vec::new(), LinkageForm::Pie),
            line("-pie"),
            "an empty selection still takes the form"
        );
    }

    #[test]
    fn a_chain_link_fails_on_either_condition() {
        assert!(
            !aux_build_failed(&variant_build(0, true)),
            "exit zero with an artifact is the one case that succeeded"
        );
        assert!(
            aux_build_failed(&variant_build(1, true)),
            "a non-zero exit is a failure whatever it left on disk"
        );
        assert!(
            aux_build_failed(&variant_build(0, false)),
            "and so is a clean exit that produced nothing to link against"
        );
        assert!(aux_build_failed(&variant_build(1, false)));
    }

    #[test]
    fn a_fortify_request_the_libc_settled_lower_gates_only_that_case() {
        let check = check_named("fortify-enforced-dynamic");
        let macros = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<String, String>>()
        };
        let declined = macros(&[
            ("_FORTIFY_SOURCE", "3"),
            ("__USE_FORTIFY_LEVEL", "2"),
            ("__OPTIMIZE__", "1"),
        ]);

        let gated = fortify_level_declined(Verdict::ProbeInvalid, check, &declined)
            .expect("a request that arrived and was settled lower is the libc declining");
        assert_eq!(gated.rule, report::gating_rule::FORTIFY_LEVEL_DECLINED);
        assert!(
            gated.reason.contains("_FORTIFY_SOURCE=3")
                && gated.reason.contains("__USE_FORTIFY_LEVEL=2"),
            "both numbers must be quoted so the claim is checkable, got: {}",
            gated.reason
        );

        for (why, m) in [
            (
                "the request never arrived, so the arm measured something else",
                macros(&[
                    ("_FORTIFY_SOURCE", "2"),
                    ("__USE_FORTIFY_LEVEL", "2"),
                    ("__OPTIMIZE__", "1"),
                ]),
            ),
            (
                "the libc settled at the level asked for, so silence is chard's problem",
                macros(&[
                    ("_FORTIFY_SOURCE", "3"),
                    ("__USE_FORTIFY_LEVEL", "3"),
                    ("__OPTIMIZE__", "1"),
                ]),
            ),
            (
                "unoptimized: glibc installs nothing whatever the level says",
                macros(&[
                    ("_FORTIFY_SOURCE", "3"),
                    ("__USE_FORTIFY_LEVEL", "2"),
                    ("__OPTIMIZE__", "?"),
                ]),
            ),
            (
                "no settled level at all, which is fortify-headers and musl, not glibc",
                macros(&[("_FORTIFY_SOURCE", "3"), ("__OPTIMIZE__", "1")]),
            ),
        ] {
            assert!(
                fortify_level_declined(Verdict::ProbeInvalid, check, &m).is_none(),
                "gated where it should not: {why}"
            );
        }

        for verdict in [Verdict::On, Verdict::Off, Verdict::Unsupported] {
            assert!(
                fortify_level_declined(verdict, check, &declined).is_none(),
                "{verdict:?} was relabelled as a libc limitation"
            );
        }
    }

    #[test]
    fn a_z_keyword_the_linker_ignored_gates_only_the_check_that_supplied_it() {
        let check = check_named("relative-relocs");
        let control = check.positive;
        assert!(
            z_keywords(control).contains(&"pack-relative-relocs"),
            "the check's own control is what names the keyword: {control:?}"
        );

        for said in [
            "/usr/bin/ld: warning: -z pack-relative-relocs ignored.",
            "/usr/bin/ld: warning: -z pack-relative-relocs ignored",
            "ld: warning: unknown -z value: pack-relative-relocs",
            "clang: /usr/bin/ld: warning: -z pack-relative-relocs ignored",
        ] {
            let quoted = z_keyword_rejection(&build_with_stderr(said), control)
                .unwrap_or_else(|| panic!("not recognised: {said}"));
            let gated = linker_keyword_limitation(Verdict::ProbeInvalid, check, Some(&quoted))
                .expect("a linker that ignored the keyword gates the check");
            assert!(
                gated.reason.contains(said.trim()),
                "the gating must quote the linker verbatim, got: {}",
                gated.reason
            );
        }

        // A warning about someone else's keyword is not this check's evidence.
        assert!(
            z_keyword_rejection(
                &build_with_stderr("/usr/bin/ld: warning: -z separate-code ignored"),
                control,
            )
            .is_none(),
            "a keyword this check did not supply was read as its own"
        );
        // And silence is not a rejection: binutils 2.38 implements this and says nothing.
        assert!(
            z_keyword_rejection(&build_with_stderr(""), control).is_none(),
            "a quiet link was read as a refusal"
        );

        for verdict in [Verdict::On, Verdict::Off, Verdict::Unsupported] {
            assert!(
                linker_keyword_limitation(verdict, check, Some("ld: warning: -z x ignored"))
                    .is_none(),
                "{verdict:?} was relabelled as a linker limitation"
            );
        }
    }

    #[test]
    fn an_observable_the_standard_library_does_not_have_gates_only_that_check() {
        let symbol = check_named("cxx-assertions-symbol");

        let gated = stdlib_limitation(
            Verdict::ProbeInvalid,
            symbol,
            Some("libc++"),
            Some("libc++"),
        )
        .expect("libc++ has no libstdc++ assertion symbol to read");
        assert!(
            gated.reason.contains("libc++"),
            "the gating must name the library that answered, got: {}",
            gated.reason
        );

        assert!(
            stdlib_limitation(
                Verdict::ProbeInvalid,
                symbol,
                Some("libstdc++"),
                Some("libstdc++")
            )
            .is_none(),
            "the implementation the observable belongs to was gated out of its own check"
        );
        assert!(
            stdlib_limitation(Verdict::ProbeInvalid, symbol, None, None).is_none(),
            "a toolchain that named no standard library gated a check anyway"
        );
        // Controls on one library and a measured build on another are a triple that could
        // not discriminate for what was measured, not a question with no referent, and must
        // not settle `--fail-on-missing`.
        for (clean, measured) in [
            (Some("libc++"), Some("libstdc++")),
            (Some("libc++"), None),
            (None, Some("libc++")),
        ] {
            assert!(
                stdlib_limitation(Verdict::ProbeInvalid, symbol, clean, measured).is_none(),
                "controls on {clean:?} and a measured build on {measured:?} read as \
                 not-applicable"
            );
        }

        // A check that declares no unsupported library is never gated by this rule, on
        // any library: `cxx-stdlib-assertions` is how libc++ hardening is measured.
        let sibling = check_named("cxx-stdlib-assertions");
        for stdlib in ["libc++", "libstdc++"] {
            assert!(
                stdlib_limitation(Verdict::ProbeInvalid, sibling, Some(stdlib), Some(stdlib))
                    .is_none(),
                "{stdlib} gated a check that declared no limitation against it"
            );
        }

        for verdict in [Verdict::On, Verdict::Off, Verdict::Unsupported] {
            assert!(
                stdlib_limitation(verdict, symbol, Some("libc++"), Some("libc++")).is_none(),
                "{verdict:?} was relabelled as a standard-library limitation"
            );
        }
    }

    #[test]
    fn a_rejection_must_name_this_checks_own_control_flag() {
        let rejected = build_with_stderr(
            "clang: warning: unknown warning option '-Wtrampolines'; did you mean '-Wtrampoline'?",
        );
        let found = control_flag_rejection(&rejected, &["-Wtrampolines"])
            .expect("clang naming the control flag is a rejection of it");
        // The rejected set, before the quoted line, is the control flag alone: clang's
        // `did you mean '-Wtrampoline'?` names a flag this check did not supply.
        let (rejected_set, quoted) = found
            .split_once(": ")
            .expect("the reason names the rejected flags, then quotes the line");
        assert_eq!(rejected_set, "clang does not know -Wtrampolines");
        assert!(
            quoted.contains("did you mean"),
            "the driver's own line is quoted whole, got: {quoted}"
        );

        assert!(
            control_flag_rejection(&rejected, &["-Wbidi-chars=any"]).is_none(),
            "a line about a different flag is not a rejection of this check's control"
        );
        assert!(
            control_flag_rejection(
                &build_with_stderr("warning: something else entirely"),
                &["-Wtrampolines"]
            )
            .is_none(),
            "a line with no rejection phrase is not a rejection"
        );
    }

    #[test]
    fn a_limitation_relabels_only_a_withheld_verdict() {
        let musl_gated = check_named("fortify-requested");
        let absent = controls_with_positive(probe::Outcome::Absent);

        let withheld = known_limitation(
            Verdict::ProbeInvalid,
            musl_gated,
            "musl",
            "gcc",
            absent.positive.outcome,
        )
        .expect("a musl-gated check whose forced-on arm showed nothing is a libc limit");
        assert_eq!(withheld.libc.as_deref(), Some("musl"));

        // The same everything, on a verdict the measurement actually reached.
        for verdict in [Verdict::On, Verdict::Off, Verdict::BuildFailed] {
            assert!(
                known_limitation(verdict, musl_gated, "musl", "gcc", absent.positive.outcome)
                    .is_none(),
                "{verdict:?} was relabelled as a libc limitation"
            );
        }
    }

    #[test]
    fn a_gcc_only_option_is_a_compiler_limitation_on_clang_and_not_on_gcc() {
        let gcc_only = check_named("trampolines-warned");
        let absent = controls_with_positive(probe::Outcome::Absent);

        assert!(
            known_limitation(
                Verdict::ProbeInvalid,
                gcc_only,
                "glibc",
                "clang",
                absent.positive.outcome
            )
            .is_some(),
            "-Wtrampolines has no clang equivalent, so clang declined nothing"
        );
        assert!(
            known_limitation(
                Verdict::ProbeInvalid,
                gcc_only,
                "glibc",
                "gcc",
                absent.positive.outcome
            )
            .is_none(),
            "on gcc the option exists, so a withheld verdict is chard's problem"
        );

        // A check gated on neither is never relabelled, whatever the pair.
        let ungated = check_named("pie-macro");
        assert!(
            known_limitation(
                Verdict::ProbeInvalid,
                ungated,
                "musl",
                "clang",
                absent.positive.outcome
            )
            .is_none()
        );
    }

    #[test]
    fn a_libc_that_demonstrated_the_mechanism_is_not_reported_as_lacking_it() {
        let musl_gated = check_named("fortify-requested");
        for outcome in [probe::Outcome::Present, probe::Outcome::Indeterminate] {
            assert!(
                known_limitation(
                    Verdict::ProbeInvalid,
                    musl_gated,
                    "musl",
                    "gcc",
                    Some(outcome),
                )
                .is_none(),
                "a positive arm reading `{}` has not established a limitation",
                outcome.as_str()
            );
        }
    }

    /// An observation of `check_id` whose build wrote an artifact with digest `sha`, and
    /// the store entry `run_check` records for it.
    fn observed_artifact(
        probe_id: &str,
        check_id: &str,
        sha: &str,
        elf: elf::ElfFacts,
    ) -> (Observation, Option<(String, report::FactEntry)>) {
        let probe = probe::find(probe_id).expect("a corpus probe");
        let check = probe
            .checks
            .iter()
            .find(|c| c.id == check_id)
            .expect("a check of that probe");
        let mut observation = blank_observation(probe, check, Verdict::On);
        let mut build = variant_build(0, true);
        build.artifact_sha256 = Some(sha.to_owned());
        observation.build = Some(build);
        observation.controls = Some(controls_with_positive(probe::Outcome::Present));
        (
            observation,
            Some((
                sha.to_owned(),
                report::FactEntry::Elf { elf: Box::new(elf) },
            )),
        )
    }

    /// The observations, and the store their entries make.
    fn split<const N: usize>(
        items: [(Observation, Option<(String, report::FactEntry)>); N],
    ) -> (Vec<Observation>, report::FactStore) {
        let mut facts = Facts::default();
        let observations = items
            .into_iter()
            .map(|(observation, entry)| {
                facts.record(entry);
                observation
            })
            .collect();
        assert!(facts.refused.is_empty(), "{:?}", facts.refused);
        (observations, facts.store)
    }

    /// The facts of a linked executable whose `.comment` carries `lines`.
    fn linked_with_comment(lines: &[&str]) -> elf::ElfFacts {
        let mut elf = elf_with_report("");
        elf.comment = lines.iter().map(|l| (*l).to_owned()).collect();
        elf
    }

    const GCC_LINE: &str = "GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)";
    const LLD_LINE: &str = "Linker: LLD 22.1.8";

    #[test]
    fn artifact_comments_keys_one_artifact_by_its_digest() {
        let sha = "a".repeat(64);
        let (observations, facts) = split([
            observed_artifact(
                "link-defaults",
                "pie",
                &sha,
                linked_with_comment(&[GCC_LINE]),
            ),
            observed_artifact(
                "link-defaults",
                "relro",
                &sha,
                linked_with_comment(&[GCC_LINE]),
            ),
        ]);
        let (c, cxx) = artifact_comments(&observations, &facts, false, LinkSelections::default());
        assert_eq!(c.artifacts.len(), 1, "{:?}", c.artifacts);
        assert_eq!(
            c.artifacts[0].label,
            "link-defaults-measured sha256:aaaaaaaaaaaaaaaa"
        );
        assert_eq!(c.artifacts[0].lines, vec![GCC_LINE.to_owned()]);
        assert!(!c.artifacts[0].relocatable && !c.artifacts[0].profile_free);
        assert!(c.artifacts[0].unread.is_none());
        assert!(c.without_facts.is_empty(), "{:?}", c.without_facts);
        assert!(cxx.artifacts.is_empty() && cxx.without_facts.is_empty());

        let (clean, _) = artifact_comments(&observations, &facts, true, LinkSelections::default());
        assert_eq!(
            clean.artifacts[0].label, "link-defaults-clean sha256:aaaaaaaaaaaaaaaa",
            "under a profile with no flags the measured build is the clean build"
        );
        assert!(!clean.artifacts[0].profile_free);
    }

    #[test]
    fn artifact_comments_leaves_out_a_build_withheld_before_its_triple() {
        let (mut withheld, entry) = observed_artifact(
            "link-defaults",
            "pie",
            &"b".repeat(64),
            linked_with_comment(&[GCC_LINE]),
        );
        withheld.controls = None;
        let (observations, facts) = split([(withheld, entry)]);
        assert_eq!(facts.len(), 1, "the build is stored");
        let (c, _) = artifact_comments(&observations, &facts, false, LinkSelections::default());
        assert!(c.artifacts.is_empty(), "{:?}", c.artifacts);
        assert_eq!(c.without_facts, vec!["link-defaults".to_owned()]);
    }

    #[test]
    fn artifact_comments_marks_relocatables_and_unread_sections() {
        let mut no_pie = linked_with_comment(&[GCC_LINE]);
        no_pie.pie = None;
        let mut unread = linked_with_comment(&[]);
        unread.truncations.push(elf::Truncation {
            table: elf::ElfTable::Comment,
            kind: elf::TruncationKind::Unread,
            detail: ".comment: 0x900+0x40 could not be read (past EOF)".to_owned(),
        });
        let (observations, facts) = split([
            observed_artifact(
                "cet-object",
                "cet-marked-object",
                &"b".repeat(64),
                linked_with_comment(&[GCC_LINE]),
            ),
            observed_artifact("link-defaults", "pie", &"c".repeat(64), no_pie),
            observed_artifact("link-defaults", "relro", &"d".repeat(64), unread),
        ]);
        let (c, _) = artifact_comments(&observations, &facts, false, LinkSelections::default());
        assert_eq!(c.artifacts.len(), 3, "{:?}", c.artifacts);
        assert!(
            c.artifacts[0].relocatable,
            "an Object-mode probe's artifact: {:?}",
            c.artifacts[0]
        );
        assert!(
            c.artifacts[1].relocatable,
            "facts with no `pie` reading are a relocatable's: {:?}",
            c.artifacts[1]
        );
        assert!(!c.artifacts[2].relocatable);
        assert!(
            c.artifacts[2]
                .unread
                .as_deref()
                .is_some_and(|why| why.contains("could not be read")),
            "{:?}",
            c.artifacts[2]
        );
    }

    #[test]
    fn artifact_comments_leaves_the_clean_build_uncounted_under_a_profile_that_selects() {
        const CLEAN: &str = "linker-default-execstack-clean sha256:ffffffffffffffff";
        let (observations, facts) = split([
            observed_artifact(
                "link-defaults",
                "pie",
                &"e".repeat(64),
                linked_with_comment(&[GCC_LINE, LLD_LINE]),
            ),
            observed_artifact(
                "linker-default-execstack",
                "linker-default-noexecstack",
                &"f".repeat(64),
                linked_with_comment(&[GCC_LINE]),
            ),
        ]);
        let lld = ["-fuse-ld=lld".to_owned()];
        let (c, _) = artifact_comments(
            &observations,
            &facts,
            false,
            LinkSelections { c: &lld, cxx: None },
        );
        assert_eq!(c.artifacts.len(), 2);
        assert_eq!(c.selection, lld);
        assert_eq!(c.artifacts[1].label, CLEAN);
        assert!(c.artifacts[1].profile_free, "{:?}", c.artifacts[1]);
        assert!(!c.artifacts[0].profile_free, "{:?}", c.artifacts[0]);
        let held = toolchain::artifact_agreement("lld", Some("LLD 22.1.8"), &c);
        assert_eq!(
            held.agreement,
            toolchain::Agreement::Agrees,
            "{}",
            held.evidence
        );
        assert_eq!(held.artifacts_read, 1);
        assert!(
            held.evidence.contains(CLEAN)
                && held
                    .evidence
                    .contains("while the profile selected `-fuse-ld=lld`"),
            "{}",
            held.evidence
        );

        // Flags that select no linker: the clean artifact counts, and beside a signed
        // one it is the run's own artifacts disagreeing.
        let unselected = LinkSelections::default();
        let (flagged, _) = artifact_comments(&observations, &facts, false, unselected);
        assert!(
            flagged.artifacts.iter().all(|a| !a.profile_free),
            "{:?}",
            flagged.artifacts
        );
        assert_eq!(
            flagged.artifacts[1].label, CLEAN,
            "the label says which build was read"
        );
        let both = toolchain::artifact_agreement("lld", Some("LLD 22.1.8"), &flagged);
        assert_eq!(
            both.agreement,
            toolchain::Agreement::Disagrees,
            "{}",
            both.evidence
        );
        assert_eq!(both.artifacts_read, 2);
        assert!(
            both.evidence.contains("the run's own artifacts disagree")
                && !both.evidence.contains("while the profile selected"),
            "{}",
            both.evidence
        );
        // Alone under an lld banner, the unsigned clean artifact is the disagreement the
        // assumption exists to publish.
        let (alone, _) = artifact_comments(&observations[1..], &facts, false, unselected);
        let lying = toolchain::artifact_agreement("lld", Some("LLD 22.1.8"), &alone);
        assert_eq!(
            lying.agreement,
            toolchain::Agreement::Disagrees,
            "{}",
            lying.evidence
        );
        assert_eq!(lying.artifacts_read, 1);
        assert!(
            lying.evidence.contains("lld-and-mold-sign-every-output"),
            "{}",
            lying.evidence
        );

        // No flags at all: the clean build is the one link line there is.
        let (clean, _) = artifact_comments(&observations, &facts, true, unselected);
        assert!(!clean.artifacts[1].profile_free, "{:?}", clean.artifacts[1]);
        assert_eq!(clean.artifacts[1].label, CLEAN);
    }

    #[test]
    fn artifact_comments_counts_the_clean_build_under_a_prefix_alone() {
        let (observations, facts) = split([
            observed_artifact(
                "link-defaults",
                "pie",
                &"e".repeat(64),
                linked_with_comment(&[GCC_LINE, LLD_LINE]),
            ),
            observed_artifact(
                "linker-default-execstack",
                "linker-default-noexecstack",
                &"f".repeat(64),
                linked_with_comment(&[GCC_LINE]),
            ),
        ]);
        let mut fed = 0_usize;
        for prefixes in [
            vec!["-B/opt/mold/libexec".to_owned()],
            vec!["--prefix".to_owned(), "/opt/mold/libexec".to_owned()],
        ] {
            let (prefixed, _) = artifact_comments(
                &observations,
                &facts,
                false,
                LinkSelections {
                    c: &prefixes,
                    cxx: None,
                },
            );
            assert_eq!(prefixed.selection, prefixes);
            assert_eq!(prefixed.artifacts.len(), 2);
            assert!(
                prefixed.artifacts.iter().all(|a| !a.profile_free),
                "{prefixes:?}: {:?}",
                prefixed.artifacts
            );
            let mut with_program = prefixes.clone();
            with_program.push("-fuse-ld=lld".to_owned());
            let (programmed, _) = artifact_comments(
                &observations,
                &facts,
                false,
                LinkSelections {
                    c: &with_program,
                    cxx: None,
                },
            );
            assert!(
                programmed.artifacts[1].profile_free,
                "{:?}",
                programmed.artifacts[1]
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, 2, "both spellings of the prefix were fed");
    }

    #[test]
    fn artifact_comments_splits_the_cxx_probes_and_names_the_probes_that_fed_nothing() {
        let no_facts = |probe_id: &str, check_id: &str| {
            let probe = probe::find(probe_id).expect("a corpus probe");
            let check = probe
                .checks
                .iter()
                .find(|c| c.id == check_id)
                .expect("a check of that probe");
            (blank_observation(probe, check, Verdict::BuildFailed), None)
        };
        let (observations, facts) = split([
            observed_artifact(
                "link-defaults",
                "pie",
                &"1".repeat(64),
                linked_with_comment(&[GCC_LINE]),
            ),
            observed_artifact(
                "cxx-stdlib-assertions",
                "cxx-stdlib-assertions",
                &"2".repeat(64),
                linked_with_comment(&[GCC_LINE, LLD_LINE]),
            ),
            no_facts("stack-canary", "canary-emitted"),
            no_facts("cet-object", "cet-marked-object"),
        ]);
        let lld = ["-fuse-ld=lld".to_owned()];
        let split = LinkSelections {
            c: &[],
            cxx: Some(&lld),
        };
        let (c, cxx) = artifact_comments(&observations, &facts, false, split);
        assert_eq!(c.artifacts.len(), 1, "{:?}", c.artifacts);
        assert_eq!(cxx.artifacts.len(), 1, "{:?}", cxx.artifacts);
        assert!(c.selection.is_empty(), "{:?}", c.selection);
        assert_eq!(cxx.selection, lld);
        assert_eq!(
            cxx.artifacts[0].label,
            "cxx-stdlib-assertions-measured sha256:2222222222222222"
        );
        assert_eq!(
            c.without_facts,
            vec!["cet-object".to_owned(), "stack-canary".to_owned()],
            "named once each, in id order"
        );
        assert!(cxx.without_facts.is_empty(), "{:?}", cxx.without_facts);

        let (one, none) =
            artifact_comments(&observations, &facts, false, LinkSelections::default());
        assert_eq!(
            one.artifacts.len(),
            2,
            "with one linker every artifact is held to it: {:?}",
            one.artifacts
        );
        assert!(none.artifacts.is_empty() && none.without_facts.is_empty());
        assert!(none.selection.is_empty(), "{:?}", none.selection);
    }

    /// A control arm as `report::decide` takes it, with no flags: these tests read the
    /// verdict and the withheld cause, never the arm's flags.
    fn arm(detection: Option<&Detection>) -> report::ArmInput<'_> {
        report::ArmInput {
            detection,
            flags: Vec::new(),
            overridden: None,
        }
    }

    /// A regime arm that was required and evaluated.
    fn regime_arm(detection: Option<&Detection>) -> Option<report::ArmInput<'_>> {
        detection.map(|d| arm(Some(d)))
    }

    /// The verdict `decide` reached on a discriminating triple around a reading, and the
    /// reading: forced on read present at the recommended level, forced off read absent.
    fn decided(check: &Check, level: Option<&str>, observed: &str) -> (Verdict, Detection) {
        let reading = Detection {
            outcome: probe::Outcome::Present,
            level: level.map(ToOwned::to_owned),
            observed: observed.to_owned(),
            rule: None,
        };
        let grade = check.levels.grade().expect("the check is graded");
        let positive = Detection {
            outcome: probe::Outcome::Present,
            level: Some(grade.recommended.to_owned()),
            observed: observed.to_owned(),
            rule: None,
        };
        let negative = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let (verdict, controls) = report::decide(
            &reading,
            arm(Some(&positive)),
            arm(Some(&negative)),
            None,
            Some(grade),
        );
        assert!(
            controls.discriminating(),
            "the triple around the reading agrees"
        );
        (verdict, reading)
    }

    /// A declared limitation that fires whenever it is asked, so a test sees exactly where
    /// `settle` asks.
    fn always_declared() -> impl FnOnce(Verdict) -> Option<report::Gating> {
        |_| {
            Some(report::Gating {
                rule: report::gating_rule::LIBC_DECLARED,
                arch: None,
                libc: Some("test".to_owned()),
                needs_vm: false,
                reason: "declared".to_owned(),
            })
        }
    }

    #[test]
    fn an_off_scale_level_is_withheld_under_its_own_rule() {
        let ssp = check_named("ssp-level");
        let (verdict, reading) = decided(ssp, Some("bogus"), "__SSP_STRONG__=3");
        assert_eq!(verdict, Verdict::Indeterminate);
        let settled = settle_for(verdict, ssp, &reading, always_declared(), None, None, &[]);
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled.gating.expect("an off-scale level names its reason");
        assert_eq!(gating.rule, report::gating_rule::LEVEL_OFF_SCALE);
        assert!(gating.reason.contains("`bogus`"), "{}", gating.reason);
        assert_eq!(
            settled.level, None,
            "an ungraded word is not published as a level"
        );
    }

    #[test]
    fn a_forged_macro_overwrites_the_level_reason() {
        let ssp = check_named("ssp-level");
        assert_eq!(ssp.channel(), Channel::Macro);
        let (verdict, reading) = decided(ssp, Some("bogus"), "__SSP_STRONG__=3");
        let forged = ["-D__SSP_STRONG__=3".to_owned()];
        let settled = settle_for(
            verdict,
            ssp,
            &reading,
            always_declared(),
            None,
            None,
            &forged,
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled.gating.expect("a forged macro names its reason");
        assert_eq!(gating.rule, report::gating_rule::MACRO_SPOOFED);
        assert!(
            gating.reason.contains("__SSP_STRONG__"),
            "{}",
            gating.reason
        );
        assert_eq!(settled.level, None);
    }

    #[test]
    fn a_present_reading_with_no_level_on_a_graded_check_is_withheld() {
        let ssp = check_named("ssp-level");
        let (verdict, reading) = decided(ssp, None, "__SSP__=1");
        assert_eq!(verdict, Verdict::Indeterminate);
        let settled = settle_for(verdict, ssp, &reading, always_declared(), None, None, &[]);
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled.gating.expect("a missing level names its reason");
        assert_eq!(gating.rule, report::gating_rule::LEVEL_OFF_SCALE);
        assert!(gating.reason.contains("no level"), "{}", gating.reason);
        assert_eq!(settled.level, None);
    }

    #[test]
    fn the_artifact_rule_leaves_a_level_reason_standing() {
        let relro = check_named("relro");
        let mut no_dynamic = elf_with_report("");
        no_dynamic.has_dynamic = false;
        let (verdict, reading) = decided(relro, Some("bogus"), "PT_GNU_RELRO");
        assert_eq!(verdict, Verdict::Indeterminate);
        let settled = settle_for(
            verdict,
            relro,
            &reading,
            always_declared(),
            Some(&no_dynamic),
            None,
            &[],
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled.gating.expect("the level reason stands");
        assert_eq!(gating.rule, report::gating_rule::LEVEL_OFF_SCALE);

        let absent = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let settled = settle_for(
            Verdict::Off,
            relro,
            &absent,
            always_declared(),
            Some(&no_dynamic),
            None,
            &[],
        );
        assert_eq!(settled.verdict, Verdict::NotApplicable);
        assert_eq!(
            settled.gating.map(|g| g.rule),
            Some(report::gating_rule::ARTIFACT_CANNOT_CARRY)
        );
    }

    /// The six shapes that record no C library, each with its `elf_type` and a phrase of the
    /// clause that withholds it: a `-static` executable with no `.dynamic`; a static PIE,
    /// which has one; a relocatable object with every link fact `None`; and three the
    /// classifier reads as dynamic links: an interpreter forged onto an object with no dynamic
    /// section, and the `-static-pie -Wl,--dynamic-linker=<path>` link alone and given one
    /// shared library, whose list names `libz.so.1` and no C library.
    fn artifacts_that_record_no_library() -> [(elf::ElfFacts, &'static str, &'static str); 6] {
        let mut static_exec = elf_with_report("");
        static_exec.has_interp = false;
        static_exec.has_dynamic = false;
        static_exec.statically_linked = Some(true);
        let mut static_pie = elf_with_report("");
        static_pie.elf_type = "ET_DYN".to_owned();
        static_pie.has_interp = false;
        static_pie.pie = Some(true);
        static_pie.static_pie = Some(true);
        static_pie.statically_linked = Some(true);
        let mut relocatable = elf_with_report("");
        relocatable.elf_type = "ET_REL".to_owned();
        relocatable.has_interp = false;
        relocatable.has_dynamic = false;
        for slot in [
            &mut relocatable.pie,
            &mut relocatable.static_pie,
            &mut relocatable.shared_object,
            &mut relocatable.statically_linked,
            &mut relocatable.gnu_relro,
            &mut relocatable.bind_now,
            &mut relocatable.gnu_stack_present,
            &mut relocatable.gnu_stack_executable,
        ] {
            *slot = None;
        }
        relocatable.relro = None;
        let mut interp_alone = elf_with_report("");
        interp_alone.has_dynamic = false;
        assert_eq!(interp_alone.statically_linked, Some(false));
        let mut interp_libz = elf_with_report("");
        interp_libz.elf_type = "ET_DYN".to_owned();
        interp_libz.pie = Some(true);
        interp_libz.needed = vec!["libz.so.1".to_owned()];
        assert!(interp_libz.has_interp && interp_libz.has_dynamic);
        let mut interp_no_entry = elf_with_report("");
        interp_no_entry.elf_type = "ET_DYN".to_owned();
        interp_no_entry.pie = Some(true);
        interp_no_entry.dt_debug = true;
        interp_no_entry.df_1_pie = true;
        assert!(interp_no_entry.has_interp && interp_no_entry.has_dynamic);
        assert!(
            interp_no_entry.needed.is_empty(),
            "this artifact records no needed library: {:?}",
            interp_no_entry.needed
        );
        assert_eq!(interp_no_entry.statically_linked, Some(false));
        [
            (static_exec, "ET_EXEC", "no dynamic section"),
            (static_pie, "ET_DYN", "C library on executable output"),
            (relocatable, "ET_REL", "cannot run an object of this type"),
            (interp_alone, "ET_EXEC", "no dynamic section"),
            (interp_no_entry, "ET_DYN", "C library on executable output"),
            (interp_libz, "ET_DYN", "C library on executable output"),
        ]
    }

    /// The facts the reader takes from a checked-in synthetic object under
    /// `tests/fixtures/elf/`.
    fn fixture_facts(name: &str) -> elf::ElfFacts {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/elf")
            .join(format!("{name}.elf"));
        elf::facts_for(&path).unwrap_or_else(|e| panic!("{name} reads: {e}"))
    }

    #[test]
    fn an_executable_links_shared_object_classification_withholds_pie_and_as_needed() {
        let g = report::gating_rule::LINK_MODE_CONTRADICTED;
        let unmarked = fixture_facts("elf64-le-x86_64-static-pie-unmarked");
        assert_eq!(
            unmarked.shared_object,
            Some(true),
            "the classifier's reading"
        );

        let mut gated = 0;
        for (id, ungated, read_fields) in [
            ("pie", Verdict::Off, "pie, static_pie"),
            ("as-needed", Verdict::Indeterminate, "shared_object"),
        ] {
            let check = check_named(id);
            assert_eq!(check.channel(), Channel::ElfStatic, "{id}");
            assert_eq!(
                probe_of(check).link_mode,
                probe::LinkMode::Executable,
                "{id}"
            );
            let mut variant = blank_variant();
            variant.elf = Some(unmarked.clone());
            let reading = check.decode(&evidence_for(&variant)).detection;
            let present = Detection {
                outcome: probe::Outcome::Present,
                level: None,
                observed: String::new(),
                rule: None,
            };
            let absent = Detection {
                outcome: probe::Outcome::Absent,
                level: None,
                observed: String::new(),
                rule: None,
            };
            // `pie`'s observable is present when the flag acts; `as-needed`'s too, an entry
            // left out.
            let (verdict, controls) = report::decide(
                &reading,
                arm(Some(&present)),
                arm(Some(&absent)),
                None,
                None,
            );
            assert!(controls.discriminating(), "{id}: {controls:?}");
            assert_eq!(verdict, ungated, "{id}: the wrong verdict the gate stops");

            let settled = settle_for(
                verdict,
                check,
                &reading,
                always_declared(),
                Some(&unmarked),
                None,
                &[],
            );
            assert_eq!(settled.verdict, Verdict::Indeterminate, "{id}");
            let gating = settled.gating.expect("the contradiction names its rule");
            assert_eq!(gating.rule, g, "{id}");
            for quoted in [
                read_fields,
                "asked the driver for an executable",
                "classifies as a shared object",
                "ET_DYN",
            ] {
                assert!(
                    gating.reason.contains(quoted),
                    "{id}: `{quoted}` in {}",
                    gating.reason
                );
            }
            gated += 1;
        }
        assert_eq!(gated, 2);
    }

    #[test]
    fn as_needed_over_a_shared_object_classification_is_withheld_only_where_its_list_is_empty() {
        let unmarked = fixture_facts("elf64-le-x86_64-static-pie-unmarked");
        let as_needed = check_named("as-needed");
        let read = |facts: &elf::ElfFacts| {
            let mut variant = blank_variant();
            variant.elf = Some(facts.clone());
            as_needed.decode(&evidence_for(&variant)).detection
        };
        let positive = Detection {
            outcome: probe::Outcome::Present,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let negative = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let settled_over = |facts: &elf::ElfFacts| {
            let reading = read(facts);
            let (verdict, controls) = report::decide(
                &reading,
                arm(Some(&positive)),
                arm(Some(&negative)),
                None,
                None,
            );
            assert!(controls.discriminating());
            let settled = settle_for(
                verdict,
                as_needed,
                &reading,
                always_declared(),
                Some(facts),
                None,
                &[],
            );
            (reading, settled)
        };
        assert!(
            unmarked.needed.is_empty(),
            "the unmarked artifact lists no needed library: {:?}",
            unmarked.needed
        );
        let (reading, settled) = settled_over(&unmarked);
        assert_eq!(reading.outcome, probe::Outcome::Indeterminate);
        assert!(
            reading.observed.contains("shared_object=true"),
            "{}",
            reading.observed
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        assert_eq!(
            settled.gating.map(|g| g.rule),
            Some(report::gating_rule::LINK_MODE_CONTRADICTED),
            "the gate, before the row"
        );
        let mut kept = unmarked.clone();
        kept.needed = vec!["libm.so.6".to_owned(), "libc.so.6".to_owned()];
        let (reading, settled) = settled_over(&kept);
        assert_eq!(reading.outcome, probe::Outcome::Absent);
        assert!(
            !reading.observed.contains("shared_object="),
            "the list decided and the classification was not read: {}",
            reading.observed
        );
        assert_eq!(
            settled.verdict,
            Verdict::Off,
            "the list says what the link kept, and the gate leaves what did not rest on \
             the classification"
        );
        assert!(settled.gating.is_none(), "{:?}", settled.gating);
        // The C library recorded and the unused library not: `no-loader-output` reads the
        // classification to ask whether archives supplied it, and over a shared-object
        // classification that read is what the gate withholds.
        kept.needed = vec!["libc.so.6".to_owned()];
        let (reading, settled) = settled_over(&kept);
        assert_eq!(reading.outcome, probe::Outcome::Present);
        assert!(
            reading.observed.contains("statically_linked="),
            "{}",
            reading.observed
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        assert_eq!(
            settled.gating.map(|g| g.rule),
            Some(report::gating_rule::LINK_MODE_CONTRADICTED)
        );
    }

    #[test]
    fn a_measured_artifact_carries_its_probes_link_mode_for_every_probe() {
        let variant = blank_variant();
        let mut modes = BTreeSet::new();
        for p in probe::CORPUS {
            let artifact = MeasuredArtifact::of(p, &variant, None);
            assert_eq!(artifact.link_mode(), p.link_mode, "{}", p.id);
            assert!(
                artifact.read_fields().is_empty(),
                "{}: a reading with no proof rested on no field",
                p.id
            );
            modes.insert(format!("{:?}", p.link_mode));
        }
        assert!(modes.len() >= 3, "the corpus spans {modes:?}");
    }

    #[test]
    fn the_measured_artifact_carries_the_probes_link_mode_and_every_reading_is_withheld() {
        let unmarked = fixture_facts("elf64-le-x86_64-static-pie-unmarked");
        let mut variant = blank_variant();
        variant.elf = Some(unmarked.clone());
        let mut checked = 0;
        for id in ["pie", "as-needed"] {
            let check = check_named(id);
            let probe = probe_of(check);
            let decoding = check.decode(&evidence_for(&variant));
            let artifact = MeasuredArtifact::of(probe, &variant, decoding.proof.as_ref());
            assert_eq!(artifact.link_mode(), probe::LinkMode::Executable, "{id}");
            assert!(std::ptr::eq(
                artifact.elf().expect("the variant's facts"),
                variant.elf.as_ref().expect("set")
            ));
            assert!(
                artifact.read_fields().iter().any(|f| matches!(
                    f,
                    crate::predicate::ElfField::SharedObject | crate::predicate::ElfField::Pie
                )),
                "{id}: the reading rested on the classification"
            );
            for verdict in Verdict::ALL
                .iter()
                .copied()
                .filter(|v| !matches!(v, Verdict::ProbeInvalid | Verdict::Unsupported))
            {
                for outcome in [
                    probe::Outcome::Present,
                    probe::Outcome::Absent,
                    probe::Outcome::Indeterminate,
                ] {
                    let (gated, gating) = artifact_gating(
                        verdict,
                        check,
                        artifact.link_mode(),
                        outcome,
                        artifact.elf(),
                        &artifact.read_fields(),
                    )
                    .unwrap_or_else(|| panic!("{id}: {verdict:?} over {outcome:?} stood"));
                    assert_eq!(gated, Verdict::Indeterminate, "{id}: {verdict:?}");
                    assert_eq!(gating.rule, report::gating_rule::LINK_MODE_CONTRADICTED);
                    checked += 1;
                }
            }
        }
        assert!(checked >= 2 * 3 * 4, "{checked}");
    }

    #[test]
    fn the_link_mode_gate_leaves_what_the_probe_asked_for() {
        let unmarked = fixture_facts("elf64-le-x86_64-static-pie-unmarked");
        let marked = fixture_facts("elf64-le-x86_64-static-pie-dt-debug");
        assert_eq!(marked.static_pie, Some(true));
        let exec = probe::LinkMode::Executable;
        let mut checked = 0;
        for id in ["pie", "as-needed"] {
            let check = check_named(id);
            let read = read_fields_over(check, Some(&unmarked));
            assert!(report::link_mode_limitation(check, exec, Some(&unmarked), &read).is_some());
            for kept in [Verdict::ProbeInvalid, Verdict::Unsupported] {
                let gated = gating_for(kept, check, probe::Outcome::Absent, Some(&unmarked));
                assert!(gated.is_none(), "{id}: {kept:?} carries its own cause");
            }
            for mode in [
                probe::LinkMode::SharedObject,
                probe::LinkMode::SharedObjectAsCompiled,
                probe::LinkMode::Object,
            ] {
                assert!(
                    report::link_mode_limitation(check, mode, Some(&unmarked), &read).is_none(),
                    "{id}: {mode:?}"
                );
            }
            let read_marked = read_fields_over(check, Some(&marked));
            assert!(
                report::link_mode_limitation(check, exec, Some(&marked), &read_marked).is_none(),
                "{id}: a marked static PIE classifies as one"
            );
            assert!(report::link_mode_limitation(check, exec, None, &read).is_none());
            checked += 1;
        }
        assert_eq!(checked, 2);
    }

    #[test]
    fn the_link_mode_gate_reaches_the_checks_whose_reading_rested_on_the_classification() {
        let unmarked = fixture_facts("elf64-le-x86_64-static-pie-unmarked");
        let mut kept = unmarked.clone();
        kept.needed = vec!["libm.so.6".to_owned(), "libc.so.6".to_owned()];
        let corpus: usize = probe::CORPUS.iter().map(|p| p.checks.len()).sum();
        for (facts, expected) in [
            (&unmarked, &["pie", "as-needed"][..]),
            (&kept, &["pie"][..]),
        ] {
            let mut fed = 0;
            let reached: Vec<&str> = probe::CORPUS
                .iter()
                .flat_map(|p| p.checks.iter().map(move |c| (p, c)))
                .inspect(|_| fed += 1)
                .filter(|(p, c)| {
                    let read = read_fields_over(c, Some(facts));
                    report::link_mode_limitation(c, p.link_mode, Some(facts), &read).is_some()
                })
                .map(|(_, c)| c.id)
                .collect();
            assert_eq!(fed, corpus);
            assert_eq!(reached, expected, "of {fed} checks");
        }
    }

    #[test]
    fn an_artifact_that_records_no_library_withholds_as_needed_under_the_artifact_rule() {
        let check = check_named("as-needed");
        assert_eq!(check.channel(), Channel::ElfStatic);
        let positive = Detection {
            outcome: probe::Outcome::Present,
            level: None,
            observed: "needed=[\"libc.so.6\"]".to_owned(),
            rule: None,
        };
        let negative = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: "needed=[\"libm.so.6\",\"libc.so.6\"]".to_owned(),
            rule: None,
        };
        let read = |facts: &elf::ElfFacts| {
            let mut variant = blank_variant();
            variant.elf = Some(facts.clone());
            check.decode(&evidence_for(&variant)).detection
        };
        let settled_over = |verdict: Verdict, reading: &Detection, facts: &elf::ElfFacts| {
            settle_for(
                verdict,
                check,
                reading,
                always_declared(),
                Some(facts),
                None,
                &[],
            )
        };

        for (facts, elf_type, because) in &artifacts_that_record_no_library() {
            let reading = read(facts);
            assert_eq!(reading.outcome, probe::Outcome::Indeterminate, "{because}");
            assert!(reading.observed.contains(because), "{}", reading.observed);
            let (verdict, controls) = report::decide(
                &reading,
                arm(Some(&positive)),
                arm(Some(&negative)),
                None,
                None,
            );
            assert!(controls.discriminating(), "the arms stayed dynamic");
            assert_eq!(verdict, Verdict::Indeterminate);
            let settled = settled_over(verdict, &reading, facts);
            assert_eq!(settled.verdict, Verdict::NotApplicable, "{because}");
            let gating = settled
                .gating
                .expect("the row names what the artifact lacks");
            assert_eq!(gating.rule, report::gating_rule::ARTIFACT_CANNOT_CARRY);
            assert!(gating.reason.contains(elf_type), "{}", gating.reason);
            assert_eq!(settled.level, None);
        }
    }

    #[test]
    fn a_link_that_records_a_library_reads_its_list_whatever_the_classification() {
        let check = check_named("as-needed");
        let positive = Detection {
            outcome: probe::Outcome::Present,
            level: None,
            observed: "needed=[\"libc.so.6\"]".to_owned(),
            rule: None,
        };
        let negative = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: "needed=[\"libm.so.6\",\"libc.so.6\"]".to_owned(),
            rule: None,
        };
        let read = |facts: &elf::ElfFacts| {
            let mut variant = blank_variant();
            variant.elf = Some(facts.clone());
            check.decode(&evidence_for(&variant)).detection
        };
        let settled_over = |verdict: Verdict, reading: &Detection, facts: &elf::ElfFacts| {
            settle_for(
                verdict,
                check,
                reading,
                always_declared(),
                Some(facts),
                None,
                &[],
            )
        };

        let mut dynamic = elf_with_report("");
        dynamic.needed.push("libc.so.6".to_owned());
        assert!(dynamic.statically_linked == Some(false) && dynamic.has_dynamic);
        let reading = read(&dynamic);
        assert_eq!(reading.outcome, probe::Outcome::Present);
        let (verdict, _) = report::decide(
            &reading,
            arm(Some(&positive)),
            arm(Some(&negative)),
            None,
            None,
        );
        assert_eq!(verdict, Verdict::On);
        let settled = settled_over(verdict, &reading, &dynamic);
        assert_eq!(settled.verdict, Verdict::On);
        assert!(settled.gating.is_none(), "{:?}", settled.gating);
        let mut recorded = dynamic.clone();
        recorded.needed.push("libm.so.6".to_owned());
        let reading = read(&recorded);
        assert_eq!(reading.outcome, probe::Outcome::Absent);
        let (verdict, _) = report::decide(
            &reading,
            arm(Some(&positive)),
            arm(Some(&negative)),
            None,
            None,
        );
        assert_eq!(verdict, Verdict::Off);
        let settled = settled_over(verdict, &reading, &recorded);
        assert_eq!(
            settled.verdict,
            Verdict::Off,
            "the row holds on a dynamic link"
        );
        assert!(settled.gating.is_none(), "{:?}", settled.gating);
    }

    #[test]
    fn output_with_no_loader_withholds_the_missing_entry_and_reads_a_recorded_one() {
        let check = check_named("as-needed");
        let positive = Detection {
            outcome: probe::Outcome::Present,
            level: None,
            observed: "needed=[\"libc.so.6\"]".to_owned(),
            rule: None,
        };
        let negative = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: "needed=[\"libm.so.6\",\"libc.so.6\"]".to_owned(),
            rule: None,
        };
        let read = |facts: &elf::ElfFacts| {
            let mut variant = blank_variant();
            variant.elf = Some(facts.clone());
            check.decode(&evidence_for(&variant)).detection
        };
        let settled_over = |verdict: Verdict, reading: &Detection, facts: &elf::ElfFacts| {
            settle_for(
                verdict,
                check,
                reading,
                always_declared(),
                Some(facts),
                None,
                &[],
            )
        };
        let mut no_interp = elf_with_report("");
        no_interp.needed = vec!["libm.so.6".to_owned(), "libc.so.6".to_owned()];
        no_interp.elf_type = "ET_DYN".to_owned();
        no_interp.has_interp = false;
        no_interp.dt_debug = true;
        no_interp.pie = Some(true);
        no_interp.static_pie = Some(true);
        no_interp.statically_linked = Some(true);
        let reading = read(&no_interp);
        assert_eq!(reading.outcome, probe::Outcome::Absent);
        let (verdict, _) = report::decide(
            &reading,
            arm(Some(&positive)),
            arm(Some(&negative)),
            None,
            None,
        );
        assert_eq!(verdict, Verdict::Off);
        let settled = settled_over(verdict, &reading, &no_interp);
        assert_eq!(
            settled.verdict,
            Verdict::Off,
            "a static-PIE classification with a list reads its list"
        );
        assert!(settled.gating.is_none(), "{:?}", settled.gating);

        no_interp.needed = vec!["libc.so.6".to_owned()];
        let reading = read(&no_interp);
        assert_eq!(reading.outcome, probe::Outcome::Indeterminate);
        // The non-PIE twin, `-no-pie -Wl,--no-dynamic-linker` with the same trailing
        // `-Bstatic`: an `ET_EXEC` with no interpreter, classified as a static link, so a key
        // on the static-PIE marker alone would miss it.
        let mut no_pie = no_interp.clone();
        no_pie.elf_type = "ET_EXEC".to_owned();
        no_pie.pie = Some(false);
        no_pie.static_pie = Some(false);
        no_pie.dt_debug = false;
        assert_eq!(no_pie.statically_linked, Some(true));
        let twin = read(&no_pie);
        assert_eq!(
            twin.outcome,
            probe::Outcome::Indeterminate,
            "{}",
            twin.observed
        );
        assert!(
            twin.observed.contains("no dynamic loader"),
            "{}",
            twin.observed
        );
        let (verdict, controls) = report::decide(
            &reading,
            arm(Some(&positive)),
            arm(Some(&negative)),
            None,
            None,
        );
        assert!(controls.discriminating());
        assert_eq!(verdict, Verdict::Indeterminate);
        let settled = settled_over(verdict, &reading, &no_interp);
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        assert!(settled.gating.is_none(), "{:?}", settled.gating);
    }

    #[test]
    fn a_declared_limitation_relabels_a_probe_invalid_in_the_sequence() {
        let ssp = check_named("ssp-level");
        let absent = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let settled = settle_for(
            Verdict::ProbeInvalid,
            ssp,
            &absent,
            always_declared(),
            None,
            None,
            &[],
        );
        assert_eq!(settled.verdict, Verdict::Unsupported);
        assert_eq!(
            settled.gating.map(|g| g.rule),
            Some(report::gating_rule::LIBC_DECLARED)
        );
    }

    #[test]
    fn a_declared_rule_publishes_its_premise_verdict_and_keeps_its_reason() {
        let relro = check_named("relro");
        let mut no_dynamic = elf_with_report("");
        no_dynamic.has_dynamic = false;
        let absent = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let family = [
            report::gating_rule::LIBC_DECLARED,
            report::gating_rule::COMPILER_DECLARED,
            report::gating_rule::FLAG_UNKNOWN,
            report::gating_rule::FLAG_REFUSED,
            report::gating_rule::NO_UNHARDENED_STATE,
            report::gating_rule::LINKER_KEYWORD_IGNORED,
            report::gating_rule::STDLIB_LACKS_OBSERVABLE,
            report::gating_rule::FORTIFY_LEVEL_DECLINED,
            report::gating_rule::SCAFFOLDING,
        ];
        for rule in family {
            let settled = settle_for(
                Verdict::ProbeInvalid,
                relro,
                &absent,
                |_| {
                    Some(report::Gating {
                        rule,
                        arch: None,
                        libc: None,
                        needs_vm: false,
                        reason: "declared".to_owned(),
                    })
                },
                Some(&no_dynamic),
                None,
                &[],
            );
            assert_eq!(settled.verdict, rule.verdict(), "{}", rule.id);
            assert_eq!(settled.gating.map(|g| g.rule), Some(rule), "{}", rule.id);
        }
    }

    /// The gating `run_check` publishes over a build whose artifact is set aside, and what its
    /// reason quotes.
    fn reach_set_aside(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        let (absence, quoted, check) = if rule.id == report::gating_rule::ARTIFACT_OTHER_COMPILER.id
        {
            let line = "GCC: (GNU) 16.2.1 20261029 (Red Hat 16.2.1-3)".to_owned();
            let absence = compile::WitnessAbsence::OtherCompiler {
                lines: vec![line.clone()],
                named: "clang 22.1.8".to_owned(),
                witnessed: true,
            };
            (absence, line, "ssp-level-emitted")
        } else {
            let found = "ab".repeat(elf::RUN_WITNESS_BYTES);
            (
                compile::WitnessAbsence::Foreign(vec![found.clone()]),
                found,
                "canary-emitted",
            )
        };
        (report::witness_gating(check_named(check), &absence), quoted)
    }

    /// One gating rule reached through the code that constructs it in a run, with the part
    /// of its input its row's `evidence` column says the reason quotes.
    fn reach(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        use report::gating_rule as g;

        if rule.stage == g::Stage::Declared {
            return reach_declared(rule);
        }
        let unreached = || -> report::Gating { panic!("{} was not reached", rule.id) };
        let first_gating = |outcome: ProbeOutcome| {
            outcome
                .observations
                .into_iter()
                .next()
                .and_then(|o| o.gating)
                .unwrap_or_else(unreached)
        };
        let (gating, quoted) = match rule.id {
            id if id == g::ARCH.id
                || id == g::NO_CHECK_ON_TARGET.id
                || id == g::ARCH_OUTSIDE_TABLE.id =>
            {
                reach_arch(rule)
            }
            id if id == g::NEEDS_VM.id || id == g::EXECUTION_MODE_ASSUMED.id => reach_kernel(rule),
            id if id == g::MACRO_SPOOFED.id || id == g::LEVEL_OFF_SCALE.id => {
                let ssp = check_named("ssp-level");
                let (word, macro_name) = ("bogus", "__SSP_STRONG__");
                let (verdict, reading) = decided(ssp, Some(word), &format!("{macro_name}=3"));
                let (forged, quoted) = if id == g::MACRO_SPOOFED.id {
                    (vec![format!("-D{macro_name}=3")], macro_name)
                } else {
                    (Vec::new(), word)
                };
                let gating = settle_for(
                    verdict,
                    ssp,
                    &reading,
                    always_declared(),
                    None,
                    None,
                    &forged,
                )
                .gating
                .unwrap_or_else(unreached);
                (gating, quoted.to_owned())
            }
            id if id == g::NO_DRIVER.id => {
                // Typed as the lookup's own failure, a file that is not there.
                let said = "no clang++ beside clang";
                let err =
                    anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::NotFound, said));
                let gating = first_gating(no_driver(probe_named("copy-dt-needed"), &err));
                (gating, said.to_owned())
            }
            id if id == g::UNMEASURED.id => {
                let said = "the clean build could not be run";
                let err = anyhow::Error::from(std::io::Error::other(said));
                let gating = first_gating(unmeasured(probe_named("copy-dt-needed"), "clean", &err));
                (gating, said.to_owned())
            }
            id if id == g::ARTIFACT_UNWITNESSED.id || id == g::ARTIFACT_OTHER_COMPILER.id => {
                reach_set_aside(rule)
            }
            id if id == g::ARTIFACT_CANNOT_CARRY.id
                || id == g::ARTIFACT_UNREADABLE.id
                || id == g::ARTIFACT_LTO_IR.id =>
            {
                reach_artifact(rule)
            }
            id if id == g::LINK_MODE_CONTRADICTED.id => reach_link_mode(rule),
            id if id == g::ARTIFACT_LACKS_SELF_REPORT.id => {
                // A macro check over a read artifact whose `.chard.report` is listed and
                // was cut: the reader's own entry is what the reason quotes.
                let ssp = check_named("ssp-level");
                let mut facts = elf_with_report("");
                let unread = ".chard.report: 0x2000+0x400 could not be read (past the end)";
                facts.sections = vec![".chard.report".to_owned()];
                facts.truncations = vec![cut(
                    elf::ElfTable::SectionNames,
                    elf::TruncationKind::Unread,
                    unread,
                )];
                let gating = gating_for(Verdict::Off, ssp, probe::Outcome::Absent, Some(&facts))
                    .map_or_else(|| panic!("{} was not reached", rule.id), |(_, g)| g);
                (gating, unread.to_owned())
            }
            // Every detector rule, by its stage, so a new one cannot miss this arm.
            _ if rule.stage == g::Stage::Detector => reach_detector(rule),
            id if id == g::RUN_OUTPUT_UNREADABLE.id || id == g::RUN_DEADLINE_ELAPSED.id => {
                reach_run(rule)
            }
            id if id == g::RUN_UNDER_EMULATION.id => reach_emulation(),
            id if id == g::LINK_INPUTS_UNMATCHED.id => reach_link_inputs(),
            id if id == g::CLEAN_LINK_UNMATCHED.id => reach_clean_link(),
            id if id == g::COMPILE_INPUTS_UNMATCHED.id => reach_compile_inputs(),
            id if id == g::SANITIZER_GROUP_UNMEASURED.id => reach_sanitizer_groups(),
            id if id == g::SIGNED_OVERFLOW_SANITIZED.id => reach_signed_overflow_sanitized(),
            id if id == g::LTO_CODEGEN_AT_LINK.id => reach_lto_codegen(),
            id if id == g::TARGET_CONTRADICTED.id => reach_target(),
            id if id == g::TARGET_ABI_CONTRADICTED.id => reach_abi(),
            id if id == g::MACRO_CONTRADICTED.id => reach_twin(),
            other => panic!("{other} has no construction site in `reach`"),
        };
        (gating, quoted)
    }

    /// [`reach`] for the two kernel rules, through [`report::gate_applicability`] with a
    /// gate no corpus check declares: a borrowed kernel (`needs-vm`, quoting the mode), and
    /// `host` by default (`execution-mode-assumed`, quoting the observation).
    fn reach_kernel(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        use crate::env::KernelAttribution::{Assumed, Borrowed};
        use report::gating_rule as g;

        let gate = probe::Gate {
            needs_vm: true,
            ..probe::PORTABLE
        };
        let observation = "no runtime marker file, no /run/systemd/container, /proc/1/environ \
                           unreadable (permission denied, os error 13), the identity uid map \
                           `0 0 4294967295`, /proc/1/comm is `bash`: nothing chard reads from inside tells a \
                           container that plants none of these from a system that owns its \
                           kernel";
        let (kernel, quoted) = if rule.id == g::NEEDS_VM.id {
            (
                Borrowed,
                format!("{:?}", crate::env::ExecutionMode::Container),
            )
        } else {
            (Assumed { observation }, observation.to_owned())
        };
        let Applicability::Untrustworthy(gating) =
            report::gate_applicability("-f", "-f", &gate, kernel, "x86_64")
        else {
            panic!("{} was not reached", rule.id)
        };
        (gating, quoted)
    }

    /// [`reach`] for the mechanism table's three decisions off the measured cells, through
    /// [`report::gate_applicability`]: x86 CET on aarch64 (`arch-gated`),
    /// `linker-default-noexecstack` on aarch64 (`no-check-on-target`), and riscv64, which has
    /// no row (`arch-outside-table`). The quoted input is the architecture.
    fn reach_arch(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        use report::gating_rule as g;

        let (check, target) = if rule.id == g::ARCH.id {
            ("cet-macro", "aarch64")
        } else if rule.id == g::NO_CHECK_ON_TARGET.id {
            ("linker-default-noexecstack", "aarch64")
        } else {
            ("cet-macro", "riscv64")
        };
        let check = check_named(check);
        let gating = match report::gate_applicability(
            check.id,
            check.flag,
            &check.gate,
            crate::env::KernelAttribution::Established,
            target,
        ) {
            Applicability::Unsupported(gating) | Applicability::Unread(gating) => gating,
            Applicability::Untrustworthy(_) | Applicability::Applicable => {
                panic!("{} was not reached", rule.id)
            }
        };
        (gating, target.to_owned())
    }

    /// [`reach`] for `link-inputs-unmatched-by-arms`, through [`settle_listings`].
    fn reach_link_inputs() -> (report::Gating, String) {
        let said = "its inputs include /srv/stripped/crtbeginS.o";
        let settled = Settled {
            verdict: Verdict::Off,
            gating: None,
            level: None,
        };
        let gating = settle_listings(
            settled,
            check_named("cet-marked"),
            &ProbeListings {
                link: Some(said),
                ..ProbeListings::default()
            },
        )
        .gating
        .expect("link-inputs-unmatched-by-arms was not reached");
        (gating, said.to_owned())
    }

    /// [`reach`] for `clean-link-unmatched-by-measured`, through [`settle_listings`].
    fn reach_clean_link() -> (report::Gating, String) {
        let said = "the measured build's link program include /usr/bin/ld where the clean \
                    build's include /srv/px/ld";
        let settled = Settled {
            verdict: Verdict::Off,
            gating: None,
            level: None,
        };
        let gating = settle_listings(
            settled,
            check_named("linker-default-noexecstack"),
            &ProbeListings {
                clean_link: Some(said),
                ..ProbeListings::default()
            },
        )
        .gating
        .expect("clean-link-unmatched-by-measured was not reached");
        (gating, said.to_owned())
    }

    /// [`reach`] for `compile-inputs-unmatched-by-arms`, through [`settle_listings`].
    fn reach_compile_inputs() -> (report::Gating, String) {
        let said = "its header options include -isystem /srv/inc where the arms' include none";
        let settled = Settled {
            verdict: Verdict::Off,
            gating: None,
            level: None,
        };
        let gating = settle_listings(
            settled,
            check_named("fortify-effective"),
            &ProbeListings {
                compile: Some(said),
                ..ProbeListings::default()
            },
        )
        .gating
        .expect("compile-inputs-unmatched-by-arms was not reached");
        (gating, said.to_owned())
    }

    /// [`reach`] for `sanitizer-group-unmeasured`, through [`settle_listings`] handed
    /// clang's resolved lists with `enum` enabled and left out of the trap list.
    fn reach_sanitizer_groups() -> (report::Gating, String) {
        let check = check_named("ubsan-trap-mode");
        let trapped = "-fsanitize-trap=alignment,shift-base";
        let listing: report::SanitizerWords = Ok(vec![
            "-fsanitize=alignment,enum,shift-base".to_owned(),
            trapped.to_owned(),
        ]);
        let settled = Settled {
            verdict: Verdict::On,
            gating: None,
            level: None,
        };
        let settled = settle_listings(
            settled,
            check,
            &ProbeListings {
                sanitizers: Some(&listing),
                ..ProbeListings::default()
            },
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled
            .gating
            .unwrap_or_else(|| panic!("sanitizer-group-unmeasured was not reached"));
        // The other direction: an `off` beside gcc's one-group words as written (the gcc
        // 13 shape), reached through the same site.
        let one_group = "-fsanitize-trap=enum";
        let gcc: report::SanitizerWords =
            Ok(vec!["-fsanitize=enum".to_owned(), one_group.to_owned()]);
        let off = settle_listings(
            Settled {
                verdict: Verdict::Off,
                gating: None,
                level: None,
            },
            check,
            &ProbeListings {
                sanitizers: Some(&gcc),
                ..ProbeListings::default()
            },
        );
        assert_eq!(off.verdict, Verdict::Indeterminate);
        let reached = off
            .gating
            .unwrap_or_else(|| panic!("sanitizer-group-unmeasured was not reached on off"));
        assert_eq!(reached.rule.id, gating.rule.id);
        assert!(reached.reason.contains(one_group), "{}", reached.reason);
        (gating, trapped.to_owned())
    }

    /// [`reach`] for `signed-overflow-sanitized`, through [`settle_listings`] handed gcc's
    /// `-fsanitize=undefined` as written.
    fn reach_signed_overflow_sanitized() -> (report::Gating, String) {
        let check = check_named("no-strict-overflow");
        let word = "-fsanitize=undefined";
        let listing: report::SanitizerWords = Ok(vec![word.to_owned()]);
        let settled = settle_listings(
            Settled {
                verdict: Verdict::On,
                gating: None,
                level: None,
            },
            check,
            &ProbeListings {
                sanitizers: Some(&listing),
                ..ProbeListings::default()
            },
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled
            .gating
            .unwrap_or_else(|| panic!("signed-overflow-sanitized was not reached"));
        (gating, word.to_owned())
    }

    /// [`reach`] for `lto-codegen-at-link`, through [`settle_listings`] handed the mode a
    /// clang `-cc1` line resolved.
    fn reach_lto_codegen() -> (report::Gating, String) {
        let check = check_named("pic-shared-link");
        let word = "-flto=full";
        let listing: report::LtoWords = Ok(report::LtoListing {
            lto: vec![word.to_owned()],
            relocation: vec!["-mrelocation-model static".to_owned()],
        });
        let settled = Settled {
            verdict: Verdict::On,
            gating: None,
            level: None,
        };
        let settled = settle_listings(
            settled,
            check,
            &ProbeListings {
                lto: Some(&listing),
                ..ProbeListings::default()
            },
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled
            .gating
            .unwrap_or_else(|| panic!("lto-codegen-at-link was not reached"));
        (gating, word.to_owned())
    }

    /// gcc's slim-LTO marker as the reader records it: a common symbol, so defined, in
    /// `.symtab`.
    fn slim_marker() -> elf::SymbolFact {
        elf::SymbolFact {
            defined: true,
            tables: vec![".symtab".to_owned()],
            versioned: Vec::new(),
        }
    }

    /// [`reach`] for the three artifact rules, through [`artifact_gating`] handed the
    /// measured artifact.
    fn reach_artifact(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        use report::gating_rule as g;

        let check = check_named("relative-relocs");
        let mut facts = elf_with_report("");
        let unread = ".dynamic unreadable at entry 3 of 9 (offset 0x3f8)";
        let quoted = if rule == g::ARTIFACT_UNREADABLE {
            facts.truncations = vec![cut(
                elf::ElfTable::Dynamic,
                elf::TruncationKind::Unread,
                unread,
            )];
            unread.to_owned()
        } else if rule == g::ARTIFACT_LTO_IR {
            facts
                .sections
                .push(format!("{}opts", report::LTO_IR_SECTION_PREFIX));
            facts
                .watched_symbols
                .insert(report::LTO_SLIM_SYMBOL.to_owned(), slim_marker());
            report::LTO_SLIM_SYMBOL.to_owned()
        } else {
            facts.elf_type.clone()
        };
        let gating = gating_for(Verdict::Off, check, probe::Outcome::Absent, Some(&facts))
            .map_or_else(
                || panic!("{} was not reached", rule.id),
                |(_, gating)| gating,
            );
        (gating, quoted)
    }

    /// [`reach`] for the link-mode rule, through [`artifact_gating`] handed the unmarked
    /// static PIE as an executable link's artifact.
    fn reach_link_mode(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        let facts = fixture_facts("elf64-le-x86_64-static-pie-unmarked");
        let gating = gating_for(
            Verdict::Off,
            check_named("pie"),
            probe::Outcome::Absent,
            Some(&facts),
        )
        .map_or_else(|| panic!("{} was not reached", rule.id), |(_, g)| g);
        (gating, facts.elf_type)
    }

    /// [`reach`] for a detector's rule, through [`settle`] handed a reading the detector
    /// withheld under it, in the shape its detector returns. `frame-reuse-did-not-hold`'s
    /// sentence is `detect_zero_init_padding`'s own, which is held to withholding it under
    /// the rule.
    fn reach_detector(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        let zipb_run = null_check_run("ZIPB pad=00 ctrl=00 ctrl_supported=0\n");
        let macros = BTreeMap::new();
        let zipb = crate::decode::runtime::detect_zero_init_padding(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&zipb_run),
            workdir: None,
        });
        let (check, said) = if rule == report::gating_rule::FRAME_REUSE_DID_NOT_HOLD {
            assert_eq!(
                zipb.outcome,
                probe::Outcome::Indeterminate,
                "{}",
                zipb.observed
            );
            assert_eq!(
                zipb.rule.map(|r| r.rule().id),
                Some(rule.id),
                "{}",
                zipb.observed
            );
            (
                check_named("zero-init-padding-bits"),
                zipb.observed.as_str(),
            )
        } else if rule == report::gating_rule::CANARY_NOT_ASKED_FOR {
            (
                check_named("hardened-downgrade-warned"),
                "neither the diagnostic nor the canary warning was emitted, and the build's \
                 recorded flags never asked for the canary's warning",
            )
        } else if rule == report::gating_rule::FORTIFY_BELOW_SUBOBJECT_LEVEL {
            (
                check_named("strict-flex-arrays-enforced"),
                "the build is optimized and glibc settled its fortify level at \
                 __USE_FORTIFY_LEVEL=0, below the 2 at which its wrappers check a subobject bound",
            )
        } else if rule == report::gating_rule::UNOPTIMIZED_BUILD_CANNOT_SHOW {
            (
                check_named("no-strict-aliasing"),
                "compiled without optimization: the store is observed whether or not the flag \
                 was passed, so this build cannot answer the question",
            )
        } else {
            (
                check_named("no-strict-overflow"),
                "the guard ran in a build that was not optimized, where clang keeps it \
                 whether or not the flag was passed",
            )
        };
        let reading =
            Detection::withheld(report::gating_rule::DetectorRule::of(rule), said.to_owned());
        let gating = settle_for(
            Verdict::Indeterminate,
            check,
            &reading,
            |_| None,
            None,
            None,
            &[],
        )
        .gating
        .unwrap_or_else(|| panic!("{} was not reached", rule.id));
        (gating, said.to_owned())
    }

    #[test]
    fn a_detectors_withholding_is_published_under_the_rule_it_named() {
        use report::gating_rule as g;

        let check = check_named("no-strict-overflow");
        let said = "the guard ran in a build that was not optimized, where clang keeps it";
        let withheld = Detection::withheld(
            g::DetectorRule::of(g::GUARD_KEPT_WITHOUT_THE_FLAG),
            said.to_owned(),
        );
        let settled = settle_for(
            Verdict::Indeterminate,
            check,
            &withheld,
            |_| None,
            None,
            None,
            &[],
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled.gating.expect("the detector's rule is published");
        assert_eq!(gating.rule, g::GUARD_KEPT_WITHOUT_THE_FLAG);
        assert_eq!(gating.reason, said);
        assert_eq!(gating.rule.verdict(), Verdict::Indeterminate);

        // The same reading with no rule names none: the reason stays in `observed` alone.
        let unnamed = Detection::indeterminate(said.to_owned());
        let settled = settle_for(
            Verdict::Indeterminate,
            check,
            &unnamed,
            |_| None,
            None,
            None,
            &[],
        );
        assert!(
            settled.gating.is_none(),
            "{:?}",
            settled.gating.map(|g| g.rule.id)
        );

        // Not on a verdict the triple did not reach through the reading.
        assert!(report::detector_gating(Verdict::ProbeInvalid, &withheld).is_none());
        // Nor on a reading that is not the detector's `indeterminate`: the level rule's
        // `present` word and this rule never both apply.
        let present = Detection {
            outcome: probe::Outcome::Present,
            level: None,
            observed: said.to_owned(),
            rule: Some(g::DetectorRule::of(g::GUARD_KEPT_WITHOUT_THE_FLAG)),
        };
        assert!(report::detector_gating(Verdict::Indeterminate, &present).is_none());

        // The run gate overwrites it, as the later stage.
        let mut capped = null_check_run("optimize=no\nfrontend=clang\noverflow-guard=ran");
        capped.output_truncated = true;
        let settled = settle_for(
            Verdict::Indeterminate,
            check,
            &withheld,
            |_| None,
            None,
            Some(&capped),
            &[],
        );
        assert_eq!(
            settled.gating.map(|g| g.rule),
            Some(g::RUN_OUTPUT_UNREADABLE)
        );
        assert!(g::RUN_OUTPUT_UNREADABLE.stage > g::GUARD_KEPT_WITHOUT_THE_FLAG.stage);
        assert!(g::GUARD_KEPT_WITHOUT_THE_FLAG.stage > g::LEVEL_OFF_SCALE.stage);
    }

    #[test]
    fn a_rule_of_another_stage_is_not_a_detectors_rule() {
        use report::gating_rule::{ALL, DetectorRule, Stage};

        let mut refused = 0;
        for rule in ALL {
            match std::panic::catch_unwind(|| DetectorRule::of(*rule)) {
                Ok(made) => {
                    assert_eq!(rule.stage, Stage::Detector, "{} was accepted", rule.id);
                    assert_eq!(made.rule(), *rule, "{}", rule.id);
                }
                Err(payload) => {
                    assert_ne!(rule.stage, Stage::Detector, "{} was refused", rule.id);
                    assert!(
                        payload
                            .downcast_ref::<&str>()
                            .is_some_and(|s| s.contains("a detector names a rule of its own stage")),
                        "{} was refused for another reason",
                        rule.id
                    );
                    refused += 1;
                }
            }
        }
        let detectors = ALL.iter().filter(|r| r.stage == Stage::Detector).count();
        assert_eq!(
            detectors, 5,
            "the detector rules: guard-kept-without-the-flag, unoptimized-build-cannot-show, \
             fortify-below-the-subobject-level, canary-not-asked-for and frame-reuse-did-not-hold"
        );
        assert_eq!(
            refused,
            ALL.len() - detectors,
            "every detector rule accepted, every other refused"
        );
    }

    #[test]
    fn a_detectors_rule_is_open_to_the_emulation_rule_the_self_report_gate_and_a_cut() {
        use report::gating_rule as g;

        let detector = |said: &str| report::Gating {
            rule: g::GUARD_KEPT_WITHOUT_THE_FLAG,
            arch: None,
            libc: None,
            needs_vm: false,
            reason: said.to_owned(),
        };
        // The predicate is exactly the level and detector stages, over every rule's stage.
        for rule in g::ALL {
            assert_eq!(
                rule.stage.is_reading_rule(),
                matches!(rule.stage, g::Stage::Level | g::Stage::Detector),
                "{}",
                rule.id
            );
        }

        // The emulation rule, over a Machine reading on a foreign artifact.
        let (check, run, elf) = emulated_stack_clash("aarch64");
        let settled = Settled {
            verdict: Verdict::Indeterminate,
            gating: Some(detector("the detector's reason")),
            level: None,
        };
        let after = settle_emulation(
            settled,
            Verdict::Indeterminate,
            check,
            Some(&elf),
            None,
            Some(&run),
            read("x86_64"),
            false,
        );
        assert_eq!(after.gating.map(|g| g.rule), Some(g::RUN_UNDER_EMULATION));

        // The self-report gate, on a macro check whose measured build wrote no artifact.
        let ssp = check_named("ssp-level");
        let mut bare = blank_variant();
        bare.build = Some(variant_build(0, false));
        let settled = Settled {
            verdict: Verdict::Indeterminate,
            gating: Some(detector("the detector's reason")),
            level: None,
        };
        let after = settle_self_report_unread(settled, ssp, &bare, false);
        assert_eq!(
            after.gating.map(|g| g.rule),
            Some(g::ARTIFACT_LACKS_SELF_REPORT)
        );

        // A cut stream replaces the reading and drops the rule.
        let check = check_named("no-strict-overflow");
        let mut capped = null_check_run("optimize=no\nfrontend=clang\noverflow-guard=ran");
        capped.output_truncated = true;
        let mut variant = blank_variant();
        variant.run = Some(capped);
        let withheld = Detection::withheld(
            g::DetectorRule::of(g::GUARD_KEPT_WITHOUT_THE_FLAG),
            "the guard ran".to_owned(),
        );
        let replaced = withhold_unreadable(check, &variant, withheld);
        assert_eq!(replaced.outcome, probe::Outcome::Indeterminate);
        assert!(replaced.rule.is_none(), "{}", replaced.observed);
        assert!(
            replaced
                .observed
                .contains("the detector read: the guard ran")
        );
    }

    /// [`reach`] for the two run rules, through [`settle`] handed the measured run.
    fn reach_run(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        use report::gating_rule as g;

        let check = check_named("no-delete-null-pointer-checks");
        let mut run = null_check_run("null-check=deleted");
        let quoted = if rule == g::RUN_DEADLINE_ELAPSED {
            run.deadline_ms = Some(4321);
            run.timed_out = true;
            run.exit_status = -1;
            run.signal = Some("SIGKILL".to_owned());
            "4321 ms".to_owned()
        } else {
            let error = "stdout: permission denied";
            run.output_error = Some(error.to_owned());
            error.to_owned()
        };
        let reading = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: "null-check=deleted".to_owned(),
            rule: None,
        };
        let gating = settle_for(
            Verdict::Off,
            check,
            &reading,
            |_| None,
            None,
            Some(&run),
            &[],
        )
        .gating
        .unwrap_or_else(|| panic!("{} was not reached", rule.id));
        (gating, quoted)
    }

    /// [`reach`] for `run-under-emulation`, through [`settle`] handed a whole run of a
    /// `Machine` check over an aarch64 artifact on an x86_64 kernel.
    fn reach_emulation() -> (report::Gating, String) {
        let (check, run, elf) = emulated_stack_clash("aarch64");
        let settled = settle_for(
            Verdict::On,
            check,
            &stack_clash_reading(),
            |_| None,
            Some(&elf),
            Some(&run),
            &[],
        );
        let gating = settle_emulation(
            settled,
            Verdict::On,
            check,
            Some(&elf),
            None,
            Some(&run),
            read("x86_64"),
            false,
        )
        .gating
        .expect("run-under-emulation was not reached");
        (gating, "aarch64".to_owned())
    }

    /// `stack-clash-guard-page`, a run of it that read the guard hit, and its artifact's
    /// facts with `elf.machine` set to `machine`.
    fn emulated_stack_clash(machine: &str) -> (&'static Check, runner::RunRecord, elf::ElfFacts) {
        let check = check_named("stack-clash-guard-page");
        let run = null_check_run("SCPRT dist=8388620 n=67108864 ratio_pct=12");
        let mut elf = elf_with_report("");
        elf.machine = machine.to_owned();
        (check, run, elf)
    }

    fn stack_clash_reading() -> Detection {
        Detection {
            outcome: probe::Outcome::Present,
            level: None,
            observed: "SCPRT dist=8388620 n=67108864 ratio_pct=12".to_owned(),
            rule: None,
        }
    }

    #[test]
    fn a_machine_reading_over_a_foreign_artifact_is_withheld_and_nothing_else_is() {
        use report::gating_rule as g;

        let settle_on = |check: &Check, run: Option<&runner::RunRecord>, machine: &str| {
            let mut elf = elf_with_report("");
            elf.machine = machine.to_owned();
            if machine == "i386" {
                elf.elf_class = 32;
            }
            emulation_of(settled_on(check, Some(&elf), run), check, &elf, run)
        };
        let (clash, run, _) = emulated_stack_clash("aarch64");

        let foreign = settle_on(clash, Some(&run), "aarch64");
        assert_eq!(foreign.verdict, Verdict::Indeterminate);
        let gating = foreign.gating.expect("withheld under a named rule");
        assert_eq!(gating.rule, g::RUN_UNDER_EMULATION);
        assert!(gating.reason.contains("aarch64") && gating.reason.contains("x86_64"));
        assert_eq!(foreign.level, None);

        for native in ["x86_64", "i386"] {
            let settled = settle_on(clash, Some(&run), native);
            assert_eq!(
                (settled.verdict, settled.gating.is_none()),
                (Verdict::On, true)
            );
        }
        // The kernel's family at the other width, an x32 artifact, which only a compat
        // option chard cannot see runs: withheld, as a foreign machine is.
        let mut x32 = elf_with_report("");
        x32.elf_class = 32;
        let settled = settle_for(
            Verdict::On,
            clash,
            &stack_clash_reading(),
            |_| None,
            Some(&x32),
            Some(&run),
            &[],
        );
        let settled = settle_emulation(
            settled,
            Verdict::On,
            clash,
            Some(&x32),
            None,
            Some(&run),
            read("x86_64"),
            false,
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        assert!(settled.gating.is_some_and(
            |gating| gating.rule == g::RUN_UNDER_EMULATION && gating.reason.contains("32-bit")
        ));
        let unrun = settle_on(clash, None, "aarch64");
        assert_eq!((unrun.verdict, unrun.gating.is_none()), (Verdict::On, true));

        // A run killed at its deadline keeps that reason: the reading is incomplete, which
        // is the more fundamental statement of the two.
        let mut killed = run.clone();
        killed.timed_out = true;
        killed.exit_status = -1;
        killed.signal = Some("SIGKILL".to_owned());
        let cut = settle_on(clash, Some(&killed), "aarch64");
        assert_eq!(
            cut.gating.map(|g| g.rule),
            Some(g::RUN_DEADLINE_ELAPSED),
            "the deadline's reason stands over the emulation's"
        );
        // And a `probe-invalid` is the triple's, whatever ran it.
        let mut elf = elf_with_report("");
        elf.machine = "aarch64".to_owned();
        let invalid = settle_emulation(
            Settled {
                verdict: Verdict::ProbeInvalid,
                gating: None,
                level: None,
            },
            Verdict::ProbeInvalid,
            clash,
            Some(&elf),
            None,
            Some(&run),
            read("x86_64"),
            false,
        );
        assert_eq!(
            (invalid.verdict, invalid.gating.is_none()),
            (Verdict::ProbeInvalid, true)
        );

        let program: Vec<&Check> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.run_basis() == Some(probe::RunBasis::Program))
            .collect();
        // Fifteen, each measured to read alike natively and under emulation: twelve with the
        // gating; `zero-call-used-regs`, measured on 2026-10-01 by running eight static aarch64
        // builds of its probe (gcc 16.2.1 and clang 22.1.8 on Fedora 44 aarch64; none, `used-gpr`,
        // `used-gpr-arg`, `skip`) natively and under qemu-aarch64-static on Fedora 44 x86_64: every
        // `ZCUR` line identical.
        assert_eq!(program.len(), 15, "the measured list");
        for check in program {
            let settled = settle_on(check, Some(&run), "aarch64");
            assert!(
                settled.gating.is_none(),
                "{}: a Program reading stands under emulation",
                check.id
            );
        }
    }

    #[test]
    fn a_machine_reading_over_the_other_byte_order_is_withheld() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        use report::gating_rule as g;
        let (clash, run, _) = emulated_stack_clash("aarch64");
        let settle_under = |machine: &str, order: Option<elf::ByteOrder>, kernel: &str| {
            let mut elf = elf_with_report("");
            elf.machine = machine.to_owned();
            elf.elf_data = order;
            let settled = settle_for(
                Verdict::On,
                clash,
                &stack_clash_reading(),
                |_| None,
                Some(&elf),
                Some(&run),
                &[],
            );
            settle_emulation(
                settled,
                Verdict::On,
                clash,
                Some(&elf),
                None,
                Some(&run),
                read(kernel),
                false,
            )
        };
        for (machine, order, kernel, withheld, names) in [
            (
                "ppc64",
                Some(BigEndian),
                "ppc64le",
                true,
                "big-endian ppc64",
            ),
            ("ppc64", Some(LittleEndian), "ppc64le", false, ""),
            (
                "aarch64",
                Some(LittleEndian),
                "aarch64_be",
                true,
                "little-endian aarch64",
            ),
            ("aarch64", Some(BigEndian), "aarch64_be", false, ""),
            ("x86_64", None, "x86_64", true, "carries no byte order"),
            (
                "mips",
                Some(BigEndian),
                "mips64",
                true,
                "spelling carries no byte order",
            ),
        ] {
            let settled = settle_under(machine, order, kernel);
            if withheld {
                assert_eq!(
                    settled.verdict,
                    Verdict::Indeterminate,
                    "{machine} on {kernel}"
                );
                let gating = settled.gating.expect("withheld under a named rule");
                assert_eq!(gating.rule, g::RUN_UNDER_EMULATION, "{machine} on {kernel}");
                assert!(
                    gating.reason.contains(names),
                    "{machine} on {kernel}: {}",
                    gating.reason
                );
            } else {
                assert_eq!(
                    (settled.verdict, settled.gating.is_none()),
                    (Verdict::On, true),
                    "{machine} on {kernel}"
                );
            }
        }
    }

    #[test]
    fn the_run_basis_split_is_the_measured_one() {
        let machine: Vec<&str> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.run_basis() == Some(probe::RunBasis::Machine))
            .map(|c| c.id)
            .collect();
        // `Machine` by mechanism: the readings are the fault the kernel's stack mapping
        // produces, the kernel's shadow-stack status word and a CPU fault, a PROT_BTI
        // mapping's branch-target exception, and an authentication fault under kernel keys.
        assert_eq!(
            machine,
            [
                "noexecstack-enforced",
                "shadow-stack-enforced",
                "bti-enforced",
                "pac-ret-enforced",
                "stack-clash-guard-page"
            ]
        );
        for check in probe::CORPUS.iter().flat_map(|p| p.checks) {
            assert_eq!(
                check.run_basis().is_some(),
                check.channel() == Channel::Runtime,
                "{}: a basis exactly on the runtime channel",
                check.id
            );
        }
    }

    /// [`reach`] for `target-arch-contradicted`, through
    /// [`report::withhold_on_contradicted_target`] over the observations a run published.
    fn reach_target() -> (report::Gating, String) {
        // An unmeasured probe's observations, held to an artifact whose machine flips the
        // gate.
        let err = anyhow::Error::from(std::io::Error::other("unbuilt"));
        let mut observations = unmeasured(probe_named("link-defaults"), "clean", &err).observations;
        let target = toolchain::target_agreement(
            "aarch64",
            toolchain::ArchSource::Dumpmachine,
            &[toolchain::ArtifactMachine {
                label: "link-defaults sha256:00".to_owned(),
                machine: "x86_64".to_owned(),
                class: 64,
                order: Some(elf::ByteOrder::LittleEndian),
                lang: Some(Lang::C),
            }],
            &[],
            None,
        );
        report::withhold_on_contradicted_target(&mut observations, &target);
        let gating = observations
            .into_iter()
            .find(|o| o.check == "cet-marked")
            .and_then(|o| o.gating)
            .expect("target-arch-contradicted was not reached");
        (gating, "e_machine x86_64".to_owned())
    }

    /// [`reach`] for `macro-contradicted-by-artifact`, through
    /// [`report::withhold_contradicted_macros`] over a run's settled observations: a
    /// macro reading present beside its artifact twin absent.
    fn reach_twin() -> (report::Gating, String) {
        let mut observations = vec![
            blank_observation(
                probe_named("toolchain-macros"),
                check_named("cet-macro"),
                Verdict::On,
            ),
            blank_observation(
                probe_named("link-defaults"),
                check_named("cet-marked"),
                Verdict::Off,
            ),
        ];
        observations[0].level = Some("full".to_owned());
        report::withhold_contradicted_macros(&mut observations);
        let gating = observations
            .into_iter()
            .find(|o| o.check == "cet-macro")
            .and_then(|o| o.gating)
            .expect("macro-contradicted-by-artifact was not reached");
        (
            gating,
            "`cet-marked` reads `off` on the elf-static channel".to_owned(),
        )
    }

    /// [`reach`] for `target-abi-contradicted`, through the same function over an
    /// artifact of the read family at the other width: an x32 object under an x86_64 read.
    fn reach_abi() -> (report::Gating, String) {
        let err = anyhow::Error::from(std::io::Error::other("unbuilt"));
        let mut observations = unmeasured(probe_named("link-defaults"), "clean", &err).observations;
        let target = toolchain::target_agreement(
            "x86_64",
            toolchain::ArchSource::Dumpmachine,
            &[toolchain::ArtifactMachine {
                label: "link-defaults sha256:00".to_owned(),
                machine: "x86_64".to_owned(),
                class: 32,
                order: Some(elf::ByteOrder::LittleEndian),
                lang: Some(Lang::C),
            }],
            &[],
            None,
        );
        report::withhold_on_contradicted_target(&mut observations, &target);
        let gating = observations
            .into_iter()
            .find(|o| o.check == "cet-marked")
            .and_then(|o| o.gating)
            .expect("target-abi-contradicted was not reached");
        (gating, "ELF32 little-endian".to_owned())
    }

    /// One declared rule's firing input, as the builds `run_check` hands
    /// [`DeclaredReadings::read`]: each arm a [`Variant`] and, for the two arms `decide`
    /// reads, the outcome the controls publish for it.
    struct DeclaredCase {
        probe: &'static Probe,
        check: &'static Check,
        libc: &'static str,
        compiler: &'static str,
        positive: Variant,
        positive_outcome: Option<probe::Outcome>,
        negative: Option<Variant>,
        negative_outcome: Option<probe::Outcome>,
        clean: Variant,
        measured: Variant,
        /// The tool's sentence the rule was handed, where its evidence is one.
        line: Option<String>,
        /// The positive arm compiled and not linked, where the rule reads one.
        positive_object: Option<Variant>,
    }

    impl DeclaredCase {
        /// The case with `arm`'s build replaced by one that carries nothing: no build
        /// record, no macros, no outcome.
        fn blank(mut self, arm: report::gating_rule::Arm) -> Self {
            use report::gating_rule::Arm;
            match arm {
                Arm::Positive => {
                    self.positive = blank_variant();
                    self.positive_outcome = None;
                    self.positive_object = None;
                }
                Arm::Negative => {
                    self.negative = self.negative.map(|_| blank_variant());
                    self.negative_outcome = None;
                }
                Arm::Clean => self.clean = blank_variant(),
                Arm::Measured => self.measured = blank_variant(),
            }
            self
        }

        /// What the declared family publishes for this case, through the path
        /// `run_check` takes.
        fn gating(&self) -> Option<report::Gating> {
            let mut controls = controls_with_positive(probe::Outcome::Absent);
            controls.positive.outcome = self.positive_outcome;
            controls.negative.outcome = self.negative_outcome;
            let readings = DeclaredReadings::read(
                self.check,
                &controls,
                (&self.positive, self.check.positive),
                self.positive_object.as_ref(),
                self.negative.as_ref(),
                &self.clean,
                &self.measured,
                read("x86_64"),
            );
            declared_gating(
                Verdict::ProbeInvalid,
                self.probe,
                self.check,
                self.libc,
                self.compiler,
                &readings,
            )
        }
    }

    #[test]
    fn the_emulation_reason_names_chards_build_only_where_its_arch_stands_in() {
        use crate::elf::ByteOrder::LittleEndian;
        let (clash, run, _) = emulated_stack_clash("aarch64");
        let reason_under = |kernel: crate::env::NativeMachine<'_>| {
            let mut elf = elf_with_report("");
            elf.machine = "aarch64".to_owned();
            elf.elf_data = Some(LittleEndian);
            let settled = settle_for(
                Verdict::On,
                clash,
                &stack_clash_reading(),
                |_| None,
                Some(&elf),
                Some(&run),
                &[],
            );
            settle_emulation(
                settled,
                Verdict::On,
                clash,
                Some(&elf),
                None,
                Some(&run),
                kernel,
                false,
            )
            .gating
            .expect("an aarch64 artifact on an x86_64 kernel is withheld")
            .reason
        };
        let read = reason_under(read("x86_64"));
        assert!(
            read.contains("the kernel's own machine is x86_64 (little-endian), so")
                && !read.contains("chard's own build"),
            "{read}"
        );
        let own = reason_under(crate::env::NativeMachine::chards_own("x86_64"));
        let order = if cfg!(target_endian = "big") {
            "big-endian"
        } else {
            "little-endian"
        };
        assert!(
            own.contains(&format!(
                "the kernel's own machine is x86_64 ({order}, chard's own build's order, \
                 since /proc/sys/kernel/arch was not read and the spelling is chard's own), so"
            )),
            "{own}"
        );
    }

    #[test]
    fn a_machine_reading_over_a_record_the_reader_refused_is_withheld() {
        use report::gating_rule as g;
        let (clash, run, _) = emulated_stack_clash("aarch64");
        let refused = "probe: not an ELF file (bad magic)";
        let open = || Settled {
            verdict: Verdict::On,
            gating: None,
            level: None,
        };
        let settled = settle_emulation(
            open(),
            Verdict::On,
            clash,
            None,
            Some(refused),
            Some(&run),
            read("x86_64"),
            false,
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled.gating.expect("withheld under a named rule");
        assert_eq!(gating.rule, g::RUN_UNDER_EMULATION);
        assert!(gating.reason.contains(refused), "{}", gating.reason);
        // No refusal recorded either: still withheld, saying so.
        let unrecorded = settle_emulation(
            open(),
            Verdict::On,
            clash,
            None,
            None,
            Some(&run),
            read("x86_64"),
            false,
        );
        assert!(
            unrecorded
                .gating
                .is_some_and(|gt| gt.reason.contains("no record of it was stored")),
            "the reason says no record was stored"
        );
        // A `Program` reading over the same refused record is left to its own verdict.
        let program = check_named("no-strict-overflow");
        assert_eq!(program.run_basis(), Some(probe::RunBasis::Program));
        let left = settle_emulation(
            open(),
            Verdict::On,
            program,
            None,
            Some(refused),
            Some(&run),
            read("x86_64"),
            false,
        );
        assert_eq!(left.verdict, Verdict::On);
        assert!(left.gating.is_none());
        // No run fires nothing; a `probe-invalid` is the triple's.
        let no_run = settle_emulation(
            open(),
            Verdict::On,
            clash,
            None,
            Some(refused),
            None,
            read("x86_64"),
            false,
        );
        assert!(no_run.gating.is_none());
        let invalid = settle_emulation(
            Settled {
                verdict: Verdict::ProbeInvalid,
                gating: None,
                level: None,
            },
            Verdict::ProbeInvalid,
            clash,
            None,
            Some(refused),
            Some(&run),
            read("x86_64"),
            false,
        );
        assert_eq!(invalid.verdict, Verdict::ProbeInvalid);
        assert!(invalid.gating.is_none());
    }

    /// [`settle_emulation`] of a stack-clash reading `decided` whose run printed `line` before
    /// its `SCPRT` line, under an aarch64 kernel.
    fn settle_translated(
        line: &str,
        decided: Verdict,
        unread: Option<&str>,
        elf: Option<&elf::ElfFacts>,
        macos: bool,
    ) -> Settled {
        let run = null_check_run(&format!("{line}SCPRT dist=8388620 n=67108864 ratio_pct=12"));
        settle_emulation(
            Settled {
                verdict: decided,
                gating: None,
                level: None,
            },
            decided,
            check_named("stack-clash-guard-page"),
            elf,
            unread,
            Some(&run),
            read("aarch64"),
            macos,
        )
    }

    #[test]
    fn on_macos_the_probes_translation_read_settles_a_reading_over_a_refused_record() {
        use report::gating_rule as g;
        let refused = "probe: not an ELF file (bad magic)";
        let settle_with = settle_translated;
        let native = settle_with(
            "CHARD-TRANSLATION 0\n",
            Verdict::On,
            Some(refused),
            None,
            true,
        );
        assert_eq!(native.verdict, Verdict::On);
        assert!(
            native.gating.is_none(),
            "the probe's 0 publishes the reading"
        );
        for (line, words) in [
            (
                "CHARD-TRANSLATION 1\n",
                "the probe read sysctl.proc_translated as 1: Rosetta 2 translated the run",
            ),
            (
                "CHARD-TRANSLATION unreadable errno:2\n",
                "(errno:2, ENOENT: no such sysctl, as on an Intel Mac)",
            ),
            (
                "CHARD-TRANSLATION unreadable errno:1\n",
                "could not read sysctl.proc_translated (errno:1)",
            ),
            ("", "the probe printed no CHARD-TRANSLATION line"),
            ("CHARD-TRANSLATION 2\n", "in no shape chard reads"),
            (
                "CHARD-TRANSLATION 0\nCHARD-TRANSLATION 0\n",
                "in no shape chard reads",
            ),
        ] {
            let settled = settle_with(line, Verdict::On, Some(refused), None, true);
            assert_eq!(settled.verdict, Verdict::Indeterminate, "{line:?}");
            let gating = settled.gating.expect("withheld under a named rule");
            assert_eq!(gating.rule, g::RUN_UNDER_EMULATION, "{line:?}");
            assert!(
                gating.reason.contains(words) && gating.reason.contains(refused),
                "{line:?}: {}",
                gating.reason
            );
        }
        // A `probe-invalid` is the triple's, whatever the line.
        let invalid = settle_with(
            "CHARD-TRANSLATION 1\n",
            Verdict::ProbeInvalid,
            Some(refused),
            None,
            true,
        );
        assert_eq!(invalid.verdict, Verdict::ProbeInvalid);
        assert!(invalid.gating.is_none());
    }

    #[test]
    fn the_translation_line_is_read_on_macos_over_a_refused_record_alone() {
        let refused = "probe: not an ELF file (bad magic)";
        let settle_with = settle_translated;
        // Off macOS the line settles nothing: the rule as it reads without it.
        let linux = settle_with(
            "CHARD-TRANSLATION 0\n",
            Verdict::On,
            Some(refused),
            None,
            false,
        );
        assert_eq!(linux.verdict, Verdict::Indeterminate);
        assert!(
            linux.gating.is_some_and(|gt| gt.reason.contains(refused)),
            "the Linux reason, without the line's clause"
        );
        // A record never stored is withheld, whatever the line.
        let unrecorded = settle_with("CHARD-TRANSLATION 0\n", Verdict::On, None, None, true);
        assert!(
            unrecorded
                .gating
                .is_some_and(|gt| gt.reason.contains("no record of it was stored")),
            "the reason says no record was stored"
        );
        // An ELF record of a foreign machine is held to the kernel, the line not consulted.
        let mut foreign = elf_with_report("");
        foreign.machine = "x86_64".to_owned();
        let held = settle_with(
            "CHARD-TRANSLATION 0\n",
            Verdict::On,
            None,
            Some(&foreign),
            true,
        );
        assert_eq!(held.verdict, Verdict::Indeterminate);
        assert!(
            held.gating.is_some_and(
                |gt| gt.reason.contains("x86_64") && !gt.reason.contains("proc_translated")
            ),
            "the machine comparison, not the line"
        );
    }

    /// [`settle`] of an `On` reading of `check` with the stack-clash detection over `elf`,
    /// nothing declared and no profile flags.
    fn settled_on(
        check: &Check,
        elf: Option<&elf::ElfFacts>,
        run: Option<&runner::RunRecord>,
    ) -> Settled {
        settle_for(
            Verdict::On,
            check,
            &stack_clash_reading(),
            |_| None,
            elf,
            run,
            &[],
        )
    }

    /// [`settle_emulation`] of an `On` reading over `elf`, with no reader's refusal, on an
    /// x86_64 kernel read from the sysctl.
    fn emulation_of(
        settled: Settled,
        check: &Check,
        elf: &elf::ElfFacts,
        run: Option<&runner::RunRecord>,
    ) -> Settled {
        settle_emulation(
            settled,
            Verdict::On,
            check,
            Some(elf),
            None,
            run,
            read("x86_64"),
            false,
        )
    }

    /// A kernel spelling read from `/proc/sys/kernel/arch`, as the tests name one.
    fn read(spelling: &str) -> crate::env::NativeMachine<'_> {
        crate::env::NativeMachine::read(spelling)
    }

    #[test]
    fn the_positive_controls_native_reads_the_artifacts_byte_order() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        let check = check_named("shadow-stack-enforced");
        let under = |order: Option<elf::ByteOrder>| {
            let DeclaredCase {
                probe,
                libc,
                compiler,
                mut positive,
                positive_outcome,
                clean,
                measured,
                ..
            } = machine_case(
                declared_case(report::gating_rule::KERNEL_LACKS_SHADOW_STACK),
                "SHSTK kernel=errno:22 cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
            );
            let elf = positive.elf.as_mut().expect("the case carries an artifact");
            elf.machine = "ppc64".to_owned();
            elf.elf_class = 64;
            elf.elf_data = order;
            let mut controls = controls_with_positive(probe::Outcome::Indeterminate);
            controls.positive.outcome = positive_outcome;
            let readings = DeclaredReadings::read(
                check,
                &controls,
                (&positive, check.positive),
                None,
                None,
                &clean,
                &measured,
                read("ppc64le"),
            );
            let fired = declared_gating(
                Verdict::ProbeInvalid,
                probe,
                check,
                libc,
                compiler,
                &readings,
            )
            .map(|g| g.rule);
            (readings.positive.native, fired)
        };
        assert_eq!(
            under(Some(BigEndian)),
            (Some(false), None),
            "the other order is an interpreter's, and the rule declines"
        );
        assert_eq!(
            under(Some(LittleEndian)),
            (
                Some(true),
                Some(report::gating_rule::KERNEL_LACKS_SHADOW_STACK)
            )
        );
        assert_eq!(under(None), (None, None), "no order, nothing to hold");
    }

    /// The ELF fields `check`'s own reading over `elf` rests on, as `run_check` hands them
    /// to the gates through the reading's proof.
    fn read_fields_over(
        check: &Check,
        elf: Option<&elf::ElfFacts>,
    ) -> BTreeSet<crate::predicate::ElfField> {
        let mut variant = blank_variant();
        variant.elf = elf.cloned();
        measured_artifact::elf_fields_read(check.decode(&evidence_for(&variant)).proof.as_ref())
    }

    /// [`artifact_gating`] for a check read from its own probe's artifact.
    fn gating_for(
        verdict: Verdict,
        check: &Check,
        reading: probe::Outcome,
        elf: Option<&elf::ElfFacts>,
    ) -> Option<(Verdict, report::Gating)> {
        let read = read_fields_over(check, elf);
        artifact_gating(
            verdict,
            check,
            probe_of(check).link_mode,
            reading,
            elf,
            &read,
        )
    }

    /// [`settle`] for a check read from its own probe's artifact.
    fn settle_for(
        verdict: Verdict,
        check: &Check,
        reading: &Detection,
        declared: impl FnOnce(Verdict) -> Option<report::Gating>,
        elf: Option<&elf::ElfFacts>,
        run: Option<&runner::RunRecord>,
        profile_flags: &[String],
    ) -> Settled {
        let mut variant = blank_variant();
        variant.elf = elf.cloned();
        let decoding = check.decode(&evidence_for(&variant));
        let artifact = MeasuredArtifact::of(probe_of(check), &variant, decoding.proof.as_ref());
        settle(
            verdict,
            check,
            reading,
            declared,
            artifact,
            run,
            profile_flags,
        )
    }

    /// The probe `check` belongs to.
    fn probe_of(check: &Check) -> &'static Probe {
        probe::CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.id == check.id))
            .unwrap_or_else(|| panic!("{} belongs to no probe", check.id))
    }

    /// A variant whose build said `stderr`.
    fn variant_saying(stderr: &str) -> Variant {
        Variant {
            build: Some(build_with_stderr(stderr)),
            ..blank_variant()
        }
    }

    /// A variant whose macros are `pairs`.
    fn variant_with_macros(pairs: &[(&str, &str)]) -> Variant {
        Variant {
            macros: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..blank_variant()
        }
    }

    /// The input on which `rule`, a member of the declared family, fires: every arm its
    /// row names carries what the rule reads, and every other arm carries nothing.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per declared rule, read top to bottom; the table is the point"
    )]
    fn declared_case(rule: report::gating_rule::Rule) -> DeclaredCase {
        use report::gating_rule as g;

        let said = |stderr: &str, flags: &[&str]| {
            control_flag_rejection(&build_with_stderr(stderr), flags)
                .unwrap_or_else(|| panic!("{}: the reader does not see {stderr}", rule.id))
        };
        let base = |check: &'static Check| DeclaredCase {
            probe: probe_of(check),
            check,
            libc: "glibc",
            compiler: "gcc",
            positive: blank_variant(),
            positive_outcome: None,
            negative: (!check.negative.is_empty()).then(blank_variant),
            negative_outcome: None,
            clean: blank_variant(),
            measured: blank_variant(),
            line: None,
            positive_object: None,
        };
        match rule.id {
            id if id == g::LIBC_DECLARED.id => {
                let check = check_named("fortify-level-ge-2-subobject");
                DeclaredCase {
                    libc: check.gate.libc_unsupported[0],
                    positive_outcome: Some(probe::Outcome::Absent),
                    ..base(check)
                }
            }
            id if id == g::COMPILER_DECLARED.id => DeclaredCase {
                compiler: "clang",
                positive_outcome: Some(probe::Outcome::Absent),
                ..base(check_named("bidi-chars-any"))
            },
            id if id == g::FLAG_UNKNOWN.id || id == g::FLAG_REFUSED.id => {
                let check = check_named("auto-var-init-active");
                let flag = check.positive[0];
                let stderr = if id == g::FLAG_REFUSED.id {
                    format!("clang: error: '{flag}' hasn't been enabled")
                } else {
                    format!("clang: error: unknown argument: '{flag}'")
                };
                DeclaredCase {
                    compiler: "clang",
                    positive: variant_saying(&stderr),
                    line: Some(said(&stderr, check.positive)),
                    ..base(check)
                }
            }
            id if id == g::NO_UNHARDENED_STATE.id => {
                let check = check_named("no-copy-dt-needed");
                let stderr = "ld: error: unknown argument '--copy-dt-needed-entries'";
                DeclaredCase {
                    negative: Some(variant_saying(stderr)),
                    line: Some(said(stderr, check.negative)),
                    ..base(check)
                }
            }
            id if id == g::LINKER_KEYWORD_IGNORED.id => {
                let check = check_named("relative-relocs");
                let stderr = "/usr/bin/ld: warning: -z pack-relative-relocs ignored";
                let line = z_keyword_rejection(&build_with_stderr(stderr), check.positive)
                    .expect("the reader sees the ignored keyword");
                DeclaredCase {
                    positive: variant_saying(stderr),
                    line: Some(line),
                    ..base(check)
                }
            }
            id if id == g::STDLIB_LACKS_OBSERVABLE.id => {
                let check = check_named("cxx-assertions-symbol");
                let lib = check.gate.cxx_stdlib_unsupported[0];
                DeclaredCase {
                    clean: variant_with_macros(&[("_CXX_STDLIB", lib)]),
                    measured: variant_with_macros(&[("_CXX_STDLIB", lib)]),
                    ..base(check)
                }
            }
            id if id == g::FORTIFY_LEVEL_DECLINED.id => DeclaredCase {
                positive: variant_with_macros(&[
                    ("_FORTIFY_SOURCE", "3"),
                    ("__USE_FORTIFY_LEVEL", "2"),
                    ("__OPTIMIZE__", "1"),
                ]),
                ..base(check_named("fortify-enforced-dynamic"))
            },
            id if id == g::SCAFFOLDING.id => {
                let probe = probe_named("copy-dt-needed");
                let stderr = "ld: unknown options: -soname -rpath-link";
                DeclaredCase {
                    positive: variant_saying(stderr),
                    line: Some(said(stderr, SCAFFOLDING_FLAGS)),
                    ..base(&probe.checks[0])
                }
            }
            id if id == g::LINK_DROPS_MARKING.id => link_drop_case(base(check_named("cet-marked"))),
            id if id == g::SUBOBJECT_BOUND_LOST_IN_WRAPPER.id => {
                wrapper_case(base(check_named("fortify-level-ge-2-subobject")))
            }
            id if id == g::KERNEL_LACKS_SHADOW_STACK.id => machine_case(
                base(check_named("shadow-stack-enforced")),
                "SHSTK kernel=errno:22 cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
            ),
            id if id == g::CPU_LACKS_SHADOW_STACK.id => machine_case(
                base(check_named("shadow-stack-enforced")),
                "SHSTK kernel=ok cpu=no-ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
            ),
            id if id == g::MACHINE_LACKS_BTI.id => machine_case(
                base(check_named("bti-enforced")),
                "BTI hwcap=no\nBTI branch=attempted\nBTI branch=landed returned=42\n",
            ),
            id if id == g::MACHINE_LACKS_PAC.id => machine_case(
                base(check_named("pac-ret-enforced")),
                "PAC hwcap=no fpac=unread\nPAC return=attempted\nPAC return=hijacked\n",
            ),
            id if id == g::CPU_SHOWS_NO_FPAC.id => {
                let mut case = machine_case(
                    base(check_named("pac-ret-enforced")),
                    "PAC hwcap=yes fpac=no\nPAC return=attempted\n",
                );
                // The death a failed authentication raises without FPAC: the return faults on
                // the poisoned address.
                if let Some(run) = case.positive.run.as_mut() {
                    run.exit_status = -1;
                    run.signal = Some("SIGSEGV".to_owned());
                    run.stderr = "chard-fault-v1 signal=11 code=1 sent=no arch=aarch64 \
                                  pc=0x20000000400a8c addr=0x20000000400a8c word=none \
                                  esr=0x82000004 at-target=no\n"
                        .to_owned();
                }
                case
            }
            id if id == g::OPT_IN_NOT_HONOURED.id => DeclaredCase {
                positive_outcome: Some(probe::Outcome::Absent),
                ..machine_case(base(check_named("shadow-stack-enforced")), IGNORED_TUNABLES)
            },
            id if id == g::LOADER_REFUSES_EXECSTACK.id => {
                loader_case(base(check_named("noexecstack-enforced")))
            }
            other => panic!("{other} has no construction site in `declared_case`"),
        }
    }

    /// `subobject-bound-lost-in-wrapper`'s case: a silent positive control whose own run
    /// printed clang 18.1.3's line over glibc 2.39, the member's 8 at the call site and the
    /// whole object's 16 through the wrapper, in an arm glibc settled at level 2.
    fn wrapper_case(base: DeclaredCase) -> DeclaredCase {
        DeclaredCase {
            compiler: "clang",
            positive_outcome: Some(probe::Outcome::Absent),
            positive: Variant {
                run: Some(null_check_run(
                    "CHARD-BOS main1=8 main0=16 wrap1=16 glibc_wrappers=1 clang_path=?\n\
                     no-check-fired 0\n",
                )),
                ..variant_with_macros(&[
                    ("_FORTIFY_SOURCE", "2"),
                    ("__USE_FORTIFY_LEVEL", "2"),
                    ("__OPTIMIZE__", "1"),
                ])
            },
            ..base
        }
    }

    /// `kernel-lacks-shadow-stack`'s and `cpu-lacks-shadow-stack`'s case: a positive control
    /// read `indeterminate`, whose own run printed `stdout` (a kernel without user shadow
    /// stack gives `EINVAL`, 22; a CPU without it, `no-ss`), over an x86_64 artifact the
    /// x86_64 kernel `gating` names ran itself.
    fn machine_case(base: DeclaredCase, stdout: &str) -> DeclaredCase {
        DeclaredCase {
            positive_outcome: Some(probe::Outcome::Indeterminate),
            positive: Variant {
                run: Some(null_check_run(stdout)),
                elf: Some(probe::tests::elf_with_report("")),
                ..blank_variant()
            },
            ..base
        }
    }

    /// The pinned process's lines on a Wolfi-derived rootfs's glibc 2.44-r23, which ignores
    /// `GLIBC_TUNABLES` (measured 2026-10-21 on Fedora 44 x86_64, its loader and libc linked
    /// in): the witness tunable had no effect, and the marked program ran unprotected.
    const IGNORED_TUNABLES: &str = "SHSTK tunables=ignored\n\
        SHSTK-UNPINNED kernel=ok cpu=ss features=0 ssp=zero\n\
        SHSTK-UNPINNED clobber=hijacked\n\
        SHSTK kernel=ok cpu=ss features=0 ssp=zero\n\
        SHSTK clobber=hijacked\n";

    /// The loader's line a Wolfi-derived rootfs's glibc printed for the `-z execstack` arm, the
    /// same day.
    const LOADER_REFUSED: &str = "Fatal glibc error: executable stack is not allowed";

    /// `loader-refuses-execstack`'s case: a negative control read `indeterminate`, whose
    /// run exited 127 with the loader's refusal and no stdout, over an x86_64 artifact the
    /// x86_64 kernel ran itself.
    fn loader_case(base: DeclaredCase) -> DeclaredCase {
        let mut run = null_check_run("");
        run.exit_status = 127;
        run.stderr = format!("{LOADER_REFUSED}\n");
        DeclaredCase {
            negative_outcome: Some(probe::Outcome::Indeterminate),
            negative: Some(Variant {
                run: Some(run),
                elf: Some(probe::tests::elf_with_report("")),
                ..blank_variant()
            }),
            ..base
        }
    }

    #[test]
    fn each_documented_guard_of_the_c_library_rules_declines_alone() {
        use report::gating_rule as g;
        let fired = |case: &DeclaredCase| case.gating().map(|gating| gating.rule);
        let opt_in = || declared_case(g::OPT_IN_NOT_HONOURED);
        let loader = || declared_case(g::LOADER_REFUSES_EXECSTACK);
        let with_stdout = |stdout: &str| DeclaredCase {
            positive: Variant {
                run: Some(null_check_run(stdout)),
                elf: Some(probe::tests::elf_with_report("")),
                ..blank_variant()
            },
            ..opt_in()
        };
        let foreign = || {
            let mut elf = probe::tests::elf_with_report("");
            elf.machine = "aarch64".to_owned();
            elf
        };
        let cases: Vec<(&str, DeclaredCase)> = vec![
            (
                "no witness line",
                with_stdout(&IGNORED_TUNABLES.replace("SHSTK tunables=ignored\n", "")),
            ),
            (
                "an unallocated witness",
                with_stdout(&IGNORED_TUNABLES.replace("ignored", "unallocated")),
            ),
            (
                "another C library",
                DeclaredCase {
                    libc: "uclibc",
                    ..opt_in()
                },
            ),
            (
                "another check",
                DeclaredCase {
                    check: check_named("cet-marked"),
                    ..opt_in()
                },
            ),
            (
                "a positive arm with no artifact",
                DeclaredCase {
                    positive: Variant {
                        elf: None,
                        ..opt_in().positive
                    },
                    ..opt_in()
                },
            ),
            (
                "a positive arm for another machine",
                DeclaredCase {
                    positive: Variant {
                        elf: Some(foreign()),
                        ..opt_in().positive
                    },
                    ..opt_in()
                },
            ),
            (
                "another check, for the loader",
                DeclaredCase {
                    check: check_named("cet-marked"),
                    ..loader()
                },
            ),
            (
                "a negative arm with no artifact",
                DeclaredCase {
                    negative: loader().negative.map(|v| Variant { elf: None, ..v }),
                    ..loader()
                },
            ),
            (
                "a negative arm for another machine",
                DeclaredCase {
                    negative: loader().negative.map(|v| Variant {
                        elf: Some(foreign()),
                        ..v
                    }),
                    ..loader()
                },
            ),
        ];
        for (what, case) in cases {
            let rule = fired(&case);
            assert!(
                rule != Some(g::OPT_IN_NOT_HONOURED) && rule != Some(g::LOADER_REFUSES_EXECSTACK),
                "{what}: fired {rule:?}"
            );
        }
    }

    #[test]
    fn the_c_library_rules_decline_where_their_observation_does_not_hold() {
        use report::gating_rule as g;
        let fired = |case: &DeclaredCase| case.gating().map(|gating| gating.rule);
        let opt_in = || declared_case(g::OPT_IN_NOT_HONOURED);
        assert_eq!(fired(&opt_in()), Some(g::OPT_IN_NOT_HONOURED));
        assert_eq!(
            fired(&DeclaredCase {
                libc: "musl",
                ..opt_in()
            }),
            Some(g::LIBC_DECLARED)
        );
        let honoured = DeclaredCase {
            positive: Variant {
                run: Some(null_check_run(
                    &IGNORED_TUNABLES.replace("tunables=ignored", "tunables=honoured"),
                )),
                elf: Some(probe::tests::elf_with_report("")),
                ..blank_variant()
            },
            ..opt_in()
        };
        assert_eq!(fired(&honoured), None);
        assert_eq!(
            fired(&DeclaredCase {
                positive_outcome: Some(probe::Outcome::Indeterminate),
                ..opt_in()
            }),
            None
        );

        let loader = || declared_case(g::LOADER_REFUSES_EXECSTACK);
        assert_eq!(fired(&loader()), Some(g::LOADER_REFUSES_EXECSTACK));
        let mut silent = null_check_run("");
        silent.exit_status = 127;
        let no_line = DeclaredCase {
            negative: Some(Variant {
                run: Some(silent),
                elf: Some(probe::tests::elf_with_report("")),
                ..blank_variant()
            }),
            ..loader()
        };
        assert_eq!(fired(&no_line), None);
        assert_eq!(
            fired(&DeclaredCase {
                negative_outcome: Some(probe::Outcome::Absent),
                ..loader()
            }),
            None
        );
    }

    /// `link-drops-marking`'s case: a silent linked positive control beside the same arm's
    /// object, which carries both CET bits and a digest the reason must quote.
    fn link_drop_case(base: DeclaredCase) -> DeclaredCase {
        let mut marked = elf_with_report("");
        marked.elf_type = "ET_REL".to_owned();
        marked.x86_ibt = true;
        marked.x86_shstk = true;
        let mut build = build_with_stderr("");
        build.artifact_sha256 = Some("0b1ec7".repeat(10) + "0b1e");
        DeclaredCase {
            positive_outcome: Some(probe::Outcome::Absent),
            positive_object: Some(Variant {
                elf: Some(marked),
                build: Some(build),
                ..blank_variant()
            }),
            ..base
        }
    }

    /// [`reach`] for the declared family, through [`declared_gating`], the chain
    /// `run_check` consults on `probe-invalid`. The quoted input is read off the case by the
    /// row's `evidence` column.
    fn reach_declared(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        use report::gating_rule::{self as g, Evidence};

        let case = declared_case(rule);
        let gating = case
            .gating()
            .unwrap_or_else(|| panic!("{} was not reached", rule.id));
        let macro_of = |variant: &Variant, name: &str| {
            variant
                .macros
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("{}: the case carries no {name}", rule.id))
        };
        let quoted = match rule.evidence {
            Evidence::ToolSentence { .. } => case.line.clone().unwrap_or_else(|| {
                panic!("{} rests on a tool's sentence and was handed none", rule.id)
            }),
            Evidence::DeclaredAndSilent if rule == g::LIBC_DECLARED => case.libc.to_owned(),
            Evidence::DeclaredAndSilent => case.compiler.to_owned(),
            Evidence::FortifyMacros => format!(
                "__USE_FORTIFY_LEVEL={}",
                macro_of(&case.positive, "__USE_FORTIFY_LEVEL")
            ),
            Evidence::StdlibMacros => macro_of(&case.measured, "_CXX_STDLIB"),
            Evidence::ObjectMarking => case
                .positive_object
                .as_ref()
                .and_then(|o| o.build.as_ref()?.artifact_sha256.clone())
                .unwrap_or_else(|| panic!("{} was handed no object digest", rule.id)),
            Evidence::ObjectSizeWitness => case
                .positive
                .run
                .as_ref()
                .and_then(|r| r.stdout.lines().find(|l| l.starts_with("CHARD-BOS ")))
                .map_or_else(
                    || panic!("{} was handed no CHARD-BOS line", rule.id),
                    str::to_owned,
                ),
            Evidence::MachineWitness => case
                .positive
                .run
                .as_ref()
                .and_then(|r| {
                    r.stdout.lines().find(|l| {
                        l.starts_with("SHSTK kernel=")
                            || l.starts_with("BTI hwcap=")
                            || l.starts_with("PAC hwcap=")
                    })
                })
                .map_or_else(
                    || panic!("{} was handed no SHSTK, BTI or PAC line", rule.id),
                    str::to_owned,
                ),
            Evidence::TunablesWitness => case
                .positive
                .run
                .as_ref()
                .and_then(|r| r.stdout.lines().find(|l| l.starts_with("SHSTK tunables=")))
                .map_or_else(
                    || panic!("{} was handed no SHSTK tunables line", rule.id),
                    str::to_owned,
                ),
            Evidence::LoaderRefusal => case
                .negative
                .as_ref()
                .and_then(|v| v.run.as_ref())
                .and_then(crate::decode::runtime::loader_refusal)
                .map_or_else(
                    || panic!("{} was handed no loader line", rule.id),
                    str::to_owned,
                ),
            other => panic!("{} is declared with evidence {other:?}", rule.id),
        };
        (gating, quoted)
    }

    #[test]
    fn every_declared_rule_reads_the_arms_its_row_names() {
        use report::gating_rule::{Arm, Stage};

        let every_arm = [Arm::Positive, Arm::Negative, Arm::Clean, Arm::Measured];
        let mut held = 0;
        for rule in report::gating_rule::ALL
            .iter()
            .filter(|r| r.stage == Stage::Declared)
        {
            assert!(!rule.arms.is_empty(), "{} reads no build", rule.id);
            let fired = declared_case(*rule).gating().map(|g| g.rule);
            assert_eq!(
                fired,
                Some(*rule),
                "{} does not fire on its named arms",
                rule.id
            );
            for arm in every_arm {
                let blanked = declared_case(*rule).blank(arm).gating().map(|g| g.rule);
                if rule.arms.contains(&arm) {
                    assert_ne!(
                        blanked,
                        Some(*rule),
                        "{} fired with {arm:?} blanked, which its row says it reads",
                        rule.id
                    );
                } else {
                    assert_eq!(
                        blanked,
                        Some(*rule),
                        "{} stopped firing with {arm:?} blanked, which its row does not name",
                        rule.id
                    );
                }
            }
            held += 1;
        }
        assert!(held > 0, "no declared rule was held");
    }

    #[test]
    fn every_declared_sentence_rule_fires_only_on_its_kind_of_sentence() {
        use report::gating_rule::{Arm, Evidence, Flags, Sentence, Stage};

        let mut held = 0;
        for rule in report::gating_rule::ALL
            .iter()
            .filter(|r| r.stage == Stage::Declared)
        {
            let Evidence::ToolSentence {
                arm,
                flags,
                sentence,
            } = rule.evidence
            else {
                continue;
            };
            let base = declared_case(*rule);
            let flag = match (flags, arm) {
                (Flags::Scaffolding, _) => SCAFFOLDING_FLAGS[0],
                (Flags::Control, Arm::Negative) => base.check.negative[0],
                (Flags::Control, _) => base.check.positive[0],
            };
            let token = spellings(flag)
                .last()
                .expect("a flag has at least its own spelling");
            let phrasings = [
                (false, format!("cc: error: unknown argument: '{token}'")),
                (true, format!("cc: error: '{token}' hasn't been enabled")),
            ];
            for (refusal, stderr) in phrasings {
                let own_kind = match sentence {
                    Sentence::Unknown => !refusal,
                    Sentence::Refused => refusal,
                    Sentence::Ignored => continue,
                };
                let mut case = declared_case(*rule);
                match arm {
                    Arm::Positive => case.positive = variant_saying(&stderr),
                    Arm::Negative => case.negative = Some(variant_saying(&stderr)),
                    Arm::Clean | Arm::Measured => panic!("{} quotes a {arm:?} build", rule.id),
                }
                let fired = case.gating();
                if let Some(g) = &fired
                    && let Evidence::ToolSentence {
                        sentence: published,
                        ..
                    } = g.rule.evidence
                {
                    let published_refusal = published == Sentence::Refused;
                    assert_eq!(
                        published_refusal, refusal,
                        "{} fired {} on `{stderr}`",
                        rule.id, g.rule.id
                    );
                }
                assert_eq!(
                    fired.map(|g| g.rule) == Some(*rule),
                    own_kind,
                    "{} on `{stderr}`",
                    rule.id
                );
            }
            held += 1;
        }
        assert!(held >= 4, "only {held} sentence rules were held");
    }

    #[test]
    fn every_other_rule_names_the_arms_its_stage_is_handed() {
        use report::gating_rule::{Arm, Stage};

        for rule in report::gating_rule::ALL {
            let expected: &[Arm] = match rule.stage {
                Stage::Declared => continue,
                Stage::Driver
                | Stage::Probe
                | Stage::Applicability
                | Stage::Target
                | Stage::Twin => &[],
                Stage::Level
                | Stage::Detector
                | Stage::Artifact
                | Stage::Run
                | Stage::Sanitizer
                | Stage::Lto
                | Stage::Spoof => &[Arm::Measured],
                // `ask_link` asks the driver about the measured build's flags
                // and the selection both control arms carry, and `ask_compile`
                // asks the same of the compile.
                Stage::Link | Stage::Compile => &[Arm::Measured, Arm::Positive, Arm::Negative],
            };
            assert_eq!(rule.arms, expected, "{}", rule.id);
        }
    }

    #[test]
    fn two_rules_in_settle_publish_the_later_stage() {
        use report::gating_rule as g;

        let later = |a: g::Rule, b: g::Rule| if b.stage > a.stage { b } else { a };
        let declared = |rule: g::Rule| {
            move |_: Verdict| {
                Some(report::Gating {
                    rule,
                    arch: None,
                    libc: None,
                    needs_vm: false,
                    reason: "declared".to_owned(),
                })
            }
        };

        // The level rule and the macro-spoof rule.
        let ssp = check_named("ssp-level");
        let (verdict, reading) = decided(ssp, Some("bogus"), "__SSP_STRONG__=3");
        let forged = vec!["-D__SSP_STRONG__=3".to_owned()];
        let alone = settle_for(verdict, ssp, &reading, |_| None, None, None, &[]);
        assert_eq!(alone.gating.map(|g| g.rule), Some(g::LEVEL_OFF_SCALE));
        let both = settle_for(verdict, ssp, &reading, |_| None, None, None, &forged);
        assert_eq!(
            both.gating.map(|g| g.rule),
            Some(later(g::LEVEL_OFF_SCALE, g::MACRO_SPOOFED))
        );

        // A declared rule and the macro-spoof rule, on a macro-channel check the family
        // withheld.
        assert_eq!(ssp.channel(), Channel::Macro);
        let observed = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: "__SSP_STRONG__=3".to_owned(),
            rule: None,
        };
        let decl = g::FLAG_UNKNOWN;
        let alone = settle_for(
            Verdict::ProbeInvalid,
            ssp,
            &observed,
            declared(decl),
            None,
            None,
            &[],
        );
        assert_eq!(alone.gating.map(|g| g.rule), Some(decl));
        let both = settle_for(
            Verdict::ProbeInvalid,
            ssp,
            &observed,
            declared(decl),
            None,
            None,
            &forged,
        );
        assert_eq!(
            both.gating.map(|g| g.rule),
            Some(later(decl, g::MACRO_SPOOFED))
        );

        // The level rule and the artifact's truncation, on a graded check that reads a
        // table.
        let mut cut_everywhere = elf_with_report("");
        cut_everywhere.truncations = elf::ElfTable::ALL
            .iter()
            .map(|t| cut(*t, elf::TruncationKind::Unread, "cut"))
            .collect();
        let graded = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| {
                c.levels.grade().is_some()
                    && report::truncated_reading(c, Some(&cut_everywhere)).is_some()
            })
            .expect("a graded check reads a table");
        let (verdict, reading) = decided(graded, Some("bogus"), "bogus");
        let alone = settle_for(verdict, graded, &reading, |_| None, None, None, &[]);
        assert_eq!(alone.gating.map(|g| g.rule), Some(g::LEVEL_OFF_SCALE));
        let both = settle_for(
            verdict,
            graded,
            &reading,
            |_| None,
            Some(&cut_everywhere),
            None,
            &[],
        );
        assert_eq!(
            both.gating.map(|g| g.rule),
            Some(later(g::LEVEL_OFF_SCALE, g::ARTIFACT_UNREADABLE))
        );

        // The declared family and the artifact gates are disjoint by verdict.
        let mut no_dynamic = elf_with_report("");
        no_dynamic.has_dynamic = false;
        for facts in [&cut_everywhere, &no_dynamic] {
            for check in probe::CORPUS.iter().flat_map(|p| p.checks) {
                for outcome in [probe::Outcome::Absent, probe::Outcome::Indeterminate] {
                    assert!(
                        gating_for(Verdict::ProbeInvalid, check, outcome, Some(facts)).is_none(),
                        "{} is gated on its artifact on probe-invalid",
                        check.id
                    );
                }
            }
        }
    }

    #[test]
    fn the_self_report_gate_sits_between_the_level_rule_and_the_spoof_rule() {
        use report::gating_rule as g;

        let later = |a: g::Rule, b: g::Rule| if b.stage > a.stage { b } else { a };
        let ssp = check_named("ssp-level");
        assert_eq!(ssp.channel(), Channel::Macro);
        // A read artifact that names no macro, under a graded macro check.
        let no_section = elf_with_report("");
        let (verdict, reading) = decided(ssp, Some("bogus"), "__SSP_STRONG__=3");
        let alone = settle_for(verdict, ssp, &reading, |_| None, None, None, &[]);
        assert_eq!(alone.gating.map(|g| g.rule), Some(g::LEVEL_OFF_SCALE));
        let both = settle_for(
            verdict,
            ssp,
            &reading,
            |_| None,
            Some(&no_section),
            None,
            &[],
        );
        assert_eq!(
            both.gating.map(|g| g.rule),
            Some(later(g::LEVEL_OFF_SCALE, g::ARTIFACT_LACKS_SELF_REPORT))
        );
        let (verdict, reading) = decided(ssp, Some("strong"), "__SSP_STRONG__=1");
        let alone = settle_for(
            verdict,
            ssp,
            &reading,
            |_| None,
            Some(&no_section),
            None,
            &[],
        );
        assert_eq!(
            alone.gating.map(|g| g.rule),
            Some(g::ARTIFACT_LACKS_SELF_REPORT)
        );
        let spoofed = vec!["-D__SSP_STRONG__=1".to_owned()];
        let both = settle_for(
            verdict,
            ssp,
            &reading,
            |_| None,
            Some(&no_section),
            None,
            &spoofed,
        );
        assert_eq!(
            both.gating.map(|g| g.rule),
            Some(later(g::ARTIFACT_LACKS_SELF_REPORT, g::MACRO_SPOOFED))
        );
    }

    #[test]
    fn a_run_rule_beside_another_in_settle_publishes_the_later_stage() {
        use report::gating_rule as g;

        let later = |a: g::Rule, b: g::Rule| if b.stage > a.stage { b } else { a };
        let mut cut_everywhere = elf_with_report("");
        cut_everywhere.truncations = elf::ElfTable::ALL
            .iter()
            .map(|t| cut(*t, elf::TruncationKind::Unread, "cut"))
            .collect();

        // The level rule and a run rule, on a graded runtime check.
        let mut killed = null_check_run("");
        killed.timed_out = true;
        killed.exit_status = -1;
        killed.signal = Some("SIGKILL".to_owned());
        let mut cut_run = null_check_run("");
        cut_run.output_truncated = true;
        let graded_runtime = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.channel() == Channel::Runtime && c.levels.grade().is_some())
            .expect("a runtime check grades a level");
        let (verdict, reading) = decided(graded_runtime, Some("bogus"), "bogus");
        let alone = settle_for(verdict, graded_runtime, &reading, |_| None, None, None, &[]);
        assert_eq!(alone.gating.map(|g| g.rule), Some(g::LEVEL_OFF_SCALE));
        for (run, rule) in [
            (&killed, g::RUN_DEADLINE_ELAPSED),
            (&cut_run, g::RUN_OUTPUT_UNREADABLE),
        ] {
            let both = settle_for(
                verdict,
                graded_runtime,
                &reading,
                |_| None,
                None,
                Some(run),
                &[],
            );
            assert_eq!(
                both.gating.map(|g| g.rule),
                Some(later(g::LEVEL_OFF_SCALE, rule))
            );
        }

        // A run rule and the artifact's truncation, on a runtime check that reads a table.
        let tabled_runtime = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| {
                c.channel() == Channel::Runtime
                    && report::truncated_reading(c, Some(&cut_everywhere)).is_some()
            })
            .expect("a runtime check reads a table");
        let (verdict, reading) = (
            Verdict::Off,
            Detection {
                outcome: probe::Outcome::Absent,
                level: None,
                observed: String::new(),
                rule: None,
            },
        );
        for (run, rule) in [
            (&killed, g::RUN_DEADLINE_ELAPSED),
            (&cut_run, g::RUN_OUTPUT_UNREADABLE),
        ] {
            let alone = settle_for(
                verdict,
                tabled_runtime,
                &reading,
                |_| None,
                None,
                Some(run),
                &[],
            );
            assert_eq!(alone.gating.map(|g| g.rule), Some(rule), "{}", rule.id);
            let both = settle_for(
                verdict,
                tabled_runtime,
                &reading,
                |_| None,
                Some(&cut_everywhere),
                Some(run),
                &[],
            );
            assert_eq!(
                both.gating.map(|g| g.rule),
                Some(later(rule, g::ARTIFACT_UNREADABLE)),
                "{}",
                rule.id
            );
        }
    }

    #[test]
    fn every_gating_rule_is_reached_by_its_own_construction_site() {
        let mut reached = 0;
        for rule in report::gating_rule::ALL {
            let (gating, quoted) = reach(*rule);
            assert_eq!(gating.rule, *rule, "{} reached another row", rule.id);
            assert_eq!(gating.rule.verdict(), rule.premise.verdict());
            assert!(
                !quoted.is_empty(),
                "{} was handed nothing to quote",
                rule.id
            );
            assert!(
                gating.reason.contains(&quoted),
                "{} ({:?}) does not quote `{quoted}`: {}",
                rule.id,
                rule.evidence,
                gating.reason
            );
            reached += 1;
        }
        assert_eq!(
            reached,
            report::gating_rule::ALL.len(),
            "a row was not reached"
        );
        assert!(reached > 0, "the table is empty");
    }

    /// A run record carrying `stdout`: for `no-delete-null-pointer-checks`, whose detector
    /// reads a `null-check=` marker off it, and for the subobject rung's `CHARD-BOS` line.
    fn null_check_run(stdout: &str) -> runner::RunRecord {
        runner::RunRecord {
            argv: vec!["probe".to_owned()],
            exit_status: 0,
            signal: None,
            stdout: stdout.to_owned(),
            stderr: String::new(),
            timed_out: false,
            deadline_ms: Some(5000),
            output_error: None,
            output_truncated: false,
            duration_ms: 1,
            environment: None,
        }
    }

    #[test]
    fn a_union_zeroed_by_the_profile_is_withheld_by_the_regime_arm() {
        fn arm(detection: &Detection) -> report::ArmInput<'_> {
            report::ArmInput {
                detection: Some(detection),
                flags: Vec::new(),
                overridden: None,
            }
        }
        let check = check_named("zero-init-padding-bits");
        assert_eq!(
            check.regime_arm(),
            Some(&["-fzero-init-padding-bits=standard"][..])
        );
        assert!(
            check.owes_regime_control(false),
            "a profile with flags owes the arm"
        );
        assert!(
            !check.owes_regime_control(true),
            "a clean profile owes none"
        );
        let macros = BTreeMap::new();
        let read = |stdout: &str| {
            let run = null_check_run(stdout);
            crate::decode::runtime::detect_zero_init_padding(&Evidence {
                macros: &macros,
                elf: None,
                build: None,
                run: Some(&run),
                workdir: None,
            })
        };
        let zeroed = read("ZIPB pad=00 ctrl=5a ctrl_supported=1\n");
        let dirt = read("ZIPB pad=5a ctrl=5a ctrl_supported=1\n");
        assert_eq!(
            zeroed.outcome,
            probe::Outcome::Present,
            "{}",
            zeroed.observed
        );
        assert_eq!(dirt.outcome, probe::Outcome::Absent, "{}", dirt.observed);
        let (verdict, controls) =
            report::decide(&zeroed, arm(&zeroed), arm(&dirt), Some(arm(&zeroed)), None);
        assert_eq!(verdict, Verdict::ProbeInvalid);
        assert_eq!(
            controls.withheld(),
            Some(report::WithheldBecause::RegimeConfounded)
        );
        let (verdict, controls) =
            report::decide(&zeroed, arm(&zeroed), arm(&dirt), Some(arm(&dirt)), None);
        assert_eq!(verdict, Verdict::On);
        assert_eq!(controls.withheld(), None);
    }

    #[test]
    fn a_silent_overflow_handler_is_withheld_by_the_compiles_words() {
        let run = null_check_run("optimize=yes\nfrontend=gcc\ngcc-major=16\noverflow-guard=ran\n");
        let macros = BTreeMap::new();
        let reading = crate::decode::runtime::detect_no_strict_overflow(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        });
        assert_eq!(
            reading.outcome,
            probe::Outcome::Present,
            "{}",
            reading.observed
        );
        let check = check_named("no-strict-overflow");
        let on = || Settled {
            verdict: Verdict::On,
            gating: None,
            level: None,
        };
        let words: report::SanitizerWords =
            Ok(vec!["-fsanitize=signed-integer-overflow".to_owned()]);
        let settled = settle_listings(
            on(),
            check,
            &ProbeListings {
                sanitizers: Some(&words),
                ..ProbeListings::default()
            },
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        assert_eq!(
            settled.gating.map(|g| g.rule.id),
            Some(report::gating_rule::SIGNED_OVERFLOW_SANITIZED.id)
        );
        let none: report::SanitizerWords = Ok(Vec::new());
        assert_eq!(
            settle_listings(
                on(),
                check,
                &ProbeListings {
                    sanitizers: Some(&none),
                    ..ProbeListings::default()
                },
            )
            .verdict,
            Verdict::On
        );
    }

    #[test]
    fn a_runtime_reading_over_a_cut_stream_is_withheld() {
        use probe::Outcome;

        let check = check_named("no-delete-null-pointer-checks");
        assert_eq!(check.channel(), Channel::Runtime);
        let with_run = |run: runner::RunRecord| {
            let mut v = blank_variant();
            v.build = Some(variant_build(0, true));
            v.run = Some(run);
            v
        };
        let read = |v: &Variant| reading(check, v).detection;

        let whole = with_run(null_check_run("null-check=deleted"));
        assert_eq!(
            read(&whole).outcome,
            Outcome::Absent,
            "a whole stream is read"
        );

        for marker in ["null-check=deleted", "null-check=kept"] {
            let mut capped = null_check_run(marker);
            capped.output_truncated = true;
            let d = read(&with_run(capped));
            assert_eq!(d.outcome, Outcome::Indeterminate, "{marker}");
            assert!(
                d.observed.contains("capture cap") && d.observed.contains("the detector read"),
                "the replacement says the stream was cut and keeps the reading: {}",
                d.observed
            );

            let mut unread = null_check_run(marker);
            unread.output_error = Some("stdout: permission denied".to_owned());
            let d = read(&with_run(unread));
            assert_eq!(d.outcome, Outcome::Indeterminate, "{marker}");
            assert!(d.observed.contains("permission denied"), "{}", d.observed);
        }

        // The run beside a macro-channel check is evidence that check never read.
        let macro_check = check_named("ssp-level");
        assert_ne!(macro_check.channel(), Channel::Runtime);
        let mut capped = null_check_run("");
        capped.output_truncated = true;
        assert!(report::cut_stream_reading(macro_check, Some(&capped)).is_none());
    }

    #[test]
    fn a_cut_stream_on_the_measured_build_names_its_rule() {
        let check = check_named("no-delete-null-pointer-checks");
        let mut capped = null_check_run("null-check=deleted");
        capped.output_truncated = true;
        let reading = Detection {
            outcome: probe::Outcome::Indeterminate,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let never = |_: Verdict| None;
        for verdict in [Verdict::Off, Verdict::On, Verdict::Indeterminate] {
            let settled = settle_for(verdict, check, &reading, never, None, Some(&capped), &[]);
            assert_eq!(settled.verdict, Verdict::Indeterminate, "{verdict:?}");
            assert_eq!(
                settled.gating.map(|g| g.rule),
                Some(report::gating_rule::RUN_OUTPUT_UNREADABLE),
                "{verdict:?}"
            );
        }
        let settled = settle_for(
            Verdict::ProbeInvalid,
            check,
            &reading,
            never,
            None,
            Some(&capped),
            &[],
        );
        assert_eq!(settled.verdict, Verdict::ProbeInvalid);
        assert!(settled.gating.is_none());

        let whole = null_check_run("null-check=deleted");
        let settled = settle_for(
            Verdict::Off,
            check,
            &reading,
            never,
            None,
            Some(&whole),
            &[],
        );
        assert_eq!(
            settled.verdict,
            Verdict::Off,
            "a whole stream earns its verdict"
        );
        assert!(settled.gating.is_none());
    }

    #[test]
    fn a_killed_run_names_the_deadline_it_hit() {
        let check = check_named("no-delete-null-pointer-checks");
        let mut killed = null_check_run("");
        killed.timed_out = true;
        killed.exit_status = -1;
        killed.signal = Some("SIGKILL".to_owned());
        let indeterminate = Detection {
            outcome: probe::Outcome::Indeterminate,
            level: None,
            observed: String::new(),
            rule: None,
        };
        let never = |_: Verdict| None;
        let settled = settle_for(
            Verdict::Indeterminate,
            check,
            &indeterminate,
            never,
            None,
            Some(&killed),
            &[],
        );
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled.gating.expect("the deadline is the cause");
        assert_eq!(gating.rule, report::gating_rule::RUN_DEADLINE_ELAPSED);
        assert!(
            gating.reason.contains("5000 ms deadline"),
            "{}",
            gating.reason
        );

        let mut exited_in_window = killed.clone();
        exited_in_window.signal = Some("SIGSEGV".to_owned());
        let settled = settle_for(
            Verdict::Indeterminate,
            check,
            &indeterminate,
            never,
            None,
            Some(&exited_in_window),
            &[],
        );
        assert!(
            settled.gating.is_none(),
            "the segfault is the detector's to name"
        );

        let absent = Detection {
            outcome: probe::Outcome::Absent,
            level: None,
            observed: String::new(),
            rule: None,
        };
        for verdict in [Verdict::Off, Verdict::On] {
            let settled = settle_for(verdict, check, &absent, never, None, Some(&killed), &[]);
            assert_eq!(settled.verdict, Verdict::Indeterminate, "{verdict:?}");
            assert_eq!(
                settled.gating.map(|g| g.rule),
                Some(report::gating_rule::RUN_DEADLINE_ELAPSED),
                "{verdict:?}"
            );
        }
        let settled = settle_for(
            Verdict::ProbeInvalid,
            check,
            &absent,
            never,
            None,
            Some(&killed),
            &[],
        );
        assert_eq!(
            settled.verdict,
            Verdict::ProbeInvalid,
            "its controls name the cause"
        );
        assert!(settled.gating.is_none());

        // On every arm, a killed run's reading is replaced before the triple sees it.
        let mut killed_deleted = killed.clone();
        killed_deleted.stdout = "null-check=deleted".to_owned();
        let mut v = blank_variant();
        v.build = Some(variant_build(0, true));
        v.run = Some(killed_deleted);
        let d = reading(check, &v).detection;
        assert_eq!(d.outcome, probe::Outcome::Indeterminate);
        assert!(d.observed.contains("5000 ms deadline"), "{}", d.observed);

        // A probe that exited cleanly in the window is read.
        let mut finished = null_check_run("null-check=deleted");
        finished.timed_out = true;
        v.run = Some(finished.clone());
        let d = reading(check, &v).detection;
        assert_eq!(d.outcome, probe::Outcome::Absent, "{}", d.observed);
        let settled = settle_for(
            Verdict::Off,
            check,
            &absent,
            never,
            None,
            Some(&finished),
            &[],
        );
        assert_eq!(settled.verdict, Verdict::Off);
        assert!(settled.gating.is_none());
    }

    #[test]
    fn settling_never_manufactures_a_measurement_over_the_whole_domain() {
        let checks: Vec<&'static Check> =
            probe::CORPUS.iter().flat_map(|p| p.checks.iter()).collect();
        let plain = elf_with_report("");
        let mut truncated = elf_with_report("");
        truncated.truncations = vec![cut(
            elf::ElfTable::Dynamic,
            elf::TruncationKind::Unread,
            ".dynamic unreadable at entry 1 of 2 (offset 0x10)",
        )];
        let elves = [None, Some(&plain), Some(&truncated)];
        let whole = null_check_run("null-check=kept\n");
        let mut capped = whole.clone();
        capped.output_truncated = true;
        let mut unreadable = whole.clone();
        unreadable.output_error = Some("read failed".to_owned());
        let mut killed = whole.clone();
        killed.timed_out = true;
        killed.signal = Some("SIGKILL".to_owned());
        let runs = [
            None,
            Some(&whole),
            Some(&capped),
            Some(&unreadable),
            Some(&killed),
        ];
        let forged = [Vec::new(), vec!["-D__SSP_STRONG__=3".to_owned()]];
        let outcomes = [
            probe::Outcome::Present,
            probe::Outcome::Absent,
            probe::Outcome::Indeterminate,
        ];
        let (mut settled_calls, mut gated) = (0usize, 0usize);
        for &check in &checks {
            let levels = [
                None,
                Some("bogus".to_owned()),
                check.recommended_level().map(str::to_owned),
            ];
            let levels = &levels;
            for (&decided, outcome, level) in Verdict::ALL.iter().flat_map(|v| {
                outcomes
                    .iter()
                    .flat_map(move |o| levels.iter().cloned().map(move |l| (v, *o, l)))
            }) {
                let reading = Detection {
                    outcome,
                    level,
                    observed: String::new(),
                    rule: None,
                };
                for &elf in &elves {
                    artifact_gate_holds(decided, check, outcome, elf);
                    for (&run, flags, declares) in runs.iter().flat_map(|r| {
                        forged
                            .iter()
                            .flat_map(move |f| [false, true].map(move |d| (r, f, d)))
                    }) {
                        settled_calls += 1;
                        gated += usize::from(settles_through_its_rule(
                            decided, check, &reading, elf, run, flags, declares,
                        ));
                    }
                }
            }
        }
        assert!(checks.len() >= 50, "the corpus is {} checks", checks.len());
        assert!(
            gated > 0 && gated < settled_calls,
            "{gated} of {settled_calls} settled through a rule"
        );
    }

    /// `artifact_gating` at one point of the domain: a verdict only through its rule, never
    /// a measurement, and never over the toolchain's own `unsupported`.
    fn artifact_gate_holds(
        decided: Verdict,
        check: &'static Check,
        outcome: probe::Outcome,
        elf: Option<&elf::ElfFacts>,
    ) {
        if let Some((verdict, gating)) = gating_for(decided, check, outcome, elf) {
            assert_eq!(
                verdict,
                gating.rule.verdict(),
                "{}: {}",
                check.id,
                gating.rule.id
            );
            assert!(
                !verdict.is_measurement(),
                "{}: an artifact gate published {verdict:?}",
                check.id
            );
            assert_ne!(
                decided,
                Verdict::Unsupported,
                "{}: an artifact gate overwrote unsupported",
                check.id
            );
        }
    }

    /// `settle` at one point of the domain, held to its properties; `true` when a rule
    /// settled it.
    fn settles_through_its_rule(
        decided: Verdict,
        check: &'static Check,
        reading: &Detection,
        elf: Option<&elf::ElfFacts>,
        run: Option<&runner::RunRecord>,
        flags: &[String],
        declares: bool,
    ) -> bool {
        let declared = move |_: Verdict| {
            declares.then(|| report::Gating {
                rule: report::gating_rule::LIBC_DECLARED,
                arch: None,
                libc: Some("test".to_owned()),
                needs_vm: false,
                reason: "declared".to_owned(),
            })
        };
        let settled = settle_for(decided, check, reading, declared, elf, run, flags);
        let at = || {
            format!(
                "{} {decided:?} {:?} {:?} elf={} run={} flags={flags:?} declared={declares}",
                check.id,
                reading.outcome,
                reading.level,
                elf.is_some(),
                run.is_some()
            )
        };
        match &settled.gating {
            Some(g) => assert_eq!(settled.verdict, g.rule.verdict(), "{}: {}", at(), g.rule.id),
            None => assert_eq!(
                settled.verdict,
                decided,
                "{}: a verdict moved with no rule",
                at()
            ),
        }
        if settled.verdict.is_measurement() {
            assert_eq!(
                settled.verdict,
                decided,
                "{}: a rule published a measurement",
                at()
            );
        }
        settled.gating.is_some()
    }
}
