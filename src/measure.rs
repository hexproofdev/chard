// SPDX-License-Identifier: BSD-3-Clause

//! The measurement loop: build a probe, validate the detector, decide a verdict.
//!
//! This is the code every chard number passes through, and it lives in the library where a
//! test can reach it. Behind `fn main`, the control-triple wiring, the coverage denominator
//! and the profile-versus-control distinction would each be verifiable only by running a
//! sweep and reading the output.
//!
//! The sequence is deliberately kept whole. `run_check` reads top to bottom — gather the
//! bare evidence, force the flag on, force it off, decide, record — because the control
//! triple is the thing a reader most needs to audit in one place, and scattering it
//! across small helpers is how it silently stops being a triple.
//!
//! ## The distinction this loop exists to preserve
//!
//! Two builds answer two different questions. `clean` carries no profile and no control
//! flags beyond the target and runtime the profile selects ([`clean_flags`]); it is the
//! reference against which the controls establish that the *detector works on this
//! toolchain*, which must not depend on the profile under test. `measured` carries the
//! profile and is the thing being reported on.
//!
//! Conflating them is not hypothetical. Controls built on top of the profile, measuring
//! Fedora's `%build_cflags` (which injects hardening through
//! `-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1`), produce nine `probe-invalid`
//! verdicts. A spec file cannot be switched off by a later flag, so every negative
//! control still shows the observable and the harness concludes its own detectors are
//! broken. They are fine; the question is wrong.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};

use crate::compile;
use crate::elf;
use crate::env::Environment;
use crate::error::UserError;
use crate::probe::{self, Channel, Check, Detection, Evidence, Lang, Probe};
use crate::report::{
    self, Applicability, Diagnostic, EvidenceOut, Observation, Profile, Severity, Variant, Verdict,
};
use crate::run as runner;
use crate::toolchain::{self, Detected};

/// What a probe's measurement produced: its observations, and anything about the run
/// that is not attributable to a single check.
pub struct ProbeOutcome {
    pub observations: Vec<Observation>,
    /// The artifacts and dumps the observations and their arms reference, for the
    /// report's `facts`. See [`report::FactStore`].
    pub facts: report::FactStore,
    pub diagnostics: Vec<Diagnostic>,
}

/// A probe's share of the report's [`report::FactStore`] while it is measured, and every
/// entry the store refused.
///
/// A refusal is a second, different entry offered under a digest the store holds, which
/// is chard's reading of one sequence of bytes disagreeing with itself.
/// [`measure_probe`] publishes each one as an error diagnostic naming both entries, and the
/// store keeps the first.
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
pub struct Conditions<'a> {
    pub env: &'a Environment,
    pub profile: &'a Profile,
    pub toolchain_kind: toolchain::Kind,
    /// The architecture the toolchain compiles for under this profile
    /// (`toolchain::gate_target`: the target the profile's flags select, as the dump under
    /// them names it, and otherwise `Detected::target_arch`, falling back to
    /// `env.kernel.arch` when `-dumpmachine` gave no triple chard read) — what
    /// arch-gated checks (CET, GCS, branch-protection) gate on. Deliberately not
    /// `env.kernel.arch` read again here: that is the architecture chard's own binary
    /// was compiled for, which is the wrong question under cross-compilation.
    pub target_arch: &'a str,
    /// With no profile flags the measured build *is* the clean build, so there is
    /// nothing to gain from compiling it twice — and the regime-matched negative arm
    /// would duplicate the profile-free one.
    pub profile_is_clean: bool,
}

impl Conditions<'_> {
    /// Whether the profile adds anything to a bare build.
    /// `cxxflags` counts, and its absence here was a false `off`. A profile whose C
    /// flags and linker flags are empty while its C++ flags are not — reachable through
    /// `--profile explicit --flags '' --cxxflags '-D_LIBCPP_HARDENING_MODE=...'`, which
    /// is how a distribution that hardens only its C++ builds would be measured — was
    /// read as clean, so no measured build was compiled, every C++ check was decided
    /// over a flag-free artifact, and the report published `off` beside the very
    /// `profile.cxxflags` it had not applied. The control arms are profile-free by
    /// design, so they discriminated perfectly and stamped the cell as trustworthy.
    pub fn profile_is_clean(profile: &Profile) -> bool {
        profile.cflags.is_empty() && profile.cxxflags.is_empty() && profile.ldflags.is_empty()
    }
}

/// Flags for the measured variant: the profile, plus anything appended after it
/// so that it wins.
///
/// A C++ probe is built with the profile's CXXFLAGS when the distribution keeps a
/// separate set, and with CFLAGS otherwise. Building it with CFLAGS unconditionally
/// asked the wrong question wherever the two differ, which on both dpkg and abuild is
/// precisely where the C++ hardening lives — see [`Profile::cxxflags`].
pub fn variant_flags(profile: &Profile, lang: Lang, extra: &[&str]) -> Vec<String> {
    let base = match lang {
        Lang::Cxx if !profile.cxxflags.is_empty() => &profile.cxxflags,
        _ => &profile.cflags,
    };
    let mut flags = base.clone();
    flags.extend(profile.ldflags.iter().cloned());
    flags.extend(extra.iter().map(|s| (*s).to_owned()));
    flags
}

/// Flags for a control arm: the control's own flags and nothing else.
///
/// Controls are deliberately profile-free. Every control in the corpus is written
/// to be self-sufficient for this reason — the fortify controls carry their own
/// `-O2`, for instance, because fortify is inert without optimization and a
/// control that silently did nothing would invalidate the check it was meant to
/// validate.
pub fn control_flags(extra: &[&str]) -> Vec<String> {
    extra.iter().map(|s| (*s).to_owned()).collect()
}

/// Flags for one control arm of `check`: the control's own, and, when the check reads a
/// link or what it produced, the linker selection the profile's link line makes.
///
/// The profile-free rule is about what hardens the build, and a linker is not that. A
/// `-fuse-ld=lld` profile's measured build linked with ld.lld while both controls linked
/// with the driver's default: measured on 2026-09-28 on Fedora 44 aarch64 (clang 22.1.8,
/// `--profile explicit` with ldflags `-fuse-ld=lld`), `no-copy-dt-needed` read `on` with
/// no gating over a triple whose positive control quoted GNU ld's stderr, so the triple
/// validated the detector on a linker the cell never used. Carrying the selection makes
/// the triple and the measured build share a linker. That record's check,
/// `no-copy-dt-needed`, reads the linker's own stderr through the compiler-diag channel,
/// so the diag arms carry the selection too: every probe build links, so the flag is used
/// rather than reported unused. Macro checks keep the bare control flags, since the dump
/// they read links nothing.
///
/// Every arm, on every channel, also carries the target selection the profile makes
/// ([`crate::toolchain::target_selecting_flags`]), ahead of the linker's, because a
/// target is not hardening either and the triple has to validate the detector on the
/// target the measured build was compiled for. Measured on 2026-09-30 in a Fedora 44 x86_64
/// container with glibc-devel 2.43-8.fc44.i686, whose i386 `crt1.o`, `crti.o` and `crtn.o`
/// carry no x86 feature note, with the arms of a `-m32` profile on an x86_64 driver built for
/// x86_64: `cet-marked` read `off` under `-m32 -fcf-protection=full` for gcc 16.2.1 and
/// clang 22.1.8 over a triple whose positive control was an x86_64 program linked against
/// marked startup objects, beside `cet-marked-object` `on`. Where the arms are built for the
/// target, the positive arm's link drops the marking its object carries and the cell reads
/// `unsupported`, its `gating.rule` `link-drops-marking` over the triple's
/// `positive-silent`, as it is in a native i386 userspace. The same rule means a check
/// with no negative control of its own builds its negative arm with the selection rather
/// than letting the clean build stand in, and the clean build carries the selection too
/// ([`clean_flags`]).
///
/// The selection includes the system root (`--sysroot`, `-isysroot`), which chooses the C
/// library a fixed target builds against, and the library search directories (`-L`) beside
/// it (the spellings and the cross gcc measurement are at
/// [`crate::toolchain::target_selecting_flags`]). Measured on 2026-09-30 on Fedora 44 x86_64
/// with clang 22.1.8 and roots extracted from the `almalinux:9` image (glibc 2.34) and the
/// `debian:12` one (glibc 2.36), with no root on the arms: the measured build read the root's
/// `__GLIBC_MINOR__` while every arm and the clean build read the host's 43 (glibc 2.43).
/// Under `-D_FORTIFY_SOURCE=3` the measured `fortify-level-ge-2-subobject` build did not
/// abort on glibc 2.34 against a positive control that aborted on 2.43, and the ratchet,
/// finding level 3 enforced above an unenforced level 2, withheld all four fortify rungs;
/// under the Debian 12 root, whose startup objects carry no x86 feature note, `cet-marked`
/// read `off` with `-fcf-protection=full` over a positive control linked against the
/// host's marked ones. With the root on the arms the first reads `unsupported` under
/// `subobject-bound-lost-in-wrapper` and the ratchet publishes level 3; the second reads
/// `unsupported` under `link-drops-marking`. The figures are in the project ledger.
///
/// Every arm, on every channel, carries the runtime selection too
/// ([`crate::toolchain::runtime_selecting_flags`]: the C++ standard library, the compiler
/// runtime and the resource directory it is read from, the unwinder, and the GCC
/// installation and triple), after the target's and ahead of the linker's. Measured on
/// 2026-10-05 on Fedora 44 x86_64 with clang 22.1.8 and no runtime selection on the arms,
/// under `--profile explicit` with `--gcc-install-dir=` a copy of the gcc 16.1.1 install
/// directory whose `crtbegin*.o` carried no x86 feature note, and `-fcf-protection=full`,
/// `cet-marked` read `off` over a positive control linked against the host's marked
/// `crtbeginS.o`. With the selection on the arms the positive arm's link drops the marking
/// as the measured build's does, and the cell reads `unsupported` under
/// `link-drops-marking`; `shadow-stack-enforced`, whose positive arm had run under an
/// enforced shadow stack that the measured build's startup objects could not have asked
/// for, read `off` without the selection and reads `probe-invalid` with it, that arm
/// silent. `--gcc-triple=` and `-resource-dir` are taken after the same reading under each,
/// measured 2026-10-06 (the measurement is at
/// [`crate::toolchain::runtime_selecting_flags`]). The macro arms carry the selection
/// because the C++ library, the GCC installation and the resource directory choose the
/// headers a dump reads; a C dump under `-stdlib=` or `--rtlib=` draws clang's "argument
/// unused" warning, as the measured build's does.
///
/// The selection includes the `-B` and `--prefix` prefixes, clang's `-ccc-install-dir` and
/// default configuration directories, and the static or shared forms of the runtime
/// libraries; the measurements, of 2026-10-06, are at
/// [`crate::toolchain::runtime_selecting_flags`]. `-B` reaches the arms that link as the
/// linker selection's, and the macro arms because gcc reads headers from the prefix; an arm
/// that links takes the linker's program flags ([`crate::toolchain::linker_program_flags`])
/// beside it, so it carries the prefix once.
///
/// Every arm of a check that reads the measured build, on every channel, carries the header
/// selection too ([`crate::toolchain::header_selecting_flags`]: the profile's own `-I`,
/// `-isystem`, `-idirafter`, `-iquote`, `-include`, `-imacros`, `-undef` and `-pthread`),
/// after the runtime's and ahead of the linker's; the arms of a check that reads the clean
/// build ([`Check::measures_toolchain_default`]) carry none, as that build carries none. A
/// header the profile selects is the runtime argument once more: it hardens nothing, and a
/// triple compiled against other headers validates the detector on another compile, which
/// the compile listing comparison ([`crate::compile_inputs`]) saw and withheld on. Without
/// the selection a profile carrying any of those words withholds every check in
/// `report::COMPILE_INPUT_READINGS` under `compile-inputs-unmatched-by-arms`: measured on
/// Fedora 44 x86_64, `--profile explicit --flags "-O2 -I/usr/include -pthread
/// -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE" --ldflags "-pie -pthread"` withholds
/// 17 of 72 without the selection under gcc 16.1.1 and clang 22.1.8 alike, over triples that
/// discriminated, and publishes 12 of them with it, the other five withheld under
/// `macro-supplied-by-profile` by the directory clauses below. The macro arms carry the
/// selection because a search directory, a forced include and `-undef` are what a dump reads. A
/// carried header acts on every arm as it acts on the measured build, unless its effect
/// turns on a macro only one build defines. In the first case the worst outcome is a triple
/// it silences (`probe-invalid`), never a wrong `off`. In the second the arms carry the
/// header and neither the profile's macro words nor its hardening flags, so they read it as
/// inert and the triple reads the build the profile makes: `off` where that build has no
/// request, and a forged reading where the header defines or undefines a macro the compiler
/// reserves for its own account, which the verdict layer holds for a check with an artifact
/// twin (`macro-contradicted-by-artifact`, [`crate::report::MACRO_TWINS`]) and the spoof
/// clause holds for the two without, `optimization-enabled` and `fortify-effective`
/// ([`crate::report::MACRO_WITHOUT_TWIN`]), wherever the list selects a header search
/// directory or carries a forced include or another input it cannot read by name
/// ([`twinless_unread_input`] has the measurement)
/// ([`crate::toolchain::header_selecting_flags`] has the argument and the shapes held). The
/// default-asking arms stand on the footing of the build they vouch for,
/// which carries no header word ([`clean_flags`] says why): with the selection on them (the
/// guard below removed), the assembly probe's arms under `-include /usr/include/stdio.h`
/// fail on the assembler's errors and `linker-default-noexecstack` reads `probe-invalid`
/// over `positive-unevaluable`, where with the guard the check reads `on` as under `-O2`
/// alone (Fedora 44 x86_64, gcc 16.1.1).
/// [`stand_in_selection`] is the same selection for the listing comparison, and
/// `tests::the_stand_in_selection_is_what_the_arms_carry` holds the two to each other.
pub fn arm_flags(check: &Check, profile: &Profile, lang: Lang, extra: &[&str]) -> Vec<String> {
    let line = variant_flags(profile, lang, &[]);
    let mut flags = crate::toolchain::target_selecting_flags(&line);
    flags.extend(crate::toolchain::runtime_selecting_flags(&line));
    if !check.measures_toolchain_default {
        flags.extend(crate::toolchain::header_selecting_flags(&line));
    }
    if check.channel() != Channel::Macro {
        flags.extend(crate::toolchain::linker_program_flags(&line));
    }
    flags.extend(control_flags(extra));
    flags
}

/// Flags for the clean build: the target and system root the profile selects, with the
/// library search directories (`-L`) beside it ([`crate::toolchain::target_selecting_flags`]),
/// then the runtime it selects ([`crate::toolchain::runtime_selecting_flags`]), and nothing
/// else.
///
/// The clean build is what a check asking for the toolchain's default reads
/// ([`Check::measures_toolchain_default`]), and what a check with no negative control of
/// its own would stand in for that arm, so it is built for the same target as the arms
/// ([`arm_flags`]) and the measured build. A clean build with no flags at all, under `-m32`
/// on an x86_64 driver, gives `linker-default-noexecstack` an `EM_X86_64` link while its
/// arms, which carry `-m32`, are `EM_386`: reproduced on 2026-09-30 in `ubuntu:22.04` (gcc
/// 11.4.0, clang 14.0.0) and `fedora:44` (gcc 16.2.1, clang 22.1.8) containers on a Fedora
/// 44 x86_64 host, where the check published `off` and `on` respectively, each over a triple
/// claiming a target its artifact did not have. The linker's program flags are left off:
/// that the clean build links with the driver's default linker is what
/// [`artifact_comments`] marks `profile_free`. The runtime selection is carried for the
/// reason [`arm_flags`] gives: a default read against startup objects or a C++ library the
/// profile does not build with is another toolchain's default. That includes the `-B` and
/// `--prefix` prefixes, so the clean build runs the programs a prefix holds, its linker
/// among them, and a profile selecting by prefix alone does not mark the clean artifact
/// `profile_free`.
///
/// The header selection ([`crate::toolchain::header_selecting_flags`]), which every arm of
/// a check that reads the measured build carries, is not carried here. A header word is a
/// compile input the profile adds, not a
/// choice of which toolchain answers, and the checks that read the clean build
/// ([`Check::measures_toolchain_default`]) ask the linker's default of an assembly probe,
/// `linker_default_execstack.S`, which a forced C include cannot build: measured on Fedora
/// 44 x86_64 with gcc 16.1.1 with the selection added here (one line,
/// [`crate::toolchain::header_selecting_flags`] beside the runtime's), `--profile explicit
/// --flags "-O2 -include /usr/include/stdio.h"` reads `linker-default-noexecstack`
/// `build-failed` over the assembler's errors on `stdio.h`, where without it the check
/// reads `on` as under `-O2` alone. The default-asking checks are the assembly probe's alone, and
/// `tests::the_default_asking_checks_are_the_assembly_probes` holds the two together, and
/// `tests::a_default_asking_checks_arms_carry_no_header_word` holds [`arm_flags`]' guard. A check with no negative
/// control of its own does not lose the selection by this: its negative arm is built with
/// the selection alone rather than stood in for by the clean build, as under a linker
/// selection ([`arm_flags`]). The compile listing comparison adds the selection to its
/// stand-in beside these flags ([`unmatched_compile_inputs`]).
pub fn clean_flags(profile: &Profile, lang: Lang) -> Vec<String> {
    let line = variant_flags(profile, lang, &[]);
    let mut flags = crate::toolchain::target_selecting_flags(&line);
    flags.extend(crate::toolchain::runtime_selecting_flags(&line));
    flags
}

/// Builds and runs probe variants with one toolchain, in one work directory.
///
/// **One child at a time, and that is load-bearing.** The obvious lever on a sweep of
/// ~5,000 invocations is to run them concurrently, and it is deliberately not taken: the
/// `runtime` channel reads how a probe died and both records publish a `duration_ms`, so
/// parallel compiles would perturb the measurement rather than merely the schedule.
/// `compile::tests::one_child_runs_at_a_time_and_its_spawner_waits_for_it` holds it as a
/// reading of the source: no concurrency word in `src/` beyond an allowlist of named sites,
/// and each process spawn bound once, outside any loop, and waited for in its own function
/// in text order. Its doc comment lists what that reading does not see.
///
/// What makes the assumption easy to break silently is that nothing else objects to it.
/// Each variant's artifact and capture filenames are keyed on `{probe.id}-{tag}` and probe
/// sources are written once before the sweep, but auxiliary libraries are not:
/// `build_aux_libs` writes each `AuxLib`'s source and links `lib{stem}.so` at the same
/// names in the work directory for every variant, with the arm's target and linker
/// selection, so two `copy-dt-needed` variants built at once would overwrite each other's
/// dependency chain. The timing fields would degrade with no error; a `--jobs` pool built
/// from threads, async tasks or a spawning loop makes the test named above fail. If depth
/// ever rises, the timing fields and the auxiliary library paths are what has to be
/// re-derived first.
pub struct Driver<'a> {
    /// The detected half of the toolchain, which is all measurement reads: the driver
    /// paths. The join key lives on the published `toolchain::Toolchain`, and a loop
    /// that does not need it cannot depend on it having been composed.
    pub toolchain: &'a Detected,
    pub workdir: &'a Path,
    pub timeout: Duration,
    /// The flag for the structured-diagnostics side build, when
    /// `--structured-diagnostics` is on and this toolchain has a structured form. `None`
    /// builds nothing extra. See [`crate::structured`].
    pub structured: Option<&'static str>,
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

    /// Build a probe's `aux_libs` in order, returning the first failed record if any.
    ///
    /// Fixed flags, not the arm's, beyond its target and linker selection
    /// ([`aux_lib_flags`]): `-shared -fPIC` and the library's own `-l` arguments,
    /// plus a `-soname` so the dependent library records the name a loader would search
    /// for rather than the absolute path it happened to be built at. The flag under test
    /// belongs to the final link alone — applying it here would change the shape of the
    /// chain instead of how the last link is allowed to traverse it, and the two arms
    /// would then differ in more than the one thing being measured.
    ///
    /// Rebuilt per variant rather than cached. They are cheap, and a cache would have to
    /// know which arms may share one — the kind of bookkeeping that produced the stale
    /// artifact `compile::build` now clears the output path to prevent.
    fn build_aux_libs(
        &self,
        probe: &Probe,
        driver: &std::path::Path,
        arm: &[String],
    ) -> Result<Option<compile::BuildRecord>> {
        for aux in probe.aux_libs {
            let source = self.workdir.join(aux.source_name);
            std::fs::write(&source, aux.source)
                .with_context(|| crate::error::HarnessPath(source.clone()))
                .context("writing the auxiliary library source")?;
            let artifact = self.workdir.join(format!("lib{}.so", aux.stem));
            let flags = aux_lib_flags(arm, aux.stem, self.workdir);
            let record = compile::build(driver, &flags, &source, &artifact, aux.link_libs)?;
            if aux_build_failed(&record) {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// The same build again with the compiler's SARIF on stderr, decoded, for a probe with
    /// a check the structured decoder reads; `None` when the gate is off or the probe has
    /// no such check.
    ///
    /// A separate build rather than a flag on the arm's own, so the stream the prose decoder
    /// reads is untouched, and to its own output path, so the arm's artifact is too. A side
    /// build that cannot be run is recorded as undecodable rather than propagated: the gate
    /// must not cost a probe its verdicts.
    fn structured_capture(
        &self,
        probe: &Probe,
        driver: &Path,
        flags: &[String],
        source: &Path,
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
        let record = compile::build(driver, &side, source, &out, probe.link_libs);
        Some(crate::structured::Capture::of(
            flag,
            record.as_ref().map_err(|e| format!("{e:#}")),
        ))
    }

    /// Build (and if needed run) one variant, collecting whatever evidence the
    /// probe's channels require.
    ///
    /// # Errors
    ///
    /// Errors when the compiler cannot be invoked or the work directory is unusable.
    pub fn gather(&self, probe: &Probe, flags_in: &[String], tag: &str) -> Result<Variant> {
        let driver = self.driver_for(probe.lang)?;
        let needs_macros = probe.checks.iter().any(|c| c.channel() == Channel::Macro);

        // `tag` names the variant only ("clean", "measured", "<check>-pos"); the
        // probe id is prefixed here so retained evidence filenames read as
        // `link-defaults-clean` rather than repeating the probe twice.
        let qualified = format!("{}-{tag}", probe.id);

        // The dump's own record is kept beside its output. It was discarded here, so a
        // macro-channel cell carried no command a reader could re-run, and a dump that
        // exited non-zero after printing most of its defines read as a clean one.
        // `Variant::sufficient_for` reads the exit status off this record.
        let (macros_preprocessor, macro_dump) = if needs_macros {
            let (macros, record) =
                compile::macro_dump(driver, probe.lang, flags_in, true, self.workdir, &qualified)?;
            (macros, Some(record))
        } else {
            (BTreeMap::new(), None)
        };

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
            artifact: None,
            structured: None,
            workdir: Some(self.workdir.to_path_buf()),
        };
        if !probe.needs_build() {
            return Ok(variant);
        }

        // The probe's own dependency chain, before its link. A failure here is a harness
        // fault rather than a measurement: the scaffolding is fixed, so if it will not
        // build, nothing downstream can be read as a property of the flag under test.
        // Recorded as the probe's build record so the check reports `build-failed` with
        // the driver's own words, instead of a verdict drawn from an absent artifact.
        if let Some(failed) = self.build_aux_libs(probe, driver, flags_in)? {
            variant.build = Some(failed);
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
        // Drop flags that cannot coexist with this output kind, then append the flags
        // that produce it, which means a profile written for executables does not fail
        // to link a library probe.
        //
        // `extra_flags` sees what survived the filter, because `-fPIC` is a default and
        // must not overwrite an explicit `-fno-pic` from a control or an operator: the
        // appended flag would win, and the report would name a flag list it did not
        // measure.
        let (flags_in, dropped) = probe.link_mode.partition_flags(flags_in);
        let mut flags = flags_in;
        let produced = probe.link_mode.extra_flags(&flags);
        flags.extend(produced.iter().map(|s| (*s).to_owned()));
        // Where the chain was built, and where the linker must look to *follow* it.
        // `-rpath-link` is not optional: without it the transitive library cannot be
        // found in either arm, both fail identically, and a flag that works perfectly
        // reads as a control that could not discriminate.
        flags.extend(chain_search_flags(probe, self.workdir));
        let mut build = compile::build(driver, &flags, &source, &artifact, probe.link_libs)?;
        variant.structured = self.structured_capture(probe, driver, &flags, &source, &qualified);
        // What the filter removed, carried into the record. `profile.cflags` names the list
        // the operator gave; without this, a build that used a different one says so
        // nowhere, and the resolution is indistinguishable from a harness bug.
        build.dropped_flags = dropped;
        let build = build;
        // Exited 0 and wrote nothing. `compile::build` clears the path first, so this is
        // now distinguishable from a build that produced something, and both the ELF read
        // and the run are skipped rather than reaching for a file that is not there.
        //
        // Kept separate from the unreadable-artifact case below: "no artifact" and "an
        // artifact this reader does not understand" are different facts, and conflating
        // them would report a Mach-O binary and a `-fsyntax-only` invocation the same way.
        // `-fsyntax-only` is the honest instance — a caller can ask for it through
        // `--profile explicit` — and a wrapper that swallows `-o` is the hostile one.
        let produced_artifact = build.artifact_sha256.is_some();
        if build.succeeded() && produced_artifact {
            variant.artifact = Some(artifact.clone());
            // A build that succeeds but produces an unreadable artifact is a
            // harness problem, not a measurement: record it as missing evidence
            // so the check reports build-failed rather than a verdict. The reason
            // is kept rather than dropped by `.ok()`, because `build-failed` beside
            // an `exit_status: 0` build record is a contradiction a reader cannot
            // resolve without it.
            match elf::facts_for(&artifact) {
                Ok(facts) => variant.elf = Some(facts),
                Err(e) => variant.elf_error = Some(report::ArtifactRefusal::of(&e)),
            }
            // Prefer what the compiler believed over what a separate preprocessor
            // job reported. `-dM -E` is driven by *cpp_options and code generation
            // by *cc1_options, so a spec file patching one and not the other makes
            // them disagree — and the artifact is the side that matters.
            // Read whenever the artifact carries one, and *not* gated on `needs_macros`:
            // that flag exists to skip the expensive `cc -dM -E` job, and the self-report
            // is bytes already parsed out of an artifact already read. Gating both on one
            // condition meant a runtime-channel probe's arms carried no account of
            // themselves at all, which is what left `fortify_level_declined` unable to
            // read `__USE_FORTIFY_LEVEL` off the very arm that had just been built with
            // the flag forced on.
            // The one reading of the section (`report::self_report_entries`): the artifact's
            // macros replace the dump's exactly when the artifact gave an account, a report
            // whose fields all read undefined included (an empty map, the artifact's word that
            // nothing is defined). Where the artifact carries no report the dump stays the
            // witness, the probe's warning in `evidence_faults` says why, and a
            // macro-channel check over the artifact is withheld under
            // `artifact-lacks-self-report` (`report::self_report_limitation`) rather than
            // published from the dump. Keyed on the parsed map being non-empty, the
            // replacement would drop an all-`?` report for the dump.
            if let Some(facts) = variant.elf.as_ref()
                && let Ok(from_artifact) = report::self_report_entries(facts)
            {
                variant.macros = from_artifact;
                variant.macro_source = "compiled-artifact";
            }
            if probe.needs_run() {
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

const MACRO_WATCH: &[&str] = &[
    "__SSP__",
    "__SSP_STRONG__",
    "__SSP_ALL__",
    "__SSP_EXPLICIT__",
    "_FORTIFY_SOURCE",
    "__USE_FORTIFY_LEVEL",
    // Apple's own spelling of the settled level, single leading underscore.
    "_USE_FORTIFY_LEVEL",
    // FreeBSD's, from `<ssp/ssp.h>`.
    "__SSP_FORTIFY_LEVEL",
    "__ARM_FEATURE_BTI_DEFAULT",
    "__ARM_FEATURE_PAC_DEFAULT",
    "__ARM_FEATURE_GCS_DEFAULT",
    "__PIE__",
    "__PIC__",
    "__CET__",
    "__OPTIMIZE__",
];

/// The self-report's entries a library header settles from other inputs, which neither the
/// compiler nor a `-D` on the command line defines: the three fortify levels.
///
/// - `__USE_FORTIFY_LEVEL`: glibc's `<features.h>`, from `_FORTIFY_SOURCE`, `__OPTIMIZE__`
///   and the compiler's version.
/// - `_USE_FORTIFY_LEVEL`: Apple's `<secure/_common.h>`, from the same.
/// - `__SSP_FORTIFY_LEVEL`: FreeBSD's `<ssp/ssp.h>`, from `_FORTIFY_SOURCE`, `__OPTIMIZE__`,
///   the compiler and the language; and 15.1's `<sys/select.h>`, which settles 0 where no
///   request reached it.
///
/// The two views [`compare_macro_views`] holds to each other are two translation units:
/// the probe's own, with the headers its source includes, and the macros-only unit the dump
/// preprocesses (`compile::LIBC_PROBE_HEADERS`). A macro on this list that one view alone
/// carries is a header the other unit did not reach, not a job the spec file patched.
/// Measured on FreeBSD 15.1 amd64 (clang 19.1.7): under `bare` the C++ probe
/// `cxx-stdlib-assertions` self-reports `__SSP_FORTIFY_LEVEL=0`, settled by
/// `<sys/select.h>` on the way through `<vector>`, while its dump unit reaches no header
/// that settles it under no request and defines none. Compared, that pair reads as "the
/// compiler and the preprocessor disagree", the spec-file hazard; read that way, a fleet
/// sweep finds it in the FreeBSD 15.1 `bare` and `bare-optimized` cells and nowhere else
/// among the 287 of its 299 reports read (fleet sweep, 2026-10-29). Where both views
/// carry the macro and differ, the inputs the header read differ, and that is a
/// disagreement.
///
/// Why the list hides no split the hazard makes: a header settles each of these from inputs
/// that are themselves compared on presence and value (`_FORTIFY_SOURCE`, `__OPTIMIZE__`,
/// `__GNUC__`, `__GNUC_MINOR__`, `__clang_major__`) or shared by construction (the language,
/// since the dump is taken in the probe's language), so a spec file reaching one job and
/// not the other splits an input the comparison still names. Two shapes the uncompared note
/// cannot tell from a header the other unit did not reach, each published and neither
/// silent: a job-only header selection (an `-include`, `-nostdinc` or sysroot reaching one
/// job) that settles the level on one side, and a job-only `-D` of the level's own name,
/// which no compared input shows; the note's sentence says what the one-sided reading can
/// be, not which it was. `__GLIBC__` and `__GLIBC_MINOR__` are not here: `<features.h>`
/// defines them from nothing, so a one-sided reading of either is a header-selection split,
/// which the comparison names as a disagreement. `_GLIBCXX_ASSERTIONS` and
/// `_LIBCPP_HARDENING_MODE` are not here either: a header supplies a default for each, and a
/// `-D` on one job alone is the hazard proper, which a one-sided reading of either must
/// name. `COMPILER_DEFINED_MACROS` below classifies by who may define a name (the flag list
/// may not); this list classifies by who does.
///
/// Held by `every_header_defined_name_is_a_watched_read_entry_noted_on_either_side` to
/// exactly these three names, each a read entry of the self-report, watched where the dump
/// alone carries it ([`MACRO_WATCH`]) and kept in `evidence.macros`
/// ([`MACRO_EVIDENCE_KEEP`]); the FreeBSD shape itself is
/// `a_header_defined_macro_one_view_alone_carries_is_not_a_disagreement`.
const HEADER_DEFINED_MACROS: &[&str] = &[
    "__USE_FORTIFY_LEVEL",
    "_USE_FORTIFY_LEVEL",
    "__SSP_FORTIFY_LEVEL",
];

/// The self-report's entries that are chard's own summaries rather than macros.
///
/// `probes/chard_selfreport.h` writes every other entry from the macro of the same name,
/// and these two from a ladder over other macros (`_FORTIFY_IMPL` from the C library's
/// fortify guards, `_CXX_STDLIB` from the C++ library's version macro). No compiler and
/// no preprocessor defines either, so a dump never carries them, and comparing them
/// published `codegen=glibc cpp=<undefined>` beside a dump that ran, under a sentence
/// blaming a spec file. Of their inputs, `__USE_FORTIFY_LEVEL` and `_USE_FORTIFY_LEVEL`
/// are self-reported and compared. `_FORTIFY_HEADERS_H`, `__GLIBCXX__` and
/// `_LIBCPP_VERSION` are in neither the self-report nor [`MACRO_WATCH`], so a split
/// between the two views on one of them is not seen.
///
/// Held to the header by
/// `the_self_report_summaries_are_the_entries_the_header_derives`.
const SELF_REPORT_SUMMARIES: &[&str] = &["_FORTIFY_IMPL", "_CXX_STDLIB"];

/// A dump's value for a macro, followed through the dump's own definitions.
///
/// The self-report prints a macro's expansion (`CHARD__XSTR` expands its argument) and a
/// `-dM -E` dump prints its replacement text, so `_LIBCPP_HARDENING_MODE` reads `2` in
/// the one and `_LIBCPP_HARDENING_MODE_FAST` in the other wherever libc++'s headers
/// define the mode names. Followed object-like name by name, for at most as many steps as
/// the dump has definitions, so a cycle ends; a value that names no definition is the
/// expansion. Function-like and multi-token replacement lists are left as printed.
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

/// What comparing the compiled artifact's macros with the preprocessor dump found: the
/// macros the two views disagree about, and the header-defined macros one view alone
/// carries, which were not compared ([`HEADER_DEFINED_MACROS`]). Each entry is one macro,
/// `name: codegen=<value> cpp=<value>`.
#[derive(Debug, Default, PartialEq, Eq)]
struct MacroViews {
    disagreements: Vec<String>,
    header_one_sided: Vec<String>,
}

/// Where the compiled artifact's macros and the preprocessor dump disagree, one entry per
/// macro, or none where there is no second view to disagree with; beside them, the
/// header-defined macros one view alone carries, which are a difference of headers reached
/// rather than a disagreement, and are published as uncompared.
///
/// Two views exist only where the macros came from the artifact's self-report and a dump
/// ran beside it and was read. A probe with no macro-channel check takes no dump
/// (`Gatherer::gather`), and its empty map compared with the self-report would publish each
/// macro of every such probe whose artifact carries a self-report as `cpp=<undefined>`,
/// with no preprocessor job behind it. A dump that failed or
/// defined nothing is not compared either: its own diagnostic names the failure, and a
/// comparison against it is a comparison against nothing in particular
/// ([`Variant::macro_dump_failure`]).
///
/// A macro the artifact carries is compared whatever its name, and one the dump alone
/// carries only where chard watches it ([`MACRO_WATCH`]), since every build defines
/// thousands the self-report never mentions. On a header-defined name a one-sided reading
/// goes to `header_one_sided` instead of `disagreements`, on either side; a reading both
/// views carry is compared by value as any other.
fn compare_macro_views(bare: &Variant) -> MacroViews {
    let mut views = MacroViews::default();
    if bare.macro_source != "compiled-artifact"
        || bare.macro_dump.is_none()
        || bare.macro_dump_failure().is_some()
    {
        return views;
    }
    let cpp = &bare.macros_preprocessor;
    let header_defined = |name: &str| HEADER_DEFINED_MACROS.contains(&name);
    for (name, value) in &bare.macros {
        if SELF_REPORT_SUMMARIES.contains(&name.as_str()) {
            continue;
        }
        match cpp.get(name).map(|v| expanded_in_dump(cpp, v)) {
            Some(other) if other == value => {}
            Some(other) => views
                .disagreements
                .push(format!("{name}: codegen={value} cpp={other}")),
            None if header_defined(name) => views
                .header_one_sided
                .push(format!("{name}: codegen={value} cpp=<undefined>")),
            None => views
                .disagreements
                .push(format!("{name}: codegen={value} cpp=<undefined>")),
        }
    }
    for name in cpp.keys() {
        if MACRO_WATCH.contains(&name.as_str()) && !bare.macros.contains_key(name) {
            let entry = format!("{name}: codegen=<undefined> cpp=defined");
            if header_defined(name) {
                views.header_one_sided.push(entry);
            } else {
                views.disagreements.push(entry);
            }
        }
    }
    views
}

/// Macros the *compiler* defines to describe its own code generation.
///
/// A build system never defines these: they are reserved-namespace names gcc and clang
/// emit from their own state, and chard's self-report header reads them back out of the
/// compiled artifact to learn what the compiler did. `_FORTIFY_SOURCE` is deliberately
/// absent — defining it *is* the mechanism, which is why every distribution does.
///
/// A flag list that defines one of these is not configuring a compiler, it is answering
/// the question chard asked. Measured: `--flags '-D__SSP_STRONG__=3 -D__CET__=3
/// -D__PIE__=2'` moved `ssp-level`, `cet-macro` and `pie-macro` from `off` to `on` with
/// levels `strong`, `full` and `2`, and `discriminating: true` on all three, against a
/// binary carrying none of those protections. The control triple did not fail — forced
/// on showed the macro and forced off did not — because the controls test the detector,
/// and here the detector was working and the *input* was forged.
const COMPILER_DEFINED_MACROS: &[&str] = &[
    "__SSP__",
    "__SSP_STRONG__",
    "__SSP_ALL__",
    "__SSP_EXPLICIT__",
    "__USE_FORTIFY_LEVEL",
    // Listed for the same reason as glibc's spelling above, and it became necessary in
    // the same commit that made this macro decide `fortify-effective`: a macro a verdict
    // turns on has to be one the flag list cannot forge.
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
    // `exceptions-macro` turns on this one. Without it, on Fedora 44 x86_64 under gcc
    // 16.1.1 and clang 22.1.8 (2026-10-01, `--profile explicit`), `-D__EXCEPTIONS=1` read
    // the macro `on` beside `except-table-emitted` `off`, and `-U__EXCEPTIONS -fexceptions`
    // read it `off` beside a table that was emitted.
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
///
/// A flag list that defines or undefines one of these reaches the measured probe's own control
/// flow: `-D__CET__=3` under `-fcf-protection=none` makes `shadow_stack.c` and
/// `zero_call_used_regs.c` assemble landing pads the compiler never chose, `-D__OPTIMIZE__` at
/// `-O0` makes the five probes that print the optimiser's state tell their decoders it ran, and
/// `-D__clang__` under gcc makes `trapv.c` and `ub_signed_overflow.c` print `frontend=clang` and
/// the others choose clang's construct. The macro checks are withheld under
/// `macro-supplied-by-profile`; without this rule these are not, so a `-D` of a reserved name would
/// steer a runtime or artifact probe and only the macro check would say so.
/// [`settle_probe_branches`] withholds every elf-static, runtime and compiler-diag check of such a
/// probe under the same rule where the list defines a macro the probe branches on; a macro check of
/// the probe is the spoof clause's.
/// `every_probe_declares_the_reserved_macros_its_source_branches_on` derives each row from the
/// probe's source and holds the table to it, so a probe that gains or loses a branch moves the
/// table or fails the suite. The derivation holds two branches a grep of the nine C probes misses:
/// `cxx_assertions.cpp` prints `chard-opt=` from `__OPTIMIZE__`, and
/// `strict_flex_arrays_enforced.c` names its C library from `__FreeBSD__`, which is on the
/// compiler-defined list.
///
/// Read at the input layer, as `macro-supplied-by-profile` is: the spellings
/// `spoofed_macros` reads name the macro, and a preprocessor input the reader does not
/// read by name ([`unread_preprocessor_input`]: a forced include or macro file in any of
/// its spellings, a response file, a define handed to the
/// frontend) withholds the probe's checks too, since any of them can define or undefine
/// what the probe branches on; so does a measured compile whose driver listing differs
/// from the arms' (`compile-inputs-unmatched-by-arms`'s own comparison, handed in as
/// `unmatched_compile`), the carrier of a `-specs=` or `--config=` file's macro
/// operations. A header search directory the profile selects (`-I`, `-isystem`,
/// `-idirafter`, `-iquote`) withholds the probe's compile-input readings
/// (`report::COMPILE_INPUT_READINGS` holds three of them), since under it a header the
/// probe includes can be shadowed, keyed on a macro only the measured build defines, which
/// the arms, carrying the directory and never the macro words, read as inert; the listing
/// comparison withheld those three under any such directory until the arms carried it. A
/// shadow header under such a directory that steers the probe's other readings, or a wrapper
/// that adds a define to the measured build alone,
/// reaches the probe unseen here; the macro channel's twin rule (`report::MACRO_TWINS`)
/// holds the macro checks over those routes, and the runtime and artifact checks of these
/// probes have no twin to be held to, residuals `THREAT_MODEL.md` names.
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
    ("ub-signed-overflow", &["__OPTIMIZE__", "__clang__"]),
    ("ub-strict-aliasing", &["__OPTIMIZE__", "__clang__"]),
    ("ubsan-trap", &["__clang__"]),
    ("zero-call-used-regs", &["__CET__"]),
];

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

/// `macro-supplied-by-profile` over what [`settle`] left, for a check of a probe in
/// [`PROBE_MACRO_BRANCHES`] whose measured flag list defines or undefines a macro the
/// probe's source branches on: the program chard built and ran took the branch the list
/// chose, not the one the compiler's own state would have, so the reading measures the
/// list. The same rule and stage as the macro channel's spoof clause inside `settle`, which
/// reads the macro checks; this reads the probe's other channels, by probe. A check already
/// withheld by a declared rule, the triple or an artifact gate keeps that reason, as the
/// spoof clause leaves a declared rule standing: the rule says the list steered the probe,
/// which is true of a measurement and adds nothing to a withholding.
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
            "the flag list defines or undefines {} itself, and the source of the probe `{}` \
             branches on it, so the branch the program chard built and ran took may be the \
             list's rather than the compiler's own; the observation measures the flag list \
             and is withheld",
            spoofed.join(", "),
            probe.id
        )
    } else if unread_preprocessor_input(profile_flags) {
        format!(
            "the flag list carries a preprocessor input this rule does not read by name (a \
             forced include or macro file, in any of its spellings, a response file) \
             or hands a define to the frontend, and the source of the probe `{}` branches \
             on {}, which such an input can define or undefine, so the branch the program \
             chard built and ran took may be the list's rather than the compiler's own; the \
             observation is withheld",
            probe.id,
            names.join(", ")
        )
    } else if let Some(unmatched) = unmatched_compile {
        // The driver's `-###` listing for the measured compile names what a specs or
        // configuration file, or a header selection, added: a macro operation or a header
        // among them can define what the probe branches on, and the list never named it.
        format!(
            "the driver's listing for the measured compile differs from the arms' ({unmatched}), \
             and the source of the probe `{}` branches on {}, which a macro operation or a \
             header the listing names can define or undefine, so the branch the program chard \
             built and ran took may be the list's rather than the compiler's own; the \
             observation is withheld",
            probe.id,
            names.join(", ")
        )
    } else if report::COMPILE_INPUT_READINGS.contains(&check.id)
        && crate::toolchain::header_selecting_flags(profile_flags)
            .iter()
            .any(|w| crate::toolchain::selects_header_directory(w))
    {
        // Without the directory words on the arms, the listing comparison would withhold a
        // compile-input reading of such a probe under any header search directory. Under one
        // a header the probe includes can be shadowed, keyed on a macro only the measured
        // build defines, and the arms, carrying the directory and never the macro words, read
        // the shadow as inert (as for the twinless macro checks' clause,
        // `twinless_unread_input`). The probe's other readings under a directory word are
        // published, a residual `THREAT_MODEL.md` names.
        format!(
            "the flag list selects a header search directory (`-I`, `-isystem`, `-idirafter` \
             or `-iquote`), under which a header the probe `{}` includes can be shadowed, and \
             its source branches on {}, which such a header can define or undefine as the \
             list's own `-D` would, so the branch the program chard built and ran took may be \
             the list's rather than the compiler's own; the observation is withheld",
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

/// Which compiler-defined macros this flag list defines or undefines itself.
///
/// Recognises the spellings a flag list actually uses: `-DNAME`, `-DNAME=v`, `-UNAME`,
/// and the `-Wp,` and `-Xpreprocessor` forms that pass them through the driver: Fedora
/// ships `-Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3`, so the comma-joined form is not
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
///
/// The spoof clause reads the macro names a list spells; a forced include, a macro file, a
/// response file or a define handed to the frontend can define or
/// undefine the same names without spelling them, and so can a header under a directory the
/// list selects that shadows one the probe includes. The control arms carry the profile's
/// directory and include words as the header selection ([`arm_flags`]) and never its macro
/// words, so a header keyed on a profile macro acts on the measured build alone and is inert
/// in the arms. A check with a twin is held at the verdict by
/// `macro-contradicted-by-artifact` wherever such a header forges its macro
/// (`report::MACRO_TWINS`); the two without are held here, by the input, as the probes of
/// [`PROBE_MACRO_BRANCHES`] are under an unread input. Measured at the change that carried
/// the selection with gcc 16.1.1 on Fedora 44 x86_64, each over arms that discriminated and
/// each `indeterminate` under this clause now: `--profile explicit --flags "-O0 -DGATE
/// -include h"` with `h` defining `__OPTIMIZE__ 1` under `GATE` read `optimization-enabled`
/// `on` over an unoptimised build, `-O2 -DGATE -include h` with `h` undefining it read `off`
/// over an optimised one, and `-O0 -DGATE -I<dir>` with the directory's `stdc-predef.h`
/// including the next one and defining `__OPTIMIZE__ 1` under `GATE` read `on`. `observed`
/// is the reading's own sentence, from which the names it reads are quoted.
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
    let directory = crate::toolchain::header_selecting_flags(profile_flags)
        .iter()
        .any(|w| crate::toolchain::selects_header_directory(w));
    let carrier = match (directory, unread_preprocessor_input(profile_flags)) {
        (true, true) => {
            "selects a header search directory (`-I`, `-isystem`, `-idirafter` or `-iquote`), \
             under which a header the probe includes can be shadowed, and carries a \
             preprocessor input this rule does not read by name (a forced include or macro \
             file, in any of its spellings, a response file, a define handed to the \
             frontend); either"
        }
        (true, false) => {
            "selects a header search directory (`-I`, `-isystem`, `-idirafter` or `-iquote`), \
             under which a header the probe includes can be shadowed, and such a header"
        }
        (false, true) => {
            "carries a preprocessor input this rule does not read by name (a forced include or \
             macro file, in any of its spellings, a response file) or hands a define \
             to the frontend, and such an input"
        }
        (false, false) => return None,
    };
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
        "the flag list {carrier} can define or undefine {reads} as the list's own `-D` would, \
         and no check reading the artifact or a run of it holds `{}` (it has no twin), \
         so this macro may report what such an input told it rather than what the compiler \
         chose; the observation is withheld",
        check.id
    ))
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
///
/// A `-D` the driver takes as another option's value (`-u -D_X`, a symbol; `-L -D_X`, a
/// directory; `--std -D_X`, a standard's name) is no operation, and is passed over with the
/// word that takes it, as every reader of the list passes it (`toolchain::read`); a word
/// handed to a tool (`-Xclang -D_X`) is read as a plain operation, which names the macro
/// without modelling the frontend word's place, and [`unread_preprocessor_input`] holds
/// the twinless checks to it.
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
            // honours): it ends at `=`, at `(` for a function-like macro the probes'
            // `#ifdef` and `defined()` see by its name, or at a space, as
            // `report::flag_keys` ends it.
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
///
/// Measured 2026-09-30 on Fedora 44 x86_64 with g++ 16.1.1 and clang++ 22.1.8, by
/// `-dM -E` of an empty C++ unit: `-Wp,-D_X -U_X` and `-U_X -Wp,-D_X` leave `_X` defined,
/// `-D_X -Wp,-U_X` and `-Wp,-U_X -D_X` do not, and `-Xpreprocessor -D_X -U_X` defines it;
/// `-Wp,-D_X -Wp,-U_X` and `-Wp,-D_X,-U_X` do not, and `-U_X -D _X -U _X` does not.
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
/// frontend through `-Xclang`. [`preprocessor_ops`] reads that last as a plain `-D` or
/// `-U`, which names the macro but does not model the frontend word's place among the
/// driver's own. Each word is read as it stands, as the pieces of a `-Wp,` word, and as
/// the argument of `-Xpreprocessor` or `-Xclang`, separate or joined as `-Xclang=` (one
/// unsplit value: measured 2026-10-05 on Fedora 44 x86_64 with clang 22.1.8, `-Xclang=-DX=1`
/// defined `X` and `-Xclang=-DX,@file` defined `X` as `,@file`). The value of an option
/// that takes the next word (`-u -include`, a symbol; `-L -imacros`, a directory) is no
/// input of its own and is passed over with the word that takes it, read for a response
/// file alone, which the driver expands wherever it stands.
///
/// Any of these can define `_GLIBCXX_ASSERTIONS` without [`profile_defines`] seeing it,
/// so [`cxx_assertions_source`] names no library default over a list that carries one.
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
        // file in; `preprocessor_ops` has the measurement).
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

/// What put libstdc++'s assertions into the measured build, where they are there.
///
/// `c++config.h` defines `_GLIBCXX_ASSERTIONS` itself when `_GLIBCXX_DEBUG` is defined,
/// and when `__OPTIMIZE__` is undefined and `_GLIBCXX_NO_ASSERTIONS` is not, so an
/// unoptimized build carries the assertions whether or not anyone asked, and all three
/// checks in [`CXX_ASSERTIONS_ATTRIBUTED`] read `on` over it. The verdicts are true of the
/// artifact; this names the cause beside them:
///
/// - `profile`: the profile's flags leave `_GLIBCXX_ASSERTIONS` or `_GLIBCXX_DEBUG`
///   defined ([`profile_defines`]);
/// - `library-unoptimized-default`: they leave neither defined, the build has no
///   `__OPTIMIZE__`, they leave `_GLIBCXX_NO_ASSERTIONS` undefined, which is the
///   library's own condition (`_GLIBCXX_NO_ASSERTIONS` is outside the published macro
///   map, so the profile's flags are the published input that reads it), and they carry
///   no preprocessor input the reader does not resolve ([`unread_preprocessor_input`]);
/// - `unattributed`: neither holds. The profile's `-D` and `-U` spellings do not account
///   for the macro, and either the library's unoptimized condition does not hold or the
///   profile carries an input that could have defined the macro unseen, so no source is
///   named. It may be the profile's own `-include`, `-imacros`, `@file`,
///   `--define-macro` or `-Xclang -D` argument, or a driver default or a spec file; chard
///   does not tell these apart.
///
/// `None` where the check is not one of the three, the macros do not name libstdc++, or
/// `_GLIBCXX_ASSERTIONS` is undefined. `macros` is the measured build's map as the report
/// publishes it: the observation's `evidence.macros` on the macro channel, and the
/// `.chard.report` of its build's `facts` entry elsewhere. `profile_flags` is the
/// profile's C++ list, [`variant_flags`] for [`Lang::Cxx`].
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
///
/// Public and published: the report carries this list under `evidence_filters.macros`,
/// with its size and a digest, and every macro-channel observation's
/// `evidence.macros_filter` names that digest. The filter existed for as long as the
/// evidence did and was recorded nowhere, so `evidence.macros` read as the macro state
/// when it was thirty-odd names of it, and a distribution's own hardening macro under
/// some other name left no trace beside the verdict. `tests/evidence_completeness.rs`
/// holds every name a detector consults to be in this list.
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
    // Which implementation is providing the wrappers, and — from a preprocessor
    // dump rather than an artifact — fortify-headers' own include guard, which it
    // defines only inside its `_FORTIFY_SOURCE > 0 && __OPTIMIZE__` gate. On musl
    // one of these two is the only evidence that fortify instantiated at all, so a
    // reader checking the fortify verdict against the evidence needs them here.
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
    // The names `_LIBCPP_HARDENING_MODE` forwards to. A preprocessor dump prints a
    // macro's replacement text, not its expansion, so a mode arrives as
    // `_LIBCPP_HARDENING_MODE_FAST`, or as `_LIBCPP_HARDENING_MODE_DEFAULT` where the
    // headers chose it, and the predicate's `c-int` term looks the name up in the same
    // map. Without these the published map held the mode's name and not its value, so the
    // level `cxx-hardening-requested` read could not be re-derived from the report;
    // `tests/predicates.rs` (`filtered_macros_suffice`) holds the filter to it.
    // The self-report prints the expansion, a number, so a map read from an artifact
    // carries none of them.
    "_LIBCPP_HARDENING_MODE_NONE",
    "_LIBCPP_HARDENING_MODE_FAST",
    "_LIBCPP_HARDENING_MODE_EXTENSIVE",
    "_LIBCPP_HARDENING_MODE_DEBUG",
    "_LIBCPP_HARDENING_MODE_DEFAULT",
    // Which standard library answered. `_CXX_STDLIB` is chard's own summary, written
    // by the self-report header's `#if defined(_LIBCPP_VERSION)` arm, and the two
    // version macros are the real ones that arm tests — kept as the fallback for a
    // platform whose artifact cannot be read.
    //
    // The summary was missing here while both fallbacks were present, which is the
    // wrong way round on the platform chard actually runs on: where the artifact
    // *can* be read, `measure` replaces the preprocessor dump with the self-report
    // wholesale, and the self-report carries `_CXX_STDLIB` and neither version macro.
    // So on every Linux report the `cxx-hardening-requested` detector identified the
    // library, answered `on` or `off`, and published evidence from which that answer
    // could not be reproduced — the replay harness read the same observation back as
    // `indeterminate`, being the only check in the corpus to show a single outcome.
    // A verdict whose own evidence does not support it is the thing this project
    // exists not to publish, even when the verdict is right.
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
        boundary: crate::probe::boundary_for(check.flag),
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
///
/// Infallible by construction, and that is the whole point of the signature. A probe
/// that cannot be *measured* — no driver for its language, a compiler that outlives
/// `INVOKE_TIMEOUT`, a control arm that cannot be built at all — comes back as checks
/// carrying the reason, and the sweep continues. One unavailable probe destroying every
/// unrelated measurement is the clean-looking zero this project exists to refuse, so
/// there is deliberately no `Result` here for a later edit to propagate through.
///
/// A `Result` here would do exactly that. `gather` reaches `compile::build`, which returns
/// an error when the toolchain outlives its bound, and through `?` that error would travel
/// all the way out through the measure loop: one wedged invocation on one control arm would
/// make `chard measure` emit an error envelope with **zero** of its checks. The missing-`g++`
/// case below is the same defect from a different trigger, which is why the guard is
/// structural rather than another catch at the call site.
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
///
/// Applied to the copies the observation publishes and never to the records the
/// detectors read. A detector matches on the wording of a diagnostic, and the record it
/// is handed is the one `compile::invoke` captured; what is rewritten is the copy that
/// leaves the process, so a rule that scrubs too much can cost a reader a path and
/// cannot cost a verdict its evidence.
pub(crate) fn publish_text(text: &str, workdir: &Path) -> String {
    scrub_compiler_temp_names(&compile::relativize(text, workdir))
}

/// Rewrite an observation's published copies for the report.
///
/// The three places a path or a temporary name reaches the report: the build and run
/// records the observation carries, the control arms' `detail` and retained builds,
/// and the prose that quotes a diagnostic (`evidence.observed`, a gating's reason, a
/// build rejection). The artifact's facts are not here: they go to the report's
/// [`report::FactStore`] as read, being the artifact's own account in which nothing is a
/// path chard chose, and the one reason stored beside them is rewritten where it is
/// made ([`artifact_fact`]).
///
/// The `Variant`s this observation was decided from are not reachable from here, which
/// is the point: `run_check` has already read them, and the copies it cloned into the
/// observation are what this rewrites.
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
///
/// gcc writes `/tmp/ccXXXXXX.o`, clang `/tmp/name-XXXXXX.o`, and Apple's clang the same
/// under the per-user directory in `/var/folders/`, which its linker may spell with a
/// `/private` prefix. Both drivers honour `TMPDIR`, which `compile::invoke` clears, so
/// the first root is where their objects land on the hosts chard supports. A linker
/// warning names the object it is about, so the name reaches `stderr`, and from there
/// the `detail` of the control arm that quoted it: the one line that differs between two
/// runs of one measurement, once the timings are out of the way.
const TEMP_ROOTS: [&str; 3] = ["/tmp/", "/var/tmp/", "/var/folders/"];

/// The suffixes the two drivers give a temporary file. `.ii` before `.i`, because a
/// name is matched by the first suffix that fits.
const TEMP_SUFFIXES: [&str; 8] = [".ii", ".i", ".o", ".s", ".ld", ".le", ".res", ".args"];

/// The characters that end a path inside a diagnostic, beside whitespace.
///
/// Whitespace other than the space the line is split on ends one too: lld quotes an object
/// as `>>> defined in /tmp/probe-93b266.o` and ends the line there, and otherwise the path
/// runs on through the newline into the next line's `>>>`, matches no suffix and is kept.
/// Measured on OpenBSD 7.9 amd64 (clang 19.1.7, its lld) in the negative arms of `pie-macro`
/// and `pic-macro`, where that is the one line two normalized reports of one measurement
/// differ in besides the runs' own readings.
const PATH_END: [char; 6] = [':', '\'', '"', ')', ',', ';'];

/// Does `c` end a path inside a diagnostic? [`PATH_END`] says which.
fn ends_path(c: char) -> bool {
    PATH_END.contains(&c) || c.is_whitespace()
}

/// Is `path` a temporary file one of the compilers named?
///
/// Two conditions, both required: under a temporary root, and shaped the way the driver
/// shapes its names. gcc's is `cc` and six random characters (`mkstemps` draws letters
/// and digits) before the suffix; clang's is the source's stem, a dash and six. The root
/// alone was the rule, and it scrubbed every path under `/tmp`: an operator's
/// `-I/tmp/hdrs`, quoted in a diagnostic, was published as `<compiler-temp>`, and a
/// reader lost a path in the name of losing a random one.
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
///
/// A path runs from a temporary root to whitespace or to the punctuation a diagnostic
/// closes it with, so `ld: /tmp/ccAbC123.o: warning:` keeps its shape and loses its
/// name. Every other path under those roots is kept as written; [`is_compiler_temp_name`]
/// is the rule.
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
    // its checks under `no-driver` (see `no_driver`), and the sweep continues. It must
    // never abort the run.
    //
    // This is live, not hypothetical. A `driver_for` error propagated out of the whole
    // measure loop through `?` means a machine with `gcc` and no `g++` emits **no
    // report at all**, verified by measuring with `musl-gcc`, which has no C++ driver.
    // Every image in the VM catalogue installs `gcc clang binutils` and no `g++`, so a
    // sweep would return nothing for every one of them: one unavailable probe
    // destroying every unrelated measurement, which is the clean-looking zero this
    // project exists to refuse.
    if let Err(err) = driver.driver_for(probe.lang) {
        return no_driver(probe, &err);
    }

    // Two distinct builds, answering two distinct questions.
    //
    // `clean` carries no profile and no control flags, only the profile's target
    // and runtime selection (`clean_flags`), which every arm carries too. It is the reference
    // against which the controls establish that the *detector works on this
    // toolchain* — a property of detector and toolchain only, which must not
    // depend on the profile under test.
    //
    // `measured` carries the profile. It is the thing we are reporting on.
    //
    // Conflating the two is a mistake worth spelling out. Controls built on top of
    // the profile, measuring Fedora's `%build_cflags` (which injects hardening
    // through `-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1`), produce nine
    // `probe-invalid` verdicts. A spec file cannot be switched off by a later flag,
    // so every negative control still shows the observable and the harness
    // concludes its own detectors are broken. The detectors are fine; the question
    // is wrong.
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
    let unmatched = unmatched_link_inputs(driver, probe, ctx);
    let unmatched_clean = unmatched_clean_link(driver, probe, ctx);
    let unmatched_compile = unmatched_compile_inputs(driver, probe, ctx);
    // The compile's answer is per check: a difference the driver makes with the
    // optimisation level withholds the checks whose arms are at another level.
    let sanitizers = measured_sanitizers(driver, probe, ctx);
    let lto = measured_lto(driver, probe, ctx);

    let mut facts = Facts::default();
    for check in probe.checks {
        match run_check(
            driver,
            probe,
            check,
            (&clean, bare),
            ctx,
            ProbeListings {
                link: unmatched.as_deref(),
                clean_link: unmatched_clean.as_deref(),
                compile: unmatched_compile.for_check(check, ctx, probe.lang),
                sanitizers: sanitizers.as_ref(),
                lto: lto.as_ref(),
            },
            &mut facts,
        ) {
            Ok(observation) => observations.push(observation),
            // A control arm that cannot be *attempted* is a failure to validate the
            // detector, not a reading of the toolchain. Contained to this check: the
            // probe's evidence is already gathered and its other checks are decidable.
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
    ProbeOutcome {
        observations,
        facts: facts.store,
        diagnostics,
    }
}

/// What the driver queries `measure_probe` makes once per probe found, as one check of the
/// probe reads them in [`run_check`]: each a sentence that withholds the check, or the
/// listing's words a rule reads.
#[derive(Debug, Clone, Copy)]
pub struct ProbeListings<'a> {
    /// [`unmatched_link_inputs`]'s sentence, for a check that reads the measured link.
    pub link: Option<&'a str>,
    /// [`unmatched_clean_link`]'s sentence, for a check that reads the clean build.
    pub clean_link: Option<&'a str>,
    /// The compile-input comparison's sentence for this check
    /// ([`CompileInputsUnmatched::for_check`]).
    pub compile: Option<&'a str>,
    /// The measured compile's sanitizer words ([`measured_sanitizers`]).
    pub sanitizers: Option<&'a report::SanitizerWords>,
    /// The measured compile's LTO words ([`measured_lto`]).
    pub lto: Option<&'a report::LtoWords>,
}

/// The artifacts a probe's faults are read from, each under the label that says which
/// build it is.
///
/// Under a clean profile `measure_probe` hands the clean variant as the measured one too,
/// and every loop in [`evidence_faults`] iterates this list, so a fault in that one
/// artifact is diagnosed once, under `clean`: the label `artifact_comments` gives the same
/// build under every profile, since it says which build was read. Iterated as two roles
/// before, one artifact under `--profile bare` was named twice, as the clean artifact's
/// cut table and again as the measured artifact's, and a reader of `diagnostics` counted
/// two cut artifacts where there was one.
fn fault_roles<'a>(clean: &'a Variant, bare: &'a Variant) -> Vec<(&'a Variant, &'static str)> {
    if std::ptr::eq(clean, bare) {
        vec![(clean, "clean")]
    } else {
        vec![(clean, "clean"), (bare, "measured")]
    }
}

/// A table the reader could not finish, on an artifact it otherwise read, as one error
/// diagnostic per cut table per artifact, and a view it dropped as one warning per entry.
///
/// The checks that declare the table withhold through `report::truncation_limitation`,
/// and a check reading only the other tables publishes over the same artifact, so the
/// cut is named once here, at the probe, whether or not any check declared the table.
/// Once per table, because a table can carry more than one `unread` entry (a symbol
/// table cut at two places, or a `.chard.report` and a `.GCC.command.line` both listed
/// and not held), and the first entry's sentence is the one quoted. Once per artifact, because
/// `roles` lists each artifact once, as [`fault_roles`] says. An `ignored` entry leaves
/// the facts whole and is a `warning`: the artifact declared something about the table the
/// reader did not follow, which a reader of `diagnostics` should see without opening
/// stored artifact's `truncations`.
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
///
/// Diagnostics rather than observations, every one of them: each says something about
/// chard or about the invocation, not about the toolchain's hardening, and a reader who
/// sees `build-failed` in a cell needs the reason next to it rather than in a verdict.
fn evidence_faults(probe: &Probe, clean: &Variant, bare: &Variant) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let roles = fault_roles(clean, bare);

    // An artifact that linked and that chard could not read. The checks over it already
    // withhold — `sufficient_for` returns `build-failed` for an absent `elf` — but the
    // reason was dropped by `.ok()`, so the report showed `build-failed` beside a build
    // record with `exit_status: 0` and empty stderr and said nothing about why. That is
    // a fault in chard, not a finding about the toolchain, which is what makes it a
    // diagnostic rather than an observation.
    // Exited 0 and wrote nothing. Distinct from the unreadable-artifact case below and
    // reported separately: "no artifact" and "an artifact this reader does not
    // understand" are different facts, and a reader who sees `build-failed` beside
    // `exit_status: 0` needs to know which one happened. `-fsyntax-only` through
    // `--profile explicit` is the honest way to reach it.
    for (variant, tag) in &roles {
        if variant
            .build
            .as_ref()
            .is_some_and(|b| b.succeeded() && b.artifact_sha256.is_none())
        {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: format!(
                    "the {tag} build exited 0 and produced no artifact, so every check \
                     over it withholds, the macro checks under artifact-lacks-self-report: \
                     these flags compile without linking"
                ),
                context: Some(probe.id.to_owned()),
                rejection: None,
            });
        }
    }

    for (variant, tag) in &roles {
        if let Some(reason) = variant.elf_error.as_ref() {
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

    // A macro dump that failed, or defined nothing. The checks over it withhold through
    // `Variant::sufficient_for`, and this is where the reason reaches the report: six
    // `indeterminate` cells with nothing beside them is what a reader saw before, with
    // no way to learn that the preprocessor had exited 1 on a missing include.
    for (variant, tag) in &roles {
        if variant.macro_dump.is_none() {
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
    // missing. The condition is `report::self_report_entries`, the reading `gather` took
    // the artifact's macros through and the gate `report::self_report_limitation` fires
    // on, so this warning and that withholding cannot name different artifacts: on a
    // probe with a macro-channel check the two appear together, except where the triple
    // withheld or a declared rule spoke and the gate leaves that reason standing, and on
    // every other probe the warning stands alone, since no verdict there reads the
    // section. An artifact the reader refused, or a build that wrote none, has its own
    // error diagnostic above and its macro checks withheld by `settle_self_report_unread`.
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

/// The diagnostics of the two macro views compared ([`compare_macro_views`]): the
/// disagreement, and the header-defined macros one view alone carries. Its own function
/// for `evidence_faults`'s length; the probe names the context.
fn macro_view_diagnostics(probe: &Probe, bare: &Variant) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    // The two macro views should agree, where there are two: a dump is taken only for a
    // probe with a macro-channel check, and elsewhere there is one view and nothing is
    // compared ([`compare_macro_views`]). Where they disagree, a spec file is
    // patching one job and not the other, and any verdict taken from the
    // preprocessor alone would be describing a compiler that is not the one
    // generating code. This is the spec-file hazard DESIGN.md describes,
    // made observable rather than assumed away. A header-defined macro one view alone
    // carries is the two units reaching different headers, not that hazard, and is
    // published as uncompared rather than as a disagreement or as silence.
    let MacroViews {
        mut disagreements,
        mut header_one_sided,
    } = compare_macro_views(bare);
    if !disagreements.is_empty() {
        disagreements.sort();
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "the compiler and the preprocessor disagree about {} macro(s): {}. \
                 Verdicts use the compiled artifact, which is the side that decides \
                 what the code does; a harness reading `cc -dM -E` alone would be \
                 wrong here",
                disagreements.len(),
                disagreements.join(", ")
            ),
            context: Some(probe.id.to_owned()),
            rejection: None,
        });
    }
    if !header_one_sided.is_empty() {
        header_one_sided.sort();
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "the compiler's and the preprocessor's views were not compared on {} \
                 header-defined macro(s) that one view alone carries: {}. A library header \
                 sets such a macro from other macros, so a view that never reached that \
                 header does not carry it. The one-sided reading can be the probe's own \
                 translation unit and the dump's macros-only unit including different \
                 headers, or a header selection or a define that reached one job alone; \
                 chard did not tell which. Verdicts use the compiled artifact either way",
                header_one_sided.len(),
                header_one_sided.join(", ")
            ),
            context: Some(probe.id.to_owned()),
            rejection: None,
        });
    }
    diagnostics
}

/// Every check of a probe whose language has no driver chard could find.
///
/// The checks read `indeterminate`, which `--fail-on-missing` does not settle, and not
/// `not-applicable`: the absence of a C++ driver is established by
/// [`crate::compile::cxx_driver_for`], which rewrites the C driver's name and looks beside
/// it, so a miss is a fact about that lookup and not about the toolchain. `icx` has
/// `icpx`, and a lone `--cc` symlink may have `g++` elsewhere on `PATH`. It stays distinct
/// from [`unmeasured`] by its rule id: here the probe was never started, there a stage of
/// it failed.
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
                    "{} needs a {:?} driver and none was found beside the C driver: \
                     {reason}. The other probes are unaffected",
                    probe.id, probe.lang
                ),
            });
            observation
        })
        .collect();
    ProbeOutcome {
        observations,
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
///
/// Distinct from a control arm that *built* and failed to discriminate — that is a
/// `probe-invalid` verdict about the detector, and it is a real finding. This is the
/// harness never getting far enough to ask, which is not a finding about anything.
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
            "a control arm for {} could not be built at all ({reason}), so the detector \
             was never validated and no verdict is derivable from it. This probe's other \
             checks are unaffected",
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
///
/// `indeterminate` rather than `not-applicable`, and the difference is the point: the
/// probe *applies* on this toolchain, we simply failed to observe it. Publishing
/// `not-applicable` would state a property of the toolchain that we derived from a
/// failure of the harness — the same conversion `compile::invoke` refuses when it turns
/// a timed-out compile into an error instead of a failed `BuildRecord`.
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
                    "probe {} was not measured: its {stage} build could not be attempted \
                     at all ({reason}). Only this probe's checks are affected",
                    probe.id
                ),
            });
            observation
        })
        .collect();
    ProbeOutcome {
        observations,
        facts: report::FactStore::default(),
        diagnostics: vec![Diagnostic {
            severity: Severity::Error,
            message: format!(
                "probe {} not measured: the {stage} build could not be attempted: {reason}. \
                 Its {} check(s) are indeterminate rather than missing, and every other \
                 probe is unaffected",
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
/// `bare` is the variant being reported on — the measured build, or the clean one when
/// the profile adds nothing. `clean` is the reference the controls are built against,
/// profile-free but for the target and runtime the profile selects ([`clean_flags`]), and
/// the two must not be swapped: see the module note.
///
/// # Errors
///
/// Errors when a control arm cannot be built at all.
#[allow(
    clippy::too_many_lines,
    reason = "the control triple reads as one sequence: bare, forced on, forced off, \
              regime-matched, decide. Splitting it would scatter the logic a reader \
              most needs to audit in one place."
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
    let ProbeListings {
        link: unmatched_link,
        clean_link: unmatched_clean,
        compile: unmatched_compile,
        sanitizers,
        lto,
    } = listings;
    let mut observation = blank_observation(probe, check, Verdict::Indeterminate);

    match report::applicability(check, ctx.env, ctx.target_arch) {
        // Each publishes the verdict its rule's premise reserves: `arch-gated` is a fact
        // about the target; `needs-vm`, `execution-mode-assumed`, `no-check-on-target` and
        // `arch-outside-table` are limits on what this run could observe.
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

    // The measured build alone is held to the profile: a build the driver refused for a
    // profile flag is `build-failed` on every channel, the compiler-diagnostic one
    // included (`Variant::sufficient_for_measured` says why that channel needed telling).
    // The refusal it read is the one published, as `build_rejection` and, on that channel,
    // as the reason: the gate, the field and the reason are one reading.
    if let Err(withheld) = bare.sufficient_for_measured(check.channel(), ctx.profile) {
        observation.verdict = withheld.verdict;
        // The reason, in the field a reader checks a verdict against. On the macro
        // channel that is the dump's own failure; elsewhere it is the run's.
        // An artifact the reader refused is the elf-static channel's reason. Reading
        // `run_error` here, which is `None` for an artifact that was never run, would
        // publish every elf-static cell over a Mach-O artifact on Darwin as an
        // `indeterminate` with no `observed` at all. The compiler-diagnostic channel is
        // withheld here only for a build the driver refused, and its reason is the exit
        // status and the refused line, not the first line of stderr, which on a link the
        // linker refused is the compiler's own chatter.
        observation.evidence.observed = match check.channel() {
            Channel::Macro => bare
                .macro_dump_failure()
                .or_else(|| build_failure_reason(bare)),
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
        // The build this observation carries, and the dump it read its macros from:
        // entered only now, on a path that returns the observation, so an entry is never
        // left behind by a check that errors out before it publishes one.
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
    // and nothing else of it (`arm_flags`). The positive list is the one for this target:
    // `probe::ArchControl` says why it can vary.
    let positive_control = check.positive_for(ctx.target_arch);
    let positive_flags = arm_flags(check, ctx.profile, probe.lang, positive_control);
    let positive_flags_for_object = positive_flags.clone();
    let negative_flags = arm_flags(check, ctx.profile, probe.lang, check.negative);
    let positive = driver.gather(probe, &positive_flags, &format!("{}-pos", check.id))?;
    let positive_reading = positive
        .sufficient_for(check.channel())
        .ok()
        .map(|()| reading(check, &positive));

    // A check with no negative control uses the clean build as its
    // negative sample: for a flag that is off by default, an unflagged
    // build is exactly what "absent" looks like.
    // The variant is kept, not just its detection: `unhardened_state_limitation` reads
    // its build record to see whether the toolchain refused the control outright.
    // With a linker or header selection to carry, the clean build does not stand in: it
    // links with the driver's default and reads no profile header, so the arm is built with
    // the selection alone.
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

    // Regime-matched negative arm, for runtime detectors only. A runtime
    // observable can be produced by something other than the flag under
    // test — `-fstack-protector-strong` makes uninitialized locals read as
    // zero, which is also what `-ftrivial-auto-var-init=zero` produces — so
    // the negative control is re-run on top of the profile to check that the
    // signal in the measured build is actually attributable. Skipped when the
    // profile is empty, since the arm would then duplicate the profile-free
    // one.
    // The arm's variant is held beside the detection, as the other two arms' are: the
    // arm publishes its own build and run, and the store takes its artifact's facts.
    // The arm's flags are the check's own (`Regime::Arm`), appended to the profile. Both
    // `Option`s are `Some` together: `owes_regime_control` is `regime_arm` and the profile.
    let regime_flags = check
        .regime_arm()
        .filter(|_| check.owes_regime_control(ctx.profile_is_clean));
    let regime = match regime_flags {
        Some(flags) => Some(driver.gather(
            probe,
            &variant_flags(ctx.profile, probe.lang, flags),
            &format!("{}-regime-neg", check.id),
        )?),
        None => None,
    };
    // Two levels of `Option`, because the two absences are different facts: the outer is
    // whether a regime arm was owed at all, the inner whether the owed arm could be read.
    // An owed arm that cannot be read reaches `decide` with no detection, the state the
    // plain arms use for an arm that could not be evaluated, and `decide` withholds it as
    // `regime-unevaluable`; its reason is published as the arm's `detail` below.
    // A synthetic `indeterminate` detection for such an arm, with no reading behind it,
    // would publish an `outcome` with no `decoded`, and the replay rule
    // `decoded-reading-disagrees-with-facts` would refuse the whole report wherever a
    // toolchain rejects a regime arm's flag (`-fcf-protection=none` on gcc 7.5 and clang
    // 6.0 under `bare-optimized`). `sufficient_for` is `Ok` exactly when
    // `unevaluable_reason` is `None`.
    let regime_negative_reading: Option<Option<probe::Decoding>> = regime.as_ref().map(|regime| {
        regime
            .sufficient_for(check.channel())
            .is_ok()
            .then(|| reading(check, regime))
    });

    // Each arm reaches `decide` with the flags that built it, the same lists the three
    // `gather` calls above were given, so the published `Controls` is complete on
    // construction and cannot claim fewer flags than built an arm. The negative list is
    // empty exactly when the clean build stood in, which is what that arm was built with.
    let (verdict, mut controls) = report::decide(
        &bare_detection,
        report::ArmInput {
            detection: positive_reading.as_ref().map(|r| &r.detection),
            flags: positive_flags,
        },
        report::ArmInput {
            detection: negative_reading.as_ref().map(|r| &r.detection),
            flags: negative_flags,
        },
        regime_negative_reading
            .as_ref()
            .zip(regime_flags)
            .map(|(r, flags)| report::ArmInput {
                detection: r.as_ref().map(|r| &r.detection),
                flags: variant_flags(ctx.profile, probe.lang, flags),
            }),
        check.levels.grade(),
    );
    // Every arm publishes what it compiled and what happened when it ran, whether the
    // triple agreed or not: these two are what lets a reader re-run an arm and check the
    // outcome it is being asked to take on trust. The artifact's own account is the
    // store's, entered below.
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
    // An arm that could not be evaluated says why, in the field a reader consults for
    // what the arm observed. `decide` is handed no detection for such an arm and leaves
    // `detail` empty, so `positive-unevaluable` named no cause: on the macro channel the
    // cause is the arm's own dump having failed, and nothing else in the report
    // recorded that job.
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
    // A link-ANDed marking whose linked positive control read absent: the same arm is
    // compiled and not linked, so the declared family can tell a compiler that did not
    // mark from a link that cleared the mark (`report::link_drop_limitation`).
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
    // `bare` is the build the check's own observable was read from, which
    // `subject_variant` chose above, so the artifact rule inside `settle` asks its
    // precondition of the same object the detector examined. Every field of `settled`
    // is read below, and an unread one is a compile error, so the sequence's result
    // reaches the observation whole.
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
    // wrote none, on a run whose artifacts are ELF. `settle` could not see it, since the
    // artifact gates read `bare.elf` and here there is none.
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
    // A check asking for the toolchain's default reads the clean build, whose target and
    // runtime selection its arms carry too and which carries no header word (nor do they),
    // so the measured link's inputs are not its subject.
    let settled = settle_link_inputs(
        settled,
        check,
        unmatched_link.filter(|_| !check.measures_toolchain_default),
    );
    // Its own build is the clean one, which is held to the measured link instead: the
    // program the link runs and the directories it searches.
    let settled = settle_clean_link(settled, check, unmatched_clean);
    // The same for the compile: the clean build and the arms that vouch for it are built
    // without the measured compile's headers and macros, which are not such a check's subject.
    let settled = settle_compile_inputs(
        settled,
        check,
        unmatched_compile.filter(|_| !check.measures_toolchain_default),
    );
    // The measured compile's own sanitizer request, read from the driver's -### words: a
    // group the probe cannot show, left in handler mode beside an `on` or trapped beside an
    // `off`, is unmeasured whatever the artifact's traps said.
    let settled = settle_sanitizer_groups(settled, check, sanitizers);
    // The measured compile's link-time optimization, from the same listing: a link that
    // succeeded under it says what the link generated.
    let settled = settle_lto_codegen(settled, check, ctx.toolchain_kind, lto);
    // An `on` that stood under LTO because the listing resolved the compile to PIC without
    // PIE is quoted beside the detector's own account: the listing is its evidence.
    let lto_pic = report::lto_pic_evidence(check, settled.verdict, ctx.toolchain_kind, lto);
    observation.verdict = settled.verdict;
    observation.gating = settled.gating;
    observation.level = settled.level;
    observation.controls = Some(controls);
    observation.evidence = EvidenceOut {
        macros: (check.channel() == Channel::Macro).then(|| relevant_macros(&bare.macros)),
        macros_filter: None,
        macro_source: None,
        macro_dump: None,
        observed: Some(match lto_pic {
            Some(listing) => format!("{}; {listing}", bare_detection.observed),
            None => bare_detection.observed.clone(),
        }),
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
    // above leaves none behind: the measured build, each evaluated arm of a check that
    // reads artifacts, and each dump a macro-channel reading came from. The negative arm
    // is the clean build where the check declares no negative control, the arm the
    // triple read.
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
///
/// `None` unless the check has needles and some arm carries a side build. An arm with no
/// build of its own, or no capture, is not compared against nothing: it is named in
/// `arms_missing`, so the comparison accounts for every arm it was fed. The negative arm is
/// the clean build where the check has no negative control, the same substitution
/// `run_check` makes for its verdict.
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
///
/// In a module of its own so that [`MeasuredArtifact::of`] is the only way to build one: the
/// link mode is the probe's, read from the probe the caller hands it, and no caller can
/// write a mode beside the facts. A test cannot reach `run_check`'s one call without a
/// toolchain, so the type holds the hand-off; which probe, variant and proof the call passes
/// is the call's to get right.
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
///
/// The ladder as a whole, these steps and the ones before `decide`, is
/// [`report::gating_rule::Stage`]; each rule's row in [`report::gating_rule::ALL`] names
/// its step.
///
/// Pure over its inputs, so the order is a thing tests hold rather than a sequence of
/// statements in [`run_check`]: the five tests from
/// `an_off_scale_level_is_withheld_under_its_own_rule` on, in this module, pin one claim
/// each. Each rule overwrites the reason of the one before it where both apply:
///
/// 1. [`report::level_gating`]: a level the check's own scale could not grade. Placed
///    first because it is the reason for an `indeterminate` on a discriminating triple,
///    and every later rule either declines that verdict or has the stronger claim. Then,
///    where it did not speak, [`report::detector_gating`]: the detector's own withholding
///    under the rule it named ([`probe::Detection::rule`]), the other reason for an
///    `indeterminate` on a discriminating triple, and overwritten by the same later rules.
///    The two never both apply: the level rule reads a `present` word the scale cannot
///    grade, the detector rule an `indeterminate` the detector named.
/// 2. `declared`, the known-limitation family, consulted on `probe-invalid` only. Every
///    member already declines any other verdict; the guard here makes that a property of
///    this sequence as well, so the level reason above cannot be overwritten through a
///    member that later forgets its own guard. Where it fires the verdict is the one the
///    rule's premise reserves (`report::gating_rule::Premise`): `unsupported` for a fact
///    about the toolchain, `indeterminate` for a control or scaffold chard could not
///    build, `not-applicable` for an observable another implementation owns.
/// 3. The two gates on the measured run, each withholding a runtime reading whatever it
///    was: [`report::deadline_limitation`], a run chard's deadline killed, under
///    `run-deadline-elapsed` with the deadline; then [`report::stream_limitation`],
///    output that hit the capture cap or could not be read, under
///    `run-output-unreadable`. The third rule of the stage, `run-under-emulation`, runs
///    after this function returns, in [`settle_emulation`], and speaks only where (1) did
///    or nothing did.
/// 4. [`artifact_gating`], the gates on the measured artifact, in the order its own
///    documentation gives. A table the check reads that the reader could not finish turns
///    the reading into `indeterminate` under `artifact-unreadable`, overwriting a level
///    reason, since an unread table is the more fundamental statement; an executable
///    link's artifact that classifies as a shared object withholds a reading of the
///    classification under `artifact-contradicts-link-mode`; then
///    [`report::artifact_limitation`], an observable the artifact cannot carry, turns an
///    unearned `off` into `not-applicable`. Each rests on
///    the artifact in hand; the libc and driver rules in (2) upgrade a `probe-invalid`
///    instead. The precondition is handed the reading's outcome with the verdict because
///    the two disagree in one case: a `present` reading whose level the scale could not
///    grade is `indeterminate` too, and the rule declines it, so the level reason from
///    (1) stands. It is handed the verdict `decide` reached rather than the one (3) left,
///    and overwrites (3) where both apply.
/// 5. The macro-spoof rule, last: a macro-channel observation whose macro the flag list
///    defined itself is a measurement of the flag list, not of the toolchain.
///
/// The control triple cannot catch (5) and is not failing when it happens: forced on
/// shows the macro, forced off does not, so the *detector* is demonstrably working. What
/// the triple establishes is that chard can see the macro, not that the compiler is the
/// one that set it. A `-D__SSP_STRONG__=3` in a queried flag list satisfies every control
/// and publishes `on (strong)` over a binary with no canary. It was reachable without any
/// compromise: when chard still queried package managers, `rpm` read `~/.rpmmacros`, so
/// redefining `%build_cflags` there put arbitrary `-D`s into a measured profile until
/// `$HOME` was scrubbed. Those queries are gone and the rule closes the class, including
/// `--profile explicit --flags`, where the operator supplies the list directly. Withheld
/// rather than corrected, because chard cannot tell what the compiler *would* have
/// defined once something else has defined it; and last, so a forged macro's reason
/// overwrites a level reason, the more fundamental statement of the two.
///
/// `profile_flags` is the measured profile's own list for the probe's language, the one
/// a forged macro would have come from.
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
    // premise is. Keyed on the rule having fired rather than on the verdict being
    // `unsupported`, which is how it was keyed while every declared rule published that:
    // an `indeterminate` or `not-applicable` from (2) rests on the arms, and the artifact
    // gates would otherwise overwrite it with a reason about the measured build instead.
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
                    "the flag list defines or undefines {} itself, so this macro reports what it was \
                     told rather than what the compiler chose; the observation measures \
                     the flag list and is withheld",
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

/// `artifact-lacks-self-report` over what [`settle`] left (where nothing spoke, or a reading
/// rule did), for a macro-channel check whose
/// measured build wrote an artifact chard's ELF reader refused (`elf_error`, on every host
/// but where it refused a Mach-O object on macOS, over which the dump is read by design)
/// or exited 0 and wrote none (every host):
/// the reading is the `-dM -E` dump's alone, as over a read artifact without its section,
/// and [`report::self_report_limitation`] inside `settle` could not see it, since the
/// artifact gates read `bare.elf` and here there is none. The selection is
/// [`report::artifact_account_missing`], the one the consistency rule reads. Speaks where
/// nothing did or only the level or detector rule did
/// ([`report::gating_rule::Stage::is_reading_rule`]), as
/// [`settle_emulation`] does, which keeps the ladder's order: a declared rule's
/// `unsupported`, the triple's `probe-invalid` and the later spoof rule stand. A variant
/// with no build record is a probe that builds nothing, and the dump is all it has.
///
/// Measured on Fedora 44 x86_64, gcc 16.1.1, without this settlement: a driver overwriting
/// each linked program with two bytes, and one deleting it, each with
/// `-fstack-protector-strong` handed to the dump alone, published `ssp-level` `on`, level
/// `strong`, from the dump beside an error diagnostic naming only the elf-static checks as
/// withheld.
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
///
/// It speaks where nothing did or where only the level or detector rule did
/// ([`report::gating_rule::Stage::is_reading_rule`]), which is where its stage sits on the
/// ladder: after `Level`
/// and `Detector`, which it overwrites, and after the deadline and
/// stream rules of its own stage, which are the more fundamental statement (the reading is
/// incomplete) and keep their reason. An artifact gate or the spoof rule, later stages, has
/// already spoken over it inside `settle`. `decided` is the verdict `decide` reached, the
/// one `settle` was handed, so a `probe-invalid` is left alone whatever `settle` made of
/// it. `unread` is the reader's refusal of the measured artifact where it gave one, which
/// the rule quotes, since a record it could not read holds nothing to the kernel. `macos`
/// is whether the run is on macOS ([`crate::env::Distro::is_macos`]), the one platform
/// whose probes print the `sysctl.proc_translated` line the rule then reads from `run`. See
/// [`report::emulation_limitation`].
///
/// [`Stage::Run`]: report::gating_rule::Stage::Run
#[allow(
    clippy::too_many_arguments,
    reason = "the rule reads the settled reading, the decided verdict, the check, the artifact's \
              record or its refusal, the run, the kernel and the platform; a struct for the \
              one production call site would only rename them"
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

/// `link-inputs-unmatched-by-arms` over what [`settle`] and [`settle_emulation`] left: the
/// rule of [`Stage::Link`], which overwrites every earlier stage's reason, since each of
/// them read a triple built on another link. `unmatched` is the sentence
/// [`unmatched_link_inputs`] gave the probe. See [`report::link_inputs_limitation`].
///
/// [`Stage::Link`]: report::gating_rule::Stage::Link
fn settle_link_inputs(settled: Settled, check: &Check, unmatched: Option<&str>) -> Settled {
    match report::link_inputs_limitation(check, unmatched) {
        Some(limit) => Settled {
            verdict: limit.rule.verdict(),
            level: published_level(limit.rule.verdict(), None),
            gating: Some(limit),
        },
        None => settled,
    }
}

/// Whether the measured build's link and the arms' combine other startup objects, as a
/// sentence naming the difference, or `None` where the driver names the same ones or the
/// probe has nothing to compare.
///
/// Compared only where it can decide something: a profile adding flags (with none, the
/// measured build is the clean one, built with the arms' selection), a probe that links,
/// and a check of the probe in [`report::LINK_INPUT_READINGS`] that reads the measured
/// build. The measured listing is taken under [`variant_flags`], the arms' under
/// [`arm_flags`] with no control flags, which is the target, runtime, header and linker
/// selection every linking arm of the probe carries; each passes through the probe's output kind
/// ([`probe::LinkMode::partition_flags`] and `extra_flags`), as its build does. The arms'
/// listing takes the measured link's linkage form ([`crate::link_inputs`] says why). A
/// listing that cannot be read is a match that cannot be shown, and its sentence withholds
/// as a difference does. Two `-###` runs per probe that compares, and four probes of the
/// corpus compare: `link-defaults`, `shared-object-defaults`, `stack-exec-runtime` and
/// `shadow-stack` (the listed check of `linker-default-execstack` reads the clean build).
fn unmatched_link_inputs(
    driver: &Driver<'_>,
    probe: &Probe,
    ctx: &Conditions<'_>,
) -> Option<String> {
    let reads_link = probe.checks.iter().find(|c| {
        report::LINK_INPUT_READINGS.contains(&c.id)
            && !c.measures_toolchain_default
            && c.channel() != Channel::Macro
    });
    let check = reads_link
        .filter(|_| !ctx.profile_is_clean && probe.link_mode != probe::LinkMode::Object)?;
    let program = match driver.driver_for(probe.lang) {
        Ok(program) => program,
        Err(why) => return Some(format!("chard found no driver to ask ({why:#})")),
    };
    let linked = |flags: &[String]| linked_flags(probe, flags);
    let measured_flags = linked(&variant_flags(ctx.profile, probe.lang, &[]));
    let measured = match crate::link_inputs::query(program, &measured_flags) {
        Ok(inputs) => inputs,
        Err(why) => return Some(format!("for the measured build, {why}")),
    };
    let arm_selection = arms_link_query(
        linked(&arm_flags(check, ctx.profile, probe.lang, &[])),
        measured.form,
    );
    let arms = match crate::link_inputs::query(program, &arm_selection) {
        Ok(inputs) => inputs,
        Err(why) => return Some(format!("for the arms' selection, {why}")),
    };
    crate::link_inputs::difference(&measured, &arms).map(|d| {
        format!(
            "the driver's -### listing for the measured link ({}) and for the arms' \
             selection under the same linkage form ({}) differ: {d}",
            measured_flags.join(" "),
            arm_selection.join(" ")
        )
    })
}

/// `clean-link-unmatched-by-measured` over what [`settle_link_inputs`] left: the second rule
/// of [`Stage::Link`], for the checks that read the clean build, to which [`run_check`] hands
/// the first no sentence, so neither overwrites the other. `unmatched` is the
/// sentence [`unmatched_clean_link`] gave the probe. See [`report::clean_link_limitation`].
///
/// [`Stage::Link`]: report::gating_rule::Stage::Link
fn settle_clean_link(settled: Settled, check: &Check, unmatched: Option<&str>) -> Settled {
    match report::clean_link_limitation(check, unmatched) {
        Some(limit) => Settled {
            verdict: limit.rule.verdict(),
            level: published_level(limit.rule.verdict(), None),
            gating: Some(limit),
        },
        None => settled,
    }
}

/// Whether the clean build a default-asking check reads would link otherwise than the
/// measured build, as a sentence naming the difference, or `None` where the driver's
/// answers agree or the probe has nothing to compare.
///
/// Compared only where it can decide something: a profile adding flags (with none, the
/// measured build is the clean one), a probe that links, and a check of the probe that
/// reads the clean build's link ([`report::reads_the_clean_link`], the predicate the rule
/// withholds by). Four driver queries, each through the probe's output kind as its build
/// is: the `-###` link line of the measured build's flags ([`variant_flags`]) and of the
/// check's arms' selection with no control flag ([`arm_flags`]), which is the clean build's
/// flags with the measured line's linker program selection and so links with the linker
/// the measured line names; and the `-print-search-dirs` answer of the measured build's
/// flags and of the clean build's own ([`clean_flags`]). What each is compared on, and why
/// each side is read where it is, is [`crate::link_inputs::clean_link_difference`]'s. An
/// answer that cannot be read is an agreement that cannot be shown, and its sentence
/// withholds as a difference does.
fn unmatched_clean_link(
    driver: &Driver<'_>,
    probe: &Probe,
    ctx: &Conditions<'_>,
) -> Option<String> {
    let reads_clean = probe
        .checks
        .iter()
        .find(|c| report::reads_the_clean_link(c));
    let check = reads_clean
        .filter(|_| !ctx.profile_is_clean && probe.link_mode != probe::LinkMode::Object)?;
    let program = match driver.driver_for(probe.lang) {
        Ok(program) => program,
        Err(why) => return Some(format!("chard found no driver to ask ({why:#})")),
    };
    let measured_flags = linked_flags(probe, &variant_flags(ctx.profile, probe.lang, &[]));
    let footing_flags = linked_flags(probe, &arm_flags(check, ctx.profile, probe.lang, &[]));
    let clean_build_flags = linked_flags(probe, &clean_flags(ctx.profile, probe.lang));
    let measured = match crate::link_inputs::query(program, &measured_flags) {
        Ok(inputs) => inputs,
        Err(why) => return Some(format!("for the measured build, {why}")),
    };
    let footing = match crate::link_inputs::query(program, &footing_flags) {
        Ok(inputs) => inputs,
        Err(why) => return Some(format!("for the clean build's link, {why}")),
    };
    let measured_dirs = match crate::link_inputs::query_search_dirs(program, &measured_flags) {
        Ok(dirs) => dirs,
        Err(why) => return Some(format!("for the measured build, {why}")),
    };
    let clean_dirs = match crate::link_inputs::query_search_dirs(program, &clean_build_flags) {
        Ok(dirs) => dirs,
        Err(why) => return Some(format!("for the clean build, {why}")),
    };
    crate::link_inputs::clean_link_difference((&measured, &measured_dirs), (&footing, &clean_dirs))
        .map(|d| {
            format!(
                "the driver's answers for the measured build ({}) and for the clean build \
                 ({}; its link line {}) differ: {d}",
                crate::link_inputs::under(&measured_flags),
                crate::link_inputs::under_named(&clean_build_flags, "selection flag"),
                if footing_flags == clean_build_flags {
                    "under the same flags".to_owned()
                } else {
                    format!(
                        "{}, the measured line's linker selection among them",
                        crate::link_inputs::under_named(&footing_flags, "selection flag")
                    )
                }
            )
        })
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
/// form; without that test the line could be deleted with every test green.
fn arms_link_query(
    mut selection: Vec<String>,
    measured: crate::link_inputs::LinkageForm,
) -> Vec<String> {
    selection.push(measured.driver_flag().to_owned());
    selection
}

/// `compile-inputs-unmatched-by-arms` over what [`settle_link_inputs`] and
/// [`settle_clean_link`] left: the rule of
/// [`Stage::Compile`], which overwrites every earlier stage's reason, since each of them
/// read a triple compiled against other headers or macros. `unmatched` is the sentence
/// [`unmatched_compile_inputs`] gave the check ([`CompileInputsUnmatched::for_check`]).
/// See [`report::compile_inputs_limitation`].
///
/// [`Stage::Compile`]: report::gating_rule::Stage::Compile
fn settle_compile_inputs(settled: Settled, check: &Check, unmatched: Option<&str>) -> Settled {
    match report::compile_inputs_limitation(check, unmatched) {
        Some(limit) => Settled {
            verdict: limit.rule.verdict(),
            level: published_level(limit.rule.verdict(), None),
            gating: Some(limit),
        },
        None => settled,
    }
}

/// `sanitizer-group-unmeasured` over what [`settle_compile_inputs`] left: the rule of
/// [`Stage::Sanitizer`], on `on` and `partial` where the measured compile's sanitizer words
/// ([`measured_sanitizers`]) leave a group enabled and in handler mode, and on `off` where
/// they leave one enabled and in trap mode. See [`report::sanitizer_group_limitation`].
///
/// [`Stage::Sanitizer`]: report::gating_rule::Stage::Sanitizer
fn settle_sanitizer_groups(
    settled: Settled,
    check: &Check,
    sanitizers: Option<&report::SanitizerWords>,
) -> Settled {
    match report::sanitizer_group_limitation(check, settled.verdict, sanitizers) {
        Some(limit) => Settled {
            verdict: limit.rule.verdict(),
            level: published_level(limit.rule.verdict(), None),
            gating: Some(limit),
        },
        None => settled,
    }
}

/// `lto-codegen-at-link` over what [`settle_sanitizer_groups`] left: the rule of
/// [`Stage::Lto`], on `on` alone, where the measured compile's LTO words ([`measured_lto`])
/// leave link-time optimization in effect under a driver that is not gcc. See
/// [`report::lto_codegen_limitation`].
///
/// [`Stage::Lto`]: report::gating_rule::Stage::Lto
fn settle_lto_codegen(
    settled: Settled,
    check: &Check,
    kind: toolchain::Kind,
    lto: Option<&report::LtoWords>,
) -> Settled {
    match report::lto_codegen_limitation(check, settled.verdict, kind, lto) {
        Some(limit) => Settled {
            verdict: limit.rule.verdict(),
            level: published_level(limit.rule.verdict(), None),
            gating: Some(limit),
        },
        None => settled,
    }
}

/// What the compile-input comparison found for one probe: a difference between the
/// measured compile's listing and the stand-in under the profile's words, which withholds
/// every listed check of the probe; and, per class of optimisation words the arms carry, a
/// difference the driver makes with the level between the stand-in and a listing at that
/// class's level, which withholds the checks whose arms are in the class.
/// [`CompileInputsUnmatched::for_check`] answers for one check.
#[derive(Debug, Default)]
struct CompileInputsUnmatched {
    whole: Option<String>,
    by_class: Vec<(Vec<String>, String)>,
    /// Where the measured compile's exception model is not the arms'
    /// ([`crate::compile_inputs::exception_model_difference`]), or why it could not be told:
    /// the one sentence a check in [`report::EXCEPTION_MODEL_READINGS`] is withheld by.
    exception_model: Option<String>,
}

impl CompileInputsUnmatched {
    /// The sentence that withholds `check`, if any: the whole probe's, or the first of the
    /// check's arm classes ([`arm_optimization_classes`]) the driver answers otherwise
    /// than the stand-in.
    fn for_check(&self, check: &Check, ctx: &Conditions<'_>, lang: Lang) -> Option<&str> {
        if report::EXCEPTION_MODEL_READINGS.contains(&check.id) {
            return self.exception_model.as_deref();
        }
        if let Some(whole) = &self.whole {
            return Some(whole);
        }
        arm_optimization_classes(check, ctx, lang)
            .into_iter()
            .find_map(|class| {
                self.by_class
                    .iter()
                    .find(|(words, _)| *words == class)
                    .map(|(_, why)| why.as_str())
            })
    }
}

/// The distinct optimisation-word classes of a check's arms: the `-O` words of its
/// positive and negative lists (none for a check whose controls carry no `-O`, the fortify
/// controls' `-O2`, `optimization-enabled`'s `-O2` and `-O0`), and the regime arm's where
/// one is owed, which are the profile's words followed by the arm's own.
fn arm_optimization_classes(check: &Check, ctx: &Conditions<'_>, lang: Lang) -> Vec<Vec<String>> {
    let mut classes: Vec<Vec<String>> = Vec::new();
    let mut push = |words: Vec<String>| {
        if !classes.contains(&words) {
            classes.push(words);
        }
    };
    push(crate::compile_inputs::optimization_words(&control_flags(
        check.positive,
    )));
    push(crate::compile_inputs::optimization_words(&control_flags(
        check.negative,
    )));
    if let Some(arm) = check
        .regime_arm()
        .filter(|_| check.owes_regime_control(ctx.profile_is_clean))
    {
        push(crate::compile_inputs::optimization_words(&variant_flags(
            ctx.profile,
            lang,
            arm,
        )));
    }
    classes
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
/// `_GLIBCXX_ASSERTIONS`, `_GLIBCXX_NO_ASSERTIONS`, `_LIBCPP_HARDENING_MODE`). A driver that
/// adds one of them with the optimisation level asks for what the controls set for
/// themselves, which the checks that read it control and the others do not read (the
/// register entry `optimization-level-defaults-decide-only-their-own-checks`, whose test
/// holds the entry's text to this set).
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
/// words in another order or number differ too (fix check 1 found the words-only-on-one-side
/// reading admitting a reordered pair).
fn level_bound_difference(
    (stand_in, stand_in_flags): (&crate::compile_inputs::CompileInputs, &[String]),
    (at_class, class_flags): (&crate::compile_inputs::CompileInputs, &[String]),
    owned: &BTreeSet<String>,
) -> Option<String> {
    let differing = crate::compile_inputs::differences(stand_in, at_class);
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

/// Whether the measured build's compile and the arms' read other headers or predefined
/// macros, as [`CompileInputsUnmatched`]: a sentence naming the difference for the whole
/// probe, one per class of arm optimisation words, or neither where the driver names the
/// same inputs or the probe has nothing to compare.
///
/// Compared only where it can decide something: a profile adding flags, and a check of the
/// probe in [`report::COMPILE_INPUT_READINGS`] that reads the measured build. The measured
/// listing is taken under [`variant_flags`], the stand-in under [`clean_flags`] (the target
/// and runtime selection every arm carries on every channel) and the header selection the
/// arms carry too ([`crate::toolchain::header_selecting_flags`]), followed by the profile's own
/// optimisation words ([`crate::compile_inputs::optimization_words`]) and its `-D` and
/// `-U` words ([`crate::compile_inputs::macro_words`]; the module note says why each is
/// carried), each over an empty input of the probe's language; a difference there
/// withholds every listed check. Where they match, one listing per distinct class of
/// optimisation words the listed checks' arms carry ([`arm_optimization_classes`]), other
/// than the profile's own, is compared with the stand-in ([`level_bound_difference`]):
/// what the driver changes with the level reached the measured compile and the stand-in
/// and not the arms at another level, and withholds their checks, unless it is only a
/// macro the controls set themselves. A listing that cannot be read withholds as a
/// difference does. Two `-###` runs per probe that compares, and one more per class
/// (`toolchain-macros` has three: none, `-O2`, `-O0`), over the nine probes of the corpus
/// that hold a listed check: `toolchain-macros`, `exceptions`, `fortify-printf-flag`,
/// `fortify-known-object`, `fortify-dynamic-object`, `fortify-subobject`,
/// `fortify-percent-n`, `strict-flex-arrays-enforced` and, in C++, `cxx-stdlib-assertions`.
fn unmatched_compile_inputs(
    driver: &Driver<'_>,
    probe: &Probe,
    ctx: &Conditions<'_>,
) -> CompileInputsUnmatched {
    let listed: Vec<&Check> = probe
        .checks
        .iter()
        .filter(|c| {
            (report::COMPILE_INPUT_READINGS.contains(&c.id)
                || report::EXCEPTION_MODEL_READINGS.contains(&c.id))
                && !c.measures_toolchain_default
        })
        .collect();
    if listed.is_empty() || ctx.profile_is_clean {
        return CompileInputsUnmatched::default();
    }
    let whole = |why: String| CompileInputsUnmatched {
        whole: Some(why.clone()),
        by_class: Vec::new(),
        exception_model: Some(why),
    };
    let program = match driver.driver_for(probe.lang) {
        Ok(program) => program,
        Err(why) => return whole(format!("chard found no driver to ask ({why:#})")),
    };
    let language = match probe.lang {
        Lang::C => "c",
        Lang::Cxx => "c++",
    };
    let measured_flags = variant_flags(ctx.profile, probe.lang, &[]);
    let measured = match crate::compile_inputs::query(program, &measured_flags, language) {
        Ok(inputs) => inputs,
        Err(why) => return whole(format!("for the measured build, {why}")),
    };
    let selection = stand_in_selection(ctx.profile, probe.lang, &measured_flags);
    let profile_words = crate::compile_inputs::optimization_words(&measured_flags);
    let macro_words = crate::compile_inputs::macro_words(&measured_flags);
    let flags_at = |words: &[String]| -> Vec<String> {
        selection
            .iter()
            .chain(words.iter())
            .chain(macro_words.iter())
            .cloned()
            .collect()
    };
    let stand_in_flags = flags_at(&profile_words);
    let stand_in = match crate::compile_inputs::query(program, &stand_in_flags, language) {
        Ok(inputs) => inputs,
        Err(why) => return whole(format!("for the arms' selection, {why}")),
    };
    let exception_model = crate::compile_inputs::exception_model_difference(&measured, &stand_in)
        .map(|d| {
            format!(
                "the driver's -### listing for the measured compile ({}) and for the arms' \
                 selection ({}) differ: {d}",
                measured_flags.join(" "),
                stand_in_flags.join(" ")
            )
        });
    if let Some(d) = crate::compile_inputs::difference(&measured, &stand_in) {
        return CompileInputsUnmatched {
            whole: Some(format!(
                "the driver's -### listing for the measured compile ({}) and for the arms' \
                 selection with the profile's own optimisation and macro words ({}) differ: \
                 {d}",
                measured_flags.join(" "),
                stand_in_flags.join(" ")
            )),
            by_class: Vec::new(),
            exception_model,
        };
    }
    let owned = macros_the_controls_set();
    let mut classes: Vec<Vec<String>> = Vec::new();
    for check in &listed {
        for class in arm_optimization_classes(check, ctx, probe.lang) {
            if class != profile_words && !classes.contains(&class) {
                classes.push(class);
            }
        }
    }
    let mut by_class = Vec::new();
    for class in classes {
        let class_flags = flags_at(&class);
        let why = match crate::compile_inputs::query(program, &class_flags, language) {
            Ok(at_class) => level_bound_difference(
                (&stand_in, &stand_in_flags),
                (&at_class, &class_flags),
                &owned,
            ),
            Err(why) => Some(format!(
                "for the arms at their own optimisation level ({}), {why}",
                class_flags.join(" ")
            )),
        };
        if let Some(why) = why {
            by_class.push((class, why));
        }
    }
    CompileInputsUnmatched {
        whole: None,
        by_class,
        exception_model,
    }
}

/// The selection the arms' stand-in listing is taken under
/// ([`unmatched_compile_inputs`]), ahead of the profile's optimisation and macro words: the
/// clean build's ([`clean_flags`]) and the header selection the arms carry beside it
/// ([`crate::toolchain::header_selecting_flags`]). What a macro arm of a check that reads
/// the measured build carries before its own flags ([`arm_flags`]), which
/// `tests::the_stand_in_selection_is_what_the_arms_carry` holds; the comparison is never
/// run for a default-asking check, whose arms carry less.
fn stand_in_selection(profile: &Profile, lang: Lang, measured: &[String]) -> Vec<String> {
    let mut selection = clean_flags(profile, lang);
    selection.extend(crate::toolchain::header_selecting_flags(measured));
    selection
}

/// The measured compile's sanitizer words
/// ([`crate::compile_inputs::CompileInputs::sanitizers`]) for a probe holding a check in
/// [`report::SANITIZER_GROUP_CHECKS`]: `None` for any other probe; `Err` where the listing
/// could not be read, which [`report::sanitizer_group_limitation`] publishes as unknown. One
/// `-###` run for the one probe of the corpus that reads it, under [`variant_flags`] as the
/// measured build is. Asked under the clean profile too, as [`measured_lto`] is. One might
/// argue the clean profile needs no listing, since a sanitizer a driver's configuration
/// file adds reaches the control arms too and confounds the triple rather than this rule.
/// That holds for a group the probe can show and not for one it cannot: a driver that adds
/// `-fsanitize=return -fsanitize-trap=return` by itself leaves the forced-on arm trapping,
/// the forced-off arm calling handlers and the measured build silent, so the triple
/// discriminates and, unlisted, the `bare` cell reads `off` (gcc 13.3.0, measured), the
/// shape this rule exists for. Under the clean profile the words are the
/// driver's own, which is what the reason then quotes.
fn measured_sanitizers(
    driver: &Driver<'_>,
    probe: &Probe,
    ctx: &Conditions<'_>,
) -> Option<report::SanitizerWords> {
    probe
        .checks
        .iter()
        .find(|c| report::SANITIZER_GROUP_CHECKS.contains(&c.id))?;
    let program = match driver.driver_for(probe.lang) {
        Ok(program) => program,
        Err(why) => return Some(Err(format!("chard found no driver to ask ({why:#})"))),
    };
    let language = match probe.lang {
        Lang::C => "c",
        Lang::Cxx => "c++",
    };
    let flags = variant_flags(ctx.profile, probe.lang, &[]);
    Some(
        crate::compile_inputs::query(program, &flags, language)
            .map(|inputs| inputs.sanitizers)
            .map_err(|why| format!("for the measured build, {why}")),
    )
}

/// The measured compile's link-time-optimization words
/// ([`crate::compile_inputs::CompileInputs::lto`]) for a probe holding a check in
/// [`report::LTO_CODEGEN_CHECKS`]: `None` for any other probe and for gcc, whose link the
/// rule does not ask about (so no `-###` run is spent on it); `Err` where the listing could
/// not be read, which [`report::lto_codegen_limitation`] publishes as unknown. Asked under
/// the clean profile too, unlike [`measured_sanitizers`]: a configuration file the driver
/// loads by itself reaches the measured build and the arms alike, the triple then
/// discriminates on a build that is under LTO, and this rule is the only one left to say so.
fn measured_lto(
    driver: &Driver<'_>,
    probe: &Probe,
    ctx: &Conditions<'_>,
) -> Option<report::LtoWords> {
    probe
        .checks
        .iter()
        .find(|c| report::LTO_CODEGEN_CHECKS.contains(&c.id))
        .filter(|_| ctx.toolchain_kind != toolchain::Kind::Gcc)?;
    let program = match driver.driver_for(probe.lang) {
        Ok(program) => program,
        Err(why) => return Some(Err(format!("chard found no driver to ask ({why:#})"))),
    };
    let language = match probe.lang {
        Lang::C => "c",
        Lang::Cxx => "c++",
    };
    let flags = variant_flags(ctx.profile, probe.lang, &[]);
    Some(
        crate::compile_inputs::query(program, &flags, language)
            .map(|inputs| report::LtoListing {
                lto: inputs.lto,
                relocation: inputs.relocation,
            })
            .map_err(|why| format!("for the measured build, {why}")),
    )
}

/// Put the macro channel's provenance beside a macro-channel observation's evidence.
///
/// Both fields, and for every macro-channel verdict including a withheld one: the
/// dump's record is what makes the cell re-derivable by hand, and the source says
/// whether `macros` is the artifact's own testimony or the preprocessor's. Nothing is
/// attached on the other channels, where the dump was never consulted and would sit
/// beside a verdict it had no part in.
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
///
/// The record's `stdout` is the dump, some 3,000 `#define` lines and 200 KB on either
/// compiler family, and a macro-channel observation carries the record so a reader can
/// re-run the job and see how it ended. Carried whole, one probe's eight macro-channel
/// cells put 1.7 MB of defines beside 8 KB of report, measured on Apple clang 17 under
/// `bare`; the trimmed map in `evidence.macros` and the toolchain-level dump under
/// `--emit-macros` are where the defines are read from. The count is kept because it
/// is the one fact about the output a failed dump's reader needs: a dump that exited 1
/// after 882 lines is the truncated-prefix case, and one that exited 1 after none is a
/// job that never started.
///
/// The `Variant`'s own record is untouched: `compile::macro_dump` parsed the defines
/// out of it, and a test that reads them back reads the original.
///
/// `stdout_sha256` is the digest of the dump's lines sorted ([`compile::dump_digest`]), the
/// key of its `macro-dump` entry in the report's store ([`dump_fact`]), so the replaced
/// stream is still named by its content.
fn published_dump_record(record: &compile::BuildRecord) -> compile::BuildRecord {
    let defines = define_lines(&record.stdout);
    let mut published = record.clone();
    published.stdout_sha256 = Some(dump_key(record));
    published.stdout = format!(
        "<{defines} #define line(s) omitted; evidence.macros carries the filtered map \
         and --emit-macros keeps the toolchain-level dump>"
    );
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
///
/// The reason names the artifact's path, and the entry is keyed by the artifact's bytes,
/// so the path is replaced by `<artifact>` before the work directory is made relative:
/// two builds that wrote equal bytes under two names are one entry with one reason. A
/// digest with neither facts nor a reason is not reachable from [`Driver::gather`], which
/// reads every artifact it digests, and yields no entry, so the observation naming it
/// fails `fact-store-disagrees-with-references` rather than reading as a fact.
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
///
/// The defines are filtered through [`relevant_macros`], the same filter the observation's
/// inline `evidence.macros` passes through, and the entry names the filter's digest.
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

/// The failed build's exit status and the compiler's first line, or `None` where the
/// variant's build succeeded or none was taken.
///
/// On the macro channel this is the measured build's reason too, not only an arm's: a
/// macro check whose build failed withholds as `build-failed` beside a dump that succeeded
/// (`Variant::sufficient_for`), and the dump has no failure of its own to name.
fn build_failure_reason(variant: &Variant) -> Option<String> {
    variant
        .build
        .as_ref()
        .and_then(|b| b.failure(variant.workdir.as_deref()))
        .map(|ended| format!("the build {ended}"))
}

/// Why `variant` cannot answer `channel`, as one line, or `None` when it can.
///
/// The reason a control arm publishes as its `detail` when it could not be evaluated.
/// Each channel's failure has its own record: the macro channel's is the dump's own
/// failure, the runtime channel's is the run that could not be spawned or the build
/// that produced nothing to run, the artifact channel's is the read that failed or the
/// build that failed. A verdict alone (`build-failed`) names the class and nothing a
/// reader could act on; the exit status and the compiler's first line are what turn an
/// unevaluable arm into a reproducible one.
fn unevaluable_reason(variant: &Variant, channel: Channel) -> Option<String> {
    let withheld = variant.sufficient_for(channel).err()?;
    let build_failure = || build_failure_reason(variant);
    let reason = match channel {
        Channel::Macro => variant.macro_dump_failure().or_else(build_failure),
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
///
/// A libc that is known not to implement the mechanism, *and* whose positive control just
/// demonstrated it, gets `unsupported` rather than `probe-invalid`. Decided here rather
/// than in `applicability` so the claim rests on the forced flag producing nothing, not on
/// the libc's name: Alpine is musl and does fortify, via fortify-headers, so a name-based
/// gate reported a hard limitation for a system that has none. The compiler family earns
/// it the same way — gcc-only options such as `-Wtrampolines` and `-Wbidi-chars` have no
/// clang equivalent, so clang declines nothing and `off` would misread a missing mechanism
/// as a distribution's choice.
///
/// A rule rather than two inline branches, and for the reason `published_level` is one.
/// The `probe-invalid` precondition is currently *implied* by its own body: both
/// limitations fire only when the positive control read `absent`, an arm that read absent
/// cannot discriminate, and `decide` returns `probe-invalid` for everything that does not.
/// So no measurement on any toolchain can distinguish this guard from its absence, and an
/// integration test cannot pin it — the same situation `published_level` describes, where
/// one was written and passed with the rule deliberately broken. Written as a total
/// function, a test can hand it the pair `decide` never produces.
///
/// Kept rather than deleted as provably redundant, because deleting it would make
/// correctness depend on `plain_controls` never reporting a discriminating triple whose
/// positive arm was absent — a coupling across two modules that nothing states.
///
/// libc first, compiler second, and at most one: `or_else` is what stops a libc reason
/// being overwritten by a compiler one, which the sequential form arranged by side effect
/// through a `verdict == ProbeInvalid` re-test that was already false by then.
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
///
/// The `arms` column of [`report::gating_rule::ALL`] states which builds a rule reads. For
/// the declared family that is a claim about which of these fields its construction site
/// is handed, and [`declared_gating`] receives nothing of the triple but this value, so
/// the claim is one a test can hold: `every_declared_rule_reads_the_arms_its_row_names`
/// fires each rule, blanks every arm its row does not name and asserts the rule still
/// fires, then blanks each arm it does name and asserts it no longer does. The regime arm
/// is absent because no declared rule reads it.
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
    /// Whether the kernel executed the arm's artifact itself (`env::runs_natively` over its
    /// `elf.machine`, class and byte order and the kernel's own machine and order); `None`
    /// where no artifact was read, the kernel's family or byte order is unknown, or the
    /// artifact's record carries no byte order. `report::machine_lacks_shadow_stack` reads
    /// it: under qemu-user the emulator, not the machine, answers the probe's questions.
    native: Option<bool>,
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
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per build the declared family reads, and the kernel they ran on"
    )]
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
                native: positive.elf.as_ref().and_then(|e| {
                    crate::env::runs_natively(kernel, &e.machine, e.elf_class, e.elf_data)
                }),
            },
            negative: NegativeReading {
                rejection: negative
                    .and_then(|v| v.build.as_ref())
                    .and_then(|b| control_flag_rejection(b, check.negative)),
                outcome: negative.and(controls.negative.outcome),
                refusal: negative
                    .and_then(|v| v.run.as_ref())
                    .and_then(crate::decode::runtime::loader_refusal)
                    .map(str::to_owned),
                native: negative.and_then(|v| v.elf.as_ref()).and_then(|e| {
                    crate::env::runs_natively(kernel, &e.machine, e.elf_class, e.elf_data)
                }),
            },
            clean: probe::cxx_stdlib(evidence_for(clean).macros),
            measured: probe::cxx_stdlib(evidence_for(measured).macros),
        }
    }
}

/// The declared family, in the order it is consulted; the first that fires is the
/// reason.
///
/// Declared limitations first, the compiler's own statement second: where both apply the
/// existing reason is the more specific one, and the second only has to catch what the
/// first declines. Every member declines any verdict but `probe-invalid`.
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
///
/// Every check but one reads the measured build, because the profile's flags are what is
/// being measured. A check asking what the toolchain does when *nothing* was passed has
/// to read a build that passed nothing — see [`Check::measures_toolchain_default`], where
/// the false `on` this rule exists to stop is recorded.
///
/// A function rather than an `if` inline, so a test can put both checks through it: the
/// selection is invisible in a report, and the arms of the control triple carry none of
/// the profile's hardening either way, so nothing downstream would notice it silently
/// reverting. The clean build and the arms are built for the same target
/// ([`clean_flags`]), so the triple vouches for the artifact this reads.
fn subject_variant<'a>(check: &Check, clean: &'a Variant, measured: &'a Variant) -> &'a Variant {
    if check.measures_toolchain_default {
        clean
    } else {
        measured
    }
}

/// The reading a variant gives `check`: its decoder's, through [`Check::decode`], with the
/// cut gate a code decoder needs applied after it.
///
/// A predicate carries its own gate: its `@truncated` preamble reads the variant's
/// `truncations` before any clause, so a reading over a table the reader could not finish
/// is `indeterminate`, and its sentence names the unread tables. A code decoder has no
/// preamble, and [`withhold_unreadable`] replaces its detection instead. Either way the
/// replacement reaches `decide` on a control arm as an indeterminate detection, and
/// `decide` withholds `probe-invalid` through the arm's own cause; on the measured build
/// [`artifact_gating`] turns the reading into `indeterminate` under `artifact-unreadable`.
/// The arm's `ElfFacts` are in the report's store, `truncations` included, where the arm's
/// check reads artifacts.
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
/// variant's artifact was cut on a table the check reads.
///
/// Applied to every arm and to the measured build alike, through [`reading`], and to code
/// decoders alone: the macro and elf-static predicates carry the same gate as their
/// `@truncated` preamble. The replacement
/// carries the reason first and the detector's own reading after it, so a `?` cell in
/// `table` (which prints `evidence.observed`) and a withheld arm's `detail` both say which
/// table was cut and what the detector made of the bytes that were there.
///
/// A runtime check's run whose output was cut, unreadable or ended by chard's deadline is
/// withheld here the same way, for the reason [`runner::RunRecord::stream_cut`] gives, and
/// on the measured build [`settle`] names `run-deadline-elapsed` or
/// `run-output-unreadable`. The table comes first where both apply, so
/// one sentence leads rather than two.
fn withhold_unreadable(
    check: &Check,
    variant: &Variant,
    detection: probe::Detection,
) -> probe::Detection {
    match report::truncated_reading(check, variant.elf.as_ref())
        .or_else(|| report::cut_stream_reading(check, variant.run.as_ref()))
    {
        None => detection,
        // The detector's rule does not survive the cut: the reading is now the cut's, and
        // the run gate names its own rule over it.
        Some(why) => probe::Detection {
            outcome: probe::Outcome::Indeterminate,
            level: None,
            observed: format!("{why}; the detector read: {}", detection.observed),
            rule: None,
        },
    }
}

/// The five gates on the artifact the detector read, in the order that keeps them apart.
///
/// The truncation gate runs first, the slim-LTO gate (`report::lto_ir_limitation`) second,
/// the self-report gate (`report::self_report_limitation`, the macro channel's, over an
/// artifact the reader parsed; `settle_self_report_unread` takes one it did not) third,
/// the link-mode gate (`report::link_mode_limitation`, an executable link whose artifact
/// classifies as a shared object, read against `link_mode`, the probe's own, and against
/// `read`, the fields this reading rested on) fourth, and the precondition last. The
/// link-mode gate precedes the precondition because both read the link classification, and
/// where it contradicts the probe's request the precondition's answer rests on it too. The
/// precondition follows the truncation gate
/// because the precondition reads `pie`, `has_dynamic` and `shared_object`, every one
/// derived from `.dynamic`: a `.dynamic` the reader could not finish empties them, and the
/// precondition would then call `relro` inapplicable to a section that exists and was cut.
/// `unsupported` is left alone by all five, since it rests on the toolchain's own statement
/// and already carries the rule that earned it. A `probe-invalid` is left alone too: its
/// controls carry the cause, and where the arm that failed was itself cut on a read table,
/// its `detail` names the table through [`withhold_unreadable`]. When the truncation,
/// slim-LTO, self-report or link-mode gate fires on one, it still suppresses the
/// precondition, which does not apply to `probe-invalid` either. Every other verdict, `on`
/// and `partial` included, becomes `indeterminate`, for the reason the gate that fired
/// gives.
fn artifact_gating(
    verdict: Verdict,
    check: &Check,
    link_mode: probe::LinkMode,
    reading: probe::Outcome,
    elf: Option<&elf::ElfFacts>,
    read: &std::collections::BTreeSet<crate::predicate::ElfField>,
) -> Option<(Verdict, report::Gating)> {
    if verdict == Verdict::Unsupported {
        return None;
    }
    if let Some(gating) = report::truncation_limitation(check, elf) {
        return (verdict != Verdict::ProbeInvalid).then_some((gating.rule.verdict(), gating));
    }
    // A slim LTO object is consulted second: a cut symbol table is the first gate's to
    // name, and a precondition read over an object with no generated code would rule on
    // facts the final link has not produced yet.
    if let Some(gating) = report::lto_ir_limitation(check, elf) {
        return (verdict != Verdict::ProbeInvalid).then_some((gating.rule.verdict(), gating));
    }
    // A macro-channel reading over an artifact that carries no readable `.chard.report`
    // is the dump's, consulted third: it reads the artifact's own account, as the two
    // above do, and a `probe-invalid` is left to its controls as they leave it.
    if let Some(gating) = report::self_report_limitation(check, elf) {
        return (verdict != Verdict::ProbeInvalid).then_some((gating.rule.verdict(), gating));
    }
    // An executable link whose artifact classifies as a shared object is consulted before
    // the precondition, whatever the reading: the `relative-relocs` and `nodlopen` rows read
    // the same classification.
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
///
/// One value, because the split and the two selections are one fact about the report: a
/// C++ side exists exactly when `linker.cxx` does, and a caller cannot hand
/// [`artifact_comments`] a split without the selection that side was detected under.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkSelections<'a> {
    pub c: &'a [String],
    pub cxx: Option<&'a [String]>,
}

/// The artifacts the observations carry facts for, as the witnesses
/// `toolchain::artifact_agreement` holds the linker to: the C++ probes' apart when
/// `selections.cxx` is present, every other probe's first.
///
/// Beside [`subject_variant`] because it reads that choice back. An observation's
/// `build.artifact_sha256`, and the facts `facts` holds under it
/// ([`report::FactStore::measured_elf_of`], so only observations that built their control
/// triple), describe the build its verdict was read from: the measured build, or the clean build for a check that
/// `measures_toolchain_default`. That clean artifact is labelled `clean` under every
/// profile, since the label says which build was read. When the side's link line
/// selected a linker program (`-fuse-ld=` or `--ld-path=`, as
/// [`toolchain::linker_program_flags`] reads them) it was linked under the driver's
/// default link line and the selected linker had no part in it, so it is marked
/// `profile_free` for the count to leave out and
/// the evidence to name beside the selection. Under a profile whose flags select no
/// linker, `bare-optimized` or `openssf-tldr` among the built-in ones, both builds go
/// through the same link line and the artifact is a witness like any other; left out, a
/// run of that one probe under a lying lld banner read as nothing measured. The checks of
/// one probe share one artifact, so entries are keyed by digest and each artifact is read
/// once. The label names the probe, the variant and a prefix of the digest, so a reader
/// can find the full record without the evidence carrying a work-directory path.
/// Relocatables and unread `.comment` sections are marked, and every probe that
/// contributed no artifact is named, so the count published can be judged against the
/// selection that produced it.
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
///
/// Sibling of [`unknown_flag_limitation`], on the other arm. That rule fires when the
/// flag under test is unknown, so the hardened state cannot be constructed; this one
/// fires when the control that constructs the *unhardened* state is unknown, so absence
/// can never be demonstrated and the triple has nothing to compare against.
///
/// `no-copy-dt-needed` on lld is the case that produced it. lld takes
/// `--no-copy-dt-needed-entries` and refuses `--copy-dt-needed-entries` outright — it has
/// no mode in which it copies a `DT_NEEDED`, so the behaviour the flag asks for is the
/// only behaviour it has. Without the rule both BSD lanes publish `probe-invalid` for that:
/// chard's instrument reported as broken by a linker that cannot be put into the state the
/// check is defined against.
///
/// Rests on the linker's own statement, for the reason [`unknown_flag_limitation`] gives:
/// a list of which linkers implement which options would be chard's belief, and the
/// diagnostic is the tool's account of itself.
///
/// The premise is a limit of chard's instrument, and the rule's class says so
/// (`report::gating_rule::Premise::InstrumentLimitation`). `unsupported` would tell a reader
/// that lld lacks a mechanism lld has permanently on, and would settle `--fail-on-missing`
/// over a check chard never measured. The
/// statement the rejection does support is that a one-state flag cannot be put through a
/// two-state triple here; a cell that accepts that withholding lists it in
/// `tests/sweep-expected`.
///
/// Declines a refusal (`rejection_is_a_refusal`): the reason says the driver does not know
/// the flag, and the table row's `Sentence::Unknown` is what `report::consistency` holds
/// the quoted line to. A negative control a driver knows and will not enable is a case no
/// corpus check has; it stays a plain `probe-invalid` until one does and earns a rule of
/// its own. `scaffolding_limitation` declines one for the same reason.
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
             option it does not know, so the unhardened state could not be built and \
             absence was never demonstrable. The toolchain may have no mode without the \
             mechanism, and a triple with no absent arm cannot measure it, so the verdict \
             is withheld rather than blamed on the probe or on the toolchain. The tool \
             said: {rejection}",
            check.flag
        ),
    })
}

/// The gating a linker earns by accepting a keyword it does not implement.
///
/// Third sibling of [`unknown_flag_limitation`] and [`unhardened_state_limitation`], and
/// the quietest of the three: nothing failed, nothing was refused, the link succeeded, and
/// the mechanism simply is not there. `relative-relocs` on binutils below 2.38 is the case
/// — `-z pack-relative-relocs` accepted, warned about, ignored, and no `DT_RELR` in the
/// artifact, which read as chard's instrument failing.
///
/// Rests on the linker's own sentence, quoted into the gating, for the reason its two
/// siblings do. The alternative on offer was the version number, and a version is the
/// explanation for a witness rather than the predicate.
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
             linked anyway — so the mechanism is missing from this linker rather than from \
             the build, and no arm could have shown the observable. A linker that \
             implements it is measured normally instead of gated. The linker said: \
             {rejection}",
            check.flag
        ),
    })
}

/// The gating the C library earns by settling a fortify request below what was asked.
///
/// `-D_FORTIFY_SOURCE=3` is a request, not an instruction. glibc reads it, decides what it
/// can actually install, and writes the answer into `__USE_FORTIFY_LEVEL` — so an artifact
/// built with the flag forced on can carry `_FORTIFY_SOURCE=3` and
/// `__USE_FORTIFY_LEVEL=2` at the same time, which is the C library saying, in its own
/// header macros, that the level this check asserts is not available here. The observable
/// then cannot appear in either arm and the check published `probe-invalid`.
///
/// Both numbers come from the positive arm's own build rather than from a version chard
/// parsed, and both are quoted into the gating so the claim is checkable. The optimization
/// conjunct is not decoration: below `-O1` glibc installs nothing whatever the level says,
/// so an unoptimized arm's settled level is not evidence about the toolchain.
///
/// The retirement condition is the case that would make this wrong: a libc that installs
/// the level-3 checks while reporting a lower `__USE_FORTIFY_LEVEL`. None is known.
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
            "{} was forced on and arrived: the positive control's own artifact reports \
             `_FORTIFY_SOURCE={arrived}`. The C library settled it at \
             `__USE_FORTIFY_LEVEL={settled}`, which is below the level this check asserts, \
             so the observable could not appear in either arm. That is the C library's \
             headers, as the profile selects them, declining the request in their own \
             macros rather than chard failing to measure it.",
            check.flag
        ),
    })
}

/// The gating a C++ standard library earns by keeping its assertions somewhere else: the
/// check is `not-applicable`, since its observable belongs to the other implementation.
///
/// The third axis of [`known_limitation`], and the one that cannot use its evidence: a
/// check whose observable belongs to the other implementation produces `indeterminate` in
/// both arms rather than `absent` in the positive one, so the "forced on and nothing
/// appeared" test never fires and `probe-invalid` is published instead.
///
/// `stdlib` is what the toolchain's own macros say — see [`crate::probe::cxx_stdlib`] —
/// not what the platform suggests, so a libc++ toolchain on Linux and one on a BSD are
/// gated by the same evidence. The declared side of the pair says which implementation
/// *chard's observable* belongs to, which is a fact about the probe rather than a belief
/// about anybody's toolchain.
///
/// That is why the rule's premise is `Inapplicable` rather than a toolchain fact: libc++
/// hardening is real and `cxx-stdlib-assertions` measures it, so `unsupported` would tell a
/// reader the protection was missing.
///
/// The premise holds only when the library is the same in both builds it could be read
/// from. `clean` is the build the control arms share a footing with, profile-free but for
/// the target and the runtime ([`clean_flags`]), and `measured` is the
/// build the verdict is about. Where the two still name different libraries the pair stays
/// `probe-invalid`, which is what it is: the triple could not discriminate for the library
/// that was measured, and nothing about that is inapplicable. A profile selecting the other
/// library (`-stdlib=libstdc++` on a clang whose default is libc++) is not that case: the
/// selection reaches `clean` and every arm ([`crate::toolchain::runtime_selecting_flags`]),
/// so the controls pose the question for the library the measured build used. That is
/// unmeasured: no clang defaulting to libc++ was at hand, nor libc++ itself on the Fedora 44
/// host the selection was measured on.
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
            "{} is read through an observable {stdlib} does not have, and {stdlib} is the \
             standard library this toolchain reports using in the measured build and in \
             the controls alike, so neither control arm could \
             move it. The protection it asks about is not absent here — it is measured \
             through that library's own mechanism instead.",
            check.flag
        ),
    })
}

/// The gating a probe's own scaffolding may earn when the platform cannot build it: the
/// verdict is withheld as `indeterminate`, since the question was never posed.
///
/// Distinct from [`unknown_flag_limitation`], which is about the flag under test. This is
/// about the chain a probe needs to *pose* its question: `copy-dt-needed` builds a two-deep
/// shared-library chain with `-soname` and `-rpath-link`, and Apple's linker implements
/// neither. Both arms then fail identically on the scaffolding, the triple cannot
/// discriminate, and the result was `probe-invalid` — chard's probe blamed for a platform
/// whose object format has no `DT_NEEDED` for the flag to govern in the first place.
///
/// Deliberately keyed on the linker saying it does not know the harness's own flags rather
/// than on the object format, because chard does not otherwise ask what format a host
/// produces, and a Mach-O-shaped guess would be a second place for that belief to live.
///
/// The premise is a limit of chard's instrument: the probe's chain did not build, and
/// that says nothing about the flag under test. `unsupported` would settle
/// `--fail-on-missing` over a check chard never posed.
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
            "{} is measured by building a chain of shared libraries and asking the linker \
             to resolve through it, and this toolchain rejected the flags that build the \
             chain, so the probe could not be posed here and the verdict is withheld. \
             The linker said: {rejection}",
            check.flag
        ),
    })
}

/// The gating a compiler's own "I do not know that flag" may substitute for a `probe-invalid`.
///
/// [`known_limitation`] already turns some of these into `unsupported`, on the evidence that
/// the flag was forced on and no observable appeared. That evidence is unavailable here.
/// `-Wtrampolines` forced on a clang that has never heard of it produces no observable *and*
/// no canary — the diagnostic channel emits nothing at all — so the positive arm reads
/// `indeterminate` rather than `absent`, and `compiler_limitation` correctly declines.
/// Without this rule the result is `probe-invalid` on clang 22.1.8 for `trampolines-warned`
/// and `hardened-downgrade-warned`: chard reporting its own instrument as broken because the
/// compiler lacks the flag.
///
/// This rule rests on the stronger evidence the other two cannot use: the driver said so, in
/// as many words, on stderr. That is why it does not consult `check.gate.compiler_unsupported`
/// — the declared list is chard's belief about a compiler, and this is the compiler's own
/// statement about itself, which is right even where the list is incomplete or a new release
/// drops a flag it used to have.
///
/// Total, and takes the rejection rather than finding it, for the reason `known_limitation`
/// gives at length: the `probe-invalid` precondition is implied by its own body on every
/// toolchain that exists, so a test must be able to hand it the pair the loop never produces.
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
                "{} was forced on and {compiler} refused to enable it, so the positive \
                 control never applied it and the triple had nothing to discriminate. The \
                 flag exists on this compiler and is gated behind an opt-in the guide does \
                 not ask for, which is why this is not reported as an option the driver \
                 does not know. The driver said: {rejection}",
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
            "{} was forced on and {compiler} reported it as an option it does not know, so \
             the positive control never applied it and the triple had nothing to \
             discriminate — a limitation of this compiler rather than a broken probe. A \
             {compiler} that implements it is measured normally instead of gated. The \
             driver said: {rejection}",
            check.flag
        ),
    })
}

/// Where the linker must look to *follow* a probe's own dependency chain.
///
/// Empty for the probes that have no chain, which is all but one of them. For the one that
/// does, `-rpath-link` is not optional: without it the transitive library cannot be found
/// in either arm, both fail identically, and a flag working perfectly reads as a control
/// that could not discriminate — which is how `no-copy-dt-needed` first measured as
/// broken.
///
/// A function rather than an inline `if`, because the inline form's negation could be
/// dropped without any test noticing: the flags would then be supplied to every probe that
/// does not need them and withheld from the one that does.
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
///
/// The runtime selection ([`crate::toolchain::runtime_selecting_flags`]), so a chain
/// library links the startup objects and compiler runtime the final link does;
/// the header selection ([`crate::toolchain::header_selecting_flags`]) beside it, so the
/// chain compiles against the headers the final build does.
///
/// The target selection, system root included
/// ([`crate::toolchain::target_selecting_flags`]), because a library built for another
/// target cannot be linked at all. Measured on 2026-09-30 under `-m32` on an x86_64 driver,
/// in a Fedora 44 x86_64 container with glibc-devel.i686, with the chain built for the
/// driver's default target whatever the arm's: every `no-copy-dt-needed` link was refused
/// with ld's "skipping incompatible `libchard_dt_a.so`", for gcc 16.2.1 and clang 22.1.8.
///
/// The linker selection, because the driver's default linker may not emit the target at
/// all: its program flags ([`crate::toolchain::linker_program_flags`]), since its prefixes
/// belong to the runtime selection. Measured on 2026-09-30 on Fedora 44 x86_64, in a
/// `fedora:44` container with clang 22.1.8 and lld 22.1.8, with the chain linked by the
/// default linker whatever the arm selected, under
/// `--target=aarch64-linux-gnu --sysroot=ROOT -fuse-ld=lld` over a root exported from the
/// arm64 `fedora:44` image, every chain link ran `/usr/bin/ld.bfd`, which refused it with
/// "unrecognised emulation mode: aarch64linux", and `no-copy-dt-needed` read
/// `probe-invalid` over arms that each carried `-fuse-ld=lld`. Neither selection hardens
/// anything, so the flag under test still belongs to the final link alone.
fn aux_lib_flags(arm: &[String], stem: &str, workdir: &Path) -> Vec<String> {
    let mut flags = crate::toolchain::target_selecting_flags(arm);
    flags.extend(crate::toolchain::runtime_selecting_flags(arm));
    flags.extend(crate::toolchain::header_selecting_flags(arm));
    flags.extend(crate::toolchain::linker_program_flags(arm));
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
///
/// Two conditions and either is enough: a non-zero exit, or an exit of zero with no
/// artifact behind it. The second is not hypothetical — a driver can report success and
/// leave nothing on disk when the output path is unwritable, and the next link in the
/// chain then fails for a reason that has nothing to do with the flag under test.
///
/// Extracted so a test can put both through it. The scaffolding is fixed, so a failure
/// here is a harness fault rather than a measurement, and a predicate that answered `true`
/// for a successful build would report every probe with a chain as broken — while one
/// that required both conditions would let a zero-byte artifact through to the link that
/// depends on it.
fn aux_build_failed(record: &compile::BuildRecord) -> bool {
    !record.succeeded() || record.artifact_sha256.is_none()
}

/// The flags `build_aux_libs` supplies itself, which `scaffolding-unbuildable` recognises
/// the linker refusing.
///
/// Named apart from that function because the two lists answer different questions: it
/// passes them, this recognises the linker refusing them. Public so the consistency rule
/// that re-reads a published arm's stderr asks the same question `run_check` asked.
pub const SCAFFOLDING_FLAGS: &[&str] = &["-soname", "-rpath-link", "-shared", "-fPIC"];

/// The `-z` keywords a flag list supplies to the linker.
///
/// `-Wl,-z,pack-relative-relocs` reaches the linker as the pair `-z pack-relative-relocs`,
/// and it is the keyword — not the `-z` — that names the mechanism. [`spellings`] is the
/// wrong instrument here: it yields `-z` and the keyword as separate tokens and
/// [`flag_rejection`] then discards the keyword, because it keeps only tokens beginning
/// with `-`. A rule built on that would match any `-z … ignored` line and name `-z` as the
/// thing the linker did not know, which is a frequency argument wearing a witness's
/// clothes.
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

/// The linker's own sentence saying it took a `-z` keyword and ignored it.
///
/// Distinct from [`control_flag_rejection`], which catches a tool refusing a flag it does
/// not know. This is the quieter case: GNU ld accepts every `-z` it is given, warns
/// `-z <keyword> ignored` for the ones it has no implementation for, and links
/// successfully — so the observable never appears, the arms cannot be told apart, and the
/// check published `probe-invalid` over a linker that had simply never heard of the
/// mechanism. Measured on binutils 2.30, 2.34 and 2.35.2 for `pack-relative-relocs`, all
/// three warning and ignoring, against 2.38 which implements it and says nothing.
///
/// Both spellings the corpus contains: GNU ld's `ignored` (with and without a trailing
/// period, which differs by release) and lld's `unknown -z value`.
///
/// The line must name a keyword *this check's own control supplied*. A warning about some
/// other keyword on the same command line says nothing about this check.
pub fn z_keyword_rejection(build: &compile::BuildRecord, flags: &[&str]) -> Option<String> {
    let supplied = z_keywords(flags);
    build.stderr.lines().find_map(|line| {
        let lower = line.to_lowercase();
        let ignored = lower.contains("ignored") || lower.contains("unknown -z value");
        (ignored && supplied.iter().any(|k| line.contains(k))).then(|| line.trim().to_owned())
    })
}

/// Every spelling a tool may name `flag` by: as written, and — where the driver hands it
/// on — the pieces the linker actually sees.
///
/// `-Wl,--copy-dt-needed-entries` reaches lld as `--copy-dt-needed-entries`, and lld says
/// `unknown argument '--copy-dt-needed-entries'` with no `-Wl,` anywhere in the line. Both
/// rejection rules match a rejected token against flags chard supplied, so without this
/// they compare the driver's spelling against the linker's and find nothing.
///
/// Shared by [`profile_flag_rejection`] and [`control_flag_rejection`] rather than written
/// twice: if one expanded and the other did not, a control flag the linker refused by its
/// bare name would go unrecognised, and `no-copy-dt-needed` would read `probe-invalid` on
/// both BSD lanes, the case `unhardened_state_limitation` exists to catch.
fn spellings(flag: &str) -> impl Iterator<Item = &str> {
    std::iter::once(flag).chain(
        flag.strip_prefix("-Wl,")
            .into_iter()
            .flat_map(|rest| rest.split(',')),
    )
}

/// Did the toolchain reject a flag the *profile* supplied, rather than one this check owns?
///
/// Two independent signals have to agree, which is what keeps this from labelling every
/// build failure a profile problem. The tool has to say it did not recognise something —
/// `ld: unknown options:`, GNU ld's `unrecognized option`, lld's `unknown argument` — **and**
/// a token on that line has to be a flag chard passed from the profile. Either alone is
/// weak: the phrase appears in messages about input files, and a profile flag appears in
/// almost every diagnostic simply because it was on the command line.
///
/// `-Wl,-z,relro` is expanded before matching, because the driver splits it and the linker
/// reports the pieces: Apple's `ld` names `-z`, never `-Wl,-z,relro`. That expansion is why
/// the match is on tokens rather than on the flag string as written.
///
/// Returns `None` when either signal is missing, which leaves the plain `build-failed` a
/// probe's own broken recipe deserves.
///
/// Only a line on which the tool stopped counts here ([`Lines::Refusals`]): a `warning:`
/// or `note:` line naming a profile flag is a flag the driver went on without, and a build
/// that then failed for its own reasons did not fail for the flag. clang warns about an
/// unknown `-W` option and compiles on; gcc accepts an unknown `-Wno-` option and prints a
/// `note:` naming it only when another diagnostic was emitted. Either line beside a build
/// the probe's own observable failed (an `-is-error` check reads a failed build as
/// present) attributed the failure to the profile, and on the compiler-diagnostic channel
/// that withheld a true reading. The control-flag reader keeps every line
/// ([`control_flag_rejection`] says why).
pub fn profile_flag_rejection(build: &compile::BuildRecord, profile: &Profile) -> Option<String> {
    profile_flag_refusal(build, profile).map(|refusal| refusal.sentence)
}

/// A profile flag the toolchain refused, as [`profile_flag_rejection`] reads it, with the
/// line it was refused on, the tool and the flags kept apart from the sentence that names
/// them.
///
/// It is read from the first refusal line of the build, the one a cell's `build_rejection`
/// names. A build can refuse more than one profile flag, one line each; [`profile_flag_refusals`]
/// reads them all, and is what `report::profile_flag_rejections` counts a run by.
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
///
/// [`profile_flag_refusal`] stops at the first refusal line, the one a cell's
/// `build_rejection` names. gcc prints one line per unknown option, so a build refusing two
/// profile flags names only the first, and a run-level count over that reader names the
/// second nowhere: `--flags "-O2 -fno-aaa-flag -fno-bbb-flag"` on gcc 16, Fedora 44 x86_64,
/// gives one diagnostic through it, and a fake driver refusing two `openssf-tldr` flags as
/// gcc 9 does the same (measured 2026-10-16). This reads every line with the same rule, so its
/// first entry is that refusal's tool and line.
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
///
/// The same two-signal rule as [`profile_flag_rejection`], pointed at the other source of
/// flags. It answers a different question and earns a different verdict: a profile flag the
/// driver refuses makes the build a `build-failed` chard should not blame on its own recipe,
/// where a *control* flag the driver refuses means the control never applied the thing it
/// was forcing, so the triple could not have discriminated and the check is `unsupported`
/// here rather than `probe-invalid`.
///
/// Not gated on the build having failed. `-Wtrampolines` is unknown to clang and clang says
/// so in a *warning*, exiting 0 — the probe builds, runs, produces no observable, and the
/// only trace that the flag was never in force is the line on stderr.
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
///
/// A line with no severity word (`ld: unrecognized option '--as-needed'`, Apple's `ld:
/// unknown options: -z`) is the tool stopping, and counts as a refusal; so does an `error:`
/// line, including clang's `error: unknown warning option '-Wx' [-Werror,...]`, which is the
/// warning promoted.
fn line_is_a_warning_or_note(line: &str) -> bool {
    line.splitn(4, ':')
        .take(3)
        .map(str::trim)
        .any(|head| head.eq_ignore_ascii_case("warning") || head.eq_ignore_ascii_case("note"))
}

/// The shared half of both rejection rules: a line that says "I do not know this" *and*
/// names one of `supplied`.
///
/// Extracted rather than written twice. The comment the phrase list carries is the argument
/// for one copy: it already records a gap that cost a whole profile column because a spelling
/// was missing from it, and a second list would be a second chance to miss one.
///
/// Returns the rejected flags (sorted and distinct), the tool that said so, and the line
/// it said it on.
/// The phrases that mean a driver knows the flag and declines to enable it, as opposed to
/// never having heard of it.
///
/// A subset of `flag_rejection`'s own list, and the reason the two gating rules are
/// separate: `flag-unknown-to-driver` on a clang 15 would state that the flag does not
/// exist there, which is false. It exists and is gated behind an opt-in the guide does not
/// ask for.
const REFUSED_PHRASES: [&str; 1] = ["hasn't been enabled"];

/// Whether a rejection line is a refusal to enable rather than an unknown flag.
///
/// Public so `report::consistency` can hold a published `flag-refused-by-driver` or
/// `flag-unknown-to-driver` to the line it quotes.
pub fn rejection_is_a_refusal(line: &str) -> bool {
    let lowered = line.to_lowercase();
    REFUSED_PHRASES.iter().any(|p| lowered.contains(p))
}

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
    // Every spelling a driver or linker uses to say it does not know a flag. The two gcc
    // entries are not redundant: gcc 9.4 says "unrecognized command line option" and gcc 16
    // says "unrecognized command-line option", and neither contains "unrecognized option",
    // so the shorter phrase matched neither. That gap cost a whole profile column — on
    // Ubuntu 20.04 under `openssf-tldr`, gcc 9.4 rejects `-fstrict-flex-arrays=3` (a gcc 13
    // flag) and every probe fails to build, which was published as 24 plain `build-failed`
    // observations reading as though chard's own recipes were broken on that toolchain.
    //
    // "unknown warning option" is a seventh for the same reason and was found the same way:
    // clang says it of `-Wtrampolines` and `-Whardened`, and it does not contain "unknown
    // option", so the list matched neither. Measured on clang 22.1.8 / aarch64, where those
    // two checks published `probe-invalid` — chard's instrument accused of being broken by a
    // compiler that had simply never heard of the flag.
    // An eighth, and the only one of the set that is not the driver disowning the flag.
    // clang 13 through 15 know `-ftrivial-auto-var-init=zero` and refuse to enable it:
    // `'-ftrivial-auto-var-init=zero' hasn't been enabled; enable it at your own peril for
    // benchmarking purpose only with '-enable-trivial-auto-var-init-zero-...'`. Measured on
    // Ubuntu 22.04's clang 13.0.1, 14.0.0 and 15.0.7; `=pattern` is accepted by all three,
    // so only the one spelling is gated. Without it the positive control fails to build,
    // nothing claims the failure, and `auto-var-init-active` publishes `probe-invalid` with
    // no rule at all: chard's instrument accused of being broken by a compiler that
    // declined the flag in plain text. Kept apart from the other seven by
    // [`REFUSED_PHRASES`], because a driver that knows a flag and will not enable it is not
    // a driver that has never heard of it, and the two must not publish the same reason.
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
        // the tool *does* know: clang's `unknown warning option '-Wfoo'; did you mean
        // '-Wbar'?` names `-Wbar` as the spelling it would accept. Read whole, the line
        // named `-Wbar` as rejected whenever chard had supplied it, and a control that
        // passed `-Wbar` read as unknown to a driver that had just recommended it.
        // `tests/diag_grammar.rs` drew that stream from its grammar of rejection lines.
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
                            // naming the flag: clang says `unknown warning option
                            // '-Wtrampolines'; did you mean '-Wtrampoline'?`, and the
                            // semicolon left the token as `-Wtrampolines';`, matching
                            // nothing. Trimmed from the ends only, so a flag's own
                            // punctuation is untouched.
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
        // look at the compiler driver or the linker. A severity word is no tool: clang's
        // frontend prints `warning: unknown warning option '-Wtrampolines'` with no prefix,
        // and the reason read `warning does not know -Wtrampolines`.
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
///
/// [`claim_workdir`] says why a run claims the directory and how another run's claim is
/// judged.
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
    /// A claim removed while the run measured, by hand or by a run that misjudged it, means
    /// another run may have shared the directory, so its artifacts may be in this report.
    /// The run refuses rather than publish what it cannot vouch for. This is the backstop
    /// behind [`claim_workdir`]'s judgement: whatever misreads a live claim as gone, the run
    /// whose claim was removed finds out here. It protects that run only: the run that
    /// removed the claim publishes, which is why the judgement withholds where it cannot tell.
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
                    "this run's claim on its work directory, {}, was removed while it measured, \
                     so another run may have shared the directory and its files; nothing is \
                     published; run again with no other chard measure using the directory",
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
///
/// The time namespace is part of the identity because `/proc/<pid>/stat` reports a start
/// time shifted by the reading process's boot-time offset: a run in another time namespace
/// reads a live holder's start time as different, which is how pid reuse reads.
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
///
/// The owner is read first. `/proc` mounted with `hidepid` hides another user's processes,
/// and a live run's claim would then read as a gone one's and be removed, so a claim
/// another user owns, or whose owner cannot be read, is never judged by its process.
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
        return ClaimStanding::Unjudged(
            "it was made under another boot, or on another host sharing the directory",
        );
    }
    if other.namespace != own.namespace {
        return ClaimStanding::Unjudged(
            "it was made in another pid namespace, such as a container sharing the directory",
        );
    }
    if other.clock != own.clock {
        return ClaimStanding::Unjudged(
            "it was made in another time namespace, where process start times read \
             differently",
        );
    }
    standing_from_stat(
        &std::fs::read_to_string(format!("/proc/{}/stat", other.pid)),
        other,
    )
}

/// The standing `/proc/<pid>/stat` (`stat`, as read) gives a claim this system can judge.
///
/// A zombie (`Z`) or a dead task (`X`) is gone: the run exited and only its parent's
/// `wait` is outstanding, which in a container with no init may never come.
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
/// Every probe source, artifact and capture file in a work directory has a fixed name, so
/// two runs sharing one overwrite each other's files mid-run. Measured on Fedora 44
/// x86_64 with gcc 16.1.1 without this claim: a `bare` and an `openssf-tldr` run
/// started together in one directory both exited 0, and some of the `bare` reports
/// published `indeterminate` and `probe-invalid` where a run alone measured `on`, `off`,
/// `partial` or `not-applicable`. Their diagnostics named the symptom (unreadable ELF
/// facts, two facts for one artifact, non-discriminating controls) and nothing named the
/// other run as its cause, and nothing kept an artifact the other run built from being
/// read as this run's.
///
/// Each run creates a file whose name records its holder ([`ClaimHolder`]) with
/// `create_new`, then lists the directory. Of two runs that start together on one local
/// filesystem at least one sees the other's file, because each creates before it lists; both may, and then both
/// refuse, which a retry settles. A claim this user made whose process `/proc` shows gone
/// (a killed run, or a zombie) is removed, with a note, and does not refuse. A claim this system cannot
/// judge refuses, naming the file to remove: without `/proc` (Darwin, the BSDs) a killed
/// run's claim stays until the operator removes it, and so does one made in another pid or
/// time namespace, under another boot or by another user. A live claim is `TRANSIENT`; an
/// unjudged one is `USER_INPUT`, since waiting does not settle it. A run that makes no
/// claim is not seen. [`WorkdirClaim::confirm`] is checked before the report is
/// published, so a run whose claim was removed under it refuses rather than publish.
///
/// The standard library's file locks are newer than the crate's `rust-version`, and a
/// lock through `libc` is outside the crate's dependencies and its `unsafe` rule; a
/// named file is what the floor allows.
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
        // made it (a second claim in one process, as the unit test does), so it is live;
        // without one, a gone process with this pid may have.
        Err(taken) if taken.kind() == std::io::ErrorKind::AlreadyExists => {
            let holder = if own.known() {
                Ok(own.pid)
            } else {
                Err("this system's /proc does not say which processes are alive")
            };
            return Err(claim_refusal(workdir, &path, holder));
        }
        // The claim is the first file a run writes into the work directory, and chard's own,
        // so it is tagged as one: `error::classify` reads the tag before the io kind.
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
            "the work directory {} is in use by another chard measure, process {pid} \
             (its claim is {file}); wait for that run to finish, or pass a different --workdir",
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
                "if no chard measure is using {}, remove {}; otherwise pass a different \
                 --workdir",
                workdir.display(),
                held.display()
            ),
        )
        .into(),
    }
}

/// The level an observation may publish, given its verdict.
///
/// A rule rather than an inline branch, because it is exactly the kind of invariant this
/// project keeps stating in prose and enforcing in one place. It shipped wrong once:
/// `probe-invalid` observations published `level: "strong"`, so a withheld verdict and a
/// confident detail contradicted each other inside one object, and a reader could take
/// the level as fact while the verdict said the evidence was unusable.
///
/// Written as a total function so it can be enumerated. An integration test cannot pin
/// this — it can only assert about the verdicts the host's compiler happens to produce,
/// and on a machine whose bare `cc` is hardened there are no withheld verdicts to check.
/// One was written, and it passed with the rule deliberately broken.
pub fn published_level(verdict: Verdict, measured: Option<&str>) -> Option<String> {
    verdict
        .is_measurement()
        .then(|| measured.map(ToOwned::to_owned))
        .flatten()
}

/// The compiler-diagnostic channel's reason for a build the driver refused: how the build
/// ended, in [`compile::BuildRecord::ended`]'s words, and the refused line. A refusal is
/// read from a build's stderr, so the record is there; were it not, the sentence says the
/// build was refused rather than inventing a status.
fn refused_build_reason(build: Option<&compile::BuildRecord>, line: &str) -> String {
    let ended = build.map_or_else(|| "was refused".to_owned(), compile::BuildRecord::ended);
    format!("the build {ended}: {line}")
}

#[cfg(test)]
mod tests {
    /// The control arms' macro set reads each spelling of a macro word as gcc does and walks
    /// by the classifier: a long define or undefine, joined or two-token, the pieces of a
    /// `-Wp,` word, and a value another word takes, which names nothing.
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

    /// No control arm of the corpus spells `-D` or `-U` apart from its name, in any of gcc's
    /// spellings, so [`macros_the_controls_set`] never takes its joining branch today; an arm
    /// that did would make that branch the one reading it.
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

    /// A refused build's reason says how the build ended in `BuildRecord::ended`'s words:
    /// the `-1` sentinel names a signal, never "exited -1", and a real `exit(-1)` reads 255.
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
                super::refused_build_reason(Some(&record(exit_status)), "cc: error: no"),
                format!("the build {ended}: cc: error: no")
            );
        }
        assert_eq!(
            super::refused_build_reason(None, "cc: error: no"),
            "the build was refused: cc: error: no"
        );
    }

    use super::*;

    /// A work directory for one claim test, emptied first.
    fn claim_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("chard-claim-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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

    /// The start time is read after the last `)`, so a command name holding spaces and
    /// parentheses does not move the field, and a line too short or not numeric there
    /// gives none.
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

    /// A claim's name gives back the holder it was written from, and a name with a part
    /// missing, a part too many, an empty part or a pid that is not a number gives none,
    /// which `judge_claim` reads as a claim it cannot judge.
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

    /// A claim another user owns, or whose owner cannot be read, is never judged by its
    /// process: the same gone holder that this user's claim is removed for refuses then.
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

    /// A part `/proc` does not give makes this process's identity unknown, and then no
    /// other run's claim is judged gone, even one whose pid names no process.
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

    /// `/proc/self` names this process only where it reads as this pid.
    #[test]
    fn proc_self_is_this_process_only_where_it_names_its_pid() {
        assert!(proc_self_is(&Ok("42".into()), 42));
        assert!(!proc_self_is(&Ok("5".into()), 42));
        assert!(!proc_self_is(&Err(std::io::ErrorKind::NotFound.into()), 42));
    }

    /// The stat line decides: absent is gone, unreadable or unparseable is unjudged, a
    /// zombie or dead task is gone whatever its start time, a live one is live only at the
    /// start time the claim recorded.
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

    /// A run whose claim was removed while it measured finds out before it publishes, and
    /// refuses as `TRANSIENT`.
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

    /// One claim at a time: a second claim on a held directory is refused and leaves the
    /// first in place, and the directory is free again once the first is dropped.
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

    /// Where `/proc` says who is alive: a claim whose process is gone, or whose pid now
    /// names a process started at another time, is removed and refuses nothing; one made
    /// under another boot, or with a name chard does not write, refuses as the caller's,
    /// naming the file, and stays.
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

    /// A claim held by a live process refuses as `TRANSIENT`, naming the process, and stays.
    #[test]
    fn a_live_holders_claim_refuses_as_transient() {
        let own = ClaimHolder::this_process();
        if !own.known() {
            eprintln!("chard: no /proc here, so another run's claim is never judged live");
            return;
        }
        let dir = claim_dir("live");
        // The test's parent outlives the test, and spawning a child here would be a site
        // `compile::tests` holds to the two that bound one; the killed holder is
        // `tests/error_classes.rs`'s.
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

    /// A compiler's temporary object name is replaced wherever a diagnostic quotes it,
    /// and nothing else in the line moves.
    ///
    /// The gcc spelling, the clang spelling and Apple's, each closed by the punctuation a
    /// diagnostic closes a path with. The negative cases matter as much: a path under a
    /// temporary root that no compiler named is a path a reader wants, and every path
    /// under `/tmp` was scrubbed before the shape was part of the rule.
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
            // Under a temporary root and named by nobody's driver: an operator's include
            // directory, a header inside it, a five-character stem, an object with a
            // stem the operator chose, a temporary suffix on a name with no random part.
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

    /// The observation's copies are rewritten for publication and the arms' records
    /// with them, and the rewrite reaches every field a path can land in.
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

    /// An arm that could not be evaluated names why, per channel, and one that could
    /// names nothing.
    ///
    /// A `positive-unevaluable` with `detail: None` tells a reader the arm did not build or
    /// run and gives nothing to reproduce. The macro channel's case is the sharpest, a dump
    /// that exits 1 on a missing include while the build beside it succeeds, so the build
    /// record says nothing is wrong.
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
            artifact: None,
            structured: None,
            workdir: None,
        };

        // Readable on the macro channel: no reason.
        assert_eq!(unevaluable_reason(&base(), Channel::Macro), None);

        // A dump that failed: the exit status and the compiler's first line.
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

        // A build that failed, on the artifact channel: its exit status and first line.
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

    /// The Darwin case this was written for, verbatim from `mac10-ossf.json`.
    ///
    /// Apple's `ld` rejects six GNU linker options in one line, and 23 of 51 checks failed
    /// to link under `openssf-tldr` because of it. Every one reported a bare `build-failed`,
    /// with the explanation reachable only by opening `build.stderr` on each — twenty-three
    /// cells for one fact, none of them saying which.
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
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

        // Both signals are required, and each is tested by removing the other. A phrase
        // with no profile flag on the line is about something else entirely...
        assert!(
            profile_flag_rejection(&build("cc: error: unknown option: -fnonsense"), &profile)
                .is_none(),
            "a flag this profile never supplied is the check's own problem"
        );
        // ...and a profile flag with no rejection phrase is just a flag that was on the
        // command line, which is true of nearly every diagnostic a failing build emits.
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

    /// A `warning:` or `note:` line naming a profile flag is not a refusal: the driver went
    /// on without the flag, and a build that then failed did not fail for it. A line with no
    /// severity word, or an `error:` line, is the tool stopping. The control-flag reader
    /// keeps the warning lines, since clang only warns about an unknown `-W` control.
    #[test]
    fn a_warning_or_note_naming_a_profile_flag_is_not_a_refusal() {
        let mut profile = Profile {
            id: "explicit".to_owned(),
            flags_source: "user".to_owned(),
            cflags: vec!["-O2".to_owned(), "-Wchard-no-such".to_owned()],
            cxxflags: Vec::new(),
            ldflags: vec!["-Wl,--as-needed".to_owned()],
            toolchain_note: None,
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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
        // The refusal is read past the warning that precedes it, and the line kept apart
        // from the sentence is the refusal's.
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

    /// A *compiler* refusing a profile flag is classified the same as a linker refusing one.
    ///
    /// The linker case above was found on Darwin and fixed there; the compiler case was
    /// missed because gcc's wording contains neither of the phrases that matched. gcc 9.4
    /// says "unrecognized command line option" and gcc 16 says "unrecognized command-line
    /// option" — the hyphen moved between releases — and "unrecognized option" is a
    /// substring of neither.
    ///
    /// The stderr below is verbatim from a sweep: Ubuntu 20.04's gcc 9.4 under
    /// `openssf-tldr`, refusing `-fstrict-flex-arrays=3` because that flag arrived in gcc
    /// 13. Every probe in that run failed to build, and all 24 were published as plain
    /// `build-failed` — a verdict that reads as chard's own recipe being broken on an old
    /// toolchain, when what happened is a profile asking for a flag the compiler predates.
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
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

        // gcc 9.4, verbatim from the sweep. ASCII quotes, no hyphen in "command line".
        let old_gcc = profile_flag_rejection(
            &build("gcc: error: unrecognized command line option '-fstrict-flex-arrays=3'"),
            &profile,
        )
        .expect("gcc 9.4's wording must classify");
        assert!(old_gcc.starts_with("gcc rejected"), "{old_gcc}");
        assert!(old_gcc.contains("-fstrict-flex-arrays=3"), "{old_gcc}");

        // gcc 16 on the development host: hyphenated, and the flag in typographic quotes.
        let new_gcc = profile_flag_rejection(
            &build("gcc: error: unrecognized command-line option \u{2018}-fstrict-flex-arrays=3\u{2019}"),
            &profile,
        )
        .expect("gcc 16's wording, with curly quotes, must classify");
        assert!(
            new_gcc.contains("-fstrict-flex-arrays=3"),
            "the flag must survive typographic quote trimming: {new_gcc}"
        );

        // clang's spelling of the same refusal, which already matched.
        assert!(
            profile_flag_rejection(
                &build("clang: error: unknown argument: '-fstrict-flex-arrays=3'"),
                &profile
            )
            .is_some()
        );

        // The other signal is still required: a flag this profile never supplied is the
        // check's own problem, however the compiler phrases its refusal.
        assert!(
            profile_flag_rejection(
                &build("gcc: error: unrecognized command line option '-fwho-knows'"),
                &profile
            )
            .is_none()
        );

        // The tool name is taken from the text before the first colon, and only when that
        // text looks like one thing. A compiler reached through a wrapper puts a space
        // there — `ccache gcc: error: ...` — and naming the tool "ccache gcc" would be
        // reporting the invocation as the thing that refused the flag. It falls back
        // instead, and the diagnostic line is quoted whole either way, so nothing is lost
        // by declining to guess.
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

    /// Only a measurement carries a level, for every verdict in the vocabulary.
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
        // Every verdict in the vocabulary is covered by one list or the other, so a
        // new one cannot slip past this test unclassified.
        assert_eq!(measured.len() + withheld.len(), Verdict::ALL.len());
    }

    /// A flag list's net state for a macro follows the order gcc and clang apply the
    /// spellings in, as measured and recorded on [`profile_defines`].
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

    /// gcc's long and abbreviated spellings of `-D` and `-U` are read as the short word
    /// (`toolchain::LONG_ALIASES`), so each attributes the assertions as its short spelling
    /// does, the abbreviated define naming the profile; a `-D` the driver takes as another
    /// option's value (`-u -D_GLIBCXX_ASSERTIONS`, a symbol; `-L`, a directory) is no define.
    /// Every attributed check is fed and counted.
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

    /// The attribution names the profile where its flags leave the assertions defined, the
    /// library where they do not and the build is unoptimized, and neither otherwise; and
    /// nothing where the assertions are off, the library is another, or the check reads no
    /// assertions.
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

    /// A flag list that defines the compiler's own macros is answering chard's question.
    ///
    /// `_FORTIFY_SOURCE` must never appear here: defining it *is* how fortify is
    /// requested, and Fedora ships `-Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3` — so a
    /// rule that flagged it would withhold fortify on every rpm-based distribution.
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

        // The split spelling, one argument for the switch and one for the name, is the
        // same definition, the reader being shared with `profile_defines`.
        assert_eq!(spoof(&["-D", "__PIE__=2"]), vec!["__PIE__"]);

        // The comma-joined preprocessor form still gets caught when it is a spoof.
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

        // Every name in the list is reserved-namespace, which is what makes the rule
        // safe: a build system defining one of these is not configuring a compiler.
        //
        // Two spellings qualify, and C reserves both under the same clause: an identifier
        // beginning with an underscore followed by either a second underscore or an
        // uppercase letter is reserved for *any* use (C17 7.1.3), which includes being a
        // macro name. Apple's `_USE_FORTIFY_LEVEL` is the second spelling.
        //
        // A single underscore then a *lowercase* letter is reserved as well, but only for
        // identifiers with file scope in the ordinary and tag name spaces — and a `-D`
        // lands in the macro name space, which that clause does not cover. So `_x` must
        // never be added here: a build system may define one legitimately, and this rule
        // would withhold a real measurement.
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

    /// Every macro name a macro-channel predicate reads, beside the check that reads it:
    /// the `Macro` and `CInt` terms of each clause's condition and of each level-bearing
    /// conclusion. The walk restates `predicate::terms` here rather than exposing it,
    /// because every line of `src/predicate/` outside its test module is the decoder's
    /// fingerprint.
    fn macro_names_the_predicates_read() -> Vec<(&'static str, String)> {
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
        for (check, predicate) in crate::predicate::macro_channel::table() {
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

    /// Every macro a macro-channel predicate reads is a field the self-report header writes,
    /// or is named here as the dump's own.
    ///
    /// A report whose fields all read undefined is the artifact's account that nothing is
    /// defined and earns an `off` from the artifact (`report::self_report_entries`), and
    /// `parse_self_report` drops the undefined fields, so a macro the predicate reads that the
    /// header never writes would read as undefined over every artifact: an `off` the
    /// artifact never testified to. The header's inventory is read by [`self_report_entries`]
    /// (the test helper below, over `CHARD_REPORT_BODY`), the predicates' names by
    /// [`macro_names_the_predicates_read`].
    #[test]
    fn every_macro_a_predicate_reads_is_a_field_the_header_writes() {
        // The dump-side twin of the header's `_FORTIFY_IMPL` summary: fortify-headers'
        // include guard, which the header condenses and the dump prints as itself.
        const DUMP_ONLY: &[&str] = &["_FORTIFY_HEADERS_H"];
        let header = include_str!("../probes/chard_selfreport.h");
        let (read, derived) = self_report_entries(header).expect("the header reads");
        let written: std::collections::BTreeSet<&str> = read
            .iter()
            .chain(derived.iter())
            .map(String::as_str)
            .collect();
        let names = macro_names_the_predicates_read();
        assert!(!names.is_empty(), "no predicate reads a macro");
        for (check, name) in &names {
            assert!(
                written.contains(name.as_str()) || DUMP_ONLY.contains(&name.as_str()),
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

    /// Every macro a macro-channel predicate reads is one the flag list cannot forge, or is
    /// named here with the reason it may be.
    ///
    /// `exceptions-macro` shipped reading `__EXCEPTIONS` with the name absent from
    /// [`COMPILER_DEFINED_MACROS`], so `-D__EXCEPTIONS=1` published `on` and
    /// `-U__EXCEPTIONS -fexceptions` published `off` (Fedora 44 x86_64, gcc 16.1.1 and clang
    /// 22.1.8, 2026-10-01). This makes the next macro check fail here instead.
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
            // chard_selfreport.h condenses it into `_FORTIFY_IMPL`. A flag list defining
            // either is not withheld today, and no musl host has measured what it reads.
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

    /// [`PROBE_MACRO_BRANCHES`] is the set of probes whose source branches on a watched
    /// macro, each row the macros its source tests, derived here from the source: a probe
    /// that gains a branch on `__CET__`, `__OPTIMIZE__` or `__clang__` fails this until the
    /// table names it, and one that loses its branch fails it until the row goes.
    ///
    /// Nine of the rows are the C probes a `grep` of `probes/` for the three names finds; the
    /// tenth, the C++ probe, and `strict_flex_arrays_enforced.c`'s `__FreeBSD__` are what only
    /// this derivation finds. The self-report header's own `#ifdef` lines are not a probe's
    /// branches: they stringify the macros for the macro channel, whose guard is the spoof
    /// clause in `settle` and the twin rule.
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
            10,
            "the nine C probes a grep for the three names finds, and the C++ one"
        );
        for (id, _) in &declared {
            assert!(
                probe::CORPUS.iter().any(|p| p.id == *id),
                "{id} is not a probe in the corpus"
            );
        }
    }

    /// The derivation reads a directive's whole identifier and nothing else: a name inside
    /// a longer one, a name in a comment or in code, and a name in a `#define` do not
    /// count; one tested through `defined()` or bare does.
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
        assert!(branches_in("/* __OPTIMIZE__ as the compiler set it */\n").is_empty());
        assert!(branches_in("printf(\"%d\", __OPTIMIZE__);\n").is_empty());
        assert!(branches_in("#define CHARD_X __CET__\n").is_empty());
        assert!(branches_in("#ifdef __CET__X\n#if __PIE__2\n").is_empty());
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

    /// Each macro check with no twin ([`report::MACRO_WITHOUT_TWIN`]) is withheld by the
    /// spoof clause's unread-input case under every spelling [`unread_preprocessor_input`]
    /// reads and under every header search directory spelling the header reader takes, the
    /// reason naming the macro the reading quotes and the check; a plain `-D` of another
    /// macro, `-undef`, `-pthread`, a directory word handed to another tool or left
    /// dangling, a longer option and an empty list withhold nothing there, and a macro
    /// check with a twin is never held by it, whatever the list. Every check of both lists
    /// is fed and counted.
    #[test]
    fn a_twinless_macro_check_is_withheld_under_an_unread_preprocessor_input() {
        let check_named = |id: &str| -> &'static Check {
            probe::CORPUS
                .iter()
                .flat_map(|p| p.checks.iter())
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("the corpus carries {id}"))
        };
        // (spelling, the carrier phrase the reason names for it)
        let unread = [
            ("-include /srv/h", "does not read by name"),
            ("-include/srv/h", "does not read by name"),
            ("-imacros /srv/m", "does not read by name"),
            ("--include=/srv/h", "does not read by name"),
            ("--imacros /srv/m", "does not read by name"),
            ("--im /srv/m", "does not read by name"),
            ("-Wp,--include=/srv/h", "does not read by name"),
            ("-Wp,--im,/srv/m", "does not read by name"),
            ("-Xpreprocessor --imacros=/srv/m", "does not read by name"),
            ("@/srv/args", "does not read by name"),
            ("-Xclang -DGATE", "does not read by name"),
            ("-Xclang=-UGATE", "does not read by name"),
            ("-Wp,-include,/srv/h", "does not read by name"),
            ("-include-pch /srv/p", "does not read by name"),
            ("-I/srv/i", "header search directory"),
            ("-I /srv/i", "header search directory"),
            ("-I=inc", "header search directory"),
            ("-isystem /srv/s", "header search directory"),
            ("-isystem=inc", "header search directory"),
            ("-idirafter/srv/a", "header search directory"),
            ("-iquote /srv/q", "header search directory"),
            ("-Xarch_x86_64 -I/srv/x", "header search directory"),
            ("-I/srv/i -include /srv/h", "either"),
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
                "optimization-enabled" => "__OPTIMIZE__=1",
                "fortify-effective" => "__USE_FORTIFY_LEVEL=3",
                other => panic!("no observed line for {other}; add one"),
            };
            for (spelling, carrier) in unread {
                let mut flags = words(&["-O2"]);
                flags.extend(words(&spelling.split(' ').collect::<Vec<_>>()));
                let reason = twinless_unread_input(check, observed, &flags)
                    .unwrap_or_else(|| panic!("{id}: `{spelling}` withheld nothing"));
                let name = observed.split('=').next().expect("a name before the value");
                assert!(
                    reason.contains(&format!("`{name}`"))
                        && reason.contains(&format!("`{id}`"))
                        && reason.contains(carrier),
                    "{id}: `{spelling}` names the carrier `{carrier}`: {reason}"
                );
                // The directory words the reason spells are the reader's own list, so the
                // prose cannot drift from `HEADER_DIRECTORY`.
                if carrier != "does not read by name" {
                    for word in crate::toolchain::HEADER_DIRECTORY {
                        assert!(
                            reason.contains(&format!("`{word}`")),
                            "{id}: `{spelling}`: the reason names {word}: {reason}"
                        );
                    }
                }
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

    /// The law behind the clause: every spelling the header reader carries to the arms
    /// ([`header_spellings`], the reader's own lists) trips the twinless clause, as a
    /// directory word or an unread input, except the two whole words that name no file or
    /// directory (`-undef`, `-pthread`) and `-I-`, which the reader does not take; so a word
    /// added to the reader's list alone cannot be carried past the clause. And a macro
    /// check with a twin is never held by it, whatever the list.
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
                let carried = !crate::toolchain::header_selecting_flags(&flags).is_empty();
                let whole = crate::toolchain::HEADER_WHOLE.iter().any(|w| w == spelling);
                let held = twinless_unread_input(check, "__OPTIMIZE__=1", &flags).is_some();
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

    /// The twinless clause at its call site: `settle` withholds `optimization-enabled`'s
    /// `on` under `macro-supplied-by-profile` where the list selects a directory or carries
    /// a forced include, leaves it `on` under `-O2` alone, and leaves a declared rule's
    /// verdict standing, since the clause reads a measurement only.
    #[test]
    fn settle_applies_the_twinless_clause_to_a_measurement_alone() {
        let check = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .find(|c| c.id == "optimization-enabled")
            .expect("the corpus carries optimization-enabled");
        let reading = Detection {
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
            let out = settle_for(
                Verdict::On,
                check,
                &reading,
                |_| None,
                None,
                None,
                &words(&list.split(' ').collect::<Vec<_>>()),
            );
            if held {
                assert_eq!(out.verdict, Verdict::Indeterminate, "`{list}`");
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

    /// Each probe of [`PROBE_MACRO_BRANCHES`] has every elf-static, runtime and
    /// compiler-diag check withheld under `macro-supplied-by-profile` where the measured
    /// list defines or undefines a macro the row names, in each spelling the spoof clause
    /// reads, with the reason naming the macro and the probe; a macro check of the probe is
    /// left to the spoof clause. One case per row, which is the test per probe the item
    /// asked for.
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
                // A preprocessor input the reader does not read by name withholds too,
                // with a reason that says what kind of input and what the probe branches
                // on.
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

    /// gcc's long and abbreviated spellings of `-D` and `-U` are read by name
    /// (`toolchain::LONG_ALIASES`): one of a macro a branching probe does not branch on
    /// withholds nothing of that probe's checks, as `-DX` withholds nothing, and a `-D` the
    /// driver takes as another option's value (`-u -DX`, a symbol) is that value, not a
    /// define. Every probe of [`PROBE_MACRO_BRANCHES`] is fed and counted.
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
                // The last two name the branch macro itself: a value is no define, and a
                // reader that took it as one would withhold here.
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

    /// A measured compile whose driver listing differs from the arms' (a specs or
    /// configuration file's macro operation, the comparison `compile-inputs-unmatched-by-arms`
    /// makes) withholds a branching probe's checks too, quoting the difference.
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

    /// A header search directory in the list withholds exactly the compile-input readings
    /// of a branching probe (the three `report::COMPILE_INPUT_READINGS` holds among them,
    /// which the listing comparison withheld under any such directory until the arms
    /// carried it), in every directory spelling the header reader takes, with the reason
    /// naming the directory, the probe and the macro; the probe's other readings, which the
    /// comparison never withheld, keep their verdict, and so does every reading under
    /// `-undef`, `-pthread` or a directory word handed to another tool. Both sides counted.
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
                                && crate::toolchain::HEADER_DIRECTORY
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
        // The other readings, counted from the table: each non-macro check that is not a
        // compile-input reading under every directory spelling, and every non-macro check
        // under every word the clause leaves alone.
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

    /// The probe rule leaves a reading as it was where the list defines a watched macro the
    /// probe does not branch on, or nothing of the kind; keeps a verdict another rule
    /// withheld; and touches no probe outside the table whatever the list defines.
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

    /// A C++ probe is built with the distribution's CXXFLAGS wherever it keeps a separate
    /// set, and with CFLAGS wherever it does not.
    ///
    /// Building it with CFLAGS unconditionally asked the wrong question on both dpkg and
    /// abuild, which is precisely where the C++ hardening lives. All three states are
    /// enumerated because the guard is a fallback: a C++ probe with empty CXXFLAGS must
    /// still get CFLAGS, and a C probe must get CFLAGS even when CXXFLAGS is populated.
    #[test]
    fn a_cxx_probe_uses_cxxflags_only_where_the_distribution_keeps_them_apart() {
        let separate = Profile {
            id: "test".to_owned(),
            flags_source: "builtin".to_owned(),
            cflags: vec!["-DC_SIDE".to_owned()],
            cxxflags: vec!["-DCXX_SIDE".to_owned()],
            ldflags: vec!["-Wl,-z,now".to_owned()],
            toolchain_note: None,
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

    /// Every control arm is built for the target the profile selects, on every channel,
    /// and the linker selection stays off the macro arms.
    ///
    /// Under `-m32` on an x86_64 driver the arms were built for x86_64, so `cet-marked`
    /// read `off` over a triple validated on another target's startup objects (Fedora 44
    /// x86_64 with glibc-devel.i686, 2026-09-30; see [`arm_flags`]).
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
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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
        for option in crate::toolchain::HEADER_VALUED {
            spellings.push(format!("{option}/srv/v"));
            spellings.push(format!("{option} /srv/v"));
            spellings.push(format!("{option}=rel"));
        }
        spellings.push("-I-".to_owned());
        spellings.extend(
            crate::toolchain::HEADER_WHOLE
                .iter()
                .map(|w| (*w).to_owned()),
        );
        spellings
    }

    /// Every control arm, on every channel, and the clean build are built against the
    /// runtime the profile selects, from either flag list and in each accepted spelling.
    ///
    /// Under `--gcc-install-dir=` a copy of the gcc install directory whose `crtbegin*.o`
    /// carried no x86 feature note, `cet-marked` read `off` with `-fcf-protection=full`
    /// over a positive control linked against the host's marked one (Fedora 44 x86_64,
    /// clang 22.1.8, 2026-10-05; see [`arm_flags`]).
    #[test]
    fn a_control_arm_is_built_against_the_runtime_the_profile_selects() {
        arms_carry_every_spelling(&RUNTIME_SPELLINGS, true);
    }

    /// Every control arm, on every channel, is built against the headers the profile
    /// selects, from either flag list and in each accepted spelling, and the clean build is
    /// not ([`clean_flags`] says why).
    ///
    /// Without the selection, an explicit profile carrying `-I`, `-isystem`, `-include` or
    /// gcc's `-pthread` withholds every compile-input reading under
    /// `compile-inputs-unmatched-by-arms`, 17 of 72 on an x86_64 cell (Fedora 44, gcc 16.1.1
    /// and clang 22.1.8; see [`arm_flags`]).
    #[test]
    fn a_control_arm_is_built_against_the_headers_the_profile_selects() {
        let spellings = header_spellings();
        assert_eq!(spellings.len(), 21, "every list of the reader is fed");
        let spellings: Vec<&str> = spellings.iter().map(String::as_str).collect();
        arms_carry_every_spelling(&spellings, false);
    }

    /// The selection the compile listing's stand-in is taken under is what a macro arm of a
    /// check that reads the measured build carries before its own flags, and a linking arm
    /// carries beside the linker's program flags, for a profile making every selection from
    /// either list: the comparison certifies a match the arms have.
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
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

    /// A two-token selection whose value spells another reader's option reaches the arms and
    /// the clean build as the measured line's own words, each once: the target reader's
    /// `--library-directory -B<dir>/` (a library directory to both drivers, which passes the
    /// relative-path refusal that `-L -B<dir>/` does not) is no runtime prefix, `-L -I/x` no
    /// header word, `-B -pthread` no header word, and the runtime's `--stdlib -pthread` none
    /// either; the arms of a macro check and of a linking check, and the clean build, are
    /// held to the words (`toolchain::selections` has the measurement). A longer header
    /// option passes over itself alone (`-include-pch -B<dir>/`: the prefix is read, as gcc
    /// reads it), a pair after `-Xarch_` is carried whole, and a root through the
    /// preprocessor is the target's four words. A selection spelled as the value of an
    /// option that selects nothing (`-u -B<dir>/`, `-MF -L/x`, `-o -I/x`, `-D -m32`, `-z
    /// -fuse-ld=lld`) is that option's and reaches neither the arms nor the clean build,
    /// while the selections around the pair do (`toolchain::Hand::Value`).
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
            // A selection spelled as the value of an option that selects nothing is the
            // option's and reaches no arm and no clean build (`toolchain::Hand::Value`).
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
                compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

    /// gcc's long spellings are the selections they are to gcc, carried as written:
    /// `--machine 32` is `-m32` as the pair (and chooses the target), `--machine=32` and
    /// `--machine-32` are it joined, `--li`, `--pref` and `--im` are `-L`, `-B` and
    /// `-imacros`; a selection spelled as the value of `--def` or `--forc` (`-D`, `-u`) is
    /// the value, and a word joined to `--std` or `--machine` is no selection
    /// (`toolchain::LONG_ALIASES`); the arms of a macro check and of a linking check, and the
    /// clean build, are held to the words as [`the_arms_carry_a_two_token_value_once`] holds
    /// the short spellings.
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
            crate::toolchain::selects_target(&words("-O2 --machine 32"))
                && crate::toolchain::selects_target(&words("--machine=64"))
                && !crate::toolchain::selects_target(&words("--machine")),
            "`--machine 32` chooses the target as `-m32` does; `--machine` alone chooses none"
        );
    }

    /// The checks that read the clean build ([`Check::measures_toolchain_default`]) are
    /// exactly the checks of the assembly probes, so the exclusion [`arm_flags`] keys on the
    /// first is the one [`clean_flags`] argues from the second: a C default-asking check, or
    /// an assembly probe whose check reads the measured build, moves one without the other
    /// and fails here.
    #[test]
    fn the_default_asking_checks_are_the_assembly_probes() {
        let mut fed = 0_usize;
        for probe in probe::CORPUS {
            let assembly = std::path::Path::new(probe.source_name)
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
                    compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

    /// An arm's flags come in one order, the target, the runtime, the headers, the linker and
    /// the arm's own, and a C++ arm reads the runtime its own list selects.
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
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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
        // The header selection is the language's own list's too: a C++ arm carries the C++
        // list's directory and not the C list's, and the C arm the reverse, whole arms
        // compared so a reader of the wrong list cannot pass by its prefix.
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

    /// The clean build a default-asking check reads is built for the target its control
    /// arms are, and carries nothing else of the profile.
    ///
    /// Under `-m32` on an x86_64 driver, a clean build without the target selection is
    /// `EM_X86_64` while the arms of `linker-default-noexecstack` are `EM_386`, so the triple
    /// vouches for a target the artifact does not have (measured 2026-09-30; see
    /// [`clean_flags`]).
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
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
        };
        let clean = clean_flags(&profile, probe.lang);
        assert_eq!(
            clean,
            vec!["-m32"],
            "the target and nothing that hardens or links"
        );
        let target = |flags: &[String]| crate::toolchain::target_selecting_flags(flags);
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

    /// A default-asking check's arms stand on the clean build's footing, which carries no
    /// header word, and a check that reads the measured build carries the word after the
    /// target: under `-include /usr/include/stdio.h` the assembly probe's arms with the
    /// word failed on the assembler's errors and `linker-default-noexecstack` read
    /// `probe-invalid` over a clean build that read `on` (Fedora 44 x86_64, gcc 16.1.1, with
    /// the guard removed; see [`arm_flags`]). Every spelling of the
    /// reader's lists is fed to the default-asking arm, which carries none.
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
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

    /// A profile is clean when it adds nothing to a bare build, and either flag list can
    /// make it dirty.
    ///
    /// The measured build is skipped and the regime-matched control arm suppressed when
    /// this answers true, so a profile carrying only `ldflags` that read as clean would
    /// have its linker hardening silently dropped from the measurement.
    #[test]
    fn a_profile_carrying_either_flag_list_is_not_clean() {
        let empty = Profile {
            id: "bare".to_owned(),
            flags_source: "builtin".to_owned(),
            cflags: Vec::new(),
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: None,
            compiler_environment: crate::compile::CompilerEnvironment::of_this_run(),
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

        // The arm this test was missing, and the one that was a published `off`: a
        // distribution that hardens only its C++ builds supplies CXXFLAGS and nothing
        // else, and a profile read as clean compiles no measured build at all — so every
        // C++ check answered over a flag-free artifact while the report printed the
        // cxxflags beside it.
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

    /// The check that asks about a default reads the build that passed nothing.
    ///
    /// Both halves matter and each is a separate way to reintroduce the bug: the
    /// selection rule, and the declaration on the one check that needs it. The pairing
    /// is what made it a false `on` — that check's own positive control is a flag the
    /// guide's TL;DR block passes, so a measured build under that profile produced the
    /// observable by itself and the linker's compiled-in default was credited with it.
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

    /// Real stored ELF facts with only `self_report` varied.
    ///
    /// A second copy of `probe`'s fixture of the same name rather than a shared one: the
    /// two test modules cannot see each other, and deserializing rather than constructing
    /// is what makes a new `ElfFacts` field fail here loudly instead of defaulting to
    /// something these assertions would silently accept. `truncations` is the exception:
    /// it carries `#[serde(default)]`, so a fixture that omits it reads as a whole
    /// artifact, which is the reading these tests want. `symbol_tables` defaults the same
    /// way, to an object with no symbol table; a test whose check reads one sets it.
    fn elf_with_report(self_report: &str) -> crate::elf::ElfFacts {
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

    /// Any probe, for the `context` field. `evidence_faults` reads only `id` and
    /// `source`, and taking a real one keeps the id in the assertions honest.
    fn some_probe() -> &'static Probe {
        probe::find("link-defaults").expect("the probe is in the corpus")
    }

    /// A build that exits 0 and writes nothing is a fault in the invocation, and it is
    /// reported for whichever arm did it.
    ///
    /// `-fsyntax-only` reaches this honestly through `--profile explicit`: the compiler
    /// succeeds, no artifact exists, and every check over that arm withholds. Without the
    /// diagnostic the report shows `build-failed` beside an `exit_status: 0` record with
    /// empty stderr and says nothing about why. Both arms are asserted separately because
    /// the loop runs over two and a test that only ever dirties one cannot tell a loop
    /// from a single case.
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

        // A build that produced an artifact is not a fault, and neither is one that
        // failed: a failing build is a finding about the toolchain, reported as a
        // verdict, not a fault in chard.
        let mut built = blank_variant();
        built.build = Some(variant_build(0, true));
        assert!(evidence_faults(probe, &built, &blank_variant()).is_empty());

        let mut failed = blank_variant();
        failed.build = Some(variant_build(1, false));
        assert!(evidence_faults(probe, &failed, &blank_variant()).is_empty());
    }

    /// An artifact that linked and could not be read is a different fault from one that
    /// was never produced, and is reported per arm.
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

    /// The faults of a bare variant whose macros came from `source`, beside a dump whose
    /// `-dM -E` job exited `dump`, or none where `dump` is `None`.
    fn macro_view_faults(
        macros: &[(&str, &str)],
        cpp: &[(&str, &str)],
        source: &'static str,
        dump: Option<i32>,
    ) -> Vec<Diagnostic> {
        let mut bare = blank_variant();
        bare.macro_source = source;
        bare.macros = macro_pairs(macros);
        bare.macros_preprocessor = macro_pairs(cpp);
        bare.macro_dump = dump.map(|status| variant_build(status, false));
        evidence_faults(some_probe(), &blank_variant(), &bare)
    }

    /// [`macro_view_faults`] beside a dump that exited 0.
    fn macro_view_faults_dumped(
        macros: &[(&str, &str)],
        cpp: &[(&str, &str)],
        source: &'static str,
    ) -> Vec<Diagnostic> {
        macro_view_faults(macros, cpp, source, Some(0))
    }

    /// The compiler and the preprocessor are expected to agree, and every way they can
    /// disagree is a warning, where there are two views to compare and except the one
    /// that is not a disagreement.
    ///
    /// A spec file patching `*cpp_options` and not `*cc1_options` makes the two views
    /// diverge, and a verdict taken from the preprocessor alone would then describe a
    /// compiler that is not the one generating code. The asymmetry is deliberate: a macro
    /// the *codegen* view carries is always compared, but one carried only by the
    /// preprocessor is a divergence only when it is a macro chard watches — every build
    /// defines thousands the artifact's self-report never mentions, and reporting those
    /// would bury the finding under noise.
    ///
    /// Two views exist only where a dump ran and was read. Without the gate every probe
    /// with no macro-channel check whose artifact carries a self-report publishes each of
    /// its self-reported macros as `cpp=<undefined>`: measured on Fedora 44 x86_64 under
    /// gcc 16.1.1 and clang 22.1.8, in each of the six cells of the `bare`,
    /// `bare-optimized` and `openssf-tldr` frame.
    #[test]
    fn the_two_macro_views_are_compared_only_where_a_disagreement_would_matter() {
        let faults_for = macro_view_faults_dumped;

        // Only the compiled artifact's view can disagree with anything: when the macros
        // came from the preprocessor there is one view, not two.
        assert!(
            faults_for(&[("__PIE__", "2")], &[("__PIE__", "0")], "preprocessor").is_empty(),
            "with no artifact there is nothing to compare the preprocessor against"
        );

        // Agreement is silence.
        assert!(
            faults_for(
                &[("__PIE__", "2")],
                &[("__PIE__", "2")],
                "compiled-artifact"
            )
            .is_empty()
        );

        for (macros, cpp, expected) in [
            (
                &[("__PIE__", "2")][..],
                &[("__PIE__", "0")][..],
                "codegen=2 cpp=0",
            ),
            (
                &[("__PIE__", "2")][..],
                &[("__STDC_VERSION__", "201710L")][..],
                "codegen=2 cpp=<undefined>",
            ),
            (
                &[("__STDC_VERSION__", "201710L")][..],
                &[("__STDC_VERSION__", "201710L"), ("__PIE__", "2")][..],
                "codegen=<undefined> cpp=defined",
            ),
        ] {
            let faults = faults_for(macros, cpp, "compiled-artifact");
            assert_eq!(faults.len(), 1, "{macros:?} vs {cpp:?}");
            assert_eq!(faults[0].severity, Severity::Warning);
            assert!(
                faults[0].message.contains(expected),
                "{macros:?} vs {cpp:?}: {}",
                faults[0].message
            );
        }

        // The exception: a macro only the preprocessor carries, which chard does not
        // watch. Every build has thousands of these.
        assert!(
            faults_for(
                &[("__PIE__", "2")],
                &[("__PIE__", "2"), ("__STDC_VERSION__", "201710L")],
                "compiled-artifact"
            )
            .is_empty(),
            "an unwatched macro missing from the self-report is not a divergence"
        );
    }

    /// A probe that took no dump, or whose dump failed or defined nothing, publishes no
    /// disagreement: there is one view. Without the gate this shape carries the warning in
    /// each of the six cells measured.
    #[test]
    fn a_probe_with_no_dump_read_publishes_no_disagreement() {
        let faults_with = macro_view_faults;
        // No dump ran: one view, whatever the self-report says. This is every probe
        // without a macro-channel check, with macros a report lists under gcc 16.1.1.
        let self_report = [
            ("__GNUC__", "16"),
            ("__GLIBC__", "2"),
            ("__STDC_VERSION__", "202311L"),
            ("__USE_FORTIFY_LEVEL", "0"),
        ];
        assert!(
            faults_with(&self_report, &[], "compiled-artifact", None).is_empty(),
            "no preprocessor job ran, so nothing disagreed with the artifact"
        );
        // The same self-report beside a dump that defines none of them is a disagreement
        // about every one but the header-defined level, and the dump's watched `__SSP__`
        // the self-report lacks is the fourth; the level is noted as uncompared beside
        // them: the gate is the dump, not the shape of the maps.
        let faults = faults_with(
            &self_report,
            &[("__SSP__", "1")],
            "compiled-artifact",
            Some(0),
        );
        assert_eq!(faults.len(), 2, "{faults:?}");
        assert!(
            faults[0].message.contains("about 4 macro(s)")
                && faults[0]
                    .message
                    .contains("__GLIBC__: codegen=2 cpp=<undefined>")
                && faults[0]
                    .message
                    .contains("__GNUC__: codegen=16 cpp=<undefined>")
                && faults[0]
                    .message
                    .contains("__SSP__: codegen=<undefined> cpp=defined"),
            "{}",
            faults[0].message
        );
        assert!(
            faults[1]
                .message
                .contains("not compared on 1 header-defined macro(s)")
                && faults[1]
                    .message
                    .contains("__USE_FORTIFY_LEVEL: codegen=0 cpp=<undefined>"),
            "{}",
            faults[1].message
        );
        // A dump that failed has its own diagnostic, and no comparison beside it.
        let faults = faults_with(
            &[("__PIE__", "2")],
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
        let faults = faults_with(&[("__PIE__", "2")], &[], "compiled-artifact", Some(0));
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0].message.contains("defined no macros"),
            "{}",
            faults[0].message
        );
    }

    /// What the self-report writes that no preprocessor defines, and what the dump prints
    /// as replacement text where the self-report prints the expansion, are not
    /// disagreements; a real divergence beside either still is.
    #[test]
    fn the_self_reports_summaries_and_spellings_are_not_disagreements() {
        let faults_for = macro_view_faults_dumped;
        // A real divergence on a watched macro beside a dump that ran: the warning, with
        // the summaries beside it left out. The self-report's summaries are not macros,
        // and the dump never carries them.
        let faults = faults_for(
            &[
                ("__SSP_STRONG__", "3"),
                ("_FORTIFY_IMPL", "glibc"),
                ("_CXX_STDLIB", "libstdc++"),
            ],
            &[("__SSP_STRONG__", "2")],
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0]
                .message
                .contains("about 1 macro(s): __SSP_STRONG__: codegen=3 cpp=2."),
            "{}",
            faults[0].message
        );
        assert!(
            faults_for(
                &[("_FORTIFY_IMPL", "glibc"), ("_CXX_STDLIB", "libstdc++")],
                &[("__STDC_VERSION__", "201710L")],
                "compiled-artifact"
            )
            .is_empty(),
            "a summary the dump cannot carry is not a disagreement"
        );

        // The dump prints replacement text and the self-report the expansion: a mode the
        // headers name is compared as the number it expands to, and a different number
        // is still a disagreement.
        let libcxx = [
            ("_LIBCPP_HARDENING_MODE", "_LIBCPP_HARDENING_MODE_FAST"),
            ("_LIBCPP_HARDENING_MODE_FAST", "2"),
        ];
        assert!(
            faults_for(
                &[("_LIBCPP_HARDENING_MODE", "2")],
                &libcxx,
                "compiled-artifact"
            )
            .is_empty(),
            "the same mode in its two spellings"
        );
        let faults = faults_for(
            &[("_LIBCPP_HARDENING_MODE", "8")],
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
        // A chain is followed to its end, however deep, and a value naming no definition
        // is already the expansion.
        assert_eq!(
            expanded_in_dump(&macro_pairs(&[("A", "B"), ("B", "C"), ("C", "2")]), "A"),
            "2",
            "three steps"
        );
        assert_eq!(expanded_in_dump(&macro_pairs(&[("A", "B")]), "Z"), "Z");
        // A chain that is not libc++'s is followed the same way, and a different value at
        // its end is still a disagreement.
        let faults = faults_for(
            &[("X", "1")],
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

    /// A header-defined macro one view alone carries is published as uncompared, not as a
    /// disagreement and not as silence; one both views carry is compared as any other.
    ///
    /// The shape is FreeBSD 15.1's (clang 19.1.7) under `bare`: the C++ probe's artifact
    /// self-reports `__SSP_FORTIFY_LEVEL=0`, settled by `<sys/select.h>` on the way through
    /// `<vector>`, and its macros-only dump unit, reaching no header that settles it under
    /// no request, defines none. Compared, the pair reads as the spec-file disagreement, as
    /// it does in a fleet sweep's FreeBSD 15.1 `bare` and `bare-optimized` cells.
    /// Each name on the list is one the self-report reads from the macro of the same name,
    /// so a one-sided reading is a header the other unit did not reach and never a summary
    /// the dump cannot carry (`every_header_defined_name_is_a_watched_read_entry_noted_on_either_side`
    /// holds the list itself).
    #[test]
    fn a_header_defined_macro_one_view_alone_carries_is_not_a_disagreement() {
        let faults_for = macro_view_faults_dumped;
        let freebsd = [("__SSP_FORTIFY_LEVEL", "0"), ("__FreeBSD__", "15")];
        let faults = faults_for(&freebsd, &[("__FreeBSD__", "15")], "compiled-artifact");
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            !faults[0].message.contains("disagree about"),
            "{}",
            faults[0].message
        );
        assert!(
            faults[0]
                .message
                .contains("not compared on 1 header-defined macro(s) that one view alone carries: __SSP_FORTIFY_LEVEL: codegen=0 cpp=<undefined>."),
            "{}",
            faults[0].message
        );
        assert_eq!(faults[0].severity, Severity::Warning);
        // The other side: a watched header macro the dump alone carries.
        let faults = faults_for(
            &[("__FreeBSD__", "15")],
            &[("__FreeBSD__", "15"), ("__USE_FORTIFY_LEVEL", "0")],
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            !faults[0].message.contains("disagree about")
                && faults[0]
                    .message
                    .contains("__USE_FORTIFY_LEVEL: codegen=<undefined> cpp=defined"),
            "{}",
            faults[0].message
        );
        // Both views carrying it and differing is the disagreement it always was.
        let faults = faults_for(
            &[("__USE_FORTIFY_LEVEL", "2")],
            &[("__USE_FORTIFY_LEVEL", "0")],
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0]
                .message
                .contains("disagree about 1 macro(s): __USE_FORTIFY_LEVEL: codegen=2 cpp=0."),
            "{}",
            faults[0].message
        );
        // Agreement is silence, under `openssf-tldr` on the same guest.
        assert!(
            faults_for(
                &[("__SSP_FORTIFY_LEVEL", "0")],
                &[("__SSP_FORTIFY_LEVEL", "0")],
                "compiled-artifact"
            )
            .is_empty()
        );
    }

    /// Every name on the header-defined list is a read entry of the self-report, watched
    /// where the dump alone carries it, kept in `evidence.macros`, and noted rather than
    /// published as a disagreement on either side; the list is exactly the three fortify
    /// levels; and a name the header defines from nothing, off the list, is a disagreement.
    #[test]
    fn every_header_defined_name_is_a_watched_read_entry_noted_on_either_side() {
        let faults_for = macro_view_faults_dumped;
        // The list's names are the self-report's read entries, watched where the dump alone
        // can carry them, and kept in the evidence a reader sees the uncompared value in.
        let header = include_str!("../probes/chard_selfreport.h");
        let (read, derived) = self_report_entries(header).expect("the header reads");
        assert_eq!(
            HEADER_DEFINED_MACROS,
            &[
                "__USE_FORTIFY_LEVEL",
                "_USE_FORTIFY_LEVEL",
                "__SSP_FORTIFY_LEVEL"
            ],
            "the list is the three fortify levels"
        );
        for name in HEADER_DEFINED_MACROS {
            assert!(read.iter().any(|r| r == name), "{name} is not a read entry");
            assert!(!derived.iter().any(|d| d == name), "{name} is a summary");
            assert!(MACRO_WATCH.contains(name), "{name} is not watched");
            assert!(
                MACRO_EVIDENCE_KEEP.contains(name),
                "{name} is trimmed from evidence.macros"
            );
            // Both one-sided shapes for every name: noted, never a disagreement.
            let shared = ("__STDC_VERSION__", "201710L");
            for (macros, cpp, entry) in [
                (
                    vec![(*name, "0"), shared],
                    vec![shared],
                    format!("{name}: codegen=0 cpp=<undefined>"),
                ),
                (
                    vec![shared],
                    vec![shared, (*name, "0")],
                    format!("{name}: codegen=<undefined> cpp=defined"),
                ),
            ] {
                let faults = faults_for(&macros, &cpp, "compiled-artifact");
                assert_eq!(faults.len(), 1, "{name}: {faults:?}");
                assert!(
                    !faults[0].message.contains("disagree about")
                        && faults[0].message.contains(&entry),
                    "{name}: {}",
                    faults[0].message
                );
            }
        }
        // A name off the list, one the header defines from nothing, is a disagreement on
        // either side where it is watched or codegen-carried.
        let faults = faults_for(
            &[("__GLIBC__", "2")],
            &[("__STDC_VERSION__", "201710L")],
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0]
                .message
                .contains("disagree about 1 macro(s): __GLIBC__: codegen=2 cpp=<undefined>."),
            "{}",
            faults[0].message
        );
    }

    /// The header-defined list hides no split the spec-file hazard makes: a compiler-defined
    /// or command-line macro one view alone carries is still a disagreement, and the
    /// header-settled macro beside it is noted, not silent.
    ///
    /// The shapes: `-D_FORTIFY_SOURCE=2` reaching the compile and not the dump, which splits
    /// the request (named) and FreeBSD's settled level (noted); `-fstack-protector-strong`
    /// reaching the compile alone; a `__PIE__` the dump alone carries. The last two are the
    /// shapes `the_two_macro_views_are_compared_only_where_a_disagreement_would_matter`
    /// holds, restated beside the list so the list's edge is visible from one place.
    #[test]
    fn a_compiler_or_command_line_macro_one_view_alone_carries_is_still_a_disagreement() {
        let faults_for = macro_view_faults_dumped;
        let faults = faults_for(
            &[
                ("_FORTIFY_SOURCE", "2"),
                ("__SSP_FORTIFY_LEVEL", "2"),
                ("__OPTIMIZE__", "1"),
            ],
            &[("__OPTIMIZE__", "1")],
            "compiled-artifact",
        );
        assert_eq!(faults.len(), 2, "{faults:?}");
        let disagreement = faults
            .iter()
            .find(|f| f.message.contains("disagree about"))
            .expect("the request's split is a disagreement");
        assert!(
            disagreement
                .message
                .contains("disagree about 1 macro(s): _FORTIFY_SOURCE: codegen=2 cpp=<undefined>."),
            "{}",
            disagreement.message
        );
        let noted = faults
            .iter()
            .find(|f| f.message.contains("header-defined"))
            .expect("the settled level is noted");
        assert!(
            noted
                .message
                .contains("__SSP_FORTIFY_LEVEL: codegen=2 cpp=<undefined>"),
            "{}",
            noted.message
        );
        for (macros, cpp, expected) in [
            (
                &[("__SSP_STRONG__", "3")][..],
                &[("__STDC_VERSION__", "201710L")][..],
                "__SSP_STRONG__: codegen=3 cpp=<undefined>",
            ),
            (
                &[("__STDC_VERSION__", "201710L")][..],
                &[("__STDC_VERSION__", "201710L"), ("__PIE__", "2")][..],
                "__PIE__: codegen=<undefined> cpp=defined",
            ),
        ] {
            let faults = faults_for(macros, cpp, "compiled-artifact");
            assert_eq!(faults.len(), 1, "{macros:?} vs {cpp:?}: {faults:?}");
            assert!(
                faults[0].message.contains("disagree about 1 macro(s)")
                    && faults[0].message.contains(expected),
                "{macros:?} vs {cpp:?}: {}",
                faults[0].message
            );
        }
        // The request macros stay compared: neither is header-defined here.
        for name in [
            "_FORTIFY_SOURCE",
            "_GLIBCXX_ASSERTIONS",
            "_LIBCPP_HARDENING_MODE",
        ] {
            assert!(!HEADER_DEFINED_MACROS.contains(&name), "{name}");
        }
    }

    /// The self-report's entries, from the header's own inventory: the `CHARD__R_*` tokens
    /// `CHARD_REPORT_BODY` lists, each resolved to its defines. Returns the names read from
    /// the macro of the same name and the names derived from a ladder, or the first listed
    /// entry whose define this cannot read, so a shape it does not know fails rather than
    /// being skipped.
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

    /// The self-report's summaries are exactly the entries its header writes from a ladder
    /// rather than from the macro of the same name.
    ///
    /// An entry the header derives that the comparison treats as a macro publishes a
    /// disagreement no spec file caused (`_FORTIFY_IMPL: codegen=glibc cpp=<undefined>`
    /// beside every dump that ran); a macro listed as a summary is one the comparison
    /// never checks. The entries come from the header's own list, so one the parser
    /// cannot read fails here instead of passing unexamined.
    #[test]
    fn the_self_report_summaries_are_the_entries_the_header_derives() {
        let header = include_str!("../probes/chard_selfreport.h");
        let (read, mut derived) = self_report_entries(header).expect("the header reads");
        // Every entry `CHARD_REPORT_BODY` lists, counted. A new entry moves this, and the
        // test then asks which kind it is.
        assert_eq!(
            read.len() + derived.len(),
            32,
            "read {read:?}, derived {derived:?}"
        );
        derived.sort_unstable();
        let mut summaries = SELF_REPORT_SUMMARIES.to_vec();
        summaries.sort_unstable();
        assert_eq!(derived, summaries);

        // The shapes that slipped past the line-by-line parse: a derived entry whose
        // string is on a continuation line fails, and one on its own line is a summary.
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
        // An entry listed under another prefix fails rather than being left out.
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

    /// A probe that asks for a self-report and gets none says so, once, as provenance,
    /// and says which way the artifact lacks it: unlisted, listed and unread, or listed
    /// and holding no field. A report whose fields all read undefined is an account, not an
    /// absence, and draws no warning.
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

        // Listed, read, and holding no report: the markers with no field between them,
        // a field with no markers, and a marker with no end each count as absent, since
        // the artifact testified to nothing the header writes, and the length is said.
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
            assert!(
                faults[0].message.contains(&format!(
                    "lists `.chard.report` and its {} bytes hold no report (no `CHARD-REPORT-V2` \
                     or `CHARD-REPORT-V1` marker",
                    text.len()
                )),
                "{text:?}: {}",
                faults[0].message
            );
        }

        // A section that is there is not a fault...
        let mut carried = blank_variant();
        carried.elf = Some(elf_with_report(
            "CHARD-REPORT-V1\n__PIE__=2\nCHARD-REPORT-END",
        ));
        assert!(evidence_faults(with_report, &blank_variant(), &carried).is_empty());

        // ...and neither is a probe that never asked for one. Most of the corpus embeds
        // the section, so this is a named exception rather than an arbitrary pick.
        let no_report = probe::find("stack-canary").expect("the probe is in the corpus");
        assert!(
            !no_report.embeds_self_report(),
            "this test needs a probe that embeds no section"
        );
        let mut plain = blank_variant();
        plain.elf = Some(elf_with_report(""));
        assert!(evidence_faults(no_report, &blank_variant(), &plain).is_empty());
    }

    /// A macro-channel reading over a read artifact that carries no readable
    /// `.chard.report` is withheld under `artifact-lacks-self-report`, whatever the triple
    /// decided short of `probe-invalid`, with the reason naming the way the section is
    /// missing; an artifact that names macros, a run that read no artifact (the Mach-O
    /// case, which reads the dump by design), and a check on another channel are left
    /// alone. The gate and `gather`'s replacement read one predicate, so the verdict is
    /// withheld exactly where `macros` would have been the dump's.
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
            assert!(
                gating.reason.contains("`-dM -E` dump's alone"),
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
        // `probe-invalid` keeps its controls' cause, as under the sibling gates.
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
        // A name table the reader refused leaves the list empty, which has not shown the
        // section absent: the refusal is quoted instead of "0 sections", and the wording
        // does not claim the section is listed.
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

        // The artifact names macros: nothing to withhold, and `gather` would have taken
        // them, so `macro_source` is `compiled-artifact` exactly where the gate is silent.
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

        // Another channel over the same artifact reads its own tables, not the section.
        let canary = check_named("canary-emitted");
        assert_eq!(canary.channel(), Channel::ElfStatic);
        assert!(
            gating_for(Verdict::Off, canary, Outcome::Absent, Some(&unlisted))
                .is_none_or(|(_, g)| g.rule != g::ARTIFACT_LACKS_SELF_REPORT)
        );
    }

    /// A build record that exited 0 and wrote `artifact`, or nothing.
    fn build_exiting_zero(artifact: Option<String>) -> crate::compile::BuildRecord {
        crate::compile::BuildRecord {
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

    /// A macro-channel reading over a measured build whose artifact chard's reader refused,
    /// or which wrote none, is withheld under `artifact-lacks-self-report` on an ELF run,
    /// quoting the refusal; on macOS, where the dump is read by design, and on a probe that
    /// builds nothing, it is left alone, as are a declared rule's `unsupported`, the
    /// triple's `probe-invalid`, and a later rule that already spoke.
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
        // An ELF artifact the reader refused is an absence on macOS too, as an ELF
        // cross-compiler's would be; a Mach-O object is the dump reading by design there,
        // and an absence on every other host.
        assert_eq!(
            settle_self_report_unread(settled(Verdict::On, None), ssp, &refused, true)
                .gating
                .map(|g| g.rule),
            Some(g::ARTIFACT_LACKS_SELF_REPORT)
        );
        let mut mach_o = blank_variant();
        mach_o.build = Some(build_exiting_zero(Some("cd".repeat(32))));
        mach_o.elf_error = Some(report::ArtifactRefusal {
            why: format!("probe-measured: {}", crate::elf::MACH_O_REFUSAL),
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

    /// A measured build that exited 0 and wrote no artifact is withheld on every host, since
    /// there is nothing to read on any; a failed build is `build-failed` before this step, and
    /// a probe that builds nothing, or an artifact that was read, is not this step's.
    #[test]
    fn a_macro_reading_over_a_build_that_wrote_no_artifact_is_withheld_on_every_host() {
        use report::gating_rule as g;

        let ssp = check_named("ssp-level");
        let settled = |verdict: Verdict| Settled {
            verdict,
            level: None,
            gating: None,
        };
        // A build that exited 0 and wrote nothing.
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
        // No artifact is an absence on macOS too: there is nothing to read on any host.
        assert!(
            settle_self_report_unread(settled(Verdict::Off), ssp, &unwritten, true)
                .gating
                .is_some()
        );
        // A failed build is `build-failed` before this step and is not its.
        let mut failed = blank_variant();
        failed.build = Some(crate::compile::BuildRecord {
            exit_status: 1,
            ..build_exiting_zero(None)
        });
        assert!(
            settle_self_report_unread(settled(Verdict::Off), ssp, &failed, false)
                .gating
                .is_none()
        );
        // A probe that builds nothing, and a read artifact, are not this step's.
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

    /// `pic-shared-link`, a code decoder reading `.dynamic`, has a reading over a dynamic
    /// table the reader could not finish withheld, on an arm by `withhold_unreadable` and on
    /// the measured build by `artifact_gating`: the detector alone reads the link `present`
    /// from a `textrel` the reader never finished.
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

    /// A control arm read from a table the reader could not finish cannot vouch for
    /// anything, and the triple withholds through that arm's own cause.
    ///
    /// The bytes that were there read `present`, which is exactly the reading that cannot
    /// be trusted: a symbol table cut after the canary reference looks like one that
    /// carried it, and one cut before looks like one that did not. The reading is
    /// indeterminate on either, decided by the predicate's `@truncated` preamble before any
    /// clause reads a symbol, and its sentence names the table. Then each arm in turn: `decide` produces `probe-invalid` with the cause
    /// that names the arm, and no new cause was needed.
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

        // An ignored view leaves the facts whole, and a check reading other tables is
        // untouched by a cut it does not read.
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

        let absent = probe::Detection {
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

    /// OpenBSD's canary failure handler is read as a canary by both symbol checks, and the
    /// triple behaves on it as on `__stack_chk_fail`.
    ///
    /// The two OpenBSD 7.9 amd64 shapes measured with clang 19.1.7 (see
    /// `predicate::elf_static`'s `CANARY`): with RETGUARD off, `-fstack-protector-all`
    /// references `__stack_smash_handler` and `-fno-stack-protector` does not, so the
    /// triple discriminates; by default neither arm references it, since RETGUARD replaces
    /// the canary, and the triple withholds as `positive-silent` rather than reading `off`.
    /// The handler's absence also shows in `observed`, so the withheld arm's detail names
    /// the platform's handler as well as glibc's.
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

        // An unrelated watched symbol is not a canary: the handler list is the three names.
        let check = check_named("canary-emitted");
        let fortify = reading(check, &handler_variant(Some("__memcpy_chk"))).detection;
        assert_eq!(fortify.outcome, Outcome::Absent);
    }

    /// A cut `.dynamic` withholds under `artifact-unreadable` before the precondition can
    /// read its emptied facts as a section the artifact does not carry.
    ///
    /// The ordering `artifact_gating` exists for. The precondition on `relative-relocs`
    /// reads `pie`, which a cut `.dynamic` leaves false on an executable, so on the same
    /// facts the precondition alone would say the artifact cannot carry the observable.
    /// The truncation gate runs first and says the reading is unmeasured, which is the
    /// true statement. The other rows of the gate: `probe-invalid` and `unsupported` are
    /// left alone, since each already carries its cause, and a `present` reading is
    /// withheld too, unlike under the precondition.
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

    /// A slim LTO object withholds an elf-static reading over it under
    /// `artifact-holds-lto-ir`, unless `report::LTO_IR_CARRIES` names the check with the
    /// measurement that earned the exemption.
    ///
    /// The shape gcc 16.1.1 gave the `exceptions` probe under `-fexceptions -flto -c` on
    /// Fedora 44 x86_64: an `ET_REL` with `.gnu.lto_*` sections and `__gnu_lto_slim`,
    /// no `.gcc_except_table`, reads `off` over a discriminating triple without this gate. A
    /// fat object (the same sections and no marker) is read by its channel; a macro check over the
    /// slim object, which kept no readable `.chard.report`, is withheld under the same rule
    /// with its own sentence, and one over an object that kept a readable section is
    /// left to its channel; and a symbol table the reader could not finish withholds an object
    /// holding IR, since slim and fat cannot then be told apart.
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
        // Through the gate the measure path takes: the LTO rule is consulted before the
        // self-report gate, which keeps every absence the object's form does not explain.
        let through = |f: &crate::elf::ElfFacts| {
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
        listed
            .sections
            .push(crate::elf::SELF_REPORT_SECTION.to_owned());
        for (what, f) in [("a fat object", &fat), ("a listed, empty section", &listed)] {
            assert_eq!(
                through(f),
                Some((Verdict::Indeterminate, g::ARTIFACT_LACKS_SELF_REPORT)),
                "{what} is the self-report gate's case"
            );
        }
        for (id, why) in report::LTO_IR_CARRIES {
            let exempt = check_named(id);
            assert_eq!(exempt.channel(), probe::Channel::ElfStatic, "{id}");
            assert!(
                probe::CORPUS
                    .iter()
                    .any(|p| p.link_mode == probe::LinkMode::Object
                        && p.checks.iter().any(|c| c.id == *id)),
                "{id} is exempted from a gate only an object probe can meet"
            );
            assert!(
                why.contains("measured"),
                "{id}'s exemption names no measurement"
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

    /// An artifact with no symbol table cannot carry a symbol reference, and the three
    /// checks that read one are `not-applicable` over it; a symbol table the reader could
    /// not reach withholds under `artifact-unreadable` first.
    ///
    /// The object is a stripped static link: `-static -s` removes `.symtab` and leaves no
    /// `.dynsym`, the canary was emitted, and the controls are built unstripped, so the
    /// triple discriminates and the reading is `off` with no gate. The precondition reads
    /// `symbol_tables`, which the reader fills from the tables it walked; a file whose
    /// section headers are gone lists none and records `symbols` unread, and the
    /// truncation gate speaks before the precondition can call the table absent.
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

    /// A table the file does not have is a table the reader could not finish only if the
    /// reader claims so, and it does not: an `ET_REL` carries no `.dynamic` and records
    /// nothing about one.
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

    /// A cut table is one error diagnostic at the probe, named once whether or not a
    /// check declares it and however many entries record it; a dropped view is a warning.
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

        // Under a clean profile the clean artifact is the measured one, and one cut
        // artifact is one error, named under the label the build was read under.
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

    /// A check from the corpus, by check id rather than probe id.
    fn probe_named(id: &str) -> &'static probe::Probe {
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

    /// Controls whose positive arm read `outcome`, which is the only field either
    /// limitation consults. The flags are sentinels, so a pass that rewrote them would
    /// show.
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
            },
            regime_negative: None,
            discrimination: report::Discrimination::Withheld(
                report::WithheldBecause::PositiveSilent,
            ),
        }
    }

    /// A known limitation relabels a withheld verdict and never touches a measured one.
    ///
    /// A build that emitted `stderr` and succeeded.
    ///
    /// Exit 0 deliberately: clang reports an unknown `-W` option as a *warning*, so the
    /// build the rejection has to be found in is a passing one.
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

    /// A probe whose scaffolding the platform cannot build is gated, not blamed.
    ///
    /// The pair the loop produces on a Mac: Apple's linker implements neither `-soname`
    /// nor `-rpath-link`, so both arms of `copy-dt-needed` fail on the chain rather than
    /// on the flag, and the triple has nothing to discriminate.
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

        // And never for a probe that has no scaffolding: the same linker message during
        // an ordinary build says nothing about a chain that was never built.
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

    /// A driver that knows the flag and refuses it says something else, and the rule says so.
    ///
    /// clang 13 through 15 carry `-ftrivial-auto-var-init=zero` and decline to enable it
    /// without an opt-in the guide does not ask for. Reported under `flag-unknown-to-driver`
    /// the report would state that the flag does not exist on that compiler, which is false,
    /// and a reader acting on it would conclude the wrong thing about clang 15. Measured on
    /// Ubuntu 22.04: clang 15.0.7 rejects `=zero` and accepts `=pattern`, so the refusal is
    /// specific to the one spelling.
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
        // The `flag-unknown-to-driver` wording, which must not appear here. Matched on
        // that clause rather than on "does not know", which the refusal reason uses itself
        // to say what it is not.
        assert!(
            !gated
                .reason
                .contains("reported it as an option it does not know"),
            "a flag the driver knows must not be reported as one it does not: {}",
            gated.reason
        );

        // And the other direction stays put.
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

    /// The compiler's own statement gates the check, and only a withheld verdict.
    ///
    /// The pair the loop does produce — `trampolines-warned` on clang 22.1.8, where the
    /// positive arm read `indeterminate` rather than `absent` so `compiler_limitation`
    /// declined — and the pairs it must not relabel.
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

        // No rejection means no claim: a probe-invalid with a compiler that accepted the
        // flag is the broken detector this verdict exists to report.
        assert!(
            unknown_flag_limitation(Verdict::ProbeInvalid, check, "clang", None).is_none(),
            "probe-invalid without a rejection was relabelled as a compiler limitation"
        );

        // And never over a verdict the measurement reached, for the reason the libc and
        // compiler limitations are not: it would overwrite a reading with a gating reason.
        for verdict in [Verdict::On, Verdict::Off, Verdict::Unsupported] {
            assert!(
                unknown_flag_limitation(verdict, check, "clang", Some(said)).is_none(),
                "{verdict:?} was relabelled as a compiler limitation"
            );
        }
    }

    /// The linker's bare spelling of a `-Wl,` control still ties back to the flag.
    ///
    /// lld names `--copy-dt-needed-entries`; chard supplied `-Wl,--copy-dt-needed-entries`.
    /// Comparing those two literally finds nothing, which is why both rejection rules
    /// expand through [`spellings`] rather than one of them doing it.
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

    /// A control the linker refuses gates the check, and only a withheld verdict.
    ///
    /// The pair the loop produces on both BSD lanes: lld takes
    /// `--no-copy-dt-needed-entries` and refuses `--copy-dt-needed-entries`, so the
    /// negative arm was indeterminate and `probe-invalid` was published for a linker with
    /// no unhardened mode to measure against.
    #[test]
    fn a_control_the_toolchain_refuses_gates_only_a_withheld_verdict() {
        let check = check_named("no-copy-dt-needed");
        let said = "ld: error: unknown argument '--copy-dt-needed-entries'";

        let gated = unhardened_state_limitation(Verdict::ProbeInvalid, check, Some(said))
            .expect("a toolchain that refuses the negative control gates the check");
        assert!(
            gated.reason.contains("absence was never demonstrable") && gated.reason.contains(said),
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

    /// One artifact is one entry, however many checks and arms read it, and its entry is
    /// a function of its bytes alone.
    ///
    /// Every check of a probe reads the measured build, and a negative arm that is the
    /// clean build reads the clean one, so the store sees the same digest many times. Two
    /// builds that wrote equal bytes under two names are the case the path replacement is
    /// for: a reader's reason names the path it read, and without the replacement the
    /// second offer would be refused as a different fact about the same bytes. A digest
    /// offered a genuinely different entry is refused, the first kept, and the refusal
    /// names both.
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

    /// A dump is stored under the digest its published record carries, filtered, and only
    /// where the macros were read from it.
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
        // The key is over the sorted lines: the same defines printed in another order are
        // the same entry, and the dump as printed is not the key. `stdout` and `reordered` are
        // each out of sorted order, so a site that hashed either as printed would differ.
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

    /// Only a probe with a chain gets the flags for following one.
    ///
    /// The negation could be dropped without a test noticing, and the result reads as a
    /// working flag that could not be measured: `no-copy-dt-needed` builds a two-deep
    /// library chain, and without `-rpath-link` the transitive library is unfindable in
    /// *both* arms, so they fail identically and the triple reports itself unable to
    /// discriminate.
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

    /// A link in a probe's own chain is built with the arm's target, runtime, header and
    /// linker selections, in that order, and with nothing of the arm that hardens.
    ///
    /// Under `--target=aarch64-linux-gnu -fuse-ld=lld` on an x86_64 host, a chain linked by
    /// the default `ld.bfd`, which cannot emit aarch64, reads `no-copy-dt-needed`
    /// `probe-invalid` (measured 2026-09-30; see [`aux_lib_flags`]). The header
    /// selection is fed in a two-token and a whole spelling, so a chain compiled against
    /// other headers than its arm is caught here and not only end to end
    /// (`tests/fake_driver.rs`, `chain_libraries_follow_their_build`).
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

    /// The arms' link listing is taken under the measured link's own linkage form, after the
    /// arms' selection, so a form the profile chose (`-pie` through a specs `*self_spec`, or
    /// `-shared`, `-static`) is normalised rather than read as a difference (`link_inputs` says
    /// why): a measured link of each form gets exactly that form's driver flag appended, and
    /// nothing else moves.
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

    /// A link in the probe's own chain fails on either condition, not both.
    ///
    /// The scaffolding is fixed, so a failure here is a harness fault rather than a
    /// measurement. Requiring both conditions would let a build that exited zero with no
    /// artifact through to the link that depends on it; dropping the negation would report
    /// every successful chain as broken.
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

    /// A libc that settles the request below what was asked gates the check, and only then.
    ///
    /// The five conjuncts each have a negative here, because each one is a way this rule
    /// could convert a real instrument failure into a claim about somebody's C library.
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

    /// A keyword the linker took and ignored gates the check, in every spelling measured.
    ///
    /// GNU ld accepts any `-z`, warns for the ones it has no implementation for, and links
    /// anyway — so `relative-relocs` on binutils below 2.38 read `probe-invalid` over a
    /// linker that had never heard of the mechanism. The four positives below are the four
    /// spellings measured in the archive; the negatives are the two ways this rule could
    /// become a frequency argument.
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

    /// The standard library the toolchain names gates the check that reads the other one.
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
        // A profile that selects the other library: the controls, built without it, read
        // libc++, while the measured build linked libstdc++, where the observable has a
        // referent. That is a triple that could not discriminate for what was measured,
        // not a question with no referent, and it must not settle `--fail-on-missing`.
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

    /// The phrase list covers what clang actually says, and still ties it to the flag.
    ///
    /// `"unknown warning option"` does not contain `"unknown option"`, so the list matched
    /// neither `-Wtrampolines` nor `-Whardened` before. The second half of the rule is what
    /// keeps the wider list honest: a line naming some *other* unknown flag is not a
    /// statement about this check's control.
    #[test]
    fn a_rejection_must_name_this_checks_own_control_flag() {
        let rejected = build_with_stderr(
            "clang: warning: unknown warning option '-Wtrampolines'; did you mean '-Wtrampoline'?",
        );
        let found = control_flag_rejection(&rejected, &["-Wtrampolines"])
            .expect("clang naming the control flag is a rejection of it");
        // The rejected set is what precedes the quoted line, and it must be the control
        // flag alone. clang's `did you mean '-Wtrampoline'?` puts a second, similar flag on
        // the same line; it is not a flag this check supplied and must not be listed as
        // rejected. The line itself is quoted afterwards on purpose, so it does contain the
        // suggestion — asserting on `found` as a whole would be asserting the opposite.
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

    /// The `probe-invalid` precondition cannot be reached through the measurement loop:
    /// both limitations fire only when the positive control read `absent`, an arm that
    /// read absent cannot discriminate, and `decide` returns `probe-invalid` for
    /// everything that does not. So the guard is implied by its own body, no toolchain
    /// can produce an input that tells it from its absence, and this is the pair `decide`
    /// never produces — handed in directly, which is the only way to assert that the
    /// defence holds.
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

        // The same everything, on a verdict the measurement actually reached. Relabelling
        // it would overwrite a real reading with a gating reason.
        for verdict in [Verdict::On, Verdict::Off, Verdict::BuildFailed] {
            assert!(
                known_limitation(verdict, musl_gated, "musl", "gcc", absent.positive.outcome)
                    .is_none(),
                "{verdict:?} was relabelled as a libc limitation"
            );
        }
    }

    /// The compiler family earns the relabelling the same way the libc does.
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

    /// A positive control that *demonstrated* the mechanism refuses the relabelling, and
    /// that is the whole reason the gate is not keyed on the libc's name.
    ///
    /// Alpine is musl and does fortify, through fortify-headers. A name-based gate
    /// reported a hard limitation for a system that has none, so the claim rests on the
    /// forced flag having produced nothing — here, on the arm having produced something.
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
        elf: crate::elf::ElfFacts,
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
    fn linked_with_comment(lines: &[&str]) -> crate::elf::ElfFacts {
        let mut elf = elf_with_report("");
        elf.comment = lines.iter().map(|l| (*l).to_owned()).collect();
        elf
    }

    const GCC_LINE: &str = "GCC: (GNU) 16.2.1 20260610 (Red Hat 16.2.1-1)";
    const LLD_LINE: &str = "Linker: LLD 22.1.8";

    /// The checks of one probe share one artifact, so one digest is one entry, labelled
    /// with the variant the profile made the subject.
    ///
    /// `artifacts_read` is published as a count of distinct artifacts; without this pin
    /// the denominator inflates by the number of checks a probe has and no assertion on a
    /// live report (`>= 1`) would see it.
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

    /// A probe whose only observation was withheld before its triple has its build stored
    /// and contributes no witness: its artifact is not read and the probe is named among
    /// those that fed nothing, as for an observation that carries no `evidence.elf`.
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

    /// A relocatable, whichever way it is known to be one, and an unread `.comment` are
    /// marked, so the evidence can name them.
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

    /// A check that reads the clean build is labelled `clean` under any profile, and its
    /// artifact is marked for the count to leave out exactly when the profile's link line
    /// selected a linker.
    ///
    /// The false `disagrees` this pins against: `linker-default-noexecstack` reads the
    /// clean build, so under `--flags -fuse-ld=lld` its artifact was linked by the
    /// driver's default and carries the compiler line only, beside `link-defaults`'
    /// artifact carrying `Linker: LLD`. Fed as measured, the pair reads as the run's own
    /// artifacts disagreeing and an error diagnostic accuses an honest `PATH`. The
    /// over-withholding on the other side: under `bare-optimized` the profile has flags
    /// and selects no linker, both builds go through the driver's default, and the clean
    /// artifact is a witness like any other. Left out, a run of that one probe under a
    /// lying lld banner publishes `no-linked-artifact` over an artifact it has read, and
    /// every x86_64 report under that profile names a selection the profile never made.
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

    /// A selection of prefixes alone, in either spelling, leaves the clean artifact counted:
    /// the clean build carries the `-B` and `--prefix` prefixes with the runtime selection,
    /// so it goes through the measured build's link line. Beside a program
    /// flag it is the default's again, and marked.
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

    /// The C++ probes' artifacts go to the C++ linker only when there is one, each side
    /// carries the selection its link line made, and every probe that contributed no
    /// artifact is named on the side it would have fed.
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
        }
    }

    /// A regime arm that was required and evaluated.
    fn regime_arm(detection: Option<&Detection>) -> Option<report::ArmInput<'_>> {
        detection.map(|d| arm(Some(d)))
    }

    /// A reading, a verdict `decide` reached on a discriminating triple around it, and
    /// the check's own flag. The arms are the ones `decide` credits for any graded check:
    /// forced on read present at the recommended level, forced off read absent.
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

    /// An off-scale level word names `level-outside-check-scale` and publishes no level.
    /// A declared limitation stands by that fires on anything it is asked about, and stays
    /// quiet because the verdict is `indeterminate` rather than `probe-invalid`.
    ///
    /// Through [`settle`], the function `run_check` calls, so a dropped level rule there
    /// fails here; the order these tests pin is the one `settle`'s doc comment states.
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

    /// The same off-scale reading under a flag list that forges the macro takes the spoof
    /// rule: it runs after the level rule, and a forged macro is the more fundamental
    /// reason of the two.
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

    /// A present reading with no level at all, on a graded check, takes the level rule's
    /// no-level sentence under the same rule id.
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

    /// The artifact rule declines a present reading, so the level reason stands in an
    /// artifact that rule speaks for when the reading found nothing; the second half shows
    /// the rule live on the same object.
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
    /// which has one; a relocatable object with every link fact `None`; an interpreter
    /// forged onto an object with no dynamic section, which the classifier reads as a dynamic
    /// link; and an interpreter over a dynamic section with no entry, the `-static-pie
    /// -Wl,--dynamic-linker=<path>` link, which classifies as a dynamic PIE; and that link
    /// given one shared library, whose list names `libz.so.1` and no C library.
    fn artifacts_that_record_no_library() -> [(crate::elf::ElfFacts, &'static str, &'static str); 6]
    {
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
        assert!(interp_no_entry.needed.is_empty());
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
    fn fixture_facts(name: &str) -> crate::elf::ElfFacts {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/elf")
            .join(format!("{name}.elf"));
        elf::facts_for(&path).unwrap_or_else(|e| panic!("{name} reads: {e}"))
    }

    /// The static PIE written with neither `DF_1_PIE` nor `DT_DEBUG`, as lld 10.0.0 links one
    /// under `-z rodynamic`, classifies as a shared object; `pie` and `as-needed` are read
    /// from probes linked as executables, so over it each is withheld under
    /// `artifact-contradicts-link-mode`, through a triple that discriminated, whichever way
    /// the detector read. Without the gate `pie` reads `off`; `as-needed`'s own predicate
    /// withholds the empty list under `shared-output`, the one clause that reads the
    /// classification, and the gate names that field.
    ///
    /// The same object handed to the gate as a shared-object probe's is left alone, and so is
    /// the static PIE marked by `DT_DEBUG` alone, which the classifier reads as one.
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
            // left out. The positive arm reads it and the negative does not.
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

    /// `as-needed` over a shared-object classification, as the link-mode gate sees it:
    /// with the list empty, the predicate withholds under `shared-output` (a `-shared` link
    /// has no startup object, and under a driver passing `--as-needed` by default records
    /// nothing, so the empty list may be the flag's own doing) and the gate withholds the
    /// reading as resting on the classification; with the list kept, as lld 10.0.0 keeps it
    /// under `-pie -Wl,--no-dynamic-linker -Wl,-z,rodynamic`, the predicate reads the list
    /// without touching the classification, and the gate, keyed on the fields the reading
    /// rested on, leaves the reading to stand.
    #[test]
    fn as_needed_over_a_shared_object_classification_is_withheld_only_where_its_list_is_empty() {
        let unmarked = fixture_facts("elf64-le-x86_64-static-pie-unmarked");
        let as_needed = check_named("as-needed");
        let read = |facts: &crate::elf::ElfFacts| {
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
        let settled_over = |facts: &crate::elf::ElfFacts| {
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
        assert!(unmarked.needed.is_empty());
        let (reading, settled) = settled_over(&unmarked);
        assert_eq!(reading.outcome, probe::Outcome::Indeterminate);
        assert!(
            reading.observed.contains("shared_object=true")
                && reading.observed.contains("has no startup object")
                && reading.observed.contains("neither marker")
                && reading.observed.contains("the tags cannot say which"),
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

    /// [`MeasuredArtifact::of`] carries each probe's own link mode, whichever it is, so a
    /// constant in its place fails here for the probes that are not executables.
    #[test]
    fn a_measured_artifact_carries_its_probes_link_mode_for_every_probe() {
        let variant = blank_variant();
        let mut modes = std::collections::BTreeSet::new();
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

    /// The measured artifact `run_check` hands [`settle`] carries the probe's own link mode,
    /// the facts of the variant it read and the reading's proof, and over the unmarked static
    /// PIE (an empty list, so `as-needed` read the classification too) every verdict the
    /// triple can reach short of `probe-invalid` and `unsupported` is withheld, `partial` and
    /// `indeterminate` as much as `on` and `off`.
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

    /// What the link-mode gate leaves alone over the unmarked static PIE: a `probe-invalid`
    /// or `unsupported`, which carry their own cause, and a probe linked as a shared object,
    /// which asked for one; and the static PIE marked by `DT_DEBUG` alone, which classifies
    /// as one.
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

    /// Which checks the link-mode gate can reach: those whose reading rested on the link
    /// classification, read from a probe linked as an executable. Over the unmarked static
    /// PIE, whose list is empty, `pie` and `as-needed`; over the same object with its list
    /// kept, as lld 10.0.0 keeps it under `-pie -Wl,--no-dynamic-linker -Wl,-z,rodynamic`,
    /// `pie` alone, since `as-needed` then decided on the list. Listed so a check added on
    /// either side is counted here rather than gated, or not, unseen.
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

    /// An artifact that records no library withholds `as-needed` as `not-applicable` under
    /// the artifact rule, over a triple whose profile-free arms discriminated.
    ///
    /// A reproduction (gcc 13.3 on Ubuntu 24.04 x86_64, `--profile explicit --flags -O2
    /// --ldflags -static`): the predicate read `present` from an empty `DT_NEEDED` list and,
    /// with no row in the table, the sequence published `on`. Decoded through the shipped
    /// predicate here, five shapes read `indeterminate` under the clause named beside each,
    /// `decide` keeps that over discriminating arms, and the row turns it into
    /// `not-applicable` with a reason naming the entry the artifact lacks: a `-static`
    /// executable with no `.dynamic`, a static PIE with one, a relocatable object with no
    /// dynamic section, an interpreter forged onto an object with none, and an interpreter
    /// over a dynamic section with no entry, the `-static-pie -Wl,--dynamic-linker=<path>`
    /// link that classifies as a dynamic PIE. The next test reads the links that record a
    /// library.
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
        let read = |facts: &crate::elf::ElfFacts| {
            let mut variant = blank_variant();
            variant.elf = Some(facts.clone());
            check.decode(&evidence_for(&variant)).detection
        };
        let settled_over = |verdict: Verdict, reading: &Detection, facts: &crate::elf::ElfFacts| {
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
            assert!(
                gating
                    .reason
                    .contains("DT_NEEDED entry naming the C library")
                    && gating.reason.contains(elf_type)
                    && gating.reason.contains("carries none")
                    && gating
                        .reason
                        .contains("a link that took it from an archive records none for it")
                    && gating
                        .reason
                        .contains("a static PIE given an interpreter, or given one shared library"),
                "{}",
                gating.reason
            );
            assert_eq!(settled.level, None);
        }
    }

    /// A link that records a library passes through `as-needed`'s row silent, `present` to
    /// `on` and `absent` to `off`, whatever its classification: a dynamic executable, and the
    /// `-pie -Wl,--no-dynamic-linker` link, which classifies as a static PIE and keeps its
    /// list (lld 10.0.0 and GNU ld 2.34 under clang 10, Ubuntu 20.04 x86_64; GNU ld 2.46.1
    /// under gcc 16.1.1 and clang 22.1.8, Fedora 44 x86_64, 2026-10-27).
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
        let read = |facts: &crate::elf::ElfFacts| {
            let mut variant = blank_variant();
            variant.elf = Some(facts.clone());
            check.decode(&evidence_for(&variant)).detection
        };
        let settled_over = |verdict: Verdict, reading: &Detection, facts: &crate::elf::ElfFacts| {
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

    /// Output linked with no dynamic loader (a static PIE here, `DT_DEBUG` its marker; an
    /// `ET_EXEC` with no interpreter classifies the same way) with its list kept, the `-pie
    /// -Wl,--no-dynamic-linker` link, reads its list where the unused library is recorded,
    /// `off`; with the C library recorded and the unused library's entry missing, the shape
    /// `-static-pie -Wl,--no-as-needed -Wl,-Bdynamic libc.so.6 -Wl,-Bstatic` writes (the
    /// trailing `-Bstatic` sending the probe's `-lm` to `libm.a`; gcc 9.4 and clang 10 with
    /// GNU ld 2.34, Ubuntu 20.04 x86_64; gcc 13.3 with GNU ld 2.42, Ubuntu 24.04 x86_64), it is
    /// withheld under `no-loader-output` with no row, the row holding on the C library's
    /// entry, since the archive may have supplied the library.
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
        let read = |facts: &crate::elf::ElfFacts| {
            let mut variant = blank_variant();
            variant.elf = Some(facts.clone());
            check.decode(&evidence_for(&variant)).detection
        };
        let settled_over = |verdict: Verdict, reading: &Detection, facts: &crate::elf::ElfFacts| {
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
        assert!(
            reading.observed.contains("linked with no dynamic loader")
                && reading
                    .observed
                    .contains("the tags cannot say which this link chose")
                && reading
                    .observed
                    .contains("the archive may have supplied the library"),
            "{}",
            reading.observed
        );
        // The non-PIE twin, `-no-pie -Wl,--no-dynamic-linker` with the same trailing
        // `-Bstatic`: an `ET_EXEC` with no interpreter, classified as a static link, which a
        // key on the static-PIE marker alone let through to `on`.
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

    /// The declared family speaks on `probe-invalid`, which shows it live in the sequence
    /// and not merely unreached by the tests above.
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

    /// Every rule the declared family constructs publishes the verdict its premise
    /// reserves, and the artifact gates leave it standing.
    ///
    /// The artifact here has no `.dynamic`, so `relro`'s precondition fails and an
    /// `indeterminate` reaching [`artifact_gating`] would become `not-applicable` under
    /// `artifact-cannot-carry-observable`. The two instrument-limitation rules publish
    /// `indeterminate`, which a guard on `unsupported` alone does not cover; the declared
    /// rule's own reason is the one that must survive.
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

    /// One gating rule reached through the code that constructs it in a run, with the part
    /// of its input its row's `evidence` column says the reason quotes.
    ///
    /// Each arm calls the construction site `run_check`, `settle` or `measure_probe` calls,
    /// with inputs of the shape a real run hands it; the shapes are the ones the tests
    /// above pin one rule at a time. The quoted input is the tool's sentence for a
    /// [`report::gating_rule::Evidence::ToolSentence`] rule and, for every other rule, the
    /// value of the kind its `Evidence` names that the case handed the site: the target, the
    /// execution mode, the declared libc or compiler, the macro, the error, the artifact
    /// type, the table the reader cut, the detector's word, how the run was cut, the
    /// deadline that killed it, the artifacts' machine. The declared family is
    /// [`reach_declared`]. An id with no arm in either panics, so a rule added to the table
    /// fails [`every_gating_rule_is_reached_by_its_own_construction_site`] until it has one.
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
            id if id == g::GUARD_KEPT_WITHOUT_THE_FLAG.id => reach_detector(),
            id if id == g::RUN_OUTPUT_UNREADABLE.id || id == g::RUN_DEADLINE_ELAPSED.id => {
                reach_run(rule)
            }
            id if id == g::RUN_UNDER_EMULATION.id => reach_emulation(),
            id if id == g::LINK_INPUTS_UNMATCHED.id => reach_link_inputs(),
            id if id == g::CLEAN_LINK_UNMATCHED.id => reach_clean_link(),
            id if id == g::COMPILE_INPUTS_UNMATCHED.id => reach_compile_inputs(),
            id if id == g::SANITIZER_GROUP_UNMEASURED.id => reach_sanitizer_groups(),
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
        let report::Applicability::Untrustworthy(gating) =
            report::gate_applicability("-f", "-f", &gate, kernel, "x86_64")
        else {
            panic!("{} was not reached", rule.id)
        };
        (gating, quoted)
    }

    /// [`reach`] for the mechanism table's three decisions off the measured cells, through
    /// [`report::gate_applicability`]: x86 CET is absent from aarch64, which answers its
    /// question with BTI and PAC (`arch-gated`); `DT_TEXTREL` exists on aarch64 and
    /// `textrel-absent` has no construction for it (`no-check-on-target`); riscv64 has no
    /// row (`arch-outside-table`). The quoted input is the architecture.
    fn reach_arch(rule: report::gating_rule::Rule) -> (report::Gating, String) {
        use report::gating_rule as g;

        let (check, target) = if rule.id == g::ARCH.id {
            ("cet-macro", "aarch64")
        } else if rule.id == g::NO_CHECK_ON_TARGET.id {
            ("textrel-absent", "aarch64")
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
            report::Applicability::Unsupported(gating) | report::Applicability::Unread(gating) => {
                gating
            }
            report::Applicability::Untrustworthy(_) | report::Applicability::Applicable => {
                panic!("{} was not reached", rule.id)
            }
        };
        (gating, target.to_owned())
    }

    /// [`reach`] for `link-inputs-unmatched-by-arms`, through [`settle_link_inputs`] handed
    /// a discriminating `off` on `cet-marked` and the sentence a listing comparison gave.
    fn reach_link_inputs() -> (report::Gating, String) {
        let said = "its inputs include /srv/stripped/crtbeginS.o";
        let settled = Settled {
            verdict: Verdict::Off,
            gating: None,
            level: None,
        };
        let gating = settle_link_inputs(settled, check_named("cet-marked"), Some(said))
            .gating
            .expect("link-inputs-unmatched-by-arms was not reached");
        (gating, said.to_owned())
    }

    /// [`reach`] for `clean-link-unmatched-by-measured`, through [`settle_clean_link`] handed
    /// a discriminating `off` on `linker-default-noexecstack` and the sentence the clean
    /// build's comparison gave.
    fn reach_clean_link() -> (report::Gating, String) {
        let said = "the measured build's link program include /usr/bin/ld where the clean \
                    build's include /srv/px/ld";
        let settled = Settled {
            verdict: Verdict::Off,
            gating: None,
            level: None,
        };
        let gating = settle_clean_link(
            settled,
            check_named("linker-default-noexecstack"),
            Some(said),
        )
        .gating
        .expect("clean-link-unmatched-by-measured was not reached");
        (gating, said.to_owned())
    }

    /// [`reach`] for `compile-inputs-unmatched-by-arms`, through [`settle_compile_inputs`]
    /// handed a discriminating `off` on `fortify-effective` and the sentence a listing
    /// comparison gave.
    fn reach_compile_inputs() -> (report::Gating, String) {
        let said = "its header options include -isystem /srv/inc where the arms' include none";
        let settled = Settled {
            verdict: Verdict::Off,
            gating: None,
            level: None,
        };
        let gating = settle_compile_inputs(settled, check_named("fortify-effective"), Some(said))
            .gating
            .expect("compile-inputs-unmatched-by-arms was not reached");
        (gating, said.to_owned())
    }

    /// [`reach`] for `sanitizer-group-unmeasured`, through [`settle_sanitizer_groups`] handed
    /// an `on` on `ubsan-trap-mode` and clang's resolved lists with `enum` enabled and left out
    /// of the trap list, whose word the reason quotes.
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
        let settled = settle_sanitizer_groups(settled, check, Some(&listing));
        assert_eq!(settled.verdict, Verdict::Indeterminate);
        let gating = settled
            .gating
            .unwrap_or_else(|| panic!("sanitizer-group-unmeasured was not reached"));
        // The other direction: an `off` beside gcc's one-group words as written (the gcc
        // 13 shape), reached through the same site.
        let one_group = "-fsanitize-trap=enum";
        let gcc: report::SanitizerWords =
            Ok(vec!["-fsanitize=enum".to_owned(), one_group.to_owned()]);
        let off = settle_sanitizer_groups(
            Settled {
                verdict: Verdict::Off,
                gating: None,
                level: None,
            },
            check,
            Some(&gcc),
        );
        assert_eq!(off.verdict, Verdict::Indeterminate);
        let reached = off
            .gating
            .unwrap_or_else(|| panic!("sanitizer-group-unmeasured was not reached on off"));
        assert_eq!(reached.rule.id, gating.rule.id);
        assert!(reached.reason.contains(one_group), "{}", reached.reason);
        (gating, trapped.to_owned())
    }

    /// [`reach`] for `lto-codegen-at-link`, through [`settle_lto_codegen`] handed an `on` on
    /// `pic-shared-link` under clang and the mode its `-cc1` line resolved, whose word the
    /// reason quotes.
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
        let settled = settle_lto_codegen(settled, check, toolchain::Kind::Clang, Some(&listing));
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

    /// [`reach`] for `guard-kept-without-the-flag`, through [`settle`] handed a reading the
    /// detector withheld under the rule, the shape `detect_no_strict_overflow` returns for
    /// a guard that ran in an unoptimized clang build, on a discriminating triple; the
    /// quoted input is the detector's own sentence.
    fn reach_detector() -> (report::Gating, String) {
        let check = check_named("no-strict-overflow");
        let said = "the guard ran in a build that was not optimized, where clang keeps it \
                    whether or not the flag was passed";
        let reading = Detection::withheld(
            report::gating_rule::DetectorRule::of(report::gating_rule::GUARD_KEPT_WITHOUT_THE_FLAG),
            said.to_owned(),
        );
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
        .expect("guard-kept-without-the-flag was not reached");
        (gating, said.to_owned())
    }

    /// A detector's withholding is published under the rule it named, on `indeterminate`
    /// alone; a rule of another stage cannot be named ([`report::gating_rule::DetectorRule`]).
    ///
    /// Through [`settle`], as the level rule's test is. The run gate overwrites it where
    /// both apply, as it overwrites the level rule; the emulation rule and the self-report
    /// gate find it open, and a cut stream drops it, each in its own test below.
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

    /// A rule of another stage is not a detector's rule: the newtype refuses it where it is
    /// made, so a decoder cannot hand `settle` a rule the ladder consults elsewhere.
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
        assert_eq!(
            refused,
            ALL.len() - 1,
            "one detector rule, every other refused"
        );
    }

    /// The detector's rule is open to the later gates that read `Stage::Level` as open: the
    /// emulation rule overwrites it on a `Machine` reading, the self-report gate overwrites
    /// it on a macro check whose measured build wrote no artifact, and a cut stream drops it
    /// from the reading before `settle` sees it, so the run gate's rule stands alone.
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

    /// [`reach`] for `run-under-emulation`, through [`settle`] handed a whole run of the
    /// one `Machine` check over an aarch64 artifact on an x86_64 kernel.
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
    fn emulated_stack_clash(
        machine: &str,
    ) -> (&'static Check, runner::RunRecord, crate::elf::ElfFacts) {
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

    /// The emulation rule withholds a `Machine` reading over a foreign artifact and nothing
    /// else: not the same reading over a native one (an i386 artifact on an x86_64 kernel
    /// included, though an x32 one is withheld), not a `Program` check's reading over a foreign one, and not a reading
    /// with no run beside it. Measured 2026-10-01 under qemu-aarch64 10.2.2: the twelve
    /// `Program` checks read the same as on an aarch64 kernel, so they stand.
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
        // `ZCUR` line identical. `strict-flex-arrays-enforced`, measured on 2026-10-02 with ten
        // static aarch64 builds of its probe (gcc 16.2.1 and clang 22.1.8 on Fedora 44 aarch64; no
        // fortify, and `-O2 -D_FORTIFY_SOURCE=2` at each `-fstrict-flex-arrays` level) run natively
        // and under qemu-aarch64-static 10.2.2 on Fedora 44 x86_64: every row's outcome identical,
        // the emulator adding only its own line inside a caught row's markers. `trapv-trapped`,
        // measured on 2026-10-02 by running its probe under an aarch64 chard in an arm64 Fedora 44
        // container on Fedora 44 x86_64 (qemu-aarch64 10.2.2, gcc 16.2.1 and clang 22.1.8, fifteen
        // profile forms each) against the same forms on Fedora 44 aarch64: every verdict identical,
        // the detector setting aside the line qemu appends to a signal death.
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

    /// The emulation rule holds the byte order: the kernel's family and
    /// width in the other order is withheld, the same order stands, a record with no order
    /// is withheld with a reason naming the record, and a kernel whose spelling carries no
    /// order (mips under this x86_64 chard) is withheld with a reason naming the spelling.
    #[test]
    fn a_machine_reading_over_the_other_byte_order_is_withheld() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        use report::gating_rule as g;
        let (clash, run, _) = emulated_stack_clash("aarch64");
        // The byte order: the kernel's family and width in the other
        // order is withheld, the same order stands, a record with no order is withheld with
        // a reason naming the record, and a kernel whose spelling carries no order (mips
        // under this x86_64 chard) is withheld with a reason naming the spelling.
        let settle_under = |machine: &str, order: Option<crate::elf::ByteOrder>, kernel: &str| {
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

    /// The corpus's runtime checks, split as the project ledger records the measurement:
    /// the `Machine` checks and every other runtime check `Program`. A runtime check
    /// added later declares its basis on its decoder, which this list then names.
    #[test]
    fn the_run_basis_split_is_the_measured_one() {
        let machine: Vec<&str> = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .filter(|c| c.run_basis() == Some(probe::RunBasis::Machine))
            .map(|c| c.id)
            .collect();
        // `noexecstack-enforced` is `Machine` by its mechanism: its reading is the fault the
        // kernel's mapping of the stack produces. `shadow-stack-enforced` is `Machine` by its
        // mechanism too: the reading is the kernel's status word and a fault the CPU raises.
        assert_eq!(
            machine,
            [
                "noexecstack-enforced",
                "shadow-stack-enforced",
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
        // The run's observations as `measure_probe` published them, here a probe
        // that went unmeasured, held to an artifact whose machine flips the gate.
        let err = anyhow::Error::from(std::io::Error::other("unbuilt"));
        let mut observations = unmeasured(probe_named("link-defaults"), "clean", &err).observations;
        let target = crate::toolchain::target_agreement(
            "aarch64",
            crate::toolchain::ArchSource::Dumpmachine,
            &[crate::toolchain::ArtifactMachine {
                label: "link-defaults sha256:00".to_owned(),
                machine: "x86_64".to_owned(),
                class: 64,
                order: Some(crate::elf::ByteOrder::LittleEndian),
                lang: Some(crate::probe::Lang::C),
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
        let target = crate::toolchain::target_agreement(
            "x86_64",
            crate::toolchain::ArchSource::Dumpmachine,
            &[crate::toolchain::ArtifactMachine {
                label: "link-defaults sha256:00".to_owned(),
                machine: "x86_64".to_owned(),
                class: 32,
                order: Some(crate::elf::ByteOrder::LittleEndian),
                lang: Some(crate::probe::Lang::C),
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

    /// The `run-under-emulation` reason names chard's own build only where chard's own
    /// `ARCH` stands in for an absent `/proc/sys/kernel/arch`: a read `x86_64` names
    /// little-endian from the table with no clause about chard. Choosing the clause for every
    /// read spelling equal to `ARCH` would make every such reason on an x86_64 host say the
    /// spelling carries no order, which it does.
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

    /// A `Machine` reading over a run whose artifact the reader refused is withheld under
    /// `run-under-emulation`, quoting the refusal: the record holds no
    /// machine, width or byte order to the kernel's, which is every run on Darwin, where an
    /// `-arch x86_64` program runs under Rosetta 2 with nothing in the record to say so. A
    /// `Program` reading rests on nothing the record would hold, a `probe-invalid` is the
    /// triple's, and no run fires nothing.
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
        assert!(
            gating.reason.contains(refused)
                && gating.reason.contains("Rosetta 2")
                && gating.reason.contains("x86_64 kernel"),
            "{}",
            gating.reason
        );
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
    /// its `SCPRT` line, under an aarch64 kernel: the two translation tests' shape.
    fn settle_translated(
        line: &str,
        decided: Verdict,
        unread: Option<&str>,
        elf: Option<&crate::elf::ElfFacts>,
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

    /// On macOS a `Machine` reading over a record the reader refused is settled by the
    /// probe's `sysctl.proc_translated` line: `0` publishes it, `1` withholds naming the
    /// translation, and an unreadable read, no line or a line in no known shape withholds
    /// naming what the probe printed, each quoting the refusal; a `probe-invalid` is the
    /// triple's. A mutation reading `1` or an unreadable sysctl as native fails here.
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

    /// Where the rule does not consult the translation line: off macOS, so the Linux rule
    /// reads as without it; over a record never stored; and over an ELF record of a foreign
    /// machine, which is held to the kernel.
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
            linux.gating.is_some_and(|gt| gt.reason.contains(refused)
                && gt.reason.contains("x86_64 program on Apple silicon")
                && !gt.reason.contains("proc_translated")),
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
    /// nothing declared and no profile flags: the shape these tests settle before the
    /// emulation rule.
    fn settled_on(
        check: &Check,
        elf: Option<&crate::elf::ElfFacts>,
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
        elf: &crate::elf::ElfFacts,
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

    /// The positive control's `native`, the third site that reads an artifact's byte order
    /// (`report::machine_lacks_shadow_stack` reads it): a big-endian ppc64 artifact under a
    /// ppc64le kernel is not the kernel's own, the little-endian one is, and a record with
    /// no order is neither; and the shadow-stack rule declines the first, since under an
    /// emulator the emulator answers the probe's questions. Without this test, forcing
    /// little-endian at this site passes every other test.
    #[test]
    fn the_positive_controls_native_reads_the_artifacts_byte_order() {
        use crate::elf::ByteOrder::{BigEndian, LittleEndian};
        let check = check_named("shadow-stack-enforced");
        let under = |order: Option<crate::elf::ByteOrder>| {
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
    ) -> std::collections::BTreeSet<crate::predicate::ElfField> {
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
    #[allow(
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
                elf: Some(crate::probe::tests::elf_with_report("")),
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
                elf: Some(crate::probe::tests::elf_with_report("")),
                ..blank_variant()
            }),
            ..base
        }
    }

    /// Each guard the two C-library rules document declines on its own: every other input is
    /// the firing case. An arm the kernel did not run itself (no artifact to read, or a
    /// foreign machine), another check, a C library other than glibc, and a witness that is
    /// missing or could not run (`unallocated`) each leave the cell `probe-invalid`.
    #[test]
    fn each_documented_guard_of_the_c_library_rules_declines_alone() {
        use report::gating_rule as g;
        let fired = |case: &DeclaredCase| case.gating().map(|gating| gating.rule);
        let opt_in = || declared_case(g::OPT_IN_NOT_HONOURED);
        let loader = || declared_case(g::LOADER_REFUSES_EXECSTACK);
        let with_stdout = |stdout: &str| DeclaredCase {
            positive: Variant {
                run: Some(null_check_run(stdout)),
                elf: Some(crate::probe::tests::elf_with_report("")),
                ..blank_variant()
            },
            ..opt_in()
        };
        let foreign = || {
            let mut elf = crate::probe::tests::elf_with_report("");
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

    /// The two C-library rules decline where their observation does not hold. musl ignores
    /// `GLIBC_TUNABLES` too, and `libc-declared` names it first; a witness that saw its tunable
    /// take effect leaves the silence to `probe-invalid`, as does a positive control that read
    /// anything but `absent`. Exit 127 with no loader line, or a negative control that read
    /// anything but `indeterminate`, leaves the stack-exec cell where it was.
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
                elf: Some(crate::probe::tests::elf_with_report("")),
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
                elf: Some(crate::probe::tests::elf_with_report("")),
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
    /// `run_check` consults on `probe-invalid`.
    ///
    /// The quoted input is read off the case by the row's `evidence` column: the sentence
    /// for a tool-sentence rule, the declared libc or compiler for the declared-and-silent
    /// pair, the settled level for the fortify rule, the library's name for the stdlib rule.
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
                .and_then(|r| r.stdout.lines().find(|l| l.starts_with("SHSTK kernel=")))
                .map_or_else(
                    || panic!("{} was handed no SHSTK line", rule.id),
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

    /// Each declared rule reads the builds its row names in the `arms` column, and no
    /// other.
    ///
    /// The half of the column the reachability test cannot see: a rule reached with every
    /// arm filled says nothing about which arm it read. Here each rule fires on an input
    /// in which only its named arms carry anything, which shows it needs no other; then
    /// each named arm is blanked in turn and the rule no longer fires, which shows it
    /// reads that one. A construction site moved to another build's field fails one half
    /// or the other. The blanking goes through [`DeclaredReadings::read`], so the field
    /// each build fills is held along with the rule that reads it.
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

    /// Each rule resting on a driver's sentence fires only on the kind of sentence its
    /// row's `Sentence` column names.
    ///
    /// `report::consistency` holds a published quote to that column
    /// (`gating-rejection-absent-from-arm-stderr`), so a construction site that accepts the
    /// other kind publishes a report chard itself refuses with exit 3. Each such rule's
    /// named arm is handed both phrasings of a line naming the flag the row reads: the
    /// unknown-flag phrasing and the refusal. Whatever fires quotes a line of its own kind,
    /// and the rule fires on its own kind.
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

    /// The rules outside the declared family read the builds their stage allows: none
    /// before the triple is built, the measured build alone after `decide`, and none at
    /// the target stage.
    ///
    /// Their construction sites take no other build. [`report::gate_applicability`],
    /// [`no_driver`] and [`unmeasured`] run before any arm exists and are handed none;
    /// [`settle`], outside its `declared` argument, is handed the measured reading, the
    /// measured artifact, the measured run and the measured profile's flags, and nothing
    /// of a control arm; [`report::withhold_on_contradicted_target`] is handed the
    /// published observations and the run's target agreement, and no build of the check.
    /// The signatures hold that; this holds the table to the signatures.
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
                // `unmatched_link_inputs` asks the driver about the measured build's flags
                // and the selection both control arms carry, and `unmatched_compile_inputs`
                // asks the same of the compile.
                Stage::Link | Stage::Compile => &[Arm::Measured, Arm::Positive, Arm::Negative],
            };
            assert_eq!(rule.arms, expected, "{}", rule.id);
        }
    }

    /// Where two rules consulted in [`settle`] both apply, the one later on the ladder is
    /// the reason published, which is the order [`report::gating_rule::Stage`] derives.
    ///
    /// Each case arms two rules at once and the expected winner is taken from the table,
    /// as the armed rule with the greater stage, rather than written into the case. The
    /// declared family and the artifact gates never apply together: the family consults
    /// `probe-invalid` only, and [`artifact_gating`] declines it, which the last
    /// assertion holds. The level and detector rules and the declared family never apply
    /// together either, since those two publish `indeterminate` only, and neither do the declared
    /// family and the run rules, which decline `probe-invalid`. The level rule, the run
    /// rules and the artifact's truncation do, on a runtime check, and
    /// [`a_run_rule_beside_another_in_settle_publishes_the_later_stage`] pairs them.
    /// `target-arch-contradicted` is consulted after `settle`, over whatever it published,
    /// and `report::tests::a_target_withholding_raises_no_base_inference_contradiction`
    /// holds what it leaves. The stages before
    /// `decide` return early in `measure_probe` and `run_check` rather than overwrite,
    /// and no test drives them together: they need a driver that builds.
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

    /// Where the self-report gate and the level rule, or the self-report gate and the
    /// macro-spoof rule, both apply, the one later on the ladder is the reason published,
    /// as in [`two_rules_in_settle_publish_the_later_stage`]: the gate is at
    /// [`report::gating_rule::Stage::Artifact`], after `Level` and before `Spoof`, so it
    /// overwrites an off-scale level and a macro the flag list defined overwrites it.
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

    /// Where a run rule and the level rule or the artifact's truncation both apply, the
    /// one later on the ladder is the reason published, as in
    /// [`two_rules_in_settle_publish_the_later_stage`]: the run rules overwrite a level
    /// reason, and the artifact gate overwrites a run rule, since `settle` consults the
    /// run rules before the artifact gates.
    #[test]
    fn a_run_rule_beside_another_in_settle_publishes_the_later_stage() {
        use report::gating_rule as g;

        let later = |a: g::Rule, b: g::Rule| if b.stage > a.stage { b } else { a };
        let mut cut_everywhere = elf_with_report("");
        cut_everywhere.truncations = elf::ElfTable::ALL
            .iter()
            .map(|t| cut(*t, elf::TruncationKind::Unread, "cut"))
            .collect();

        // The level rule and a run rule, on a graded runtime check whose measured run
        // chard's deadline killed.
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

    /// Every row of the gating table is reached by the code that constructs it, and its
    /// reason quotes the input of the kind its `evidence` column names.
    ///
    /// The table [`report::gating_rule::ALL`] states each rule's premise, stage, arms and
    /// evidence; this is the half that says the rows describe code that runs. A rule the
    /// schema declares and no construction site produces is a reason no reader will ever
    /// see, and the schema pin cannot tell it from a live one, because it compares
    /// vocabularies rather than paths. Each row is reached through its own site in
    /// [`reach`], its constructed gating carries that row, its verdict is the one the
    /// premise reserves, and its reason contains the input [`reach`] handed it of the kind
    /// the row's `evidence` names, so an `Evidence` value is held to a reason that quotes
    /// it rather than read as a label.
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

    /// A runtime reading over output chard did not read whole is withheld on every arm,
    /// whatever the detector made of it, and a check on another channel is untouched.
    ///
    /// `null-check=deleted` reads `absent`, the `off` a cut stream must never earn; `kept`
    /// reads `present`, and is withheld too, because a decoder reads absence on its way to
    /// either. An unreadable stream is the limiting case of a cut one and is withheld the
    /// same way.
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

    /// On the measured build a cut stream names `run-output-unreadable`, over whatever
    /// verdict reached `settle`, and leaves `probe-invalid` to its controls.
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

    /// A runtime reading whose probe was killed at the deadline is withheld under
    /// `run-deadline-elapsed`, the reason naming the deadline, whatever the detector read:
    /// a killed probe never finished writing, so a marker in its partial output is not
    /// evidence either way. A run that exited in the window before the kill finished, and
    /// its reading stands.
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

        // On every arm: `null-check=deleted` in a killed run's output reads `absent` from
        // the detector and is replaced before the triple sees it.
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

    /// `settle` and `artifact_gating` over their whole finite domain: every verdict `decide`
    /// can hand them, every check in the corpus, every outcome, a level or none, a declared
    /// rule or none, three artifact shapes, four run shapes, and a forged macro or none.
    ///
    /// The four properties are the ones a clean-looking zero would break. A published
    /// `gating` fixes the verdict beside it, since the rule's premise reserves exactly one;
    /// a verdict settles only through a rule, so a silent rewrite is caught; no rule turns
    /// a withheld verdict into a measurement or one measurement into another, which is the
    /// direction the ladder must never move; and `artifact_gating` never publishes a
    /// measurement and leaves the toolchain's own `unsupported` alone. Written as an
    /// exhaustive test rather than a Kani harness: the inputs are corpus checks behind
    /// `LazyLock` predicates, `ElfFacts` and `RunRecord`s, which a model checker would have
    /// to make symbolic field by field, while the domain that matters is finite and runs
    /// here in full on every host.
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
