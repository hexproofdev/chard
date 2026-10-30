// SPDX-License-Identifier: BSD-3-Clause

//! A flag that is present and does nothing must never be reported `on`.
//!
//! The control triple guards one direction. Both control arms are profile-free and
//! self-sufficient, so they discriminate perfectly whether or not the measured build's own
//! flag took effect; a detector blind to a present flag is caught, a flag present and
//! inert is not. `DESIGN.md` names the case that made this concrete,
//! `-D_FORTIFY_SOURCE=3` with no `-O`, and the guard for it is one branch in one detector.
//! This file makes the guard a rule: every graded or conditional mechanism in the corpus
//! names the form in which its flag is present and inert, and the built binary is driven
//! once per form to show the verdict is anything except `on`.
//!
//! Two tables. [`INERT_FORMS`] is one row per form: the check (or a composite in
//! [`COMPOSITES`], read from the report's `composites`), the probe that carries it,
//! the profile that spells the inert form, the verdicts the row accepts, and the host
//! condition under which the form is inert at all. [`NO_INERT_FORM`] names the covered
//! checks that have none, each with the reason. The corpus invariant covers two sets and
//! requires every check in either to appear in one table or the other: the graded checks
//! (`Levels::Graded` in `src/probe.rs`), and the checks whose positive and negative control
//! arms both carry `-O2`. The second is the corpus's own signal of an optimization precondition, and
//! a mechanism with that precondition has a form in which the flag is present and the
//! optimizer is absent. A check added to either set without its inert form fails here
//! before it ships.
//!
//! A row's expected set is either measured or derived. A derived set was read off the
//! detector and the gate by someone with no host that meets the row's condition, and the
//! row's comment says so; the first run on such a host either confirms it or fails naming
//! the verdict, and the set is changed only with that report open.
//!
//! A third table, [`WITHHELD_ON_PLATFORM`], names the platforms on which a row's check cannot
//! discriminate at all, and the withheld verdict the row accepts there instead of its
//! expected set, with the cause. It never admits a measurement, so it widens what a row
//! accepts only by readings that are not `on` and not an unearned `off`.
//!
//! The host condition is the honest part. A form is inert under some libc, some
//! architecture or some compiler and a true `on` elsewhere: `-D_FORTIFY_SOURCE=3` without
//! `-O` is inert under glibc's headers and in force under Apple's, and `-fcf-protection`
//! is inert off x86 and the recommended flag on it. A row whose condition the host does
//! not meet is announced through `tests/common`'s capability gap and counted, and on an
//! ELF host the artifact rows are required to run.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod common;

/// Under which host the form is inert.
enum Applies {
    /// Inert on every toolchain chard runs on.
    Always,
    /// The observable is read from an ELF artifact, so a Mach-O host cannot exercise it.
    ElfArtifact,
    /// Inert only under a C library whose implementation is one of these.
    Libc(&'static [&'static str]),
    /// Inert only where the target architecture is outside this set.
    ArchOutside(&'static [&'static str]),
    /// Inert only under this compiler family.
    Compiler(&'static [&'static str]),
    /// The observable is read from an ELF artifact, and the form is inert only under this
    /// compiler family: both conditions, so a Mach-O host with the family is a gap.
    ElfCompiler(&'static [&'static str]),
    /// The observable is read from an ELF artifact, and the form is inert only where the
    /// target architecture is outside this set: both conditions, as for `ElfCompiler`.
    ElfArchOutside(&'static [&'static str]),
    /// The observable is read from an ELF artifact, and the form is inert only where the
    /// target architecture is inside this set: the converse of `ElfArchOutside`, for a form
    /// that forges a mechanism's marking where the mechanism exists.
    ElfArchInside(&'static [&'static str]),
    /// Inert only under this compiler family, and only where `cc` links and runs a
    /// program built with these flags (split on whitespace): a sanitizer whose runtime the
    /// host lacks fails the probe's build, which says nothing about the form.
    CompilerRuntime(&'static [&'static str], &'static str),
    /// Inert only under this C++ standard library.
    CxxStdlib(&'static str),
    /// Inert only under gcc older than this major version, read from the report's
    /// `toolchain.version`. It names no family to [`compiler_families`]: a gate that runs
    /// every row naming gcc runs a current gcc, which this row is never inert under, so
    /// the row is a host gap everywhere but on an old gcc.
    GccBefore(u32),
}

/// One inert form of one check's flag.
struct InertForm {
    check: &'static str,
    probe: &'static str,
    /// The `--profile explicit --flags` string. Split on whitespace by chard.
    flags: &'static str,
    /// Verdicts the row accepts. Never `on`, which the invariant test enforces.
    expected: &'static [&'static str],
    applies: Applies,
    /// Why the flag does nothing in this form.
    inert_because: &'static str,
}

const INERT_FORMS: &[InertForm] = &[
    InertForm {
        check: "ssp-level",
        probe: "toolchain-macros",
        flags: "-fstack-protector-strong -fno-stack-protector",
        expected: &["off"],
        applies: Applies::Always,
        inert_because: "a later -fno-stack-protector countermands the request; the macro \
                        must follow the last spelling on the line",
    },
    // Measured 2026-10-02 with chard from the wf-u-ssp-funcmap tree, `--probe
    // ssp-function-map`: `off` with a discriminating triple under gcc 16.1.1 and clang
    // 22.1.8 (Fedora 44 x86_64), gcc 16.2.1 and clang 22.1.8 (Fedora 44 aarch64), gcc 11.4.0
    // and clang 14.0.0 (Ubuntu 22.04), gcc 13.3.0 and clang 18.1.3 (Ubuntu 24.04), gcc
    // 15.2.0 and clang 23.1.2 (Alpine, musl) and gcc 12.2.0 (Debian 12 i386). gcc's
    // -fstack-protector-explicit is no row: it reads `off` everywhere but Ubuntu 22.04,
    // whose gcc 11.4.0 adds -fstack-protector-strong after it, so the build is `strong`
    // and both stack-protector readers say so. `ssp-level` reads `__SSP_EXPLICIT__`, and
    // that form reads `partial` at `explicit` there, a level and not an inert `on`; this
    // check reads `off`, since no probe function is marked stack_protect, and
    // `report::OPT_IN_LEVELS` keeps the pair from reading as a disagreement.
    InertForm {
        check: "ssp-level-emitted",
        probe: "ssp-function-map",
        flags: "-fstack-protector-strong -fno-stack-protector",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -fno-stack-protector countermands the request, and no \
                        function in the object refers to the canary failure handler",
    },
    // The seven fortify rows below are measured on FreeBSD, 2026-10-27, in the fleet's two
    // guests under `--profile explicit --flags "-O0 -D_FORTIFY_SOURCE=2"`. On 15.1 (clang 19.1.7)
    // `fortify-requested` and `fortify-effective` read `indeterminate`
    // (`requested-without-optimization`, `freebsd-unoptimized`: clang instantiates the
    // wrappers at -O0 and they check nothing there), `fortify-enforced-known` `off` (the
    // overrun survived with `__memcpy_chk` referenced) and the three rungs FreeBSD does not
    // implement `unsupported`; `fortify-printf-flag` reads `indeterminate` over the referenced
    // `__strcpy_chk` through its `freebsd-unoptimized` clause, which
    // `probe::tests::the_printf_flag_withholds_freebsds_unoptimized_wrapper_only` holds (no
    // guest report of that build carries the clause). On
    // 14.5 (clang 21.1.8), whose headers carry no wrappers, every row but `fortify-requested`,
    // which reads `indeterminate`, reads `unsupported`. These rows run only in the guests; no
    // gate on this host exercises them.
    InertForm {
        check: "fortify-requested",
        probe: "toolchain-macros",
        flags: "-D_FORTIFY_SOURCE=3",
        expected: &["indeterminate", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "freebsd"]),
        inert_because: "glibc and fortify-headers instantiate their checks only under \
                        __OPTIMIZE__, so the request is set and nothing is checked; the \
                        verdict is withheld rather than read as on or off",
    },
    InertForm {
        check: "fortify-effective",
        probe: "toolchain-macros",
        flags: "-D_FORTIFY_SOURCE=3",
        expected: &["off", "indeterminate", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "freebsd"]),
        inert_because: "the C library settles the level at 0 without optimization, and the \
                        settled level is what this check reads",
    },
    // `fortify-printf-flag` is graded. Measured 2026-10-02 with `nm` over the probe's object
    // at -O0 under gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64 and gcc 16.2.1 and clang
    // 22.1.8 on Fedora 44 aarch64, glibc 2.43: `printf` and `strcpy`, and no flag.
    InertForm {
        check: "fortify-printf-flag",
        probe: "fortify-printf-flag",
        flags: "-D_FORTIFY_SOURCE=3",
        // `indeterminate` is FreeBSD 15's: the wrapper referenced and checking nothing.
        expected: &["off", "unsupported", "indeterminate"],
        applies: Applies::Libc(&["glibc", "musl", "freebsd"]),
        inert_because: "the C library instantiates no wrapper without optimization, so \
                        printf and strcpy are called unchecked whatever the request",
    },
    InertForm {
        check: "fortify-enforced-dynamic",
        probe: "fortify-dynamic-object",
        flags: "-D_FORTIFY_SOURCE=3",
        expected: &["off", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "freebsd"]),
        inert_because: "the check's own notes: the level-3 wrappers do not exist at -O0, so \
                        a profile with no -O reports off",
    },
    // The three rungs below share the dynamic rung's form, and each is measured on three
    // hosts. Under glibc the measured build
    // has no wrapper to fire, the probe survives, and `detect_fortify_runtime` and
    // `detect_fortify_percent_n` read the survivor as absent: all three read `off` on
    // Fedora 44 x86_64 (gcc 16.1.1, glibc 2.43) and Fedora 44 aarch64 (gcc 16.2.1, glibc
    // 2.43), 2026-09-28. Under musl the level-2 positive control shows
    // nothing and `report::libc_limitation` settles the check as unsupported before the
    // measured build is read; a musl carrying fortify-headers fires the level-1 rung, and
    // its headers gate on __OPTIMIZE__ the way glibc's do, so that host reads off. Alpine
    // edge (musl 1.2.6, gcc 15.2.0, fortify-headers 3.0.2) read exactly that on
    // 2026-09-26: `fortify-enforced-known` `off`, the two level-2 rungs `unsupported` under
    // `libc-declared`.
    InertForm {
        check: "fortify-enforced-known",
        probe: "fortify-known-object",
        flags: "-D_FORTIFY_SOURCE=3",
        expected: &["off", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "freebsd"]),
        inert_because: "the level-1 wrappers, like the level-3 ones, exist only under \
                        __OPTIMIZE__, so the known-object overrun runs unchecked and the \
                        probe reports that it survived",
    },
    InertForm {
        check: "fortify-level-ge-2-subobject",
        probe: "fortify-subobject",
        flags: "-D_FORTIFY_SOURCE=3",
        expected: &["off", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "freebsd"]),
        inert_because: "the subobject bound is asked of a wrapper that does not exist at \
                        -O0, so the write that leaves the member runs unchecked",
    },
    InertForm {
        check: "fortify-level-ge-2-percent-n",
        probe: "fortify-percent-n",
        flags: "-D_FORTIFY_SOURCE=3",
        expected: &["off", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "freebsd"]),
        inert_because: "the %n rejection lives in the fortified printf wrapper, which the \
                        headers install only under __OPTIMIZE__, so the plain printf runs \
                        and the probe reports that it survived",
    },
    InertForm {
        check: "cet-macro",
        probe: "toolchain-macros",
        flags: "-fcf-protection=full",
        expected: &["unsupported"],
        applies: Applies::ArchOutside(&["x86_64", "x86"]),
        inert_because: "CET is an x86 mechanism; off x86 the flag names nothing the target \
                        can express, and the arch gate settles the check before any build",
    },
    InertForm {
        check: "cet-marked",
        probe: "link-defaults",
        flags: "-fcf-protection=full",
        expected: &["unsupported"],
        applies: Applies::ArchOutside(&["x86_64", "x86"]),
        inert_because: "the artifact reading of the same x86-only mechanism",
    },
    // The marking forged by the linker: an object with no `endbr64` linked `-z ibt -z shstk`
    // carries both property bits. Measured 2026-10-05 on Fedora 44 x86_64 (gcc 16.1.1, clang
    // 22.1.8, GNU ld 2.46.1): `probe-invalid`, withheld as `regime-confounded`, under both
    // compilers. `unsupported` off x86 is the arch gate, derived and not measured on an
    // aarch64 host.
    InertForm {
        check: "cet-marked",
        probe: "link-defaults",
        flags: "-fcf-protection=none -Wl,-z,ibt -Wl,-z,shstk",
        expected: &["probe-invalid", "unsupported"],
        applies: Applies::ElfArtifact,
        inert_because: "the linker forces both bits over code compiled with no landing pad \
                        and no shadow-stack awareness, so the marking claims what the code \
                        does not carry",
    },
    InertForm {
        check: "cet-marked-object",
        probe: "cet-object",
        flags: "-fcf-protection=full",
        expected: &["unsupported"],
        applies: Applies::ArchOutside(&["x86_64", "x86"]),
        inert_because: "the object-file reading of the same x86-only mechanism",
    },
    // `shadow-stack-enforced` is graded (`opt-in` below `default`): the running program's
    // reading of the same flag. Three forms, the first two inert wherever the flag is, the
    // third inert under the C library upstream ships. Measured 2026-10-02 at the probe that
    // reads the unpinned run, by hand and through chard: on the Fedora 44 x86_64 host
    // (glibc 2.43, gcc 16.1.1 and clang 22.1.8, a CPU that enumerates CET shadow stack)
    // `-fcf-protection=full` reads `partial` at `opt-in`; in the `ubuntu:24.04` image
    // (glibc 2.39) the program read the same by hand; in the Alpine edge image (musl 1.2.6,
    // gcc 15.2.0) it read `features=0` and the clobber taken with the pin set and without
    // it, and the container makes the cell `indeterminate` under `needs-vm` before the libc
    // is consulted, so the musl set carries both. `unsupported` in the glibc set is a kernel
    // without user shadow stack or a target off x86_64, and `indeterminate` a CPU without
    // CET_SS or a container: none of them is the form doing something. `probe-invalid` in the
    // glibc set is derived from the detector and the gates, not measured: a glibc that never
    // enables the shadow stack (before 2.39, which spoke the out-of-tree CET interface, or one
    // built without `--enable-cet`) on a kernel and CPU that have it reads `features=0` under
    // the pin, so the positive control is silent, no machine or libc gate claims the cell, and
    // the triple cannot discriminate.
    InertForm {
        check: "shadow-stack-enforced",
        probe: "shadow-stack",
        flags: "-fcf-protection=full",
        expected: &["indeterminate"],
        applies: Applies::ArchOutside(&["x86_64"]),
        inert_because: "the probe reads x86 CET through `arch_prctl`, which Linux offers on \
                        x86_64 alone, and the gate withholds the check before any build: off \
                        x86_64 the mechanism table has the target answering the question \
                        with a mechanism no check reads (aarch64's Guarded Control Stack), \
                        or having the x86 shadow stack unread (x86), or no row, each \
                        `indeterminate` (`no-check-on-target`, `arch-outside-table`) rather \
                        than the `unsupported` the arch gate published before the table",
    },
    InertForm {
        check: "shadow-stack-enforced",
        probe: "shadow-stack",
        flags: "-fcf-protection=full",
        expected: &["unsupported", "indeterminate"],
        applies: Applies::Libc(&["musl"]),
        inert_because: "musl has no shadow-stack support, so a marked program runs without \
                        one whatever the tunable says",
    },
    InertForm {
        check: "shadow-stack-enforced",
        probe: "shadow-stack",
        flags: "-fcf-protection=full",
        expected: &["partial", "unsupported", "indeterminate", "probe-invalid"],
        applies: Applies::Libc(&["glibc"]),
        inert_because: "glibc 2.39 and later enable the shadow stack only for a process \
                        that sets `GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK`, so a marked \
                        program run as a deployment runs it has none; the check reads \
                        `opt-in` there, below the ask, and never `on`. An earlier glibc, or \
                        one built without CET, enables it under no tunable, so the positive \
                        control is silent and the cell `probe-invalid`",
    },
    InertForm {
        check: "cet-endbr-emitted",
        probe: "cet-endbr",
        flags: "-fcf-protection=full",
        expected: &["unsupported"],
        applies: Applies::ArchOutside(&["x86_64", "x86"]),
        inert_because: "the landing-pad reading of the same x86-only mechanism",
    },
    // Not required by the corpus invariant: `cet-endbr-emitted` grades nothing and neither
    // arm carries -O2. Measured 2026-10-02 with chard from the wf-u-cet-endbr64 tree,
    // `--probe cet-endbr`: both forms below read `off`, over a triple that discriminated,
    // under gcc 16.1.1 and clang 22.1.8 (Fedora 44 x86_64), gcc 15.2.0 and clang 23.1.2
    // (Alpine, musl), gcc 13.3.0 and clang 18.1.3 (Ubuntu 24.04), gcc 11.4.0 and clang 14.0.0
    // (Ubuntu 22.04), gcc 12.2.0 (Debian 12 i386), and gcc 16.2.1 and clang 22.1.8 under
    // `-m32` in a Fedora 44 container; off x86 the arch gate settles both as `unsupported`.
    InertForm {
        check: "cet-endbr-emitted",
        probe: "cet-endbr",
        flags: "-O2 -fcf-protection=return",
        expected: &["off", "unsupported"],
        applies: Applies::ElfArtifact,
        inert_because: "=return asks for the shadow stack alone and compiles no landing pad, \
                        so the flag is present and the branch half the check reads is not",
    },
    InertForm {
        check: "cet-endbr-emitted",
        probe: "cet-endbr",
        flags: "-O2 -fcf-protection=branch -fcf-protection=none",
        expected: &["off", "unsupported"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -fcf-protection=none countermands the request under gcc and \
                        clang alike, and no function begins with a landing pad",
    },
    InertForm {
        check: "branch-protection-macro",
        probe: "toolchain-macros",
        flags: "-mbranch-protection=standard",
        expected: &["unsupported"],
        applies: Applies::ArchOutside(&["aarch64"]),
        inert_because: "branch protection is an aarch64 mechanism; off aarch64 the driver \
                        rejects the flag and the arch gate settles the check first",
    },
    InertForm {
        check: "branch-protection-marked",
        probe: "link-defaults",
        flags: "-mbranch-protection=standard",
        expected: &["unsupported"],
        applies: Applies::ArchOutside(&["aarch64"]),
        inert_because: "the artifact reading of the same aarch64-only mechanism",
    },
    // The aarch64 shape of `cet-marked`'s forged marking: `-z force-bti` sets BTI over code
    // with no landing pad, and the return half comes from the code itself. Measured
    // 2026-10-05 on Fedora 44 aarch64 under qemu-user (gcc 16.2.1, clang 22.1.8, GNU ld
    // 2.46.1, glibc 2.43): `probe-invalid`, withheld as `regime-confounded`, under both
    // compilers. The reading is of the linked artifact's note, so emulation does not touch it.
    InertForm {
        check: "branch-protection-marked",
        probe: "link-defaults",
        flags: "-mbranch-protection=pac-ret -Wl,-z,force-bti",
        expected: &["probe-invalid"],
        applies: Applies::ElfArchInside(&["aarch64"]),
        inert_because: "the linker forces the BTI bit over code compiled with no landing \
                        pad, so the marking claims a branch protection the code does not carry",
    },
    // The same forcing with nothing from the code, measured as the row above under both
    // compilers.
    InertForm {
        check: "branch-protection-marked",
        probe: "link-defaults",
        flags: "-mbranch-protection=none -Wl,-z,force-bti",
        expected: &["probe-invalid"],
        applies: Applies::ElfArchInside(&["aarch64"]),
        inert_because: "the linker forces the BTI bit over code compiled with no landing pad",
    },
    // `-z gcs=always` forces the GCS bit the same way, with GNU ld and LLD alike. Measured as
    // the rows above: `probe-invalid`, withheld as `regime-confounded`.
    InertForm {
        check: "gcs-marked",
        probe: "link-defaults",
        flags: "-mbranch-protection=none -Wl,-z,gcs=always",
        expected: &["probe-invalid"],
        applies: Applies::ElfArchInside(&["aarch64"]),
        inert_because: "the linker forces the GCS bit over code compiled with no \
                        shadow-stack awareness",
    },
    InertForm {
        check: "pie",
        probe: "link-defaults",
        flags: "-fPIE -no-pie",
        expected: &["off", "not-applicable"],
        applies: Applies::ElfArtifact,
        inert_because: "position-independent code linked as a fixed-address executable is \
                        ET_EXEC; the request reached the compiler and the link discarded it",
    },
    InertForm {
        check: "relro",
        probe: "link-defaults",
        flags: "-Wl,-z,relro -Wl,-z,lazy",
        expected: &["partial", "not-applicable"],
        applies: Applies::ElfArtifact,
        inert_because: "-z lazy withholds BIND_NOW, so the segment is present and the \
                        recommended level is not reached",
    },
    // Not required by the corpus invariant: `separate-code` grades nothing and neither arm
    // carries -O2. Measured 2026-10-02 with chard from the wf-s-separate-code tree, `--probe
    // link-defaults`: this form read `off` and its reverse `on` under gcc and clang with GNU
    // ld 2.46.1 (Fedora 44 x86_64), 2.45.1 (Alpine, musl), 2.42 (Ubuntu 24.04), 2.38
    // (Ubuntu 22.04) and 2.40 (Debian 12 i386, gcc), and with `-fuse-ld=lld` (lld 22.1.8)
    // and `-fuse-ld=mold` (mold 2.40.4) before it in the Fedora 44 x86_64 container. A
    // later -z noseparate-code wins on all three linkers.
    InertForm {
        check: "separate-code",
        probe: "link-defaults",
        flags: "-Wl,-z,separate-code -Wl,-z,noseparate-code",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -z noseparate-code countermands the request, and the code \
                        segment's pages hold the read-only data beside the code",
    },
    InertForm {
        check: "relative-relocs",
        probe: "link-defaults",
        flags: "-Wl,-z,pack-relative-relocs -fno-PIE -no-pie",
        // `probe-invalid` is accepted for a binutils too old to emit DT_RELR at all, where
        // the positive control is silent and the check is withheld whatever the profile.
        // `off` is not accepted: on a fixed-address link the linker silently ignores the
        // flag, and `report::artifact_limitation` makes that reading `not-applicable`, so
        // the row keeps no verdict the corpus cannot produce.
        expected: &["not-applicable", "indeterminate", "probe-invalid"],
        applies: Applies::ElfArtifact,
        inert_because: "relative relocations presuppose position independence; the linker \
                        accepts the keyword on a fixed-address link and packs nothing",
    },
    InertForm {
        check: "ssp-covers-small-arrays",
        probe: "ssp-small-array",
        // Far above any array the probe holds or could reasonably grow: the probe's one
        // construct is four bytes, and a value that merely exceeds it would be back below
        // the threshold the day a second construct is added.
        flags: "-fstack-protector --param ssp-buffer-size=65536",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "plain -fstack-protector instruments only functions holding an \
                        array of at least ssp-buffer-size bytes, and no array in the probe \
                        qualifies at this threshold",
    },
    // The two `-fexceptions` checks' arms carry no -O, so the invariant does not cover them
    // (neither is graded and neither result depends on -O: measured at -O0 and -O2 on gcc
    // and clang, Fedora 44 x86_64 and aarch64, Alpine with musl, Ubuntu 22.04 and 24.04,
    // 2026-10-01). The rows are for the one form in which the flag is present and does
    // nothing, a later -fno-exceptions, which read macro and table 0 on all of those.
    InertForm {
        check: "exceptions-macro",
        probe: "exceptions",
        flags: "-fexceptions -fno-exceptions",
        expected: &["off"],
        applies: Applies::Always,
        inert_because: "a later -fno-exceptions countermands the request; the macro must \
                        follow the last spelling on the line",
    },
    // `ubsan-trap-mode`'s arms carry no -O and the check is not graded, so the invariant
    // does not cover it; the rows are the two forms in which the flag is on the line and
    // does nothing. Measured 2026-10-02 with `objdump -d` over the probe's object on Fedora
    // 44 x86_64 (gcc 16.1.1, clang 22.1.8): no trap in the function under either form, at
    // -O0 and -O2, and the handler calls under the second. The gate admits x86_64 and
    // aarch64, the machines every test host is.
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-fsanitize-trap=undefined",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "trap mode chooses how an enabled sanitizer reports, and without \
                        -fsanitize=undefined no check is compiled to trap",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=undefined",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -fno-sanitize-trap=undefined countermands the request, and \
                        every check calls its runtime handler instead",
    },
    // A group named out of trap mode beside the trapped rest, whose handler call the object
    // does not show: the artifact traps every group it can show, so the cell read `on` until
    // 2026-10-08, true of the artifact and not of the request. The measured compile's sanitizer
    // words, read from the driver's -### command, name the group enabled and untrapped, and
    // `sanitizer-group-unmeasured` withholds. Two reasons the object shows no handler: the
    // probe holds no construct (`enum` and `return`, which neither compiler checks in C;
    // clang's `object-size`, where gcc's has one and reads `indeterminate` under
    // `trap-beside-handler`), or the compiler folds the handler call beneath a trapped check
    // on the same access (gcc 16.1.1's `alignment` and `nonnull-attribute`, clang 22.1.8's
    // `nonnull-attribute` and `nullability-arg`, measured at -O2 on Fedora 44 x86_64 with no
    // `__ubsan_handle_` symbol in the object).
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=enum",
        expected: &["indeterminate"],
        applies: Applies::ElfArtifact,
        inert_because: "enum is enabled and left in handler mode, and the probe holds no \
                        construct for it, so the mode of that group is unmeasured",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=return",
        expected: &["indeterminate"],
        applies: Applies::ElfArtifact,
        inert_because: "return is enabled and left in handler mode, and the probe holds no \
                        construct for it in C, so the mode of that group is unmeasured",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=object-size",
        expected: &["indeterminate"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "clang's object-size is enabled and left in handler mode, and the probe \
                        holds no object of known size for it, so its mode is unmeasured",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=nonnull-attribute",
        expected: &["indeterminate"],
        applies: Applies::ElfArtifact,
        inert_because: "nonnull-attribute is enabled and left in handler mode, and its handler \
                        call is folded beneath the trapped null check on the same access, so \
                        the object shows no handler and its mode is unmeasured",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=alignment",
        expected: &["indeterminate"],
        applies: Applies::ElfCompiler(&["gcc"]),
        inert_because: "gcc folds alignment's handler call beneath the trapped null check on the \
                        same access, so the object shows no handler and its mode is unmeasured",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -fsanitize=undefined,nullability-arg -fsanitize-trap=undefined,nullability-arg -fno-sanitize-trap=nullability-arg",
        expected: &["indeterminate"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "nullability-arg, enabled beside undefined since that group does not hold \
                        it, is named out of trap mode; clang folds its handler call beneath the \
                        trapped nonnull check on the same argument, so the object shows no \
                        handler and its mode is unmeasured",
    },
    // Two clang forms, measured through chard `--cc clang
    // --profile explicit --probe ubsan-trap` under clang 22.1.8 on Fedora 44 x86_64 (the
    // harness here runs the host `cc`, so on a gcc host both rows are gaps). The first is
    // the group the compiler drops: the observation's own `build.stderr` carries clang's
    // warning that the object size sanitizer has no effect at -O0, and `off` there says the
    // group was dropped, not that it runs in handler mode. The second is the negation of a
    // group that traps by default. `-fsanitize=local-bounds -fsanitize-trap=local-bounds` is
    // not a row: the trap flag restates clang's default for that group and the build does
    // trap, so `on` is the mechanism in effect rather than a flag read as inert.
    //
    // The second row's floor is clang 20. Under Ubuntu 24.04's clang 18.1.3 and 19.1.1
    // (x86_64, 2026-10-13) it reads `indeterminate` (gating sanitizer-group-unmeasured), and
    // `make compiler-arms` fails on it: probe_sources reads a ud2 trap for local-bounds there
    // with or without -fno-sanitize-trap=local-bounds, so the countermand is not in force
    // and the row is not an inert form on those compilers. 20.1.2 reads `off`.
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O0 -fsanitize=object-size -fsanitize-trap=object-size",
        expected: &["off"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "clang drops object-size at -O0 with a warning, so no check exists \
                        to trap and none is reported enabled",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -fsanitize=local-bounds -fsanitize-trap=local-bounds \
                -fno-sanitize-trap=local-bounds",
        expected: &["off"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "a later -fno-sanitize-trap=local-bounds countermands the request \
                        and clang's default for the group, and the check calls \
                        __ubsan_handle_local_out_of_bounds instead",
    },
    // The observable present with no trap-mode flag on the line, as in the strict-aliasing
    // rows below: -ftrapv enables no sanitizer, yet clang compiles it to the trap UBSan's
    // signed-overflow check emits (ud1 with check number 0 on x86_64), which the detector's
    // `overflow-trap-only` clause withholds rather than reading `on`. The unit tests in
    // `src/elf/code.rs` and `tests/predicates.rs` hold that clause to bytes; these rows hold
    // it to a compiled probe. Measured 2026-10-02, `--profile explicit`: both rows, and
    // -O1, -O3, -Os and -Og with -ftrapv, read `indeterminate` on Fedora 44 x86_64 under
    // gcc 16.1.1 (a call to libgcc, no trap) and clang 22.1.8 (the check-0 trap alone),
    // and on Fedora 44 aarch64 under gcc 16.2.1 and clang 22.1.8. With `x86-ud1-check`
    // widened to every ud1, clang's rows read `on` on x86_64 and fail here.
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-ftrapv",
        expected: &["indeterminate"],
        applies: Applies::ElfArtifact,
        inert_because: "-ftrapv with no sanitizer traps on signed overflow under clang, with \
                        check number 0, and calls libgcc under gcc; neither is UBSan's \
                        trap mode",
    },
    InertForm {
        check: "ubsan-trap-mode",
        probe: "ubsan-trap",
        flags: "-O2 -ftrapv",
        expected: &["indeterminate"],
        applies: Applies::ElfArtifact,
        inert_because: "the same flag with the optimizer on: clang still emits only the \
                        check-0 trap and gcc still calls libgcc, and neither is UBSan's \
                        trap mode",
    },
    InertForm {
        check: "except-table-emitted",
        probe: "exceptions",
        flags: "-fexceptions -fno-exceptions",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -fno-exceptions countermands the request, and the cleanup \
                        region gets no landing pad and so no table",
    },
    // A forged macro rather than an inert flag, which would read `on` were `__EXCEPTIONS`
    // not on `measure`'s compiler-defined list (Fedora 44 x86_64, gcc 16.1.1 and clang
    // 22.1.8, 2026-10-01).
    InertForm {
        check: "exceptions-macro",
        probe: "exceptions",
        flags: "-D__EXCEPTIONS=1",
        expected: &["indeterminate"],
        applies: Applies::Always,
        inert_because: "the flag list defines the compiler's macro itself and requests no \
                        unwind tables, so the reading is withheld as supplied by the profile",
    },
    // Measured 2026-10-01 over `probes/exceptions.c` at -O2: macro 1 and table 0 under
    // clang 14.0.0 (Ubuntu 22.04), 18.1.3 (Ubuntu 24.04), 22.1.8 (Fedora 44) and 23.1.2
    // (Alpine), all x86_64; gcc 11.4.0 through 16.1.1 reject the flag. The macro reads
    // `on` there, which is why this row is the table's and the macro's notes name the form.
    InertForm {
        check: "except-table-emitted",
        probe: "exceptions",
        flags: "-fexceptions -fignore-exceptions",
        expected: &["off"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "clang's -fignore-exceptions keeps -fexceptions on the line and its \
                        macro defined, and removes the landing pad the cleanup needs, so \
                        no table is emitted",
    },
    // gcc 13 and later read -fnon-call-exceptions as -fexceptions, and both checks read it
    // `on` there (gcc 16.1.1 Fedora 44 x86_64, gcc 16.2.1 Fedora 44 aarch64), which is why
    // the flag keys with the `exceptions` family; that side is a true `on` and has no row.
    // Under clang the flag does nothing in C: macro and table both read `off` (clang
    // 22.1.8, Fedora 44 x86_64 and aarch64, measured 2026-10-01).
    InertForm {
        check: "exceptions-macro",
        probe: "exceptions",
        flags: "-fnon-call-exceptions",
        expected: &["off"],
        applies: Applies::Compiler(&["clang"]),
        inert_because: "clang accepts -fnon-call-exceptions and neither defines __EXCEPTIONS \
                        nor enables unwind tables for C under it",
    },
    InertForm {
        check: "except-table-emitted",
        probe: "exceptions",
        flags: "-fnon-call-exceptions",
        expected: &["off"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "clang accepts -fnon-call-exceptions and gives the cleanup region no \
                        landing pad under it, so no table is emitted",
    },
    // Not an inert flag but an inert artifact: under gcc's -flto the object is slim, and
    // the table the flag asks for is emitted at the final link, which the probe does not
    // perform. Before `report::lto_ir_limitation` this read `off` over a discriminating
    // triple on Fedora 44 x86_64 (gcc 16.1.1, 2026-10-01). clang's -flto object is bitcode,
    // which the reader does not parse, and reads `indeterminate` on its own.
    InertForm {
        check: "except-table-emitted",
        probe: "exceptions",
        flags: "-fexceptions -flto",
        expected: &["indeterminate"],
        applies: Applies::ElfArtifact,
        inert_because: "the object holds compiler IR and no generated code, so the reading \
                        is withheld rather than read as a table that was never emitted",
    },
    // `plt-bypassed`'s arms carry no -O, and its reading was the same at -O0 and -O2
    // (gcc 11.4.0 to 16.2.1, clang 14.0.0 to 23.1.2, gcc 12.2.0 on i386, 2026-10-02), so the
    // invariant does not cover it. The last of -fno-plt and -fplt wins on every compiler
    // measured. gcc on aarch64 also ignores -fno-plt in code that is not
    // position-independent and reads `off` there (`-fno-pic -fno-plt`, and plain -fno-plt on
    // Fedora's gcc, which does not default to PIE); no `Applies` names a compiler on one
    // architecture, so that form is carried by the check's notes and the
    // 2026-10-02 -fno-plt note in the project ledger rather than by a row.
    InertForm {
        check: "plt-bypassed",
        probe: "no-plt",
        flags: "-fno-plt -fplt",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -fplt countermands the request, and the call is a direct \
                        call through the PLT",
    },
    // Not an inert flag but an inert artifact, as for `except-table-emitted` above: gcc's
    // -flto object holds no code and so no call, and clang's is bitcode.
    InertForm {
        check: "plt-bypassed",
        probe: "no-plt",
        flags: "-O2 -fno-plt -flto",
        expected: &["indeterminate"],
        applies: Applies::ElfArtifact,
        inert_because: "the object holds compiler IR and no generated call, so the reading \
                        is withheld rather than read from a relocation that was never emitted",
    },
    // The two -ftrapv checks' arms carry no -O, so the invariant does not cover them (the
    // helper call and the overflow's death were the same at -O0, -O1, -O2, -O3, -Os and -Og
    // under gcc 11.4.0 to 16.2.1 and clang 14.0.0 to 23.1.2, 2026-10-02). The rows are the
    // forms in which the flag is on the line and does nothing. On gcc the last of -ftrapv,
    // -fno-trapv and -fwrapv wins, so a later -fno-trapv or -fwrapv calls no helper and the
    // sum wraps; clang has no -fno-trapv, and its -ftrapv traps under -fwrapv in either
    // order, so those rows are gcc's alone.
    InertForm {
        check: "trapv-helper-called",
        probe: "trapv-helper",
        flags: "-ftrapv -fno-trapv",
        expected: &["off"],
        applies: Applies::ElfCompiler(&["gcc"]),
        inert_because: "a later -fno-trapv countermands the request, and gcc calls no \
                        trapping helper",
    },
    InertForm {
        check: "trapv-helper-called",
        probe: "trapv-helper",
        flags: "-ftrapv -fwrapv",
        expected: &["off"],
        applies: Applies::ElfCompiler(&["gcc"]),
        inert_because: "on gcc a later -fwrapv makes signed overflow wrap and replaces the \
                        trapping helpers with plain arithmetic",
    },
    InertForm {
        check: "trapv-trapped",
        probe: "trapv",
        flags: "-ftrapv -fno-trapv",
        expected: &["off"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "a later -fno-trapv countermands the request, and the sum wraps",
    },
    InertForm {
        check: "trapv-trapped",
        probe: "trapv",
        flags: "-ftrapv -fwrapv",
        expected: &["off"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "on gcc a later -fwrapv defines the overflow to wrap, and the sum \
                        wraps",
    },
    // UBSan's signed-overflow check takes the arithmetic from -ftrapv when both are on the
    // line: under gcc the object calls no helper and the overflow traps through the
    // sanitizer (SIGILL on x86, SIGTRAP on aarch64) rather than aborting through libgcc;
    // under clang the trap is the same either way, and the feature test shows the check.
    // Measured with `-fsanitize-trap=signed-integer-overflow` on gcc 13.3.0 to 16.2.1 and
    // clang 14.0.0 to 23.1.2, 2026-10-02; the older spelling below is the one gcc 11 and
    // 12 also accept.
    InertForm {
        check: "trapv-helper-called",
        probe: "trapv-helper",
        flags: "-ftrapv -fsanitize=signed-integer-overflow -fsanitize-undefined-trap-on-error",
        expected: &["off"],
        applies: Applies::ElfCompiler(&["gcc"]),
        inert_because: "the sanitizer instruments the arithmetic in place of -ftrapv, so \
                        gcc calls no trapping helper",
    },
    InertForm {
        check: "trapv-trapped",
        probe: "trapv",
        flags: "-ftrapv -fsanitize=signed-integer-overflow -fsanitize-undefined-trap-on-error",
        expected: &["indeterminate"],
        applies: Applies::Always,
        inert_because: "the overflow traps through the sanitizer's check rather than \
                        -ftrapv's, which gcc's -ftrapv never does and which clang's cannot \
                        be told apart from, so the reading is withheld",
    },
    // In recovering mode the sanitizer reports and the sum wraps, -ftrapv beside it or not.
    // The full runtime's report says `runtime error:`; clang's minimal runtime says `ubsan:
    // add-overflow by 0x...` and exits 0, which a detector looking for `runtime error:` alone
    // would read as the flag `off` (clang 22.1.8, Fedora 44 x86_64, 2026-10-02). The rows run only
    // where the runtime links: Fedora 44 ships no libubsan for gcc.
    InertForm {
        check: "trapv-trapped",
        probe: "trapv",
        flags: "-ftrapv -fsanitize=signed-integer-overflow",
        expected: &["indeterminate"],
        applies: Applies::CompilerRuntime(&["gcc", "clang"], "-fsanitize=signed-integer-overflow"),
        inert_because: "the sanitizer's recovering check takes the addition, reports it and \
                        lets the sum wrap, so the run does not show what -ftrapv does",
    },
    InertForm {
        check: "trapv-trapped",
        probe: "trapv",
        flags: "-ftrapv -fsanitize=signed-integer-overflow -fsanitize-minimal-runtime",
        expected: &["indeterminate"],
        applies: Applies::CompilerRuntime(
            &["clang"],
            "-fsanitize=signed-integer-overflow -fsanitize-minimal-runtime",
        ),
        inert_because: "the minimal runtime's recovering check takes the addition, reports \
                        it without `runtime error:` and lets the sum wrap, so the run does \
                        not show what -ftrapv does",
    },
    // `pic-shared-link` is neither graded nor optimization-gated, so the invariant does not
    // require these; they hold the check's reverse error, a link that succeeds without
    // -fPIC. The verdicts are measured on 2026-10-02 with chard from the
    // wf-s-fpie-shared-diag tree: gcc and clang on Fedora 44 x86_64 (GNU ld, lld and mold)
    // and aarch64 (GNU ld), and in the Ubuntu 22.04, Ubuntu 24.04 and Alpine containers.
    // The first row is gated off 32-bit x86 (the report's kernel arch `x86`): in the i386
    // container the same day every cell read `probe-invalid`, GNU ld linking non-PIC code
    // there by text relocation, so `off` is not what that target gives and the row is a
    // gap there rather than a widened expectation that would also admit it on x86_64.
    InertForm {
        check: "pic-shared-link",
        probe: "pic-shared-link",
        flags: "-fPIC -fPIE",
        expected: &["off"],
        applies: Applies::ElfArchOutside(&["x86"]),
        inert_because: "a later -fPIE countermands -fPIC, and the code addresses its own \
                        exported global directly, which the linker refuses in a shared object",
    },
    // Not an inert flag but the observable without the flag: -Bsymbolic binds the probe's
    // global locally and a -fPIE object links. The regime arm, the profile followed by
    // -fPIE, links too, and withholds.
    InertForm {
        check: "pic-shared-link",
        probe: "pic-shared-link",
        flags: "-O2 -fPIE -Wl,-Bsymbolic",
        expected: &["probe-invalid"],
        applies: Applies::ElfArtifact,
        inert_because: "the link succeeds because -Bsymbolic made the reference local, not \
                        because the code is position-independent",
    },
    // Non-PIC code linked whole by text relocation. GNU ld and mold link it on x86_64 and
    // the regime arm's large-model -fPIE links too, so the cell is `probe-invalid`; lld
    // refuses that arm, and the detector's `-z notext` reading withholds the measured build
    // itself, `indeterminate`. On aarch64 gcc links it and clang refuses it, but both
    // compilers reject `-mcmodel=large` with `-fPIE`, so the regime arm cannot be built and
    // the cell is `probe-invalid` (measured 2026-10-02, Fedora 44 aarch64, clang 22.1.8).
    // No measured cell reads `off`.
    InertForm {
        check: "pic-shared-link",
        probe: "pic-shared-link",
        flags: "-O2 -fno-pic -mcmodel=large -Wl,-z,notext",
        expected: &["indeterminate", "probe-invalid"],
        applies: Applies::ElfArtifact,
        inert_because: "-z notext lets the linker take non-PIC code by text relocation, so a \
                        link that succeeds shows nothing about position independence",
    },
    // `pic-object-relocs` is neither graded nor optimization-gated either, and these rows
    // hold the same reverse error on the object: -fPIC on the line and the code built
    // without it. Measured on 2026-10-02 with chard from the wf-u-fpic-object-relocs tree:
    // gcc and clang on Fedora 44 x86_64 and aarch64 and in the Ubuntu 22.04, Ubuntu 24.04
    // and Alpine containers, and gcc 12.2.0 on Debian 12 i386, where the object reads `off`
    // as well (`R_386_GOTOFF`, `R_386_32`).
    InertForm {
        check: "pic-object-relocs",
        probe: "pic-object",
        flags: "-fPIC -fPIE",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -fPIE countermands -fPIC, and the code reaches its own \
                        exported global directly",
    },
    InertForm {
        check: "pic-object-relocs",
        probe: "pic-object",
        flags: "-O2 -fPIC -fno-pic",
        expected: &["off"],
        applies: Applies::ElfArtifact,
        inert_because: "a later -fno-pic countermands -fPIC, and the code reaches its own \
                        exported global by an absolute or PC-relative relocation",
    },
    // A GOT access with no -fPIC on the line: clang's -fsanitize=hwaddress reaches the
    // probe's own exported global through the GOT under -fPIE and -fno-pic alike, so the
    // measured cell reads `present`. Both controls are profile-free and discriminate; the
    // regime arm, the profile followed by -fPIE, reads `present` too and withholds the
    // cell as regime-confounded. Measured on 2026-10-02 with chard from the
    // wf-u-fpic-object-relocs tree: clang 22.1.8 on Fedora 44 x86_64 and aarch64, and
    // clang 14.0.0, 18.1.3 and 23.1.2 in the Ubuntu 22.04, Ubuntu 24.04 and Alpine
    // containers. gcc's hwasan reaches the global directly and reads `off`, so the row
    // is clang's.
    InertForm {
        check: "pic-object-relocs",
        probe: "pic-object",
        flags: "-O2 -fPIE -fsanitize=hwaddress",
        expected: &["probe-invalid"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "clang's hwasan instrumentation reaches a defined global through the \
                        GOT whatever the code model, so the GOT relocation is the \
                        sanitizer's and not -fPIC's",
    },
    // -fPIC on the line and the probe's global made hidden over its explicit default
    // visibility: clang's -fvisibility-from-dllstorageclass, whose
    // -fvisibility-nodllstorageclass defaults to hidden, overrides the attribute on ELF,
    // and -fPIC then reaches the global directly, as -fPIE does. The regime arm adds -fPIE,
    // also direct, so a reader that did not record the anchor's visibility would read the
    // cell `off` over a discriminating triple. The measured build and the regime arm both
    // read `indeterminate` on the hidden anchor, and the cell is `probe-invalid`
    // (regime-unevaluable). Measured on 2026-10-02: clang 22.1.8 on Fedora 44 x86_64 and aarch64,
    // and clang 14.0.0, 18.1.3 and 23.1.2 in the Ubuntu 22.04, Ubuntu 24.04 and Alpine containers.
    // gcc rejects the flag, so the row is clang's.
    InertForm {
        check: "pic-object-relocs",
        probe: "pic-object",
        flags: "-O2 -fPIC -fvisibility-from-dllstorageclass -fvisibility-nodllstorageclass=hidden",
        expected: &["probe-invalid"],
        applies: Applies::ElfCompiler(&["clang"]),
        inert_because: "the flag pair makes the probe's exported global hidden, and a hidden \
                        global is reached directly under -fPIC as under -fPIE, so the \
                        relocation does not say which was given",
    },
    // Not an inert flag but an object that cannot show it: a slim LTO object holds
    // intermediate code, gcc's in an ELF file with no code relocation and clang's in a
    // bitcode file chard does not read as ELF, so the cell withholds rather than reading
    // the -fPIC on the line. Under gcc the regime arm's object is the same slim LTO
    // object, so gcc's cell is
    // `probe-invalid` (regime-unevaluable) and clang's, which never reached ELF,
    // `indeterminate`; measured 2026-10-02 on both Fedora 44 hosts and in the four
    // containers.
    InertForm {
        check: "pic-object-relocs",
        probe: "pic-object",
        flags: "-O2 -fPIC -flto",
        expected: &["indeterminate", "probe-invalid"],
        applies: Applies::ElfArtifact,
        inert_because: "the object holds LTO intermediate code, so no relocation in it says \
                        how the code reaches the global",
    },
    InertForm {
        check: "no-strict-aliasing",
        probe: "ub-strict-aliasing",
        flags: "-fno-strict-aliasing",
        expected: &["indeterminate"],
        applies: Applies::Always,
        inert_because: "the check's own notes: without optimization the store is observed \
                        with or without the flag, so the detector requires __OPTIMIZE__",
    },
    // The two rows below are the same false `on` from the other side: the observable
    // present with the flag absent, as in the `ssp-level` row's countermanded request.
    // gcc applies the aliasing rule by default only from -O2 and -Os, so at -O1 and -Og
    // the store is observed with no flag passed. Without the probe's witnesses both read `on`
    // under gcc 16.1.1 (Fedora 44 x86_64) and gcc 16.2.1 (Fedora 44 aarch64), `--profile
    // explicit`, 2026-10-01. With them both read `indeterminate` on those hosts, and
    // the probe's per-compiler readings agree for gcc 7.5 to 15.2. clang applies the rule
    // from -O1 and reads `off` there, so the rows are gcc's alone.
    //
    // `-O1 -fno-strict-aliasing` and `-Og -fno-strict-aliasing` are the flag itself
    // present and inert, the rows after the two bare ones. On gcc 12 and later the copy the
    // probe compiles at -O2 keeps the flag and observes the store, so without a witness the
    // probe prints the same stdout at -O1 with the flag as at -O2 with it. The probe's
    // tail-call witness names the level, and chard reads both forms `indeterminate` under
    // gcc 16.1.1 and 16.2.1. Under gcc 11.4, 12.2, 13.3 and 15.2 the
    // probe was built by hand and its lines read through the decoder's rule, not by chard;
    // the 2026-10-01 notes in the project ledger record both.
    InertForm {
        check: "no-strict-aliasing",
        probe: "ub-strict-aliasing",
        flags: "-O1",
        expected: &["indeterminate"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "gcc does not apply the aliasing rule at -O1 by default, so the \
                        store is observed with no flag passed, and the copy the probe \
                        compiles at -O2 loses it",
    },
    InertForm {
        check: "no-strict-aliasing",
        probe: "ub-strict-aliasing",
        flags: "-Og",
        expected: &["indeterminate"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "gcc does not apply the aliasing rule at -Og by default, so the \
                        store is observed with no flag passed, and the copy the probe \
                        compiles at -O2 loses it",
    },
    InertForm {
        check: "no-strict-aliasing",
        probe: "ub-strict-aliasing",
        flags: "-O1 -fno-strict-aliasing",
        expected: &["indeterminate"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "gcc does not apply the aliasing rule at -O1 by default, so there \
                        is no rule for the flag to turn off; the build's tail call stays a \
                        call, which names the level",
    },
    InertForm {
        check: "no-strict-aliasing",
        probe: "ub-strict-aliasing",
        flags: "-Og -fno-strict-aliasing",
        expected: &["indeterminate"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "gcc does not apply the aliasing rule at -Og by default, so there \
                        is no rule for the flag to turn off; the build's tail call stays a \
                        call, which names the level",
    },
    // The observable present with the flag absent, from a sanitizer rather than a level:
    // clang's recoverable alignment check, part of -fsanitize=undefined, keeps the reload
    // the rule would fold. Without the probe's uninstrumented copy this reads `on` under clang
    // 22.1.8 (Fedora 44 x86_64, 2026-10-01); with it the probe's lines read
    // `indeterminate` through the decoder under clang 14.0.0, 18.1.3 and 22.1.8. gcc's
    // sanitizers keep nothing the rule folds (gcc 11.4 to 16.2.1), so the rows are clang's.
    InertForm {
        check: "no-strict-aliasing",
        probe: "ub-strict-aliasing",
        flags: "-O2 -fsanitize=undefined",
        expected: &["indeterminate"],
        applies: Applies::CompilerRuntime(&["clang"], "-fsanitize=undefined"),
        inert_because: "the rule is in force and the alignment check's handler call keeps \
                        the reload, so the store is observed with no flag passed; the copy \
                        built without instrumentation loses it",
    },
    // The flag itself present and inert: under clang's -fsanitize=type the store is
    // observed with or without -fno-strict-aliasing, and the uninstrumented copy, which
    // still carries the aliasing tags that sanitizer needs, loses it either way (clang
    // 22.1.8, Fedora 44 x86_64, 2026-10-01). The floor is clang 20: Ubuntu 24.04's clang
    // 18.1.3 and 19.1.1 do not build -fsanitize=type, so the row is announced there and
    // `make compiler-arms` fails on it (x86_64, 2026-10-13); 20.1.2 runs it.
    InertForm {
        check: "no-strict-aliasing",
        probe: "ub-strict-aliasing",
        flags: "-O2 -fno-strict-aliasing -fsanitize=type",
        expected: &["indeterminate"],
        applies: Applies::CompilerRuntime(&["clang"], "-fsanitize=type"),
        inert_because: "the type sanitizer's instrumented code keeps the reload whatever \
                        the flag says, so the build observes the store with the flag and \
                        without it",
    },
    // Not the flag inert but its observable produced by another route: clang's
    // -fsanitize=safe-stack moves the probe's buffer onto a separately mapped read-write
    // stack, and the payload faults there under -z execstack as well as -z noexecstack, so
    // without a regime arm this exact profile would publish `on` over an RWE PT_GNU_STACK
    // (Fedora 44 x86_64, clang 22.1.8, 2026-10-02). The probe declines because the buffer is
    // not just below `argv`, and with the probe's check removed the regime arm reads
    // `present` and the check withholds on its own. The published verdict is
    // `link-inputs-unmatched-by-arms`'s: the probe runs and declines (`CHARD_EXIT_DECLINED`),
    // and because the driver's `-###` for this link names `libclang_rt.safestack.a` and the
    // arms' names no runtime, the rule withholds the startup-object checks as `indeterminate`
    // over the probe's reading. Measured 2026-10-12 on Fedora 44 x86_64 under clang 22.1.8
    // through `make compiler-arms`, the gate that runs this row. The row pins the verdict word
    // alone: a regression of the probe's decline beneath the rule would still read `indeterminate`
    // and pass here, and nothing in this file asserts the decline itself.
    InertForm {
        check: "noexecstack-enforced",
        probe: "stack-exec-runtime",
        flags: "-Wl,-z,execstack -fsanitize=safe-stack",
        expected: &["indeterminate"],
        applies: Applies::CompilerRuntime(&["clang"], "-fsanitize=safe-stack"),
        inert_because: "the fault the check reads as a non-executable stack is SafeStack's \
                        read-write unsafe stack faulting, whatever PT_GNU_STACK says about \
                        main's",
    },
    InertForm {
        check: "no-delete-null-pointer-checks",
        probe: "ub-null-check",
        flags: "-fno-delete-null-pointer-checks",
        expected: &["run-failed", "probe-invalid", "indeterminate"],
        applies: Applies::Always,
        inert_because: "the check's own notes: without optimization the dead load is not \
                        eliminated and the null dereference executes, so an unoptimized \
                        profile cannot yield a verdict",
    },
    InertForm {
        check: "no-strict-overflow",
        probe: "ub-signed-overflow",
        flags: "-fno-strict-overflow",
        // Measured on the clang leg: with `cc` on PATH resolving to clang 22.1.8 on Fedora
        // 44 aarch64 (glibc 2.43), 2026-09-28, this row reads
        // `indeterminate` and 23 of the 29 rows run, 3 of 3 passing. The leg has a trap on
        // Fedora: `command -v clang` is ccache's shim, which picks the compiler from
        // argv[0], so a `cc` symlink to the shim runs gcc 16.2.1 and this row is announced
        // as unexercised (`this toolchain is gcc`) while the run passes. The symlink has to
        // name `/usr/bin/clang`, and the row's printed verdict line is the check that it
        // did.
        expected: &["indeterminate"],
        applies: Applies::Compiler(&["clang"]),
        inert_because: "the detector's own doc: clang folds the guard only in the optimizer, \
                        so an unoptimized clang build runs it whether or not the flag was \
                        passed, and the verdict is withheld; gcc 8 and later fold it at -O0, \
                        where the flag is the mechanism too, and gcc before 8 is the next \
                        row",
    },
    InertForm {
        check: "no-strict-overflow",
        probe: "ub-signed-overflow",
        flags: "-fno-strict-overflow",
        // The gcc form of the row above. Measured by hand with the probe on x86_64 (gcc
        // 4.8.4, 5.4.0 and 7.5.0 keep the guard at -O0 without the flag, gcc 8.3.0 and later
        // fold it; the detector's doc has the runs), and through chard under gcc 7.5.0 on
        // Ubuntu 18.04 x86_64 and i386, where `--profile
        // explicit --flags -fno-strict-overflow` read `indeterminate`; this test itself has
        // not run there. A gate host has a current gcc, so the row is a host gap there.
        expected: &["indeterminate"],
        applies: Applies::GccBefore(8),
        inert_because: "the detector's own doc: gcc 4.8, 5.4 and 7.5 keep the guard at -O0 \
                        whether or not the flag was passed, as clang does, and the verdict \
                        is withheld below gcc 8; gcc 8 and later fold it at -O0, and the flag is the \
                        mechanism there",
    },
    InertForm {
        check: "no-strict-overflow",
        probe: "ub-signed-overflow",
        flags: "-O1 -fno-strict-overflow",
        // The optimizing level the same gccs keep the guard at. Measured by hand with the
        // probe on x86_64 (gcc 4.8.4, 5.4.0 and 7.5.0 ran the guard at -O1 and -Og with and
        // without the flag, and folded it at -O2 and -Os without it; the detector's doc has
        // the runs), and through chard under all three, where the decoder withholds the
        // `--profile explicit --flags -O1` reading from the compile line's -O word; this test
        // itself has not run there, and the row is a host gap on a gate host, as the row above
        // is.
        expected: &["indeterminate"],
        applies: Applies::GccBefore(8),
        inert_because: "the detector's own doc: at -O1, -Og and -O gcc 4.8, 5.4 and 7.5 keep \
                        the guard whether or not the flag was passed, as they do at -O0, and \
                        the probe reports only that the build was optimized, so the decoder \
                        reads the compile line's last -O word and withholds at those levels; \
                        -O2 and above fold it without the flag, and the flag is the mechanism \
                        there",
    },
    InertForm {
        check: "strict-flex-arrays",
        probe: "strict-flex-arrays",
        flags: "-fstrict-flex-arrays=3",
        expected: &["indeterminate"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "gcc answers __builtin_object_size with -1 for every query without \
                        optimization whatever the flag says, and the detector withholds on \
                        that reading; clang folds the query at -O0, so the form is not \
                        inert there",
    },
    // The enforcement reading of the same flag has three forms. Measured 2026-10-02 by hand
    // with the probe on Fedora 44 x86_64 (gcc 16.1.1, clang 22.1.8) and aarch64 (gcc
    // 16.2.1, clang 22.1.8), glibc 2.43, and on macOS arm64 (Apple clang 21.0.0); through
    // chard on the Linux hosts and in the ubuntu:24.04 and Alpine containers with the
    // commit that adds the check. `probe-invalid` is in each glibc set for clang 18.1.3
    // with glibc 2.39 (ubuntu:24.04), whose ctrl copy is caught in no arm, so the triple
    // withholds under any flags there; musl reads `unsupported` through the libc gate.
    InertForm {
        check: "strict-flex-arrays-enforced",
        probe: "strict-flex-arrays-enforced",
        flags: "-fstrict-flex-arrays=3",
        expected: &["indeterminate", "probe-invalid", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl"]),
        inert_because: "glibc installs its fortified wrappers only under __OPTIMIZE__, so \
                        no copy is checked, the ctrl row survives with the trailing rows, \
                        and the detector withholds; Apple's wrappers check at -O0, where \
                        the form reads level 3 and is not inert",
    },
    InertForm {
        check: "strict-flex-arrays-enforced",
        probe: "strict-flex-arrays-enforced",
        flags: "-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1 -fstrict-flex-arrays=3",
        expected: &["indeterminate", "probe-invalid", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "apple"]),
        inert_because: "fortify level 1 asks for the whole object, which the laundered \
                        pointer hides, so no subobject bound is checked whatever the flag \
                        bounds; the ctrl row survives and the detector withholds",
    },
    InertForm {
        check: "strict-flex-arrays-enforced",
        probe: "strict-flex-arrays-enforced",
        flags: "-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstrict-flex-arrays=3 \
                -fstrict-flex-arrays=0",
        expected: &["off", "probe-invalid", "unsupported"],
        applies: Applies::Libc(&["glibc", "musl", "apple"]),
        inert_because: "the last spelling on the line wins, so every trailing array is \
                        flexible again while the ctrl copy is still caught",
    },
    InertForm {
        check: "hardened-downgrade-warned",
        probe: "hardened-downgrade",
        flags: "-Whardened",
        expected: &["indeterminate", "probe-invalid", "unsupported"],
        applies: Applies::Always,
        inert_because: "the check's own notes: a profile that never passes -fhardened has \
                        nothing for -Whardened to report",
    },
    InertForm {
        check: "implicit-function-declaration-is-error",
        probe: "implicit-function-declaration",
        flags: "-Werror=implicit-function-declaration \
                -Wno-error=implicit-function-declaration",
        expected: &["off"],
        applies: Applies::Always,
        inert_because: "a later -Wno-error= lowers the severity the earlier -Werror= raised",
    },
    InertForm {
        check: "implicit-int-is-error",
        probe: "implicit-int",
        flags: "-Werror=implicit-int -Wno-error=implicit-int",
        expected: &["off"],
        applies: Applies::Always,
        inert_because: "a later -Wno-error= lowers the severity the earlier -Werror= raised",
    },
    InertForm {
        check: "int-conversion-is-error",
        probe: "int-conversion",
        flags: "-Werror=int-conversion -Wno-error=int-conversion",
        expected: &["off"],
        applies: Applies::Always,
        inert_because: "a later -Wno-error= lowers the severity the earlier -Werror= raised",
    },
    InertForm {
        check: "incompatible-pointer-types-is-error",
        probe: "incompatible-pointer-types",
        flags: "-Werror=incompatible-pointer-types -Wno-error=incompatible-pointer-types",
        expected: &["off"],
        applies: Applies::Always,
        inert_because: "a later -Wno-error= lowers the severity the earlier -Werror= raised",
    },
    InertForm {
        check: "format-security-is-error",
        probe: "format-security",
        flags: "-Wformat -Werror=format-security -Wno-error=format-security",
        expected: &["off"],
        applies: Applies::Always,
        inert_because: "a later -Wno-error= lowers the severity the earlier -Werror= raised; \
                        -Wformat is carried so the diagnostic itself is still emitted",
    },
    InertForm {
        check: "format-security-is-error",
        probe: "format-security",
        flags: "-Wno-format -Werror=format-security",
        // Measured on two gcc hosts rather than derived, and the form changed because the
        // derived one was not inert everywhere. `-Werror=format-security` alone is inert
        // only where the compiler leaves `-Wformat-security` off by default: Fedora 44's
        // gcc 16.1.1 reports it `[disabled]`, so the flag is discarded and the build fails
        // with no format diagnostic, while Alpine edge's gcc 15.2.0 reports `-Wformat=1`
        // and `-Wformat-security` `[enabled]`, so the same flag genuinely promotes a real
        // warning to an error and the check reads `on`. That `on` is correct, so the detector is
        // right and the premise that the flag alone is inert fails on a gcc that enables the
        // warning.
        //
        // `-Wno-format` makes the intent explicit, so the form is the promotion flag with
        // the diagnostic it promotes switched off, on any gcc whatever its defaults. Both
        // hosts then answer the same way: `cc1: error: '-Wformat-security' ignored without
        // '-Wformat'`, which carries no source location, so no format diagnostic is found
        // and the detector withholds.
        expected: &["indeterminate", "build-failed", "probe-invalid"],
        applies: Applies::Compiler(&["gcc"]),
        inert_because: "without -Wformat gcc discards -Werror=format-security and fails at \
                        cc1 level with a message carrying no source location, so the build \
                        fails with no format diagnostic and the detector withholds",
    },
    InertForm {
        check: "cxx-hardening-requested",
        probe: "cxx-stdlib-assertions",
        flags: "-D_GLIBCXX_ASSERTIONS",
        expected: &["off", "indeterminate"],
        applies: Applies::CxxStdlib("libc++"),
        inert_because: "libc++ does not read libstdc++'s macro, so the request names a \
                        library that is not the one linked",
    },
    InertForm {
        check: "cxx-hardening-requested",
        probe: "cxx-stdlib-assertions",
        flags: "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
        expected: &["off", "indeterminate"],
        applies: Applies::CxxStdlib("libstdc++"),
        inert_because: "libstdc++ does not read libc++'s macro, so the request names a \
                        library that is not the one linked",
    },
    // `zero-call-used-regs` is graded (`arg` below `gpr`). Measured 2026-10-01, first by
    // building the probe by hand: both forms leave argument registers holding the caller's
    // values, the line reading as the bare build's does, at -O0 through -O3 and -Os under
    // gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64 and gcc 16.2.1 and clang 22.1.8 on
    // Fedora 44 aarch64, and at -O0 and -O2 under OpenBSD 7.9's clang 19.1.7 on amd64 and
    // arm64. Then through chard, `--profile explicit --probe zero-call-used-regs`: both
    // forms read `off` over a discriminating triple under the four Fedora compilers, gcc
    // 11.4.0 (Ubuntu 22.04 container), gcc 13.3.0 and clang 18.1.3 (Ubuntu 24.04), and gcc
    // 15.2.0 and clang 23.1.2 (Alpine), and through this file under Apple clang 21.0.0 on
    // macOS arm64. `unsupported` is in each set for a target outside the check's gate,
    // which is not the form doing something. `build-failed` is not: a driver that does not
    // know the flag, as clang 14.0.0 (Ubuntu 22.04) rejects every spelling, says so on its
    // stderr, the observation carries it as `build_rejection`, and [`judge`] announces the
    // row as a gap. A build that fails with no rejection is a probe broken under a flag the
    // driver knows, and fails the row (2026-10-01; before then each set accepted
    // `build-failed` of either kind).
    InertForm {
        check: "zero-call-used-regs",
        probe: "zero-call-used-regs",
        flags: "-fzero-call-used-regs=skip",
        expected: &["off", "unsupported"],
        applies: Applies::Always,
        inert_because: "`skip` is the value that zeroes no register, the default spelled \
                        out, so a function returns with its registers as it left them",
    },
    InertForm {
        check: "zero-call-used-regs",
        probe: "zero-call-used-regs",
        flags: "-fzero-call-used-regs=used-gpr -fzero-call-used-regs=skip",
        expected: &["off", "unsupported"],
        applies: Applies::Always,
        inert_because: "the last spelling on the line wins, so the requested `used-gpr` is \
                        replaced by `skip` and no register is zeroed",
    },
    // A composite's row: `cfi-effective` is reduced over `branch-protection-marked` (and
    // `cet-marked` on x86), which read the marking and are right to read it `on` here. It
    // asserts under OpenBSD's C library only, the one whose kernel chard has measured
    // reading the header, so it is a gap on every Linux host. It decides something on
    // OpenBSD arm64 alone: on amd64 `cet-marked` reads `partial` under OpenBSD 7.9's clang,
    // and the composite is `off` with the header or without it. Its `bare` control cannot
    // excuse it (see `COMPOSITES`). What exercises the reading on every host is the replay
    // case beside the corpus,
    // `tests/detector_replay.rs::the_recorded_nobtcfi_artifact_reads_cfi_effective_off`,
    // over the measured artifact's recorded facts.
    InertForm {
        check: "cfi-effective",
        probe: "link-defaults",
        flags: "-Wl,-z,nobtcfi",
        expected: &["off"],
        applies: Applies::Libc(&["openbsd"]),
        inert_because: "the PT_OPENBSD_NOBTCFI program header the flag writes turns \
                        OpenBSD's branch-target enforcement off for the whole program, so a \
                        marking on both edges is not protection on both",
    },
    // The composite over the forged marking above: `cet-marked` withheld, so the constituent
    // is not established. Measured 2026-10-05 on Fedora 44 x86_64 under gcc 16.1.1 and clang
    // 22.1.8: `indeterminate`. x86 only, since off x86 the constituent is
    // `branch-protection-marked`, which this form does not touch.
    InertForm {
        check: "cfi-effective",
        probe: "link-defaults",
        flags: "-fcf-protection=none -Wl,-z,ibt -Wl,-z,shstk",
        expected: &["indeterminate"],
        applies: Applies::ElfArchInside(&["x86_64", "x86"]),
        inert_because: "the marking the constituent reads was forced by the linker over \
                        code with no landing pad, so neither edge is shown in force",
    },
    // The aarch64 counterpart: `branch-protection-marked` withheld over `-z force-bti`, so the
    // constituent is not established. Measured 2026-10-05 on Fedora 44 aarch64 under
    // qemu-user, gcc 16.2.1 and clang 22.1.8: `indeterminate`.
    InertForm {
        check: "cfi-effective",
        probe: "link-defaults",
        flags: "-mbranch-protection=pac-ret -Wl,-z,force-bti",
        expected: &["indeterminate"],
        applies: Applies::ElfArchInside(&["aarch64"]),
        inert_because: "the branch half of the marking the constituent reads was forced by \
                        the linker over code with no landing pad",
    },
];

/// A row whose check cannot discriminate on one platform, so the triple withholds there under
/// any flags and the row's expected verdict cannot be reached.
///
/// The row's purpose is that an inert form never reads `on`, and a withheld verdict whose
/// cause is the platform satisfies it. Keyed by the row's check and flags and by the C
/// library that names the platform, with the verdict and the withholding cause both pinned:
/// the same verdict for another cause, or on another platform, still fails the row. Only
/// verdicts that are not measurements can be admitted, which
/// [`every_platform_withholding_admits_a_withheld_verdict_for_a_row_that_exists`] holds.
struct Withheld {
    check: &'static str,
    flags: &'static str,
    /// `environment.libc.impl` of the platform.
    libc: &'static str,
    verdict: chard::report::Verdict,
    withheld_because: chard::report::WithheldBecause,
    /// Why the check cannot discriminate there, whatever the flags.
    because: &'static str,
}

/// Measured 2026-10-01 with `tests/inert_flags.rs` in OpenBSD 7.9 guests
/// (clang 19.1.7) from fresh overlays of the fleet's bases: amd64 under KVM, and arm64 under
/// qemu TCG (`-cpu max,pauth-impdef=on,sve=off,sme=off`). The rows fail there on these
/// readings alone; the project ledger ("Withheld on OpenBSD 7.9, by cause") records each
/// cause for the profiles the fleet measured.
const WITHHELD_ON_PLATFORM: &[Withheld] = &[
    Withheld {
        check: "ssp-level",
        flags: "-fstack-protector-strong -fno-stack-protector",
        libc: "openbsd",
        verdict: chard::report::Verdict::ProbeInvalid,
        withheld_because: chard::report::WithheldBecause::PositiveSilent,
        because: "OpenBSD 7.9's clang defines no __SSP* macro under any -fstack-protector \
                  mode, so the positive control is silent and the check withholds under every \
                  profile, bare included",
    },
    Withheld {
        check: "ssp-covers-small-arrays",
        flags: "-fstack-protector --param ssp-buffer-size=65536",
        libc: "openbsd",
        verdict: chard::report::Verdict::ProbeInvalid,
        withheld_because: chard::report::WithheldBecause::PositiveSilent,
        because: "OpenBSD's clang emits RETGUARD in place of a canary unless \
                  -fno-ret-protector is given, and the controls are profile-free, so the \
                  positive arm carries no canary and the check withholds under every profile",
    },
    // Measured 2026-10-02 with chard from the wf-u-ssp-funcmap tree in an OpenBSD 7.9 amd64
    // KVM guest (clang 19.1.7) from a fresh overlay: under `bare`, this form and explicit
    // `-fno-ret-protector -fstack-protector-strong` the positive arm's four functions refer
    // to RETGUARD cookies and no canary target, so the check withholds; the latter's
    // measured build reads `strong` through `__stack_smash_handler`. arm64 is unmeasured.
    Withheld {
        check: "ssp-level-emitted",
        flags: "-fstack-protector-strong -fno-stack-protector",
        libc: "openbsd",
        verdict: chard::report::Verdict::ProbeInvalid,
        withheld_because: chard::report::WithheldBecause::PositiveSilent,
        because: "OpenBSD's clang emits RETGUARD in place of a canary unless \
                  -fno-ret-protector is given, and the controls are profile-free, so no \
                  function of the positive arm refers to a canary target and the check \
                  withholds under every profile",
    },
];

/// The platform withholding that admits this reading of `row`, if any.
fn withheld_admits<'a>(
    row: &InertForm,
    libc: &str,
    verdict: &str,
    cause: &str,
) -> Option<&'a Withheld> {
    WITHHELD_ON_PLATFORM.iter().find(|w| {
        w.check == row.check
            && w.flags == row.flags
            && w.libc == libc
            && w.verdict.as_str() == verdict
            && w.withheld_because.as_str() == cause
    })
}

/// Checks the invariant covers that have no inert form, each with the reason.
///
/// A check leaves this list when it leaves the covered set. `pie-macro` and `pic-macro`
/// carry no recommended level, which is the only thing that would make them graded;
/// `src/probe.rs` carries why a code model selector is not a hardening level.
/// `cxx-hardening-requested` and `pie` are outside the graded set too: the guide's ask for
/// libc++ is its lowest mode, so a grade against it grades nothing, and `pie`'s one word
/// names the ELF flavour. Their rows in `INERT_FORMS` stay, as rows for checks the
/// invariant does not cover, because the forms are inert and driven. A row here naming a
/// check the corpus does not grade fails the test above rather than sitting stale.
const NO_INERT_FORM: &[(&str, &str)] = &[
    (
        "auto-var-init-active",
        "the flag has no precondition; the case where its observable appears without it, a \
         stack protector zeroing the frame, is the regime arm's, which \
         tests/measurement_loop.rs exercises, and a profile carrying both flags measures \
         `on` with the regime arm attributing the zero to the flag",
    ),
    (
        "stack-clash-guard-page",
        // Measured: `--profile explicit --flags
        // -fstack-clash-protection` with no -O reads `on` (the first touch lands 12% of
        // the way into the allocation) and `-fno-stack-clash-protection` reads `off` (100%),
        // for gcc and clang alike, on Fedora 44 x86_64 (gcc 16.1.1, clang 22.1.8) and
        // Fedora 44 aarch64 (gcc 16.2.1, clang 22.1.8), glibc 2.43, 2026-09-28.
        "the probing sequence is emitted when the prologue and the dynamic allocation are \
         expanded, which gcc and clang do at every optimization level, so the flag is the \
         mechanism at -O0 as well; -O2 in both control arms keeps the two arms' frames \
         alike and gates nothing, and the profile-free triple already exercises the flag's \
         own negative",
    ),
    (
        "cxx-assertions-symbol",
        // Measured on 2026-09-29 with `--profile explicit --probe
        // cxx-stdlib-assertions`, gcc and clang on Fedora 44 x86_64 (gcc 16.1.1,
        // libstdc++ 16.1.1) and Fedora 44 aarch64 (gcc 16.2.1, libstdc++ 16.2.1), clang
        // 22.1.8 on both; every cell alike on both hosts and both compilers. With no -O:
        // `-D_GLIBCXX_ASSERTIONS` reads `on`, `-D_GLIBCXX_ASSERTIONS
        // -D_GLIBCXX_NO_ASSERTIONS` reads `on`, `-U_GLIBCXX_ASSERTIONS` reads `on` (as
        // `bare` does), and `-D_GLIBCXX_NO_ASSERTIONS` reads `off`. With -O2,
        // `-D_GLIBCXX_ASSERTIONS` reads `on` and `-U_GLIBCXX_ASSERTIONS` reads `off`. The
        // regime arm read `absent` in every cell that built one.
        //
        // The library's -O0 default is not the regime arm's case: the arm is the profile's
        // flags followed by the negative list, and that list carries -O2 and
        // -D_GLIBCXX_NO_ASSERTIONS, either of which removes the default, so the arm reads
        // `absent` and the -O0 `on` without the flag is published as `on`. The symbol and
        // the SIGABRT are both in that artifact, so the `on` is true of it; it is a
        // library default rather than a flag, which is the attribution question, not the
        // inert-form one.
        "the request is honoured unoptimized and optimized alike: -D_GLIBCXX_ASSERTIONS \
         puts the assertion handler in the artifact at -O0 and at -O2, and at -O0 it does \
         so with the library's own off switch, -D_GLIBCXX_NO_ASSERTIONS, beside it. At -O0 \
         the flag is redundant rather than inert, because libstdc++ enables the assertions \
         itself when __OPTIMIZE__ is undefined, so the handler is present and `on` is true \
         of the artifact with the flag or without it",
    ),
];

/// One form of a graded check's flag that is present and inert on part of what it names:
/// the check reads `on`, since the mechanism is present, at a level that is not the one the
/// flag requested, and the inertness is in the difference between the two words.
///
/// The fourth table. [`INERT_FORMS`] holds a form to anything but `on`,
/// which is the rule for a flag that does nothing; a flag that does something other than
/// what it names needs the level compared, not the verdict. The case: `-fstack-protector-all`
/// under clang's `-fsanitize=safe-stack`. Every function carries the `sspreq` attribute, and
/// `SafeStack` places a canary only in the functions it gave an unsafe frame, so `-all` is
/// present and inert on every frame with no unsafe local (`probes/ssp_function_map.c` has the
/// mechanism and the measurement). `ssp-level-emitted` reads `on` at `unsafe-frame`, a word
/// `probe::SSP_LEVELS` admits on no rung, and never `all`; a row here fails on `on` at the
/// requested word, on `on` at any word but the one it names, and on any verdict that is not
/// `on`, since the mechanism is present and `off` or a withheld verdict would be the false
/// zero from the other side. Run with the macro probe beside the row's own, so the
/// `stack-protector` group's `agree` is read too: the macro records the request, and the
/// group must name the split rather than agree.
struct PartlyInertForm {
    check: &'static str,
    /// The probe carrying the check, and the probe carrying the macro reader beside it.
    probes: &'static [&'static str],
    /// The `--profile explicit --flags` string. Split on whitespace by chard.
    flags: &'static str,
    /// The word the flag requests, which the row refuses `on` at.
    requested: &'static str,
    /// The word the row accepts `on` at: on no rung of the check's scale.
    reads: &'static str,
    /// The corroboration group the check is in, whose `agree` must be false under the form.
    group: &'static str,
    applies: Applies,
    /// Why the flag does part of what it names and not the rest.
    inert_because: &'static str,
}

const PARTLY_INERT_FORMS: &[PartlyInertForm] = &[
    // Measured 2026-10-08 with chard from this tree, `--probe ssp-function-map --probe
    // toolchain-macros`, clang 22.1.8 on Fedora 44 x86_64 (glibc 2.43): `on` at
    // `unsafe-frame` with a discriminating triple (the positive arm, plain
    // `-fstack-protector-all`, reads `all` over five functions; the negative, no canary), the
    // macro reader `on` at `all` from `__SSP_ALL__`, and the group `agree: false` with its
    // note opening `LEVELS DISAGREE`. The same reading at -O0, -O1 and -O2; the row carries
    // no -O so the form is the flag alone. Before this date the artifact read `strong`, a
    // rung, and the group agreed. gcc rejects `-fsanitize=safe-stack`, so the row is clang's.
    PartlyInertForm {
        check: "ssp-level-emitted",
        probes: &["ssp-function-map", "toolchain-macros"],
        flags: "-fstack-protector-all -fsanitize=safe-stack",
        requested: "all",
        reads: "unsafe-frame",
        group: "stack-protector",
        applies: Applies::CompilerRuntime(&["clang"], "-fsanitize=safe-stack"),
        inert_because: "SafeStack moves escaping or unprovable locals to an unsafe stack and a \
                        canary is placed in that frame for any function carrying an ssp \
                        attribute, while the rest get none (that SafeStack runs before the \
                        stack protector and that the safestack attribute is what withholds the \
                        ordinary canary is inferred from the objects, not read from the LLVM \
                        source: THREAT_MODEL.md's safestack-canaries-follow-the-unsafe-frame), \
                        so -fstack-protector-all marks every function and protects only the \
                        ones with an unsafe frame; ssp_any and the in-range array stay bare",
    },
];

/// The composites a row may name in place of a check, each with the checks it is reduced
/// over: a row's probe must carry one of them.
///
/// A composite row's flag takes a protection away rather than asking for one, so the
/// `bare` control that excuses a check row reading `on` cannot excuse it: `on` under
/// `bare` is the reading the inert form exists to move, and on OpenBSD 7.9 arm64, the one
/// host where the `cfi-effective` row decides anything, `bare` reads it `on`. Excused
/// there, a regressed opt-out reading would be announced as a gap and pass.
/// [`bare_control_can_excuse`] holds that, and
/// `a_composite_row_reading_on_fails_whatever_its_bare_control_reads` tests it.
const COMPOSITES: &[(&str, &[&str])] =
    &[("cfi-effective", &["cet-marked", "branch-protection-marked"])];

/// Whether a row reading `on` may be announced as a gap because the same probe reads `on`
/// under `bare`: only for a check row, never for a composite's; see [`COMPOSITES`].
fn bare_control_can_excuse(row: &InertForm) -> bool {
    !COMPOSITES.iter().any(|(c, _)| *c == row.check)
}

/// Whether `control`, the row's probe measured under `bare`, excuses the row's `on`.
fn excused_by_control(row: &InertForm, control: &Value) -> bool {
    bare_control_can_excuse(row) && verdict_of(control, row.check) == Some("on")
}

/// The observation, or the composite, carrying `id` in a report.
fn reading<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
    let section = if COMPOSITES.iter().any(|(c, _)| *c == id) {
        "composites"
    } else {
        "observations"
    };
    let key = if section == "composites" {
        "id"
    } else {
        "check"
    };
    report[section]
        .as_array()
        .into_iter()
        .flatten()
        .find(|o| o[key] == id)
}

fn chard_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chard"))
}

/// Whether the binary is built and `cc` answers; a refusal panics unless the operator
/// opted into skipping.
///
/// Under a gate that names a compiler ([`common::expected_compiler`]) a skip panics even
/// then: `make compiler-arms` exists to run the rows of that compiler, and a skip there
/// would pass the gate having run none of them.
fn can_run(verifies: &str) -> bool {
    let ready = common::require_binary(&chard_binary(), verifies) && common::require_cc(verifies);
    if let (false, Some(want)) = (ready, common::expected_compiler()) {
        panic!(
            "the gate expects `cc` to be {want} and this test could not run, so none of \
             {want}'s rows ran; CHARD_ALLOW_TEST_SKIP does not excuse a gate"
        );
    }
    ready
}

/// Measure one probe under one explicit profile and return the report.
///
/// A contradiction (exit 3) is a chard defect and panics with the quarantined report's
/// findings; anything that is not a report panics too. The compiler is present and the
/// binary is built, so neither is a reason to skip.
fn measure(row: &InertForm, work: &common::Work) -> Value {
    measure_flags(row, work, Some(row.flags))
}

/// Every row's report under its own flags, in row order, measured on up to eight threads
/// (fewer where the host has fewer CPUs), each row in its own work directory.
fn measure_rows(rows: &[InertForm]) -> Vec<Value> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    let next = AtomicUsize::new(0);
    let slots: Vec<std::sync::Mutex<Option<Value>>> =
        rows.iter().map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(row) = rows.get(i) else { break };
                    let work = common::Work::new("inert", &format!("{i}-{}", row.check));
                    let report = measure(row, &work);
                    *slots[i].lock().expect("a slot") = Some(report);
                }
            });
        }
    });
    let mut reports: Vec<Value> = slots
        .into_iter()
        .map(|s| s.into_inner().expect("a slot").expect("every row measured"))
        .collect();
    assert_eq!(reports.len(), rows.len(), "one report per row");
    // Eight measurements at once load the host, and a run that hits its deadline can leave a
    // row reading a withheld verdict some rows accept, untested. Such a row is measured again
    // alone, so concurrency adds no way for a row to pass that the series did not have.
    for (i, row) in rows.iter().enumerate() {
        if hit_a_deadline(&reports[i]) {
            eprintln!(
                "inert_flags: {} under `{}` hit a run deadline beside other rows; measured again alone",
                row.check, row.flags
            );
            let work = common::Work::new("inert-alone", &format!("{i}-{}", row.check));
            reports[i] = measure(row, &work);
        }
    }
    reports
}

/// Whether any run record in `value` hit its deadline (`timed_out`, which every run record
/// carries).
fn hit_a_deadline(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| (k == "timed_out" && v.as_bool() == Some(true)) || hit_a_deadline(v)),
        Value::Array(items) => items.iter().any(hit_a_deadline),
        _ => false,
    }
}

/// The same measurement with the row's flags, or with none at all under `bare`.
///
/// `None` is the row's own control: the toolchain as configured, with nothing added. See
/// [`an_inert_flag_is_never_reported_on`] for what reads it.
fn measure_flags(row: &InertForm, work: &common::Work, flags: Option<&str>) -> Value {
    let mut args = vec!["measure".to_owned(), "--profile".to_owned()];
    match flags {
        Some(flags) => {
            args.extend(["explicit", "--flags", flags].map(str::to_owned));
        }
        None => args.push("bare".to_owned()),
    }
    report_of(&args, &[row.probe], work, row.check, row.flags)
}

/// Whether `probe` carries a check that declares `needs_vm`, whose reading is the
/// kernel's policy and is withheld where nothing established whose kernel it is.
fn reads_kernel_policy(probe: &str) -> bool {
    chard::probe::find(probe).is_some_and(|p| p.checks.iter().any(|c| c.gate.needs_vm))
}

/// `chard measure` with `args`, `--probe` each of `probes`, `--workdir` and `--output`
/// under `work`, parsed; `check` and `flags` name the row in a failure.
///
/// Where a probe carries a check that declares `needs_vm` and the report reads `host` on an
/// `assumed-host` basis, the measurement is run again with `--execution host`, in a second
/// workdir, and that report is the row's. chard withholds such a check
/// under `execution-mode-assumed` where nothing observed the mode and nobody asserted it,
/// so the row's claim about its flag would go unevaluated on every host the suite runs on
/// that is not a container; this harness asserts the word the suite can give, that its
/// hosts (developer machines, CI's hosted runners) run their own kernels. A container the
/// suite runs in is recognised by its marker file, cgroup needle, systemd's marker, PID 1's
/// `container=` word or user namespace, keeps the plain run, and
/// the row accepts `indeterminate` under `needs-vm` there.
fn report_of(
    args: &[String],
    probes: &[&str],
    work: &common::Work,
    check: &str,
    flags: &str,
) -> Value {
    let run = |execution: Option<&str>, tag: &str| -> Value {
        let output_path = work.path(&format!("report{tag}.json"));
        let mut command = Command::new(chard_binary());
        command.args(args);
        for probe in probes {
            command.arg("--probe").arg(probe);
        }
        if let Some(execution) = execution {
            command.arg("--execution").arg(execution);
        }
        let output = command
            .arg("--workdir")
            .arg(work.path(&format!("work{tag}")))
            .arg("--output")
            .arg(&output_path)
            .output()
            .unwrap_or_else(|e| panic!("spawning chard for {check}: {e}"));
        if output.status.code() == Some(3) {
            let quarantined =
                std::fs::read_to_string(work.path(&format!("report{tag}.json.contradicted")))
                    .unwrap_or_else(|e| format!("(the quarantined report could not be read: {e})"));
            panic!(
                "{check} under `{flags}`: chard refused to publish a self-contradicting report:\n{}",
                quarantined.chars().take(2000).collect::<String>()
            );
        }
        let text = std::fs::read_to_string(&output_path).unwrap_or_else(|e| {
            panic!(
                "{check} under `{flags}`: no report was written ({e}); stderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{check} under `{flags}`: the report is not JSON: {e}"))
    };
    let report = run(None, "");
    let by_default = report["environment"]["execution"]["mode_evidence"]["basis"].as_str()
        == Some("assumed-host");
    if by_default && probes.iter().any(|probe| reads_kernel_policy(probe)) {
        return run(Some("host"), "-host");
    }
    report
}

/// The C++ standard library the toolchain identified in this report's evidence, by the
/// same ladder `probe::cxx_stdlib` uses: the self-report's `_CXX_STDLIB`, else the
/// library's own version macro.
fn cxx_stdlib(report: &Value) -> Option<String> {
    let observation = report["observations"]
        .as_array()?
        .iter()
        .find(|o| o["check"] == "cxx-hardening-requested")?;
    let macros = observation["evidence"]["macros"].as_object()?;
    if let Some(named) = macros.get("_CXX_STDLIB").and_then(Value::as_str) {
        return Some(named.to_owned());
    }
    if macros.contains_key("_LIBCPP_VERSION") {
        return Some("libc++".to_owned());
    }
    if macros.contains_key("__GLIBCXX__") {
        return Some("libstdc++".to_owned());
    }
    None
}

/// The C library implementation a report names, or `unknown`.
fn libc_of(report: &Value) -> &str {
    report["environment"]["libc"]["impl"]
        .as_str()
        .unwrap_or("unknown")
}

/// Whether the host the report describes meets a row's condition, or why it does not.
fn applies_here(applies: &Applies, report: &Value) -> Result<(), String> {
    let libc = libc_of(report);
    let arch = report["environment"]["kernel"]["arch"]
        .as_str()
        .unwrap_or("unknown");
    let compiler = report["toolchain"]["kind"].as_str().unwrap_or("unknown");
    match applies {
        Applies::Always => Ok(()),
        Applies::ElfArtifact if common::ELF_HOST => Ok(()),
        Applies::ElfArtifact => Err("the observable is an ELF artifact and this host's cc \
                                     emits something else"
            .to_owned()),
        Applies::Libc(list) if list.contains(&libc) => Ok(()),
        Applies::Libc(list) => Err(format!(
            "inert only under {list:?}; this host's C library is {libc}"
        )),
        Applies::ElfArchOutside(_) | Applies::ElfArchInside(_) | Applies::ElfCompiler(_)
            if !common::ELF_HOST =>
        {
            Err(
                "the observable is an ELF artifact and this host's cc emits something else"
                    .to_owned(),
            )
        }
        Applies::ElfArchInside(list) if list.contains(&arch) => Ok(()),
        Applies::ElfArchInside(list) => Err(format!(
            "the form forges a marking only on {list:?}; this host is {arch}"
        )),
        Applies::ArchOutside(list) | Applies::ElfArchOutside(list) if !list.contains(&arch) => {
            Ok(())
        }
        Applies::ArchOutside(list) => Err(format!(
            "inert only off {list:?}; this host is {arch}, where the flag is the mechanism"
        )),
        Applies::ElfArchOutside(list) => Err(format!(
            "the row's verdict is measured only off {list:?}; this host is {arch}"
        )),
        Applies::Compiler(list) | Applies::ElfCompiler(list) if list.contains(&compiler) => Ok(()),
        Applies::Compiler(list) | Applies::ElfCompiler(list) => Err(format!(
            "inert only under {list:?}; this toolchain is {compiler}"
        )),
        Applies::CompilerRuntime(list, _) if !list.contains(&compiler) => Err(format!(
            "inert only under {list:?}; this toolchain is {compiler}"
        )),
        Applies::CompilerRuntime(_, flag) => links_and_runs(flag),
        Applies::GccBefore(before) => {
            let version = report["toolchain"]["version"].as_str().unwrap_or("unknown");
            let major = version
                .split('.')
                .next()
                .and_then(|m| m.parse::<u32>().ok());
            match major {
                Some(major) if compiler == "gcc" && major < *before => Ok(()),
                _ => Err(format!(
                    "inert only under gcc before {before}; this toolchain is {compiler} \
                     {version}"
                )),
            }
        }
        Applies::CxxStdlib(want) => match cxx_stdlib(report) {
            Some(have) if have == *want => Ok(()),
            Some(have) => Err(format!(
                "inert only under {want}; this toolchain's C++ library is {have}"
            )),
            None => Err(format!(
                "inert only under {want}; no C++ library identified itself here"
            )),
        },
    }
}

/// Whether `cc` builds, links and runs an empty program under `flag`, or why not.
fn links_and_runs(flag: &str) -> Result<(), String> {
    let work = common::Work::new("inert-runtime", &flag.replace(['=', ' '], "-"));
    let source = work.write("empty.c", "int main(void) { return 0; }\n");
    let program = work.path("empty");
    let built = Command::new("cc")
        .args(flag.split_whitespace())
        .arg("-o")
        .arg(&program)
        .arg(&source)
        .output()
        .map_err(|e| format!("spawning cc with {flag}: {e}"))?;
    if !built.status.success() {
        return Err(format!(
            "cc does not build and link a program with {flag} on this host, so the \
             sanitizer's runtime is missing or the flag unknown"
        ));
    }
    let ran = Command::new(&program)
        .output()
        .map_err(|e| format!("running a program built with {flag}: {e}"))?;
    if !ran.status.success() {
        return Err(format!(
            "a program built with {flag} does not run on this host ({})",
            ran.status
        ));
    }
    Ok(())
}

/// The compiler family a report's toolchain identified as, `toolchain.kind`.
fn toolchain_kind(report: &Value) -> &str {
    report["toolchain"]["kind"].as_str().unwrap_or("unknown")
}

/// The compiler families a row's condition names, or `None` where it names none.
fn compiler_families(applies: &Applies) -> Option<&'static [&'static str]> {
    match applies {
        Applies::Compiler(list)
        | Applies::ElfCompiler(list)
        | Applies::CompilerRuntime(list, _) => Some(list),
        _ => None,
    }
}

/// Whether a row belongs to another compiler: its condition names families and `kind` is
/// not one of them, so no host with this toolchain can run it.
fn belongs_elsewhere(applies: &Applies, kind: &str) -> bool {
    compiler_families(applies).is_some_and(|list| !list.contains(&kind))
}

/// What one driving test did with its rows, split by compiler: the rows another compiler
/// owns, which this toolchain cannot run, and the rest, which it can.
///
/// `conditions` is the table's conditions in row order; `exercised` and `gaps` are row
/// indices. The split is read from the table, not from the outcomes, so it is a second
/// reading of each row beside `applies_here`'s: a row of another compiler that was
/// exercised, or one that was neither exercised nor announced, is a problem returned to
/// the caller beside the count line. `expected` is the family a gate requires (see
/// [`common::expected_compiler`]): the reports must name it, and every row naming it must
/// have run. Pure: [`accounting`] prints the line and writes it to the test ledger, so the
/// self-test's forged runs leave no count line that could stand in for a driving test's.
fn compiler_accounting(
    table: &str,
    kind: &str,
    expected: Option<&str>,
    conditions: &[&Applies],
    exercised: &[usize],
    gaps: &[usize],
) -> (String, Vec<String>) {
    let mut problems = Vec::new();
    let total = conditions.len();
    // Placement before counts: a row listed twice can offset a row never listed, and a
    // sum compares sizes only. Each row sits in exactly one list, and no index is past
    // the table.
    let strays: Vec<usize> = exercised
        .iter()
        .chain(gaps)
        .copied()
        .filter(|&i| i >= total)
        .collect();
    if !strays.is_empty() {
        problems.push(format!(
            "{table}: rows {strays:?} are past the table's {total} rows"
        ));
    }
    for i in 0..total {
        let placed = exercised.iter().chain(gaps).filter(|&&j| j == i).count();
        if placed != 1 {
            problems.push(format!(
                "{table} row {i} is listed {placed} times across exercised and announced, \
                 not once"
            ));
        }
    }
    let elsewhere: Vec<usize> = (0..total)
        .filter(|&i| belongs_elsewhere(conditions[i], kind))
        .collect();
    for &i in &elsewhere {
        if exercised.contains(&i) {
            problems.push(format!(
                "{table} row {i} was exercised under {kind}, and its condition names only {:?}",
                compiler_families(conditions[i]).unwrap_or(&[])
            ));
        } else if !gaps.contains(&i) {
            problems.push(format!(
                "{table} row {i} belongs to {:?} and was neither exercised nor announced",
                compiler_families(conditions[i]).unwrap_or(&[])
            ));
        }
    }
    let runnable = total.saturating_sub(elsewhere.len());
    let host_gaps = gaps.iter().filter(|i| !elsewhere.contains(i)).count();
    let families: BTreeSet<&str> = elsewhere
        .iter()
        .filter_map(|&i| compiler_families(conditions[i]))
        .flatten()
        .copied()
        .filter(|f| *f != kind)
        .collect();
    let families = families.into_iter().collect::<Vec<_>>().join(", ");
    let line = if elsewhere.is_empty() {
        format!(
            "{table}: {} of {runnable} rows a {kind} toolchain can run were exercised, \
             {host_gaps} announced for this host; no row of {total} belongs to another compiler",
            exercised.len()
        )
    } else {
        format!(
            "{table}: {} of {runnable} rows a {kind} toolchain can run were exercised, \
             {host_gaps} announced for this host; {} of {total} rows belong to {families} \
             and were not exercised (`make compiler-arms ARMS_CC=<family>` runs them)",
            exercised.len(),
            elsewhere.len()
        )
    };
    if exercised.len().saturating_add(host_gaps) != runnable {
        problems.push(format!(
            "{table}: {} exercised and {host_gaps} announced for this host do not sum to the \
             {runnable} rows a {kind} toolchain can run",
            exercised.len()
        ));
    }
    if let Some(want) = expected {
        if want != kind {
            problems.push(format!(
                "{table}: the gate expects `cc` to be {want} and the reports name {kind}; `cc` \
                 on PATH does not reach {want} (a symlink to a ccache shim runs the compiler \
                 its own name picks)"
            ));
        }
        let owned: Vec<usize> = (0..total)
            .filter(|&i| compiler_families(conditions[i]).is_some_and(|l| l.contains(&want)))
            .collect();
        let missed: Vec<usize> = owned
            .iter()
            .copied()
            .filter(|i| !exercised.contains(i))
            .collect();
        if !missed.is_empty() {
            problems.push(format!(
                "{table}: the gate runs the rows that name {want}, and {} of {} did not run: \
                 rows {missed:?} (their announcements above say why)",
                missed.len(),
                owned.len()
            ));
        }
    }
    (line, problems)
}

/// [`compiler_accounting`] over the toolchain every report of one driving test named: one
/// family, or a problem, since a `cc` that answered as two compilers in one run leaves no
/// row's split meaningful. The count line is printed and written to the test ledger
/// (`make test` prints it after the run), and only from here.
fn accounting(
    table: &str,
    kinds: &BTreeSet<String>,
    conditions: &[&Applies],
    exercised: &[usize],
    gaps: &[usize],
) -> Vec<String> {
    match kinds.iter().collect::<Vec<_>>().as_slice() {
        [kind] if kind.as_str() == "unknown" => vec![format!(
            "{table}: the reports name no toolchain kind, so no row can be told this \
             toolchain's or another compiler's"
        )],
        [kind] => {
            let (line, problems) = compiler_accounting(
                table,
                kind,
                common::expected_compiler().as_deref(),
                conditions,
                exercised,
                gaps,
            );
            eprintln!("{line}");
            common::record("count", &line);
            problems
        }
        [] => vec![format!(
            "{table}: no report named a toolchain, so no row was accounted"
        )],
        many => vec![format!(
            "{table}: the reports of one run name {} toolchain kinds, {many:?}",
            many.len()
        )],
    }
}

/// What is wrong with the `NO_INERT_FORM` entries, given the checks the invariant covers.
fn no_form_problems(covered: &BTreeSet<&str>) -> Vec<String> {
    let mut problems = Vec::new();
    for (check, reason) in NO_INERT_FORM {
        if !covered.contains(check) {
            problems.push(format!(
                "`{check}` is listed as a covered check with no inert form, and the corpus \
                 has no check by that id that is graded or pins -O2 in both control arms"
            ));
        }
        if reason.len() < 60 {
            problems.push(format!(
                "`{check}`'s reason for having no inert form is {} characters, which does \
                 not state one",
                reason.len()
            ));
        }
    }
    problems
}

/// What is wrong with one `INERT_FORMS` row: its probe, its check, its expected set.
fn row_problems(row: &InertForm) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(probe) = chard::probe::find(row.probe) else {
        problems.push(format!(
            "`{}`'s row names probe `{}`, which is not in the corpus",
            row.check, row.probe
        ));
        return problems;
    };
    let carries = |id: &str| probe.checks.iter().any(|c| c.id == id);
    let reduced_over = COMPOSITES
        .iter()
        .find(|(c, _)| *c == row.check)
        .map(|(_, over)| over.iter().any(|id| carries(id)));
    if reduced_over == Some(false) || (reduced_over.is_none() && !carries(row.check)) {
        problems.push(format!(
            "`{}`'s row names probe `{}`, which does not carry that check",
            row.check, row.probe
        ));
    }
    if row.expected.contains(&"on") || row.expected.is_empty() {
        problems.push(format!(
            "`{}`'s row under `{}` expects {:?}; an inert form is never `on` and the \
             set has to say what it is instead",
            row.check, row.flags, row.expected
        ));
    }
    for verdict in row.expected {
        if !chard::report::Verdict::ALL
            .iter()
            .any(|v| v.as_str() == *verdict)
        {
            problems.push(format!(
                "`{}`'s row expects `{verdict}`, which is not a verdict",
                row.check
            ));
        }
    }
    problems
}

/// Every graded check, and every check whose control arms both carry `-O2`, names its
/// inert form or the reason it has none.
///
/// The second set is read off the corpus itself: a check pins `-O2` in both
/// arms exactly when the mechanism it measures needs the optimizer, and a mechanism with
/// that precondition has a form in which the flag is present and the optimizer is absent.
/// `-D_FORTIFY_SOURCE=3` with no `-O` is the case that named this file, and
/// `no-strict-overflow` under clang is the one this rule caught after the graded rule had
/// passed it: its detector documents the false `on` and it grades nothing.
///
/// Runs without a compiler: the tables are checked against the corpus alone.
#[test]
fn every_graded_or_optimization_gated_check_names_its_inert_form_or_a_reason() {
    let mut problems = Vec::new();
    let checks = || chard::probe::CORPUS.iter().flat_map(|p| p.checks.iter());
    let graded: BTreeSet<&str> = checks()
        .filter(|c| c.levels.grade().is_some())
        .map(|c| c.id)
        .collect();
    let optimization_gated: BTreeSet<&str> = checks()
        .filter(|c| c.positive.contains(&"-O2") && c.negative.contains(&"-O2"))
        .map(|c| c.id)
        .collect();
    assert!(
        !graded.is_empty(),
        "no check in the corpus is graded, so half of this invariant would hold over \
         nothing"
    );
    assert!(
        !optimization_gated.is_empty(),
        "no check in the corpus carries -O2 in both control arms, so half of this \
         invariant would hold over nothing"
    );
    let covered: BTreeSet<&str> = graded.union(&optimization_gated).copied().collect();

    let with_form: BTreeSet<&str> = INERT_FORMS.iter().map(|r| r.check).collect();
    let without: BTreeSet<&str> = NO_INERT_FORM.iter().map(|(c, _)| *c).collect();
    for check in &covered {
        let why_covered = match (graded.contains(check), optimization_gated.contains(check)) {
            (true, true) => "is graded and pins -O2 in both control arms",
            (true, false) => "is graded",
            (false, true) => {
                "pins -O2 in both control arms, so its mechanism needs the \
                              optimizer"
            }
            (false, false) => unreachable!("covered is the union of the two sets"),
        };
        match (with_form.contains(check), without.contains(check)) {
            (true, false) | (false, true) => {}
            (true, true) => problems.push(format!(
                "`{check}` has an inert form and is also listed as having none"
            )),
            (false, false) => problems.push(format!(
                "`{check}` {why_covered}, and names no inert form: add a row to \
                 INERT_FORMS spelling the form in which the flag is present and does \
                 nothing, or to NO_INERT_FORM with the reason there is none"
            )),
        }
    }
    problems.extend(no_form_problems(&covered));
    problems.extend(INERT_FORMS.iter().flat_map(row_problems));
    eprintln!(
        "inert_flags: {} covered checks ({} graded, {} pinning -O2 in both arms, {} in \
         both sets), {} with an inert form, {} with a stated reason for none, {} rows in \
         all",
        covered.len(),
        graded.len(),
        optimization_gated.len(),
        graded.intersection(&optimization_gated).count(),
        covered.iter().filter(|c| with_form.contains(*c)).count(),
        covered.iter().filter(|c| without.contains(*c)).count(),
        INERT_FORMS.len()
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// `-Wl,-z,nodlopen` does nothing to an executable. The corpus measures it on a shared
/// object, and that is a property of the probe rather than of any profile, so it is
/// asserted on the corpus rather than driven through the binary.
#[test]
fn nodlopen_is_measured_where_the_flag_can_take_effect() {
    let probe = chard::probe::CORPUS
        .iter()
        .find(|p| p.checks.iter().any(|c| c.id == "nodlopen"))
        .expect("nodlopen is in the corpus");
    assert_eq!(
        probe.link_mode,
        chard::probe::LinkMode::SharedObject,
        "`nodlopen` is carried by probe `{}`, linked as {:?}; the linker ignores -z \
         nodlopen on anything except a shared object, so measured there the check would \
         read off on every toolchain",
        probe.id,
        probe.link_mode
    );
}

/// A composite row reading `on` fails even where its `bare` control reads `on` too, and a
/// check row in the same position is excused; both through the functions the driving test
/// calls, over reports shaped as chard writes them.
///
/// Without the exemption the `cfi-effective` row could not fail on any host: on OpenBSD
/// arm64 `bare` reads the composite `on`, so a regressed opt-out reading would have read
/// `on` under the row and under the control alike and been announced as a gap.
#[test]
fn a_composite_row_reading_on_fails_whatever_its_bare_control_reads() {
    let composite_rows: Vec<&InertForm> = INERT_FORMS
        .iter()
        .filter(|r| COMPOSITES.iter().any(|(c, _)| *c == r.check))
        .collect();
    assert!(
        !composite_rows.is_empty(),
        "no row names a composite, so nothing was checked"
    );
    let on = |row: &InertForm, libc: &str, arch: &str| {
        let (section, key) = if bare_control_can_excuse(row) {
            ("observations", "check")
        } else {
            ("composites", "id")
        };
        let checks = chard::probe::find(row.probe).map_or(0, |p| p.checks.len());
        serde_json::json!({
            "environment": {"libc": {"impl": libc}, "kernel": {"arch": arch}},
            "coverage": {"checks_attempted": checks},
            section: [{key: row.check, "verdict": "on"}],
        })
    };
    for row in composite_rows {
        let report = match row.applies {
            Applies::Libc(list) => on(row, list[0], "aarch64"),
            // Its condition includes an ELF host, which a Mach-O host is not, so the row
            // is a gap there by `applies_here` and has nothing to judge.
            Applies::ElfArchInside(_) if !common::ELF_HOST => continue,
            Applies::ElfArchInside(list) => on(row, "glibc", list[0]),
            _ => panic!(
                "`{}`'s row is neither libc- nor arch-gated; extend this test to its condition",
                row.check
            ),
        };
        assert_eq!(verdict_of(&report, row.check), Some("on"));
        assert!(
            !excused_by_control(row, &report),
            "`{}` under `{}`: a `bare` control reading `on` excused a composite row",
            row.check,
            row.flags
        );
        assert!(
            matches!(judge(row, &report), Outcome::Exercised(p) if !p.is_empty()),
            "`{}` under `{}`: a report reading `on` where the row applies did not fail",
            row.check,
            row.flags
        );
    }
    let check_row = INERT_FORMS
        .iter()
        .find(|r| bare_control_can_excuse(r))
        .expect("a check row exists");
    assert!(
        excused_by_control(check_row, &on(check_row, "glibc", "aarch64")),
        "a check row's `bare` control reading `on` no longer excuses it"
    );
}

/// Every [`WITHHELD_ON_PLATFORM`] entry names a row, admits a verdict that is not a
/// measurement, and states its cause; and through [`refused`], which [`judge`] applies to
/// every exercised row, the reading it names passes on its platform and fails on another,
/// under another cause, and as `on`.
///
/// Runs without a compiler, so a widening that admitted a measurement, or one keyed so
/// loosely that a Linux host's reading passed through it, fails on every host rather than
/// only inside a guest.
#[test]
fn every_platform_withholding_admits_a_withheld_verdict_for_a_row_that_exists() {
    use chard::report::WithheldBecause;
    assert!(
        !WITHHELD_ON_PLATFORM.is_empty(),
        "no platform withholding is listed, so this test checks nothing; delete it with the \
         table"
    );
    let passes = |row: &InertForm, libc: &str, verdict: &str, cause: &str| {
        refused(row, libc, verdict, cause).is_none()
    };
    let mut problems = Vec::new();
    for w in WITHHELD_ON_PLATFORM {
        let Some(row) = INERT_FORMS
            .iter()
            .find(|r| r.check == w.check && r.flags == w.flags)
        else {
            problems.push(format!(
                "`{}` under `{}`: no INERT_FORMS row has that check and those flags",
                w.check, w.flags
            ));
            continue;
        };
        if w.verdict.is_measurement() {
            problems.push(format!(
                "`{}` under `{}`: admits `{}` on {}, a measurement; a platform that cannot \
                 discriminate earns no `on` and no `off`",
                w.check,
                w.flags,
                w.verdict.as_str(),
                w.libc
            ));
        }
        if w.because.len() < 60 {
            problems.push(format!(
                "`{}` under `{}`: the cause is {} characters, which does not state one",
                w.check,
                w.flags,
                w.because.len()
            ));
        }
        if row.expected.contains(&w.verdict.as_str()) {
            problems.push(format!(
                "`{}` under `{}`: `{}` is already in the row's expected set",
                w.check,
                w.flags,
                w.verdict.as_str()
            ));
        }
        let (v, c) = (w.verdict.as_str(), w.withheld_because.as_str());
        if !passes(row, w.libc, v, c) {
            problems.push(format!(
                "`{}` under `{}`: {v} ({c}) on {} does not pass the row",
                w.check, w.flags, w.libc
            ));
        }
        if passes(row, "glibc", v, c) {
            problems.push(format!(
                "`{}` under `{}`: {v} ({c}) on glibc passes the row, so the widening is not \
                 keyed to {}",
                w.check, w.flags, w.libc
            ));
        }
        let other = WithheldBecause::ALL
            .iter()
            .find(|o| **o != w.withheld_because)
            .expect("more than one cause");
        if passes(row, w.libc, v, other.as_str()) {
            problems.push(format!(
                "`{}` under `{}`: {v} for another cause ({}) passes the row",
                w.check,
                w.flags,
                other.as_str()
            ));
        }
        if passes(row, w.libc, "on", "-") {
            problems.push(format!(
                "`{}` under `{}`: `on` passes the row on {}",
                w.check, w.flags, w.libc
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// A `build-failed` is a gap only where the driver rejected the row's flag. Without a
/// `build_rejection` it is a build that broke under a flag the driver knows, and a row
/// that does not list `build-failed` fails on it rather than passing with nothing read.
#[test]
fn a_build_failure_is_a_gap_only_where_the_driver_rejected_the_flag() {
    let row = INERT_FORMS
        .iter()
        .find(|r| r.check == "zero-call-used-regs" && matches!(r.applies, Applies::Always))
        .expect("the zero-call-used-regs row exists");
    assert!(!row.expected.contains(&"build-failed"));
    let checks = chard::probe::find(row.probe).map_or(0, |p| p.checks.len());
    let failed = |rejection: Option<&str>| {
        let mut observation = serde_json::json!({"check": row.check, "verdict": "build-failed"});
        if let Some(r) = rejection {
            observation["build_rejection"] = Value::from(r);
        }
        serde_json::json!({
            "coverage": {"checks_attempted": checks},
            "observations": [observation],
        })
    };
    let rejected = failed(Some(
        "cc rejected -fzero-call-used-regs=skip, supplied by the profile not by this check: \
         clang: error: unknown argument: '-fzero-call-used-regs=skip'",
    ));
    assert!(
        matches!(judge(row, &rejected), Outcome::Gap(_)),
        "a driver that rejected the row's flag was not announced as a gap"
    );
    assert!(
        matches!(judge(row, &failed(None)), Outcome::Exercised(p) if !p.is_empty()),
        "a build that failed under a flag the driver knows passed the row"
    );
}

/// What one row's run established.
enum Outcome {
    /// The host does not meet the row's condition; the string says why.
    Gap(String),
    /// The row was exercised; the list holds what it found wrong, if anything.
    Exercised(Vec<String>),
}

/// One check's or composite's verdict in a report, or `None` when nothing carries it.
fn verdict_of<'a>(report: &'a Value, check: &str) -> Option<&'a str> {
    reading(report, check).and_then(|o| o["verdict"].as_str())
}

/// The line the driving test prints for an exercised row: its verdict and why. Printed
/// there rather than in [`judge`], which the self-test also calls over a forged report,
/// so a guest log never shows a reading no run produced.
fn reading_line(row: &InertForm, report: &Value) -> String {
    let observation = reading(report, row.check);
    let field = |f: &dyn Fn(&Value) -> &Value| {
        observation
            .and_then(|o| f(o).as_str())
            .unwrap_or("-")
            .to_owned()
    };
    format!(
        "inert_flags: {:<40} {:<64} -> {} (level {}, gating {}, withheld {})",
        row.check,
        row.flags,
        field(&|o| &o["verdict"]),
        field(&|o| &o["level"]),
        field(&|o| &o["gating"]["rule"]),
        field(&|o| &o["controls"]["withheld_because"]),
    )
}

/// Read one row's report: the check was attempted, and its verdict is one the row accepts.
fn judge(row: &InertForm, report: &Value) -> Outcome {
    let mut problems = Vec::new();
    let expected_checks = chard::probe::find(row.probe)
        .map(|p| p.checks.len())
        .expect("the invariant test pins every row's probe");
    let attempted = report["coverage"]["checks_attempted"].as_u64();
    if attempted != u64::try_from(expected_checks).ok() {
        problems.push(format!(
            "{} under `{}`: probe `{}` carries {expected_checks} checks and the run \
             attempted {attempted:?}",
            row.check, row.flags, row.probe
        ));
    }

    let Some(observation) = reading(report, row.check) else {
        problems.push(format!(
            "{} under `{}`: the check was not attempted; no observation carries it",
            row.check, row.flags
        ));
        return Outcome::Exercised(problems);
    };
    let verdict = observation["verdict"].as_str().unwrap_or("?");
    let level = observation["level"].as_str().unwrap_or("-");
    let rule = observation["gating"]["rule"].as_str().unwrap_or("-");
    let cause = observation["controls"]["withheld_because"]
        .as_str()
        .unwrap_or("-");

    if let Err(why) = applies_here(&row.applies, report) {
        return Outcome::Gap(format!(
            "{why}; measured here as {verdict} and not asserted on"
        ));
    }

    // A driver that rejects the row's own flag built nothing the form could act on, so the
    // row is a gap there, named by the rejection the report carries. Read from
    // `build_rejection` rather than accepted as `build-failed`, because the verdict alone
    // also covers a probe that broke under a flag the driver knows, which reads nothing
    // and must fail a row that does not expect it.
    if verdict == "build-failed"
        && let Some(rejection) = observation["build_rejection"].as_str()
    {
        return Outcome::Gap(format!(
            "the driver rejected the form's flag, so nothing was built under it: {rejection}"
        ));
    }

    problems.extend(refused(row, libc_of(report), verdict, cause).map(|why| {
        format!(
            "{} under `{}`: {why} (level {level}, gating {rule}, withheld {cause})",
            row.check, row.flags
        )
    }));
    Outcome::Exercised(problems)
}

/// Why the row refuses `verdict`, withheld for `cause` under `libc`, or `None` when it
/// accepts it: never `on`, else the row's expected set or a [`WITHHELD_ON_PLATFORM`] entry.
fn refused(row: &InertForm, libc: &str, verdict: &str, cause: &str) -> Option<String> {
    if verdict == "on" {
        return Some(format!(
            "reported `on` for a flag that is present and inert ({})",
            row.inert_because
        ));
    }
    if row.expected.contains(&verdict) || withheld_admits(row, libc, verdict, cause).is_some() {
        return None;
    }
    Some(format!(
        "verdict `{verdict}` is outside the expected {:?}; read the report before widening \
         the set",
        row.expected
    ))
}

/// Print the [`WITHHELD_ON_PLATFORM`] entry that admitted an exercised row's reading, if
/// one did, so a guest log names the cause beside the verdict.
fn print_admission(row: &InertForm, report: &Value) {
    let observation = reading(report, row.check);
    let field = |f: &str| {
        observation
            .and_then(|o| o.pointer(f))
            .and_then(Value::as_str)
            .unwrap_or("-")
    };
    let verdict = field("/verdict");
    if row.expected.contains(&verdict) {
        return;
    }
    if let Some(w) = withheld_admits(
        row,
        libc_of(report),
        verdict,
        field("/controls/withheld_because"),
    ) {
        eprintln!(
            "inert_flags:   admitted on {} as {} ({}): {}",
            w.libc,
            w.verdict.as_str(),
            w.withheld_because.as_str(),
            w.because
        );
    }
}

/// The compiler accounting bites: over forged outcomes for a four-row table (one row for
/// any compiler, one gcc's, one clang's, one naming both), each way a row can go missing
/// or run where it cannot is a problem, and only the honest split passes. Run with no
/// toolchain, so the rule is checked on every host, including one with no clang at all.
#[test]
fn the_compiler_accounting_fails_a_row_skipped_or_run_where_it_cannot() {
    let rows = [
        Applies::Always,
        Applies::Compiler(&["gcc"]),
        Applies::ElfCompiler(&["clang"]),
        Applies::CompilerRuntime(&["gcc", "clang"], "-fsanitize=undefined"),
    ];
    let conditions: Vec<&Applies> = rows.iter().collect();
    let run = |kind: &str, expected: Option<&str>, exercised: &[usize], gaps: &[usize]| {
        compiler_accounting("self-test", kind, expected, &conditions, exercised, gaps).1
    };
    let has = |problems: &[String], text: &str| problems.iter().any(|p| p.contains(text));
    // Honest: under gcc, the clang row is announced and the rest run.
    assert_eq!(run("gcc", None, &[0, 1, 3], &[2]), Vec::<String>::new());
    // Honest, with a host gap among the rows gcc can run.
    assert_eq!(run("gcc", None, &[0, 1], &[2, 3]), Vec::<String>::new());
    // The clang row run under gcc: the row, and the sum it pushes past the runnable count.
    let ran = run("gcc", None, &[0, 1, 2, 3], &[]);
    assert!(has(&ran, "row 2 was exercised under gcc"), "{ran:?}");
    assert!(has(&ran, "do not sum"), "{ran:?}");
    // The clang row neither run nor announced.
    let lost = run("gcc", None, &[0, 1, 3], &[]);
    assert!(has(&lost, "row 2 belongs to"), "{lost:?}");
    assert!(has(&lost, "row 2 is listed 0 times"), "{lost:?}");
    // A runnable row silently dropped.
    let dropped = run("gcc", None, &[0, 1], &[2]);
    assert!(has(&dropped, "row 3 is listed 0 times"), "{dropped:?}");
    assert!(has(&dropped, "do not sum"), "{dropped:?}");
    // A row listed twice offsetting a row never listed: the sum alone balances here.
    let twice = run("gcc", None, &[0, 1], &[1, 2]);
    assert!(has(&twice, "row 1 is listed 2 times"), "{twice:?}");
    assert!(has(&twice, "row 3 is listed 0 times"), "{twice:?}");
    let repeated = run("gcc", None, &[0, 0, 1], &[2]);
    assert!(has(&repeated, "row 0 is listed 2 times"), "{repeated:?}");
    assert!(has(&repeated, "row 3 is listed 0 times"), "{repeated:?}");
    // An index past the table offsetting a row never listed.
    let stray = run("gcc", None, &[0, 1], &[2, 9]);
    assert!(has(&stray, "rows [9] are past the table"), "{stray:?}");
    assert!(has(&stray, "row 3 is listed 0 times"), "{stray:?}");
    // The gate: clang expected, gcc answered.
    let wrong = run("gcc", Some("clang"), &[0, 1, 3], &[2]);
    assert!(has(&wrong, "expects `cc` to be clang"), "{wrong:?}");
    // The gate: clang answered, and a clang row was announced as a host gap.
    let missed = run("clang", Some("clang"), &[0, 2], &[1, 3]);
    assert_eq!(missed.len(), 1, "{missed:?}");
    assert!(missed[0].contains("rows [3]"), "{missed:?}");
    // The gate passes only when every row naming the family ran.
    assert_eq!(
        run("clang", Some("clang"), &[0, 2, 3], &[1]),
        Vec::<String>::new()
    );
    // The toolchain the reports name: none, two, or one with no kind is never accounted.
    let kinds = |list: &[&str]| {
        list.iter()
            .map(|k| (*k).to_owned())
            .collect::<BTreeSet<_>>()
    };
    for (named, text) in [
        (kinds(&[]), "no report named a toolchain"),
        (kinds(&["clang", "gcc"]), "name 2 toolchain kinds"),
        (kinds(&["unknown"]), "name no toolchain kind"),
    ] {
        let problems = accounting("self-test", &named, &conditions, &[0, 1, 3], &[2]);
        assert!(has(&problems, text), "{named:?}: {problems:?}");
    }
}

/// Drive every inert form through the built binary: the check was attempted, and the
/// verdict is one the row accepts.
///
/// One test rather than one per row, so the summary line counts what ran against what
/// could not, and a run that exercised nothing fails on the count rather than passing on
/// the absence of failures.
#[allow(
    clippy::too_many_lines,
    reason = "one test rather than one per row, as above, so its summary counts what ran against what could not"
)]
#[test]
fn an_inert_flag_is_never_reported_on() {
    if !can_run("that a flag present in an inert form is never reported `on`") {
        return;
    }
    let mut failures = Vec::new();
    let mut exercised = Vec::new();
    let mut gaps = Vec::new();
    // By row rather than by check: two rows of one check can differ in their condition,
    // and a clang-only row announced on a gcc host is not the artifact row beside it.
    let mut gap_rows = Vec::new();
    let mut exercised_rows = Vec::new();
    let mut kinds = BTreeSet::new();

    // Each row's measurement is independent and is a chain of child processes run one after
    // another, so they are taken at once on a few threads and judged below in row order: in
    // series they took 51 s of the suite, mostly waiting on children.
    let reports = measure_rows(INERT_FORMS);
    for (i, (row, report)) in INERT_FORMS.iter().zip(reports).enumerate() {
        kinds.insert(toolchain_kind(&report).to_owned());
        // A row whose probe reads kernel policy is evaluated only where the measurement
        // established the kernel: the harness asserts it where the report would read the
        // default, so `execution-mode-assumed` here is the harness not doing so, and the
        // row's claim going unexamined.
        if reads_kernel_policy(row.probe) {
            let rule = reading(&report, row.check).and_then(|o| o["gating"]["rule"].as_str());
            assert_ne!(
                rule,
                Some("execution-mode-assumed"),
                "{} under `{}`: the harness asserted no kernel for a row that reads kernel \
                 policy, so its claim went unevaluated",
                row.check,
                row.flags
            );
        }
        // A row can only attribute `on` to its own inert flag where the check reads
        // something else without it. Where the mechanism is a compiled-in default, `on`
        // is a true reading of the toolchain and the flag had no part in it, so the row
        // cannot discriminate and is announced rather than failed. Fedora 44 configures
        // libstdc++ with `_GLIBCXX_ASSERTIONS` defined in `c++config.h`, which no `-U` on
        // the command line can countermand, and `cxx-hardening-requested` reads `on`
        // there under any flags at all.
        // A composite row is never excused this way; see `COMPOSITES`.
        if verdict_of(&report, row.check) == Some("on")
            && bare_control_can_excuse(row)
            && applies_here(&row.applies, &report).is_ok()
        {
            let base = common::Work::new("inert-control", &format!("{i}-{}", row.check));
            let control = measure_flags(row, &base, None);
            if excused_by_control(row, &control) {
                let why = "the check reads `on` under `bare`, with none of the row's \
                           flags, so this host's toolchain carries the mechanism as a \
                           default and the inert form cannot be told from it";
                common::capability_gap(&format!("{} under `{}`", row.check, row.flags), why);
                gaps.push(row.check);
                gap_rows.push(i);
                continue;
            }
        }
        match judge(row, &report) {
            Outcome::Gap(why) => {
                common::capability_gap(&format!("{} under `{}`", row.check, row.flags), &why);
                gaps.push(row.check);
                gap_rows.push(i);
            }
            Outcome::Exercised(problems) => {
                eprintln!("{}", reading_line(row, &report));
                print_admission(row, &report);
                exercised.push(row.check);
                exercised_rows.push(i);
                failures.extend(problems);
            }
        }
    }
    failures.extend(accounting(
        "inert_flags",
        &kinds,
        &INERT_FORMS.iter().map(|r| &r.applies).collect::<Vec<_>>(),
        &exercised_rows,
        &gap_rows,
    ));

    let total = INERT_FORMS.len();
    let listed = |rows: &[&str]| {
        if rows.is_empty() {
            "none".to_owned()
        } else {
            rows.join(", ")
        }
    };
    eprintln!(
        "inert_flags: {} of {total} rows exercised on this host: {}",
        exercised.len(),
        listed(&exercised)
    );
    eprintln!(
        "inert_flags: {} of {total} rows announced as unexercised on this host: {}",
        gaps.len(),
        listed(&gaps)
    );
    assert_eq!(
        exercised.len().saturating_add(gaps.len()),
        total,
        "every row is either exercised or announced as a gap"
    );
    assert!(
        !exercised.is_empty(),
        "no inert form could be exercised on this host, so nothing was checked"
    );
    if common::ELF_HOST {
        let artifact_gaps: Vec<&str> = INERT_FORMS
            .iter()
            .enumerate()
            .filter(|(i, r)| matches!(r.applies, Applies::ElfArtifact) && gap_rows.contains(i))
            .map(|(_, r)| r.check)
            .collect();
        assert!(
            artifact_gaps.is_empty(),
            "this host emits ELF and these artifact rows still did not run: {artifact_gaps:?}"
        );
    }
    assert!(
        failures.is_empty(),
        "{} inert form(s) reported a verdict the row refuses:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Measure one partly inert form: the row's probes under its flags, in one report, so the
/// corroboration group over them is published.
fn measure_partly(row: &PartlyInertForm, work: &common::Work) -> Value {
    let args = ["measure", "--profile", "explicit", "--flags", row.flags].map(str::to_owned);
    report_of(&args, row.probes, work, row.check, row.flags)
}

/// What is wrong with one `PARTLY_INERT_FORMS` row against the corpus alone: its first probe
/// carries the check, the check is graded with `reads` an ungraded word of its scale and
/// `requested` a rung, and some other probe named carries a member of the same group on
/// another channel, or the group's `agree` would have one reader and nothing to compare.
fn partly_row_problems(row: &PartlyInertForm) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(check) = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .find(|c| c.id == row.check)
    else {
        problems.push(format!("`{}` is not a corpus check", row.check));
        return problems;
    };
    let Some(first) = row.probes.first().and_then(|id| chard::probe::find(id)) else {
        problems.push(format!("`{}`'s row names no corpus probe first", row.check));
        return problems;
    };
    if !first.checks.iter().any(|c| c.id == row.check) {
        problems.push(format!(
            "`{}`'s row names probe `{}` first, which does not carry that check",
            row.check, first.id
        ));
    }
    match check.levels.grade() {
        None => problems.push(format!(
            "`{}` grades no level, so no word can be partly inert",
            row.check
        )),
        Some(grade) => {
            if !grade.ungraded.contains(&row.reads) {
                problems.push(format!(
                    "`{}`'s row reads `{}`, which its scale does not admit on no rung ({:?})",
                    row.check, row.reads, grade.ungraded
                ));
            }
            if grade.meets(row.requested).is_none() {
                problems.push(format!(
                    "`{}`'s row requests `{}`, which is not a rung of its scale ({})",
                    row.check,
                    row.requested,
                    grade.scale.spelled()
                ));
            }
        }
    }
    if check.corroborates != Some(row.group) {
        problems.push(format!(
            "`{}` corroborates {:?}, not `{}`",
            row.check, check.corroborates, row.group
        ));
    }
    let other_channel = row
        .probes
        .iter()
        .filter_map(|id| chard::probe::find(id))
        .flat_map(|p| p.checks)
        .any(|c| c.corroborates == Some(row.group) && c.channel() != check.channel());
    if !other_channel {
        problems.push(format!(
            "`{}`'s row names no probe carrying a `{}` member on another channel, so the \
             group would have nothing to compare its word with",
            row.check, row.group
        ));
    }
    if row.inert_because.len() < 60 {
        problems.push(format!(
            "`{}`'s partly inert reason is {} characters, which does not state one",
            row.check,
            row.inert_because.len()
        ));
    }
    problems
}

/// The checks that admit a word on no rung and never publish it, each with the reason: a
/// check shares its scale with the one that does (so the `stack-protector` group compares
/// the two on one scale), and the word is the other reader's alone.
const NEVER_PUBLISHES_UNGRADED: &[(&str, &str, &str)] = &[(
    "ssp-level",
    "unsafe-frame",
    "the macro reader shares probe::SSP_LEVELS with ssp-level-emitted so the group compares \
     their words on one scale; it reads the level the preprocessor was asked for, and \
     -fsanitize=safe-stack defines no macro, so the word is the artifact reader's alone",
)];

/// Every partly inert row is well formed against the corpus, and every word a check admits
/// on no rung has a row or a named reason it never publishes the word: such a word is a
/// selection some flag made that is not what it names, and this table is where that form
/// is driven. Runs without a compiler.
#[test]
fn every_partly_inert_row_names_an_ungraded_word_of_its_checks_scale() {
    assert!(
        !PARTLY_INERT_FORMS.is_empty(),
        "the table is empty, so nothing is checked; delete the test rather than let it pass"
    );
    let mut problems: Vec<String> = PARTLY_INERT_FORMS
        .iter()
        .flat_map(partly_row_problems)
        .collect();
    let covered: BTreeSet<(&str, &str)> = PARTLY_INERT_FORMS
        .iter()
        .map(|r| (r.check, r.reads))
        .collect();
    let exempt: BTreeSet<(&str, &str)> = NEVER_PUBLISHES_UNGRADED
        .iter()
        .map(|(c, w, _)| (*c, *w))
        .collect();
    for (check, word, reason) in NEVER_PUBLISHES_UNGRADED {
        let admits = chard::probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .any(|c| c.id == *check && c.levels.ungraded().contains(word));
        if !admits {
            problems.push(format!(
                "`{check}` is exempted from driving `{word}` and admits no such word"
            ));
        }
        if covered.contains(&(check, word)) {
            problems.push(format!(
                "`{check}` at `{word}` is both exempted and driven by a row"
            ));
        }
        if reason.len() < 60 {
            problems.push(format!(
                "`{check}`'s reason for never publishing `{word}` is {} characters, which \
                 does not state one",
                reason.len()
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    let mut missing = Vec::new();
    for check in chard::probe::CORPUS.iter().flat_map(|p| p.checks) {
        for word in check.levels.ungraded() {
            if !covered.contains(&(check.id, word)) && !exempt.contains(&(check.id, word)) {
                missing.push(format!("{} at `{word}`", check.id));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "checks admit words on no rung with no partly inert row driving them and no reason \
         they never publish them: {missing:?}"
    );
}

/// Drive every partly inert form through the built binary: the check reads `on` at the
/// row's own word, never at the requested one and never anything but `on`, and the group
/// names the split rather than agreeing.
#[test]
fn a_partly_inert_flag_is_reported_on_at_its_own_word_and_never_at_the_requested_one() {
    if !can_run(
        "that a flag present in a partly inert form is reported `on` at the word it realised \
         and never at the one it requested",
    ) {
        return;
    }
    let mut failures = Vec::new();
    let mut exercised_rows = Vec::new();
    let mut gap_rows = Vec::new();
    let mut kinds = BTreeSet::new();
    for (i, row) in PARTLY_INERT_FORMS.iter().enumerate() {
        let work = common::Work::new("partly-inert", &format!("{i}-{}", row.check));
        let report = measure_partly(row, &work);
        kinds.insert(toolchain_kind(&report).to_owned());
        if let Err(why) = applies_here(&row.applies, &report) {
            common::capability_gap(&format!("{} under `{}`", row.check, row.flags), &why);
            gap_rows.push(i);
            continue;
        }
        let expected_checks: usize = row
            .probes
            .iter()
            .filter_map(|id| chard::probe::find(id))
            .map(|p| p.checks.len())
            .sum();
        let attempted = report["coverage"]["checks_attempted"].as_u64();
        if attempted != u64::try_from(expected_checks).ok() {
            failures.push(format!(
                "{} under `{}`: probes {:?} carry {expected_checks} checks and the run \
                 attempted {attempted:?}",
                row.check, row.flags, row.probes
            ));
        }
        let Some(observation) = reading(&report, row.check) else {
            failures.push(format!(
                "{} under `{}`: the check was not attempted; no observation carries it",
                row.check, row.flags
            ));
            continue;
        };
        let verdict = observation["verdict"].as_str().unwrap_or("?");
        let level = observation["level"].as_str().unwrap_or("-");
        let group = &report["corroboration"][row.group];
        let agree = group["agree"].as_bool();
        let note = group["note"].as_str().unwrap_or("-");
        eprintln!(
            "inert_flags: partly inert {:<22} {:<48} -> {verdict} (level {level}, {} agree {agree:?})",
            row.check, row.flags, row.group
        );
        if verdict != "on" {
            failures.push(format!(
                "{} under `{}`: reported `{verdict}` for a mechanism that is present; the \
                 partly inert form is `on` at `{}` ({})",
                row.check, row.flags, row.reads, row.inert_because
            ));
        } else if level == row.requested {
            failures.push(format!(
                "{} under `{}`: reported `on` at `{level}`, the word the flag requested and \
                 did not realise ({})",
                row.check, row.flags, row.inert_because
            ));
        } else if level != row.reads {
            failures.push(format!(
                "{} under `{}`: reported `on` at `{level}`, not the word the form realises \
                 (`{}`); read the report before widening the row",
                row.check, row.flags, row.reads
            ));
        }
        if agree != Some(false) || !note.starts_with("LEVELS DISAGREE") {
            failures.push(format!(
                "{} under `{}`: the `{}` group reads agree {agree:?} with note `{note}`; a \
                 word on no rung beside the requested rung is a level requested and not \
                 realised, and the group names it",
                row.check, row.flags, row.group
            ));
        }
        exercised_rows.push(i);
    }
    let conditions: Vec<&Applies> = PARTLY_INERT_FORMS.iter().map(|r| &r.applies).collect();
    let (table, total) = ("inert_flags (partly inert)", PARTLY_INERT_FORMS.len());
    failures.extend(accounting(
        table,
        &kinds,
        &conditions,
        &exercised_rows,
        &gap_rows,
    ));
    assert_eq!(
        exercised_rows.len().saturating_add(gap_rows.len()),
        total,
        "every partly inert row is either exercised or announced as a gap"
    );
    assert!(
        failures.is_empty(),
        "{} partly inert form(s) read wrongly:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
