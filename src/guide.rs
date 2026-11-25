// SPDX-License-Identifier: BSD-3-Clause
//! The OpenSSF guide's inventory: every flag and recommendation of the pinned revision, with
//! the checks that read it or the reason none does.

/// The guide revision the inventory transcribes: the date in its own by-line.
pub const REVISION: &str = "2026-08-20";

/// The upstream commit of `ossf/wg-best-practices-os-developers` whose text was read: the
/// last to touch the guide at that revision date, correcting typos after the commit that set
/// the date; the by-line alone does not tell the two apart, so the pin names the commit.
pub const REVISION_COMMIT: &str = "5689b7c908e94c9ecc6685a65661648045f2a2bc";

/// The "When" cells of the TL;DR's addendum table, in the guide's order.
pub const ADDENDUM_WHEN: &[&str] = &[
    "using GCC",
    "using GCC and only left-to-right writing in source code",
    "for executables",
    "for shared libraries",
    "for x86_64",
    "for aarch64",
    "for production code",
    "for C code treating obsolete C constructs as errors",
    "for multi-threaded C code using GNU C library pthreads",
    "during development but *not* when distributing source",
];

/// Where the guide says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The TL;DR block, to turn on in all cases.
    TlDr,
    /// A row of the TL;DR's "add the corresponding additional options" table, by its "When"
    /// cells (one flag stands in two rows).
    Addendum(&'static [&'static str]),
    /// The recommended-options tables beyond the block: a flag the guide recommends without
    /// putting it in the block or the addendum.
    Recommended,
    /// A variant a flag's own section tabulates beside the recommended spelling.
    Variant,
    /// "Discouraged Compiler Options".
    Discouraged,
    /// "Sanitizers".
    Sanitizer,
    /// "Maintaining debug information in separate files": a recommendation in prose.
    DebugInfo,
    /// "What should you do when compiling compilers?" and "... compiling linkers?".
    Toolchain,
    /// "Appendix: List of Considered Compiler Options": reviewed and excluded, with the
    /// guide's rationale.
    Considered,
}

/// Whether the `openssf-tldr` profile carries the flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carried {
    /// In the unconditional block, on every architecture (`report::openssf_tldr_cflags`).
    Base,
    /// In the executables addendum, on every architecture.
    Executable,
    /// In the architecture addendum, for these architectures.
    Arch(&'static [&'static str]),
    /// Not carried, for this reason.
    No(&'static str),
}

/// What chard reads of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reads {
    /// These checks read it.
    Checks(&'static [&'static str]),
    /// No check reads it, for this reason.
    None(&'static str),
}

/// One unit of the guide's tables, or one recommendation it makes in prose.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    /// The flag as the guide's table cell writes it, its placeholders removed (`-Werror=`
    /// for `-Werror=<warning-flag>`), or the recommendation's name.
    pub flag: &'static str,
    pub place: Place,
    pub carried: Carried,
    pub reads: Reads,
    /// What the checks read of it where that is less than the flag, or what a measurement
    /// showed; empty where the checks read the flag as the guide means it.
    pub note: &'static str,
}

/// Why an addendum flag is not in the profile.
const NOT_CARRIED: &str =
    "the profile carries the block and the executables and architecture rows only";

/// Why a recommended flag outside the block and the addendum is not in the profile.
const OUTSIDE_THE_BLOCK: &str =
    "the guide recommends it outside the block and the addendum the profile transcribes";

/// Why a variant is not in the profile.
const A_VARIANT: &str = "a variant beside the recommended spelling";

/// Why a sanitizer is not read: the guide's own line between the two kinds of build.
const INSTRUMENTED_TEST_CODE: &str = "instrumentation for test code";

/// Why an appendix flag is not in the profile.
const EXCLUDED_BY_THE_GUIDE: &str = "the guide's appendix lists it as considered and excluded";

const ZERO_CALL_USED_REGS_VARIANT: &str = "read on the check's scale (arg, gpr; skip reads off)";

/// Checks the corpus ships for flags the guide does not name, pinned so that a check added
/// for a guide flag without a row fails `every_check_is_placed_once_and_every_named_check_exists`.
pub const BEYOND_THE_GUIDE: &[&str] = &[
    // `-fno-plt`.
    "plt-bypassed",
    // `-Wl,-z,separate-code`.
    "separate-code",
    // `-Wl,-z,pack-relative-relocs`.
    "relative-relocs",
    // OpenBSD's `-fret-protector`.
    "ret-protector-emitted",
    // `-mbranch-protection=gcs`, the Guarded Control Stack half of `standard` on compilers
    // whose `standard` includes it, read on its own.
    "gcs-macro",
    "gcs-marked",
];

/// Every flag and recommendation of the guide at [`REVISION`].
pub const INVENTORY: &[Row] = &[
    // The TL;DR block, in its order.
    Row {
        flag: "-O2",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["optimization-enabled", "optimization-applied"]),
        note: "",
    },
    Row {
        flag: "-Wall",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["warn-all"]),
        note: "",
    },
    Row {
        flag: "-Wformat",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["format-mismatch-warned"]),
        note: "",
    },
    Row {
        flag: "-Wformat=2",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["format-nonliteral-warned"]),
        note: "",
    },
    Row {
        flag: "-Wconversion",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["conversion-warns-on-narrowing"]),
        note: "",
    },
    Row {
        flag: "-Wimplicit-fallthrough",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["implicit-fallthrough-warned"]),
        note: "",
    },
    Row {
        flag: "-Werror=format-security",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["format-security-is-error"]),
        note: "",
    },
    Row {
        flag: "-U_FORTIFY_SOURCE",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["fortify-requested", "fortify-effective"]),
        note: "the undefine half of the guide's request, read through the level the request \
               leaves in force",
    },
    Row {
        flag: "-D_FORTIFY_SOURCE=3",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&[
            "fortify-requested",
            "fortify-effective",
            "fortify-printf-flag",
            "fortify-enforced-known",
            "fortify-enforced-dynamic",
            "fortify-level-ge-2-subobject",
            "fortify-level-ge-2-percent-n",
        ]),
        note: "",
    },
    Row {
        flag: "-D_GLIBCXX_ASSERTIONS",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&[
            "cxx-hardening-requested",
            "cxx-stdlib-assertions",
            "cxx-assertions-symbol",
        ]),
        note: "",
    },
    Row {
        flag: "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["cxx-hardening-requested", "cxx-stdlib-assertions"]),
        note: "under libc++, which this host lacks",
    },
    Row {
        flag: "-fstrict-flex-arrays=3",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["strict-flex-arrays", "strict-flex-arrays-enforced"]),
        note: "",
    },
    Row {
        flag: "-fstack-clash-protection",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["stack-clash-guard-page"]),
        note: "",
    },
    Row {
        flag: "-fstack-protector-strong",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["ssp-level", "ssp-level-emitted", "canary-emitted"]),
        note: "",
    },
    Row {
        flag: "-Wl,-z,nodlopen",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["nodlopen"]),
        note: "",
    },
    Row {
        flag: "-Wl,-z,noexecstack",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["noexecstack", "noexecstack-enforced"]),
        note: "",
    },
    Row {
        flag: "-Wl,-z,relro",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["relro"]),
        note: "one check reads the pair as a level",
    },
    Row {
        flag: "-Wl,-z,now",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["relro"]),
        note: "the full level of the relro check",
    },
    Row {
        flag: "-Wl,--as-needed",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["as-needed"]),
        note: "",
    },
    Row {
        flag: "-Wl,--no-copy-dt-needed-entries",
        place: Place::TlDr,
        carried: Carried::Base,
        reads: Reads::Checks(&["no-copy-dt-needed"]),
        note: "",
    },
    // The addendum table, in its order.
    Row {
        flag: "-Wtrampolines",
        place: Place::Addendum(&["using GCC"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["trampolines-warned"]),
        note: "",
    },
    Row {
        flag: "-fzero-init-padding-bits=all",
        place: Place::Addendum(&["using GCC"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["zero-init-padding-bits"]),
        note: "",
    },
    Row {
        flag: "-Wbidi-chars=any",
        place: Place::Addendum(&["using GCC and only left-to-right writing in source code"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["bidi-chars-any"]),
        note: "",
    },
    Row {
        flag: "-fPIE -pie",
        place: Place::Addendum(&["for executables"]),
        carried: Carried::Executable,
        reads: Reads::Checks(&["pie-macro", "pie"]),
        note: "",
    },
    Row {
        flag: "-fPIC -shared",
        place: Place::Addendum(&["for shared libraries"]),
        carried: Carried::No("the profile builds executables"),
        reads: Reads::Checks(&[
            "pic-macro",
            "pic-shared-link",
            "pic-object-relocs",
            "textrel-absent",
        ]),
        note: "",
    },
    Row {
        flag: "-fcf-protection=full",
        place: Place::Addendum(&["for x86_64"]),
        carried: Carried::Arch(&["x86_64"]),
        reads: Reads::Checks(&[
            "cet-macro",
            "cet-marked-object",
            "cet-endbr-emitted",
            "cet-marked",
            "shadow-stack-enforced",
        ]),
        note: "",
    },
    Row {
        flag: "-mbranch-protection=standard",
        place: Place::Addendum(&["for aarch64"]),
        carried: Carried::Arch(&["aarch64"]),
        reads: Reads::Checks(&[
            "branch-protection-macro",
            "branch-protection-marked",
            "bti-enforced",
            "pac-ret-enforced",
        ]),
        note: "the Guarded Control Stack half of standard",
    },
    Row {
        flag: "-fzero-call-used-regs=used-gpr",
        place: Place::Addendum(&["for x86_64", "for aarch64"]),
        carried: Carried::Arch(&["x86_64", "aarch64"]),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: "",
    },
    Row {
        flag: "-fno-delete-null-pointer-checks",
        place: Place::Addendum(&["for production code"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["no-delete-null-pointer-checks"]),
        note: "",
    },
    Row {
        flag: "-fno-strict-overflow",
        place: Place::Addendum(&["for production code"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["no-strict-overflow"]),
        note: "read as defined signed integer overflow",
    },
    Row {
        flag: "-fno-strict-aliasing",
        place: Place::Addendum(&["for production code"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["no-strict-aliasing"]),
        note: "",
    },
    Row {
        flag: "-ftrivial-auto-var-init=zero",
        place: Place::Addendum(&["for production code"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["auto-var-init-active"]),
        note: "",
    },
    Row {
        flag: "-Werror=implicit",
        place: Place::Addendum(&["for C code treating obsolete C constructs as errors"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&[
            "implicit-function-declaration-is-error",
            "implicit-int-is-error",
        ]),
        note: "gcc's -Werror=implicit is the two warnings the checks read",
    },
    Row {
        flag: "-Werror=incompatible-pointer-types",
        place: Place::Addendum(&["for C code treating obsolete C constructs as errors"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["incompatible-pointer-types-is-error"]),
        note: "",
    },
    Row {
        flag: "-Werror=int-conversion",
        place: Place::Addendum(&["for C code treating obsolete C constructs as errors"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["int-conversion-is-error"]),
        note: "",
    },
    Row {
        flag: "-fexceptions",
        place: Place::Addendum(&["for multi-threaded C code using GNU C library pthreads"]),
        carried: Carried::No(NOT_CARRIED),
        reads: Reads::Checks(&["exceptions-macro", "except-table-emitted"]),
        note: "",
    },
    Row {
        flag: "-Werror",
        place: Place::Addendum(&["during development but *not* when distributing source"]),
        carried: Carried::No("a development setting the guide keeps out of distributed builds"),
        reads: Reads::None("a blanket promotion of every warning"),
        note: "",
    },
    // Recommended outside the block and the addendum.
    Row {
        flag: "-Wextra",
        place: Place::Recommended,
        carried: Carried::No(OUTSIDE_THE_BLOCK),
        reads: Reads::Checks(&["warn-extra"]),
        note: "",
    },
    Row {
        flag: "-Wsign-conversion",
        place: Place::Recommended,
        carried: Carried::No(OUTSIDE_THE_BLOCK),
        reads: Reads::Checks(&["sign-conversion-warns-on-signedness-change"]),
        note: "",
    },
    Row {
        flag: "-Werror=",
        place: Place::Recommended,
        carried: Carried::No(OUTSIDE_THE_BLOCK),
        reads: Reads::None("the form of the named -Werror= rows"),
        note: "",
    },
    Row {
        flag: "-ftrivial-auto-var-init",
        place: Place::Recommended,
        carried: Carried::No(OUTSIDE_THE_BLOCK),
        reads: Reads::Checks(&["auto-var-init-active", "auto-var-init-pattern"]),
        note: "the zero form is graded against the guide's ask, the pattern form read as \
               itself",
    },
    Row {
        flag: "-fhardened",
        place: Place::Recommended,
        carried: Carried::No(OUTSIDE_THE_BLOCK),
        reads: Reads::Checks(&["hardened-downgrade-warned"]),
        note: "read through its downgrade warning for `-fstack-protector-strong`, the one the probe forces",
    },
    // Variants the flags' own tables list.
    Row {
        flag: "-D_FORTIFY_SOURCE=2",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "fortify-requested",
            "fortify-effective",
            "fortify-printf-flag",
            "fortify-enforced-known",
            "fortify-enforced-dynamic",
            "fortify-level-ge-2-subobject",
            "fortify-level-ge-2-percent-n",
        ]),
        note: "read as level 2 on the numeric scale, partial against the ask",
    },
    Row {
        flag: "-D_FORTIFY_SOURCE=1",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "fortify-requested",
            "fortify-effective",
            "fortify-printf-flag",
            "fortify-enforced-known",
            "fortify-enforced-dynamic",
            "fortify-level-ge-2-subobject",
            "fortify-level-ge-2-percent-n",
        ]),
        note: "read as level 1; the known enforcement reads on, the level-2 rungs and the \
               dynamic one off",
    },
    Row {
        flag: "-D_GLIBCXX_DEBUG",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "cxx-hardening-requested",
            "cxx-stdlib-assertions",
            "cxx-assertions-symbol",
        ]),
        note: "the request reads on through the assertions the debug mode implies",
    },
    Row {
        flag: "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["cxx-hardening-requested", "cxx-stdlib-assertions"]),
        note: "read as the word extensive",
    },
    Row {
        flag: "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["cxx-hardening-requested", "cxx-stdlib-assertions"]),
        note: "read as the word debug; the runtime check reads the fast subset's abort",
    },
    Row {
        flag: "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["cxx-hardening-requested", "cxx-stdlib-assertions"]),
        note: "read as the mode none, which is no request",
    },
    Row {
        flag: "-fstrict-flex-arrays=2",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["strict-flex-arrays", "strict-flex-arrays-enforced"]),
        note: "read as level 2 on the numeric scale",
    },
    Row {
        flag: "-fstrict-flex-arrays=1",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["strict-flex-arrays", "strict-flex-arrays-enforced"]),
        note: "read as level 1",
    },
    Row {
        flag: "-fstrict-flex-arrays=0",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["strict-flex-arrays", "strict-flex-arrays-enforced"]),
        note: "read as level 0, which is off",
    },
    Row {
        flag: "-param stack-clash-protection-guard-size=",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["stack-clash-guard-page"]),
        note: "read as the probing itself, whatever gap is set",
    },
    Row {
        flag: "-fstack-protector-all",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["ssp-level", "ssp-level-emitted", "canary-emitted"]),
        note: "read as the level all",
    },
    Row {
        flag: "-fstack-protector",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "ssp-level",
            "ssp-level-emitted",
            "canary-emitted",
            "ssp-covers-small-arrays",
        ]),
        note: "read as the level basic; the buffer-size threshold is the next row's",
    },
    Row {
        flag: "--param=ssp-buffer-size=",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["ssp-covers-small-arrays"]),
        note: "read as whether an array below the default threshold is covered",
    },
    Row {
        flag: "-fcf-protection=branch",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "cet-macro",
            "cet-marked-object",
            "cet-endbr-emitted",
            "cet-marked",
            "shadow-stack-enforced",
        ]),
        note: "read as the level branch, the shadow stack off",
    },
    Row {
        flag: "-fcf-protection=return",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "cet-macro",
            "cet-marked-object",
            "cet-endbr-emitted",
            "cet-marked",
            "shadow-stack-enforced",
        ]),
        note: "read as the level return, the landing pads off",
    },
    Row {
        flag: "-fcf-protection=none",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "cet-macro",
            "cet-marked-object",
            "cet-endbr-emitted",
            "cet-marked",
            "shadow-stack-enforced",
        ]),
        note: "read as off throughout",
    },
    Row {
        flag: "-fcf-protection=check",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&[
            "cet-macro",
            "cet-marked-object",
            "cet-endbr-emitted",
            "cet-marked",
            "shadow-stack-enforced",
        ]),
        note: "read as off throughout: a link-time verification under LTO, ignored at \
               compilation, it sets none of the markings the checks read",
    },
    Row {
        flag: "-fzero-call-used-regs=used-gpr-arg",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fzero-call-used-regs=used-arg",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fzero-call-used-regs=used",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fzero-call-used-regs=all-gpr",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fzero-call-used-regs=all-gpr-arg",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fzero-call-used-regs=all-arg",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fzero-call-used-regs=all",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fzero-call-used-regs=skip",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-call-used-regs"]),
        note: ZERO_CALL_USED_REGS_VARIANT,
    },
    Row {
        flag: "-fwrapv",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["no-strict-overflow"]),
        note: "read as defined signed integer overflow",
    },
    Row {
        flag: "-fwrapv-pointer",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["no-strict-overflow"]),
        note: "reads off: the check reads integer overflow",
    },
    Row {
        flag: "-ftrapv",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["trapv-helper-called", "trapv-trapped"]),
        note: "",
    },
    Row {
        flag: "-Whardened",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["hardened-downgrade-warned"]),
        note: "",
    },
    Row {
        flag: "-fzero-init-padding-bits=union",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["zero-init-padding-bits"]),
        note: "the table's spelling, which gcc rejects",
    },
    Row {
        flag: "-Wbidi-chars=any,ucn",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["bidi-chars-any"]),
        note: "read as any",
    },
    Row {
        flag: "-Wbidi-chars=unpaired",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["bidi-chars-any"]),
        note: "reads off, which is the paired construct's answer and not this form's",
    },
    Row {
        flag: "-Wbidi-chars=unpaired,ucn",
        place: Place::Variant,
        carried: Carried::No(A_VARIANT),
        reads: Reads::Checks(&["bidi-chars-any"]),
        note: "reads off, which is the paired construct's answer and not this form's",
    },
    // Discouraged.
    Row {
        flag: "-Wl,-rpath,",
        place: Place::Discouraged,
        carried: Carried::No("discouraged by the guide"),
        reads: Reads::Checks(&["rpath-absent"]),
        note: "a weaken check: on is the absence of a run path",
    },
    // Sanitizers.
    Row {
        flag: "-fsanitize=address",
        place: Place::Sanitizer,
        carried: Carried::No(INSTRUMENTED_TEST_CODE),
        reads: Reads::None(INSTRUMENTED_TEST_CODE),
        note: "",
    },
    Row {
        flag: "-fsanitize=thread",
        place: Place::Sanitizer,
        carried: Carried::No(INSTRUMENTED_TEST_CODE),
        reads: Reads::None(INSTRUMENTED_TEST_CODE),
        note: "",
    },
    Row {
        flag: "-fsanitize=leak",
        place: Place::Sanitizer,
        carried: Carried::No(INSTRUMENTED_TEST_CODE),
        reads: Reads::None(INSTRUMENTED_TEST_CODE),
        note: "",
    },
    Row {
        flag: "-fsanitize=undefined",
        place: Place::Sanitizer,
        carried: Carried::No(INSTRUMENTED_TEST_CODE),
        reads: Reads::None("the instrumented form, for test code"),
        note: "",
    },
    Row {
        flag: "-fsanitize-minimal-runtime",
        place: Place::Sanitizer,
        carried: Carried::No(
            "a production form the guide recommends for clang in its sanitizer section, \
             outside the block the profile transcribes",
        ),
        reads: Reads::None("clang's minimal handlers are calls"),
        note: "",
    },
    Row {
        flag: "-fsanitize-trap=undefined",
        place: Place::Sanitizer,
        carried: Carried::No(
            "a production form the guide recommends in its sanitizer section, outside the \
             block the profile transcribes",
        ),
        reads: Reads::Checks(&["ubsan-trap-mode"]),
        note: "",
    },
    // Debug information, a recommendation in prose.
    Row {
        flag: "objcopy --only-keep-debug, --strip-unneeded, --add-gnu-debuglink",
        place: Place::DebugInfo,
        carried: Carried::No("a packaging step after the link, not a build flag"),
        reads: Reads::None("a packaging step after the link"),
        note: "",
    },
    // Compiling compilers.
    Row {
        flag: "--enable-default-pie",
        place: Place::Toolchain,
        carried: Carried::No("a compiler build option, not a flag of a build"),
        reads: Reads::Checks(&["pie-macro", "pie"]),
        note: "a compiler default, read under the bare profile",
    },
    Row {
        flag: "--enable-default-ssp",
        place: Place::Toolchain,
        carried: Carried::No("a compiler build option, not a flag of a build"),
        reads: Reads::Checks(&["ssp-level", "ssp-level-emitted", "canary-emitted"]),
        note: "a compiler default, read under the bare profile",
    },
    Row {
        flag: "--enable-host-pie",
        place: Place::Toolchain,
        carried: Carried::No("a compiler build option, not a flag of a build"),
        reads: Reads::None("a property of the compiler's own executables"),
        note: "",
    },
    Row {
        flag: "--enable-host-bind-now",
        place: Place::Toolchain,
        carried: Carried::No("a compiler build option, not a flag of a build"),
        reads: Reads::None("a property of the compiler's own executables"),
        note: "",
    },
    // Compiling linkers.
    Row {
        flag: "--disable-default-execstack",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::Checks(&["linker-default-noexecstack"]),
        note: "",
    },
    Row {
        flag: "--enable-warn-execstack",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::None("a linker warning on an executable-stack request"),
        note: "",
    },
    Row {
        flag: "--enable-error-execstack",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::None("a linker error on an executable-stack request"),
        note: "",
    },
    Row {
        flag: "--enable-warn-rwx-segments",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::Checks(&["rwx-segment-absent"]),
        note: "the check reads the linked program's segment flags",
    },
    Row {
        flag: "--enable-error-rwx-segments",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::Checks(&["rwx-segment-absent"]),
        note: "the check reads the segment flags the error refuses",
    },
    Row {
        flag: "--enable-relro",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::Checks(&["relro"]),
        note: "a linker default, read under the bare profile",
    },
    Row {
        flag: "--enable-textrel-check=",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::Checks(&["textrel-absent"]),
        note: "read as the artifact's freedom from text relocations",
    },
    Row {
        flag: "--enable-secureplt",
        place: Place::Toolchain,
        carried: Carried::No("a linker build option, not a flag of a build"),
        reads: Reads::None("Alpha and PowerPC only, by the guide's own description"),
        note: "",
    },
    // The appendix: considered and excluded.
    Row {
        flag: "-Wl,-z,nodump",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None(
            "excluded by the guide's appendix as a single-purpose Solaris compatibility feature",
        ),
        note: "",
    },
    Row {
        flag: "-Wl,-z,noexecheap",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None(
            "excluded by the guide's appendix as a PaX extension absent from upstream \
             toolchains",
        ),
        note: "",
    },
    Row {
        flag: "-D_LIBCPP_ASSERT",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None(
            "excluded by the guide's appendix as a deprecated spelling of libc++'s hardening",
        ),
        note: "",
    },
    Row {
        flag: "-D_LIBCPP_ENABLE_ASSERTIONS",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None(
            "excluded by the guide's appendix as a deprecated spelling of libc++'s hardening",
        ),
        note: "",
    },
    Row {
        flag: "-mshstk",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None("excluded by the guide's appendix"),
        note: "",
    },
    Row {
        flag: "-fsanitize=safe-stack",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None("excluded by the guide's appendix for its compatibility limits"),
        note: "",
    },
    Row {
        flag: "-fasynchronous-unwind-tables",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None("excluded by the guide's appendix as of no security benefit"),
        note: "",
    },
    Row {
        flag: "-fvtable-verify",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None("excluded by the guide's appendix for its overhead"),
        note: "",
    },
    Row {
        flag: "-mmitigate-rop",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None("excluded by the guide's appendix as deprecated in GCC 9.1"),
        note: "",
    },
    Row {
        flag: "CLANG_DEFAULT_PIE_ON_LINUX",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None(
            "excluded by the guide's appendix as a clang build option superseded by configuration files",
        ),
        note: "",
    },
    Row {
        flag: "-fsplit-stack",
        place: Place::Considered,
        carried: Carried::No(EXCLUDED_BY_THE_GUIDE),
        reads: Reads::None("excluded by the guide's appendix as segmented stacks for co-routines"),
        note: "",
    },
];

#[cfg(test)]
mod tests {
    use super::{ADDENDUM_WHEN, BEYOND_THE_GUIDE, Carried, INVENTORY, Place, Reads};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn both_rwx_segment_rows_name_the_check_that_reads_the_flags() {
        for flag in ["--enable-warn-rwx-segments", "--enable-error-rwx-segments"] {
            let row = INVENTORY
                .iter()
                .find(|r| r.flag == flag)
                .unwrap_or_else(|| panic!("{flag} is a row"));
            assert!(
                matches!(row.reads, Reads::Checks(&["rwx-segment-absent"])),
                "{flag} names rwx-segment-absent"
            );
        }
    }

    #[test]
    fn the_profile_is_the_carried_rows_in_order() {
        let words = |keep: &dyn Fn(Place) -> bool| -> Vec<String> {
            INVENTORY
                .iter()
                .filter(|r| keep(r.place))
                .flat_map(|r| r.flag.split_whitespace().map(str::to_owned))
                .collect()
        };
        let gate_archs: BTreeSet<&str> = crate::toolchain::TRIPLE_ARCHS
            .iter()
            .map(|(_, arch)| *arch)
            .collect();
        for arch in ["x86_64", "aarch64", "x86"] {
            assert!(
                gate_archs.contains(arch),
                "expected {arch} among TRIPLE_ARCHS's architectures, got {gate_archs:?}"
            );
        }
        for arch in gate_archs.iter().copied().chain(["riscv64"]) {
            let when = format!("for {arch}");
            let mut expected = words(&|p| p == Place::TlDr);
            expected.extend(words(
                &|p| matches!(p, Place::Addendum(ws) if ws.contains(&when.as_str())),
            ));
            expected.extend(words(&|p| p == Place::Addendum(&["for executables"])));
            assert_eq!(
                crate::report::openssf_tldr_cflags(arch),
                expected,
                "on {arch} the profile is not the guide's rows for it, in order"
            );
        }
        for row in INVENTORY {
            match row.carried {
                Carried::Base => assert_eq!(
                    row.place,
                    Place::TlDr,
                    "{} is carried as the block but stands elsewhere",
                    row.flag
                ),
                Carried::Executable => assert_eq!(
                    row.place,
                    Place::Addendum(&["for executables"]),
                    "{} is carried as the executables row but stands elsewhere",
                    row.flag
                ),
                Carried::Arch(archs) => {
                    assert!(
                        !archs.is_empty(),
                        "{} is carried for no architecture",
                        row.flag
                    );
                    let Place::Addendum(whens) = row.place else {
                        panic!("{} is carried for {archs:?} outside the addendum", row.flag);
                    };
                    let named: BTreeSet<&str> = whens
                        .iter()
                        .filter_map(|w| w.strip_prefix("for "))
                        .filter(|a| gate_archs.contains(a))
                        .collect();
                    let carried: BTreeSet<&str> = archs.iter().copied().collect();
                    assert_eq!(
                        carried, named,
                        "{} is carried for {archs:?} where the guide's addendum names {named:?}",
                        row.flag
                    );
                }
                Carried::No(reason) => {
                    assert!(
                        !reason.is_empty(),
                        "{} is not carried for no reason",
                        row.flag
                    );
                    assert_ne!(
                        row.place,
                        Place::TlDr,
                        "{} is in the block and not carried",
                        row.flag
                    );
                }
            }
        }
    }

    #[test]
    fn every_check_is_placed_once_and_every_named_check_exists() {
        let corpus: BTreeSet<&str> = crate::probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .map(|c| c.id)
            .collect();
        assert!(corpus.len() > 40, "the corpus is not being read");
        let mut placed: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for row in INVENTORY {
            if let Reads::Checks(ids) = row.reads {
                assert!(!ids.is_empty(), "{} names no check", row.flag);
                for id in ids {
                    assert!(
                        corpus.contains(id),
                        "{} names a check the corpus lacks: {id}",
                        row.flag
                    );
                    placed.entry(id).or_default().push(row.flag);
                }
            }
        }
        for id in BEYOND_THE_GUIDE {
            assert!(
                corpus.contains(id),
                "{id} is pinned beyond the guide but not shipped"
            );
            assert!(
                !placed.contains_key(id),
                "{id} is pinned beyond the guide and read by {:?}",
                placed[id]
            );
        }
        let unplaced: Vec<&str> = corpus
            .iter()
            .filter(|id| !placed.contains_key(*id) && !BEYOND_THE_GUIDE.contains(id))
            .copied()
            .collect();
        assert!(
            unplaced.is_empty(),
            "checks in no row and not pinned beyond the guide: {unplaced:?}"
        );
    }

    /// Every row is one flag, each named once; every absence gives its reason; every
    /// addendum row names a "When" cell the guide has, and every "When" cell has a row.
    #[test]
    fn every_row_is_distinct_and_every_absence_has_its_reason() {
        let mut seen = BTreeSet::new();
        for row in INVENTORY {
            assert!(!row.flag.is_empty(), "every inventory row names its flag");
            assert!(seen.insert(row.flag), "{} stands twice", row.flag);
            match row.reads {
                Reads::None(reason) => {
                    assert!(
                        !reason.is_empty(),
                        "{} is read by nothing for no reason",
                        row.flag
                    );
                }
                Reads::Checks(ids) => {
                    let distinct: BTreeSet<&str> = ids.iter().copied().collect();
                    assert_eq!(distinct.len(), ids.len(), "{} repeats a check", row.flag);
                }
            }
            if let Place::Addendum(whens) = row.place {
                assert!(!whens.is_empty(), "{} is in no addendum row", row.flag);
                for when in whens {
                    assert!(
                        ADDENDUM_WHEN.contains(when),
                        "{} names an addendum row the guide lacks: {when}",
                        row.flag
                    );
                }
            }
        }
        for when in ADDENDUM_WHEN {
            assert!(
                INVENTORY
                    .iter()
                    .any(|r| matches!(r.place, Place::Addendum(ws) if ws.contains(when))),
                "the addendum row {when:?} has no row here"
            );
        }
    }
}
