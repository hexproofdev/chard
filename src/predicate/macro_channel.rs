// SPDX-License-Identifier: BSD-3-Clause

//! The predicates for the macro-channel checks, one entry per check id.

use std::sync::LazyLock;

use super::{Clause, Cmp, Conclusion, Cond, Entry, LevelOf, Predicate, Term};

/// The macro-channel checks' predicates, keyed by check id.
#[must_use]
pub fn table() -> &'static [Entry] {
    &[
        ("ssp-level", ssp_level),
        ("fortify-requested", fortify_requested),
        ("fortify-effective", fortify_effective),
        ("pie-macro", pie_macro),
        ("pic-macro", pic_macro),
        ("cet-macro", cet_macro),
        ("gcs-macro", gcs_macro),
        ("branch-protection-macro", branch_protection_macro),
        ("optimization-enabled", optimization_enabled),
        ("cxx-hardening-requested", cxx_hardening_requested),
        ("exceptions-macro", exceptions_macro),
    ]
}

fn m(name: &str) -> Term {
    Term::Macro(name.to_owned())
}

fn defined(name: &str) -> Cond {
    Cond::Defined(m(name))
}

fn missing(name: &str) -> Cond {
    Cond::Missing(m(name))
}

fn int(name: &str, cmp: Cmp, bound: i64) -> Cond {
    Cond::Int(m(name), cmp, bound)
}

fn positive(name: &str) -> Cond {
    int(name, Cmp::Gt, 0)
}

/// The macro has an integer reading above `i64::MIN`: any integer the language reads but
/// one. `-9223372036854775808` reads as `i64::MIN` here and as an unsigned literal in C's
/// `#if`, where its magnitude does not fit `intmax_t`, so glibc's `_FORTIFY_SOURCE > 0`
/// holds of it and the language's `gt 0` does not; leaving that one value to
/// [`unreadable`] withholds where the two would disagree. A reader of the published
/// predicate that holds integers to fewer than 64 bits withholds more than this one, never
/// less.
fn readable(name: &str) -> Cond {
    int(name, Cmp::Gt, i64::MIN)
}

/// The macro is defined and its text has no integer reading: `(3)`, `3L`, `2UL`, `010`, a
/// name, or nothing. `int` is false over text it cannot read, so without a clause over this
/// a request spelt `-D_FORTIFY_SOURCE=(3)` would fall past `fortify-requested`'s
/// `requested` to `@otherwise` and read `off` beside a settled level of 3. A value the
/// language cannot read is not evidence of absence, so every predicate that reads a macro
/// as an integer has a clause over this, concluding `indeterminate`, ahead of any clause
/// whose conclusion depends on what C makes of the text.
fn unreadable(name: &str) -> Cond {
    Cond::All(vec![defined(name), Cond::NoneOf(vec![readable(name)])])
}

/// The clause that withholds under `id` where [`unreadable`] holds of `name`; `what` names
/// the reading the text was to supply.
fn withhold_unreadable(id: &str, name: &str, what: &str) -> Clause {
    clause(
        id,
        unreadable(name),
        Conclusion::Indeterminate,
        &format!(
            "{name} is defined with text chard's integer reading does not read, so {what} \
             cannot be read from it and the verdict is withheld"
        ),
    )
}

fn word(w: &str) -> Conclusion {
    Conclusion::Present(LevelOf::Word(w.to_owned()))
}

fn value_of(name: &str) -> Conclusion {
    Conclusion::Present(LevelOf::Value(m(name)))
}

fn clause(id: &str, when: Cond, then: Conclusion, because: &str) -> Clause {
    Clause {
        id: id.to_owned(),
        when,
        then,
        because: because.to_owned(),
    }
}

fn macros_only(clauses: Vec<Clause>, otherwise: Conclusion) -> Predicate {
    Predicate {
        tables: Vec::new(),
        clauses,
        otherwise,
    }
}

/// Checked strongest first: `-fstack-protector-all` defines `__SSP_ALL__`, `-strong`
/// `__SSP_STRONG__`, plain `-fstack-protector` `__SSP__`, and gcc's
/// `-fstack-protector-explicit` `__SSP_EXPLICIT__`.
static SSP_LEVEL: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![
            clause(
                "all",
                defined("__SSP_ALL__"),
                word("all"),
                "-fstack-protector-all defines __SSP_ALL__, the strongest level, checked first",
            ),
            clause(
                "strong",
                defined("__SSP_STRONG__"),
                word("strong"),
                "-fstack-protector-strong defines __SSP_STRONG__",
            ),
            clause(
                "basic",
                defined("__SSP__"),
                word("basic"),
                "plain -fstack-protector defines __SSP__",
            ),
            clause(
                "explicit",
                defined("__SSP_EXPLICIT__"),
                word("explicit"),
                "gcc's -fstack-protector-explicit defines __SSP_EXPLICIT__ and instruments \
                 only functions marked stack_protect, the weakest level",
            ),
        ],
        Conclusion::Absent,
    )
});

/// The `ssp-level` predicate.
#[must_use]
pub fn ssp_level() -> &'static Predicate {
    &SSP_LEVEL
}

/// Requested is not the same as in force. glibc's checks live in inline wrappers that
/// exist only once the optimizer runs, so `-D_FORTIFY_SOURCE=3 -O0` leaves the macro at 3
/// while `__USE_FORTIFY_LEVEL` drops to 0 and nothing is checked. `on` there would be a
/// false positive and `off` wrong too, since the flag was passed, so the reading is
/// withheld and `fortify-effective` and the runtime enforcement checks carry the result.
static FORTIFY_REQUESTED: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![
            withhold_unreadable(
                "requested-unreadable",
                "_FORTIFY_SOURCE",
                "the level requested",
            ),
            clause(
                "requested-without-optimization",
                Cond::All(vec![
                    positive("_FORTIFY_SOURCE"),
                    missing("_USE_FORTIFY_LEVEL"),
                    missing("__OPTIMIZE__"),
                ]),
                Conclusion::Indeterminate,
                "a level was requested with no optimization",
            ),
            clause(
                "requested",
                positive("_FORTIFY_SOURCE"),
                value_of("_FORTIFY_SOURCE"),
                "_FORTIFY_SOURCE above zero is a request at that level",
            ),
        ],
        Conclusion::Absent,
    )
});

/// The `fortify-requested` predicate.
#[must_use]
pub fn fortify_requested() -> &'static Predicate {
    &FORTIFY_REQUESTED
}

/// The id of `fortify-effective`'s clause that identifies fortify-headers at a request of
/// 2 or below.
pub const FORTIFY_HEADERS_CLAUSE: &str = "fortify-headers";

/// The id of `fortify-effective`'s clause that identifies fortify-headers at a request
/// above 2, where its `__bos` is `__builtin_dynamic_object_size`.
pub const FORTIFY_HEADERS_DYNAMIC_CLAUSE: &str = "fortify-headers-dynamic-request";

/// The id of `fortify-effective`'s clause that withholds under fortify-headers at a request
/// with no integer reading (`(3)`, `3L`, `-9223372036854775808`, which C reads as above 2)
/// or none at all, since the request selects its builtin.
pub const FORTIFY_HEADERS_UNREAD_CLAUSE: &str = "fortify-headers-unread-request";

/// The clauses of `fortify-effective` that read fortify-headers' level, which
/// `composite::fortify_headers_reading` reads from a published reading's `clause`.
pub const FORTIFY_HEADERS_CLAUSES: [&str; 2] =
    [FORTIFY_HEADERS_DYNAMIC_CLAUSE, FORTIFY_HEADERS_CLAUSE];

/// fortify-headers identified itself: the self-report's summary or the raw include guard.
fn fortify_headers() -> Cond {
    Cond::Any(vec![
        Cond::Eq(m("_FORTIFY_IMPL"), "fortify-headers".to_owned()),
        defined("_FORTIFY_HEADERS_H"),
    ])
}

/// The level the C library settled on, which can be lower than the one requested.
static FORTIFY_EFFECTIVE: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![
            clause(
                "glibc-zero",
                int("__USE_FORTIFY_LEVEL", Cmp::Eq, 0),
                Conclusion::Absent,
                "glibc's <features.h> settled __USE_FORTIFY_LEVEL at 0",
            ),
            clause(
                "glibc-level",
                readable("__USE_FORTIFY_LEVEL"),
                value_of("__USE_FORTIFY_LEVEL"),
                "__USE_FORTIFY_LEVEL is the level glibc's <features.h> settled on",
            ),
            withhold_unreadable(
                "glibc-unreadable",
                "__USE_FORTIFY_LEVEL",
                "the level glibc settled on",
            ),
            clause(
                "apple-zero",
                int("_USE_FORTIFY_LEVEL", Cmp::Eq, 0),
                Conclusion::Absent,
                "Apple's <secure/_common.h> settled _USE_FORTIFY_LEVEL at 0",
            ),
            clause(
                "apple-level",
                readable("_USE_FORTIFY_LEVEL"),
                value_of("_USE_FORTIFY_LEVEL"),
                "_USE_FORTIFY_LEVEL is the level Apple's <secure/_common.h> settled on, clamped at 2",
            ),
            withhold_unreadable(
                "apple-unreadable",
                "_USE_FORTIFY_LEVEL",
                "the level Apple's <secure/_common.h> settled on",
            ),
            withhold_unreadable(
                "freebsd-release-unreadable",
                "__FreeBSD__",
                "the FreeBSD release, which decides whether its headers carry <ssp/ssp.h>",
            ),
            clause(
                "freebsd-zero",
                Cond::All(vec![
                    defined("__FreeBSD__"),
                    int("__SSP_FORTIFY_LEVEL", Cmp::Eq, 0),
                ]),
                Conclusion::Absent,
                "FreeBSD's <ssp/ssp.h> settled __SSP_FORTIFY_LEVEL at 0",
            ),
            clause(
                "freebsd-unoptimized",
                Cond::All(vec![
                    defined("__FreeBSD__"),
                    int("__SSP_FORTIFY_LEVEL", Cmp::Gt, 0),
                    missing("__OPTIMIZE__"),
                ]),
                Conclusion::Indeterminate,
                "FreeBSD's <ssp/ssp.h> settled __SSP_FORTIFY_LEVEL above 0 without optimization",
            ),
            clause(
                "freebsd-level",
                Cond::All(vec![
                    defined("__FreeBSD__"),
                    readable("__SSP_FORTIFY_LEVEL"),
                ]),
                value_of("__SSP_FORTIFY_LEVEL"),
                "__SSP_FORTIFY_LEVEL is the level FreeBSD's <ssp/ssp.h> settled on, clamped at 2",
            ),
            clause(
                "freebsd-unreadable",
                Cond::All(vec![
                    defined("__FreeBSD__"),
                    unreadable("__SSP_FORTIFY_LEVEL"),
                ]),
                Conclusion::Indeterminate,
                "__SSP_FORTIFY_LEVEL is defined with text chard's integer reading does not \
                 read",
            ),
            clause(
                FORTIFY_HEADERS_DYNAMIC_CLAUSE,
                Cond::All(vec![fortify_headers(), int("_FORTIFY_SOURCE", Cmp::Gt, 2)]),
                word("1"),
                "fortify-headers at a request above 2",
            ),
            clause(
                FORTIFY_HEADERS_CLAUSE,
                Cond::All(vec![
                    fortify_headers(),
                    readable("_FORTIFY_SOURCE"),
                    int("_FORTIFY_SOURCE", Cmp::Le, 2),
                ]),
                word("1"),
                "fortify-headers: its checks use whole-object __builtin_object_size only and never subobject bounds",
            ),
            clause(
                FORTIFY_HEADERS_UNREAD_CLAUSE,
                fortify_headers(),
                Conclusion::Indeterminate,
                "fortify-headers identified itself and _FORTIFY_SOURCE is undefined or unreadable",
            ),
            clause(
                "not-requested",
                Cond::Any(vec![
                    missing("_FORTIFY_SOURCE"),
                    Cond::All(vec![
                        readable("_FORTIFY_SOURCE"),
                        int("_FORTIFY_SOURCE", Cmp::Le, 0),
                    ]),
                ]),
                Conclusion::Absent,
                "_FORTIFY_SOURCE is undefined",
            ),
            clause(
                "freebsd-without-ssp",
                Cond::All(vec![
                    defined("_FORTIFY_SOURCE"),
                    int("__FreeBSD__", Cmp::Lt, 15),
                    missing("__SSP_FORTIFY_LEVEL"),
                ]),
                Conclusion::Absent,
                "FreeBSD before 15 ships no <ssp/ssp.h>",
            ),
            clause(
                "requested-without-optimization",
                Cond::All(vec![defined("_FORTIFY_SOURCE"), missing("__OPTIMIZE__")]),
                Conclusion::Absent,
                "_FORTIFY_SOURCE is defined without optimization",
            ),
            withhold_unreadable(
                "requested-unreadable",
                "_FORTIFY_SOURCE",
                "whether a level was requested",
            ),
        ],
        // Fortify was requested and optimization is on, and still nothing identified
        // itself: a fifth C library, or headers that were never reached.
        Conclusion::Indeterminate,
    )
});

/// The `fortify-effective` predicate.
#[must_use]
pub fn fortify_effective() -> &'static Predicate {
    &FORTIFY_EFFECTIVE
}

/// `__PIE__` or `__PIC__`: a code-model selector whose value is published as information.
fn code_model(name: &str, because: &str) -> Predicate {
    macros_only(
        vec![
            withhold_unreadable("unreadable", name, "the code model"),
            clause("set", positive(name), value_of(name), because),
        ],
        Conclusion::Absent,
    )
}

static PIE_MACRO: LazyLock<Predicate> =
    LazyLock::new(|| code_model("__PIE__", "__PIE__ is defined with a value above zero"));

/// The `pie-macro` predicate.
#[must_use]
pub fn pie_macro() -> &'static Predicate {
    &PIE_MACRO
}

/// The sentence names `__PIC__` alone, the one macro the clause reads. `evidence.macros`
/// carries both names, so a reader tells position independence arriving through `-fPIE`,
/// which defines both, from a PIC default that leaves `__PIE__` undefined there.
static PIC_MACRO: LazyLock<Predicate> =
    LazyLock::new(|| code_model("__PIC__", "__PIC__ is defined with a value above zero"));

/// The `pic-macro` predicate.
#[must_use]
pub fn pic_macro() -> &'static Predicate {
    &PIC_MACRO
}

static CET_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![
            clause(
                "full",
                int("__CET__", Cmp::Eq, 3),
                word("full"),
                "__CET__ is a bitmask, 1 for branch tracking and 2 for the shadow stack",
            ),
            clause(
                "return",
                int("__CET__", Cmp::Eq, 2),
                word("return"),
                "__CET__ is 2, the shadow stack alone",
            ),
            clause(
                "branch",
                int("__CET__", Cmp::Eq, 1),
                word("branch"),
                "__CET__ is 1, branch tracking alone",
            ),
            clause(
                "none",
                int("__CET__", Cmp::Eq, 0),
                Conclusion::Absent,
                "__CET__ is 0, neither bit",
            ),
            clause(
                "unrecognised",
                defined("__CET__"),
                Conclusion::Indeterminate,
                "__CET__ is defined with a value other than 0, 1, 2 or 3",
            ),
        ],
        Conclusion::Absent,
    )
});

/// The `cet-macro` predicate.
#[must_use]
pub fn cet_macro() -> &'static Predicate {
    &CET_MACRO
}

/// Guarded Control Stack: a check of its own rather than a third bit of
/// `branch-protection-macro`, because a toolchain too old to know `gcs` still answers for
/// `bti` and `pac-ret`, and folding it in would make the pair's `full` unreachable on every
/// compiler that predates GCS. `-mbranch-protection=standard` sets it too on compilers that
/// have it.
static GCS_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![
            withhold_unreadable(
                "unreadable",
                "__ARM_FEATURE_GCS_DEFAULT",
                "whether GCS is on",
            ),
            clause(
                "set",
                positive("__ARM_FEATURE_GCS_DEFAULT"),
                Conclusion::Present(LevelOf::None),
                "__ARM_FEATURE_GCS_DEFAULT is defined with a value above zero",
            ),
        ],
        Conclusion::Absent,
    )
});

/// The `gcs-macro` predicate.
#[must_use]
pub fn gcs_macro() -> &'static Predicate {
    &GCS_MACRO
}

/// aarch64's answer to CET, and the same shape: two independent bits, which
/// `-mbranch-protection=standard` requests together. BTI guards indirect branches and PAC
/// signs return addresses, and the levels are `cet-macro`'s: a toolchain can serve one and
/// not the other, and `branch` and `return` name which survived. Measured on Apple
/// clang 21 / arm64 under `-mbranch-protection=standard`: both macros read `1`.
static BRANCH_PROTECTION_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    let bti = || positive("__ARM_FEATURE_BTI_DEFAULT");
    // PAC's macro selects a key, 1 for A and 2 for B, so any value above zero signs return
    // addresses; testing for 1 would read a b-key build as unprotected.
    let pac = || positive("__ARM_FEATURE_PAC_DEFAULT");
    macros_only(
        vec![
            clause(
                "unreadable",
                Cond::Any(vec![
                    unreadable("__ARM_FEATURE_BTI_DEFAULT"),
                    unreadable("__ARM_FEATURE_PAC_DEFAULT"),
                ]),
                Conclusion::Indeterminate,
                "__ARM_FEATURE_BTI_DEFAULT or __ARM_FEATURE_PAC_DEFAULT is defined with text chard's integer reading does not read",
            ),
            clause(
                "full",
                Cond::All(vec![bti(), pac()]),
                word("full"),
                "BTI guards indirect branches and PAC signs return addresses",
            ),
            clause("branch", bti(), word("branch"), "BTI is on and PAC is not"),
            clause(
                "return",
                pac(),
                word("return"),
                "PAC is on, with any key, and BTI is not",
            ),
        ],
        Conclusion::Absent,
    )
});

/// The `branch-protection-macro` predicate.
#[must_use]
pub fn branch_protection_macro() -> &'static Predicate {
    &BRANCH_PROTECTION_MACRO
}

static OPTIMIZATION_ENABLED: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![clause(
            "optimized",
            defined("__OPTIMIZE__"),
            Conclusion::Present(LevelOf::None),
            "__OPTIMIZE__ is defined at any -O above 0",
        )],
        Conclusion::Absent,
    )
});

/// The `optimization-enabled` predicate.
#[must_use]
pub fn optimization_enabled() -> &'static Predicate {
    &OPTIMIZATION_ENABLED
}

/// `-fexceptions` in a C translation unit defines `__EXCEPTIONS` to 1: a sorted diff of
/// `-dM -E` with and without the flag is that one line on gcc 16.1.1 and clang 22.1.8 (the
/// detection recipe `fexceptions-c-macro`). The flag is not the only way there. On gcc
/// 13.3.0, 15.2.0 and 16.1.1 `-fnon-call-exceptions` implies `-fexceptions` and defines the
/// macro and emits the table with it; on gcc 11.4.0 and on clang 14.0.0, 18.1.3, 22.1.8 and
/// 23.1.2 it does neither in C (measured 2026-10-01 over `probes/exceptions.c` at `-O2` on
/// Ubuntu 22.04, Ubuntu 24.04, Alpine and Fedora 44, all x86_64). clang's
/// `-fexceptions -fignore-exceptions` defines the macro and emits no table on the same
/// four clang versions, so the macro cannot see that form and `except-table-emitted` can;
/// `tests/inert_flags.rs` holds the table's reading of it. In C++ the macro is defined by
/// default and `-fno-exceptions` removes it, so this reading is right only on a C probe,
/// which `probes/exceptions.c` is.
static EXCEPTIONS_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![
            withhold_unreadable("unreadable", "__EXCEPTIONS", "whether exceptions are on"),
            clause(
                "set",
                positive("__EXCEPTIONS"),
                Conclusion::Present(LevelOf::None),
                "__EXCEPTIONS is defined with a value above zero",
            ),
        ],
        Conclusion::Absent,
    )
});

/// The `exceptions-macro` predicate.
#[must_use]
pub fn exceptions_macro() -> &'static Predicate {
    &EXCEPTIONS_MACRO
}

/// Which C++ hardening was asked for, and of which standard library.
// `c-int _LIBCPP_HARDENING_MODE` follows the mode's text as a macro name, and the
// published filter keeps libc++'s own mode constants.
static CXX_HARDENING_REQUESTED: LazyLock<Predicate> = LazyLock::new(|| {
    let stdlib = |name: &str| Cond::Eq(Term::CxxStdlib, name.to_owned());
    let mode = |n: i64| {
        Cond::All(vec![
            stdlib("libc++"),
            Cond::Int(Term::CInt("_LIBCPP_HARDENING_MODE".to_owned()), Cmp::Eq, n),
        ])
    };
    macros_only(
        vec![
            clause(
                "libstdcxx-assertions",
                Cond::All(vec![stdlib("libstdc++"), defined("_GLIBCXX_ASSERTIONS")]),
                Conclusion::Present(LevelOf::None),
                "libstdc++ with _GLIBCXX_ASSERTIONS defined",
            ),
            clause(
                "libstdcxx-no-assertions",
                stdlib("libstdc++"),
                Conclusion::Absent,
                "libstdc++ without _GLIBCXX_ASSERTIONS",
            ),
            clause(
                "libcxx-no-mode",
                Cond::All(vec![stdlib("libc++"), missing("_LIBCPP_HARDENING_MODE")]),
                Conclusion::Absent,
                "libc++ with no _LIBCPP_HARDENING_MODE",
            ),
            clause(
                "libcxx-none",
                mode(2),
                Conclusion::Absent,
                "libc++ in hardening mode none, (1 << 1)",
            ),
            clause(
                "libcxx-fast",
                mode(4),
                word("fast"),
                "libc++ in hardening mode fast, (1 << 2)",
            ),
            clause(
                "libcxx-debug",
                mode(8),
                word("debug"),
                "libc++ in hardening mode debug",
            ),
            clause(
                "libcxx-extensive",
                mode(16),
                word("extensive"),
                "libc++ in hardening mode extensive",
            ),
            clause(
                "libcxx-unrecognised",
                stdlib("libc++"),
                Conclusion::Indeterminate,
                "unrecognised libc++ hardening mode",
            ),
        ],
        // No standard library identified itself. A C++ build always has one, so this is a
        // build whose headers were never reached or a library neither macro names.
        Conclusion::Indeterminate,
    )
});

/// The `cxx-hardening-requested` predicate.
#[must_use]
pub fn cxx_hardening_requested() -> &'static Predicate {
    &CXX_HARDENING_REQUESTED
}
