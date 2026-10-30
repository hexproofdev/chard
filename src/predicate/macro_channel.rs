// SPDX-License-Identifier: BSD-3-Clause

//! The predicates for the macro-channel checks, one entry per check id.
//!
//! Each entry pairs a check id with a function returning a predicate built once behind a
//! `std::sync::LazyLock`, so the value `predicate::for_check` hands out is the value a
//! report serializes. The table lives in its own file so that work on the two channels
//! edits disjoint files.
//!
//! Each predicate is the decoder of its check: `probe::Check::decode` evaluates it over
//! the measured macro map, and nothing else on this channel reads macros. A clause's
//! `because` carries the reasoning of its branch, shortened, and
//! the longer argument, with the measurements behind it, is on the predicate's static.
//! `tests/predicates.rs` holds every clause reached and the published filter sufficient.
//!
//! Three spellings recur. `int [macro NAME, gt, 0]` is a macro whose integer reading is
//! above zero, [`readable`] is a macro whose integer reading is above `i64::MIN`, which
//! every reading the language makes is but for the one decimal C types as unsigned, and
//! [`unreadable`] is a macro defined with text that is not readable. Every predicate that
//! reads a macro as an integer withholds on the third under a clause of its own, ahead of
//! any clause that could read such text as no request.

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

/// The macro is defined and its text has no integer reading: `(3)`, `3L`, `2UL`, a name,
/// or nothing. `int` is false over text it cannot read, so without a clause over this a
/// request spelt `-D_FORTIFY_SOURCE=(3)` fell past `requested` to `@otherwise` and
/// `fortify-requested` published `off` beside a `__USE_FORTIFY_LEVEL` of 3 (measured on
/// Fedora 44 x86_64, gcc 16.1.1, glibc 2.43, `--profile explicit` with
/// `-O2 -D_FORTIFY_SOURCE=(3)`; on Darwin arm64 under Apple clang 21, `(3)`, `3L` and
/// `2UL` each read `off` beside `_USE_FORTIFY_LEVEL` 2). A value the language cannot read
/// is not evidence of absence, so every predicate that reads a macro as an integer has a
/// clause over this, concluding `indeterminate`, ahead of any clause that could read the
/// text as no request. `tests/predicates.rs` holds that over every macro predicate: a
/// reading that is `present` or `absent` never read such a macro.
///
/// The preprocessor evaluates `(3)`, `3L` and `2UL` to the number, and chard does not: the
/// integer reading takes a decimal and nothing else, and evaluating C expressions is not
/// a reader this project trusts itself to write. So a request spelt one of these ways is
/// withheld for good, as is a request spelt as a name, which C's `#if` reads as 0 where
/// the name is undefined; the level the library settled on is read from its own level
/// macro by `fortify-effective`, whatever the request's spelling. That is the accepted
/// cost of the rule.
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
/// defines `__SSP_STRONG__`, plain `-fstack-protector` defines `__SSP__`, and gcc's
/// `-fstack-protector-explicit` defines `__SSP_EXPLICIT__`.
///
/// `explicit` is the bottom rung of `probe::SSP_LEVELS`: gcc instruments only functions
/// marked `__attribute__((stack_protect))` under it, and a marked function is instrumented
/// at every other level too, so its protected set is contained in plain
/// `-fstack-protector`'s. A clause reads the macro, and the flag reads `partial` at
/// `explicit`. Without it the flag would read `absent`, and a toolchain that enables the
/// protector for opted-in functions would publish `off` with no level. Measured 2026-10-05
/// on Fedora 44 x86_64: gcc 16.1.1 `-dM -E` under `-fstack-protector-explicit` defines
/// `__SSP_EXPLICIT__ 4` and none of the other three, and clang 22.1.8 rejects the flag
/// (`unknown argument`). A function marked `stack_protect` with no array and no address taken
/// refers to `__stack_chk_fail` under `-explicit`, plain `-fstack-protector` and `-strong`, and
/// not under `-fno-stack-protector`, at `-O0` and `-O2` on the same gcc. The artifact readers
/// in the `stack-protector` group read `off` for that build, since no probe function opts in;
/// `report::OPT_IN_LEVELS` says why that is not a disagreement, and why the group is not
/// corroborated by it.
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
///
/// That reasoning is glibc's, and it was once applied to everyone. Apple's wrappers carry
/// no `__OPTIMIZE__` term (`<_string.h>` reaches `<secure/_string.h>` on
/// `__GNUC__ && _FORTIFY_SOURCE > 0 && !__cplusplus`), so an unoptimized Apple build has
/// fortify in force. Measured on Darwin: `bare` read `indeterminate` here while the probes
/// trapped in `__chk_fail_overflow` in the same run. `_USE_FORTIFY_LEVEL` is the settled
/// level from Apple's own headers, so an implementation that does not gate on
/// optimization identifies itself before the first clause can withhold.
///
/// glibc reads a value at or below zero as no request (`<features.h>` tests
/// `_FORTIFY_SOURCE > 0`), and so does the `requested` clause. Before that guard,
/// `-D_FORTIFY_SOURCE=-1` read `present` at level `-1`. A request the language cannot
/// read as a number, `(3)`, `3L` or `2UL`, is withheld first ([`unreadable`]): the
/// preprocessor evaluates each of them, so the library may well be at the level asked,
/// and `fortify-effective` says whether it is.
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
                "a level was requested with no optimization, so the checks glibc and \
                 fortify-headers instantiate do not exist and the request is inert; Apple's \
                 _USE_FORTIFY_LEVEL, which does not gate on optimization, is not defined \
                 here to say otherwise, and where FreeBSD's wrappers instantiate without \
                 optimization under clang they check nothing there",
            ),
            clause(
                "requested",
                positive("_FORTIFY_SOURCE"),
                value_of("_FORTIFY_SOURCE"),
                "_FORTIFY_SOURCE above zero is a request at that level; glibc reads a value \
                 at or below zero as no request",
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
///
/// The ladder is the clause order: each rung answers only when every rung above it was
/// silent.
///
/// Three implementations, so three observables. glibc computes `__USE_FORTIFY_LEVEL` in
/// `<features.h>` and silently downgrades a level it cannot serve, which is why this check
/// is separate from `fortify-requested`. Apple's parallel `_USE_FORTIFY_LEVEL`, from
/// `<secure/_common.h>`, answers for the same reason; it is a real macro, so the
/// preprocessor dump carries it on a platform whose artifacts chard cannot read, and it is
/// clamped at 2, since `<secure/_common.h>` maps every request above 1 to 2 and implements
/// no level 3. Reporting 2 for a requested 3 answers this check's question, which is what
/// is in force.
///
/// fortify-headers, Alpine's and Chimera's implementation, publishes no level macro. It
/// publishes its include guard, defined inside `#if defined(_FORTIFY_SOURCE) &&
/// _FORTIFY_SOURCE > 0 && defined(__OPTIMIZE__) && __OPTIMIZE__ > 0`, so
/// `_FORTIFY_HEADERS_H` set means the wrappers instantiated in this translation unit, the
/// claim `__USE_FORTIFY_LEVEL > 0` makes for glibc. `chard_selfreport.h` condenses the
/// guard into `_FORTIFY_IMPL`, and `gather` prefers the compiled-artifact map over the
/// `-dM -E` dump wherever one exists, so on a real Alpine measurement `_FORTIFY_IMPL` is
/// present and `_FORTIFY_HEADERS_H` is not; reading only the raw guard found nothing on
/// the system it was written for. Both keys are consulted.
///
/// The level for fortify-headers is not the level requested. Its wrappers ask
/// `__bos(p, 0)` (whole object) in 63 of their 65 uses, `__bos(p, 2)` in the other two and
/// `__bos(p, 1)` in none, so a subobject is never distinguished from its enclosing object
/// and levels 1 and 2 compile to identical code. Level 2 on the ratchet is defined by that
/// distinction, so fortify-headers is at level 1 whatever was asked. A request above 2
/// switches `__bos` to `__builtin_dynamic_object_size` where the compiler has the builtin
/// (fortify-headers 3.0.2, `fortify-headers.h`), which is orthogonal to the subobject rung
/// rather than above it; `fortify-enforced-dynamic` measures that capability on its own.
/// So the clause is split by the request, and each says what holds at it. At 2 or below
/// the checks use `__builtin_object_size` only. Above 2 they may not, and a reason saying
/// they did was false beside `fortify-enforced-dynamic` `on` in the same report (Alpine
/// 3.24 and edge, Chimera). Nor does the request alone make them dynamic: Alpine 3.21's
/// `openssf-tldr` cells read that check `unsupported` under gcc 14.2, which has the
/// builtin, so the reason says where dynamic sizing holds and leaves whether it does to
/// that check. The level is 1 in both, since one integer cannot say "dynamic,
/// whole-object", and `fortify_ratchet` carries the two axes apart.
/// A request with no integer reading selects a builtin chard cannot name, and since the
/// split reads the request, it is withheld like every other unreadable integer; so is a
/// mark beside no request, which no real build produces (the guard needs a request above
/// 0) and which `not-requested` below would read as absence. Before the split the one
/// clause read no request and published level 1 in both.
///
/// Where nothing identified itself, glibc alone would settle it: its `__USE_FORTIFY_LEVEL`
/// is defined unconditionally, so its absence means the headers were never preprocessed.
/// fortify-headers leaves no mark when inactive, and an `indeterminate` here lands on the
/// negative control, the arm that has to demonstrate absence, so the check collapsed to
/// `probe-invalid` on every musl system. Measured on Alpine: the positive arm read
/// `present` and the negative `indeterminate`. Two conditions decide it without appealing
/// to a libc's identity: fortify needs `_FORTIFY_SOURCE` above zero, and, for the
/// implementations that reach the last rungs, optimization. Apple gates on neither, and
/// its probes trap under a build with no `-O`; it stays correct because it identifies
/// itself through its own level macro first. A fifth implementation that neither gates on
/// optimization nor sets a level macro would need the treatment Apple got.
///
/// Each level macro has a rung for text that has no integer reading ([`unreadable`]),
/// below its own two, and `_FORTIFY_SOURCE` has one ahead of `not-requested`: a request
/// spelt `(3)` is a request, and reading it as none published `absent` where no
/// implementation had identified itself.
///
/// FreeBSD is the fourth implementation, and the ladder reads it from two macros, each
/// clause requiring the platform macro `__FreeBSD__` beside the level one, as the header's
/// `_FORTIFY_IMPL` arm does, so another library spelling the same level macro is not read
/// as FreeBSD's. `<ssp/ssp.h>`, which `<string.h>` and the other wrapped headers reach only
/// under `_FORTIFY_SOURCE > 0`, settles `__SSP_FORTIFY_LEVEL` itself: 1 for a request of 1,
/// 2 for any request above 1 (it implements no level 3, so the clamp is Apple's), and 0
/// where its wrappers do not instantiate, which its own `#if` admits for a C++ translation
/// unit and for a build without `__OPTIMIZE__` under a compiler other than clang (the C++
/// case measured, the other read from the header: the guests carry clang only). Under clang
/// the wrappers instantiate at every optimization level, and without optimization they
/// check nothing: their `__builtin_object_size` queries answer unknown there. Measured on
/// FreeBSD 15.1 amd64 (clang 19.1.7): at -O0 with a request of 2 the known-object overrun
/// survived with `__memcpy_chk` referenced, while at -O2 every request from 1 up aborted.
/// So the settled level is read only beside `__OPTIMIZE__`, and an unoptimized build is
/// withheld rather than read as the header's level: `absent` would be a claim the macro
/// channel cannot make about a wrapper that was instantiated, and `present` the inert form
/// `tests/inert_flags.rs` exists to refuse. A FreeBSD below 15 whose headers reached a
/// request and defined no level is a release with no `<ssp/ssp.h>` (measured on 14.5: no
/// /usr/include/ssp/, every rung silent at every level), a library known to have no
/// implementation; the boundary, 15, is the first release whose headers carry it, read from
/// the headers 15.1 ships and not measured on 15.0. A 15 or later with no level defined
/// falls through withheld, as a third library would. What the settled 2 bounds is left to
/// the two level-2 rungs: `<ssp/string.h>`'s wrappers for the `strcpy` and `memcpy` families
/// size the destination as a whole object (`__ssp_bos0`), while `strlcpy`, `strlcat` and
/// `<ssp/stdio.h>`'s wrappers ask the subobject bound at level 2 (`__ssp_bos`), read from
/// the headers 15.1 ships.
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
                "__USE_FORTIFY_LEVEL is the level glibc's <features.h> settled on, which can \
                 be lower than the one requested",
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
                "_USE_FORTIFY_LEVEL is the level Apple's <secure/_common.h> settled on, \
                 clamped at 2 since it implements no level 3",
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
                "FreeBSD's <ssp/ssp.h> settled __SSP_FORTIFY_LEVEL at 0: a request reached it \
                 and its wrappers did not instantiate, which its #if admits for a C++ \
                 translation unit or a build without __OPTIMIZE__ under a compiler other \
                 than clang",
            ),
            clause(
                "freebsd-unoptimized",
                Cond::All(vec![
                    defined("__FreeBSD__"),
                    int("__SSP_FORTIFY_LEVEL", Cmp::Gt, 0),
                    missing("__OPTIMIZE__"),
                ]),
                Conclusion::Indeterminate,
                "FreeBSD's <ssp/ssp.h> settled __SSP_FORTIFY_LEVEL above 0 without \
                 optimization, which clang allows. Its wrappers check nothing there: their \
                 size queries answer unknown, and on 15.1 the known-object overrun survived \
                 at -O0 with __memcpy_chk referenced. The settled level is not the level in \
                 force",
            ),
            clause(
                "freebsd-level",
                Cond::All(vec![
                    defined("__FreeBSD__"),
                    readable("__SSP_FORTIFY_LEVEL"),
                ]),
                value_of("__SSP_FORTIFY_LEVEL"),
                "__SSP_FORTIFY_LEVEL is the level FreeBSD's <ssp/ssp.h> settled on, clamped \
                 at 2 since it implements no level 3. At 2 its strlcpy, strlcat and stdio \
                 wrappers ask the subobject bound; its strcpy and memcpy wrappers ask the \
                 whole object",
            ),
            clause(
                "freebsd-unreadable",
                Cond::All(vec![
                    defined("__FreeBSD__"),
                    unreadable("__SSP_FORTIFY_LEVEL"),
                ]),
                Conclusion::Indeterminate,
                "__SSP_FORTIFY_LEVEL is defined with text chard's integer reading does not \
                 read, so the level FreeBSD's <ssp/ssp.h> settled on cannot be read from it \
                 and the verdict is withheld",
            ),
            clause(
                FORTIFY_HEADERS_DYNAMIC_CLAUSE,
                Cond::All(vec![fortify_headers(), int("_FORTIFY_SOURCE", Cmp::Gt, 2)]),
                word("1"),
                "fortify-headers at a request above 2: its checks never ask a subobject's \
                 bounds, so the enforced level is 1, since level 2 is defined by subobject \
                 bounds; at this request they size objects with \
                 __builtin_dynamic_object_size where the installed headers and the compiler \
                 both provide it, which fortify-enforced-dynamic measures and this level \
                 does not say",
            ),
            clause(
                FORTIFY_HEADERS_CLAUSE,
                Cond::All(vec![
                    fortify_headers(),
                    readable("_FORTIFY_SOURCE"),
                    int("_FORTIFY_SOURCE", Cmp::Le, 2),
                ]),
                word("1"),
                "fortify-headers: its checks use whole-object __builtin_object_size only and \
                 never subobject bounds, so the enforced level is 1 whatever level was \
                 requested",
            ),
            clause(
                FORTIFY_HEADERS_UNREAD_CLAUSE,
                fortify_headers(),
                Conclusion::Indeterminate,
                "fortify-headers identified itself, and _FORTIFY_SOURCE is undefined or \
                 defined with text chard's integer reading does not read, so which builtin \
                 its checks size objects with, which the request selects, cannot be read \
                 from it and the verdict is withheld",
            ),
            withhold_unreadable(
                "requested-unreadable",
                "_FORTIFY_SOURCE",
                "whether a level was requested",
            ),
            clause(
                "not-requested",
                Cond::NoneOf(vec![int("_FORTIFY_SOURCE", Cmp::Ne, 0)]),
                Conclusion::Absent,
                "no _FORTIFY_SOURCE, so no implementation instantiates",
            ),
            clause(
                "freebsd-without-ssp",
                Cond::All(vec![
                    int("__FreeBSD__", Cmp::Lt, 15),
                    missing("__SSP_FORTIFY_LEVEL"),
                ]),
                Conclusion::Absent,
                "FreeBSD before 15, a request above 0 and __SSP_FORTIFY_LEVEL undefined: the \
                 headers reached carry no <ssp/ssp.h>, which 15 is the first release to ship \
                 (measured on 14.5), so no fortify implementation instantiates and the \
                 request is inert",
            ),
            clause(
                "requested-without-optimization",
                missing("__OPTIMIZE__"),
                Conclusion::Absent,
                "a level was requested without optimization, which glibc and fortify-headers \
                 both gate on, and neither identified a level here",
            ),
        ],
        // Fortify was requested and optimization is on, and still nothing identified
        // itself: a fifth C library, or headers that were never reached. Not zero.
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

static PIE_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    code_model(
        "__PIE__",
        "__PIE__ is set and non-zero; its value names the code model, 2 for -fPIE and 1 \
         for -fpie, and is not a grade",
    )
});

/// The `pie-macro` predicate.
#[must_use]
pub fn pie_macro() -> &'static Predicate {
    &PIE_MACRO
}

/// The sentence names `__PIC__` alone, the one macro the clause reads. `evidence.macros`
/// carries both names, so a reader tells position independence arriving through `-fPIE`,
/// which defines both, from a PIC default that leaves `__PIE__` undefined there.
static PIC_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    code_model(
        "__PIC__",
        "__PIC__ is set and non-zero; its value names the code model, 2 for -fPIC and 1 \
         for -fpic, and is not a grade",
    )
});

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
                "__CET__ is a bitmask, 1 for branch tracking and 2 for the shadow stack, and \
                 3 is both",
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
                "__CET__ is 0, neither bit: the mask itself says nothing is enabled",
            ),
            clause(
                "unrecognised",
                defined("__CET__"),
                Conclusion::Indeterminate,
                "__CET__ is defined with a value that is not 0, 1, 2 or 3: text chard's \
                 integer reading does not read, or a bit this chard does not know; the mask \
                 is not absent and no level can be claimed for it",
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
/// `branch-protection-macro`.
///
/// GCS is to aarch64 what the shadow stack is to x86, and the corpus reads the shadow stack
/// through `__CET__`'s bit 2 rather than a check of its own, so the grouping is not
/// obvious. It is separate because the request is: `-mbranch-protection=bti` and
/// `=pac-ret` name their mechanisms, and a toolchain too old to know `gcs` still answers
/// for the other two. Folding it in would make the pair's `full` unreachable on every
/// compiler that predates GCS. `-mbranch-protection=standard` sets it too on compilers
/// that have it, so a `standard` build reads `on` here and `full` there.
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
                "__ARM_FEATURE_GCS_DEFAULT is set and non-zero; GCS is on or it is not, so \
                 no level",
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

/// aarch64's answer to CET, and the same shape: two independent bits, requested together.
///
/// `-mbranch-protection=standard` asks for both: BTI guards indirect branches as IBT does,
/// and PAC signs return addresses as the shadow stack protects them. The level vocabulary
/// is `cet-macro`'s for the same reason: a toolchain can serve one and not the other, and
/// `branch` and `return` name which survived. Measured on Apple clang 21 / arm64 under
/// `-mbranch-protection=standard`: both macros read `1`.
static BRANCH_PROTECTION_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    let bti = || positive("__ARM_FEATURE_BTI_DEFAULT");
    // PAC's macro selects a key, 1 for A and 2 for B, so any non-zero value signs return
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
                "__ARM_FEATURE_BTI_DEFAULT or __ARM_FEATURE_PAC_DEFAULT is defined with text \
                 chard's integer reading does not read, so which of the pair is on cannot \
                 be read and no level is claimed",
            ),
            clause(
                "full",
                Cond::All(vec![bti(), pac()]),
                word("full"),
                "BTI guards indirect branches and PAC signs return addresses, and both are on",
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
/// Ubuntu 22.04, Ubuntu 24.04, Alpine and Fedora 44, all x86_64). That is why
/// `report::family` keys it with `-fexceptions`: both checks read what it did. clang's
/// `-fexceptions -fignore-exceptions` defines the macro and emits no table on the same
/// four clang versions, so the macro cannot see that form and `except-table-emitted` can;
/// `tests/inert_flags.rs` holds the table's reading of it. The polarity is C's. In
/// C++ the macro is defined by default and `-fno-exceptions` removes it, so this reading
/// is right only on a C probe, which `probes/exceptions.c` is.
///
/// Measured 2026-10-01 in the `.chard.report` of that probe compiled `-c` at `-O0` and
/// `-O2`: `__EXCEPTIONS=1` under `-fexceptions` and `-fno-exceptions -fexceptions`, `?`
/// flagless, under `-fno-exceptions` and under `-fexceptions -fno-exceptions`, for gcc and
/// clang on the hosts `elf_static`'s `EXCEPT_TABLE` names.
static EXCEPTIONS_MACRO: LazyLock<Predicate> = LazyLock::new(|| {
    macros_only(
        vec![
            withhold_unreadable("unreadable", "__EXCEPTIONS", "whether exceptions are on"),
            clause(
                "set",
                positive("__EXCEPTIONS"),
                Conclusion::Present(LevelOf::None),
                "__EXCEPTIONS is set and non-zero, which in C -fexceptions does, and \
                 -fnon-call-exceptions on gcc 13 and later",
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
///
/// The macro-channel counterpart to `cxx-stdlib-assertions`, and the pair exists for the
/// reason `fortify-requested` and `fortify-effective` do: a request is not enforcement,
/// and divergence between the two is a finding. The runtime check answers whether a
/// precondition violation is diagnosed; this one answers whether anybody asked, and names
/// which library was asked. libstdc++ takes a boolean `_GLIBCXX_ASSERTIONS`, and libc++ a
/// `_LIBCPP_HARDENING_MODE` whose modes are `none`, `fast`, `extensive` and `debug`.
///
/// The library is identified by `cxx-stdlib`'s ladder. `_CXX_STDLIB` is chard's own
/// summary, written into the self-report by the header's `#if defined(_LIBCPP_VERSION)`
/// arm, so it is available only where the artifact can be read. `_LIBCPP_VERSION` and
/// `__GLIBCXX__` are the real macros that arm tests, and a preprocessor dump carries them
/// whatever the object format is, which keeps the identity answerable on a platform chard
/// has no reader for. On Linux, `measure` replaces the preprocessor dump with the
/// self-report wholesale, and the self-report carries `_CXX_STDLIB` and neither version
/// macro, so a Linux report shows the summary and no fallback.
///
/// libstdc++ reports no level: its request is a boolean, and the mode vocabulary is
/// libc++'s alone. Grading a level there against the other library's vocabulary would make
/// a correctly hardened libstdc++ build read `partial` for not spelling itself `fast`. The
/// check publishes libc++'s mode as information and grades nothing
/// (`probe::LIBCPP_MODES`): the guide's ask, `_LIBCPP_HARDENING_MODE_FAST`, is the lowest
/// mode libc++ has, so a grade against it would grade nothing.
///
/// libc++ spells its modes as shifts, `(1 << 1)` through `(1 << 4)`, and the macro arrives
/// as the shift when the named constant was passed on the command line, as the computed
/// value when the header's default came through, or, in a preprocessor dump, as the name
/// of the constant; `c-int` reads all three. Assuming the ordinals 1 to 4 would read
/// `(1 << 2)` as unrecognised and withhold a level on a system whose default is `fast`. The shifts
/// are not in strength order, and libc++ says so where it defines them: `EXTENSIVE` is
/// `(1 << 4)` and `DEBUG` is `(1 << 3)`, beside the comment "Deliberately not ordered."
/// Reading them as ordered would swap `extensive` and `debug`.
///
/// When no library identified itself the reading is withheld: a C++ build always has
/// one, so this is a build whose headers were never reached or a library neither macro
/// names, and neither is evidence that hardening is off.
///
// `c-int _LIBCPP_HARDENING_MODE` follows the mode's text as a macro name, and the
// published filter keeps libc++'s own mode constants, so a report re-derives every mode
// libc++ or chard's controls spell. A mode naming any other macro is outside that: with
// `-D_LIBCPP_HARDENING_MODE=MYMODE -DMYMODE=4` a preprocessor-sourced map reads `fast`
// here, and the Published view over the trimmed map stops at `Incomplete(macros.MYMODE)`,
// whether or not MYMODE was defined. The self-report prints the expansion, a number, so
// only a preprocessor-sourced map reaches this. A re-derivation over published evidence
// reads that `Incomplete` as not replayable, never as a contradiction; it retires when
// the Published view or the filter follows a `c-int` reference into the published map.
// `tests/predicates.rs` (`filtered_macros_suffice`) counts both halves.
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
                "libstdc++ with _GLIBCXX_ASSERTIONS defined; its request is a boolean, so no \
                 level",
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
                "libc++ in hardening mode debug, (1 << 3); libc++ does not order the mode \
                 bits by strength",
            ),
            clause(
                "libcxx-extensive",
                mode(16),
                word("extensive"),
                "libc++ in hardening mode extensive, (1 << 4); libc++ does not order the \
                 mode bits by strength",
            ),
            clause(
                "libcxx-unrecognised",
                stdlib("libc++"),
                Conclusion::Indeterminate,
                "unrecognised libc++ hardening mode, so no level can be claimed for it",
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
