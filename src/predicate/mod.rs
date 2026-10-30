// SPDX-License-Identifier: BSD-3-Clause

//! `chard-predicate/1`: a decoder written as data, and the one evaluator that runs it.
//!
//! A detector on the macro and elf-static channels is a pure function from published facts
//! to a reading: an outcome, a level, and the clause that decided it. Written as Rust, that
//! function is visible only to someone who trusts chard's build. Written as a [`Predicate`],
//! it is a value that serializes into the report beside the facts it read, and any reader
//! can re-evaluate it with this module's rules and compare. This module is the normative
//! statement of those rules; `DESIGN.md` points here rather than restating them.
//!
//! The types are owned and deserializable on purpose. An in-binary predicate is built once
//! behind a `std::sync::LazyLock` and handed out as `fn() -> &'static Predicate`, and the
//! value the report publishes is that same value serialized. `const` data would need a
//! second, borrowed type that cannot be deserialized, so the published predicate would not
//! be the one chard evaluated.
//!
//! # Values
//!
//! A [`Term`] evaluates to a [`Fact`], one of five shapes: `Undefined`, `Bool`, `Int`,
//! `Text` and `List`.
//!
//! - `macro NAME`: `Text` of the macro's replacement text, or `Undefined` when the map
//!   does not define it. A macro defined with no replacement text is `Text("")`.
//! - `c-int NAME`: the integer libc++'s hardening mode names, read from the value of
//!   `NAME` by this rule. The text is
//!   trimmed; then, at most eight times: the
//!   text is trimmed, the run of `(` it starts with and the run of `)` it ends with are
//!   stripped, each independently of the other and of balance, and the result is trimmed
//!   again (a parenthesis behind whitespace inside that run stays); when the text
//!   holds `<<`, it is split at the first one into `a` and `b`, each trimmed and read as
//!   an unsigned 32-bit decimal, and the value is `a` shifted left by `b` within 32 bits:
//!   a shift count of 32 or more is `Undefined`, so is a shift that would carry a bit
//!   past bit 31 (`3 << 31` is `Undefined`; `1 << 31` is 2147483648), and a side that
//!   does not read as a decimal is `Undefined`; text that reads as an unsigned 32-bit
//!   decimal is itself; anything else
//!   is looked up as a macro name, and a name that is undefined, or whose trimmed value
//!   is the name itself, gives `Undefined`. Eight steps without a number give
//!   `Undefined`. `NAME` and every name followed are reads.
//!
//!   A decimal, here and in the integer reading below, is Rust's `str::parse`: ASCII
//!   digits with an optional leading `+` (`+2` is 2), a leading `-` as well for the
//!   signed `i64` reading, and nothing else, so an interior space, a `0x` prefix or a
//!   `U` suffix does not read. To trim is `str::trim`: it removes, at both ends, every
//!   character with the Unicode `White_Space` property, U+0085 and U+3000 included.
//! - `cxx-stdlib`: `decode::common::cxx_stdlib`'s ladder. `_CXX_STDLIB`'s value when it is defined,
//!   else `Text("libc++")` when `_LIBCPP_VERSION` is defined, else `Text("libstdc++")`
//!   when `__GLIBCXX__` is defined, else `Undefined`. Each rung consulted is a read, and a
//!   rung that answers ends the ladder.
//! - `elf FIELD`: the `ElfFacts` field whose serialized JSON key is `FIELD` ([`ElfField`]).
//!   `null` is `Undefined`, a boolean is `Bool`, an integer that fits `i64` is `Int`, a
//!   string is `Text` and an array of strings is `List`. A non-negative integer above
//!   `i64::MAX` is `Undefined`, which is how the Live view reads a `usize` count that
//!   large; any other number, a float included, is the wrong shape (see Views).
//! - `symbol NAME`: `Bool(defined)` for an entry of `watched_symbols`, `Undefined` for a
//!   watched name the map does not hold. The watch list is the symbol channel's filter,
//!   as the published filter is the macro channel's: the map holds only the watched names
//!   the reader found, so its silence about any other name is not a reading. A name
//!   outside the watch list is `Incomplete`, keyed `elf.watched_symbols.NAME`, never
//!   `Undefined`. Which list is the watch list depends on the view (see Views): the Live
//!   view's is `elf::WATCHED_SYMBOLS`, the list of the chard that read the artifact, and
//!   the Published view's is the list the publication says its reader watched, since a
//!   later chard's list can hold a name the reader never looked for. [`validate`] refuses
//!   a predicate naming a symbol outside `elf::WATCHED_SYMBOLS`.
//! - `symbol-names`: `List` of the keys of `watched_symbols`, in map order. The list means
//!   something only beside the watch list it was cut from, so the Published view reads it
//!   only when the publication carries that list.
//!
//! # Conditions
//!
//! A [`Cond`] is true or false. Every comparison against a value of the wrong shape is
//! false, never an error, so a clause that does not apply is a clause that does not match.
//!
//! - `all` is true when every member is (and for an empty list); `any` when at least one
//!   is (false for an empty list); `none-of` when no member is. Members are evaluated in
//!   order and evaluation stops at the first member that settles the answer, so a read
//!   the answer did not need is never made.
//! - `defined T` is true when `T` is not `Undefined`; `missing T` when it is.
//! - `truth T` is true for `Bool(true)`, for an `Int` other than zero, and for `Text`
//!   whose integer reading (below) is other than zero. It is false otherwise.
//! - `eq [T, s]` is true when `T` renders as exactly `s`: `Text` verbatim, `Int` in base
//!   10, `Bool` as `true` or `false`. `Undefined` and `List` never equal anything.
//! - `int [T, cmp, n]` compares `T`'s integer reading with `n` under `eq`, `ne`, `lt`,
//!   `le`, `gt` or `ge`. The integer reading of `Int` is itself and of `Text` is
//!   trim, then a base-10 `i64`. Any other value, and text that does not parse, has no
//!   integer reading and the condition is false.
//! - `any-starts-with [T, s]` and `any-contains [T, s]` are true when some item of a
//!   `List` starts with or contains `s`. They are false for every other shape.
//! - `non-empty T` is true for a `List` with an item and for non-empty `Text`.
//!
//! # Evaluation
//!
//! [`evaluate`] applies three steps in order and stops at the first that concludes.
//!
//! 1. **No source.** A predicate needs the macro source when any term it contains reads a
//!    macro, and the ELF source when any term reads the artifact or `tables` is non-empty.
//!    A needed source the view does not have concludes `indeterminate`, clause
//!    `@no-source:macros` (checked first) or `@no-source:elf`. No read is recorded.
//! 2. **Truncation.** When `tables` names a table that `truncations` records as `unread`,
//!    the conclusion is `indeterminate`, clause `@truncated`. `ignored` entries never
//!    match, which is `ElfFacts::unread`'s rule: the loader's view was measured whole.
//!    The truncation list is a read whenever `tables` is non-empty.
//! 3. **Clauses.** The first clause whose `when` holds concludes with its `then`, under
//!    its `id`. When none holds, `otherwise` concludes, under the clause `@otherwise`.
//!
//! A conclusion is `present` with a level, `absent`, or `indeterminate`. A `present`
//! level is none, a fixed word, or the value of a term. A term's value renders as its
//! integer reading in base 10 when it has one, as its text otherwise, and `Bool` as
//! `true` or `false`. A level term that is `Undefined`, a `List`, or empty `Text` has no
//! rendering; the conclusion is then `indeterminate` under the same clause, since a level
//! that cannot be read is not one chard may claim. That demotion is the one case where an
//! evaluation's outcome differs from what its clause's `then` (or `otherwise`) states: an
//! `indeterminate` outcome under a conclusion that is `present` with a `value` level is a
//! level that failed to render, and [`render_observed`] says so.
//!
//! Clause ids are unique within a predicate, never empty, and never begin with `@`, which
//! the reserved clauses above use, every `because` holds a character outside
//! ECMA-262's `\s`, and a fixed `word` level is never empty, since an empty rendering is
//! not a level chard may claim. [`validate`] checks these; a reader re-evaluating a
//! published predicate validates it first, since an ambiguous clause id names no clause.
//!
//! # Views
//!
//! The evaluator reads through a [`FactView`] and records each distinct read, in the order
//! first made, with the value it returned. Two views exist.
//!
//! - [`Live`] reads the macro map and `ElfFacts` a measurement produced.
//! - [`Published`] reads the same facts as they were serialized into a report: a macro
//!   object, the filter the report says it was trimmed to, an `ElfFacts` object, and the
//!   watch list the report says its reader looked for symbols from. A key
//!   the view does not hold is `Incomplete(key)`, and the evaluation stops there rather
//!   than reading it as absent. A macro name outside the published filter is
//!   `Incomplete`, never `Undefined`: the trimmed map says nothing about a name it was
//!   not asked to keep, and reading silence as "undefined" is how an unearned `off` would
//!   be derived from a report. A name inside the filter and absent from the map is
//!   `Undefined`, because the filter says the map would have carried it. A value of the
//!   wrong JSON shape for its field is `Incomplete` too.
//!
//!   The watch list is read the same way. A `symbol NAME` whose name is outside the
//!   published list is `Incomplete("elf.watched_symbols.NAME")`, and a name inside it
//!   that `watched_symbols` does not hold is `Undefined`. A publication with no watch
//!   list answers no symbol read: `symbol NAME` and `symbol-names` are both
//!   `Incomplete("symbols_filter")`. The reading binary's own `elf::WATCHED_SYMBOLS` is
//!   never substituted for the publication's list, because a name the publishing chard
//!   did not watch would then read as undefined, and a `missing` or `none-of` clause over
//!   it would conclude `absent` from silence.
//!
//!   No absence reads as a value, `truncations` included. An absence read as empty could
//!   not tell "no truncation" from a publication that lost a non-empty list, which would
//!   turn a `@truncated` reading into whatever the clauses conclude. A publication a
//!   predicate is re-evaluated over therefore carries `truncations` explicitly, `[]` when
//!   nothing was cut, and this view reads its absence as `Incomplete`. `ElfFacts` on its
//!   own omits the empty list (`skip_serializing_if`), and a report's `elf` store entries
//!   state it, `report::serialize_stored_elf` being the serializer that does.
//!
//! Incomplete keys are spelt `macros.NAME`, `elf.FIELD`, `elf.watched_symbols`,
//! `elf.watched_symbols.NAME`, `elf.truncations` and `symbols_filter`, and `macros` or
//! `elf` for a source whose publication is not an object.
//!
//! # Rendering
//!
//! [`render_observed`] turns an evaluation into the `observed` sentence: each read in
//! order, macros as a `CHARD-REPORT-V2` self-report spells them (`NAME=value`, which is
//! `NAME=` for empty text, and `NAME undefined` when undefined: a defined macro's text
//! follows the `=`, and an undefined one has no `=`, so no two reads of one macro with
//! different values render alike, and no `-D` writes the undefined form), ELF fields as
//! `field=value` (`null` when undefined), symbols as `NAME=present(defined=BOOL)` or
//! `NAME=absent`, the watched names as `watched_symbols=LIST` and the truncation read as
//! `unread_tables=LIST`, then the deciding clause's `because` in parentheses. `@otherwise`
//! carries no reason, so its sentence is the reads alone. Reads are separated by one space.
//!
//! The sentence is for a reader, and the evaluation's reads (`reads` in a publication) are
//! its exact form: each macro read renders apart from every other value of that macro, and
//! the sentence as a whole does not. A value holding a space can spell a later read: a
//! macro `A` defined as `1 B undefined` renders `A=1 B undefined`, which is also the
//! sentence of `A` defined as `1` and an undefined `B`. A macro name is not always an
//! identifier: `c-int` looks up a macro's text as a name, so `_LIBCPP_HARDENING_MODE`
//! defined as `B=1` reads a macro named `B=1`, which renders `B=1 undefined`, as a macro
//! `B` defined as `1 undefined` does. No verdict reads the sentence;
//! `tests::the_sentence_is_distinct_per_read_and_not_as_a_whole` holds both examples.
//!
//! A `LIST` (the watched names, the unread tables, and any `List` field) renders as a JSON
//! array of strings in compact form: `[`, the items in order separated by `,` with no
//! whitespace, `]`. Each item is a JSON string: `"` and `\` are escaped with a backslash,
//! the control characters U+0008, U+0009, U+000A, U+000C and U+000D as `\b`, `\t`, `\n`,
//! `\f` and `\r`, every other character below U+0020 as `\u00` and two lowercase hex
//! digits, and every other character, non-ASCII included, as itself in UTF-8. This is
//! `serde_json`'s compact writer, and a vector pins it.
//!
//! When a `value` level has no rendering (Evaluation), the sentence ends in
//! `the level TERM has no rendering, so the reading is indeterminate`, after the clause's
//! `because` and a `; ` inside the same parentheses, or alone in parentheses under
//! `@otherwise`. `TERM` is spelt as this document spells terms: `macro NAME`,
//! `c-int NAME`, `cxx-stdlib`, `elf FIELD`, `symbol NAME` or `symbol-names`.
//!
//! [`canonical`] is compact `serde_json` of the predicate, the form a digest is taken
//! over; it never passes through `Debug`.

pub mod elf_static;
pub mod macro_channel;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::elf::{ElfFacts, ElfTable, Truncation, TruncationKind, WATCHED_SYMBOLS};
use crate::probe::Outcome;

/// The language version. A change to any rule in the module documentation, or to an
/// expected result in `schema/chard-predicate-vectors.json`, is a new version once a
/// publication has carried the version: `tests/predicate_language.rs` pins the vectors'
/// digest per version. Before the first publication the pin moves under the same name and
/// that test's note says what changed; a report written before such a change replays its
/// predicates under the rules after it, and `run.decoders_sha256`, which folds this
/// module's source in, is what tells the two apart.
pub const LANGUAGE: &str = "chard-predicate/1";

/// The reserved clause for a predicate whose macro source the view lacks.
pub const NO_SOURCE_MACROS: &str = "@no-source:macros";
/// The reserved clause for a predicate whose ELF source the view lacks.
pub const NO_SOURCE_ELF: &str = "@no-source:elf";
/// The reserved clause for a predicate one of whose tables was left unread.
pub const TRUNCATED: &str = "@truncated";
/// The reserved clause for `otherwise`.
pub const OTHERWISE: &str = "@otherwise";

const NO_SOURCE_MACROS_BECAUSE: &str = "no macro source was available to read";
const NO_SOURCE_ELF_BECAUSE: &str = "no ELF facts were available to read";
const TRUNCATED_BECAUSE: &str = "a table this reading depends on was left unread";

/// A decoder: ELF tables whose truncation withholds it, clauses tried in order, and the
/// conclusion when none matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predicate {
    pub tables: Vec<ElfTable>,
    pub clauses: Vec<Clause>,
    pub otherwise: Conclusion,
}

/// One rule: when `when` holds, `then` concludes, for the reason `because`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clause {
    pub id: String,
    pub when: Cond,
    pub then: Conclusion,
    pub because: String,
}

/// What a clause concludes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Conclusion {
    Present(LevelOf),
    Absent,
    Indeterminate,
}

/// The level a `present` conclusion carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LevelOf {
    None,
    Word(String),
    Value(Term),
}

/// A comparison for [`Cond::Int`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Cmp {
    /// Every comparison, in declaration order; what the schema's enum is pinned to.
    pub const ALL: [Self; 6] = [Self::Eq, Self::Ne, Self::Lt, Self::Le, Self::Gt, Self::Ge];

    fn holds(self, left: i64, right: i64) -> bool {
        match self {
            Self::Eq => left == right,
            Self::Ne => left != right,
            Self::Lt => left < right,
            Self::Le => left <= right,
            Self::Gt => left > right,
            Self::Ge => left >= right,
        }
    }
}

/// A condition over terms; the module documentation states each one's truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cond {
    All(Vec<Cond>),
    Any(Vec<Cond>),
    NoneOf(Vec<Cond>),
    Defined(Term),
    Missing(Term),
    Truth(Term),
    Eq(Term, String),
    Int(Term, Cmp, i64),
    AnyStartsWith(Term, String),
    AnyContains(Term, String),
    NonEmpty(Term),
}

/// Something a predicate reads; the module documentation states each one's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Term {
    Macro(String),
    CInt(String),
    CxxStdlib,
    Elf(ElfField),
    Symbol(String),
    SymbolNames,
}

impl Term {
    fn reads_macros(&self) -> bool {
        matches!(self, Self::Macro(_) | Self::CInt(_) | Self::CxxStdlib)
    }

    fn reads_elf(&self) -> bool {
        matches!(self, Self::Elf(_) | Self::Symbol(_) | Self::SymbolNames)
    }
}

/// How an [`ElfField`] is serialized, which is what [`Published`] holds a value to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldShape {
    Bool,
    NullableBool,
    Int,
    Text,
    NullableText,
    List,
    NullableList,
}

/// The `ElfFacts` fields a predicate may read, spelt as their serialized JSON keys.
///
/// The map-valued fields are reached through [`Term::Symbol`] and [`Term::SymbolNames`]
/// (`watched_symbols`) or not at all (`gnu_property_notes`), and `truncations` through the
/// truncation step. `self_report` is the macro channel's source, read as macros. The two
/// omitted-when-empty lists, `symbol_tables` and `comment`, are left out so that no
/// readable field's absence has to be read as empty; `report` and `toolchain` read them,
/// and no decoder does. `openbsd_nobtcfi` is left out because `composite::cfi` is its one
/// reader, and a recorded row without it reads `false`, so a predicate over it would read
/// a defaulted `false` on every row recorded without the field. `data_in_code_pages` is
/// omitted when `null` and readable all the same: its default is `null`, which reads as
/// `Undefined`, so a row mined before the field existed reads as no measurement rather than
/// as either answer, and a report's `facts` store states the `null` the struct omits.
/// `code_relocations` is read on the same terms.
/// `function_references` is read the same way and for the same reason.
///
/// `code_scanned`, `code_matches` and `function_entries` are omitted when empty and
/// readable all the same. A report's store states each, `[]` included
/// (`report::serialize_stored_elf`), as it states `truncations`, so the Published view
/// meets them; a publication that omits one is `Incomplete` there rather than empty, which
/// is the rule above applied to them. A recorded row without any of the three reads as empty
/// there, serde's default for an absent list; the Published view, not the record, is where an
/// omission is told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfField {
    ElfClass,
    ElfType,
    Machine,
    HasInterp,
    HasDynamic,
    Pie,
    #[serde(rename = "df_1_pie")]
    Df1Pie,
    StaticPie,
    SharedObject,
    StaticallyLinked,
    Relro,
    GnuRelro,
    BindNow,
    GnuStackPresent,
    GnuStackExecutable,
    #[serde(rename = "df_1_noopen")]
    Df1Noopen,
    Textrel,
    DtRelr,
    DtDebug,
    DtSoname,
    DynamicTags,
    Needed,
    Rpath,
    Runpath,
    GnuPropertyTypes,
    X86Ibt,
    X86Shstk,
    Aarch64Bti,
    Aarch64Pac,
    Aarch64Gcs,
    Sections,
    DataInCodePages,
    CodeRelocations,
    FunctionReferences,
    SymbolCount,
    RecordedCommandLine,
    CodeScanned,
    CodeMatches,
    FunctionEntries,
}

impl ElfField {
    /// Every field, in declaration order.
    pub const ALL: [Self; 39] = [
        Self::ElfClass,
        Self::ElfType,
        Self::Machine,
        Self::HasInterp,
        Self::HasDynamic,
        Self::Pie,
        Self::Df1Pie,
        Self::StaticPie,
        Self::SharedObject,
        Self::StaticallyLinked,
        Self::Relro,
        Self::GnuRelro,
        Self::BindNow,
        Self::GnuStackPresent,
        Self::GnuStackExecutable,
        Self::Df1Noopen,
        Self::Textrel,
        Self::DtRelr,
        Self::DtDebug,
        Self::DtSoname,
        Self::DynamicTags,
        Self::Needed,
        Self::Rpath,
        Self::Runpath,
        Self::GnuPropertyTypes,
        Self::X86Ibt,
        Self::X86Shstk,
        Self::Aarch64Bti,
        Self::Aarch64Pac,
        Self::Aarch64Gcs,
        Self::Sections,
        Self::DataInCodePages,
        Self::CodeRelocations,
        Self::FunctionReferences,
        Self::SymbolCount,
        Self::RecordedCommandLine,
        Self::CodeScanned,
        Self::CodeMatches,
        Self::FunctionEntries,
    ];

    /// The serialized JSON key, which a test holds to both serde spellings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ElfClass => "elf_class",
            Self::ElfType => "elf_type",
            Self::Machine => "machine",
            Self::HasInterp => "has_interp",
            Self::HasDynamic => "has_dynamic",
            Self::Pie => "pie",
            Self::Df1Pie => "df_1_pie",
            Self::StaticPie => "static_pie",
            Self::SharedObject => "shared_object",
            Self::StaticallyLinked => "statically_linked",
            Self::Relro => "relro",
            Self::GnuRelro => "gnu_relro",
            Self::BindNow => "bind_now",
            Self::GnuStackPresent => "gnu_stack_present",
            Self::GnuStackExecutable => "gnu_stack_executable",
            Self::Df1Noopen => "df_1_noopen",
            Self::Textrel => "textrel",
            Self::DtRelr => "dt_relr",
            Self::DtDebug => "dt_debug",
            Self::DtSoname => "dt_soname",
            Self::DynamicTags => "dynamic_tags",
            Self::Needed => "needed",
            Self::Rpath => "rpath",
            Self::Runpath => "runpath",
            Self::GnuPropertyTypes => "gnu_property_types",
            Self::X86Ibt => "x86_ibt",
            Self::X86Shstk => "x86_shstk",
            Self::Aarch64Bti => "aarch64_bti",
            Self::Aarch64Pac => "aarch64_pac",
            Self::Aarch64Gcs => "aarch64_gcs",
            Self::Sections => "sections",
            Self::DataInCodePages => "data_in_code_pages",
            Self::CodeRelocations => "code_relocations",
            Self::FunctionReferences => "function_references",
            Self::SymbolCount => "symbol_count",
            Self::RecordedCommandLine => "recorded_command_line",
            Self::CodeScanned => "code_scanned",
            Self::CodeMatches => "code_matches",
            Self::FunctionEntries => "function_entries",
        }
    }

    /// The JSON shape the field serializes to.
    #[must_use]
    pub fn shape(self) -> FieldShape {
        match self {
            Self::ElfClass | Self::SymbolCount => FieldShape::Int,
            Self::ElfType | Self::Machine | Self::RecordedCommandLine => FieldShape::Text,
            Self::Relro => FieldShape::NullableText,
            Self::Pie
            | Self::StaticPie
            | Self::SharedObject
            | Self::StaticallyLinked
            | Self::GnuRelro
            | Self::BindNow
            | Self::GnuStackPresent
            | Self::GnuStackExecutable => FieldShape::NullableBool,
            Self::HasInterp
            | Self::HasDynamic
            | Self::Df1Pie
            | Self::Df1Noopen
            | Self::Textrel
            | Self::DtRelr
            | Self::DtDebug
            | Self::DtSoname
            | Self::X86Ibt
            | Self::X86Shstk
            | Self::Aarch64Bti
            | Self::Aarch64Pac
            | Self::Aarch64Gcs => FieldShape::Bool,
            Self::DynamicTags
            | Self::Needed
            | Self::Rpath
            | Self::Runpath
            | Self::GnuPropertyTypes
            | Self::Sections
            | Self::CodeScanned
            | Self::CodeMatches
            | Self::FunctionEntries => FieldShape::List,
            Self::DataInCodePages | Self::CodeRelocations | Self::FunctionReferences => {
                FieldShape::NullableList
            }
        }
    }
}

/// What a term evaluates to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact {
    Undefined,
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<String>),
}

impl Fact {
    /// The integer reading, the module documentation's rule: an `Int` itself, `Text`
    /// trimmed and parsed as a base-10 `i64`, and nothing else. Public so that a test
    /// holding another reader to this one calls it rather than restating it.
    #[must_use]
    pub fn integer(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            Self::Text(text) => text.trim().parse::<i64>().ok(),
            Self::Undefined | Self::Bool(_) | Self::List(_) => None,
        }
    }

    /// The rendering `eq` compares against.
    fn scalar_text(&self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text.clone()),
            Self::Int(value) => Some(value.to_string()),
            Self::Bool(value) => Some(value.to_string()),
            Self::Undefined | Self::List(_) => None,
        }
    }

    /// The rendering a `value` level takes, `None` where there is none to claim.
    fn level(&self) -> Option<String> {
        match self {
            Self::Text(text) if text.is_empty() => None,
            Self::Text(text) => Some(
                self.integer()
                    .map_or_else(|| text.clone(), |i| i.to_string()),
            ),
            Self::Int(value) => Some(value.to_string()),
            Self::Bool(value) => Some(value.to_string()),
            Self::Undefined | Self::List(_) => None,
        }
    }
}

/// A key the view does not hold, named as the module documentation spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incomplete(pub String);

/// What was read, as distinct keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadKey {
    Macro(String),
    Elf(ElfField),
    Symbol(String),
    SymbolNames,
    Truncations,
}

impl ReadKey {
    /// The published key whose removal makes this read `Incomplete`.
    #[must_use]
    pub fn published_key(&self) -> String {
        match self {
            Self::Macro(name) => format!("macros.{name}"),
            Self::Elf(field) => format!("elf.{}", field.as_str()),
            Self::Symbol(_) | Self::SymbolNames => "elf.watched_symbols".to_owned(),
            Self::Truncations => "elf.truncations".to_owned(),
        }
    }
}

/// One read and the value it returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    pub key: ReadKey,
    pub value: Fact,
}

/// The result of [`evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub outcome: Outcome,
    pub level: Option<String>,
    /// The deciding clause's id, or one of the reserved `@` clauses.
    pub clause: String,
    /// Each distinct read, in the order first made.
    pub reads: Vec<Read>,
}

/// A source of facts. Each method answers one key, or names the key it cannot answer.
///
/// The evaluator records reads, not the view, so the two views record identically.
pub trait FactView {
    fn has_macros(&self) -> bool;
    fn has_elf(&self) -> bool;
    /// A macro's replacement text; `Ok(None)` is a macro known to be undefined.
    ///
    /// # Errors
    ///
    /// The name's key, when the view cannot say.
    fn macro_value(&self, name: &str) -> Result<Option<String>, Incomplete>;
    /// A field's value.
    ///
    /// # Errors
    ///
    /// The field's key, when the view does not hold it in its declared shape.
    fn elf_field(&self, field: ElfField) -> Result<Fact, Incomplete>;
    /// A watched symbol's `defined`; `Ok(None)` is a watched name `watched_symbols` does
    /// not hold.
    ///
    /// # Errors
    ///
    /// `symbols_filter` when the view has no watch list, the entry's key for a name
    /// outside the watch list or an entry with no `defined`, and `elf.watched_symbols`
    /// when the view does not hold the map.
    fn symbol(&self, name: &str) -> Result<Option<bool>, Incomplete>;
    /// The names `watched_symbols` holds.
    ///
    /// # Errors
    ///
    /// `symbols_filter` when the view has no watch list, and `elf.watched_symbols` when
    /// it does not hold the map.
    fn symbol_names(&self) -> Result<Vec<String>, Incomplete>;
    /// The tables `truncations` records as `unread`.
    ///
    /// # Errors
    ///
    /// `elf.truncations`, when the view does not hold the list or it does not read as
    /// truncations.
    fn unread_tables(&self) -> Result<Vec<ElfTable>, Incomplete>;
}

/// The facts a measurement produced, as `probe::Evidence` carries them.
#[derive(Debug, Clone, Copy)]
pub struct Live<'a> {
    pub macros: Option<&'a BTreeMap<String, String>>,
    pub elf: Option<&'a ElfFacts>,
}

fn no_elf() -> Incomplete {
    Incomplete("elf".to_owned())
}

fn no_macros() -> Incomplete {
    Incomplete("macros".to_owned())
}

fn unwatched(name: &str) -> Incomplete {
    Incomplete(format!("elf.watched_symbols.{name}"))
}

fn no_watch_list() -> Incomplete {
    Incomplete("symbols_filter".to_owned())
}

fn nullable<T>(value: Option<T>, wrap: impl FnOnce(T) -> Fact) -> Fact {
    value.map_or(Fact::Undefined, wrap)
}

impl FactView for Live<'_> {
    fn has_macros(&self) -> bool {
        self.macros.is_some()
    }

    fn has_elf(&self) -> bool {
        self.elf.is_some()
    }

    fn macro_value(&self, name: &str) -> Result<Option<String>, Incomplete> {
        Ok(self.macros.ok_or_else(no_macros)?.get(name).cloned())
    }

    fn elf_field(&self, field: ElfField) -> Result<Fact, Incomplete> {
        let e = self.elf.ok_or_else(no_elf)?;
        Ok(match field {
            ElfField::ElfClass => Fact::Int(i64::from(e.elf_class)),
            ElfField::ElfType => Fact::Text(e.elf_type.clone()),
            ElfField::Machine => Fact::Text(e.machine.clone()),
            ElfField::HasInterp => Fact::Bool(e.has_interp),
            ElfField::HasDynamic => Fact::Bool(e.has_dynamic),
            ElfField::Pie => nullable(e.pie, Fact::Bool),
            ElfField::Df1Pie => Fact::Bool(e.df_1_pie),
            ElfField::StaticPie => nullable(e.static_pie, Fact::Bool),
            ElfField::SharedObject => nullable(e.shared_object, Fact::Bool),
            ElfField::StaticallyLinked => nullable(e.statically_linked, Fact::Bool),
            ElfField::Relro => nullable(e.relro.clone(), Fact::Text),
            ElfField::GnuRelro => nullable(e.gnu_relro, Fact::Bool),
            ElfField::BindNow => nullable(e.bind_now, Fact::Bool),
            ElfField::GnuStackPresent => nullable(e.gnu_stack_present, Fact::Bool),
            ElfField::GnuStackExecutable => nullable(e.gnu_stack_executable, Fact::Bool),
            ElfField::Df1Noopen => Fact::Bool(e.df_1_noopen),
            ElfField::Textrel => Fact::Bool(e.textrel),
            ElfField::DtRelr => Fact::Bool(e.dt_relr),
            ElfField::DtDebug => Fact::Bool(e.dt_debug),
            ElfField::DtSoname => Fact::Bool(e.dt_soname),
            ElfField::DynamicTags => Fact::List(e.dynamic_tags.clone()),
            ElfField::Needed => Fact::List(e.needed.clone()),
            ElfField::Rpath => Fact::List(e.rpath.clone()),
            ElfField::Runpath => Fact::List(e.runpath.clone()),
            ElfField::GnuPropertyTypes => Fact::List(e.gnu_property_types.clone()),
            ElfField::X86Ibt => Fact::Bool(e.x86_ibt),
            ElfField::X86Shstk => Fact::Bool(e.x86_shstk),
            ElfField::Aarch64Bti => Fact::Bool(e.aarch64_bti),
            ElfField::Aarch64Pac => Fact::Bool(e.aarch64_pac),
            ElfField::Aarch64Gcs => Fact::Bool(e.aarch64_gcs),
            ElfField::Sections => Fact::List(e.sections.clone()),
            ElfField::DataInCodePages => nullable(e.data_in_code_pages.clone(), Fact::List),
            ElfField::CodeRelocations => nullable(e.code_relocations.clone(), Fact::List),
            ElfField::FunctionReferences => nullable(e.function_references.clone(), Fact::List),
            // serde_json writes a `usize` as an unsigned integer, and `Published` reads it
            // back through `as_i64`; a count past `i64::MAX` is `Undefined` in both.
            ElfField::SymbolCount => nullable(i64::try_from(e.symbol_count).ok(), Fact::Int),
            ElfField::RecordedCommandLine => Fact::Text(e.recorded_command_line.clone()),
            ElfField::CodeScanned => Fact::List(e.code_scanned.clone()),
            ElfField::CodeMatches => Fact::List(e.code_matches.clone()),
            ElfField::FunctionEntries => Fact::List(e.function_entries.clone()),
        })
    }

    fn symbol(&self, name: &str) -> Result<Option<bool>, Incomplete> {
        let e = self.elf.ok_or_else(no_elf)?;
        if !WATCHED_SYMBOLS.contains(&name) {
            return Err(unwatched(name));
        }
        Ok(e.watched_symbols.get(name).map(|s| s.defined))
    }

    fn symbol_names(&self) -> Result<Vec<String>, Incomplete> {
        let e = self.elf.ok_or_else(no_elf)?;
        Ok(e.watched_symbols.keys().cloned().collect())
    }

    fn unread_tables(&self) -> Result<Vec<ElfTable>, Incomplete> {
        let e = self.elf.ok_or_else(no_elf)?;
        Ok(unread_of(&e.truncations))
    }
}

fn unread_of(truncations: &[Truncation]) -> Vec<ElfTable> {
    truncations
        .iter()
        .filter(|t| t.kind == TruncationKind::Unread)
        .map(|t| t.table)
        .collect()
}

/// The facts as a report published them.
#[derive(Debug, Clone)]
pub struct Published<'a> {
    macros: Option<&'a Map<String, Value>>,
    filter: Option<BTreeSet<&'a str>>,
    elf: Option<&'a Map<String, Value>>,
    watch_list: Option<BTreeSet<&'a str>>,
}

impl<'a> Published<'a> {
    /// A view over a published macro object, the filter it was trimmed to (`None` for an
    /// untrimmed map), a published `ElfFacts` object, and the watch list its reader looked
    /// for symbols from (`None` when the publication carries none, which leaves every
    /// symbol read `Incomplete`). `None` for a source is a source the reading says was not
    /// available.
    ///
    /// # Errors
    ///
    /// `Incomplete("macros")` or `Incomplete("elf")` for a source that is not an object.
    pub fn new(
        macros: Option<&'a Value>,
        filter: Option<&'a [String]>,
        elf: Option<&'a Value>,
        watch_list: Option<&'a [String]>,
    ) -> Result<Self, Incomplete> {
        let macros = macros
            .map(|m| m.as_object().ok_or_else(no_macros))
            .transpose()?;
        let elf = elf.map(|e| e.as_object().ok_or_else(no_elf)).transpose()?;
        Ok(Self {
            macros,
            filter: filter.map(|names| names.iter().map(String::as_str).collect()),
            elf,
            watch_list: watch_list.map(|names| names.iter().map(String::as_str).collect()),
        })
    }

    fn elf_map(&self) -> Result<&'a Map<String, Value>, Incomplete> {
        self.elf.ok_or_else(no_elf)
    }

    fn watched(&self) -> Result<&'a Map<String, Value>, Incomplete> {
        self.elf_map()?
            .get("watched_symbols")
            .and_then(Value::as_object)
            .ok_or_else(|| Incomplete("elf.watched_symbols".to_owned()))
    }
}

fn string_list(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(ToOwned::to_owned))
        .collect()
}

impl FactView for Published<'_> {
    fn has_macros(&self) -> bool {
        self.macros.is_some()
    }

    fn has_elf(&self) -> bool {
        self.elf.is_some()
    }

    fn macro_value(&self, name: &str) -> Result<Option<String>, Incomplete> {
        let map = self.macros.ok_or_else(no_macros)?;
        let key = || Incomplete(format!("macros.{name}"));
        if let Some(filter) = &self.filter
            && !filter.contains(name)
        {
            return Err(key());
        }
        match map.get(name) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(key()),
        }
    }

    fn elf_field(&self, field: ElfField) -> Result<Fact, Incomplete> {
        let key = || Incomplete(format!("elf.{}", field.as_str()));
        let value = self.elf_map()?.get(field.as_str()).ok_or_else(key)?;
        let fact = match (field.shape(), value) {
            (
                FieldShape::NullableBool | FieldShape::NullableText | FieldShape::NullableList,
                Value::Null,
            ) => Some(Fact::Undefined),
            (FieldShape::Bool | FieldShape::NullableBool, Value::Bool(b)) => Some(Fact::Bool(*b)),
            // An integer above `i64::MAX` is the one number with no `i64` reading that Live
            // also produces (`SymbolCount`); a float is not a serialized `ElfFacts` value.
            (FieldShape::Int, Value::Number(n)) => n
                .as_i64()
                .map(Fact::Int)
                .or_else(|| n.as_u64().map(|_| Fact::Undefined)),
            (FieldShape::Text | FieldShape::NullableText, Value::String(s)) => {
                Some(Fact::Text(s.clone()))
            }
            (FieldShape::List | FieldShape::NullableList, list) => {
                string_list(list).map(Fact::List)
            }
            _ => None,
        };
        fact.ok_or_else(key)
    }

    fn symbol(&self, name: &str) -> Result<Option<bool>, Incomplete> {
        if !self
            .watch_list
            .as_ref()
            .ok_or_else(no_watch_list)?
            .contains(name)
        {
            return Err(unwatched(name));
        }
        match self.watched()?.get(name) {
            None => Ok(None),
            Some(entry) => entry
                .get("defined")
                .and_then(Value::as_bool)
                .map(Some)
                .ok_or_else(|| unwatched(name)),
        }
    }

    fn symbol_names(&self) -> Result<Vec<String>, Incomplete> {
        self.watch_list.as_ref().ok_or_else(no_watch_list)?;
        Ok(self.watched()?.keys().cloned().collect())
    }

    fn unread_tables(&self) -> Result<Vec<ElfTable>, Incomplete> {
        let key = || Incomplete("elf.truncations".to_owned());
        let value = self.elf_map()?.get("truncations").ok_or_else(key)?;
        let entries = Vec::<Truncation>::deserialize(value).map_err(|_e| key())?;
        Ok(unread_of(&entries))
    }
}

/// The evaluator's state: the view, and the reads made so far.
struct Reader<'v, V: FactView + ?Sized> {
    view: &'v V,
    reads: Vec<Read>,
}

impl<V: FactView + ?Sized> Reader<'_, V> {
    fn record(&mut self, key: ReadKey, value: Fact) {
        if !self.reads.iter().any(|r| r.key == key) {
            self.reads.push(Read { key, value });
        }
    }

    fn macro_text(&mut self, name: &str) -> Result<Option<String>, Incomplete> {
        let value = self.view.macro_value(name)?;
        self.record(
            ReadKey::Macro(name.to_owned()),
            nullable(value.clone(), Fact::Text),
        );
        Ok(value)
    }

    /// The `c-int` rule, step for step, with every lookup a read.
    ///
    /// libc++ defines its modes as `(1 << n)`, so the macro arrives as that shift or as
    /// the value it computes to, depending on whether the command line passed the named
    /// constant or the header supplied its own default. It can also arrive as another
    /// macro's name: a preprocessor dump prints replacement text rather than the expansion,
    /// so a mode the headers set for themselves comes through as the constant it was
    /// spelled with (measured on Darwin, `_LIBCPP_HARDENING_MODE` read back as the token
    /// `_LIBCPP_HARDENING_MODE_DEFAULT`). The names it forwards to are in the same map, so
    /// resolution is a lookup rather than a table kept in step with libc++. Bounded,
    /// because a macro map is arbitrary input: `-D_LIBCPP_HARDENING_MODE=X -DX=X` is a
    /// cycle a caller could hand in, and the bound is what makes it terminate.
    fn c_int(&mut self, name: &str) -> Result<Fact, Incomplete> {
        let Some(start) = self.macro_text(name)? else {
            return Ok(Fact::Undefined);
        };
        let mut text = start.trim().to_owned();
        for _ in 0..8 {
            let t = text
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim()
                .to_owned();
            if let Some((lhs, rhs)) = t.split_once("<<") {
                let (Ok(base), Ok(shift)) = (lhs.trim().parse::<u32>(), rhs.trim().parse::<u32>())
                else {
                    return Ok(Fact::Undefined);
                };
                // `checked_shl` refuses only a count of 32 or more; a bit carried past
                // bit 31 is found by shifting back, and the value is then no value.
                let shifted = base.checked_shl(shift).filter(|v| v >> shift == base);
                return Ok(nullable(shifted, |v| Fact::Int(i64::from(v))));
            }
            if let Ok(value) = t.parse::<u32>() {
                return Ok(Fact::Int(i64::from(value)));
            }
            let Some(next) = self.macro_text(&t)? else {
                return Ok(Fact::Undefined);
            };
            if next.trim() == t {
                return Ok(Fact::Undefined);
            }
            text = next;
        }
        Ok(Fact::Undefined)
    }

    fn term(&mut self, term: &Term) -> Result<Fact, Incomplete> {
        match term {
            Term::Macro(name) => Ok(nullable(self.macro_text(name)?, Fact::Text)),
            Term::CInt(name) => self.c_int(name),
            Term::CxxStdlib => {
                for (name, library) in CXX_STDLIB_LADDER {
                    if let Some(value) = self.macro_text(name)? {
                        return Ok(Fact::Text(library.unwrap_or(&value).to_owned()));
                    }
                }
                Ok(Fact::Undefined)
            }
            Term::Elf(field) => {
                let value = self.view.elf_field(*field)?;
                self.record(ReadKey::Elf(*field), value.clone());
                Ok(value)
            }
            Term::Symbol(name) => {
                let value = nullable(self.view.symbol(name)?, Fact::Bool);
                self.record(ReadKey::Symbol(name.clone()), value.clone());
                Ok(value)
            }
            Term::SymbolNames => {
                let value = Fact::List(self.view.symbol_names()?);
                self.record(ReadKey::SymbolNames, value.clone());
                Ok(value)
            }
        }
    }

    fn holds(&mut self, cond: &Cond) -> Result<bool, Incomplete> {
        Ok(match cond {
            Cond::All(members) => {
                for member in members {
                    if !self.holds(member)? {
                        return Ok(false);
                    }
                }
                true
            }
            Cond::Any(members) => {
                for member in members {
                    if self.holds(member)? {
                        return Ok(true);
                    }
                }
                false
            }
            Cond::NoneOf(members) => {
                for member in members {
                    if self.holds(member)? {
                        return Ok(false);
                    }
                }
                true
            }
            Cond::Defined(term) => self.term(term)? != Fact::Undefined,
            Cond::Missing(term) => self.term(term)? == Fact::Undefined,
            Cond::Truth(term) => match self.term(term)? {
                Fact::Bool(value) => value,
                fact @ (Fact::Int(_) | Fact::Text(_)) => fact.integer().is_some_and(|i| i != 0),
                Fact::Undefined | Fact::List(_) => false,
            },
            Cond::Eq(term, expected) => self
                .term(term)?
                .scalar_text()
                .is_some_and(|text| text == *expected),
            Cond::Int(term, cmp, bound) => self
                .term(term)?
                .integer()
                .is_some_and(|value| cmp.holds(value, *bound)),
            Cond::AnyStartsWith(term, prefix) => match self.term(term)? {
                Fact::List(items) => items.iter().any(|i| i.starts_with(prefix.as_str())),
                _ => false,
            },
            Cond::AnyContains(term, needle) => match self.term(term)? {
                Fact::List(items) => items.iter().any(|i| i.contains(needle.as_str())),
                _ => false,
            },
            Cond::NonEmpty(term) => match self.term(term)? {
                Fact::List(items) => !items.is_empty(),
                Fact::Text(text) => !text.is_empty(),
                Fact::Undefined | Fact::Bool(_) | Fact::Int(_) => false,
            },
        })
    }

    fn conclude(
        &mut self,
        conclusion: &Conclusion,
    ) -> Result<(Outcome, Option<String>), Incomplete> {
        Ok(match conclusion {
            Conclusion::Absent => (Outcome::Absent, None),
            Conclusion::Indeterminate => (Outcome::Indeterminate, None),
            Conclusion::Present(LevelOf::None) => (Outcome::Present, None),
            Conclusion::Present(LevelOf::Word(word)) => (Outcome::Present, Some(word.clone())),
            Conclusion::Present(LevelOf::Value(term)) => match self.term(term)?.level() {
                Some(level) => (Outcome::Present, Some(level)),
                None => (Outcome::Indeterminate, None),
            },
        })
    }
}

fn cond_terms<'p>(cond: &'p Cond, out: &mut Vec<&'p Term>) {
    match cond {
        Cond::All(members) | Cond::Any(members) | Cond::NoneOf(members) => {
            for member in members {
                cond_terms(member, out);
            }
        }
        Cond::Defined(term)
        | Cond::Missing(term)
        | Cond::Truth(term)
        | Cond::Eq(term, _)
        | Cond::Int(term, _, _)
        | Cond::AnyStartsWith(term, _)
        | Cond::AnyContains(term, _)
        | Cond::NonEmpty(term) => out.push(term),
    }
}

fn conclusion_terms<'p>(conclusion: &'p Conclusion, out: &mut Vec<&'p Term>) {
    if let Conclusion::Present(LevelOf::Value(term)) = conclusion {
        out.push(term);
    }
}

/// Every term the predicate contains, wherever it appears.
fn terms(p: &Predicate) -> Vec<&Term> {
    let mut out = Vec::new();
    for clause in &p.clauses {
        cond_terms(&clause.when, &mut out);
        conclusion_terms(&clause.then, &mut out);
    }
    conclusion_terms(&p.otherwise, &mut out);
    out
}

/// Whether the predicate reads the macro source.
#[must_use]
pub fn needs_macros(p: &Predicate) -> bool {
    terms(p).iter().any(|t| t.reads_macros())
}

/// Whether the predicate reads the ELF source.
#[must_use]
pub fn needs_elf(p: &Predicate) -> bool {
    !p.tables.is_empty() || terms(p).iter().any(|t| t.reads_elf())
}

/// The `cxx-stdlib` term's ladder, in the order it is consulted: each rung's macro, and
/// the library it names when defined (`None` for `_CXX_STDLIB`, whose own value is the
/// answer). The evaluator walks it and [`reached_only_by_following`] reads its names, so a
/// rung added to one is a rung of the other.
const CXX_STDLIB_LADDER: [(&str, Option<&str>); 3] = [
    ("_CXX_STDLIB", None),
    ("_LIBCPP_VERSION", Some("libc++")),
    ("__GLIBCXX__", Some("libstdc++")),
];

/// Whether a read of macro `name` in an evaluation of `p` can only have been made by a
/// `c-int` term following a value to a macro name: `p` holds a `c-int` term, and no term
/// names `name` itself (`macro`, `c-int`, or a rung of the `cxx-stdlib` ladder).
///
/// A re-derivation over a trimmed map reads an `Incomplete` at such a name as not
/// replayable rather than as a contradiction; see `report::NotReplayable`.
#[must_use]
pub fn reached_only_by_following(p: &Predicate, name: &str) -> bool {
    let all = terms(p);
    let follows = all.iter().any(|t| matches!(t, Term::CInt(_)));
    let named = all.iter().any(|t| match t {
        Term::Macro(n) | Term::CInt(n) => n == name,
        Term::CxxStdlib => CXX_STDLIB_LADDER.iter().any(|(rung, _)| *rung == name),
        Term::Elf(_) | Term::Symbol(_) | Term::SymbolNames => false,
    });
    follows && !named
}

/// Evaluate `p` over `view` by the rules in the module documentation.
///
/// # Errors
///
/// [`Incomplete`] naming the first key the evaluation needed and the view does not hold.
pub fn evaluate<V: FactView + ?Sized>(p: &Predicate, view: &V) -> Result<Evaluation, Incomplete> {
    let reserved = |clause: &str, reads: Vec<Read>| Evaluation {
        outcome: Outcome::Indeterminate,
        level: None,
        clause: clause.to_owned(),
        reads,
    };
    if needs_macros(p) && !view.has_macros() {
        return Ok(reserved(NO_SOURCE_MACROS, Vec::new()));
    }
    if needs_elf(p) && !view.has_elf() {
        return Ok(reserved(NO_SOURCE_ELF, Vec::new()));
    }
    let mut reader = Reader {
        view,
        reads: Vec::new(),
    };
    if !p.tables.is_empty() {
        let unread = view.unread_tables()?;
        reader.record(
            ReadKey::Truncations,
            Fact::List(unread.iter().map(|t| t.as_str().to_owned()).collect()),
        );
        if unread.iter().any(|t| p.tables.contains(t)) {
            return Ok(reserved(TRUNCATED, reader.reads));
        }
    }
    for clause in &p.clauses {
        if reader.holds(&clause.when)? {
            let (outcome, level) = reader.conclude(&clause.then)?;
            return Ok(Evaluation {
                outcome,
                level,
                clause: clause.id.clone(),
                reads: reader.reads,
            });
        }
    }
    let (outcome, level) = reader.conclude(&p.otherwise)?;
    Ok(Evaluation {
        outcome,
        level,
        clause: OTHERWISE.to_owned(),
        reads: reader.reads,
    })
}

/// Hold a predicate to the rules evaluation cannot check: unique clause ids, none
/// reserved, none empty, a reason on every clause, and every symbol it names on the watch
/// list.
///
/// # Errors
///
/// A sentence naming the first clause that breaks a rule.
pub fn validate(p: &Predicate) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for clause in &p.clauses {
        if clause.id.is_empty() || clause.id.starts_with('@') {
            return Err(format!(
                "clause id {:?} is empty or begins with the reserved `@`",
                clause.id
            ));
        }
        if !seen.insert(clause.id.as_str()) {
            return Err(format!("clause id {:?} appears twice", clause.id));
        }
        if clause.because.chars().all(is_schema_whitespace) {
            return Err(format!("clause {:?} gives no reason", clause.id));
        }
    }
    let conclusions = p
        .clauses
        .iter()
        .map(|c| (c.id.as_str(), &c.then))
        .chain(std::iter::once(("@otherwise", &p.otherwise)));
    for (id, conclusion) in conclusions {
        if let Conclusion::Present(LevelOf::Word(word)) = conclusion
            && word.is_empty()
        {
            return Err(format!(
                "clause {id:?} concludes an empty word level, which is no level"
            ));
        }
    }
    for term in terms(p) {
        if let Term::Symbol(name) = term
            && !WATCHED_SYMBOLS.contains(&name.as_str())
        {
            return Err(format!(
                "symbol {name:?} is not on elf::WATCHED_SYMBOLS, so no reading can say it is \
                 absent"
            ));
        }
    }
    Ok(())
}

/// Whether `c` is in ECMA-262's `\s`, the class the schema's `because` pattern `\S` is
/// the complement of: Rust's `White_Space` less U+0085, plus U+FEFF. `validate` refuses a
/// reason made only of these, so it and `schema/chard-predicate.schema.json` refuse the
/// same reasons.
#[must_use]
pub fn is_schema_whitespace(c: char) -> bool {
    (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}'
}

/// The compact JSON form a digest is taken over.
///
/// # Errors
///
/// `serde_json`'s, which these types do not produce: every map key is a string.
pub fn canonical(p: &Predicate) -> serde_json::Result<String> {
    serde_json::to_string(p)
}

fn render_read(read: &Read) -> String {
    let scalar = |fact: &Fact| match fact {
        Fact::Undefined => "null".to_owned(),
        Fact::Bool(b) => b.to_string(),
        Fact::Int(i) => i.to_string(),
        Fact::Text(t) => t.clone(),
        // The module documentation's `LIST`: `Value`'s `Display` is the compact writer.
        Fact::List(items) => Value::from(items.as_slice()).to_string(),
    };
    match (&read.key, &read.value) {
        (ReadKey::Macro(name), Fact::Undefined) => {
            format!("{name}{}", crate::decode::common::UNDEFINED_SUFFIX)
        }
        (ReadKey::Macro(name), value) => format!("{name}={}", scalar(value)),
        (ReadKey::Elf(field), value) => format!("{}={}", field.as_str(), scalar(value)),
        (ReadKey::Symbol(name), Fact::Bool(defined)) => {
            format!("{name}=present(defined={defined})")
        }
        (ReadKey::Symbol(name), _) => format!("{name}=absent"),
        (ReadKey::SymbolNames, value) => format!("watched_symbols={}", scalar(value)),
        (ReadKey::Truncations, value) => format!("unread_tables={}", scalar(value)),
    }
}

/// The `observed` sentence for an evaluation of `p`: its reads, then the deciding
/// clause's reason in parentheses.
#[must_use]
pub fn render_observed(p: &Predicate, eval: &Evaluation) -> String {
    let because = match eval.clause.as_str() {
        NO_SOURCE_MACROS => Some(NO_SOURCE_MACROS_BECAUSE),
        NO_SOURCE_ELF => Some(NO_SOURCE_ELF_BECAUSE),
        TRUNCATED => Some(TRUNCATED_BECAUSE),
        id => p
            .clauses
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.because.as_str()),
    };
    let unrendered = demoted_level(p, eval).map(|term| {
        format!(
            "the level {} has no rendering, so the reading is indeterminate",
            term_spelling(term)
        )
    });
    let reason = match (because, unrendered) {
        (Some(because), Some(note)) => Some(format!("{because}; {note}")),
        (Some(because), None) => Some(because.to_owned()),
        (None, note) => note,
    };
    let reads: Vec<String> = eval.reads.iter().map(render_read).collect();
    let reads = reads.join(" ");
    match reason {
        Some(reason) if reads.is_empty() => format!("({reason})"),
        Some(reason) => format!("{reads} ({reason})"),
        None => reads,
    }
}

/// The level term whose missing rendering demoted `eval` to `indeterminate`, if one did:
/// the deciding conclusion is `present` with a `value` level and the outcome is not.
fn demoted_level<'p>(p: &'p Predicate, eval: &Evaluation) -> Option<&'p Term> {
    let conclusion = if eval.clause == OTHERWISE {
        Some(&p.otherwise)
    } else {
        p.clauses
            .iter()
            .find(|c| c.id == eval.clause)
            .map(|c| &c.then)
    };
    match conclusion {
        Some(Conclusion::Present(LevelOf::Value(term)))
            if eval.outcome == Outcome::Indeterminate =>
        {
            Some(term)
        }
        _ => None,
    }
}

/// A term as the module documentation spells it.
fn term_spelling(term: &Term) -> String {
    match term {
        Term::Macro(name) => format!("macro {name}"),
        Term::CInt(name) => format!("c-int {name}"),
        Term::CxxStdlib => "cxx-stdlib".to_owned(),
        Term::Elf(field) => format!("elf {}", field.as_str()),
        Term::Symbol(name) => format!("symbol {name}"),
        Term::SymbolNames => "symbol-names".to_owned(),
    }
}

/// One row of a channel table: a check id and the function returning its predicate.
pub type Entry = (&'static str, fn() -> &'static Predicate);

/// The predicate the corpus holds for `check`, from either channel's table.
#[must_use]
pub fn for_check(check: &str) -> Option<&'static Predicate> {
    macro_channel::table()
        .iter()
        .chain(elf_static::table())
        .find(|(id, _)| *id == check)
        .map(|(_, predicate)| predicate())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macros(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// `c-int` over libc++'s mode shapes: this holds it to the values those shapes compute
    /// to, and to the rule that a shift that carries a bit past bit 31 is no value, where
    /// `u32::checked_shl` alone would keep the bits that fit and read `(268435457 << 4)` as
    /// 16, libc++'s `extensive`.
    #[test]
    fn c_int_follows_libcpp_mode_value() {
        let cases: &[(&[(&str, &str)], Fact)] = &[
            (&[("M", "(1 << 2)")], Fact::Int(4)),
            (&[("M", "16")], Fact::Int(16)),
            (&[("M", "F"), ("F", "(1 << 3)")], Fact::Int(8)),
            (&[("M", "X"), ("X", "X")], Fact::Undefined),
            (&[("M", "A"), ("A", "B"), ("B", "A")], Fact::Undefined),
            (&[("M", "(a << 2)")], Fact::Undefined),
            (&[("M", "(1 << 40)")], Fact::Undefined),
            (&[("M", "(1 << 31)")], Fact::Int(2_147_483_648)),
            (&[("M", "(3 << 31)")], Fact::Undefined),
            (&[("M", "(268435457 << 4)")], Fact::Undefined),
            (&[("M", "NOPE")], Fact::Undefined),
            (&[], Fact::Undefined),
        ];
        for (map, expected) in cases {
            let map = macros(map);
            let view = Live {
                macros: Some(&map),
                elf: None,
            };
            let mut reader = Reader {
                view: &view,
                reads: Vec::new(),
            };
            let got = reader.c_int("M").expect("a live view is complete");
            assert_eq!(&got, expected, "{map:?}");
        }
    }

    /// The shift rule over its whole domain against an independent oracle: a shift
    /// below 32 whose widened result fits in 32 bits is that result, and everything else
    /// is no value.
    #[test]
    fn c_int_keeps_exactly_the_shifts_that_fit() {
        let bases: [u32; 15] = [
            0,
            1,
            2,
            3,
            7,
            15,
            16,
            255,
            256,
            65_535,
            65_536,
            268_435_457,
            0x7fff_ffff,
            0x8000_0000,
            u32::MAX,
        ];
        let mut fed = 0usize;
        for shift in 0..=40u32 {
            for base in bases {
                let map = macros(&[("M", &format!("({base} << {shift})"))]);
                let view = Live {
                    macros: Some(&map),
                    elf: None,
                };
                let mut reader = Reader {
                    view: &view,
                    reads: Vec::new(),
                };
                let got = reader.c_int("M").expect("a live view is complete");
                let want = if shift < 32 {
                    u32::try_from(u128::from(base) << shift)
                        .map_or(Fact::Undefined, |v| Fact::Int(i64::from(v)))
                } else {
                    Fact::Undefined
                };
                assert_eq!(got, want, "({base} << {shift})");
                fed += 1;
            }
        }
        assert_eq!(fed, 41 * bases.len());
    }

    /// A macro read renders apart from every other value of the same macro: undefined,
    /// defined empty, defined as `?`, as `<defined>` and ` undefined`, as the word
    /// `undefined`, as text and as a number. The undefined form is the self-report's,
    /// and holds no `=`, which every defined form follows the name with.
    #[test]
    fn no_two_macro_values_render_alike() {
        let values: &[Option<&str>] = &[
            None,
            Some(""),
            Some("?"),
            Some("<defined>"),
            Some("undefined"),
            Some(" undefined"),
            Some("x"),
            Some(" x "),
            Some("2"),
            Some("(1 << 2)"),
        ];
        let mut rendered = BTreeMap::new();
        for value in values {
            let map = macros(value.map(|v| ("M", v)).as_slice());
            let view = Live {
                macros: Some(&map),
                elf: None,
            };
            let mut reader = Reader {
                view: &view,
                reads: Vec::new(),
            };
            let text = reader.macro_text("M").expect("a live view is complete");
            assert_eq!(text.as_deref(), *value);
            let [read] = reader.reads.as_slice() else {
                panic!("one read of M, got {:?}", reader.reads);
            };
            let line = render_read(read);
            match value {
                None => assert_eq!(line, "M undefined"),
                Some(v) => assert_eq!(line, format!("M={v}")),
            }
            if let Some(earlier) = rendered.insert(line.clone(), *value) {
                panic!("{earlier:?} and {value:?} both render as {line:?}");
            }
        }
        assert_eq!(rendered.len(), values.len());
    }

    /// The Published view, a publication's `macros` object, reads a macro to the same two
    /// shapes and so renders it as Live does: an absent key is undefined, a string is that
    /// text, `"?"` included. Any other value, `null` among them, is no reading of the
    /// macro (`Incomplete`), never undefined: a `null` read as undefined would read
    /// `absent` from a publication that says nothing.
    #[test]
    fn the_published_view_reads_a_macro_as_live_does() {
        let values: &[Option<&str>] = &[
            None,
            Some(""),
            Some("?"),
            Some("<defined>"),
            Some("x"),
            Some(" x "),
        ];
        let mut fed = 0usize;
        for value in values {
            let map = macros(value.map(|v| ("M", v)).as_slice());
            let object = serde_json::to_value(&map).expect("a string map serializes");
            let view = Published::new(Some(&object), None, None, None).expect("an object");
            let mut reader = Reader {
                view: &view,
                reads: Vec::new(),
            };
            let text = reader
                .macro_text("M")
                .expect("an untrimmed map is complete");
            assert_eq!(text.as_deref(), *value);
            let [read] = reader.reads.as_slice() else {
                panic!("one read of M, got {:?}", reader.reads);
            };
            let line = render_read(read);
            match value {
                None => assert_eq!(line, "M undefined"),
                Some(v) => assert_eq!(line, format!("M={v}")),
            }
            fed += 1;
        }
        assert_eq!(fed, values.len());
        for other in [
            Value::Null,
            Value::from(2),
            Value::Bool(true),
            Value::Array(Vec::new()),
        ] {
            let object = serde_json::json!({ "M": other });
            let view = Published::new(Some(&object), None, None, None).expect("an object");
            let mut reader = Reader {
                view: &view,
                reads: Vec::new(),
            };
            assert_eq!(
                reader.macro_text("M"),
                Err(Incomplete("macros.M".to_owned())),
                "{other}"
            );
            assert!(reader.reads.is_empty(), "{other}: {:?}", reader.reads);
        }
    }

    /// The Rendering section's two examples of a sentence that two evaluations share, each
    /// with reads that differ. Named there as a limit: a change that closes one fails this,
    /// and the section's sentence goes with it.
    #[test]
    fn the_sentence_is_distinct_per_read_and_not_as_a_whole() {
        let sentence = |pairs: &[(&str, &str)], names: &[&str]| {
            let map = macros(pairs);
            let view = Live {
                macros: Some(&map),
                elf: None,
            };
            let mut reader = Reader {
                view: &view,
                reads: Vec::new(),
            };
            for name in names {
                reader.macro_text(name).expect("a live view is complete");
            }
            let reads = reader.reads.clone();
            (
                reads.iter().map(render_read).collect::<Vec<_>>().join(" "),
                reads,
            )
        };
        let (joined, one) = sentence(&[("A", "1 B undefined")], &["A"]);
        let (split, two) = sentence(&[("A", "1")], &["A", "B"]);
        assert_eq!(joined, "A=1 B undefined");
        assert_eq!(joined, split);
        assert_ne!(one, two);

        let map = macros(&[("_LIBCPP_HARDENING_MODE", "B=1")]);
        let view = Live {
            macros: Some(&map),
            elf: None,
        };
        let mut reader = Reader {
            view: &view,
            reads: Vec::new(),
        };
        assert_eq!(reader.c_int("_LIBCPP_HARDENING_MODE"), Ok(Fact::Undefined));
        let followed = reader.reads.last().expect("the followed name is a read");
        assert_eq!(followed.key, ReadKey::Macro("B=1".to_owned()));
        let (other, other_reads) = sentence(&[("B", "1 undefined")], &["B"]);
        assert_eq!(render_read(followed), "B=1 undefined");
        assert_eq!(render_read(followed), other);
        assert_ne!(std::slice::from_ref(followed), other_reads.as_slice());
    }

    #[test]
    fn every_elf_field_is_spelt_as_serde_spells_it() {
        for field in ElfField::ALL {
            let json = serde_json::to_value(field).expect("a unit variant serializes");
            assert_eq!(json.as_str(), Some(field.as_str()), "{field:?}");
        }
    }

    #[test]
    fn the_channel_tables_are_disjoint_and_every_predicate_validates() {
        let mut ids = BTreeSet::new();
        let mut fed = 0usize;
        for (id, predicate) in macro_channel::table().iter().chain(elf_static::table()) {
            fed += 1;
            assert!(ids.insert(*id), "{id} has a predicate in both tables");
            validate(predicate()).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert!(std::ptr::eq(for_check(id).expect("listed"), predicate()));
        }
        assert_eq!(
            fed,
            macro_channel::table()
                .len()
                .saturating_add(elf_static::table().len())
        );
    }
}
