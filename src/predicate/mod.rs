// SPDX-License-Identifier: BSD-3-Clause

//! `chard-predicate/2`: a decoder written as data, and the one evaluator that runs it.

pub mod elf_static;
pub mod macro_channel;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::elf::{ElfFacts, ElfTable, Truncation, TruncationKind, WATCHED_SYMBOLS};
use crate::probe::Outcome;

/// The language version. A change to any rule in the module documentation, or to an
/// expected result in `schema/chard-predicate-vectors.json`, is a new version once a
/// publication has carried the version: the vectors are the part of its meaning a reader
/// can check, and `tests/predicate_language.rs` runs them and holds the schemas' `language`
/// to this name. The new name arrives with the release that carries the change; between the
/// two, a report names the
/// published version over rules that have moved, and `run.decoders_sha256`, which folds
/// this module's source in, tells it from a report of the publication.
pub const LANGUAGE: &str = "chard-predicate/2";

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
    RwxSegment,
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
    pub const ALL: [Self; 40] = [
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
        Self::RwxSegment,
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
            Self::RwxSegment => "rwx_segment",
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
            | Self::GnuStackExecutable
            | Self::RwxSegment => FieldShape::NullableBool,
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

/// A decimal, the module documentation's rule: `str::parse` of `T`, except that two or
/// more digits whose first is `0`, after any sign, do not read: C reads `010` as octal 8
/// and refuses `08`, so the predicates' `unreadable` clauses withhold over such text.
fn decimal<T: std::str::FromStr>(text: &str) -> Option<T> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

impl Fact {
    /// The integer reading, the module documentation's rule: an `Int` itself, `Text`
    /// trimmed and read as a `decimal` `i64`, and nothing else. Public so that a test
    /// holding another reader to this one calls it rather than restating it.
    #[must_use]
    pub fn integer(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            Self::Text(text) => decimal(text.trim()),
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

pub use name::MacroName;

/// A module of its own so that the field is private to it: nothing else in this crate,
/// this module's other code and its child modules included, can build a [`MacroName`]
/// but through [`MacroName::new`].
mod name {
    /// A macro's name as the language reads one: one or more pieces, each an ASCII letter,
    /// an ASCII digit, `_`, `$`, a character outside ASCII without the Unicode
    /// `White_Space` property, or a universal character name (`\u` and four hexadecimal
    /// digits, or `\U` and eight), the first not an ASCII digit.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct MacroName(String);

    impl MacroName {
        /// `text` as a macro's name, or `None` where it is not one.
        #[must_use]
        pub fn new(text: &str) -> Option<Self> {
            if text.is_empty() || text.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            let mut chars = text.chars();
            while let Some(c) = chars.next() {
                let piece = if c == '\\' {
                    // A universal character name: its digits are counted, never read.
                    let digits = match chars.next() {
                        Some('u') => 4,
                        Some('U') => 8,
                        _ => return None,
                    };
                    (0..digits).all(|_| chars.next().is_some_and(|d| d.is_ascii_hexdigit()))
                } else if c.is_ascii() {
                    c.is_ascii_alphanumeric() || c == '_' || c == '$'
                } else {
                    !c.is_whitespace()
                };
                if !piece {
                    return None;
                }
            }
            Some(Self(text.to_owned()))
        }

        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl std::fmt::Display for MacroName {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
}

/// What was read, as distinct keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadKey {
    Macro(MacroName),
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
pub trait FactView {
    fn has_macros(&self) -> bool;
    fn has_elf(&self) -> bool;
    /// A macro's replacement text; `Ok(None)` is a macro known to be undefined.
    ///
    /// # Errors
    ///
    /// The name's key, when the view cannot say.
    fn macro_value(&self, name: &MacroName) -> Result<Option<String>, Incomplete>;
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

    fn macro_value(&self, name: &MacroName) -> Result<Option<String>, Incomplete> {
        Ok(self
            .macros
            .ok_or_else(no_macros)?
            .get(name.as_str())
            .cloned())
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
            ElfField::RwxSegment => nullable(e.rwx_segment, Fact::Bool),
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

    fn macro_value(&self, name: &MacroName) -> Result<Option<String>, Incomplete> {
        let name = name.as_str();
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

    /// The one place a macro is read. Text that is not a macro's name is undefined
    /// before the view is asked, and a view takes a [`MacroName`], so no view answers for
    /// such text and no read is keyed by it.
    fn macro_text(&mut self, name: &str) -> Result<Option<String>, Incomplete> {
        let Some(key) = MacroName::new(name) else {
            return Ok(None);
        };
        let value = self.view.macro_value(&key)?;
        self.record(ReadKey::Macro(key), nullable(value.clone(), Fact::Text));
        Ok(value)
    }

    /// The `c-int` rule, step for step, with every lookup a read.
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
                let (Some(base), Some(shift)) =
                    (decimal::<u32>(lhs.trim()), decimal::<u32>(rhs.trim()))
                else {
                    return Ok(Fact::Undefined);
                };
                // `checked_shl` refuses only a count of 32 or more; a bit carried past
                // bit 31 is found by shifting back, and the value is then no value.
                let shifted = base.checked_shl(shift).filter(|v| v >> shift == base);
                return Ok(nullable(shifted, |v| Fact::Int(i64::from(v))));
            }
            if let Some(value) = decimal::<u32>(&t) {
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
/// reserved, none empty, a reason on every clause, every symbol it names on the watch
/// list, and every macro it names a macro's name ([`MacroName`]).
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
            return Err(format!("clause {id:?} concludes an empty word level"));
        }
    }
    for term in terms(p) {
        if let Term::Symbol(name) = term
            && !WATCHED_SYMBOLS.contains(&name.as_str())
        {
            return Err(format!("symbol {name:?} is not on elf::WATCHED_SYMBOLS"));
        }
        let named = match term {
            Term::Macro(name) => Some(("macro", name)),
            Term::CInt(name) => Some(("c-int", name)),
            Term::CxxStdlib | Term::Elf(_) | Term::Symbol(_) | Term::SymbolNames => None,
        };
        if let Some((kind, name)) = named
            && MacroName::new(name).is_none()
        {
            return Err(format!("the {kind} term's {name:?} is not a macro's name"));
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
    let unrendered = demoted_level(p, eval)
        .map(|term| format!("the level {} has no rendering", term_spelling(term)));
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
    }

    /// Text that is a macro's name, and text that is not. The test's oracle restates the
    /// rule, so a change to `MacroName::new` that moves one answer fails against it.
    const NAMES: &[&str] = &[
        "B",
        "_",
        "_x1",
        "X9",
        "a",
        "M$",
        "$",
        "$1",
        "__has_builtin",
        // Outside ASCII: letters, and a character that is no letter and no space.
        "\u{e9}",
        "M\u{e9}",
        "\u{ff21}",
        "M\u{2014}B",
        // Led by a digit outside ASCII (FULLWIDTH DIGIT ONE): only an ASCII one is refused.
        "\u{ff11}B",
        // A universal character name, as gcc's macro dump spells a letter outside ASCII.
        "M\\U000000e9",
        "\\u00e9t\\u00E9",
        "\\u0041",
    ];
    const NOT_NAMES: &[&str] = &[
        // A `-D` value holding `=`, and one holding a space: each spells a second read.
        "B=1",
        "a b",
        // Suffixed and signed numbers, which no `u32` parse takes and a build does pass.
        "3L",
        "2UL",
        "-1",
        "0x4",
        "1x",
        // A function-like macro's key, and what `c-int` leaves of it.
        "f(x)",
        "f(x",
        // Empty, blank, and punctuation a name never holds.
        "",
        " ",
        " B",
        "B ",
        "A.B",
        "A-B",
        "A,B",
        "A\tB",
        "B undefined",
        // A backslash that opens no universal character name, or one cut short.
        "M\\",
        "M\\x41",
        "M\\u00e",
        "M\\u00eg",
        "M\\U0000e9",
        "M\\U0000e9zz",
        "\\",
        // White space outside ASCII, first to last of the property's characters there.
        "A\u{85}B",
        "A\u{a0}B",
        "A\u{1680}B",
        "A\u{2000}B",
        "A\u{200a}B",
        "A\u{2028}B",
        "A\u{2029}B",
        "A\u{202f}B",
        "A\u{205f}B",
        "A\u{3000}B",
    ];

    /// The characters outside ASCII with the Unicode `White_Space` property, written out so
    /// the oracle does not ask the standard library what a space is.
    const WHITE_SPACE: &[char] = &[
        '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
        '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}',
        '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
    ];

    #[test]
    fn a_macro_name_is_an_identifier_with_dollar_and_no_space() {
        let oracle = |text: &str| {
            let word = |c: char| {
                matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '$')
                    || (u32::from(c) > 0x7f && !WHITE_SPACE.contains(&c))
            };
            let chars: Vec<char> = text.chars().collect();
            let hex = |run: &[char]| run.iter().all(|c| "0123456789abcdefABCDEF".contains(*c));
            let (mut at, mut rest) = (0usize, Vec::new());
            while at < chars.len() {
                if chars[at] != '\\' {
                    rest.push(chars[at]);
                    at += 1;
                    continue;
                }
                let len = match chars.get(at + 1) {
                    Some('u') => 4,
                    Some('U') => 8,
                    _ => return false,
                };
                match chars.get(at + 2..at + 2 + len) {
                    Some(run) if hex(run) => at += 2 + len,
                    _ => return false,
                }
            }
            chars.first().is_some_and(|c| !c.is_ascii_digit()) && rest.into_iter().all(word)
        };
        let mut fed = 0usize;
        for text in NAMES {
            assert!(
                oracle(text),
                "{text:?} is in NAMES and the oracle refuses it"
            );
            let name = MacroName::new(text).unwrap_or_else(|| panic!("{text:?} is a name"));
            assert_eq!(name.as_str(), *text);
            assert_eq!(name.to_string(), *text);
            fed += 1;
        }
        for text in NOT_NAMES {
            assert!(
                !oracle(text),
                "{text:?} is in NOT_NAMES and the oracle takes it"
            );
            assert_eq!(MacroName::new(text), None, "{text:?}");
            fed += 1;
        }
        // Every one-character text through U+3100, past the last white-space character.
        let mut swept = 0usize;
        for c in (0u32..0x3100).filter_map(char::from_u32) {
            swept += 1;
            let text = c.to_string();
            assert_eq!(MacroName::new(&text).is_some(), oracle(&text), "{text:?}");
            let second = format!("A{c}");
            assert_eq!(
                MacroName::new(&second).is_some(),
                oracle(&second),
                "{second:?}"
            );
            fed += 2;
        }
        assert_eq!(swept, 0x3100);
        assert_eq!(fed, NAMES.len() + NOT_NAMES.len() + 2 * swept);
    }

    /// What one view made of `c-int M` and of `macro TEXT`, each with a reader of its own.
    struct Seen {
        view: &'static str,
        followed: Result<Fact, Incomplete>,
        followed_reads: Vec<Read>,
        named: Result<Fact, Incomplete>,
        named_reads: Vec<Read>,
        /// `c-int TEXT`: the text as the term's own name, where `followed` meets it as a value.
        started: Result<Fact, Incomplete>,
        started_reads: Vec<Read>,
    }

    /// `c-int M` and `macro TEXT` through the three views a mode's value is read through:
    /// Live, Published untrimmed, and Published trimmed to `filter`.
    fn through_each_view(
        map: &BTreeMap<String, String>,
        filter: &[String],
        text: &str,
    ) -> Vec<Seen> {
        let object = serde_json::to_value(map).expect("a string map serializes");
        let live = Live {
            macros: Some(map),
            elf: None,
        };
        let whole = Published::new(Some(&object), None, None, None).expect("an object");
        let trimmed = Published::new(Some(&object), Some(filter), None, None).expect("an object");
        let views: [(&'static str, &dyn FactView); 3] = [
            ("live", &live),
            ("published", &whole),
            ("published, filtered", &trimmed),
        ];
        views
            .into_iter()
            .map(|(view, facts)| {
                let mut follow = Reader {
                    view: facts,
                    reads: Vec::new(),
                };
                let followed = follow.c_int("M");
                let mut name = Reader {
                    view: facts,
                    reads: Vec::new(),
                };
                let named = name.term(&Term::Macro(text.to_owned()));
                let mut start = Reader {
                    view: facts,
                    reads: Vec::new(),
                };
                let started = start.term(&Term::CInt(text.to_owned()));
                Seen {
                    view,
                    followed,
                    followed_reads: follow.reads,
                    named,
                    named_reads: name.reads,
                    started,
                    started_reads: start.reads,
                }
            })
            .collect()
    }

    /// What `c-int` makes of a value before it looks anything up.
    fn stripped(text: &str) -> &str {
        text.trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim()
    }

    #[test]
    fn no_macro_read_is_keyed_by_text_that_is_not_a_name() {
        let (mut fed, mut held, mut become_names) = (0usize, 0usize, BTreeSet::new());
        for text in NOT_NAMES {
            for (planted, kept) in [(false, false), (true, false), (true, true), (false, true)] {
                let mut map = macros(&[("M", text)]);
                if planted {
                    map.insert((*text).to_owned(), "4".to_owned());
                    map.insert(stripped(text).to_owned(), "4".to_owned());
                }
                let mut filter = vec!["M".to_owned()];
                if kept {
                    filter.push((*text).to_owned());
                    filter.push(stripped(text).to_owned());
                }
                for seen in through_each_view(&map, &filter, text) {
                    let at = format!("{text:?} planted={planted} kept={kept}, {}", seen.view);
                    fed += 1;
                    assert_eq!(seen.named, Ok(Fact::Undefined), "macro {at}");
                    assert!(
                        seen.named_reads.is_empty(),
                        "macro {at}: {:?}",
                        seen.named_reads
                    );
                    assert_eq!(seen.started, Ok(Fact::Undefined), "c-int {at}");
                    assert!(seen.started_reads.is_empty(), "c-int {at}");
                    if MacroName::new(stripped(text)).is_some() {
                        // Trimmed, the text is the name `B`, and that name is what is read:
                        // found where the map holds it, and outside the filter a stop at it.
                        become_names.insert(*text);
                        let keys: Vec<String> = seen
                            .followed_reads
                            .iter()
                            .map(|r| r.key.published_key())
                            .collect();
                        let stop = seen.view == "published, filtered" && !kept;
                        let want = match (stop, planted) {
                            (true, _) => Err(Incomplete("macros.B".to_owned())),
                            (false, true) => Ok(Fact::Int(4)),
                            (false, false) => Ok(Fact::Undefined),
                        };
                        assert_eq!(seen.followed, want, "c-int over {at}");
                        let read: &[&str] = if stop {
                            &["macros.M"]
                        } else {
                            &["macros.M", "macros.B"]
                        };
                        assert_eq!(keys, read, "{at}");
                        continue;
                    }
                    assert_eq!(seen.followed, Ok(Fact::Undefined), "c-int over {at}");
                    let [read] = seen.followed_reads.as_slice() else {
                        panic!("c-int over {at}: {:?}", seen.followed_reads);
                    };
                    assert_eq!(read.key.published_key(), "macros.M", "{at}");
                    assert_eq!(read.value, Fact::Text((*text).to_owned()), "{at}");
                    held += 1;
                }
            }
        }
        assert_eq!(fed, NOT_NAMES.len() * 4 * 3);
        assert_eq!(become_names, BTreeSet::from([" B", "B "]));
        assert_eq!(held, (NOT_NAMES.len() - become_names.len()) * 4 * 3);
    }

    #[test]
    fn a_name_is_still_followed_and_read() {
        let mut fed = 0usize;
        for text in NAMES {
            for kept in [false, true] {
                let map = macros(&[("M", text), (text, "(1 << 2)")]);
                let mut filter = vec!["M".to_owned()];
                if kept {
                    filter.push((*text).to_owned());
                }
                for seen in through_each_view(&map, &filter, text) {
                    let at = format!("{text:?} kept={kept}, {}", seen.view);
                    let keys = |reads: &[Read]| -> Vec<String> {
                        reads.iter().map(|r| r.key.published_key()).collect()
                    };
                    if seen.view == "published, filtered" && !kept {
                        let key = Incomplete(format!("macros.{text}"));
                        assert_eq!(seen.followed, Err(key.clone()), "c-int over {at}");
                        assert_eq!(keys(&seen.followed_reads), ["macros.M"], "{at}");
                        assert_eq!(seen.named, Err(key), "macro {at}");
                        assert!(seen.named_reads.is_empty(), "{at}");
                    } else {
                        assert_eq!(seen.followed, Ok(Fact::Int(4)), "c-int over {at}");
                        assert_eq!(
                            keys(&seen.followed_reads),
                            ["macros.M".to_owned(), format!("macros.{text}")],
                            "{at}"
                        );
                        let value = Fact::Text("(1 << 2)".to_owned());
                        assert_eq!(seen.named, Ok(value), "macro {at}");
                        assert_eq!(keys(&seen.named_reads), [format!("macros.{text}")], "{at}");
                    }
                    fed += 1;
                }
            }
        }
        assert_eq!(fed, NAMES.len() * 2 * 3);
    }

    #[test]
    fn validate_refuses_a_term_naming_text_that_is_not_a_name() {
        let over = |when: Term, level: Term| Predicate {
            tables: Vec::new(),
            clauses: vec![Clause {
                id: "defined".to_owned(),
                when: Cond::Defined(when),
                then: Conclusion::Present(LevelOf::Value(level)),
                because: "the macro is defined".to_owned(),
            }],
            otherwise: Conclusion::Indeterminate,
        };
        let name = || Term::Macro("M".to_owned());
        assert_eq!(validate(&over(name(), name())), Ok(()));
        assert_eq!(validate(&over(Term::CInt("M$".to_owned()), name())), Ok(()));
        let mut fed = 0usize;
        for text in NOT_NAMES {
            for (label, p) in [
                ("macro, when", over(Term::Macro((*text).to_owned()), name())),
                ("c-int, when", over(Term::CInt((*text).to_owned()), name())),
                (
                    "macro, level",
                    over(name(), Term::Macro((*text).to_owned())),
                ),
                ("c-int, level", over(name(), Term::CInt((*text).to_owned()))),
            ] {
                let refused = validate(&p).expect_err("a term naming no macro validated");
                assert!(
                    refused.contains("is not a macro's name")
                        && refused.contains(&format!("the {} term's {text:?}", &label[..5])),
                    "{label} {text:?}: {refused}"
                );
                fed += 1;
            }
        }
        assert_eq!(fed, NOT_NAMES.len() * 4);
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
