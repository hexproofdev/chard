// SPDX-License-Identifier: BSD-3-Clause

//! The two files `build.rs` reads a revision from where git cannot answer: the one `git
//! archive` fills in, and the one `cargo package` writes. Each reader takes the file's text
//! and does no I/O, so `tests/build_revision.rs` holds them without a build; `build.rs`
//! does the reading and says in what order the sources are asked.
//!
//! A file that holds neither a commit nor its unfilled placeholder is refused with the reason,
//! never read as a revision: a wrong revision is worse than none, since the field is half of
//! a report's dataset identity and an unknown one says so.
//!
//! A file that names a commit is taken at its word. The unpacked sources are not checked
//! against it, so a tree edited after unpacking builds as the archive's commit, without the
//! `-dirty` a clone would give it; the assumption `archive-revision-names-the-unpacked-tree`
//! (`report::ASSUMPTIONS`) says so and what would retire it.
//!
//! The rest is what the build says about where its revision came from: [`Source`], which a
//! report publishes as `run.harness_revision_source`; [`asserted`], the refusals an asserted
//! `CHARD_REVISION` meets; and [`version_words`], what `--version` prints in its parentheses.

/// The tracked file `.gitattributes` marks `export-subst`, so `git archive` replaces
/// [`ARCHIVE_PLACEHOLDER`] in it with the full hash of the commit it archives.
pub const ARCHIVE_FILE: &str = "REVISION";

/// What [`ARCHIVE_FILE`] holds everywhere but in an archive git made: git's placeholder for
/// the commit's full hash. A clone, a tree archived without a commit, and a crate archive all
/// carry it unfilled.
pub const ARCHIVE_PLACEHOLDER: &str = "$Format:%H$";

/// How many hex digits of the hash the revision keeps, as `git rev-parse --short=12` does in
/// `build.rs`, so the three sources print one commit the same way.
pub const SHORT: usize = 12;

/// A commit a file names, shortened, and whether the file says the tree it was built from had
/// uncommitted changes.
#[derive(Debug, PartialEq, Eq)]
pub struct Revision {
    pub short: String,
    pub dirty: bool,
}

/// A full object name as git prints one: 40 lowercase hex digits under SHA-1, 64 under
/// SHA-256.
fn is_object_name(word: &str) -> bool {
    (word.len() == 40 || word.len() == 64)
        && word
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn revision(hash: &str, dirty: bool) -> Revision {
    Revision {
        short: hash.chars().take(SHORT).collect(),
        dirty,
    }
}

/// Which of `build.rs`'s four sources named the revision. The first three read it from the
/// tree the build compiled; [`Source::Asserted`] is the builder's word, `CHARD_REVISION`, which
/// nothing checks against the tree, so a report carrying it joins only reports asserted alike
/// (`dataset::revision_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// git, where the manifest directory is a repository's top.
    Git,
    /// [`ARCHIVE_FILE`], filled in by `git archive`.
    Archive,
    /// `.cargo_vcs_info.json`, written by `cargo package`.
    CargoVcs,
    /// `CHARD_REVISION`, set by whoever ran the build.
    Asserted,
}

impl Source {
    /// The spelling `run.harness_revision_source` publishes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Archive => "archive",
            Self::CargoVcs => "cargo-vcs",
            Self::Asserted => "asserted",
        }
    }
}

/// The characters `--version`'s words and `dataset::revision_key` use as separators, which a
/// label may not carry: `abc, rustflags 000000000000` would print as a rustflags build, and
/// `abc [asserted]` would spell another key's text.
pub const SEPARATORS: &str = "[](),";

/// `CHARD_REVISION`'s value, where it may stand as a revision. A control character is refused
/// because cargo reads a build script's output a line at a time, so a newline would start a
/// second directive (an embedded `cargo:warning=` was executed). An empty or blank value is
/// refused because it named nothing and was published as `run.harness_revision` `""`, beside
/// a `--version` of `0.1.0 ()`. Anything but ASCII's graphic characters (a space, a character
/// that prints as nothing) or a [`SEPARATORS`] character is refused, so a label reads as what
/// it is.
pub fn asserted(value: &str) -> Result<&str, &'static str> {
    if value.chars().any(char::is_control) {
        Err("it holds a control character")
    } else if value.trim().is_empty() {
        Err("it is empty or blank, and names nothing")
    } else if !value
        .chars()
        .all(|c| c.is_ascii_graphic() && !SEPARATORS.contains(c))
    {
        Err(
            "it holds a space, a character outside ASCII, or one of [ ] ( ) , which the version and the join key use as separators",
        )
    } else {
        Ok(value)
    }
}

/// `CHARD_REVISION` as the build's environment holds it: `Ok(None)` where it is unset, the
/// label where [`asserted`] admits it, and the refusal otherwise, a value that is not UTF-8
/// among them. `build.rs` fails the build on a refusal rather than falling through to another
/// source: the builder asked for a label and got none.
pub fn asserted_env(value: Option<&std::ffi::OsStr>) -> Result<Option<&str>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(value) = value.to_str() else {
        return Err("it is not UTF-8");
    };
    asserted(value).map(Some)
}

/// How many hex digits of `run.harness_rustflags_sha256` `--version` prints.
pub const RUSTFLAGS_SHORT: usize = 12;

/// What `--version` prints in its parentheses: the revision, `asserted` beside one
/// `CHARD_REVISION` gave, and the start of the rustflags digest where cargo passed rustflags.
/// The three tree sources print the revision alone.
pub fn version_words(revision: Option<(&str, Source)>, rustflags_sha256: Option<&str>) -> String {
    let words = match revision {
        None => "revision unknown".to_owned(),
        Some((revision, Source::Asserted)) => format!("{revision}, asserted"),
        Some((revision, Source::Git | Source::Archive | Source::CargoVcs)) => revision.to_owned(),
    };
    match rustflags_sha256 {
        Some(digest) => {
            let short: String = digest.chars().take(RUSTFLAGS_SHORT).collect();
            format!("{words}, rustflags {short}")
        }
        None => words,
    }
}

/// [`ARCHIVE_FILE`]'s text: `#` lines and blank lines are its header, and exactly one other
/// line is the hash or the placeholder. `Ok(None)` is the placeholder, which names no commit.
/// An archive is a commit's tree, so its revision is never dirty; what the file cannot tell
/// is a tree edited after it was unpacked, which `CHARD_REVISION` cannot either (the module
/// doc names the assumption).
pub fn from_archive_file(text: &str) -> Result<Option<Revision>, &'static str> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err("it does not hold exactly one line besides its comments");
    };
    if line == ARCHIVE_PLACEHOLDER {
        Ok(None)
    } else if is_object_name(line) {
        Ok(Some(revision(line, false)))
    } else {
        Err("its line is neither a full commit hash nor git's unfilled placeholder")
    }
}

/// The text after `"key"` and its colon in cargo's flat JSON, up to the next `,` or `}`.
/// Enough for the file cargo writes, whose values are a hash, a boolean and a path, and no
/// general JSON reader: the build script has no dependencies.
fn value_after<'t>(text: &'t str, key: &str) -> Option<&'t str> {
    let quoted = format!("\"{key}\"");
    let (_, rest) = text.split_once(quoted.as_str())?;
    let rest = rest.trim_start().strip_prefix(':')?;
    rest.split([',', '}']).next().map(str::trim)
}

/// `.cargo_vcs_info.json`'s text, which `cargo package` writes into a crate archive made from
/// a git checkout: `git.sha1` is the commit, and `git.dirty`, written only when true, says the
/// packaged tree had uncommitted changes (`cargo package --allow-dirty`).
pub fn from_cargo_vcs_info(text: &str) -> Result<Revision, &'static str> {
    let Some(sha1) = value_after(text, "sha1") else {
        return Err("it names no git.sha1");
    };
    let Some(sha1) = sha1.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return Err("its git.sha1 is not a string");
    };
    if !is_object_name(sha1) {
        return Err("its git.sha1 is not a full commit hash");
    }
    let dirty = match value_after(text, "dirty") {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err("its git.dirty is neither true nor false"),
    };
    Ok(revision(sha1, dirty))
}
