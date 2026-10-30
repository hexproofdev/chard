// SPDX-License-Identifier: BSD-3-Clause

//! The revision files `build.rs` reads where git cannot answer (`build/revision.rs`), held
//! here without a build: the one `git archive` fills in, and the one `cargo package`
//! writes. Each reader names a commit only where the file holds one as its writer writes
//! it, and refuses everything else with a reason rather than reading it as a revision.

#[path = "../build/revision.rs"]
mod revision;

use revision::{ARCHIVE_FILE, ARCHIVE_PLACEHOLDER, Revision, SHORT, Source};

const SHA1: &str = "eeb1c58bc5f7a1e0d2c3b4a5968778695a4b3c2d";
const SHA256: &str = "eeb1c58bc5f7a1e0d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d";

fn header(line: &str) -> String {
    format!("# SPDX-License-Identifier: BSD-3-Clause\n#\n# a comment\n\n{line}\n")
}

fn clean(short: &str) -> Revision {
    Revision {
        short: short.to_owned(),
        dirty: false,
    }
}

#[test]
fn the_unfilled_placeholder_names_no_commit() {
    assert_eq!(
        revision::from_archive_file(&header(ARCHIVE_PLACEHOLDER)),
        Ok(None)
    );
}

#[test]
fn a_filled_archive_file_names_its_commit_shortened() {
    assert_eq!(SHORT, 12);
    for hash in [SHA1, SHA256] {
        assert_eq!(
            revision::from_archive_file(&header(hash)),
            Ok(Some(clean(&hash[..SHORT]))),
            "{hash}"
        );
    }
    // Line endings a checkout or an unpacker may have rewritten read the same, and so does a
    // hash an editor left padded with spaces and tabs.
    assert_eq!(
        revision::from_archive_file(&header(SHA1).replace('\n', "\r\n")),
        Ok(Some(clean(&SHA1[..SHORT])))
    );
    assert_eq!(
        revision::from_archive_file(&header(&format!(" \t{SHA1}\t "))),
        Ok(Some(clean(&SHA1[..SHORT])))
    );
}

/// A file a person or a tool wrote is not a revision unless it is the whole hash git prints:
/// a short hash, uppercase, a ref name, the placeholder half-filled, a second line, or no
/// line at all are each refused, and none is read as a commit.
#[test]
fn an_archive_file_holding_anything_else_is_refused() {
    let shapes = [
        header(&SHA1[..12]),
        header(&SHA1.to_uppercase()),
        header(&format!("{SHA1}0")),
        header("main"),
        header("$Format:%H"),
        header(&format!("{SHA1} {SHA1}")),
        header(&format!("{SHA1}\n{SHA1}")),
        header(&format!("{ARCHIVE_PLACEHOLDER}\n{SHA1}")),
        "# only a comment\n".to_owned(),
        String::new(),
    ];
    for text in &shapes {
        assert!(
            revision::from_archive_file(text).is_err(),
            "{text:?} was read as {:?}",
            revision::from_archive_file(text)
        );
    }
}

/// The tracked file reads as the placeholder in a clone and as a commit in an archive git
/// made, and never as a refusal: the build would otherwise warn on every archive.
/// `.gitattributes` marks it for `git archive` to fill in, or no archive ever names a commit.
#[test]
fn the_tracked_archive_file_is_one_git_archive_fills_in() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join(ARCHIVE_FILE)).expect("REVISION is tracked");
    assert!(
        revision::from_archive_file(&text).is_ok(),
        "{ARCHIVE_FILE} does not read: {:?}",
        revision::from_archive_file(&text)
    );
    let attributes =
        std::fs::read_to_string(root.join(".gitattributes")).expect(".gitattributes is tracked");
    assert!(
        attributes
            .lines()
            .any(|line| line.split_whitespace().collect::<Vec<_>>()
                == [&format!("/{ARCHIVE_FILE}"), "export-subst"]),
        ".gitattributes does not mark /{ARCHIVE_FILE} export-subst:\n{attributes}"
    );
}

/// The file as `cargo package` writes it, clean and dirty.
#[test]
fn cargo_vcs_info_names_its_commit_and_whether_the_tree_was_dirty() {
    let written =
        format!("{{\n  \"git\": {{\n    \"sha1\": \"{SHA1}\"\n  }},\n  \"path_in_vcs\": \"\"\n}}");
    assert_eq!(
        revision::from_cargo_vcs_info(&written),
        Ok(clean(&SHA1[..SHORT]))
    );
    let dirty = format!(
        "{{\n  \"git\": {{\n    \"sha1\": \"{SHA1}\",\n    \"dirty\": true\n  }},\n  \"path_in_vcs\": \"\"\n}}"
    );
    assert_eq!(
        revision::from_cargo_vcs_info(&dirty),
        Ok(Revision {
            short: SHA1[..SHORT].to_owned(),
            dirty: true,
        })
    );
    let compact =
        format!("{{\"git\":{{\"dirty\":false,\"sha1\":\"{SHA256}\"}},\"path_in_vcs\":\"\"}}");
    assert_eq!(
        revision::from_cargo_vcs_info(&compact),
        Ok(clean(&SHA256[..SHORT]))
    );
}

/// `CHARD_REVISION` is a label of ASCII's graphic characters other than the separators: a
/// value that names nothing (an empty one was published as `run.harness_revision` `""` beside
/// `--version` `0.1.0 ()`), would start a second build-script directive, or could be misread
/// (a space, a character that prints as nothing, a separator the version or the join key uses)
/// is refused.
#[test]
fn an_asserted_revision_that_names_nothing_or_could_be_misread_is_refused() {
    for value in [
        "",
        " ",
        "\t ",
        "abc\n",
        "abc\ncargo:warning=x",
        "abc\r",
        "\u{7f}",
        " abc",
        "a b",
        "abc\u{200b}",
        "abc, rustflags 000000000000",
        "abc [asserted]",
        "(abc)",
    ] {
        assert!(
            revision::asserted(value).is_err(),
            "{value:?} was taken as {:?}",
            revision::asserted(value)
        );
    }
    for value in [SHA1, "release-1", "abc-dirty", "v0.1.0+fleet.7"] {
        assert_eq!(revision::asserted(value), Ok(value));
    }
}

/// The environment's `CHARD_REVISION`: unset asserts nothing, a label is taken, and a value
/// that is not UTF-8 is refused like any other refusal, which `build.rs` turns into a failed
/// build rather than a fall-through to the tree's sources.
#[test]
fn the_environments_chard_revision_is_unset_a_label_or_refused() {
    use std::ffi::OsStr;
    assert_eq!(revision::asserted_env(None), Ok(None));
    assert_eq!(
        revision::asserted_env(Some(OsStr::new("release-1"))),
        Ok(Some("release-1"))
    );
    assert!(revision::asserted_env(Some(OsStr::new(""))).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        assert_eq!(
            revision::asserted_env(Some(OsStr::from_bytes(b"abc\xff"))),
            Err("it is not UTF-8")
        );
    }
}

/// `--version` names an asserted revision as asserted and a build under rustflags by the
/// start of their digest; a revision read from the tree prints alone.
#[test]
fn the_version_words_name_an_asserted_revision_and_a_build_under_rustflags() {
    let digest = "c442c3e616f5".to_owned() + &"0".repeat(52);
    for source in [Source::Git, Source::Archive, Source::CargoVcs] {
        assert_eq!(revision::version_words(Some(("abc", source)), None), "abc");
    }
    assert_eq!(
        revision::version_words(Some(("abc", Source::Asserted)), None),
        "abc, asserted"
    );
    assert_eq!(revision::version_words(None, None), "revision unknown");
    assert_eq!(
        revision::version_words(Some(("abc-dirty", Source::Git)), Some(&digest)),
        "abc-dirty, rustflags c442c3e616f5"
    );
    assert_eq!(
        revision::version_words(None, Some(&digest)),
        "revision unknown, rustflags c442c3e616f5"
    );
}

/// The source's spellings are the schema's enumeration, and the three read from the tree are
/// the ones `dataset::revision_key` joins as one. The match is exhaustive, so a new source
/// fails to compile here until it is placed.
#[test]
fn the_source_spellings_are_the_schemas_and_the_join_keys() {
    let every = [
        Source::Git,
        Source::Archive,
        Source::CargoVcs,
        Source::Asserted,
    ];
    let mut tree = Vec::new();
    for source in every {
        match source {
            Source::Git | Source::Archive | Source::CargoVcs => tree.push(source.as_str()),
            Source::Asserted => {}
        }
    }
    assert_eq!(tree, chard::dataset::TREE_SOURCES);

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("schema/chard-report.schema.json"))
            .expect("the report schema is tracked"),
    )
    .expect("the report schema is JSON");
    let spelled: Vec<&str> =
        schema["properties"]["run"]["properties"]["harness_revision_source"]["enum"]
            .as_array()
            .expect("the schema enumerates harness_revision_source")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
    assert_eq!(spelled, every.map(Source::as_str));
}

/// This binary's own stamp: a source exactly where a revision, one of the four spellings, a
/// rustflags digest of sixty-four hex digits where any, and `--version` printing what the
/// constants hold, in [`revision::version_words`]'s words.
#[test]
fn this_build_publishes_its_source_beside_its_revision_and_says_it_in_its_version() {
    use chard::report::{HARNESS_REVISION, HARNESS_REVISION_SOURCE, HARNESS_RUSTFLAGS_SHA256};
    assert_eq!(
        HARNESS_REVISION.is_some(),
        HARNESS_REVISION_SOURCE.is_some()
    );
    let every = [
        Source::Git,
        Source::Archive,
        Source::CargoVcs,
        Source::Asserted,
    ];
    let source = HARNESS_REVISION_SOURCE.map(|spelled| {
        *every
            .iter()
            .find(|s| s.as_str() == spelled)
            .unwrap_or_else(|| panic!("{spelled} is not a source"))
    });
    if let Some(digest) = HARNESS_RUSTFLAGS_SHA256 {
        assert!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{digest}"
        );
    }
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_chard"))
        .arg("--version")
        .output()
        .expect("chard runs");
    assert!(out.status.success());
    let words = revision::version_words(HARNESS_REVISION.zip(source), HARNESS_RUSTFLAGS_SHA256);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end(),
        format!("chard {} ({words})", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn cargo_vcs_info_naming_no_full_commit_is_refused() {
    let shapes = [
        "{\"path_in_vcs\": \"\"}".to_owned(),
        format!("{{\"git\": {{\"sha1\": \"{}\"}}}}", &SHA1[..12]),
        format!("{{\"git\": {{\"sha1\": \"{}\"}}}}", SHA1.to_uppercase()),
        format!("{{\"git\": {{\"sha1\": {SHA1}}}}}"),
        format!("{{\"git\": {{\"sha1\": \"{SHA1}\", \"dirty\": \"yes\"}}}}"),
        String::new(),
    ];
    for text in &shapes {
        assert!(
            revision::from_cargo_vcs_info(text).is_err(),
            "{text:?} was read as {:?}",
            revision::from_cargo_vcs_info(text)
        );
    }
}
